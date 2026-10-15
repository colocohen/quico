/*
 * quico: HTTP/3 and QUIC implementation for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the open-source project hosted at:
 *     https://github.com/colocohen/quico
 */

import { EventEmitter } from 'node:events';
import { Duplex } from 'node:stream';

import { H2Connection, SOCKET_HIGH_WATER } from './h2.js';
import * as F from './h2_frames.js';
import { buildResponsePseudoHeaders, corkForTick, pseudoHeadersToRequest, runRequestHandler, STATUS_TEXT, maxRequestsPerSocket,
         DEFAULT_HEADERS_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, startDeadline, responsePriority, trailerFields, statusHasNoBody, httpDate, streamResetLimiter } from './http_common.js';
import { observeH2 } from './h2_fingerprint.js';
import { IncomingMessage, ServerResponse } from './streams.js';
import { createTcpListener } from './tcp_listener.js';


// ============================================================
//  HTTP/2 server.
//
//  The same three layers as everywhere else in this stack: tcp_listener owns
//  the socket and ALPN, h2.js turns bytes into stream events, and streams.js
//  wraps those in the IncomingMessage / ServerResponse pair every framework
//  expects. This file is only the wiring between them — which is why it is a
//  fraction of h2.js's size despite being the thing applications touch.
//
//  It is also why an Express app runs unchanged over HTTP/2: the req and res
//  it receives are the same objects h1_server and h3_server hand it, and
//  nothing in the middle knows which protocol produced them.
// ============================================================

var DEFAULT_KEEPALIVE_TIMEOUT = 0;   // 0 = no idle limit; h2 connections are long-lived


// ============================================================
//  Protocol-independent refusal codes.
//
//  HTTP/2 and HTTP/3 both let a server refuse a stream, and both use entirely
//  different numbers for it. Code that limits request rates should not have to
//  know which protocol carried the request, so it names an INTENT and each
//  layer maps it to its own registry.
//
//  REFUSED specifically, and not CANCELLED, is what a rate limiter wants:
//  RFC 9113 §8.1 lets a client safely retry a REFUSED_STREAM on another
//  connection, because it states the request was never processed. Cancelling
//  says the opposite, and a client that retries after it may duplicate work.
// ============================================================

var STREAM_REFUSED  = 'refused';
var STREAM_CANCELLED = 'cancelled';
var CONN_OVERLOADED = 'overloaded';

function translateStreamError(code) {
  if (typeof code === 'number') return code;      // caller wants a raw code
  if (code === STREAM_CANCELLED) return F.ERROR.CANCEL;
  return F.ERROR.REFUSED_STREAM;
}

function translateConnError(code) {
  if (typeof code === 'number') return code;
  if (code === CONN_OVERLOADED) return F.ERROR.ENHANCE_YOUR_CALM;
  return F.ERROR.NO_ERROR;
}


function createServer(options, handler) {
  if (typeof options === 'function') { handler = options; options = {}; }
  options = options || {};

  var ev = new EventEmitter();
  var listener = null;
  var connections = new Set();
  var closing = false;

  var altSvc = options.altSvc || null;
  // How long a request may take to arrive (see http_common). headersTimeout
  // bounds a header block left open, which holds the whole connection;
  // requestTimeout each request, from its head to its last byte.
  var headersTimeout = options.headersTimeout != null ? options.headersTimeout : DEFAULT_HEADERS_TIMEOUT;
  var requestTimeout = options.requestTimeout != null ? options.requestTimeout : DEFAULT_REQUEST_TIMEOUT;
  // Rapid Reset (http_common streamResetLimiter): the options checked now.
  streamResetLimiter(options);
  // node:http2's maxSessionMemory: megabytes a connection may have queued.
  var maxSessionMemory = (options.maxSessionMemory > 0 ? options.maxSessionMemory : 10) * 1024 * 1024;
  // node:http's maxRequestsPerSocket, as HTTP/2 can honour it: after the Nth
  // request, GOAWAY — those in flight finish, the client opens a new
  // connection for the next (nginx's keepalive_requests, the same way).
  var maxRequests = maxRequestsPerSocket(options.maxRequestsPerSocket);

  // node:http's shouldUpgradeCallback, for extended CONNECT (RFC 8441): taken
  // up as an 'upgrade' (true) or handled as an ordinary 'request' (false).
  // Default: true when something listens for 'upgrade'.
  var shouldUpgradeCallback = typeof options.shouldUpgradeCallback === 'function'
    ? options.shouldUpgradeCallback
    : function () { return ev.listenerCount('upgrade') > 0; };


  function handleConnection(socket) {
    if (closing) { try { socket.destroy(); } catch (e) {} return; }

    var h2 = new H2Connection({
      isServer: true,
      stats: options.stats || null,
      maxConcurrentStreams: options.maxConcurrentStreams,
      initialWindowSize: options.initialWindowSize,
      connectionWindowSize: options.connectionWindowSize,
      maxFrameSize: options.maxFrameSize,
      maxHeaderListSize: options.maxHeaderListSize,
      headerTableSize: options.headerTableSize,
      // RFC 8441. On by default: a server that can accept WebSocket over
      // HTTP/2 should say so, or browsers open a second HTTP/1.1 connection
      // instead. Passing false turns it off for a server that has no
      // WebSocket endpoint and no reason to invite extended CONNECT.
      enableConnectProtocol: options.enableConnectProtocol,
      // DATA is held while the socket's unsent bytes are over this mark — the
      // flow-control windows bound what the peer may receive, this what we
      // queue for it (see flushStream in h2.js).
      isWriteBlocked: function () { return socket.writableLength >= SOCKET_HIGH_WATER; },
      // Credit is returned when the application reads, not when the frame
      // arrives. Without this the receive window never closes and a client can
      // push a body far faster than the handler consumes it — the bytes pile
      // up in our heap and flow control does nothing at all.
      autoWindowUpdate: false
    });

    var streams = {};     // id -> { req, res, deadline }
    var served = 0;       // requests on this connection (maxRequestsPerSocket)
    var destroyed = false;

    // ---- How long a request may take to arrive ----
    //
    // A header block left open (HEADERS without END_HEADERS) holds the
    // connection: no other frame may come until its CONTINUATIONs end it
    // (§6.10). Trickled, it held every other request on the connection with
    // it, and nothing timed it. Past headersTimeout the connection goes —
    // there is no stream to give up instead.
    var headerBlockTimer = null;
    h2.on('header_block_open', function () {
      if (headerBlockTimer) clearTimeout(headerBlockTimer);
      headerBlockTimer = startDeadline(headersTimeout, function () {
        headerBlockTimer = null;
        if (destroyed) return;
        h2.sendGoaway(F.ERROR.NO_ERROR);
        destroy(new Error('timeout: header block not completed within ' + headersTimeout + ' ms'), true);
      });
    });
    h2.on('header_block_closed', function () {
      if (headerBlockTimer) { clearTimeout(headerBlockTimer); headerBlockTimer = null; }
    });

    // A request whose body has not all arrived within requestTimeout of its
    // head (CONNECT excepted — a tunnel): the stream is reset (CANCEL), both ways, and the request and its
    // response end as they do when the client cancels — 'aborted', and a
    // 'streamError' for the log. Only this stream: the connection serves on.
    // (HTTP/1.1 answers 408 and closes; a stream of its own needs no more
    // than its reset.)
    function armRequestDeadline(streamId, st) {
      st.deadline = startDeadline(requestTimeout, function () {
        st.deadline = null;
        if (streams[streamId] !== st || st.req.complete) return;
        delete streams[streamId];
        h2.sendRstStream(streamId, F.ERROR.CANCEL);
        abortStream(st, 'request not received in full within ' + requestTimeout + ' ms', 'ERR_HTTP_REQUEST_TIMEOUT');
      });
    }
    function clearRequestDeadline(st) {
      if (st && st.deadline) { clearTimeout(st.deadline); st.deadline = null; }
    }

    // Accumulates the connection's HTTP/2 fingerprint from the opening frames.
    // Attached before execute() is ever called, because everything it needs
    // arrives in the peer's first flight — the fingerprint exists before a
    // single byte of content has been served, which is what makes it useful
    // for deciding whether to serve any.
    var getFingerprint = observeH2(h2);

    /**
     * What a rate limiter is handed: enough to build a key from, and the two
     * ways to refuse.
     *
     * The methods are named identically to the HTTP/3 equivalents even though
     * the wire mechanisms differ — RST_STREAM on a frame here, RESET_STREAM on
     * a QUIC stream there — so that one piece of limiting code works against
     * both without branching on version.
     */
    var connHandle = {
      httpVersion: '2.0',
      get remoteAddress() { return socket.remoteAddress; },
      get remotePort() { return socket.remotePort; },
      get encrypted() { return !!socket.encrypted; },
      // The session ticket: { data, resumed, offered } (see lemon-tls
      // getTicketInfo); null over cleartext.
      getTicketInfo: function () { return socket.getTicketInfo ? socket.getTicketInfo() : null; },
      isSessionReused: function () { return !!(socket.isSessionReused && socket.isSessionReused()); },
      get activeStreams() { return Object.keys(streams).length; },
      fingerprint: getFingerprint,

      sendRstStream: function (streamId, code) {
        h2.sendRstStream(streamId, translateStreamError(code));
      },

      // Stops new streams; in-flight ones finish. See the note in h2.js.
      goaway: function (code) { h2.goaway(translateConnError(code)); },

      // For when stopping is not enough.
      destroy: function () { destroy(null); }
    };

    h2.on('stream_open', function (streamId) {
      ev.emit('stream_open', connHandle, streamId);
    });

    // Rapid Reset: past streamResetBurst / streamResetRate, GOAWAY
    // ENHANCE_YOUR_CALM and the connection closed, as node:http2 does.
    var resetTooMany = streamResetLimiter(options);
    h2.on('stream_reset', function (streamId, code) {
      ev.emit('stream_reset', connHandle, streamId, code);
      if (destroyed || !resetTooMany()) return;
      var rr = new Error('too many stream resets (streamResetBurst, streamResetRate)');
      rr.code = 'ERR_HTTP2_STREAM_RESET_RATE';
      try { h2.goaway(F.ERROR.ENHANCE_YOUR_CALM); } catch (e) {}
      ev.emit('sessionError', rr, connHandle);
      destroy(rr, true);
    });

    // The response is complete — END_STREAM written — and the request is
    // not (RFC 9113 §8.1): a 413, a 401, a refusal answered before the upload
    // is read. Unless the application is reading the body, the client is
    // told to stop sending it: RST_STREAM with NO_ERROR, after the response,
    // which a client must not take as a failure of it. node:http2 decides it
    // the same way (the stream is closed if nothing has read from it). The
    // stream used to stay open: the client went on uploading into a window
    // nobody would open again, and held one of its concurrent streams until
    // it gave up.
    h2.on('local_end', function (streamId) {
      var st = streams[streamId];   // taken now: the response's end removes the entry
      if (!st || !st.req || st.duplex) return;
      process.nextTick(function () {
        var req = st.req;
        if (req.complete || req.aborted || destroyed) return;
        if (!req.destroyed && req.readableFlowing !== null) return;   // still being read
        if (streams[streamId] === st) delete streams[streamId];
        clearRequestDeadline(st);
        h2.sendRstStream(streamId, F.ERROR.NO_ERROR);
      });
    });

    connections.add(socket);

    // `linger`: end the socket rather than destroy it — what was written last
    // (the GOAWAY saying why) leaves first — and destroy it if the peer has
    // not closed its side in time. destroy() right after end() dropped the
    // GOAWAY the comment below meant to deliver.
    function destroy(err, linger) {
      if (destroyed) return;
      destroyed = true;
      connections.delete(socket);
      if (headerBlockTimer) { clearTimeout(headerBlockTimer); headerBlockTimer = null; }
      for (var id in streams) {
        var st = streams[id];
        clearRequestDeadline(st);
        // An extended-CONNECT tunnel (a WebSocket, CONNECT-UDP) goes with the
        // connection: its Duplex is destroyed. Its request had ended at the
        // accept, so the line below never reached it — the tunnel's user
        // waited for an end that could not come.
        if (st.duplex) { try { st.duplex.destroy(); } catch (e) {} continue; }
        // 'aborted', an Error only to a listener, 'close' (see _abort); the
        // response, mid-write, closed (_abortResponse).
        if (st.req && !st.req.complete) st.req._abort(err || null);
        if (st.res) st.res._abortResponse();
      }
      streams = {};
      if (!linger) { try { socket.destroy(); } catch (e) {} return; }
      try { socket.end(); } catch (e) {}
      var t = setTimeout(function () { try { socket.destroy(); } catch (e) {} }, 1000);
      if (t.unref) t.unref();
    }

    // An HTTP/2 connection's errors are 'sessionError' (err, session), as
    // node:http2 reports them — not 'clientError' (err, socket), which is
    // HTTP/1.1's, and whose listeners answer by writing an HTTP/1.1 status
    // line onto the socket: on an HTTP/2 connection, after its GOAWAY, that is
    // bytes the client cannot parse.
    h2.on('send', function (data) {
      if (destroyed || !socket.writable) return;
      corkForTick(socket);
      try { socket.write(data); } catch (e) { destroy(e); return; }
      // What is queued on the socket and not yet sent, bounded per connection
      // (node's maxSessionMemory, in MB, default 10). DATA waits for the
      // socket (isWriteBlocked), so what can pile up here is everything else —
      // replies the peer provokes (PING and SETTINGS acknowledgements, resets)
      // while it does not read. Past the bound the connection goes.
      if (socket.writableLength > maxSessionMemory) {
        var e = new Error('peer is not reading: ' + socket.writableLength + ' bytes queued');
        e.code = 'ERR_HTTP2_SESSION_MEMORY';
        ev.emit('sessionError', e, connHandle);
        destroy(e);
      }
    });

    // DATA was waiting for the socket; it has room again.
    socket.on('drain', function () { if (!destroyed) h2.flushAll(); });

    h2.on('error', function (err) {
      ev.emit('sessionError', err, connHandle);
      // GOAWAY has already been queued by the connection layer; let it reach
      // the peer before the socket goes, so the client learns why.
      destroy(err, true);
    });

    socket.on('data', function (chunk) {
      if (destroyed) return;
      try { h2.execute(chunk); }
      catch (err) { ev.emit('sessionError', err, connHandle); destroy(err); }
    });

    socket.on('error', function (err) {
      ev.emit('sessionError', err, connHandle);
      destroy(err);
    });

    socket.on('close', function () { destroy(null); });

    // The client half-closes (TCP FIN, or TLS close_notify): it will send
    // nothing more, and still reads (RFC 9293 §3.6; RFC 9113 has nothing
    // against it). The connection was destroyed on the spot, and every
    // response in progress with it. Now: a request whose body was still
    // arriving cannot complete — reset (CANCEL), the request 'aborted';
    // the ones fully received are answered; and when the last stream closes,
    // GOAWAY and our own end. The socket is half-open for this connection
    // only (HTTP/1.1 ends its socket with the client's, as node:http does).
    socket.allowHalfOpen = true;
    var peerEnded = false;
    function finishIfDone() {
      if (destroyed || !peerEnded || h2.activeStreams > 0) return;
      try { h2.sendGoaway(F.ERROR.NO_ERROR); } catch (e) {}
      destroy(null, true);
    }
    socket.on('end', function () {
      if (destroyed) return;
      peerEnded = true;
      if (h2.windowBlocked()) { destroy(null); return; }   // see 'window_blocked' below
      for (var id in streams) {
        var st = streams[id];
        // A tunnel (WebSocket, CONNECT-UDP) cannot go on: nothing more can
        // come from the client on it. Reset and destroyed — left open, it
        // held the connection half-open for good (finishIfDone waits for it).
        if (st.duplex) {
          delete streams[id];
          h2.sendRstStream(Number(id), F.ERROR.CANCEL);
          try { st.duplex.destroy(); } catch (e) {}
          continue;
        }
        if (st.req && !st.req.complete && !st.req.aborted) {
          delete streams[id];
          clearRequestDeadline(st);
          h2.sendRstStream(Number(id), F.ERROR.CANCEL);
          st.req._abort(null);
          if (st.res) st.res._abortResponse();
        }
      }
      finishIfDone();
    });
    h2.on('stream_close', function (id) {
      // A tunnel closed both ways: its entry goes (nothing else removes it —
      // a long-lived connection kept every WebSocket it ever carried).
      var st = streams[id];
      if (st && st.duplex) delete streams[id];
      if (peerEnded) process.nextTick(finishIfDone);
    });
    // A response that waits for the client to open a window, from a client
    // that has half-closed: it sends nothing more — no WINDOW_UPDATE either —
    // so the response can never finish, and the connection would be held
    // open for good (a client that destroyed its socket looks the same until
    // a write reaches it, and none would). Over, as before half-close.
    h2.on('window_blocked', function () {
      if (!peerEnded || destroyed) return;
      process.nextTick(function () { if (!destroyed) destroy(null); });
    });


    // ---- Requests ----

    h2.on('headers', function (streamId, headers, endStream, connectProtocol) {

      // ---- Extended CONNECT (RFC 8441) ----
      //
      // A CONNECT carrying `:protocol` is not a request/response exchange but
      // a bidirectional channel — this is how WebSocket runs over HTTP/2. The
      // application gets it through the SAME 'upgrade' event that HTTP/1.1
      // uses, so a WebSocketServer attached to this server works over both
      // without knowing which carried the connection.
      //
      // What it gets is a Duplex over the stream rather than a socket: reads
      // are DATA frames, writes are DATA frames, and the HTTP/2 connection
      // underneath keeps serving every other stream. That is the whole
      // advantage over HTTP/1.1, where an upgrade consumes the connection.
      if (connectProtocol) {
        var parsedC = pseudoHeadersToRequest(headers);
        var creq = new IncomingMessage({
          httpVersion: '2.0',
          method: 'CONNECT',
          url: parsedC.url,
          headers: parsedC.headers,
          streamId: streamId,
          socket: socket
        });
        creq.rawHeaders = [];
        creq.headers[':protocol'] = connectProtocol;
      }
      // Not taken up: an ordinary request, answered by the handler — as
      // node:http does with an upgrade nobody asked for.
      if (connectProtocol && !shouldUpgradeCallback(creq)) connectProtocol = null;
      if (connectProtocol) {
        creq._endData();

        var stream = makeStreamDuplex(streamId);
        streams[streamId] = { req: creq, res: null, duplex: stream };

        if (ev.listenerCount('upgrade') === 0) {
          // Accepted by shouldUpgradeCallback, yet nobody listens. Where
          // node:http destroys the socket, here only this stream is lost: §4
          // says to answer with an error status rather than leave the client
          // waiting for a 200 that will never come.
          h2.sendHeaders(streamId, [[':status', '501']], true);
          delete streams[streamId];
          return;
        }
        ev.emit('upgrade', creq, stream, Buffer.alloc(0));
        return;
      }

      var parsed = pseudoHeadersToRequest(headers);

      var req = new IncomingMessage({
        httpVersion: '2.0',
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        streamId: streamId,
        socket: socket
      });
      req.scheme = headers[':scheme'];
      req.authority = headers[':authority'];
      // Its HEADERS read from 0-RTT data (TLS early data): see h1_server.
      req.earlyData = socket.isEarlyData === true;
      // Per-connection, not per-request: the same function on every request of
      // a connection returns the same fingerprint, because it describes how
      // the connection was set up.
      req.h2Fingerprint = getFingerprint;

      var res = new ServerResponse({ streamId: streamId, socket: socket });
      res.req = req;
      streams[streamId] = { req: req, res: res };

      // Back-pressure: a Readable that nobody is reading must slow the peer
      // down, and the only lever h2 has is the flow-control window. Credit
      // goes back as the application READS: from _read, which the stream
      // calls when its consumer wants more. Bytes that arrived are counted in
      // (see 'data' below) and returned there.
      //
      // This was a 'data' listener, which says the same in its comment and
      // the opposite in effect: a 'data' listener switches a Readable to
      // flowing, so every body chunk was emitted the moment it arrived — with
      // nobody listening yet if the handler did anything asynchronous before
      // reading the body (an auth check, a lookup). The chunks and the 'end'
      // were lost, and the request waited forever for a body it had already
      // been given. node:http keeps a request paused until someone reads it;
      // so does this now.
      var uncredited = 0;
      req._h2Arrived = function (n) { uncredited += n; };
      req._read = function () {
        if (uncredited > 0) { h2.consume(streamId, uncredited); uncredited = 0; }
      };

      wireResponse(streamId, req, res);

      if (endStream) req._endData();
      else if (req.method !== 'CONNECT') armRequestDeadline(streamId, streams[streamId]);   // a tunnel stays open

      // A handler that throws loses its own stream, reset INTERNAL_ERROR —
      // not the connection, and not the other requests on it (see
      // runRequestHandler). A response it had already ended is left to finish.
      if (maxRequests > 0 && ++served === maxRequests) h2.goaway(F.ERROR.NO_ERROR);
      runRequestHandler(function () {
        if (typeof handler === 'function') handler(req, res);
        ev.emit('request', req, res);
      }, function () {
        if (res.writableEnded || streams[streamId] === undefined) return;
        clearRequestDeadline(streams[streamId]);
        delete streams[streamId];
        h2.sendRstStream(streamId, F.ERROR.INTERNAL_ERROR);
        req._abort(null);
        res._abortResponse();
      });
    });

    h2.on('data', function (streamId, chunk) {
      var st = streams[streamId];
      if (!st) return;
      if (st.duplex) { st.duplex.push(chunk); h2.consume(streamId, chunk.length); return; }
      if (st.req) {
        // Counted before the push: a consumer already reading pulls
        // synchronously from inside it, and _read hands the credit back.
        st.req._h2Arrived(chunk.length);
        st.req._pushData(chunk);
      }
    });

    h2.on('trailers', function (streamId, trailers) {
      var st = streams[streamId];
      if (st && st.req) st.req.trailers = trailers;
    });

    h2.on('end', function (streamId) {
      var st = streams[streamId];
      if (!st) return;
      if (st.duplex) { st.duplex.push(null); return; }
      clearRequestDeadline(st);
      if (st.req) st.req._endData();
      if (st.responseDone) delete streams[streamId];
    });

    h2.on('rst', function (streamId, code) {
      var st = streams[streamId];
      if (!st) return;
      delete streams[streamId];
      clearRequestDeadline(st);
      if (st.duplex) { st.duplex.destroy(); return; }
      abortStream(st, 'stream reset: ' + (F.ERROR_NAME[code] || code),
                  'ERR_HTTP2_STREAM_ERROR');
    });

    /**
     * End a request that the network killed under it.
     *
     * A reset arrives because the PEER cancelled, which is ordinary traffic —
     * a browser navigating away resets every in-flight stream. Destroying the
     * IncomingMessage with an Error means an application that never registered
     * an 'error' handler takes the whole process down with it, and almost none
     * do: node:http teaches people to listen for 'aborted', not 'error'.
     *
     * So: 'aborted' always, an Error only to a listener that asked for one, and
     * the server's own 'streamError' for logging either way. h2spec found this
     * on its fourth test — it resets a stream as a matter of course, and the
     * server died.
     */
    function abortStream(st, message, code) {
      var err = new Error(message);
      err.code = code;

      if (st.req) st.req._abort(err);   // 'aborted', an Error only to a listener, 'close'
      // The response gets 'close' only, as node:http's and node:http2's do
      // when the client goes. An 'error' here was guarded by "a listener
      // asked for it" — but pipe() is such a listener, and rethrows when it
      // is the only one: a client cancelling a piped response took the
      // server down.
      if (st.res) st.res._abortResponse();
      ev.emit('streamError', err, st.req, st.res);
    }

    h2.on('goaway', function () {
      // The client will not open new streams; existing ones run to completion
      // and the socket closes when they do.
      closingConnection = true;
    });

    var closingConnection = false;


    /**
     * A Duplex over one HTTP/2 stream, for extended CONNECT.
     *
     * ws_server was written against a socket: it calls write(), listens for
     * 'data', and destroys when finished. Giving it this instead of a socket
     * is the entire integration — the WebSocket framing code never learns
     * whether its bytes are TCP or DATA frames.
     *
     * The `_h2Accept` hook is the one thing a socket does not have: an HTTP/2
     * extended CONNECT is accepted with a 200 response rather than a 101, so
     * the layer above needs a way to say "accepted" that is not writing bytes.
     */
    function makeStreamDuplex(streamId) {
      var stream = new Duplex({
        read: function () {},
        write: function (chunk, encoding, callback) {
          if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
          var more = h2.sendData(streamId, chunk, false);
          if (more) { callback(); return; }
          // Send window closed: hold the callback so back-pressure reaches
          // whoever is writing, exactly as a socket would.
          var released = false;
          function onDrain(id) {
            if (id !== streamId || released) return;
            released = true;
            h2.off('drain', onDrain);
            callback();
          }
          h2.on('drain', onDrain);
        },
        final: function (callback) {
          h2.sendData(streamId, null, true);
          callback();
        },
        // Destroyed by its user while the stream is open: RST_STREAM CANCEL,
        // so the peer hears the tunnel is gone. (Destroyed by a reset or the
        // connection's end, the entry is already gone and nothing is sent.)
        destroy: function (err, callback) {
          var st = streams[streamId];
          if (st && st.duplex === stream && !destroyed) {
            delete streams[streamId];
            try { h2.sendRstStream(streamId, F.ERROR.CANCEL); } catch (e) {}
          }
          callback(err);
        }
      });

      stream._streamId = streamId;
      stream.encrypted = !!socket.encrypted;
      stream.remoteAddress = socket.remoteAddress;
      stream.remotePort = socket.remotePort;
      stream.setNoDelay = function () { return stream; };
      stream.setKeepAlive = function () { return stream; };
      stream.setTimeout = function () { return stream; };

      /**
       * Accept the extended CONNECT.
       *
       * HTTP/2 has no 101: RFC 8441 §4 says a 2xx response accepts the channel
       * and anything else refuses it. ws_server calls this instead of writing
       * an HTTP/1.1 status line — which is why the WebSocket handshake code
       * has to know which transport it is on for exactly one line, and no more.
       */
      stream._h2Accept = function (extraHeaders) {
        var list = [[':status', '200']];
        for (var n in (extraHeaders || {})) list.push([String(n).toLowerCase(), extraHeaders[n]]);
        h2.sendHeaders(streamId, list, false);
      };

      /** Refuse it, with a status (and fields: a Proxy-Status, say). */
      stream._h2Reject = function (status, message, extraHeaders) {
        var list = [[':status', String(status)]];
        for (var n in (extraHeaders || {})) list.push([String(n).toLowerCase(), String(extraHeaders[n])]);
        h2.sendHeaders(streamId, list, !message);
        if (message) h2.sendData(streamId, Buffer.from(String(message)), true);
        delete streams[streamId];
      };

      return stream;
    }


    // ============================================================
    //  Response wiring
    //
    //  ServerResponse is transport-agnostic — h1_server overrides these same
    //  three hooks to write HTTP/1.1 bytes, h3_server to write H3 frames.
    // ============================================================

    function wireResponse(streamId, req, res) {
      var bodyAllowed = true;
      var finished = false;

      res._flushHeaders = function () {
        if (res.headersSent || res._aborted || destroyed) return;
        var headers = res.getHeaders();
        var code = res.statusCode;

        // HTTP/2 has no reason phrase and no connection-specific fields.
        // buildResponsePseudoHeaders drops the latter; sending them would make
        // the message malformed for the peer and, worse, would be forwarded by
        // a proxy into an HTTP/1.1 hop where they change the framing.
        delete headers['connection'];
        delete headers['keep-alive'];
        delete headers['transfer-encoding'];
        delete headers['upgrade'];

        bodyAllowed = !statusHasNoBody(code) && req.method !== 'HEAD';

        if (!('date' in headers)) headers['date'] = httpDate();
        // A function when the server was built before its port was known —
        // the unified server builds its layers at creation and learns the
        // port from listen(), or from options.port when fed from outside.
        var altSvcNow = typeof altSvc === 'function' ? altSvc() : altSvc;
        if (altSvcNow && !('alt-svc' in headers)) headers['alt-svc'] = altSvcNow;

        var list = buildResponsePseudoHeaders(code, headers);
        try { h2.sendHeaders(streamId, list, false); }
        catch (e) { destroy(e); return; }
        res.headersSent = true;
      };

      res._write = function (chunk, encoding, callback) {
        // The peer reset this stream while the handler was still producing.
        // Discard rather than error: the handler is mid-flight and cannot be
        // expected to check on every write.
        if (res._aborted || destroyed) { callback(); return; }
        if (!res.headersSent) res._flushHeaders();
        if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);

        // A HEAD response, or a bodiless status: the application still wrote
        // the body it WOULD have sent, and the headers already describe it.
        if (!bodyAllowed) { callback(); return; }

        var more = h2.sendData(streamId, chunk, false);
        if (more) { callback(); return; }

        // The send window is closed. Hold the callback until it reopens —
        // that is what makes res.write() return false and a piped Readable
        // pause, instead of queueing the whole body in memory.
        var released = false;
        function onDrain(id) {
          if (id !== streamId || released) return;
          released = true;
          h2.off('drain', onDrain);
          callback();
        }
        h2.on('drain', onDrain);
      };

      res._final = function (callback) {
        if (res._aborted || destroyed) { callback(); return; }
        if (finished) { callback(); return; }
        finished = true;
        if (!res.headersSent) res._flushHeaders();
        var trailers = trailerFields(res.trailers);
        if (trailers) {
          h2.sendTrailers(streamId, trailers);
        } else {
          h2.sendData(streamId, null, true);
        }
        // The entry goes when the request is over too. Removed here, with the
        // request body still arriving — an application reading it after
        // answering — every DATA frame after the response was dropped, its
        // flow-control credit never returned, and the client's upload stalled.
        var st = streams[streamId];
        if (st) {
          st.responseDone = true;
          if (req.complete || req.aborted) delete streams[streamId];
        }
        callback();
      };

      /**
       * 103 Early Hints (RFC 8297): a HEADERS frame with :status 103, the
       * stream left open — the final response follows on it. node:http2's
       * signature: (hints, callback). Nothing once the head has gone.
       */
      res.writeEarlyHints = function (hints, callback) {
        if (!res.headersSent && !res._aborted && !destroyed) {
          var h = {};
          for (var n in (hints || {})) {
            if (Object.prototype.hasOwnProperty.call(hints, n) && hints[n] != null) h[String(n).toLowerCase()] = hints[n];
          }
          try { h2.sendHeaders(streamId, buildResponsePseudoHeaders(103, h), false); }
          catch (e) { /* the stream went; the final response will find out */ }
        }
        if (typeof callback === 'function') process.nextTick(callback);
      };

      /**
       * The response's priority, as the server decides it: { urgency (0..7,
       * 0 first), incremental } — RFC 9218, as h3_server's. It replaces what
       * the client asked for, and later requests from it do not override it.
       */
      res.setPriority = function (p) { h2.setStreamPriority(streamId, responsePriority(p)); };

      /** Reset the stream — the HTTP/2 way to abandon a response. */
      res.destroyStream = function (code) {
        h2.sendRstStream(streamId, code === undefined ? F.ERROR.CANCEL : code);
        clearRequestDeadline(streams[streamId]);
        delete streams[streamId];
      };

      // The application giving the exchange up — res.destroy([err]),
      // req.destroy([err]), either of which ends the stream on node:http2:
      // the response unfinished, RST_STREAM CANCEL (INTERNAL_ERROR for a
      // failure of ours); complete, RST_STREAM NO_ERROR for the rest of the
      // request body (RFC 9113 §8.1). It was local only: the client waited
      // for a response that would not come, the stream open until the
      // connection closed.
      var giveUp = function (err) {
        if (destroyed || !streams[streamId]) return;
        if (!finished) res.destroyStream(err ? F.ERROR.INTERNAL_ERROR : F.ERROR.CANCEL);
        else if (!req.complete) res.destroyStream(F.ERROR.NO_ERROR);
      };
      res._onDestroy(giveUp);
      req._onDestroy(function (err) { if (!res.writableFinished && !res.destroyed) res.destroy(err); else giveUp(err); });
    }

    // The client speaks first, but the server's SETTINGS must go out
    // immediately — a client may not send anything until it has ours.
    h2.sendPreface();
  }


  // ============================================================
  //  Listening
  //
  //  Convenience only, for an h2-only server. The unified server builds one
  //  tcp_listener and registers this handleConnection under 'h2' alongside
  //  h1_server's under 'http/1.1'.
  // ============================================================

  function listen(port, host, callback) {
    if (typeof host === 'function') { callback = host; host = undefined; }

    listener = createTcpListener({
      tls: options.tls,
      key: options.key,
      cert: options.cert,
      ca: options.ca,
      SNICallback: options.SNICallback
    });
    listener.register('h2', handleConnection);
    listener.on('error', function (err) { ev.emit('error', err); });
    listener.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
    listener.on('tlsClientError', function (err, sock) { ev.emit('tlsClientError', err, sock); });
    listener.listen(port, host, function () {
      ev.emit('listening');
      if (typeof callback === 'function') callback();
    });
    return server;
  }

  function close(callback) {
    closing = true;
    if (!listener) {
      for (var s of connections) { try { s.end(); } catch (e) {} }
      if (callback) callback();
      return;
    }
    listener.close(callback);
  }


  var server = {
    listen: listen,
    close: close,
    address: function () { return listener && listener.address ? listener.address() : null; },
    handleConnection: handleConnection,
    on: function (n, f) { ev.on(n, f); return server; },
    once: function (n, f) { ev.once(n, f); return server; },
    off: function (n, f) { ev.off(n, f); return server; },
    emit: function () { ev.emit.apply(ev, arguments); return server; },
    listenerCount: function (n) { return ev.listenerCount(n); }
  };

  return server;
}


export { createServer, STREAM_REFUSED, STREAM_CANCELLED, CONN_OVERLOADED };