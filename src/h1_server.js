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

import { H1Parser, buildResponseHead, encodeChunk, encodeLastChunk } from './h1.js';
import { corkForTick, STATUS_TEXT, runRequestHandler, DEFAULT_HEADERS_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, maxRequestsPerSocket, trailerFields, statusHasNoBody, httpDate } from './http_common.js';
import { IncomingMessage, ServerResponse } from './streams.js';
import { createTcpListener } from './tcp_listener.js';


// ============================================================
//  HTTP/1.1 server.
//
//  Layered exactly like h3_server on top of quic_server: the transport below
//  (net, or lemon-tls's TLSSocket over net) hands us a Duplex per peer, h1.js
//  turns its bytes into messages, and streams.js wraps those in the
//  IncomingMessage / ServerResponse pair every framework expects. Nothing here
//  parses HTTP and nothing in h1.js touches a socket.
//
//  TLS comes from lemon-tls, not node:tls — that is the whole point of
//  replacing node:https. `options.tls` carries the credentials; without it the
//  server speaks cleartext (http://, ws://), which is what a local dev server
//  or a service behind a terminating proxy wants.
// ============================================================


// A peer that opens a connection and then says nothing — or sends a head one
// byte at a time — costs us a socket and a buffer for as long as we let it.
// h1.js deliberately cannot help here: an incomplete head is indistinguishable
// from a slow one, and it has no clock. The clock lives here. (The headers and
// request defaults are every version's: http_common.)
var DEFAULT_KEEPALIVE_TIMEOUT = 5 * 1000;


// The hints as header fields: names lowercased, and only real values.
// Everything else about them (which links, which rels) is the caller's.
function earlyHintHeaders(hints) {
  var out = {};
  for (var n in (hints || {})) {
    if (!Object.prototype.hasOwnProperty.call(hints, n)) continue;
    var v = hints[n];
    if (v === undefined || v === null || (Array.isArray(v) && v.length === 0)) continue;
    out[String(n).toLowerCase()] = v;
  }
  return out;
}


function createServer(options, handler) {
  if (typeof options === 'function') { handler = options; options = {}; }
  options = options || {};

  var ev = new EventEmitter();
  var tcpServer = null;
  var connections = new Set();
  var closing = false;

  var headersTimeout = options.headersTimeout != null ? options.headersTimeout : DEFAULT_HEADERS_TIMEOUT;
  var keepAliveTimeout = options.keepAliveTimeout != null ? options.keepAliveTimeout : DEFAULT_KEEPALIVE_TIMEOUT;
  var requestTimeout = options.requestTimeout != null ? options.requestTimeout : DEFAULT_REQUEST_TIMEOUT;
  // maxHeaderSize is node:http's name for the same limit.
  var maxHeadSize = options.maxHeadSize || options.maxHeaderSize;
  var maxHeaderCount = options.maxHeaderCount;
  // node:http's: the Nth response says Connection: close and the connection
  // ends after it; a request past it (pipelined) is answered 503.
  var maxRequests = maxRequestsPerSocket(options.maxRequestsPerSocket);

  // Advertised on every response so a client learns HTTP/3 is available on the
  // same authority (RFC 9114 §3.3). The unified server sets it; a standalone
  // h1 server has nothing to advertise.
  var altSvc = options.altSvc || null;

  // node:http's shouldUpgradeCallback(request): whether an upgrade request
  // reaches 'upgrade' (true) or is handled as an ordinary 'request' (false).
  // Node's default, and ours: true when something listens for 'upgrade'.
  // It used to be answered 501 when nothing did — a refusal Node never gives.
  var shouldUpgradeCallback = typeof options.shouldUpgradeCallback === 'function'
    ? options.shouldUpgradeCallback
    : function () { return ev.listenerCount('upgrade') > 0; };


  // ============================================================
  //  One connection
  // ============================================================

  function handleConnection(socket) {
    if (closing) { socket.destroy(); return; }
    connections.add(socket);

    var parser = new H1Parser({
      isServer: true,
      maxHeadSize: maxHeadSize,
      maxHeaderCount: maxHeaderCount,
      // The request as the callback sees it: method, url, headers — what
      // node:http's IncomingMessage carries at that point.
      shouldUpgrade: function (info) {
        return shouldUpgradeCallback({
          method: info.method, url: info.url, headers: info.headers,
          rawHeaders: info.rawHeaders, httpVersion: info.httpVersion, socket: socket
        });
      }
    });

    var current = null;        // { req, res, info }
    var served = 0;            // requests seen on this connection (maxRequestsPerSocket)
    var destroyed = false;
    var timer = null;

    function setTimer(ms, reason) {
      clearTimer();
      if (!ms || ms <= 0) return;
      timer = setTimeout(function () {
        timer = null;
        // Nothing is half-written at this point in the states we arm the timer
        // for, so a hard destroy is honest: a 408 to a peer that has sent no
        // complete request may itself never be read.
        // requestTimeout with nothing answered yet: a 408 too, as node:http.
        if ((reason === 'headers' && !current) || (reason === 'request' && current && !current.res.headersSent)) {
          try { socket.end(buildResponseHead(408, null, { 'Connection': 'close', 'Content-Length': '0' })); }
          catch (e) {}
        }
        destroy(new Error('timeout: ' + reason));
      }, ms);
      if (timer.unref) timer.unref();
    }
    function clearTimer() { if (timer) { clearTimeout(timer); timer = null; } }

    function destroy(err) {
      if (destroyed) return;
      destroyed = true;
      clearTimer();
      connections.delete(socket);
      if (current && current.req && !current.req.complete) current.req._abort(err || null);
      if (current && current.res) current.res._abortResponse();   // see ServerResponse
      try { socket.destroy(); } catch (e) {}
    }

    // Waiting for the first byte of the first request.
    setTimer(headersTimeout, 'headers');


    // ---- Reading ----

    socket.on('data', function (chunk) {
      if (destroyed) return;
      // A request is arriving: not idle (closeIdleConnections, close()).
      socket._quicoBusy = true;

      try {
        parser.execute(chunk);
      } catch (err) {
        // h1.js reports parse failures via 'error'. A throw from here is a bug
        // in a listener (a handler that threw synchronously), not bad input.
        ev.emit('clientError', err, socket);
        destroy(err);
      }
    });

    function resumeParsing() {
      if (destroyed) return;
      holdForResponse = false;
      updateReading();
      try { parser.resume(); }
      catch (err) { ev.emit('clientError', err, socket); destroy(err); }
    }

    // Reading from the socket stops while nothing would take what it brings,
    // as node:http does it — the kernel's buffer fills, and TCP slows the
    // client down:
    //   holdForReader    the request body is not being read: the
    //                    IncomingMessage's buffer is full (push() said so),
    //                    until it asks for more (_read).
    //   holdForResponse  the request is complete and its response is not:
    //                    what follows is the next request, not looked at
    //                    until then (pipelining, RFC 9112 §9.3).
    // Neither stopped the socket. The parser took everything in — a body
    // the handler had not started reading (it was waiting on a lookup, say)
    // was held in memory as fast as the client could send it, hundreds of MB
    // in seconds; so were pipelined bytes behind a slow response.
    var holdForReader = false, holdForResponse = false;
    function updateReading() {
      if (destroyed) return;
      if (holdForReader || holdForResponse) { if (!socket.isPaused()) socket.pause(); }
      else if (socket.isPaused()) socket.resume();
    }

    socket.on('error', function (err) {
      // A peer that vanishes mid-request is ordinary, not exceptional; surface
      // it for logging but never let it reach an uncaught handler.
      ev.emit('clientError', err, socket);
      destroy(err);
    });

    socket.on('close', function () { destroy(null); });

    socket.on('end', function () {
      // The peer half-closed. Anything mid-message is truncated; the parser
      // decides which.
      try { parser.eof(); } catch (e) {}
    });


    // ---- Parser events ----

    parser.on('error', function (err) {
      ev.emit('clientError', err, socket);

      // Answer if we still can. A framing failure means we no longer know where
      // the next message starts, so the connection always closes after this.
      if (!destroyed && socket.writable) {
        var code = err.statusCode || 400;
        if (options.stats) options.stats.status(options.stats.closes.http1.sent, code);
        try {
          socket.end(buildResponseHead(code, null, {
            'Connection': 'close',
            'Content-Length': '0'
          }));
        } catch (e) {}
      }
      destroy(err);
    });

    parser.on('headers', function (info) {
      socket._quicoBusy = true;
      clearTimer();
      setTimer(requestTimeout, 'request');
      served++;
      if (maxRequests > 0 && served > maxRequests) {
        // Past the limit (node:http: "subsequent requests ... will get 503").
        try {
          socket.end(buildResponseHead(503, null, { 'Connection': 'close', 'Content-Length': '0' }));
        } catch (e) {}
        destroy(null);
        return;
      }

      var req = new IncomingMessage({
        httpVersion: info.httpVersion,
        method: info.method,
        url: info.url,
        headers: info.headers,
        socket: socket
      });
      req.rawHeaders = info.rawHeaders;
      req.complete = false;
      // Read whole from 0-RTT data (TLS early data): it could be a replay
      // (server.js holds it to earlyDataFilter). A request completed by
      // bytes after the handshake cannot be replayed, and is not early.
      req.earlyData = socket.isEarlyData === true;

      var res = new ServerResponse({ socket: socket });
      res.req = req;
      // res.destroy([err]) / req.destroy([err]) by the application, the
      // response unfinished: the socket goes, as on node:http — the only way
      // HTTP/1.1 has to say the response will not be completed. It stayed
      // open, and the client waited for the rest.
      res._onDestroy(function () { destroy(null); });
      req._onDestroy(function (err) { if (!res.writableFinished && !res.destroyed) res.destroy(err); });
      // The reader wants more: reading from the socket goes on (see
      // holdForReader).
      req._read = function () {
        if (holdForReader && current && current.req === req) { holdForReader = false; updateReading(); }
      };

      current = { req: req, res: res, info: info };
      wireResponse(info, req, res, maxRequests > 0 && served >= maxRequests);

      // Expect: 100-continue (RFC 9110 §10.1.1). The client is waiting for
      // permission before sending the body; if we never answer, it stalls for
      // its own timeout and then sends anyway. Default to allowing it, and let
      // a 'checkContinue' listener take over when one is registered — the same
      // split node:http makes.
      var expect = String(info.headers['expect'] || '').toLowerCase();
      if (expect === '100-continue') {
        if (ev.listenerCount('checkContinue') > 0) {
          runRequestHandler(function () { ev.emit('checkContinue', req, res); }, handlerFailed);
          return;   // the listener owns the exchange from here
        }
        try { socket.write('HTTP/1.1 100 Continue\r\n\r\n'); } catch (e) {}
      }

      // No special case for info.upgrade here any more. A request that will
      // actually switch protocols never reaches this handler — h1.js emits
      // 'upgrade' instead of 'headers' for those. What DOES reach it is an
      // Upgrade request that cannot switch, such as one carrying a body: that
      // is an ordinary request the application should answer (and probably
      // ignore the Upgrade on), not one to drop on the floor. The early return
      // that used to sit here hung exactly those.
      runRequestHandler(function () {
        if (typeof handler === 'function') handler(req, res);
        ev.emit('request', req, res);
      }, handlerFailed);

      // The handler threw (see runRequestHandler): a 500 if nothing has been
      // sent yet, and the connection closed — the response may be half
      // written, and nothing after it on this connection can be trusted to
      // line up. A response it had already ended is left to finish.
      function handlerFailed() {
        if (destroyed || res.writableEnded) return;
        if (!res.headersSent && socket.writable) {
          try {
            socket.end(buildResponseHead(500, null, { 'Connection': 'close', 'Content-Length': '0' }));
          } catch (e) {}
        }
        destroy(null);
      }
    });

    parser.on('body', function (chunk) {
      var req = current && current.req;
      if (!req) return;
      // Destroyed by the application: it will read no more. Dropped, and
      // reading goes on — a body nobody reads must not stop the connection.
      if (req.destroyed) return;
      if (req._pushData(chunk) === false && !holdForReader) {
        holdForReader = true;
        updateReading();
      }
    });

    parser.on('trailers', function (trailers) {
      if (current && current.req) current.req.trailers = trailers;
    });

    parser.on('end', function () {
      // requestTimeout bounds the request's arrival, as node:http's does —
      // not the response: a long download or an event stream runs as long as
      // the application keeps writing. It ran until the response was done,
      // harmless while the default was 0 (none), not with node's 300 s.
      clearTimer();

      // The request is complete. Stop looking at anything after it until its
      // response is on the wire — pipelined request N+1 must not be handled
      // before response N is sent. Pausing here rather than at 'headers' is
      // the difference between "do not read ahead" and "do not read the body
      // of the request we are answering", and the latter deadlocks any client
      // that waits for 100-continue.
      if (current && !current.res.finished) { parser.pause(); holdForResponse = true; updateReading(); }
      if (current && current.req) current.req._endData();
    });

    parser.on('upgrade', function (info, head) {
      clearTimer();

      var req = new IncomingMessage({
        httpVersion: info.httpVersion,
        method: info.method,
        url: info.url,
        headers: info.headers,
        socket: socket
      });
      req.rawHeaders = info.rawHeaders;
      req.upgrade = true;
      req._endData();

      // Hand the raw socket over, exactly as node:http does. `head` is the
      // bytes that arrived after the request head and already belong to the
      // new protocol — a WebSocket client may put its first frame in the same
      // TCP segment as the handshake, and dropping it loses that frame.
      //
      // From here we own nothing: no parser, no timers, no keep-alive.
      connections.delete(socket);
      destroyed = true;         // stop our own handlers touching the socket
      clearTimer();
      socket.removeAllListeners('data');
      socket.removeAllListeners('end');

      if (ev.listenerCount('upgrade') === 0) {
        // Accepted by shouldUpgradeCallback, yet nobody listens: as node:http
        // does, the socket is destroyed — the request is half-switched, and
        // there is no one to finish the job.
        try { socket.destroy(); } catch (e) {}
        return;
      }

      ev.emit('upgrade', req, socket, head);
    });


    // ============================================================
    //  Response wiring
    //
    //  ServerResponse is transport-agnostic (h3_server overrides the same
    //  three hooks to write H3 frames). Here they become HTTP/1.1 bytes.
    // ============================================================

    function wireResponse(info, req, res, lastOnSocket) {
      var chunked = false;
      var bodyAllowed = true;
      var willClose = !!lastOnSocket;   // maxRequestsPerSocket reached: this one closes it
      var finished = false;

      res._flushHeaders = function () {
        if (res.headersSent) return;

        var headers = res.getHeaders();
        var code = res.statusCode;

        // Status codes that define themselves as bodiless, plus HEAD, whose
        // response carries the headers of the body it is not sending.
        var bodiless = statusHasNoBody(code);
        bodyAllowed = !bodiless && info.method !== 'HEAD';

        // A bodiless status must not carry framing headers at all: a
        // Content-Length on a 204 makes some clients wait for a body that is
        // never coming.
        if (bodiless) {
          delete headers['content-length'];
          delete headers['transfer-encoding'];
        }

        // Framing, in the order RFC 9112 §6 resolves it.
        if (!bodiless) {
          if ('transfer-encoding' in headers) {
            chunked = String(headers['transfer-encoding']).toLowerCase().indexOf('chunked') !== -1;
          } else if ('content-length' in headers) {
            chunked = false;
          } else if (res._endLength !== undefined) {
            // The whole body was given to end() with nothing written before
            // it: its length is known, and sent — as node:http does. It was
            // chunked: res.end('hello') cost a chunk header and a terminating
            // chunk, and a client could not tell the size before it arrived.
            headers['content-length'] = String(res._endLength);
            chunked = false;
          } else if (info.httpVersion === '1.1' && info.keepAlive) {
            // Length unknown and the connection is reusable, so chunk it —
            // otherwise the only way to delimit the body is to close, and
            // keep-alive is lost for no reason.
            headers['transfer-encoding'] = 'chunked';
            chunked = true;
          } else {
            // HTTP/1.0, or the client asked to close: the body ends when the
            // connection does. (1.0 has no chunked encoding.)
            willClose = true;
          }
        }

        // Connection header. `keepAlive` already accounts for the client's
        // Connection: close and for HTTP/1.0 semantics.
        var keepAlive = info.keepAlive && !willClose && !closing;
        if (String(headers['connection'] || '').toLowerCase() === 'close') keepAlive = false;

        headers['connection'] = keepAlive ? 'keep-alive' : 'close';
        willClose = !keepAlive;

        if (keepAlive && info.httpVersion === '1.0') headers['keep-alive'] = 'timeout=5';
        if (!('date' in headers) && res.sendDate !== false) headers['date'] = httpDate();
        // A function when the server was built before its port was known —
        // the unified server builds its layers at creation and learns the
        // port from listen(), or from options.port when fed from outside.
        var altSvcNow = typeof altSvc === 'function' ? altSvc() : altSvc;
        if (altSvcNow && !('alt-svc' in headers)) headers['alt-svc'] = altSvcNow;

        // The application's reason phrase, else the standard one for the code
        // — and statusMessage then says what was sent, as node:http does.
        var reason = res.statusMessage || STATUS_TEXT[code] || '';
        res.statusMessage = reason;
        var head = buildResponseHead(code, reason, headers);
        // Corked: the head and the body written after it in this tick — all
        // of res.end(body) — leave as one segment, not one each.
        corkForTick(socket);
        try { socket.write(head); } catch (e) { destroy(e); return; }
        res.headersSent = true;
      };

      // 103 Early Hints before the response (RFC 8297): an interim response,
      // written whole before the final head. HTTP/1.0 has no interim
      // responses, and after the head it is too late — both send nothing.
      // node:http's signature: (hints, callback).
      res.writeEarlyHints = function (hints, callback) {
        var ok = !res.headersSent && info.httpVersion !== '1.0' && !destroyed;
        if (ok) {
          try { socket.write(buildResponseHead(103, null, earlyHintHeaders(hints))); }
          catch (e) { ok = false; }
        }
        if (typeof callback === 'function') process.nextTick(callback);
      };

      // 102 Processing (node:http's writeProcessing): an interim response,
      // as Early Hints are.
      res.writeProcessing = function () {
        if (res.headersSent || info.httpVersion === '1.0' || destroyed) return;
        try { socket.write(buildResponseHead(102, null, {})); } catch (e) {}
      };

      res._write = function (chunk, encoding, callback) {
        if (!res.headersSent) res._flushHeaders();
        if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);

        // A HEAD response, or a bodiless status, must send no body — but the
        // application still wrote one, and that is fine: it wrote the body it
        // WOULD have sent. Swallow the bytes; the headers already described
        // them.
        if (!bodyAllowed) { callback(); return; }

        var ok = true;
        try {
          if (!chunked) ok = socket.write(chunk);
          else {
            var parts = encodeChunk(chunk);
            if (parts.length) corkForTick(socket);
            for (var i = 0; i < parts.length; i++) ok = socket.write(parts[i]);
          }
        } catch (e) { callback(e); return; }

        // Respect back-pressure: without this a fast producer piped into a slow
        // client buffers the whole body in memory.
        if (ok) callback();
        else socket.once('drain', callback);
      };

      res._final = function (callback) {
        if (finished) { callback(); return; }
        finished = true;
        if (!res.headersSent) res._flushHeaders();

        try {
          if (bodyAllowed && chunked) socket.write(encodeLastChunk(trailerFields(res.trailers)));
        } catch (e) { callback(e); return; }

        callback();
        onResponseComplete();
      };

      function onResponseComplete() {
        clearTimer();
        current = null;
        socket._quicoBusy = false;
        // Whatever of the body is still to come is dropped from here on (the
        // parser reads it, to find the next request): the reader no longer
        // holds the socket back.
        holdForReader = false;
        updateReading();

        if (willClose || closing) {
          // Half-close: let the peer read what we wrote before the socket goes.
          try { socket.end(); } catch (e) {}
          return;
        }

        // Ready for the next request on this connection.
        setTimer(keepAliveTimeout, 'keep-alive');
        resumeParsing();
      }
    }
  }


  // ============================================================
  //  Listening
  // ============================================================

  // ============================================================
  //  Listening
  //
  //  Sockets, TLS and ALPN belong to tcp_listener, which h2_server and
  //  ws_server share — a client picks between them with ALPN, and that choice
  //  has to be made in one place or the three ALPN lists drift apart. What
  //  remains here is a convenience: an h1-only server that owns its listener,
  //  so this file can still be used (and tested) on its own.
  //
  //  The unified server does NOT call this. It builds one listener, registers
  //  handleConnection under 'http/1.1', and registers h2_server's under 'h2'.
  // ============================================================

  function listen(port, host, callback) {
    if (typeof host === 'function') { callback = host; host = undefined; }

    tcpServer = createTcpListener({
      tls: options.tls,
      key: options.key,
      cert: options.cert,
      ca: options.ca,
      SNICallback: options.SNICallback
    });
    tcpServer.register('http/1.1', handleConnection, { managesClose: true });
    tcpServer.on('error', function (err) { ev.emit('error', err); });
    tcpServer.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
    tcpServer.on('tlsClientError', function (err, sock) { ev.emit('tlsClientError', err, sock); });
    tcpServer.listen(port, host, function () {
      ev.emit('listening');
      if (typeof callback === 'function') callback();
    });
    return server;
  }

  // ---- Closing, as node:http ----
  //
  // Idle: a connection between requests (or before its first) — no request
  // arriving, no response being written. Closing one costs nothing.
  function closeIdleConnections() {
    for (var s of connections) if (!s._quicoBusy) { try { s.destroy(); } catch (e) {} }
  }
  // All, mid-request too. Not the sockets handed to 'upgrade' (a WebSocket):
  // those left this server at the upgrade, as in node:http.
  function closeAllConnections() {
    for (var s of connections) { try { s.destroy(); } catch (e) {} }
  }
  // No new connections, the idle ones closed; each busy one closes as its
  // response completes (onResponseComplete). It used to end every socket at
  // once: a response being written was cut off.
  function beginClose() {
    closing = true;
    closeIdleConnections();
  }

  function close(callback) {
    beginClose();
    if (!tcpServer) { if (callback) callback(); return; }
    tcpServer.close(callback);
  }

  // node:http's timeouts and limits, changed while the server runs: from
  // the next request (or connection) on.
  function setLimits(o) {
    if (o.headersTimeout !== undefined) headersTimeout = o.headersTimeout;
    if (o.keepAliveTimeout !== undefined) keepAliveTimeout = o.keepAliveTimeout;
    if (o.requestTimeout !== undefined) requestTimeout = o.requestTimeout;
    if (o.maxHeaderCount !== undefined) maxHeaderCount = o.maxHeaderCount;
    if (o.maxRequestsPerSocket !== undefined) maxRequests = maxRequestsPerSocket(o.maxRequestsPerSocket);
  }

  function address() {
    return tcpServer && tcpServer.address ? tcpServer.address() : null;
  }

  var server = {
    listen: listen,
    close: close,
    address: address,
    on: function (n, f) { ev.on(n, f); return server; },
    once: function (n, f) { ev.once(n, f); return server; },
    off: function (n, f) { ev.off(n, f); return server; },
    removeListener: function (n, f) { ev.removeListener(n, f); return server; },
    emit: function () { ev.emit.apply(ev, arguments); return server; },
    listenerCount: function (n) { return ev.listenerCount(n); },
    setTimeout: function (ms) { headersTimeout = ms; return server; },
    closeIdleConnections: closeIdleConnections,
    closeAllConnections: closeAllConnections,
    beginClose: beginClose,
    setLimits: setLimits,
    get connectionCount() { return connections.size; },

    /** Attach an already-connected Duplex, bypassing the listener. Lets the
     *  unified server share one TCP port, and makes the whole stack testable
     *  without binding anything. */
    handleConnection: handleConnection
  };

  return server;
}


export { createServer };
