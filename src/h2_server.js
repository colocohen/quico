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

import { H2Connection } from './h2.js';
import * as F from './h2_frames.js';
import { buildResponsePseudoHeaders, pseudoHeadersToRequest, STATUS_TEXT } from './http_common.js';
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


function createServer(options, handler) {
  if (typeof options === 'function') { handler = options; options = {}; }
  options = options || {};

  var ev = new EventEmitter();
  var listener = null;
  var connections = new Set();
  var closing = false;

  var altSvc = options.altSvc || null;


  function handleConnection(socket) {
    if (closing) { try { socket.destroy(); } catch (e) {} return; }

    var h2 = new H2Connection({
      isServer: true,
      maxConcurrentStreams: options.maxConcurrentStreams,
      initialWindowSize: options.initialWindowSize,
      maxFrameSize: options.maxFrameSize,
      maxHeaderListSize: options.maxHeaderListSize,
      headerTableSize: options.headerTableSize,
      // Credit is returned when the application reads, not when the frame
      // arrives. Without this the receive window never closes and a client can
      // push a body far faster than the handler consumes it — the bytes pile
      // up in our heap and flow control does nothing at all.
      autoWindowUpdate: false
    });

    var streams = {};     // id -> { req, res }
    var destroyed = false;

    connections.add(socket);

    function destroy(err) {
      if (destroyed) return;
      destroyed = true;
      connections.delete(socket);
      for (var id in streams) {
        var st = streams[id];
        if (st.req && !st.req.complete) {
          // Same reasoning as abortStream: a peer that vanished must not
          // become an uncaught exception in an application that did not ask
          // to hear about it.
          st.req.aborted = true;
          st.req.emit('aborted');
          if (st.req.listenerCount('error') > 0) st.req._abort(err || null);
          else st.req._abort(null);
        }
      }
      streams = {};
      try { socket.destroy(); } catch (e) {}
    }

    h2.on('send', function (data) {
      if (destroyed || !socket.writable) return;
      try { socket.write(data); } catch (e) { destroy(e); }
    });

    h2.on('error', function (err) {
      ev.emit('clientError', err, socket);
      // GOAWAY has already been queued by the connection layer; let it reach
      // the peer before the socket goes, so the client learns why.
      try { socket.end(); } catch (e) {}
      destroy(err);
    });

    socket.on('data', function (chunk) {
      if (destroyed) return;
      try { h2.execute(chunk); }
      catch (err) { ev.emit('clientError', err, socket); destroy(err); }
    });

    socket.on('error', function (err) {
      ev.emit('clientError', err, socket);
      destroy(err);
    });

    socket.on('close', function () { destroy(null); });
    socket.on('end', function () { destroy(null); });


    // ---- Requests ----

    h2.on('headers', function (streamId, headers, endStream) {
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

      var res = new ServerResponse({ streamId: streamId, socket: socket });
      res.req = req;
      streams[streamId] = { req: req, res: res };

      // Back-pressure: a Readable that nobody is reading must slow the peer
      // down, and the only lever h2 has is the flow-control window. Returning
      // credit as the application consumes is what connects the two.
      req.on('data', function (chunk) { h2.consume(streamId, chunk.length); });

      wireResponse(streamId, req, res);

      if (endStream) req._endData();

      if (typeof handler === 'function') handler(req, res);
      ev.emit('request', req, res);
    });

    h2.on('data', function (streamId, chunk) {
      var st = streams[streamId];
      if (st && st.req) st.req._pushData(chunk);
    });

    h2.on('trailers', function (streamId, trailers) {
      var st = streams[streamId];
      if (st && st.req) st.req.trailers = trailers;
    });

    h2.on('end', function (streamId) {
      var st = streams[streamId];
      if (st && st.req) st.req._endData();
    });

    h2.on('rst', function (streamId, code) {
      var st = streams[streamId];
      if (!st) return;
      delete streams[streamId];
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

      if (st.req) {
        st.req.aborted = true;
        st.req.emit('aborted');
        if (st.req.listenerCount('error') > 0) st.req._abort(err);
        else st.req._abort(null);           // ends the stream without throwing
      }
      if (st.res) {
        st.res._aborted = true;
        if (st.res.listenerCount('error') > 0) st.res.emit('error', err);
        st.res.emit('close');
      }
      ev.emit('streamError', err, st.req, st.res);
    }

    h2.on('goaway', function () {
      // The client will not open new streams; existing ones run to completion
      // and the socket closes when they do.
      closingConnection = true;
    });

    var closingConnection = false;


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

        bodyAllowed = !(code >= 100 && code < 200) && code !== 204 && code !== 304 &&
                      req.method !== 'HEAD';

        if (!('date' in headers)) headers['date'] = new Date().toUTCString();
        if (altSvc && !('alt-svc' in headers)) headers['alt-svc'] = altSvc;

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
        if (res.trailers && Object.keys(res.trailers).length) {
          h2.sendTrailers(streamId, res.trailers);
        } else {
          h2.sendData(streamId, null, true);
        }
        delete streams[streamId];
        callback();
      };

      /** Reset the stream — the HTTP/2 way to abandon a response. */
      res.destroyStream = function (code) {
        h2.sendRstStream(streamId, code === undefined ? F.ERROR.CANCEL : code);
        delete streams[streamId];
      };
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


export { createServer };
