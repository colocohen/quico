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
import { STATUS_TEXT } from './http_common.js';
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
// from a slow one, and it has no clock. The clock lives here.
var DEFAULT_HEADERS_TIMEOUT = 60 * 1000;
var DEFAULT_KEEPALIVE_TIMEOUT = 5 * 1000;
var DEFAULT_REQUEST_TIMEOUT = 0;          // 0 = no limit on a whole request


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
  var maxHeadSize = options.maxHeadSize;
  var maxHeaderCount = options.maxHeaderCount;

  // Advertised on every response so a client learns HTTP/3 is available on the
  // same authority (RFC 9114 §3.3). The unified server sets it; a standalone
  // h1 server has nothing to advertise.
  var altSvc = options.altSvc || null;


  // ============================================================
  //  One connection
  // ============================================================

  function handleConnection(socket) {
    if (closing) { socket.destroy(); return; }
    connections.add(socket);

    var parser = new H1Parser({
      isServer: true,
      maxHeadSize: maxHeadSize,
      maxHeaderCount: maxHeaderCount
    });

    var current = null;        // { req, res, info }
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
        if (reason === 'headers' && !current) {
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
      try { socket.destroy(); } catch (e) {}
    }

    // Waiting for the first byte of the first request.
    setTimer(headersTimeout, 'headers');


    // ---- Reading ----

    socket.on('data', function (chunk) {
      if (destroyed) return;

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
      try { parser.resume(); }
      catch (err) { ev.emit('clientError', err, socket); destroy(err); }
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
      clearTimer();
      setTimer(requestTimeout, 'request');

      var req = new IncomingMessage({
        httpVersion: info.httpVersion,
        method: info.method,
        url: info.url,
        headers: info.headers,
        socket: socket
      });
      req.rawHeaders = info.rawHeaders;
      req.complete = false;

      var res = new ServerResponse({ socket: socket });
      res.req = req;

      current = { req: req, res: res, info: info };
      wireResponse(info, req, res);

      // Expect: 100-continue (RFC 9110 §10.1.1). The client is waiting for
      // permission before sending the body; if we never answer, it stalls for
      // its own timeout and then sends anyway. Default to allowing it, and let
      // a 'checkContinue' listener take over when one is registered — the same
      // split node:http makes.
      var expect = String(info.headers['expect'] || '').toLowerCase();
      if (expect === '100-continue') {
        if (ev.listenerCount('checkContinue') > 0) {
          ev.emit('checkContinue', req, res);
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
      if (typeof handler === 'function') handler(req, res);
      ev.emit('request', req, res);
    });

    parser.on('body', function (chunk) {
      if (current && current.req) current.req._pushData(chunk);
    });

    parser.on('trailers', function (trailers) {
      if (current && current.req) current.req.trailers = trailers;
    });

    parser.on('end', function () {
      // The request is complete. Stop looking at anything after it until its
      // response is on the wire — pipelined request N+1 must not be handled
      // before response N is sent. Pausing here rather than at 'headers' is
      // the difference between "do not read ahead" and "do not read the body
      // of the request we are answering", and the latter deadlocks any client
      // that waits for 100-continue.
      if (current && !current.res.finished) parser.pause();
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
        // Nobody wants it. RFC 9110 §15.4.7: refuse rather than leave the
        // client waiting for a 101 that will never come.
        try {
          socket.end(buildResponseHead(501, null, { 'Connection': 'close', 'Content-Length': '0' }));
        } catch (e) {}
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

    function wireResponse(info, req, res) {
      var chunked = false;
      var bodyAllowed = true;
      var willClose = false;
      var finished = false;

      res._flushHeaders = function () {
        if (res.headersSent) return;

        var headers = res.getHeaders();
        var code = res.statusCode;

        // Status codes that define themselves as bodiless, plus HEAD, whose
        // response carries the headers of the body it is not sending.
        var bodiless = (code >= 100 && code < 200) || code === 204 || code === 304;
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
        if (!('date' in headers)) headers['date'] = new Date().toUTCString();
        if (altSvc && !('alt-svc' in headers)) headers['alt-svc'] = altSvc;

        var head = buildResponseHead(code, res.statusMessage || STATUS_TEXT[code], headers);
        try { socket.write(head); } catch (e) { destroy(e); return; }
        res.headersSent = true;
      };

      res._write = function (chunk, encoding, callback) {
        if (!res.headersSent) res._flushHeaders();
        if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);

        // A HEAD response, or a bodiless status, must send no body — but the
        // application still wrote one, and that is fine: it wrote the body it
        // WOULD have sent. Swallow the bytes; the headers already described
        // them.
        if (!bodyAllowed) { callback(); return; }

        var ok;
        try { ok = socket.write(chunked ? encodeChunk(chunk) : chunk); }
        catch (e) { callback(e); return; }

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
          if (bodyAllowed && chunked) socket.write(encodeLastChunk(res.trailers));
        } catch (e) { callback(e); return; }

        callback();
        onResponseComplete();
      };

      function onResponseComplete() {
        clearTimer();
        current = null;

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
    tcpServer.register('http/1.1', handleConnection);
    tcpServer.on('error', function (err) { ev.emit('error', err); });
    tcpServer.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
    tcpServer.listen(port, host, function () {
      ev.emit('listening');
      if (typeof callback === 'function') callback();
    });
    return server;
  }

  function close(callback) {
    closing = true;
    if (!tcpServer) {
      // Sockets we were handed rather than accepted: still ours to close.
      for (var s of connections) { try { s.end(); } catch (e) {} }
      if (callback) callback();
      return;
    }
    tcpServer.close(callback);
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

    /** Attach an already-connected Duplex, bypassing the listener. Lets the
     *  unified server share one TCP port, and makes the whole stack testable
     *  without binding anything. */
    handleConnection: handleConnection
  };

  return server;
}


export { createServer };
