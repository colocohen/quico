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
import fs from 'node:fs';
import lemonTls from 'lemon-tls';

import { createServer as createH3Server } from './h3_server.js';
import { createServer as createH2Server } from './h2_server.js';
import { createServer as createH1Server } from './h1_server.js';
import { createTcpListener } from './tcp_listener.js';
import { IncomingMessage, ServerResponse, _makeSocketStub } from './streams.js';


// ============================================================
//  createServer(options, handler)
//
//  HTTP/3 is always enabled (that's the point of quico).
//  Options:
//    http2: true (default) — TCP with node:http2
//    http1: true (default) — allowHTTP1 on TCP (or standalone if http2:false)
//
//  Combinations:
//    { }                          → H3 + H2 + H1    (default)
//    { http1: false }             → H3 + H2
//    { http2: false }             → H3 + H1
//    { http2: false, http1: false } → H3 only
// ============================================================

function createServer(options, handler) {
  if (typeof options === 'function') { handler = options; options = {}; }
  options = options || {};

  var enableH2 = options.http2 !== false;
  var enableH1 = options.http1 !== false;
  var needsTcp = enableH2 || enableH1;

  var ev = new EventEmitter();
  var port = null;

  // ---- TLS credentials ----
  var tlsKey = options.key || null;
  var tlsCert = options.cert || null;
  var tlsCa = options.ca || null;

  // Read from disk if paths were given (not PEM strings)
  if (typeof tlsKey === 'string' && tlsKey.indexOf('-----') === -1) {
    tlsKey = fs.readFileSync(tlsKey);
  }
  if (typeof tlsCert === 'string' && tlsCert.indexOf('-----') === -1) {
    tlsCert = fs.readFileSync(tlsCert);
  }


  // ============================================================
  //  HTTP/3 — delegates to existing h3_server.js
  //  No duplication: we pass a wrapper handler that converts
  //  plain req/res objects into proper Node.js streams.
  // ============================================================

  var h3Options = {
    key: tlsKey,
    cert: tlsCert,
    ca: tlsCa,
    SNICallback: options.SNICallback || null,
    maxConnections: options.maxConnections || 10000,
    // External UDP sockets (shared UDP port scenario). When provided,
    // the UDP layer is owned externally — caller feeds packets via
    // server.handlePacket(msg, rinfo). See RFC 9443.
    socket:  options.socket  || null,
    socket6: options.socket6 || null
  };

  var isExternalUdp = !!(options.socket || options.socket6);

  var h3srv = createH3Server(h3Options, function (plainReq, plainRes) {
    var socketStub = _makeSocketStub();
    socketStub.remoteAddress = plainReq.remoteAddress || null;
    socketStub.remotePort = plainReq.remotePort || null;

    // ---- Wrap plain req into IncomingMessage (Readable) ----
    var req = new IncomingMessage({
      httpVersion: '3.0',
      method: plainReq.method,
      url: plainReq.url,
      headers: plainReq.headers || {},
      streamId: plainReq.stream_id,
      socket: socketStub
    });

    // Bridge data from plain req → IncomingMessage
    plainReq.on('data', function (chunk) { req._pushData(chunk); });
    plainReq.on('end', function () { req._endData(); });

    // ---- Wrap plain res into ServerResponse (Writable) ----
    // ServerResponse._write → plainRes.write
    // ServerResponse._flushHeaders → plainRes.writeHead
    // ServerResponse._final → plainRes.end
    var res = new ServerResponse({
      streamId: plainReq.stream_id,
      socket: socketStub
    });
    res.req = req;

    // Store wrapper references for WebTransport event forwarding.
    // MUST come after `res` is created (was previously set while res was
    // still undefined due to var hoisting).
    plainReq._wrapper = req;
    plainRes._wrapper = res;

    // Override internal methods to delegate to the plain H3 res.
    // Key insight: we buffer one chunk behind so that _final can
    // send the last data + FIN together via plainRes.end(chunk),
    // instead of plainRes.write(chunk) + plainRes.end() separately.
    // This avoids FIN-only packets that can get lost without PTO.
    var _pendingChunk = null;

    res._flushHeaders = function () {
      if (res.headersSent) return;
      plainRes.writeHead(res.statusCode, res._headers);
      res.headersSent = true;
    };

    res._write = function (chunk, encoding, callback) {
      if (!res.headersSent) res._flushHeaders();
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);

      // Flush the previous chunk (not the current one — hold it for _final)
      if (_pendingChunk !== null) {
        plainRes.write(_pendingChunk);
      }
      _pendingChunk = chunk;
      callback();
    };

    res._final = function (callback) {
      if (!res.headersSent) res._flushHeaders();
      if (_pendingChunk !== null) {
        plainRes.end(_pendingChunk);   // data + FIN together
      } else {
        plainRes.end();                // FIN only (no body written)
      }
      callback();
    };

    // ---- WebTransport method proxying ----
    if (plainRes.sendDatagram) {
      res.sendDatagram = plainRes.sendDatagram.bind(plainRes);
    }
    if (plainRes.createBidirectionalStream) {
      res.createBidirectionalStream = plainRes.createBidirectionalStream.bind(plainRes);
    }
    if (plainRes.createUnidirectionalStream) {
      res.createUnidirectionalStream = plainRes.createUnidirectionalStream.bind(plainRes);
    }

    if (typeof handler === 'function') handler(req, res);
    ev.emit('request', req, res);
  });



  // RFC 9220: WebSocket over HTTP/3 arrives as extended CONNECT on a QUIC
  // stream and surfaces on the same 'upgrade' event as HTTP/1.1 and HTTP/2.
  // Three transports, one event, one WebSocketServer.
  h3srv.on('upgrade', function (req, stream, head) { ev.emit('upgrade', req, stream, head); });

  // ============================================================
  //  TCP — HTTP/2 and HTTP/1.1, both ours.
  //
  //  Previously node:http2 and node:https. They are gone: h2_server and
  //  h1_server implement the same two protocols, and tcp_listener owns the
  //  socket and the ALPN choice between them — one port, one certificate, one
  //  preference order, decided in one place.
  //
  //  The three request paths now converge completely. h3_server, h2_server and
  //  h1_server each hand the application the same IncomingMessage /
  //  ServerResponse pair from streams.js, so `handler` cannot tell which
  //  protocol produced a request except by reading req.httpVersion — which is
  //  exactly the property that lets Express and Fastify run unchanged over all
  //  three.
  // ============================================================

  var tcpServer = null;

  function startTcpServer(listenPort, host, callback) {
    var hasTlsCredentials = (tlsKey && tlsCert) || options.SNICallback;
    if (!needsTcp) { if (callback) callback(); return; }

    // Alt-Svc advertises HTTP/3 on the same authority (RFC 9114 §3.3), which
    // is how a browser that arrived over TCP learns to try QUIC next time.
    var altSvcHeader = 'h3=":' + listenPort + '"; ma=86400';

    var shared = {
      altSvc: altSvcHeader,
      maxHeaderListSize: options.maxHeaderListSize,
      headersTimeout: options.headersTimeout,
      keepAliveTimeout: options.keepAliveTimeout
    };

    function onRequest(req, res) {
      if (typeof handler === 'function') handler(req, res);
      ev.emit('request', req, res);
    }

    tcpServer = createTcpListener({
      // Cleartext when there are no credentials: a dev server, or a service
      // behind a terminating proxy. Without TLS there is no ALPN, so
      // tcp_listener tells h2c from HTTP/1.1 by looking for the connection
      // preface instead.
      tls: hasTlsCredentials ? lemonTls : null,
      key: tlsKey,
      cert: tlsCert,
      ca: tlsCa,
      SNICallback: options.SNICallback
    });

    // Registration order is the server's ALPN preference: h2 if the client can,
    // HTTP/1.1 if it must.
    if (enableH2) {
      var h2srv = createH2Server(shared, onRequest);
      h2srv.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
      // Extended CONNECT (RFC 8441) arrives on the same 'upgrade' event as an
      // HTTP/1.1 Upgrade, so a WebSocketServer attached to this server serves
      // both without knowing which carried the connection.
      h2srv.on('upgrade', function (req, stream, head) { ev.emit('upgrade', req, stream, head); });
      tcpServer.register('h2', h2srv.handleConnection);
    }
    if (enableH1) {
      var h1srv = createH1Server(shared, onRequest);
      h1srv.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
      // 'upgrade' is how WebSocket (and anything else that switches protocols)
      // gets the raw socket. Same signature as node:http, so the `ws` package
      // works over this server unchanged.
      h1srv.on('upgrade', function (req, socket, head) { ev.emit('upgrade', req, socket, head); });
      tcpServer.register('http/1.1', h1srv.handleConnection);
    }

    tcpServer.on('error', function (err) { ev.emit('error', err); });
    tcpServer.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
    // Fires before the TLS handshake — see tcp_listener. Same name and same
    // argument as node:net, so an IP screen written for node:http works here.
    tcpServer.on('connection', function (sock) { ev.emit('connection', sock); });

    var tcpHost = host || '0.0.0.0';
    tcpServer.listen(listenPort, tcpHost, callback);
  }


  // ============================================================
  //  listen / close / address
  // ============================================================

  function listen(listenPort, host, callback) {
    if (typeof host === 'function') { callback = host; host = null; }

    // `|| 443` turned port 0 into 443. Port 0 is not "no port": it is the
    // documented way to ask the OS for a free one, which every test harness
    // and every process that binds more than one server relies on. The old
    // form silently bound 443 instead — and on a machine where that needs
    // privileges, failed with EACCES for a caller that never mentioned 443.
    port = (listenPort === undefined || listenPort === null) ? 443 : listenPort;

    var remaining = needsTcp ? 2 : 1;
    var called = false;

    function done() {
      remaining--;
      if (remaining <= 0 && !called) {
        called = true;
        ev.emit('listening');
        if (typeof callback === 'function') callback();
      }
    }

    // H3 — always. In external mode h3srv.listen() wires up the external
    // sockets' message handler and starts the sweep timer, but does not
    // bind anything new.
    h3srv.listen(port, host, done);

    // TCP — if needed
    if (needsTcp) {
      startTcpServer(port, host, done);
    }

    return server;
  }

  function close(callback) {
    var remaining = 1 + (tcpServer ? 1 : 0);

    function onClose() {
      remaining--;
      if (remaining <= 0 && typeof callback === 'function') callback();
    }

    h3srv.close(onClose);
    if (tcpServer) { tcpServer.close(onClose); tcpServer = null; }
    else if (remaining <= 1 && typeof callback === 'function') callback();
  }

  function address() {
    // The TCP listener knows the port the OS actually assigned, which is the
    // only useful answer after listen(0).
    if (tcpServer && typeof tcpServer.address === 'function') {
      var addr = tcpServer.address();
      if (addr) return addr;
    }
    return { address: '0.0.0.0', family: 'IPv4', port: port };
  }


  // ============================================================
  //  Public API
  // ============================================================

  var server = {
    listen: listen,
    close: close,
    address: address,
    on: function (name, fn) { ev.on(name, fn); return server; },
    once: function (name, fn) { ev.once(name, fn); return server; },
    off: function (name, fn) { ev.off(name, fn); return server; },
    removeListener: function (name, fn) { ev.removeListener(name, fn); return server; },
    emit: function () { ev.emit.apply(ev, arguments); return server; },
    setTimeout: function (msecs, callback) {
      // node:http exposes this; ours is configured per protocol layer at
      // construction (headersTimeout / keepAliveTimeout), so there is nothing
      // to forward once listening. Kept for API compatibility.
      if (callback) ev.once('timeout', callback);
      return server;
    },

    /** Feed an incoming UDP packet from a shared/external socket.
     *  rinfo must be in Node's dgram format: { address, port, family, size }.
     *  Only relevant when the server was created with options.socket/socket6. */
    handlePacket: function (msg, rinfo) {
      return h3srv.handlePacket(msg, rinfo);
    },

    /** Returns true if the 5-tuple matches an active QUIC connection.
     *  Used by demuxers for routing decisions on shared UDP ports. */
    hasConnection: function (rinfo) {
      return h3srv.hasConnection(rinfo);
    }
  };

  return server;
}


export { createServer };
