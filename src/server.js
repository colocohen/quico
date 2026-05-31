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
import http2 from 'node:http2';
import nodeHttps from 'node:https';
import nodeTls from 'node:tls';

import { createServer as createH3Server } from './h3_server.js';
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


  // ============================================================
  //  TCP — HTTP/2 and/or HTTP/1.1
  // ============================================================

  var tcpServer = null;

  function startTcpServer(listenPort, host, callback) {
    var hasTlsCredentials = (tlsKey && tlsCert) || options.SNICallback;
    if (!needsTcp || !hasTlsCredentials) {
      if (callback) callback();
      return;
    }

    // Bridge SNICallback: detect context type and route accordingly.
    //   quico context (_nodeContext) → use pre-built node:tls context
    //   quico context (_rawKey)      → build node:tls context from stored creds
    //   node:tls context             → use directly (someone used tls.createSecureContext)
    var tcpSniCallback = null;
    if (options.SNICallback) {
      tcpSniCallback = function (servername, cb) {
        options.SNICallback(servername, function (err, ctx) {
          if (err) return cb(err);
          if (!ctx) return cb(new Error('SNICallback returned null'));

          // 1. Pre-built node:tls context (fastest path)
          if (ctx._nodeContext) {
            return cb(null, ctx._nodeContext);
          }
          // 2. Raw key/cert stored — build node:tls context
          if (ctx._rawKey && ctx._rawCert) {
            var nodeOpts = { key: ctx._rawKey, cert: ctx._rawCert };
            if (ctx._rawCa) nodeOpts.ca = ctx._rawCa;
            try { return cb(null, nodeTls.createSecureContext(nodeOpts)); }
            catch (e) { return cb(e); }
          }
          // 3. Assume it's already a node:tls context (tls.createSecureContext)
          cb(null, ctx);
        });
      };
    }

    var altSvcHeader = 'h3=":' + listenPort + '"; ma=86400';

    if (enableH2) {
      // ---- HTTP/2 (+ optional HTTP/1.1) via node:http2 ----
      var tcpOpts = {
        allowHTTP1: enableH1,
        settings: { enablePush: false }
      };
      if (tlsKey) tcpOpts.key = tlsKey;
      if (tlsCert) tcpOpts.cert = tlsCert;
      if (tlsCa) tcpOpts.ca = tlsCa;
      if (tcpSniCallback) tcpOpts.SNICallback = tcpSniCallback;

      tcpServer = http2.createSecureServer(tcpOpts);

      tcpServer.on('request', function (req, res) {
        res.setHeader('alt-svc', altSvcHeader);
        if (typeof handler === 'function') handler(req, res);
        ev.emit('request', req, res);
      });

    } else if (enableH1) {
      // ---- HTTP/1.1 only via node:https ----
      var tcpOpts = {};
      if (tlsKey) tcpOpts.key = tlsKey;
      if (tlsCert) tcpOpts.cert = tlsCert;
      if (tlsCa) tcpOpts.ca = tlsCa;
      if (tcpSniCallback) tcpOpts.SNICallback = tcpSniCallback;

      tcpServer = nodeHttps.createServer(tcpOpts);

      tcpServer.on('request', function (req, res) {
        res.setHeader('alt-svc', altSvcHeader);
        if (typeof handler === 'function') handler(req, res);
        ev.emit('request', req, res);
      });
    }

    if (tcpServer) {
      tcpServer.on('error', function (err) { ev.emit('error', err); });
      var tcpHost = host || '0.0.0.0';
      tcpServer.listen(listenPort, tcpHost, callback);
    } else {
      if (callback) callback();
    }
  }


  // ============================================================
  //  listen / close / address
  // ============================================================

  function listen(listenPort, host, callback) {
    if (typeof host === 'function') { callback = host; host = null; }
    port = listenPort || 443;

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
      if (tcpServer && typeof tcpServer.setTimeout === 'function') {
        tcpServer.setTimeout(msecs, callback);
      }
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
