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

import net from 'node:net';
import { Emitter } from './http_common.js';


// ============================================================
//  TCP transport: sockets, TLS, and ALPN dispatch.
//
//  The mirror image of quic_server.js. That file owns the UDP socket,
//  demultiplexes datagrams and hands a raw QUICConnection to whatever
//  application protocol layers on top; this one owns the TCP socket, runs the
//  TLS handshake, and hands a ready Duplex to whichever protocol ALPN selected.
//  Neither knows anything about HTTP.
//
//  It exists because h1_server, h2_server and ws_server must share one port —
//  a client picks between them with ALPN, and something has to make that
//  choice. Putting the choice in each server means three copies of
//  net.createServer, three SNICallback bridges, three ALPN lists that can
//  disagree, and three close()/address() implementations. Here it is written
//  once and the protocol layers become pure: they receive a socket and never
//  create one.
//
//  TLS comes from lemon-tls, passed in as `options.tls`. Without it the
//  listener is cleartext, which is what a local dev server or a service behind
//  a terminating proxy wants — and what h2c and ws:// need.
// ============================================================

// The HTTP/2 connection preface (RFC 9113 §3.4). Used here only to sniff a
// cleartext connection; the h2 layer validates it properly.
var H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'latin1');


function createTcpListener(options) {
  options = options || {};

  var ev = Emitter();
  var server = null;
  var handlers = {};        // alpn protocol -> handler(socket, protocol)
  var order = [];           // registration order = ALPN preference order
  var sockets = new Set();
  var closing = false;

  var tls = options.tls || null;
  var cachedContext = null;


  /**
   * Register a protocol handler. Registration order is the server's ALPN
   * preference: the first registered protocol wins when the client offers
   * several, which is how a server expresses "h2 if you can, h1 if you must".
   */
  function register(protocol, handler) {
    if (!handlers[protocol]) order.push(protocol);
    handlers[protocol] = handler;
    return listener;
  }


  function dispatch(socket, protocol) {
    if (closing) { try { socket.destroy(); } catch (e) {} return; }

    var handler = handlers[protocol];
    if (!handler) {
      // Nothing registered for what was negotiated. Should be impossible —
      // we only advertise what is registered — but a client can also connect
      // with no ALPN at all, and then `protocol` is whatever the fallback
      // decided.
      ev.emit('clientError', new Error('no handler for protocol ' + JSON.stringify(protocol)), socket);
      try { socket.destroy(); } catch (e) {}
      return;
    }

    sockets.add(socket);
    socket.on('close', function () { sockets.delete(socket); });
    handler(socket, protocol);
  }


  /**
   * Decide which protocol a CLEARTEXT connection is speaking.
   *
   * There is no ALPN without TLS, so the two cleartext protocols have to be
   * told apart another way. RFC 9113 §3.3 calls this "prior knowledge": an h2c
   * client simply opens with the connection preface, and the preface was
   * designed to be something no HTTP/1.1 request can begin with. Peeking at
   * the first bytes is therefore unambiguous — and the bytes are pushed back
   * so the chosen layer sees the whole stream.
   */
  function sniffCleartext(socket) {
    if (order.length === 1) { dispatch(socket, order[0]); return; }
    if (!handlers['h2'] && !handlers['h2c']) { dispatch(socket, order[0]); return; }

    var seen = Buffer.alloc(0);
    var decided = false;

    function onData(chunk) {
      if (decided) return;
      seen = Buffer.concat([seen, chunk]);

      var n = Math.min(seen.length, H2_PREFACE.length);
      var matches = seen.subarray(0, n).equals(H2_PREFACE.subarray(0, n));

      if (!matches) { decide(handlers['http/1.1'] ? 'http/1.1' : order[0]); return; }
      if (seen.length >= H2_PREFACE.length) { decide(handlers['h2'] ? 'h2' : 'h2c'); }
      // Otherwise a prefix of the preface so far: wait for more.
    }

    function decide(protocol) {
      decided = true;
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      // Put the sniffed bytes back at the FRONT of the stream. unshift is the
      // documented way to do this; without it the protocol layer never sees
      // the request line (or the preface) it is waiting for and the connection
      // hangs until a timeout — a failure that looks like a parser bug.
      if (seen.length) socket.unshift(seen);
      dispatch(socket, protocol);
    }

    function onError(err) { if (!decided) { decided = true; ev.emit('clientError', err, socket); } }
    function onClose() { decided = true; }

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  }


  /**
   * Accept a socket the caller already has — a shared port, a test harness, or
   * a listener owned elsewhere. The equivalent of quic_server's handlePacket.
   */
  function handleConnection(socket) {
    if (closing) { try { socket.destroy(); } catch (e) {} return; }

    // Emitted BEFORE the TLS handshake, so a consumer that screens by address
    // (an IP blacklist, a rate limiter) can drop the connection without paying
    // for a handshake first. node:net and node:http both call this event
    // 'connection' and hand over the socket, so a screening function written
    // against either works unchanged.
    ev.emit('connection', socket);
    if (socket.destroyed) return;

    if (!tls) { sniffCleartext(socket); return; }

    var tlsOpts = buildTlsOptions();
    var secure;
    try {
      secure = new tls.TLSSocket(socket, tlsOpts);
    } catch (err) {
      ev.emit('clientError', err, socket);
      try { socket.destroy(); } catch (e) {}
      return;
    }

    var settled = false;
    secure.on('error', function (err) {
      if (!settled) { settled = true; ev.emit('clientError', err, secure); }
      try { secure.destroy(); } catch (e) {}
    });

    // 'secure' rather than 'secureConnect': lemon-tls documents that
    // secureConnect is not emitted for a socket built with new TLSSocket(),
    // matching Node, while 'secure' fires on both sides and in both
    // construction paths. Listening for the wrong one is a server that accepts
    // connections and then never does anything with them.
    secure.on('secure', function () {
      if (settled) return;
      settled = true;

      var protocol = secure.alpnProtocol;
      if (!protocol) {
        // The client offered nothing, or offered nothing we advertise. RFC
        // 7301 lets the server proceed without ALPN, and HTTP/1.1 is the only
        // safe assumption — an h2 client always offers 'h2'.
        protocol = handlers['http/1.1'] ? 'http/1.1' : order[0];
      }
      dispatch(secure, protocol);
    });
  }


  function buildTlsOptions() {
    var o = {
      isServer: true,
      // Advertised in registration order, which is the server's preference.
      ALPNProtocols: order.slice()
    };
    if (options.ca) o.ca = options.ca;

    // Credentials reach a server-side TLSSocket through SNICallback.
    //
    // Passing key/cert (or secureContext) straight through is what node:tls
    // documents and what this did first — and the handshake simply never
    // completed, with no error on either side. lemon-tls resolves a server
    // certificate through its SNI path, so a plain key/cert pair has to be
    // wrapped in a callback that hands back the same context every time. The
    // context is built ONCE here rather than per connection: compiling the PEM
    // on the handshake path is measurable, and the hand-written SNICallback
    // most servers end up with usually gets that wrong.
    if (options.SNICallback) {
      o.SNICallback = options.SNICallback;
    } else if (options.secureContext) {
      var fixed = options.secureContext;
      o.SNICallback = function (servername, cb) { cb(null, fixed); };
    } else if (options.key && options.cert) {
      if (!cachedContext) {
        cachedContext = tls.createSecureContext({
          key: options.key, cert: options.cert, ca: options.ca
        });
      }
      var ctx = cachedContext;
      o.SNICallback = function (servername, cb) { cb(null, ctx); };
    }
    if (options.requestCert) o.requestCert = options.requestCert;
    if (options.minVersion) o.minVersion = options.minVersion;
    if (options.maxVersion) o.maxVersion = options.maxVersion;
    if (options.handshakeTimeout != null) o.handshakeTimeout = options.handshakeTimeout;
    return o;
  }


  function listen(port, host, callback) {
    if (typeof host === 'function') { callback = host; host = undefined; }
    if (order.length === 0) throw new Error('no protocol handlers registered');

    server = net.createServer({ allowHalfOpen: false }, handleConnection);
    server.on('error', function (err) { ev.emit('error', err); });
    server.listen(port, host, function () {
      ev.emit('listening');
      if (typeof callback === 'function') callback();
    });
    return listener;
  }


  function close(callback) {
    closing = true;
    if (!server) { if (callback) callback(); return; }
    server.close(function () { if (typeof callback === 'function') callback(); });

    // Idle sockets would hold the close open for their full keep-alive
    // timeout. Protocol layers that have work in flight mark the socket busy;
    // theirs are left to finish.
    for (var socket of sockets) {
      if (!socket._quicoBusy) { try { socket.end(); } catch (e) {} }
    }
  }


  var listener = {
    register: register,
    listen: listen,
    close: close,
    handleConnection: handleConnection,
    address: function () { return server && server.address ? server.address() : null; },
    on: function (n, f) { ev.on(n, f); return listener; },
    off: function (n, f) { ev.off(n, f); return listener; },
    get protocols() { return order.slice(); },
    get connections() { return sockets.size; }
  };

  return listener;
}


export { createTcpListener, H2_PREFACE };
