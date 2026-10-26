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
import crypto from 'node:crypto';
import { Emitter } from './http_common.js';
import { serverTlsOptions } from './tls_options.js';


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
  var handlerOpts = {};     // alpn protocol -> { sniff, paused }
  // Session tickets: ONE key for every connection of this server, so a
  // ticket issued on one connection opens on the next. Left to lemon-tls, each
  // connection drew its own and no client ever resumed. Random when not given:
  // tickets then last until this server restarts; pass ticketKeys (48 bytes)
  // kept across restarts to have them outlive it.
  var ticketKeys = options.ticketKeys || crypto.randomBytes(48);
  // Encrypted Client Hello keys (lemon-tls), read per connection.
  var ech = options.ech || null;
  var ocspRequest = typeof options.ocspRequest === 'function' ? options.ocspRequest : null;
  // node:tls's options, read once (tls_options.js).
  var tlsOpts = serverTlsOptions(options, false);

  var order = [];           // registration order = ALPN preference order
  var sockets = new Set();
  var closing = false;
  var refed = true;

  var tls = options.tls || null;
  var cachedContext = null;
  // The certificate's context made now, not at the first connection, and
  // its chain compressed in the background (RFC 8879, lemon-tls
  // precompressCertificate): the first client's handshake did both while it
  // waited — brotli at quality 11 alone is 4–18 ms for a chain the first
  // time. A bad key or certificate throws from createServer, as over QUIC.
  if (tls && options.key && options.cert && !options.SNICallback && !options.secureContext) {
    cachedContext = tls.createSecureContext({ key: options.key, cert: options.cert, ca: options.ca, passphrase: tlsOpts.passphrase });
    if (typeof tls.precompressCertificate === 'function' && !(tlsOpts.certificateCompression && tlsOpts.certificateCompression.length === 0))
      tls.precompressCertificate(cachedContext, tlsOpts.certificateCompression || undefined);
  }

  // TCP options, as node:http.createServer takes them and with its defaults:
  // noDelay on (see handleConnection), keepAlive off.
  // The server's counters (server_stats.js), when it keeps them.
  var stats = options.stats || null;
  var noDelay = options.noDelay !== false;
  var keepAlive = options.keepAlive === true;
  var keepAliveInitialDelay = options.keepAliveInitialDelay || 0;


  /**
   * Register a protocol handler. Registration order is the server's ALPN
   * preference: the first registered protocol wins when the client offers
   * several, which is how a server expresses "h2 if you can, h1 if you must".
   */
  //
  // opts (both optional):
  //   sniff(bytes)  Recognise this protocol from the first decrypted bytes of
  //                 a TLS connection that negotiated NO ALPN. Return true
  //                 (mine), false (not mine), or null (need more bytes).
  //                 A browser connecting to turns:host:443 is the case: it
  //                 offers no ALPN at all, while every HTTPS request from a
  //                 browser offers h2 / http/1.1 — so this only ever runs for
  //                 connections that would otherwise have been HTTP/1.1 by
  //                 default, and costs HTTPS nothing.
  //   paused        Hand the socket over paused, with any sniffed bytes put
  //                 back, and let the handler resume it. For a handler that
  //                 attaches its reader asynchronously — turn-server waits
  //                 for its 'accept' hook — and would otherwise lose the
  //                 first message to a stream already flowing.
  function register(protocol, handler, opts) {
    if (!handlers[protocol]) order.push(protocol);
    handlers[protocol] = handler;
    handlerOpts[protocol] = opts || {};
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
    if (stats) stats.protocol(protocol);

    sockets.add(socket);
    socket._quicoProtocol = protocol;
    socket.on('close', function () { sockets.delete(socket); });
    if (handlerOpts[protocol] && handlerOpts[protocol].paused) socket.pause();
    handler(socket, protocol);
  }


  /**
   * Decide which protocol a TLS connection WITHOUT ALPN is speaking, from its
   * first decrypted bytes — the encrypted counterpart of sniffCleartext.
   *
   * Only protocols registered with a sniff() take part. Bytes are gathered
   * until each of them has answered, or a cap is reached; the first to claim
   * the bytes wins, and if none does, the connection goes to `fallback`
   * exactly as it would have before. Whatever was read is put back at the
   * front of the stream, so the chosen handler sees the connection from its
   * first byte.
   */
  function sniffSecure(socket, fallback) {
    var sniffers = [];
    for (var i = 0; i < order.length; i++) {
      var o = handlerOpts[order[i]];
      if (o && typeof o.sniff === 'function') sniffers.push(order[i]);
    }

    var seen = Buffer.alloc(0);
    var decided = false;
    var SNIFF_CAP = 64;            // bytes: enough for any header-shaped test
    var SNIFF_TIMEOUT = 10000;     // a client that says nothing goes to the fallback

    function decide(protocol) {
      if (decided) return;
      decided = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.removeListener('close', onClose);
      // Paused before the bytes go back and the handler is chosen: nothing may
      // flow until a reader exists. dispatch() leaves a 'paused' handler
      // paused; any other is resumed below, as the connection would have been.
      socket.pause();
      if (seen.length) socket.unshift(seen);
      dispatch(socket, protocol);
      if (!(handlerOpts[protocol] && handlerOpts[protocol].paused) && !socket.destroyed) socket.resume();
    }

    function onData(chunk) {
      seen = seen.length ? Buffer.concat([seen, chunk]) : Buffer.from(chunk);
      var pending = false;
      for (var k = 0; k < sniffers.length; k++) {
        var r = null;
        try { r = handlerOpts[sniffers[k]].sniff(seen); } catch (e) { r = false; }
        if (r === true) { decide(sniffers[k]); return; }
        if (r === null) pending = true;
      }
      if (!pending || seen.length >= SNIFF_CAP) decide(fallback);
    }

    function onClose() { decided = true; clearTimeout(timer); }

    var timer = setTimeout(function () { decide(fallback); }, SNIFF_TIMEOUT);
    if (timer.unref) timer.unref();
    socket.on('data', onData);
    socket.on('close', onClose);
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
    if (stats) stats.connections.tcp++;

    // TCP_NODELAY, as node:http sets it on every socket it accepts. With
    // Nagle's algorithm on, a write smaller than one segment waits while
    // anything sent before it is unacknowledged — a full round trip. The TLS
    // server flight is several such writes (ServerHello, then Certificate,
    // CertificateVerify, Finished): the ServerHello went out, the rest sat
    // until the client's ACK came back, and TLS 1.3's one-round-trip
    // handshake took two. The same stall hits the tail of every response.
    // Applied here rather than only on net.createServer, because sockets are
    // also handed in from a listener owned elsewhere.
    if (noDelay && typeof socket.setNoDelay === 'function') socket.setNoDelay(true);
    if (keepAlive && typeof socket.setKeepAlive === 'function') socket.setKeepAlive(true, keepAliveInitialDelay);

    // Emitted BEFORE the TLS handshake, so a consumer that screens by address
    // (an IP blacklist, a rate limiter) can drop the connection without paying
    // for a handshake first. node:net and node:http both call this event
    // 'connection' and hand over the socket, so a screening function written
    // against either works unchanged.
    ev.emit('connection', socket);
    if (socket.destroyed) return;

    if (!tls) { sniffCleartext(socket); return; }

    var tlsOpts = buildTlsOptions(socket);
    var secure;
    var settled = false;

    // The error listener has to be in place BEFORE the handshake can produce
    // one, and the constructor starts reading immediately — so it is attached
    // to the underlying socket first and moved up as soon as the TLSSocket
    // exists.
    //
    // The gap is not theoretical. A TLS handshake can fail asynchronously:
    // an SNI lookup that answers "no certificate for that name" fires its
    // alert from a callback, long after the constructor returned. With no
    // listener at that moment the error is unhandled, and an unhandled error
    // on an EventEmitter takes the process down — meaning any scanner that
    // connects to the IP without SNI, which is a continuous background event
    // on a public address, can stop the server.
    // Reported as 'tlsClientError' (err, tlsSocket), node:tls's event for a
    // handshake that failed; 'clientError' is the HTTP layer's, for a
    // connection that is up. It was reported as 'clientError'.
    function onHandshakeError(err) {
      if (!settled) {
        settled = true;
        countHandshake(false);
        ev.emit('tlsClientError', err, secure || socket);
      }
      // The alert that says why (no_application_protocol, bad_certificate,
      // ...) is written to the socket just before this; destroy() threw it
      // away with whatever else was still queued, and the client saw only a
      // reset. The socket is ended instead, which sends what is queued, and
      // destroyed if it has not closed shortly after.
      if (socket.destroyed) return;
      try { socket.end(); } catch (e) {}
      var t = setTimeout(function () { try { socket.destroy(); } catch (e) {} }, 1000);
      if (t.unref) t.unref();
    }

    socket.on('error', onHandshakeError);

    // The handshake's end, counted once (server_stats.js): completed, or
    // failed — an error, or the client gone before it finished.
    var hsCounted = false;
    function countHandshake(ok, resumed) {
      if (hsCounted || !stats) return;
      hsCounted = true;
      stats.handshake('tcp', ok, resumed);
    }
    if (stats) socket.on('close', function () { countHandshake(false); });

    try {
      // The TCP socket underneath stays open for writing when the client
      // half-closes: the TLS socket over it decides — it ends both with the
      // client's (allowHalfOpen off, HTTP/1.1, as node:http), unless the
      // protocol above keeps it open to finish its responses (h2_server).
      socket.allowHalfOpen = true;
      secure = new tls.TLSSocket(socket, tlsOpts);
    } catch (err) {
      onHandshakeError(err);
      return;
    }

    secure.on('error', onHandshakeError);

    // Early data taken: the protocol above gets the connection now, to read
    // it as it comes (socket.isEarlyData) and answer as soon as the server's
    // Finished is out — not one round trip later, at 'secure'. The ALPN is
    // decided by then (the ticket's, or there is no early data).
    var dispatchedEarly = false;
    secure.on('earlyData', function (accepted) {
      if (stats) stats.earlyData[accepted ? 'accepted' : 'rejected']++;
      if (!accepted || settled || dispatchedEarly) return;
      var p = secure.alpnProtocol;
      if (!p || !handlers[p]) return;
      dispatchedEarly = true;
      dispatch(secure, p);
    });

    // 'secure' rather than 'secureConnect': lemon-tls documents that
    // secureConnect is not emitted for a socket built with new TLSSocket(),
    // matching Node, while 'secure' fires on both sides and in both
    // construction paths. Listening for the wrong one is a server that accepts
    // connections and then never does anything with them.
    secure.on('secure', function () {
      if (settled) return;
      settled = true;
      countHandshake(true, typeof secure.isSessionReused === 'function' && secure.isSessionReused());

      // 'secureConnection': the handshake is done — the name and the moment
      // node:tls uses. 'connection' fired before any TLS, knowing only an
      // address; here the connection can be asked what the handshake decided
      // (isSessionReused(), getTicketInfo()), which is what a caller needs to
      // tell a returning client from a new one. A listener may destroy() it.
      ev.emit('secureConnection', secure);
      if (secure.destroyed || dispatchedEarly) return;

      var protocol = secure.alpnProtocol;
      if (!protocol) {
        // The client offered nothing, or offered nothing we advertise. RFC
        // 7301 lets the server proceed without ALPN, and HTTP/1.1 is the only
        // safe assumption — an h2 client always offers 'h2'. Unless a
        // registered protocol can tell itself apart by its first bytes: then
        // those decide (see sniffSecure).
        var fallback = handlers['http/1.1'] ? 'http/1.1' : order[0];
        for (var sp = 0; sp < order.length; sp++) {
          var so = handlerOpts[order[sp]];
          if (so && typeof so.sniff === 'function') { sniffSecure(secure, fallback); return; }
        }
        protocol = fallback;
      }
      dispatch(secure, protocol);
    });
  }


  /**
   * Who this connection is, for an SNICallback that wants to know.
   *
   * A certificate can only be chosen by name when the client sends one, and
   * a client connecting to a bare IP address never does — RFC 6066 §3 forbids
   * an IP literal in SNI, so browsers leave the extension out entirely. The
   * callback then sees an empty servername and nothing else, with no way to
   * tell which of the server's addresses was dialled. That is the one thing
   * it needs to serve a certificate issued for an IP.
   *
   * The raw socket knows. A dual-stack listener reports an IPv4 peer as
   * ::ffff:a.b.c.d on an IPv6 socket; that is unwrapped here so the family
   * reported is the one the client actually used.
   */
  function connectionInfo(socket) {
    var local = socket.localAddress || null;
    var family = socket.localFamily || (local && net.isIPv6(local) ? 'IPv6' : 'IPv4');
    if (local && local.indexOf('::ffff:') === 0 && net.isIPv4(local.substring(7))) {
      local = local.substring(7);
      family = 'IPv4';
    }
    return {
      transport: 'tcp',
      localAddress: local,
      localPort: socket.localPort || null,
      family: family,
      remoteAddress: socket.remoteAddress || null,
      remotePort: socket.remotePort || null
    };
  }


  function buildTlsOptions(socket) {
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
      // Bound per connection, with the connection's details as a third
      // argument. Third, after cb, so a callback written against the
      // (servername, cb) signature node:tls documents keeps working
      // unchanged — it just never reads it.
      var userSni = options.SNICallback;
      var info = socket ? connectionInfo(socket) : null;
      o.SNICallback = function (servername, cb) { return userSni(servername, cb, info); };
    } else if (options.secureContext) {
      var fixed = options.secureContext;
      o.SNICallback = function (servername, cb) { cb(null, fixed); };
    } else if (options.key && options.cert) {
      if (!cachedContext) {
        cachedContext = tls.createSecureContext({
          key: options.key, cert: options.cert, ca: options.ca, passphrase: tlsOpts.passphrase
        });
      }
      var ctx = cachedContext;
      o.SNICallback = function (servername, cb) { cb(null, ctx); };
    }
    o.ticketKeys = ticketKeys;
    if (options.ticketData) o.ticketData = options.ticketData;
    if (ech) o.ech = ech;
    if (ocspRequest) o.ocspRequest = ocspRequest;
    if (tlsOpts.sessionTimeout !== undefined) o.ticketLifetime = tlsOpts.sessionTimeout;
    if (tlsOpts.requestCert) {
      o.requestCert = true;
      o.rejectUnauthorized = tlsOpts.rejectUnauthorized;
    }
    if (tlsOpts.minVersion) o.minVersion = tlsOpts.minVersion;
    if (tlsOpts.maxVersion) o.maxVersion = tlsOpts.maxVersion;
    // node:tls's default, 120 s: lemon-tls's own is none, and a client that
    // sent half a ClientHello held its socket for as long as it liked.
    o.handshakeTimeout = tlsOpts.handshakeTimeout !== undefined ? tlsOpts.handshakeTimeout : 120000;
    if (tlsOpts.cipherSuites) o.allowedCipherSuites = tlsOpts.cipherSuites;
    if (tlsOpts.groups) o.groups = tlsOpts.groups;
    if (tlsOpts.sigalgs) o.signatureAlgorithms = tlsOpts.sigalgs;
    if (tlsOpts.certificateCompression) o.certificateCompression = tlsOpts.certificateCompression;
    if (tlsOpts.honorCipherOrder) o.honorCipherOrder = true;
    // 0-RTT (RFC 8446 §4.2.10), as the server's options say now (they change
    // while it runs): tickets that allow it, and taking it — under its own
    // context, so a ticket of the QUIC side's carries none here.
    var ed = typeof options.earlyDataNow === 'function' ? options.earlyDataNow() : null;
    if (ed && ed.on) {
      o.earlyData = true;
      o.earlyDataMaxAge = ed.maxAge;
      o.earlyDataReplay = options.earlyDataReplay;
      o.earlyDataContext = 'tcp';
    }
    return o;
  }


  function listen(port, host, callback) {
    if (typeof host === 'function') { callback = host; host = undefined; }
    if (order.length === 0) throw new Error('no protocol handlers registered');

    server = net.createServer({ allowHalfOpen: false }, handleConnection);
    if (!refed) server.unref();
    server.on('error', function (err) { ev.emit('error', err); });
    server.listen(port, host, function () {
      ev.emit('listening');
      if (typeof callback === 'function') callback();
    });
    return listener;
  }


  function close(callback) {
    closing = true;

    // Idle sockets would hold the close open for their full keep-alive
    // timeout. Protocol layers that have work in flight mark the socket busy;
    // theirs are left to finish.
    //
    // Done whether or not this listener owns a port. With an external owner
    // — sockets handed in through handleConnection — there is no net.Server
    // here to close, and returning early (as this did) left every one of
    // those connections open after shutdown.
    // A protocol that closes its own connections (registered with
    // managesClose: HTTP/1.1 and HTTP/2 finish what is in flight first) is
    // left to it.
    for (var socket of sockets) {
      var po = handlerOpts[socket._quicoProtocol];
      if (po && po.managesClose) continue;
      if (!socket._quicoBusy) { try { socket.end(); } catch (e) {} }
    }

    if (!server) { if (callback) callback(); return; }
    server.close(function () { if (typeof callback === 'function') callback(); });
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
    get connections() { return sockets.size; },
    // node:net's: whether the process may exit while this listens.
    ref: function () { refed = true; if (server && server.ref) server.ref(); return listener; },
    unref: function () { refed = false; if (server && server.unref) server.unref(); return listener; },

    // The session ticket keys — tls.Server's names. A new key takes effect
    // for the next connection; tickets sealed with the one before no longer
    // open (those clients do a full handshake once, and get a new ticket).
    getTicketKeys: function () { return ticketKeys; },
    setTicketKeys: function (keys) { ticketKeys = keys; },
    getEchKeys: function () { return ech; },
    setEchKeys: function (keys) { ech = keys || null; }
  };

  return listener;
}


export { createTcpListener, H2_PREFACE };
