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
import crypto from 'node:crypto';

import { createServer as createH3Server } from './h3_server.js';
import { createServer as createH2Server } from './h2_server.js';
import { createServer as createH1Server } from './h1_server.js';
import { createTcpListener } from './tcp_listener.js';
import { IncomingMessage, ServerResponse, _makeSocketStub, adoptApp } from './streams.js';
import { creditAsRead } from './utils.js';
import { runEarlyDataFilter } from './http_common.js';
import { serverTlsOptions, pickTlsOptions } from './tls_options.js';
import { STATUS_CODES } from 'node:http';
import { ServerStats } from './server_stats.js';
import { createConnectUdp, isConnectUdp, datagramCapsule, STREAM_QUEUE_MAX } from './connect_udp.js';


// ============================================================
//  createServer(options, handler)
//
//  HTTP/3 is always enabled (that's the point of quico).
//  Options:
//    http2: true (default) — TCP with node:http2
//    http1: true (default) — allowHTTP1 on TCP (or standalone if http2:false)
//    ALPNProtocols         — the node:tls option: ALPN names to accept, in
//                            preference order. Applies to TCP and QUIC,
//                            each taking the names that belong to it — see
//                            tcpAlpnList() and quicAlpnList().
//
//  Combinations:
//    { }                          → H3 + H2 + H1    (default)
//    { http1: false }             → H3 + H2
//    { http2: false }             → H3 + H1
//    { http2: false, http1: false } → H3 only
// ============================================================

// ============================================================
//  ALPN on TCP
//
//  The http2 / http1 flags decide which HTTP versions run. ALPNProtocols —
//  the node:tls option, same name and same shape — adds further names and
//  sets the order in which they are preferred.
//
//  An HTTP protocol that is being served but missing from the list is put in
//  front of it rather than dropped. The list is the node:tls one, and code
//  written against node:tls would name only what it adds; silently turning off
//  HTTP/2 because a caller wrote ['acme-tls/1'] would be a failure nobody sees
//  — browsers just fall back, a little slower. Turning a version off is what
//  the flags are for.
//
//  'h3' is skipped here: it exists only over QUIC. A name the flags have
//  disabled is an error rather than an omission, because it can only mean the
//  two options disagree about what the server should do.
// ============================================================

function tcpAlpnList(requested, h2, h1) {
  var served = [];
  if (h2) served.push('h2');
  if (h1) served.push('http/1.1');
  if (requested === undefined || requested === null) return served;

  if (!Array.isArray(requested)) throw new TypeError('ALPNProtocols must be an array of strings');

  var listed = [];
  var seen = {};
  for (var i = 0; i < requested.length; i++) {
    var name = requested[i];
    if (typeof name !== 'string' || name.length === 0) {
      throw new TypeError('ALPNProtocols entries must be non-empty strings');
    }
    if (name === 'h3') continue;
    if (name === 'h2' && !h2) throw new Error("ALPNProtocols lists 'h2' but http2 is false");
    if (name === 'http/1.1' && !h1) throw new Error("ALPNProtocols lists 'http/1.1' but http1 is false");
    if (seen[name]) continue;
    seen[name] = true;
    listed.push(name);
  }

  var missing = [];
  for (var j = 0; j < served.length; j++) if (!seen[served[j]]) missing.push(served[j]);
  return missing.concat(listed);
}

// The QUIC side of the same list, by the same rule as TCP: 'h3' is always
// served — HTTP/3 is what quico is for — so it goes first when missing, and
// keeps the position it was given when listed. 'h2' and 'http/1.1' are
// skipped: they exist only over TCP.
function quicAlpnList(requested) {
  if (requested === undefined || requested === null) return ['h3'];
  var out = [];
  for (var i = 0; i < requested.length; i++) {
    var name = requested[i];
    if (name === 'h2' || name === 'http/1.1') continue;
    if (out.indexOf(name) === -1) out.push(name);
  }
  if (out.indexOf('h3') === -1) out.unshift('h3');
  return out;
}

// A name accepted in the handshake that quico does not speak. The application
// asked only that the handshake agree to it — ACME tls-alpn-01 is the case in
// point: the CA checks the certificate the handshake presented, sends nothing
// afterwards, and closes. Ending our side too keeps the socket from lingering
// if a client does not.
function closeAfterHandshake(socket) {
  try { socket.end(); } catch (e) {}
}


function createServer(options, handler) {
  if (typeof options === 'function') { handler = options; options = {}; }
  options = options || {};
  // An Express app runs on quico's req/res only once its request/response
  // objects inherit from them — see adoptApp in streams.js.
  adoptApp(handler);

  var enableH2 = options.http2 !== false;
  var enableH1 = options.http1 !== false;
  var needsTcp = enableH2 || enableH1;

  // http3: false — run no HTTP/3 on this server.
  //
  // listen() used to start the QUIC listener unconditionally, so every
  // server bound a UDP port alongside its TCP one. That is wrong whenever
  // HTTP/3 is served somewhere else on the same port — a gateway that owns
  // UDP 443 and hands QUIC packets to a dedicated server — because a
  // TCP-only server then competes for the same UDP port. The loser's bind
  // failed, and since nothing forwarded that error (see below), its listen()
  // callback simply never fired. The failure was silent.
  //
  // Alt-Svc is still sent when this is off. The usual reason to disable
  // HTTP/3 here is that it is served by another server on the same port, and
  // Alt-Svc is how a browser on TCP finds it.
  var enableH3 = options.http3 !== false;
  // node:tls's TLS options, checked now so a bad one throws from
  // createServer — for HTTP/3 too when it runs (TLS 1.3 only).
  serverTlsOptions(options, enableH3);

  // Computed here rather than in listen(), so a contradictory list throws
  // from createServer — at the line that wrote it — and not later from a
  // listen() call somewhere else.
  var tcpAlpn = tcpAlpnList(options.ALPNProtocols, enableH2, enableH1);
  var quicAlpn = quicAlpnList(options.ALPNProtocols);

  var ev = new EventEmitter();
  var port = null;

  // ---- TLS credentials ----
  var tlsKey = options.key || null;
  var tlsCert = options.cert || null;
  var tlsCa = options.ca || null;

  // Session tickets: one key for this server, TCP and QUIC alike — random
  // unless the application passes ticketKeys it keeps across restarts. And
  // the application's ticketData, carried inside each ticket (lemon-tls).
  var ticketKeys = options.ticketKeys || crypto.randomBytes(48);
  var ticketData = typeof options.ticketData === 'function' ? options.ticketData : null;
  // Encrypted Client Hello keys (RFC 9849), TCP and QUIC alike:
  // { keys: [{ config, privateKey, retry }] } — see lemon-tls generateEchKey.
  // Checked now: a key that does not match its config would otherwise show
  // only as every ECH client falling back.
  var ech = options.ech || null;
  if (ech) lemonTls.checkEchKeys(ech);

  // OCSP stapling, node:tls's way: server.on('OCSPRequest', (certificate,
  // issuer, callback) => callback(null, ocspResponse)) — asked when a client
  // requests status, TCP and QUIC alike. Without a listener nothing is
  // stapled and nothing waits.
  function ocspRequest(certificate, issuer, callback) {
    if (ev.listenerCount('OCSPRequest') === 0) return callback(null, null);
    ev.emit('OCSPRequest', Buffer.from(certificate), issuer ? Buffer.from(issuer) : null, callback);
  }
  // node:tls's TLS options — client certificates, versions, ciphers, curves,
  // signature schemes, the ticket lifetime, the handshake timeout — passed to
  // both stacks (tls_options.js), each reading them for itself.
  var tlsPassOn = pickTlsOptions(options);

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

  // node:http's shouldUpgradeCallback(request): whether an upgrade request —
  // HTTP/1.1 Upgrade, or extended CONNECT over HTTP/2 and HTTP/3 — reaches
  // 'upgrade' or is handled as an ordinary 'request'. Node's default: taken up
  // when the application listens for 'upgrade'. Decided here, for every
  // version, because the layers below always listen (to forward the event
  // up): their own "nobody listens" check could never fire, and an upgrade
  // with no listener was left hanging.
  var userShouldUpgrade = typeof options.shouldUpgradeCallback === 'function' ? options.shouldUpgradeCallback : null;
  function shouldUpgradeCallback(req) {
    if (wantsConnectUdp(req)) return true;
    return userShouldUpgrade ? !!userShouldUpgrade(req) : ev.listenerCount('upgrade') > 0;
  }

  // ---- CONNECT-UDP (RFC 9298): proxying UDP, on every version ----
  //
  // server.on('connectUdp', (req, tunnel) => tunnel.accept()) — see
  // connect_udp.js. Off until something listens: a request for it then goes
  // the way it always did (to 'upgrade' or the request handler), and none is
  // proxied. options.connectUdp: { template, allowPrivate,
  // maxTunnelsPerConnection, idleTimeout, lookup, proxyName }.
  var udpProxy = createConnectUdp(options.connectUdp || {});
  function wantsConnectUdp(req) { return ev.listenerCount('connectUdp') > 0 && isConnectUdp(req); }
  function emitConnectUdp(tunnel) {
    if (ev.listenerCount('connectUdp') === 0) return false;
    ev.emit('connectUdp', tunnel.req, tunnel);
    return true;
  }

  // HTTP/2's and HTTP/1.1's carrier: capsules on a byte stream — the
  // extended CONNECT's Duplex (DATA frames), or the upgraded socket. Past
  // STREAM_QUEUE_MAX waiting to be written, a payload is dropped, as a full
  // UDP queue drops.
  function byteStreamCarrier(req, stream, version, head, accept, reject) {
    var closed = false;
    var carrier = {
      httpVersion: version,
      connKey: req.socket || stream,
      sink: null,
      mode: function () { return 'capsule'; },
      accept: function (h) { if (!closed) accept(h); },
      reject: function (status, h) { if (closed) return; closed = true; reject(status, h); },
      sendPayload: function (u8) {
        if (closed || stream.destroyed || stream.writableLength > STREAM_QUEUE_MAX) return false;
        stream.write(datagramCapsule(u8));
        return true;
      },
      end: function () { if (closed) return; closed = true; try { stream.end(); } catch (e) {} },
      abort: function () { if (closed) return; closed = true; try { stream.destroy(); } catch (e) {} }
    };
    stream.on('error', function () {});
    udpProxy.handle(req, carrier, emitConnectUdp);
    if (!carrier.sink) return;
    stream.on('data', function (d) { carrier.sink.data(d); });
    stream.on('end', function () { carrier.sink.end(); });
    stream.on('close', function () { carrier.sink.abort(); });
    if (head && head.length) carrier.sink.data(head);
  }
  function fieldLines(h) {
    var out = '';
    for (var n in (h || {})) out += n + ': ' + String(h[n]).replace(/[\r\n]/g, '') + '\r\n';
    return out;
  }
  function connectUdpH2(req, stream) {
    byteStreamCarrier(req, stream, '2.0', null,
      function (h) { stream._h2Accept(h); },
      function (status, h) { stream._h2Reject(status, null, h); });
  }
  // HTTP/1.1: a GET with Upgrade: connect-udp, answered 101 (§3.2).
  function connectUdpH1(req, socket, head) {
    byteStreamCarrier(req, socket, '1.1', head,
      function (h) {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n' + fieldLines(h) + '\r\n');
      },
      function (status, h) {
        try {
          socket.end('HTTP/1.1 ' + status + ' ' + (STATUS_CODES[status] || 'Error') + '\r\nConnection: close\r\nContent-Length: 0\r\n' + fieldLines(h) + '\r\n');
        } catch (e) {}
      });
  }

  // The server's counters (server_stats.js): each layer counts into them
  // where things happen; getStats() copies them out.
  var stats = new ServerStats();

  var h3Options = {
    stats: stats,
    shouldUpgradeCallback: shouldUpgradeCallback,
    // CONNECT-UDP over HTTP/3: h3_server builds the carrier (QUIC datagrams,
    // or capsules in DATA frames); the request is wrapped as the others are.
    connectUdpHandler: {
      wants: wantsConnectUdp,
      handle: function (plainReq, carrier) {
        var req = new IncomingMessage({
          httpVersion: '3.0', method: plainReq.method, url: plainReq.url,
          headers: plainReq.headers || {}, streamId: plainReq.stream_id, socket: plainReq.socket || _makeSocketStub()
        });
        if (req.headers.host === undefined && req.headers[':authority'] !== undefined) req.headers.host = req.headers[':authority'];
        req._endData();
        udpProxy.handle(req, carrier, emitConnectUdp);
      }
    },
    key: tlsKey,
    cert: tlsCert,
    ca: tlsCa,
    SNICallback: options.SNICallback || null,
    ticketKeys: ticketKeys,
    ticketData: ticketData,
    ech: ech,
    ocspRequest: ocspRequest,
    // The HTTP/3 side's stateless reset secret (see quic_server). Random when
    // not given.
    resetTokenSecret: options.resetTokenSecret || null,
    // HTTP/3 address validation with Retry — node:quic's validateAddress.
    // Off unless set; see setValidateAddress below.
    validateAddress: options.validateAddress === true,
    // Handshakes under way: the threshold of 'handshakeLoad', and the cap per
    // client address (quic_server, "Handshakes under way").
    handshakeLoadThreshold: options.handshakeLoadThreshold,
    // 0-RTT (HTTP/3): off unless true; see h3_server for earlyDataFilter.
    earlyData: options.earlyData, earlyDataMaxAge: options.earlyDataMaxAge,
    earlyDataReplay: options.earlyDataReplay, earlyDataFilter: options.earlyDataFilter,
    maxHandshakesPerAddress: options.maxHandshakesPerAddress,
    // Every version's: how long a request may take to arrive (http_common).
    headersTimeout: options.headersTimeout,
    requestTimeout: options.requestTimeout,
    maxRequestsPerSocket: options.maxRequestsPerSocket,
    // Rapid Reset: cancelled streams a connection may send (http_common).
    streamResetBurst: options.streamResetBurst, streamResetRate: options.streamResetRate,
    // WebTransport sessions a connection may hold at once (SETTINGS_WT_MAX_
    // SESSIONS); unset, no limit.
    maxWebTransportSessions: options.maxWebTransportSessions,
    // QUIC's transport parameters (tls_bridge): windows and stream limits.
    transportParams: options.transportParams,
    // The congestion window a connection starts with, in packets (20).
    initialCongestionWindow: options.initialCongestionWindow,
    // A returning client's connection starts from what the last one measured
    // (RFC 9959 Careful Resume); on unless false.
    carefulResume: options.carefulResume,
    // Startup's cap on the congestion window: 'stall' (default), 'always',
    // 'off' (quic_connection, startupCap); per connection by connectionOptions.
    startupCap: options.startupCap,
    // Path MTU discovery (off by default on Windows), the largest UDP
    // payload, the RTT assumed before a sample, the reordering a packet is
    // allowed (quic_connection's CONNECTION_OPTIONS).
    pmtuDiscovery: options.pmtuDiscovery,
    maxUdpPayloadSize: options.maxUdpPayloadSize,
    initialRtt: options.initialRtt,
    reorderWindow: options.reorderWindow,
    // Per QUIC connection, asked once its ClientHello is in: (info, callback)
    // → { transportParams, initialCongestionWindow, carefulResume, startupCap,
    //     pmtuDiscovery, maxUdpPayloadSize, initialRtt, reorderWindow }.
    connectionOptions: options.connectionOptions,
    // The QUIC versions accepted, in preference (quic_version.js): ['v1', 'v2'].
    quicVersions: options.quicVersions,
    alpn: quicAlpn,
    maxConnections: options.maxConnections || 10000,
    // External UDP sockets (shared UDP port scenario). When provided,
    // the UDP layer is owned externally — caller feeds packets via
    // server.handlePacket(msg, rinfo). See RFC 9443.
    socket:  options.socket  || null,
    socket6: options.socket6 || null,
    // grease_quic_bit (RFC 9287): on, except with external sockets — a port
    // they share with other protocols may tell QUIC apart by that bit.
    // true: the port is QUIC's alone, grease there too.
    greaseQuicBit: options.greaseQuicBit
  };
  // node:tls's options (tls_options.js) — to a QUIC server that will run:
  // one that does not (http3: false) is still built, and would refuse what
  // only HTTP/3 cannot do (maxVersion TLSv1.2, TLS 1.2-only ciphers).
  if (enableH3) Object.assign(h3Options, tlsPassOn);

  var isExternalUdp = !!(options.socket || options.socket6);

  var h3srv = createH3Server(h3Options, function (plainReq, plainRes) {
    // h3_server already attached a socket stand-in carrying the QUIC
    // connection's address and its TLS fingerprints. Building a fresh stub
    // here and using that instead threw all of it away — the application saw
    // an object with no getJA4 and concluded, reasonably, that this
    // connection had no TLS.
    var socketStub = plainReq.socket || _makeSocketStub();
    if (!socketStub.remoteAddress) socketStub.remoteAddress = plainReq.remoteAddress || null;
    if (!socketStub.remotePort) socketStub.remotePort = plainReq.remotePort || null;

    // ---- Wrap plain req into IncomingMessage (Readable) ----
    var req = new IncomingMessage({
      httpVersion: '3.0',
      method: plainReq.method,
      url: plainReq.url,
      headers: plainReq.headers || {},
      streamId: plainReq.stream_id,
      socket: socketStub
    });

    // req.headers.host, from :authority — as HTTP/2 already provides it.
    //
    // HTTP/2 and HTTP/3 both carry the host as :authority and no Host header,
    // and the HTTP/2 path has always synthesized `host` from it
    // (pseudoHeadersToRequest in http_common). This path never did, so the
    // same application saw headers.host on one protocol and undefined on the
    // other — including for every WebTransport session, which only exists
    // over HTTP/3.
    //
    // ADDED, not substituted: the pseudo-headers stay, since code routes on
    // them (:protocol is how a WebTransport CONNECT is recognised). And added
    // AFTER the IncomingMessage is built, so rawHeaders — the record of what
    // the client actually sent, and what JA4H is computed from — is untouched.
    if (req.headers.host === undefined && req.headers[':authority'] !== undefined) {
      req.headers.host = req.headers[':authority'];
    }

    // Carried across the wrapper, like the socket above: built on the
    // connection, and lost if only the fields listed in the constructor
    // survive.
    if (plainReq.h3Fingerprint) req.h3Fingerprint = plainReq.h3Fingerprint;
    // Came in 0-RTT (and earlyDataFilter let it through): it may be a
    // replay — nothing with an effect that must happen once.
    req.earlyData = plainReq.earlyData === true;
    if (plainReq.webTransportProtocols) req.webTransportProtocols = plainReq.webTransportProtocols;

    // Bridge data from plain req → IncomingMessage.
    //
    // The body's flow-control credit goes back to the client as the
    // application READS it (_read), not as it arrives — as over HTTP/2 (see
    // h2_server). A handler that does not read at once — an authorization
    // check first, a lookup — had the whole upload taken in and held in
    // memory meanwhile, as fast as the client could send it. Now the client
    // can be ahead of the reader by one window, and no more.
    var holdsBody = typeof plainReq._holdBody === 'function';
    var received = null;
    if (holdsBody) {
      plainReq._holdBody();
      // Credited for what has been read (utils' creditAsRead).
      received = creditAsRead(req, function (n) { plainReq._creditBody(n); });
      // Read to the end, or abandoned (destroyed, aborted): nothing more to
      // wait for.
      req.on('close', function () { plainReq._releaseBody(); });
    }
    plainReq.on('data', function (chunk) {
      // Nobody will read it: let it go, credit and all.
      if (req.destroyed) { if (holdsBody) plainReq._releaseBody(); return; }
      if (received) received(chunk.length);
      req._pushData(chunk);
    });
    plainReq.on('end', function () {
      // Its trailers, if it sent any — before 'end', where node:http has them.
      if (plainReq.trailers) {
        req.trailers = plainReq.trailers;
        req.rawTrailers = [];
        for (var tn in plainReq.trailers) req.rawTrailers.push(tn, String(plainReq.trailers[tn]));
      }
      req._endData();
    });
    // Once the response is complete: is the rest of the body still wanted?
    // As node:http2 decides it — if the application has started reading it.
    plainReq._wantsRest = function () { return !req.destroyed && req.readableFlowing !== null; };

    // ---- Wrap plain res into ServerResponse (Writable) ----
    // ServerResponse._write → plainRes.write
    // ServerResponse._flushHeaders → plainRes.writeHead
    // ServerResponse._final → plainRes.end
    var res = new ServerResponse({
      streamId: plainReq.stream_id,
      socket: socketStub
    });
    res.req = req;

    // The stream was cancelled under this request (see releaseHttpStream in
    // h3_server) — handled as h2_server's abortStream does: 'aborted' always,
    // an Error only to a listener that asked for one, and 'close' on the
    // response so a handler still writing can stop.
    plainReq.on('aborted', function () {
      if (req.aborted) return;
      var err = new Error('stream reset by peer'); err.code = 'ERR_STREAM_RESET';
      req._abort(err);   // 'aborted', an Error only to a listener, 'close'
      res._abortResponse();
    });
    // The application giving the exchange up — res.destroy([err]),
    // req.destroy([err]), as on node:http2 where either ends the stream —
    // reaches the client: h3_server's abort (RESET_STREAM and STOP_SENDING,
    // or only STOP_SENDING once the response is complete).
    var giveUp = function (err) { plainRes.abort(err ? 0x0102 : 0x010c); };   // H3_INTERNAL_ERROR : H3_REQUEST_CANCELLED
    res._onDestroy(giveUp);
    req._onDestroy(function (err) { if (!res.writableFinished && !res.destroyed) res.destroy(err); else giveUp(err); });

    // Store wrapper references for WebTransport event forwarding.
    // MUST come after `res` is created (was previously set while res was
    // still undefined due to var hoisting).
    plainReq._wrapper = req;
    plainRes._wrapper = res;

    // Override internal methods to delegate to the plain H3 res.
    // One chunk is held back so that _final can send the last data and the
    // FIN together via plainRes.end(chunk): res.end('ok') is one packet, not
    // the data and then a FIN-only packet. (A FIN-only packet is recovered
    // like any other when lost — see fin_pns in quic_connection — so this is
    // about packets, not correctness.) Backpressure therefore bounds what is
    // held at the high-water mark plus that one chunk.
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
      // Done with this write once the stream has caught up to within the
      // high-water mark — not at once. Calling back at once told Writable
      // nothing was ever buffered, so write() never returned false and a
      // piped file was read into memory as fast as the disk allowed.
      plainRes.whenSent(res.writableHighWaterMark, callback);
    };

    res._final = function (callback) {
      if (!res.headersSent) res._flushHeaders();
      // res.addTrailers(): a HEADERS frame after the body, which carries the
      // FIN instead (gRPC's grpc-status rides there).
      var trailers = res.trailers && Object.keys(res.trailers).length ? res.trailers : null;
      if (_pendingChunk !== null) {
        plainRes.end(_pendingChunk, trailers);   // data + FIN together
      } else {
        plainRes.end(null, trailers);            // FIN only (no body written)
      }
      callback();
    };

    // 103 Early Hints — the HTTP/3 one, written on the same stream.
    if (plainRes.writeEarlyHints) {
      res.writeEarlyHints = function (hints, callback) {
        if (res.headersSent) { if (typeof callback === 'function') process.nextTick(callback); return; }
        plainRes.writeEarlyHints(hints, callback);
      };
    }

    // ---- Methods of the HTTP/3 response: its priority, and WebTransport's ----
    ['setPriority', 'sendDatagram', 'maxDatagramSize', 'createBidirectionalStream', 'createUnidirectionalStream',
     'createSendGroup', 'canOpenStream', 'setWebTransportProtocol', 'getStats', 'closeSession', 'drainSession'].forEach(function (m) {
      if (typeof plainRes[m] === 'function') res[m] = plainRes[m].bind(plainRes);
    });
    if ('datagrams' in plainRes) {
      Object.defineProperty(res, 'datagrams', { enumerable: true, get: function () { return plainRes.datagrams; } });
    }

    if (typeof handler === 'function') handler(req, res);
    ev.emit('request', req, res);
  });



  // RFC 9220: WebSocket over HTTP/3 arrives as extended CONNECT on a QUIC
  // stream and surfaces on the same 'upgrade' event as HTTP/1.1 and HTTP/2.
  // Three transports, one event, one WebSocketServer.
  h3srv.on('upgrade', function (req, stream, head) { ev.emit('upgrade', req, stream, head); });
  h3srv.on('stream_open', function (conn, id) { ev.emit('stream_open', conn, id); });
  h3srv.on('stream_reset', function (conn, id, code) { ev.emit('stream_reset', conn, id, code); });

  // A new QUIC connection, before its handshake. On a server that runs all
  // three protocols this shares the event with TCP connections, so a listener
  // may receive either a net.Socket or a QUIC connection handle. Both carry
  // remoteAddress, destroyed and destroy() — the three things screening code
  // uses — and the handle's httpVersion ('3.0') tells them apart where it
  // matters.
  h3srv.on('connection', function (conn) { ev.emit('connection', conn); });
  h3srv.on('handshakeLoad', function (e) { ev.emit('handshakeLoad', e); });
  h3srv.on('secureConnection', function (conn) { ev.emit('secureConnection', conn); });
  h3srv.on('tlsClientError', function (err, conn) { ev.emit('tlsClientError', err, conn); });

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

  // The QUIC layer's errors — a UDP bind that fails, most importantly — are
  // this server's errors. h3_server emits them, and nothing here listened,
  // so a port that could not be bound left listen() waiting forever with no
  // sign of why.
  h3srv.on('error', function (err) {
    if (err && !err.transport) err.transport = 'udp';
    ev.emit('error', err);
  });

  // ============================================================
  //  Building versus binding.
  //
  //  Everything a request needs — the TLS layer, ALPN, HTTP/2, HTTP/1.1,
  //  HTTP/3 — is built HERE, when the server is created. listen() only binds
  //  the ports this server owns.
  //
  //  It used to be the other way round: the protocol layers were built inside
  //  listen(), so a server whose sockets belonged to someone else still had to
  //  call listen() to exist — a listen() that listened to nothing — and a
  //  separate flag told it not to bind. Now the rule is simply:
  //
  //      listen() not called   → nothing bound; feed it through
  //                              handlePacket() (UDP) and handleConnection()
  //                              (TCP), from whoever owns the ports
  //      listen(port) called   → binds TCP, and UDP unless `socket` was given
  //
  //  A server can also be built and bound — the ordinary case — with nothing
  //  changing for callers that always called listen().
  // ============================================================

  // The port Alt-Svc advertises. listen(port) sets it; a server that is fed
  // from outside never calls listen(), and takes it from `options.port`
  // instead — quico cannot otherwise know which port its clients see.
  var altSvcPort = (options.port !== undefined && options.port !== null) ? options.port : 443;

  // A function, so HTTP/1.1 and HTTP/2 read the value per response. They are
  // built before listen() can say which port is real.
  //
  // Alt-Svc advertises HTTP/3 on the same authority (RFC 9114 §3.3), which is
  // how a browser that arrived over TCP learns to try QUIC next time.
  //
  // Only for an HTTP/3 this server runs. With http3:false it was sent anyway,
  // on the guess that HTTP/3 was served elsewhere on the same port — and when
  // it was not, every browser was sent to try a QUIC endpoint that does not
  // exist, failing over back to TCP each time the advertisement was renewed.
  // HTTP/3 served by something else is said with `altSvc`, the header value
  // as is (`'h3=":443"; ma=86400'`); `altSvc: false` sends none at all.
  function altSvcValue() { return 'h3=":' + altSvcPort + '"; ma=86400'; }
  var altSvcOption = options.altSvc;
  if (altSvcOption !== undefined && altSvcOption !== false && altSvcOption !== null && typeof altSvcOption !== 'string') {
    throw new TypeError('options.altSvc must be a string or false');
  }
  function altSvcHeader() {
    if (typeof altSvcOption === 'string') return altSvcOption;
    if (altSvcOption === false || altSvcOption === null || !enableH3) return null;
    return altSvcValue();
  }

  var tcpServer = null;
  var hasTlsCredentials = (tlsKey && tlsCert) || options.SNICallback;

  function onRequest(req, res) {
    if (req.earlyData === true) { earlyGate(req, res); return; }
    runHandler(req, res);
  }
  function runHandler(req, res) {
    if (typeof handler === 'function') handler(req, res);
    ev.emit('request', req, res);
  }

  // A request read from TLS early data (HTTP/2, HTTP/1.1; HTTP/3's is
  // h3_server's): handled now only if earlyDataFilter lets it — by default a
  // GET, HEAD or OPTIONS — or answered 425 Too Early, which the client
  // sends again after the handshake (RFC 8470 §5.2). No answer within
  // 100 ms: 425.
  function earlyGate(req, res) {
    runEarlyDataFilter(options.earlyDataFilter, req, function (allow) {
      if (res.writableEnded || res.destroyed) return;
      if (allow) { runHandler(req, res); return; }
      req.resume();
      stats.earlyData.tooEarly++;
      try { res.writeHead(425, { 'content-length': '0' }); res.end(); } catch (e) {}
    });
  }

  if (needsTcp) {
    var shared = {
      shouldUpgradeCallback: shouldUpgradeCallback,
      // Not over cleartext: HTTP/3 is always TLS, and browsers take Alt-Svc
      // only from an https origin — on http:// it advertised a service that
      // could not exist there.
      altSvc: hasTlsCredentials && altSvcHeader() !== null ? altSvcHeader : null,
      maxHeaderListSize: options.maxHeaderListSize,
      headersTimeout: options.headersTimeout,
      keepAliveTimeout: options.keepAliveTimeout,
      requestTimeout: options.requestTimeout,
      // node:http's: requests per connection (HTTP/1.1: the Nth closes it;
      // HTTP/2 and HTTP/3: GOAWAY after it).
      maxRequestsPerSocket: options.maxRequestsPerSocket,
      // Rapid Reset, HTTP/2's (http_common streamResetLimiter).
      streamResetBurst: options.streamResetBurst, streamResetRate: options.streamResetRate,
      maxHeadSize: options.maxHeadSize || options.maxHeaderSize,
      maxHeaderCount: options.maxHeaderCount,
      // These were being dropped: an application could set them and nothing
      // downstream ever saw them, which is worse than not offering the option
      // at all — it looks configured and is not.
      maxConcurrentStreams: options.maxConcurrentStreams,
      maxSessionMemory: options.maxSessionMemory,
      initialWindowSize: options.initialWindowSize,
      connectionWindowSize: options.connectionWindowSize,
      maxFrameSize: options.maxFrameSize,
      headerTableSize: options.headerTableSize,
      enableConnectProtocol: options.enableConnectProtocol,
      stats: stats
    };

    tcpServer = createTcpListener(Object.assign({
      // Cleartext when there are no credentials: a dev server, or a service
      // behind a terminating proxy. Without TLS there is no ALPN, so
      // tcp_listener tells h2c from HTTP/1.1 by looking for the connection
      // preface instead.
      tls: hasTlsCredentials ? lemonTls : null,
      key: tlsKey,
      cert: tlsCert,
      ca: tlsCa,
      SNICallback: options.SNICallback,
      ticketKeys: ticketKeys,
      ticketData: ticketData,
      ech: ech,
      ocspRequest: ocspRequest,
      // node:http's TCP options, with its defaults: Nagle off, keep-alive off.
      noDelay: options.noDelay,
      keepAlive: options.keepAlive,
      keepAliveInitialDelay: options.keepAliveInitialDelay,
      // 0-RTT over TLS 1.3 (HTTP/2, HTTP/1.1): the same options as HTTP/3's,
      // as they are at each connection (setOptions changes them).
      earlyDataNow: function () { var o = h3srv.getOptions(); return { on: o.earlyData === true, maxAge: o.earlyDataMaxAge }; },
      earlyDataReplay: options.earlyDataReplay,
      stats: stats
    }, tlsPassOn));   // node:tls's options (tls_options.js)

    var h2srv = null;
    var h1srv = null;

    if (enableH2) {
      h2srv = createH2Server(shared, onRequest);
      h2srv.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
      h2srv.on('sessionError', function (err, session) { ev.emit('sessionError', err, session); });
      // Extended CONNECT (RFC 8441) arrives on the same 'upgrade' event as an
      // HTTP/1.1 Upgrade, so a WebSocketServer attached to this server serves
      // both without knowing which carried the connection.
      h2srv.on('upgrade', function (req, stream, head) {
        if (wantsConnectUdp(req)) { connectUdpH2(req, stream); return; }
        ev.emit('upgrade', req, stream, head);
      });
      // Stream lifecycle, for rate limiting. `conn` carries the address to key
      // on and the two ways to refuse; see h2_server.
      h2srv.on('stream_open', function (conn, id) { ev.emit('stream_open', conn, id); });
      h2srv.on('stream_reset', function (conn, id, code) { ev.emit('stream_reset', conn, id, code); });
    }
    if (enableH1) {
      h1srv = createH1Server(shared, onRequest);
      h1srv.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
      // 'upgrade' is how WebSocket (and anything else that switches protocols)
      // gets the raw socket. Same signature as node:http, so the `ws` package
      // works over this server unchanged.
      h1srv.on('upgrade', function (req, socket, head) {
        if (wantsConnectUdp(req)) { connectUdpH1(req, socket, head); return; }
        ev.emit('upgrade', req, socket, head);
      });
    }

    // Registration order is the server's ALPN preference — tcpAlpn, which is
    // h2 then HTTP/1.1 unless ALPNProtocols says otherwise. Names beyond HTTP
    // are only meaningful with TLS: without it there is no ALPN to carry them.
    for (var a = 0; a < tcpAlpn.length; a++) {
      var proto = tcpAlpn[a];
      if (proto === 'h2') tcpServer.register('h2', h2srv.handleConnection);
      else if (proto === 'http/1.1') tcpServer.register('http/1.1', h1srv.handleConnection);
      else if (hasTlsCredentials) tcpServer.register(proto, closeAfterHandshake);
    }

    tcpServer.on('error', function (err) { ev.emit('error', err); });
    tcpServer.on('clientError', function (err, sock) { ev.emit('clientError', err, sock); });
    tcpServer.on('tlsClientError', function (err, sock) { ev.emit('tlsClientError', err, sock); });
    // Fires before the TLS handshake — see tcp_listener. Same name and same
    // argument as node:net, so an IP screen written for node:http works here.
    tcpServer.on('connection', function (sock) {
      armSocketTimeout(sock);
      ev.emit('connection', sock);
    });
    tcpServer.on('secureConnection', function (sock) { ev.emit('secureConnection', sock); });
  }

  // External UDP: the sockets are the caller's, and so is reading them. What
  // the QUIC layer still needs is its own housekeeping — the idle sweep, and
  // larger kernel buffers — and that starts now, since listen() may never be
  // called. h3srv.listen() in external mode binds nothing; see quic_server.
  if (enableH3 && isExternalUdp) {
    h3srv.listen(altSvcPort, null, function () {});
  }


  /**
   * Accept a TCP connection accepted by someone else.
   *
   * For a server whose TCP port belongs to another component — typically one
   * that demultiplexes it by first byte, sending TLS here and other protocols
   * elsewhere, the way RFC 9443 splits a UDP port. The socket is treated
   * exactly as one this server accepted itself: 'connection' fires before the
   * TLS handshake, and ALPN routes it to HTTP/2 or HTTP/1.1.
   *
   * Works without listen(): the layers exist from createServer. Bytes the
   * owner read to classify the connection must be put back first —
   * socket.unshift(chunk) — or the TLS layer starts mid-record.
   */
  function handleConnection(socket) {
    if (!tcpServer) {
      // HTTP/1.1 and HTTP/2 are both off; there is nothing to hand it to.
      try { socket.destroy(); } catch (e) {}
      return;
    }
    tcpServer.handleConnection(socket);
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
    if (port !== 0) altSvcPort = port;

    // Only what this server owns: UDP unless it was handed sockets, TCP unless
    // both HTTP/1.1 and HTTP/2 are off.
    var bindUdp = enableH3 && !isExternalUdp;
    var remaining = (bindUdp ? 1 : 0) + (needsTcp ? 1 : 0);
    var called = false;

    function done() {
      remaining--;
      if (remaining <= 0 && !called) {
        called = true;
        // After listen(0) the OS chose the port; Alt-Svc must name that one.
        if (port === 0 && tcpServer && tcpServer.address()) altSvcPort = tcpServer.address().port;
        ev.emit('listening');
        if (typeof callback === 'function') callback();
      }
    }

    // Nothing to bind — every socket is external. Still answer, and still
    // asynchronously, like a real bind would.
    if (remaining === 0) { remaining = 1; setImmediate(done); return server; }

    if (bindUdp) h3srv.listen(port, host, done);
    if (needsTcp) tcpServer.listen(port, host || '0.0.0.0', done);

    return server;
  }

  function close(callback) {
    // h3srv is closed whenever HTTP/3 is on, bound or not: in external mode it
    // still runs a sweep timer, started at creation.
    var remaining = (enableH3 ? 1 : 0) + (tcpServer ? 1 : 0);

    function onClose() {
      remaining--;
      if (remaining <= 0 && typeof callback === 'function') callback();
    }

    if (remaining === 0) { if (typeof callback === 'function') callback(); return; }
    if (enableH3) h3srv.close(onClose);
    // tcp_listener.close() ends idle connections, including ones handed in
    // through handleConnection, and closes its port only if it bound one.
    if (tcpServer) { tcpServer.close(onClose); tcpServer = null; }
  }

  function address() {
    // The TCP listener knows the port the OS actually assigned, which is the
    // only useful answer after listen(0).
    if (tcpServer && typeof tcpServer.address === 'function') {
      var addr = tcpServer.address();
      if (addr) return addr;
    }
    return { address: '0.0.0.0', family: 'IPv4', port: altSvcPort };
  }


  // ============================================================
  //  Public API
  // ============================================================

  // ---- server.setTimeout / server.timeout — node:http's ----
  //
  // Inactivity on a connection's socket: after `serverTimeout` ms with nothing
  // read or written, 'timeout' is emitted with the socket — and if nothing
  // listens for it, the socket is destroyed. 0 (the default) disables it.
  // Applied when a connection is accepted, so a change affects new
  // connections only — as in Node. TCP connections (HTTP/1.1, HTTP/2); an
  // HTTP/3 connection has QUIC's own idle timeout. This used to only register
  // the callback: no connection ever timed out.
  var serverTimeout = 0;
  function armSocketTimeout(sock) {
    if (!(serverTimeout > 0) || typeof sock.setTimeout !== 'function') return;
    sock.setTimeout(serverTimeout);
    sock.on('timeout', function () {
      if (ev.listenerCount('timeout') > 0) ev.emit('timeout', sock);
      else { try { sock.destroy(); } catch (e) {} }
    });
  }

  var server = {
    listen: listen,
    close: close,
    address: address,
    handleConnection: handleConnection,

    /**
     * The session ticket keys: 48 bytes, the key every ticket is sealed with
     * — TCP and QUIC alike. tls.Server's names and rules: setTicketKeys takes
     * a 48-byte Buffer and throws on anything else.
     *
     * A server that keeps its keys across restarts (a file, say) passes them
     * as options.ticketKeys, and can replace them while running: connections
     * from then on use the new key. Tickets sealed with the old one no longer
     * open — each of those clients does one full handshake and gets a new
     * ticket, as after a restart with random keys.
     */
    getTicketKeys: function () { return ticketKeys; },
    setTicketKeys: function (keys) {
      if (!Buffer.isBuffer(keys) || keys.length !== 48) {
        throw new TypeError('ticket keys must be a 48-byte Buffer');
      }
      ticketKeys = keys;
      if (tcpServer) tcpServer.setTicketKeys(keys);
      h3srv.setTicketKeys(keys);
    },

    /**
     * The Encrypted Client Hello keys, TCP and QUIC alike. Rotation without a
     * restart: publish the new config in DNS (ech= in the HTTPS record), then
     * setEchKeys with the new key and the old one kept as retry: false until
     * the old record's TTL has run out — clients still holding it connect
     * meanwhile. New connections use the new set; a bad key throws and the
     * old set stays.
     */
    getEchKeys: function () { return ech; },
    setEchKeys: function (keys) {
      if (keys) lemonTls.checkEchKeys(keys);
      ech = keys || null;
      if (tcpServer) tcpServer.setEchKeys(ech);
      h3srv.setEchKeys(ech);
    },

    /**
     * The secret HTTP/3 stateless reset tokens are derived from (RFC 9000
     * §10.3) — node:quic's resetTokenSecret, at least 16 bytes. Kept across
     * restarts (options.resetTokenSecret, or set here once read), it lets a
     * restarted server tell each browser still holding a connection to the
     * old one that it is gone, instead of leaving it to time out.
     */
    /**
     * HTTP/3 address validation with Retry (RFC 9000 §8.1.2): while on, each
     * new client proves its address with one extra round trip before any
     * connection state or key exchange is spent on it — the defence against
     * a flood of Initials from spoofed addresses. quico never turns it on by
     * itself; the application decides when (always, never, under load) and
     * can switch it at any moment. Applies from the next new client on.
     */
    getValidateAddress: function () { return h3srv.getValidateAddress(); },
    setValidateAddress: function (on) { h3srv.setValidateAddress(on); },

    /**
     * HTTP/3 handshakes under way: connections made and not yet complete
     * (the client's Finished verified). The application decides what load
     * is — 'handshakeLoad' ({ pending, high }) tells it when the count
     * reaches handshakeLoadThreshold (high: true) and when it is back under
     * half of it (high: false) — and what to do: setOptions({
     * validateAddress: true }), say. maxHandshakesPerAddress caps them per
     * client address; past it an Initial makes no connection. 0 turns either
     * off. Both change with setOptions, at once.
     */
    getPendingHandshakes: function () { return h3srv.getPendingHandshakes(); },
    /**
     * The options that can change while the server runs, by createServer's
     * names — one call, a partial object, checked whole before anything
     * changes (a bad value: TypeError / RangeError, nothing changed):
     *   validateAddress, handshakeLoadThreshold, maxHandshakesPerAddress
     *     the server's (from the next client; the threshold at once);
     *   startupCap, initialCongestionWindow, carefulResume, pmtuDiscovery,
     *   maxUdpPayloadSize, initialRtt, reorderWindow
     *     what new HTTP/3 connections are made with — open ones keep
     *     theirs (conn.setOptions, or connectionOptions, for one).
     * A name that cannot change this way says what can (cert:
     * setSecureContext()). getOptions(): all of them, as they are now.
     */
    getOptions: function () { return h3srv.getOptions(); },
    setOptions: function (o) { h3srv.setOptions(o); return server; },

    getResetTokenSecret: function () { return h3srv.getResetTokenSecret(); },
    setResetTokenSecret: function (secret) { h3srv.setResetTokenSecret(secret); },

    /**
     * Carry another protocol over this server's TLS port, beside HTTP.
     *
     * A client that negotiates `name` by ALPN is handed to `handler(socket)`
     * after the TLS handshake, as a decrypted Duplex. `options.sniff(bytes)`
     * also claims connections that negotiated no ALPN, by their first bytes —
     * how TURN over TLS on 443 is recognised from a browser, which offers no
     * ALPN for it. `options.paused` hands the socket over paused for the
     * handler to resume. See register() in tcp_listener.
     *
     * The name is added to the ALPN list the server advertises, after the
     * HTTP versions, so an HTTPS client still gets h2 or HTTP/1.1.
     */
    addProtocol: function (name, handler, options) {
      if (!tcpServer) throw new Error('addProtocol needs the TCP side (http1 or http2 enabled)');
      if (!hasTlsCredentials) throw new Error('addProtocol needs TLS: without it there is no ALPN, and nothing to sniff after');
      tcpServer.register(name, handler, options);
      return server;
    },

    /**
     * CONNECT-UDP's figures, across this server's tunnels: { active,
     * accepted, rejected, closed, packetsFromClient, bytesFromClient,
     * packetsToClient, bytesToClient, droppedFromClient, droppedToClient }
     * — those of tunnels still open included. Each tunnel has its own
     * (tunnel.stats, and the 'close' event's argument).
     */
    getConnectUdpStats: function () { return udpProxy.stats(); },

    /**
     * The server's counters since it was made, a copy: connections and TLS
     * handshakes over QUIC and TCP, the protocols they spoke, 0-RTT taken,
     * refused and answered 425, how connections ended by code (QUIC and
     * HTTP/3 CONNECTION_CLOSE, HTTP/2 GOAWAY, HTTP/1.1 requests refused),
     * streams reset by code, datagrams held at the anti-amplification limit,
     * internal errors caught. Counts only — no addresses, no names.
     * See server_stats.js.
     */
    getStats: function () { return stats.snapshot(); },

    // server.on('request', app) — the other way an app is attached.
    on: function (name, fn) { if (name === 'request') adoptApp(fn); ev.on(name, fn); return server; },
    once: function (name, fn) { if (name === 'request') adoptApp(fn); ev.once(name, fn); return server; },
    off: function (name, fn) { ev.off(name, fn); return server; },
    removeListener: function (name, fn) { ev.removeListener(name, fn); return server; },
    emit: function () { ev.emit.apply(ev, arguments); return server; },
    setTimeout: function (msecs, callback) {
      if (typeof msecs === 'function') { callback = msecs; msecs = undefined; }
      if (msecs !== undefined) serverTimeout = Math.max(0, Number(msecs) || 0);
      if (typeof callback === 'function') ev.on('timeout', callback);
      return server;
    },
    get timeout() { return serverTimeout; },
    set timeout(ms) { serverTimeout = Math.max(0, Number(ms) || 0); },

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
