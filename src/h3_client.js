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

import dns from 'node:dns';
import { EventEmitter } from 'node:events';
import { DEBUG } from './utils.js';
import { H3Connection, H3_ERR, H3_ERR_NAME, H3_STREAM_CODES, addH3SessionOps, h2CodeToH3 } from './h3.js';
import { createQuicClientSocket } from './quic_socket.js';
import { parseVersionList } from './quic_version.js';
import { checkConnectionOptions, CONNECTION_OPTIONS } from './quic_connection.js';
import { trailerFields, formatPriority, urlHostname, formatAuthority, StreamBase, http2HeaderObject, http2RequestFields, streamStateOf,
         nodeError, argType, sessionGone, sessionCodeError, pendingCancel } from './http_common.js';
import { creditAsRead } from './utils.js';

// What the body takes before write() says wait — written while connecting,
// or not yet sent on the stream.
var BODY_HIGH_WATER = 64 * 1024;


// The QUIC client connection's options from a request's or a session's:
// TLS (tls.connect's names), QUIC versions and connection options. What is
// particular to one connection (the address, a session to resume, a token,
// 0-RTT, the callbacks) the caller adds.
function quicClientOptions(options, hostname, rejectUnauthorized, ca) {
  return {
    socketBufferSize: options.socketBufferSize,
    // SNI and the name the certificate is checked for: tls.connect's
    // servername where given.
    hostname: options.servername || hostname,
    rejectUnauthorized: rejectUnauthorized,
    ca: ca,
    // A client certificate, for a server that asks (https.request's names).
    key: options.key || null, cert: options.cert || null, passphrase: options.passphrase,
    // Encrypted Client Hello: the server's ECHConfigList, or GREASE ECH.
    ech: options.ech || null,
    echGrease: options.echGrease === true,
    // The key-exchange groups to offer (tls.connect's ecdhCurve).
    ecdhCurve: options.ecdhCurve,
    // The signature schemes to offer (tls.connect's sigalgs).
    sigalgs: options.sigalgs,
    quicVersions: options.quicVersions,
    // This client's connection options (quic_connection's CONNECTION_OPTIONS):
    // Startup's cap on what it sends (an upload's), path MTU discovery, the
    // largest UDP payload, the RTT assumed before a sample, the reordering
    // a packet is allowed, the initial window.
    startupCap: options.startupCap,
    pmtuDiscovery: options.pmtuDiscovery,
    maxUdpPayloadSize: options.maxUdpPayloadSize,
    initialRtt: options.initialRtt,
    reorderWindow: options.reorderWindow,
    initialCongestionWindow: options.initialCongestionWindow
  };
}

// res.socket (and a session's socket) over HTTP/3: there is no TLS socket —
// the handshake ran in the QUIC connection — so what an application asks a
// TLSSocket for here is answered from that connection: as over HTTP/2 and
// HTTP/1.1, whose res.socket is the lemon-tls socket. `conn` is { quic }.
function h3SocketInfo(conn) {
  var q = conn && conn.quic;
  if (!q) return null;
  return {
    encrypted: true,
    alpnProtocol: 'h3',
    get remoteAddress() { return q.remoteAddress || null; },
    get remotePort() { return q.remotePort || null; },
    get echStatus() { return q.echStatus; },
    get echAccepted() { return q.echStatus === 'accepted'; },
    isSessionReused: function () { return !!(q.isSessionReused && q.isSessionReused()); },
    getPeerCertificate: function () { return q.getPeerCertificate ? q.getPeerCertificate() : {}; },
    getNegotiationResult: function () { return q.getNegotiationResult ? q.getNegotiationResult() : null; },
    // The connection's options while it runs (quic_connection's
    // setOptions) — shared by every request on it (a pooled connection).
    setOptions: function (o) { q.setOptions(o); return this; },
    getOptions: function () { return q.getOptions(); }
  };
}

// The address to connect to: `host` itself when it is one (localhost is
// 127.0.0.1), at once; else what dns.lookup gives.
function resolveHost(host, cb) {
  if (/^[\d.]+$/.test(host) || host.indexOf(':') >= 0 || host === 'localhost') {
    cb(null, host === 'localhost' ? '127.0.0.1' : host);
    return;
  }
  dns.lookup(host, function (err, address) { cb(err, address); });
}

// ============================================================
//  quico.request(options, callback)
//  API mirrors Node.js https.request()
// ============================================================

function request(options, callback) {
  if (typeof options === 'string') {
    var url = new URL(options);
    options = {
      hostname: urlHostname(url.hostname),
      port: parseInt(url.port) || 443,
      path: url.pathname + url.search
    };
  }

  var hostname = options.hostname || options.host || 'localhost';
  // Certificate verification options, forwarded to the QUIC/TLS layer.
  // Defaults to verifying (node:tls semantics); without this passthrough the
  // option dies here and H3 connections can never opt out — which makes the
  // one transport this library exists for the only one that can't reach a
  // self-signed or private-CA server (H2/H1.1 fallbacks honour the option).
  var rejectUnauthorized = options.rejectUnauthorized !== false;
  // Checked now, as https.request checks its options: thrown here, not from
  // inside the socket's callback later.
  parseVersionList(options.quicVersions, 'quicVersions');
  // The connection options it sets, checked now (thrown here, as above).
  (function () { var o = {}; for (var k in CONNECTION_OPTIONS) if (k !== 'carefulResume' && options[k] != null) o[k] = options[k]; checkConnectionOptions(o, 'request'); })();
  var ca = options.ca || null;
  var port = options.port || 443;
  var path = options.path || '/';
  var method = (options.method || 'GET').toUpperCase();
  var headers = options.headers || {};

  // Connection reuse: pass _connection = { quic, h3, udpSocket, nextStreamId }
  var existingConn = options._connection || null;
  // Auto-close the QUIC connection when this request finishes ONLY when we own
  // it — i.e. a fresh, standalone connection. Reused connections (existingConn)
  // and connections whose lifecycle is managed by an external pool
  // (options._managed, set by the unified client/agent) are left open; closing
  // them here would tear down a connection still pooled for reuse. Managed
  // connections are reaped by the agent (sweep/destroy) and the QUIC idle timer.
  var autoClose = !existingConn && !options._managed;

  // ---- Client Request object ----
  var reqBody = [];
  var reqFinished = false;
  var reqListeners = {};
  var quic = existingConn ? existingConn.quic : null;
  var h3 = existingConn ? existingConn.h3 : null;
  var udpSocket = existingConn ? existingConn.udpSocket : null;
  var streamId = null; // assigned when connection is ready
  var connected = existingConn ? true : false;
  var requestSent = false;   // HEADERS went out on streamId
  var readyDone = false;     // the stream exists and the request is this one's to send (ready)
  // 0-RTT (RFC 9001 §4.6, RFC 8470): with earlyData and a saved session, a
  // request that may be replayed safely — GET, HEAD, OPTIONS — goes before
  // the handshake ends. res.earlyData: 'accepted' (it went early and was
  // taken), 'rejected' (refused — by the server's TLS, or by a 425 — and
  // sent again after the handshake), null (not tried).
  // Decided when a connection is made (startConnection): the session is
  // read there — the unified client's is taken from its agent on that read,
  // and a request on a connection already open must not use one up.
  var earlyWanted = false;
  var earlyTried = false;     // set up on the early key (onEarly)
  var earlyResult = null;
  var earlyBody = null;       // what went early, to send again if refused
  var handshaken = false;     // onConnect has come
  var retry425 = false;       // the server answered the early request 425: again, after the handshake
  var after425 = null;        // to run at onConnect, when the 425 came first
  var streaming = false;     // HEADERS sent before the body ended: DATA follows as written
  var reqBodyBytes = 0, needDrain = false, drainWaiting = false;
  var reqTrailers = null;
  var finished = false;      // the response ended or failed
  var failed = false;        // the request failed (or was turned down): nothing more is sent
  var cancelled = false;     // destroy() was called
  var closeWhenSent = null;  // a connection of its own, its response done: closed once the body has gone

  var clientReq = {
    on: function (event, fn) {
      (reqListeners[event] = reqListeners[event] || []).push(fn);
      return clientReq;
    },

    // The body, as node:http's: held while connecting (write() false past
    // BODY_HIGH_WATER, then 'drain'), then streamed — HEADERS on the first
    // write once the stream exists, DATA as written, with the stream's
    // backpressure. After the response, too: a server may answer an upload
    // early (a 413, a 401) and read on. It was refused once the response had
    // ended, and the upload never finished — the server waited for a body
    // whose end never came.
    write: function (chunk) {
      if (failed || cancelled || reqFinished) return false;
      if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
      if (!chunk || chunk.byteLength === 0) return !needDrain;
      if (!streaming && readyDone && !requestSent) startStreaming();
      if (streaming) return streamOut(chunk);
      reqBody.push(chunk);
      reqBodyBytes += chunk.byteLength;
      if (reqBodyBytes >= BODY_HIGH_WATER) { needDrain = true; return false; }
      return true;
    },

    // RFC 9218: the `priority` header while the request has not gone, a
    // PRIORITY_UPDATE on the control stream after.
    setPriority: function (p) {
      if (requestSent) { if (h3 && !finished && !cancelled) h3.sendPriorityUpdate(streamId, p); return; }
      for (var k in headers) if (k.toLowerCase() === 'priority') delete headers[k];
      var v = formatPriority(p);
      if (v) headers.priority = v;
    },

    // `trailers` (node:http's addTrailers, through the unified client): a
    // HEADERS frame after the body, ending the stream (RFC 9114 §4.1).
    end: function (chunk, trailers) {
      if (reqFinished) return clientReq;
      if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
      reqTrailers = trailerFields(trailers);
      if (streaming) {
        reqFinished = true;
        if (failed || cancelled) return clientReq;
        if (chunk && chunk.byteLength) h3.sendBody(streamId, chunk, !reqTrailers);
        else if (!reqTrailers) h3.sendBody(streamId, null, true);
        if (reqTrailers) h3.sendHeaders(streamId, reqTrailers, true);
        if (closeWhenSent) { var c = closeWhenSent; closeWhenSent = null; c(); }
        return clientReq;
      }
      if (chunk && chunk.byteLength) { reqBody.push(chunk); reqBodyBytes += chunk.byteLength; }
      reqFinished = true;
      if (readyDone) sendRequest();
      return clientReq;
    },

    // Cancel this request. Its stream is what ends (RFC 9114 §4.1.1:
    // STOP_SENDING and RESET_STREAM with H3_REQUEST_CANCELLED) — not the
    // connection, which may carry other requests (a pooled one does). This
    // closed the whole connection, every other request on it included.
    // A connection that is this request's alone is closed with it.
    destroy: function () {
      if (cancelled || finished) return;
      cancelled = true;
      var conn = clientReq._connection || existingConn;
      if (conn && conn._streamHandlers && streamId !== null) delete conn._streamHandlers[streamId];
      // Still connecting: closed in onConnect (or ends by itself if the
      // handshake fails) — closing the socket under a handshake in progress
      // would leave its timers sending into a closed socket.
      if (autoClose) { if (quic) closeConnection(); return; }
      // Sent or not: its stream ID is taken, and a later request's higher
      // one opens it at the server (RFC 9000 §3.2) — where nothing would
      // ever end it, a stream of the connection's limit lost for good. So it
      // is cancelled either way; never written, its RESET_STREAM carries a
      // final size of 0 (sendRequest() will not run).
      if (h3 && streamId !== null) h3.abortStream(streamId, 0x10c);   // H3_REQUEST_CANCELLED
    }
  };

  // ---- Client Response object ----
  var clientRes = {
    statusCode: 0,
    headers: {},
    trailers: {},
    rawTrailers: [],
    _listeners: {},
    _headersReceived: false,

    on: function (event, fn) {
      (clientRes._listeners[event] = clientRes._listeners[event] || []).push(fn);
      return clientRes;
    },

    // The body's flow-control credit, returned as the layer above reads it
    // rather than as it arrives (h3's holdBody) — as the server does with a
    // request body. Credited on delivery, a response nobody read yet was
    // taken in as fast as the server could send it: a slow consumer of a
    // large download held all of it in memory, and the server never slowed.
    _holdBody: function () { if (respConn && respConn.h3) respConn.h3.holdBody(streamId); },
    _creditBody: function (n) { if (respConn && respConn.h3) respConn.h3.creditBody(streamId, n); },
    _releaseBody: function () { if (respConn && respConn.h3) respConn.h3.releaseBody(streamId); }
  };
  var respConn = null;   // the connection the response comes on (setupResponseHandlers)

  function emit(obj, event, data) {
    var listeners = (obj._listeners || obj)[event] || [];
    // For reqListeners which is a plain object
    if (obj === reqListeners) listeners = reqListeners[event] || [];
    for (var i = 0; i < listeners.length; i++) {
      try { if (data !== undefined) listeners[i](data); else listeners[i](); } catch (e) {}
    }
  }


  // ---- Resolve hostname and connect (or reuse existing) ----
  if (existingConn) {
    // Reuse existing connection — allocate stream ID and send when ready.
    // The shared dispatch listeners were installed when the connection was
    // first created; installSharedHandlers() is idempotent.
    streamId = allocateStreamId(existingConn);
    installSharedHandlers(existingConn);
    setupResponseHandlers(existingConn);
    ready(existingConn);
  } else {
    resolveAndConnect(hostname, port);
  }


  function resolveAndConnect(host, port) {
    resolveHost(host, function (err, address) {
      if (err) { emit(reqListeners, 'error', err); return; }
      startConnection(address, port);
    });
  }


  function startConnection(remoteIp, remotePort) {
    if (cancelled) return;
    var sessionNow = options.session || null;
    earlyWanted = options.earlyData === true && !!sessionNow &&
                  (method === 'GET' || method === 'HEAD' || method === 'OPTIONS');
    udpSocket = createQuicClientSocket(Object.assign(quicClientOptions(options, hostname, rejectUnauthorized, ca), {
      remoteIp: remoteIp,
      remotePort: remotePort,
      // A saved session to resume with, and the request's 'session' event for
      // each the server sends — as https.request does (its socket's
      // 'session'). Only the request that opened the connection has one: a
      // request on a connection already open sees no handshake.
      session: sessionNow,
      // The server's stapled OCSP response, as the request's 'OCSPResponse'
      // (tls.connect's requestOCSP) — on the request that opened the connection.
      requestOCSP: options.requestOCSP === true,
      // A NEW_TOKEN token for the Initial (the agent keeps them), and the
      // request's 'newToken' event for the one the server gives for next time.
      token: options.token || null,
      earlyData: earlyWanted,
      onEarly: function (q, s) {
        if (cancelled) return;
        earlyTried = true;
        earlyResult = 'accepted';   // until the server says otherwise
        setUp(q, s);
      },
      onSocket: function (q) {
        q.on('session', function (buf) { emit(reqListeners, 'session', buf); });
        q.on('new_token', function (buf) { emit(reqListeners, 'newToken', buf); });
        q.on('OCSPResponse', function (buf) { emit(reqListeners, 'OCSPResponse', buf); });
      },

      onError: function (err) {
        if (cancelled) return;
        emit(reqListeners, 'error', err);
      },

      onConnect: function (q, s) {
        // Sent early: taken, nothing more to do — or refused, and the
        // connection has forgotten it: HTTP/3 starts over on it, and the
        // request goes again, in 1-RTT.
        if (earlyTried) {
          handshaken = true;
          if (cancelled) { closeConnection(); return; }
          if (after425) { var a425 = after425; after425 = null; a425(); return; }
          if (q.earlyDataStatus !== 'rejected') return;
          earlyResult = 'rejected';
          redoAfterEarly();
          return;
        }
        setUp(q, s);
      }
      // onClose: the helper closes the UDP socket; nothing extra needed here.
    }));
  }

  // What was sent early, refused: this request's stream and the HTTP/3
  // layer it went through are dropped, and both made again.
  function redoAfterEarly() {
    var old = respConn;
    if (old && old._streamHandlers) delete old._streamHandlers[streamId];
    if (h3 && h3.detach) h3.detach();
    requestSent = false; readyDone = false; streaming = false;
    if (earlyBody) { reqBody = earlyBody.body; reqTrailers = earlyBody.trailers; reqBodyBytes = 0; }
    setUp(quic, udpSocket);
  }

  // The early request answered 425: on a new stream of the same connection,
  // once the handshake is done (now, or at onConnect).
  function againAfter425() {
    function go() {
      if (cancelled || finished) return;
      var conn = respConn;
      requestSent = false; readyDone = false; streaming = false;
      if (earlyBody) { reqBody = earlyBody.body; reqTrailers = earlyBody.trailers; }
      earlyBody = null;
      retry425 = false;
      streamId = allocateStreamId(conn);
      setupResponseHandlers(conn);
      ready(conn);
    }
    if (handshaken) go(); else after425 = go;
  }

  function setUp(q, s) {
    (function () {
        quic = q;
        udpSocket = s;
        // Cancelled while connecting: the connection was for this request
        // (an owned one, or a pool lead whose followers have been released),
        // and nobody else holds it.
        if (cancelled) { closeConnection(); return; }
        if (DEBUG) console.log('[client] QUIC connected');

        h3 = new H3Connection({ quicConnection: quic, isServer: false });
        connected = true;

        // Build connection object for reuse
        var conn = { quic: quic, h3: h3, udpSocket: udpSocket, _nextStreamId: 0 };

        // Install the shared per-connection dispatch listeners ONCE, then
        // register this request in the connection's stream-handler map.
        installSharedHandlers(conn);
        streamId = allocateStreamId(conn);

        // Store on clientReq so caller (unified client) can reuse
        clientReq._connection = conn;

        setupResponseHandlers(conn);
        ready(conn);
    })();
  }


  /**
   * Allocate next client-initiated bidi stream ID.
   * Client bidi stream IDs: 0, 4, 8, 12, ... (id = n * 4)
   */
  function allocateStreamId(conn) {
    var id = conn._nextStreamId;
    conn._nextStreamId += 4;
    return id;
  }


  /**
   * Install the three HTTP/3 event listeners ONCE per connection. They dispatch
   * each event to the right request via the connection's stream-handler map
   * (keyed by stream id), so multiplexing many requests over a single
   * connection does NOT pile up listeners on the H3 emitter (previously every
   * request added another set of listeners that were never removed).
   * Idempotent per connection.
   */
  function installSharedHandlers(conn) {
    if (conn._streamHandlers) return;  // already installed for this connection
    conn._streamHandlers = {};
    var h3c = conn.h3;

    h3c.on('http_headers', function (sid, hdrs) {
      var h = conn._streamHandlers[sid];
      if (h) h.onHeaders(hdrs);
    });
    h3c.on('http_body', function (sid, data) {
      var h = conn._streamHandlers[sid];
      if (h) h.onBody(data);
    });
    h3c.on('http_trailers', function (sid, trailers) {
      var h = conn._streamHandlers[sid];
      if (h && h.onTrailers) h.onTrailers(trailers);
    });
    h3c.on('http_end', function (sid) {
      var h = conn._streamHandlers[sid];
      if (!h) return;
      delete conn._streamHandlers[sid];  // free per-stream state before dispatch
      h.onEnd();
    });
    // The response stream was ended over what the server sent on it (an
    // oversized HEADERS, a stream with no response): the request fails,
    // rather than waiting for an end that will not come.
    h3c.on('stream_error', function (sid, code, reason) {
      var h = conn._streamHandlers[sid];
      if (!h) return;
      delete conn._streamHandlers[sid];
      if (h.onError) h.onError(code, reason);
    });
    // The server reset the request stream (RESET_STREAM): the response, or
    // what is left of it, will not come. Nothing listened, and a response
    // cut off this way never ended nor failed — it hung.
    h3c.on('stream_reset', function (sid, code) {
      var h = conn._streamHandlers[sid];
      if (!h) return;
      delete conn._streamHandlers[sid];
      if (h.onReset) h.onReset(code);
    });
    // The server will not read the rest of the request (STOP_SENDING; QUIC
    // has reset our sending part in answer). Not heard before: a request
    // the server refused this way went on "writing" into nothing, and was
    // never told.
    h3c.on('stop_sending', function (sid, code) {
      var h = conn._streamHandlers[sid];
      if (h && h.onStopSending) h.onStopSending(code);
    });

    // GOAWAY (RFC 9114 §5.2): requests on streams from its id on were not,
    // and will not be, processed — retryable, as HTTP/2's (h2_client). And
    // the connection's end ends every request still on it. Neither was
    // heard: a request sent as the server's GOAWAY was on its way — the
    // server rejected it and closed, its RESET_STREAM behind the close —
    // waited for a response forever.
    function failAll(fromId, make) {
      for (var sid in conn._streamHandlers) {
        if (Number(sid) < fromId) continue;
        var h = conn._streamHandlers[sid];
        delete conn._streamHandlers[sid];
        if (h.onGone) h.onGone(make(Number(sid)));
      }
    }
    conn._goawayId = Infinity;
    h3c.on('goaway', function (id) {
      var goawayId = conn._goawayId = Math.min(conn._goawayId, Number(id));
      // For a pool: no new requests here (as an HTTP/2 session's goingAway).
      // The GOAWAY can come before the response that puts the connection in
      // the pool, so the pool asks rather than waits for the event.
      conn.goingAway = true;
      failAll(goawayId, function () {
        var e = new Error('HTTP/3 request not processed before GOAWAY');
        e.code = 'ERR_HTTP3_GOAWAY_UNPROCESSED';
        e.retryable = true;
        return e;
      });
    });
    // On 'closing' — the moment the connection is over (a CONNECTION_CLOSE
    // either way, the idle timeout) — not only on 'close', which waits out
    // the draining period (RFC 9000 §10.2, ~3 s): a response the server cut
    // off hung that long before it failed.
    function connectionOver() {
      failAll(0, function (sid) {
        var e = new Error('HTTP/3 connection closed before the response ended');
        e.code = 'ERR_HTTP3_CONNECTION_CLOSED';
        // Past a GOAWAY's id the server said it did not process it.
        e.retryable = sid >= conn._goawayId;
        return e;
      });
    }
    conn.quic.on('closing', connectionOver);
    conn.quic.on('close', connectionOver);
  }


  /**
   * Register this request's response handlers in the connection's stream map,
   * keyed by its streamId. Replaces per-request h3.on(...) registration —
   * routing is now by map key, so no per-listener streamId check is needed.
   */
  function setupResponseHandlers(conn) {
    respConn = conn;
    // A connection the server is done with — GOAWAY'd below this stream, or
    // gone — takes no request: it fails now, as it would have on the wire.
    // On the next tick: the caller has not attached its listeners yet.
    var state = conn.quic ? conn.quic.state : 'closed';
    if (streamId >= conn._goawayId || state === 'closed' || state === 'closing' || state === 'draining') {
      var gone = new Error(streamId >= conn._goawayId ? 'HTTP/3 request not processed before GOAWAY' : 'HTTP/3 connection closed before the response ended');
      gone.code = streamId >= conn._goawayId ? 'ERR_HTTP3_GOAWAY_UNPROCESSED' : 'ERR_HTTP3_CONNECTION_CLOSED';
      gone.retryable = true;
      process.nextTick(function () { fail(gone); });
      return;
    }
    conn._streamHandlers[streamId] = {
      onHeaders: function (hdrs) {
        // 1xx (103 Early Hints): informational — the response follows on the
        // same stream. node:http's 'information', not the response: taken as
        // it, the request got status 103 and the real head was lost.
        var st1 = parseInt(hdrs[':status'], 10);
        if (st1 >= 100 && st1 < 200) {
          var ih = {}, raw = [];
          for (var hn in hdrs) { if (hn[0] !== ':') { ih[hn] = hdrs[hn]; raw.push(hn, String(hdrs[hn])); } }
          emit(reqListeners, 'information', { statusCode: st1, statusMessage: '', httpVersion: '3.0', httpVersionMajor: 3, httpVersionMinor: 0, headers: ih, rawHeaders: raw });
          return;
        }
        // 425 Too Early to what went in 0-RTT (RFC 8470 §5.2): not the
        // response — the request goes again once the handshake is done.
        if (st1 === 425 && earlyBody && !retry425) { retry425 = true; earlyResult = 'rejected'; return; }
        clientRes.headers = hdrs;
        clientRes.statusCode = parseInt(hdrs[':status']) || 0;
        clientRes._headersReceived = true;
        clientRes.earlyData = earlyTried ? earlyResult : null;

        // Fire callback with response (once)
        if (typeof callback === 'function') {
          callback(clientRes);
          callback = null;
        }
        emit(reqListeners, 'response', clientRes);
      },

      // A Buffer, as https.request's 'data' (README: h3Request is the
      // single-protocol client "as https.request"): QUIC hands up a
      // Uint8Array, and `body += chunk` read its bytes as a list of numbers.
      // A view over the same memory, as IncomingMessage._pushData makes.
      onBody: function (data) {
        if (retry425) return;
        if (!Buffer.isBuffer(data)) data = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
        emit(clientRes, 'data', data);
      },

      // The response's trailers: res.trailers / res.rawTrailers, as node:http
      // has them by 'end' (gRPC's grpc-status).
      onTrailers: function (trailers) {
        clientRes.trailers = trailers;
        clientRes.rawTrailers = [];
        for (var tn in trailers) clientRes.rawTrailers.push(tn, String(trailers[tn]));
      },

      onError: function (code, reason) {
        var err = new Error('HTTP/3 stream error: ' + reason);
        err.code = 'ERR_HTTP3_STREAM_ERROR';
        err.errorCode = code;
        fail(err);
      },

      onReset: function (code) {
        var name = H3_ERR_NAME[code] || ('0x' + Number(code).toString(16));
        var err = new Error('HTTP/3 stream reset by the server: ' + name);
        err.code = 'ERR_HTTP3_STREAM_RESET';
        err.errorCode = code;
        // H3_REQUEST_REJECTED: the server did not process it (RFC 9114 §4.1.1)
        // — safe to retry, as HTTP/2's REFUSED_STREAM. Any other code is the
        // server's answer, not a failure to reach it: not sent again over TCP.
        err.retryable = (code === 0x10b);
        if (!err.retryable) err.requestError = true;
        fail(err);
      },

      // H3_NO_ERROR: the server answers without the rest of the body (RFC
      // 9114 §4.1.2) — the response comes, and is not to be discarded. Any
      // other code before a response: the request is refused or cancelled,
      // as by a reset (H3_REQUEST_REJECTED retryable).
      onStopSending: function (code) {
        if (code === 0x100 || clientRes._headersReceived) return;
        var h = conn._streamHandlers[streamId];
        if (h) delete conn._streamHandlers[streamId];
        var name = H3_ERR_NAME[code] || ('0x' + Number(code).toString(16));
        var err = new Error('HTTP/3 request stopped by the server: ' + name);
        err.code = 'ERR_HTTP3_STREAM_RESET';
        err.errorCode = code;
        err.retryable = (code === 0x10b);
        if (!err.retryable) err.requestError = true;
        fail(err);
      },

      // The connection gone (or past GOAWAY) under it. Sent, not processed
      // per GOAWAY, and not idempotent: the server may have acted on it — not
      // sent again over TCP (RFC 9110 §9.2.2).
      onGone: function (err) {
        if (!err.retryable && requestSent && !({ GET: 1, HEAD: 1, OPTIONS: 1, TRACE: 1, PUT: 1, DELETE: 1 })[method]) err.requestError = true;
        fail(err);
      },

      onEnd: function () {
        if (retry425 && !clientRes._headersReceived) { againAfter425(); return; }
        finished = true;
        clientRes._releaseBody();   // all of it has arrived: nothing more to wait for
        emit(clientRes, 'end');
        closeIfOwned();
      }
    };
  }

  // The request failed. Before the response began, the request reports it
  // ('error' — a fallback may still be tried); after, the response does —
  // the request's error was reported to a caller that had moved on to the
  // response, and the response hung.
  function fail(err) {
    if (finished) return;
    finished = true;
    failed = true;
    clientRes._releaseBody();
    if (clientRes._headersReceived) emit(clientRes, 'error', err);
    else emit(reqListeners, 'error', err);
    closeIfOwned();
  }

  // Auto-close only if we own the connection (see `autoClose` above) — after
  // the response ends, or fails.
  // An answer to early data can come before the handshake is confirmed,
  // and with it the server's session ticket: the close waits for that, or
  // the next visit would have no ticket to resume (and send early) with.
  // A body still being uploaded (an early answer) holds the close until it
  // has ended and gone: closed under it, the upload was cut off.
  function closeIfOwned() {
    if (!autoClose) return;
    var close = function () {
      if (earlyTried && quic && quic.whenConfirmed) quic.whenConfirmed(function () { setTimeout(closeConnection, 100); });
      else setTimeout(closeConnection, 100);
    };
    if (streaming && !reqFinished && !failed && !cancelled) {
      closeWhenSent = function () { if (quic && quic.whenAllSent) quic.whenAllSent(close); else close(); };
      return;
    }
    close();
  }

  // RFC 9114 §5.2: closed with an HTTP/3 code in the application space.
  // H3_NO_ERROR. The UDP socket closes when the connection does — its
  // closing period over (quic_socket, on 'close') — not here: closed at once,
  // the CONNECTION_CLOSE just queued on it was cancelled with it, and the
  // server never learned the connection was over. A request with agent:
  // false left the server's connection (and a response it was still
  // writing) up until its idle timeout.
  function closeConnection() {
    if (quic) quic.close(0x0100, 'done', true);
    else if (udpSocket) { try { udpSocket.close(); } catch (e) {} }
  }


  // The stream exists. options.onReady (the unified client) may still turn
  // the request down — another protocol was ready first and carries it:
  // nothing goes out, and 'superseded' says so (the connection stays, for
  // the pool). Otherwise: sent whole if the body is complete, streamed if
  // some of it was written, or on the first write or end().
  function ready(conn) {
    if (typeof options.onReady === 'function' && !options.onReady()) {
      finished = true;
      failed = true;
      if (conn && conn._streamHandlers && streamId !== null) delete conn._streamHandlers[streamId];
      // Its stream ID, taken and never used: cancelled, as by destroy()
      // (an unused ID below a later request's is opened by that request).
      if (!autoClose && conn && conn.h3 && streamId !== null) { try { conn.h3.abortStream(streamId, 0x10c); } catch (e) {} }
      // Next tick: on a pooled connection this runs inside request(), before
      // the caller has its listeners on.
      process.nextTick(function () { emit(reqListeners, 'superseded'); });
      if (autoClose && quic) closeConnection();
      return;
    }
    readyDone = true;
    if (reqFinished) sendRequest();
    else if (reqBody.length) startStreaming();
  }

  // contentLength: the body's size when it is known whole (ended before it
  // went) — sent as h2_client and node:https send it, and as browsers do. A
  // server that decides whether there is a body from the headers (Express's
  // body-parser: content-length or transfer-encoding) saw none over HTTP/3,
  // and req.body came out empty.
  function requestHeaders(contentLength) {
    var h3Headers = {
      ':method': method,
      ':scheme': 'https',
      ':authority': formatAuthority(hostname, port, 443),
      ':path': path
    };
    // A repeated field (an array) stays one line per value: String(list)
    // made two cookies "a=1,b=2", which the server reads as one cookie.
    for (var name in headers) {
      var v = headers[name];
      h3Headers[name.toLowerCase()] = Array.isArray(v) ? v.map(String) : String(v);
    }
    if (!h3Headers['user-agent']) h3Headers['user-agent'] = 'quico/1.0';
    if (!h3Headers['accept']) h3Headers['accept'] = '*/*';
    if (!h3Headers['accept-encoding']) h3Headers['accept-encoding'] = 'identity';
    if (contentLength != null && h3Headers['content-length'] === undefined) h3Headers['content-length'] = String(contentLength);
    return h3Headers;
  }

  // The request whole: ended before it could go — headers, the body, the
  // trailers; FIN on the last of them.
  function sendRequest() {
    if (!h3 || !connected || cancelled || failed || requestSent) return;
    requestSent = true;
    if (DEBUG) console.log('[client] sendRequest method=' + method + ' path=' + path + ' stream=' + streamId);
    h3.sendControlStreams();   // SETTINGS before any request
    var body = reqBody; reqBody = []; reqBodyBytes = 0;
    // Early: kept, to go again if the server refuses it.
    if (earlyTried && !handshaken) earlyBody = { body: body.slice(), trailers: reqTrailers };
    if (body.length === 0 && !reqTrailers) { h3.sendHeaders(streamId, requestHeaders(), true); return; }
    var bodyLength = 0;
    for (var bi = 0; bi < body.length; bi++) bodyLength += body[bi].byteLength;
    h3.sendHeaders(streamId, requestHeaders(body.length ? bodyLength : null), false);
    for (var i = 0; i < body.length; i++) h3.sendBody(streamId, body[i], i === body.length - 1 && !reqTrailers);
    if (reqTrailers) h3.sendHeaders(streamId, reqTrailers, true);
  }

  // The body streamed: HEADERS now, without FIN, then what was held.
  function startStreaming() {
    if (!h3 || cancelled || failed || requestSent) return;
    requestSent = true;
    streaming = true;
    if (DEBUG) console.log('[client] streaming request method=' + method + ' path=' + path + ' stream=' + streamId);
    h3.sendControlStreams();
    h3.sendHeaders(streamId, requestHeaders(), false);
    var held = reqBody; reqBody = []; reqBodyBytes = 0;
    var more = true;
    for (var i = 0; i < held.length; i++) more = streamOut(held[i]);
    if (more && needDrain) { needDrain = false; emit(reqListeners, 'drain'); }
  }

  // One piece of a streamed body. Returns whether more may be written now:
  // false while more than BODY_HIGH_WATER of the stream is not yet sent,
  // and 'drain' when it is (the stream's send side, whenStreamSent).
  function streamOut(chunk) {
    h3.sendBody(streamId, chunk, false);
    if (drainWaiting) { needDrain = true; return false; }
    var later = false, over = true;
    quic.whenStreamSent(streamId, BODY_HIGH_WATER, function () {
      over = false;
      if (!later) return;
      drainWaiting = false;
      if (needDrain) { needDrain = false; emit(reqListeners, 'drain'); }
    });
    later = true;
    if (!over) return true;
    drainWaiting = true;
    needDrain = true;
    return false;
  }


  return clientReq;
}


// ============================================================
//  quico.get(url, callback)
//  Shortcut — like https.get()
// ============================================================

function get(url, callback) {
  var opts;
  if (typeof url === 'string') {
    var parsed = new URL(url);
    opts = {
      hostname: urlHostname(parsed.hostname),
      port: parseInt(parsed.port) || 443,
      path: parsed.pathname + parsed.search,
      method: 'GET'
    };
  } else {
    opts = url;
    opts.method = 'GET';
  }

  var req = request(opts, callback);
  req.end();
  return req;
}


// ============================================================
//  connect(authority, { http3: true }) — node:http2's ClientHttp2Session
//  and ClientHttp2Stream over HTTP/3
//
//  The same core API as h2_client's connect() — one session, many request
//  streams, the same events, checks and error codes — over a QUIC
//  connection. Where HTTP/3 differs, it shows: a stream's rstCode is the
//  HTTP/3 code on the wire (H3_NO_ERROR 0x100, H3_REQUEST_CANCELLED 0x10c,
//  ...), and close(code) takes an HTTP/2 code (as h3.js's h2CodeToH3 maps
//  it) or an HTTP/3 one; GOAWAY carries no error code (H3_NO_ERROR) and its
//  id is the first stream not processed (lastStreamId is the one before it);
//  the session operations are h3.js's addH3SessionOps (ping over QUIC's
//  PING, settings() refused: HTTP/3 sends its SETTINGS once).
// ============================================================

var H3_NO_ERROR = H3_ERR.H3_NO_ERROR;
var H3_REQUEST_CANCELLED = H3_ERR.H3_REQUEST_CANCELLED;
var H3_REQUEST_REJECTED = H3_ERR.H3_REQUEST_REJECTED;
var H3_INTERNAL_ERROR = H3_ERR.H3_INTERNAL_ERROR;

// node:http2: a request with one of these methods has no body, and its
// HEADERS ends the stream unless options.endStream says otherwise.
var NO_PAYLOAD = { GET: 1, HEAD: 1, DELETE: 1 };
// node:http2's flags on 'response' / 'headers' / 'trailers'.
var FLAG_END_STREAM = 0x1;
var FLAG_END_HEADERS = 0x4;

// [name, value] pairs as h3.js's sendHeaders takes them: an object, a
// repeated name a list (one field line each), in the order given.
function fieldsObject(list) {
  var o = {};
  for (var i = 0; i < list.length; i++) {
    var n = list[i][0], v = list[i][1];
    if (o[n] === undefined) o[n] = v;
    else if (Array.isArray(o[n])) o[n].push(v);
    else o[n] = [o[n], v];
  }
  return o;
}

// A decoded field section (h3.js's, with its field lines in _rawHeaders) as
// node:http2 hands one to the application.
function headersOf(section) {
  if (section && section._rawHeaders) return http2HeaderObject(section._rawHeaders);
  var raw = [];
  for (var n in section) {
    var v = section[n];
    if (Array.isArray(v)) for (var i = 0; i < v.length; i++) raw.push(n, String(v[i]));
    else raw.push(n, String(v));
  }
  return http2HeaderObject(raw);
}


// ---- The stream: node:http2's ClientHttp2Stream ----

class H3ClientStream extends StreamBase {
  constructor(session, list, method, endStream, waitForTrailers) {
    super(session, H3_STREAM_CODES);
    this.id = undefined;
    var raw = [];
    for (var i = 0; i < list.length; i++) raw.push(list[i][0], list[i][1]);
    this.sentHeaders = http2HeaderObject(raw);
    this._fields = fieldsObject(list);
    this._method = method;
    // FIN on the HEADERS — not when the end is the trailers'.
    this._headersEnd = endStream && !waitForTrailers;
    this._waitTrailers = !!waitForTrailers;
    this._h3 = null;
    this._quic = null;
    this._whenStarted = [];       // writes waiting for the stream to exist
    this._finSent = false;        // our side ended on the wire (FIN)
    this._recvEnded = false;      // the response's end came
    this._sendStopped = false;    // STOP_SENDING H3_NO_ERROR: the server reads no more
    this._responded = false;
    this._received = null;        // creditAsRead's counter, once the body may come
    this._sessCode = 0;
  }

  get pending() { return this.id === undefined; }
  get headersSent() { return true; }

  // The connection is up: the stream is opened (the next free request
  // stream: quic's nextLocalStreamId, taken by its first bytes) and its
  // HEADERS go.
  _start(session) {
    if (this.destroyed || this.closed) return;
    var quic = session._quic, h3 = session._h3;
    var id = quic.nextLocalStreamId(true);
    this._quic = quic;
    this._h3 = h3;
    this.id = id;
    session._byId.set(id, this);
    try { h3.sendHeaders(id, this._fields, this._headersEnd); }
    catch (err) { this.destroy(err); return; }
    if (this._headersEnd) this._finSent = true;
    this.emit('ready');
    // What was written while connecting goes a turn later, as node:http2's:
    // the HEADERS of every request made meanwhile go first.
    var self = this;
    process.nextTick(function () {
      var waiting = self._whenStarted;
      self._whenStarted = [];
      for (var i = 0; i < waiting.length; i++) waiting[i]();
    });
  }

  // ---- What the server sends (the session dispatches by stream id) ----

  _onHeaders(section, endAfterHeaders) {
    if (this.destroyed) return;
    this._touch();
    var headers = headersOf(section);
    var status = headers[':status'];
    // 1xx (103 Early Hints): informational, the response follows.
    if (status >= 100 && status < 200) { this.emit('headers', headers, FLAG_END_HEADERS); return; }
    this._responded = true;
    // Credit for what the application reads, not for what arrives (utils'
    // creditAsRead): the server sends no faster than the body is consumed.
    var h3 = this._h3, id = this.id;
    if (h3 && !endAfterHeaders) {
      h3.holdBody(id);
      this._received = creditAsRead(this, function (n) { if (h3) h3.creditBody(id, n); });
    }
    this.emit('response', headers, FLAG_END_HEADERS | (endAfterHeaders ? FLAG_END_STREAM : 0));
  }

  _onBody(data) {
    if (this.destroyed || this._readableState.ended) return;
    if (!data.byteLength) return;
    this._touch();
    var buf = Buffer.isBuffer(data) ? data : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    if (this._received) this._received(buf.length);
    this.push(buf);
  }

  _onTrailers(section) {
    if (this.destroyed) return;
    this._touch();
    this.emit('trailers', headersOf(section), FLAG_END_HEADERS | FLAG_END_STREAM);
  }

  _onEnd() {
    if (this.destroyed) return;
    this._recvEnded = true;
    if (!this._readableState.ended) this.push(null);
    this._maybeClosed();
  }

  // RESET_STREAM from the server, or the stream ended over what it sent (a
  // malformed response, h3.js's stream_error): closed with that code.
  // H3_REQUEST_CANCELLED is no error ('aborted' covers it), as CANCEL.
  _onReset(code) {
    if (this.destroyed) return;
    this._gone(code);
  }

  // STOP_SENDING: the server reads no more of the request (QUIC has reset
  // our sending part). H3_NO_ERROR: it answers without the rest of the body
  // (RFC 9114 §4.1.2) — the response stands, and what is written now goes
  // nowhere. Any other code before the response: the request is refused or
  // cancelled, as by a reset.
  _onStopSending(code) {
    if (this.destroyed) return;
    if (code === H3_NO_ERROR || this._responded) {
      this._sendStopped = true;
      this._maybeClosed();
      return;
    }
    this._gone(code);
  }

  // Both ways over — our FIN went (or the server stopped reading) and the
  // response ended: the stream is closed, as HTTP/2's on its second
  // END_STREAM.
  _maybeClosed() {
    if (!this._recvEnded || !(this._finSent || this._sendStopped)) return;
    var self = this;
    // After what is being read: 'end' first.
    process.nextTick(function () { self._gone(H3_NO_ERROR); });
  }

  // ---- What this side sends ----

  _read() {}

  _write(chunk, encoding, cb) {
    var self = this;
    if (this.id === undefined) { this._whenStarted.push(function () { self._write(chunk, encoding, cb); }); return; }
    if (this.closed || this._sendStopped) { cb(); return; }
    if (!this._h3) { cb(nodeError(Error, 'ERR_STREAM_WRITE_AFTER_END', 'write after end')); return; }
    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    this._touch();
    try { this._h3.sendBody(this.id, chunk, false); }
    catch (err) { cb(err); return; }
    // The stream's backpressure: on once no more than BODY_HIGH_WATER of it
    // is waiting to be sent.
    this._quic.whenStreamSent(this.id, BODY_HIGH_WATER, function () { cb(); });
  }

  _final(cb) {
    var self = this;
    if (this.id === undefined && !this.closed) { this._whenStarted.push(function () { self._final(cb); }); return; }
    if (this._headersEnd || !this._h3 || this.closed || this._sendStopped) { cb(); return; }
    if (this._waitTrailers) { this._wantTrailers(); cb(); return; }
    try { this._h3.sendBody(this.id, null, true); }
    catch (err) { cb(err); return; }
    this._finSent = true;
    cb();
    this._maybeClosed();
  }

  _sendTrailers(list) {
    if (!this._h3 || this._sendStopped) return;
    if (list.length) this._h3.sendHeaders(this.id, fieldsObject(list), true);
    else this._h3.sendBody(this.id, null, true);
    this._finSent = true;
    this._maybeClosed();
  }

  // Both ways, as HTTP/2's RST_STREAM: RESET_STREAM and STOP_SENDING.
  _sendRst(code) {
    if (this._h3 && this.id !== undefined) { try { this._h3.abortStream(this.id, code); } catch (e) {} }
    this._h3 = null;
  }

  _streamState() {
    if (this.id === undefined || this.closed) return null;
    return streamStateOf(this._finSent, this._recvEnded);
  }

  _sessionCode() { return this._sessCode; }

  _release() {
    // Not over both ways on the wire (the session ended under it, a GOAWAY
    // refused it): what is left of it is cancelled, or QUIC keeps it open.
    if (this._h3 && this.id !== undefined && !(this._recvEnded && (this._finSent || this._sendStopped))) {
      try { this._h3.abortStream(this.id, this.rstCode != null ? this.rstCode : H3_REQUEST_CANCELLED); } catch (e) {}
    } else if (this._h3 && this.id !== undefined) {
      try { this._h3.releaseBody(this.id); } catch (e) {}
    }
    this._h3 = null;
    var session = this.session;
    if (session) session._streamGone(this);
  }

  // Its session ended: with `err`, and `code` the stream's.
  _closeWith(err, code) {
    if (this.destroyed) return;
    this._sessCode = code;
    this.destroy(err || undefined);
  }
}


// ---- The session: node:http2's ClientHttp2Session ----

class H3ClientSession extends EventEmitter {
  constructor(url, options) {
    super();
    this._url = url;
    this._options = options;
    this._quic = null;
    this._h3 = null;
    this._udp = null;
    this._socketInfo = null;
    this._streams = new Set();
    this._byId = new Map();      // stream id → stream, for what the server sends
    this._pending = [];          // requests made while connecting
    this._goawayId = Infinity;   // the server's GOAWAY: the first stream it will not process
    this._origins = null;        // the origin set (RFC 8336 / 9412)
    this._h3Error = null;        // an HTTP/3 connection error of ours (h3.js's 'error')
    this.connecting = true;
    this.closed = false;
    this.destroyed = false;
    this.type = 1;               // NGHTTP2_SESSION_CLIENT
    var self = this;
    this._ops = addH3SessionOps(this, {
      quic: function () { return self._quic; },
      h3: function () { return self._h3; },
      destroyed: function () { return self.destroyed; },
      closed: function () { return self.closed; },
      isServer: false,
      options: options
    });
    this._connect();
  }

  get encrypted() { return true; }
  get alpnProtocol() { return 'h3'; }
  get socket() { return this._socketInfo; }
  // node:http2's: the connection's own origin, then those the server's
  // ORIGIN frames added.
  get originSet() { return this._originSet() ? Array.from(this._originSet()) : undefined; }

  _originSet() {
    if (!this._origins) this._origins = new Set([this._url.origin]);
    return this._origins;
  }

  _connect() {
    var self = this;
    var o = this._options;
    var host = urlHostname(this._url.hostname);
    var port = parseInt(this._url.port, 10) || 443;
    resolveHost(host, function (err, address) {
      if (self.destroyed) return;
      if (err) { self._fail(err); return; }
      try {
        self._udp = createQuicClientSocket(Object.assign(quicClientOptions(o, host, o.rejectUnauthorized !== false, o.ca || null), {
          remoteIp: address,
          remotePort: port,
          // SNI is a host name; an address has none (RFC 6066 §3).
          hostname: o.servername !== undefined ? o.servername : host,
          session: o.session || null,
          requestOCSP: o.requestOCSP === true,
          token: o.token || null,
          onSocket: function (q) {
            self._quic = q;
            // tls.connect's 'session' (a ticket to resume with), on the session as node:http2's.
            q.on('session', function (buf) { if (!self.destroyed) self.emit('session', buf); });
            if (self.destroyed) { try { q.close(0, 'cancelled', false); } catch (e) {} }
          },
          onError: function (e) { if (self.connecting) self._fail(e); },
          onConnect: function (q) { self._up(q); }
        }));
      } catch (e2) {
        self._fail(e2);
      }
    });
  }

  _up(quic) {
    var self = this;
    if (this.destroyed) { try { quic.close(H3_NO_ERROR, '', true); } catch (e) {} return; }
    this._quic = quic;
    var h3 = new H3Connection({ quicConnection: quic, isServer: false });
    this._h3 = h3;
    this.connecting = false;
    this._socketInfo = h3SocketInfo({ quic: quic });
    h3.sendControlStreams();   // SETTINGS before any request

    var each = function (fn) { return function (sid) { var st = self._byId.get(Number(sid)); if (st) fn.apply(st, Array.prototype.slice.call(arguments, 1)); }; };
    h3.on('http_headers', each(H3ClientStream.prototype._onHeaders));
    h3.on('http_body', each(H3ClientStream.prototype._onBody));
    h3.on('http_trailers', each(H3ClientStream.prototype._onTrailers));
    h3.on('http_end', each(H3ClientStream.prototype._onEnd));
    h3.on('stream_error', each(H3ClientStream.prototype._onReset));
    h3.on('stream_reset', each(H3ClientStream.prototype._onReset));
    h3.on('stop_sending', each(H3ClientStream.prototype._onStopSending));
    h3.on('error', function (err) { self._h3Error = err; });
    h3.on('peer_settings', this._ops.remote);
    h3.on('origin', function (origins) {
      if (self.destroyed) return;
      var set = self._originSet();
      var max = self._options.maxOriginSetSize != null ? self._options.maxOriginSetSize : 128;
      for (var i = 0; i < origins.length; i++) {
        if (set.size >= max) {
          self.destroy(nodeError(Error, 'ERR_HTTP2_TOO_MANY_ORIGINS', 'Remote peer has sent more than ' + max + ' origins'));
          return;
        }
        set.add(origins[i]);
      }
      self.emit('origin', origins);
    });
    // GOAWAY (RFC 9114 §5.2): its id the first request stream not processed.
    // Those from it on are refused (H3_REQUEST_REJECTED, safe to send again,
    // as HTTP/2's REFUSED_STREAM), and the session winds down (node:http2's
    // close() on GOAWAY NO_ERROR — HTTP/3's has no other code).
    h3.on('goaway', function (id) {
      if (self.destroyed) return;
      id = Number(id);
      if (id >= self._goawayId) return;   // the same GOAWAY again is no news
      self._goawayId = id;
      self.emit('goaway', H3_NO_ERROR, id - 4, Buffer.alloc(0));
      var refused = [];
      self._streams.forEach(function (st) { if (st.id !== undefined && st.id >= id) refused.push(st); });
      for (var i = 0; i < refused.length; i++) refused[i]._gone(H3_REQUEST_REJECTED, true);
      self.close();
    });
    // The connection over: the server's CONNECTION_CLOSE, ours, the idle
    // timeout ('closing'; 'close' after the draining period, if not before).
    var over = function (peer) {
      if (self.destroyed) return;
      var err = self._h3Error, code = H3_NO_ERROR;
      if (peer && peer.application && peer.error !== H3_NO_ERROR) { code = peer.error; err = err || sessionCodeError(code); }
      else if (peer && !peer.application && peer.error !== 0) {
        code = H3_INTERNAL_ERROR;
        err = err || nodeError(Error, 'ERR_HTTP3_CONNECTION_CLOSED', 'QUIC connection closed with transport error 0x' + peer.error.toString(16) + (peer.reason ? ': ' + peer.reason : ''));
      } else if (err) code = H3_INTERNAL_ERROR;
      self._end(err || null, code, false);
    };
    quic.on('closing', over);
    quic.on('close', function () { over(null); });

    this._ops.local();
    this.emit('connect', this, this._socketInfo);
    var pending = this._pending;
    this._pending = [];
    for (var i = 0; i < pending.length; i++) pending[i]._start(this);
    if (this.closed) this._goawayAndMaybeEnd();
  }

  // Not connected, and never will be.
  _fail(err) {
    if (this.destroyed) return;
    var pending = this._pending;
    this._pending = [];
    for (var i = 0; i < pending.length; i++) {
      pending[i]._closeWith(pendingCancel(err), H3_REQUEST_CANCELLED);
    }
    this._end(err, H3_REQUEST_CANCELLED, false);
  }

  // The end of the session, once: its streams with it (with `err` and
  // `code`), the connection closed with `closeCode` (when it is still up),
  // then 'error' (with an error) and 'close'.
  _end(err, code, closeCode) {
    if (this.destroyed) return;
    this.destroyed = true;
    this.connecting = false;
    this._ops.end();
    var streams = Array.from(this._streams).concat(this._pending);
    this._pending = [];
    // A stream still waiting for the connection is cancelled, as node:http2's
    // pending streams are (ERR_HTTP2_STREAM_CANCEL, with the cause).
    for (var i = 0; i < streams.length; i++) {
      if (streams[i].id === undefined && !streams[i].destroyed) streams[i]._closeWith(pendingCancel(err), code);
      else streams[i]._closeWith(err, code);
    }
    this._streams.clear();
    this._byId.clear();
    var quic = this._quic, self = this;
    if (quic && closeCode !== false) {
      // An application close needs the handshake done: before it, QUIC's
      // own (RFC 9000 §10.2.3).
      try {
        if (this._h3) quic.close(closeCode, '', true);
        else quic.close(0, 'cancelled', false);
      } catch (e) {}
    } else if (!quic && this._udp) {
      try { this._udp.close(); } catch (e) {}
    }
    // A turn of the event loop, as node:http2's after its socket's events.
    setImmediate(function () {
      if (err) self.emit('error', err);
      self.emit('close');
    });
  }

  _streamGone(stream) {
    this._streams.delete(stream);
    if (stream.id !== undefined && this._byId.get(stream.id) === stream) this._byId.delete(stream.id);
    var i = this._pending.indexOf(stream);
    if (i >= 0) this._pending.splice(i, 1);
    if (this.closed && !this.destroyed && this._streams.size === 0 && this._pending.length === 0) {
      var self = this;
      process.nextTick(function () { if (self._streams.size === 0) self._closeGracefully(); });
    }
  }

  // The last stream gone, the session closing: once what was written has
  // been delivered, CONNECTION_CLOSE with H3_NO_ERROR.
  _closeGracefully() {
    if (this.destroyed) return;
    var self = this, quic = this._quic;
    if (quic && quic.whenAllSent) quic.whenAllSent(function () { self._end(null, H3_NO_ERROR, H3_NO_ERROR); });
    else this._end(null, H3_NO_ERROR, H3_NO_ERROR);
  }

  // A client's GOAWAY (RFC 9114 §5.2) names a push ID; none is allowed (no
  // MAX_PUSH_ID is sent), so 0.
  _goawayAndMaybeEnd() {
    if (this._h3) { try { this._h3.sendGoaway(0); } catch (e) {} }
    if (this._streams.size === 0 && this._pending.length === 0) this._closeGracefully();
  }

  request(headers, options) {
    if (headers === undefined || headers === null) headers = {};
    else if (typeof headers !== 'object' || Array.isArray(headers)) throw argType('headers', 'object', headers);
    if (options !== undefined && (options === null || typeof options !== 'object')) throw argType('options', 'object', options);
    options = options || {};
    var authority = formatAuthority(urlHostname(this._url.hostname), this._url.port, 443);
    var fields = http2RequestFields(headers, 'https', authority);
    var method = fields.method;
    var endStream = options.endStream !== undefined ? !!options.endStream : NO_PAYLOAD[method] === 1;
    var stream = new H3ClientStream(this, fields.list, method, endStream, !!options.waitForTrailers);

    // node:http2: a request on a session that has ended, or is ending, is a
    // stream that fails — not a throw.
    if (this.destroyed || this.closed) {
      var e = this.destroyed ? sessionGone() : nodeError(Error, 'ERR_HTTP2_GOAWAY_SESSION', 'New streams cannot be created after receiving a GOAWAY');
      process.nextTick(function () { stream.destroy(e); });
      return stream;
    }
    this._streams.add(stream);
    if (endStream) stream.end();
    if (this._h3) stream._start(this);
    else this._pending.push(stream);
    return stream;
  }

  // node:http2's close(callback): GOAWAY, no new streams, and the session
  // ends with its last stream — then 'close', and the callback.
  close(callback) {
    if (this.closed || this.destroyed) return;
    this.closed = true;
    if (typeof callback === 'function') this.once('close', callback);
    if (!this.connecting) this._goawayAndMaybeEnd();
  }

  // node:http2's destroy(error, code): at once, CONNECTION_CLOSE with `code`
  // — H3_INTERNAL_ERROR with an error, H3_NO_ERROR without; a number in
  // place of the error is the code (an error of its own unless NO_ERROR).
  // An HTTP/2 code is mapped (h2CodeToH3), an HTTP/3 one taken as it is.
  destroy(error, code) {
    if (this.destroyed) return;
    if (typeof error === 'number') {
      code = h2CodeToH3(error);
      error = code !== H3_NO_ERROR ? sessionCodeError(code) : undefined;
    } else if (code !== undefined) code = h2CodeToH3(code);
    if (code === undefined) code = error ? H3_INTERNAL_ERROR : H3_NO_ERROR;
    this._end(error || null, code, code);
  }

  // node:http2's goaway(code, lastStreamId, opaqueData), with its checks.
  // A client's GOAWAY carries a push ID only (0): the arguments are checked
  // and not sent.
  goaway(code, lastStreamId, opaqueData) {
    if (this.destroyed) throw sessionGone();
    if (code !== undefined && typeof code !== 'number') throw argType('code', 'number', code);
    if (lastStreamId !== undefined && typeof lastStreamId !== 'number') throw argType('lastStreamId', 'number', lastStreamId);
    if (opaqueData !== undefined && !ArrayBuffer.isView(opaqueData)) throw argType('opaqueData', 'Buffer, TypedArray, or DataView', opaqueData);
    if (this._h3) this._h3.sendGoaway(0);
  }

  // The UDP socket keeps the process alive, as node:http2's socket does.
  ref() { if (this._udp && this._udp.ref) this._udp.ref(); }
  unref() { if (this._udp && this._udp.unref) this._udp.unref(); }
}

// connect() with { http3: true } (h2_client's connect() checks the
// authority and hands it here): an HTTP/3 session to `url`, an https: one.
function connectH3(url, options, listener) {
  var session = new H3ClientSession(url, options);
  if (typeof listener === 'function') session.once('connect', listener);
  return session;
}


export { request, get, h3SocketInfo, connectH3, H3ClientSession, H3ClientStream };
