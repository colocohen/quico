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
import { DEBUG } from './utils.js';
import { H3Connection, H3_ERR_NAME } from './h3.js';
import { createQuicClientSocket } from './quic_socket.js';
import { parseVersionList } from './quic_version.js';
import { checkConnectionOptions, CONNECTION_OPTIONS } from './quic_connection.js';
import { trailerFields, formatPriority } from './http_common.js';

// What the body takes before write() says wait — written while connecting,
// or not yet sent on the stream.
var BODY_HIGH_WATER = 64 * 1024;


// ============================================================
//  quico.request(options, callback)
//  API mirrors Node.js https.request()
// ============================================================

function request(options, callback) {
  if (typeof options === 'string') {
    var url = new URL(options);
    options = {
      hostname: url.hostname,
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
  var cancelled = false;     // destroy() was called

  var clientReq = {
    on: function (event, fn) {
      (reqListeners[event] = reqListeners[event] || []).push(fn);
      return clientReq;
    },

    // The body, as node:http's: held while connecting (write() false past
    // BODY_HIGH_WATER, then 'drain'), then streamed — HEADERS on the first
    // write once the stream exists, DATA as written, with the stream's
    // backpressure.
    write: function (chunk) {
      if (finished || cancelled || reqFinished) return false;
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
        if (chunk && chunk.byteLength) h3.sendBody(streamId, chunk, !reqTrailers);
        else if (!reqTrailers) h3.sendBody(streamId, null, true);
        if (reqTrailers) h3.sendHeaders(streamId, reqTrailers, true);
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
    // If already IP, skip DNS
    if (/^[\d.]+$/.test(host) || host.indexOf(':') >= 0 || host === 'localhost') {
      var ip = (host === 'localhost') ? '127.0.0.1' : host;
      startConnection(ip, port);
      return;
    }

    dns.lookup(host, function (err, address) {
      if (err) {
        emit(reqListeners, 'error', err);
        return;
      }
      startConnection(address, port);
    });
  }


  function startConnection(remoteIp, remotePort) {
    if (cancelled) return;
    var sessionNow = options.session || null;
    earlyWanted = options.earlyData === true && !!sessionNow &&
                  (method === 'GET' || method === 'HEAD' || method === 'OPTIONS');
    udpSocket = createQuicClientSocket({
      remoteIp: remoteIp,
      remotePort: remotePort,
      // SNI and the name the certificate is checked for: tls.connect's
      // servername where given.
      hostname: options.servername || hostname,
      rejectUnauthorized: rejectUnauthorized,
      ca: ca,
      // A client certificate, for a server that asks (https.request's names).
      key: options.key || null, cert: options.cert || null, passphrase: options.passphrase,
      // A saved session to resume with, and the request's 'session' event for
      // each the server sends — as https.request does (its socket's
      // 'session'). Only the request that opened the connection has one: a
      // request on a connection already open sees no handshake.
      session: sessionNow,
      // The server's stapled OCSP response, as the request's 'OCSPResponse'
      // (tls.connect's requestOCSP) — on the request that opened the connection.
      requestOCSP: options.requestOCSP === true,
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
      initialCongestionWindow: options.initialCongestionWindow,
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
    });
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

      onBody: function (data) {
        if (retry425) return;
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
  function closeIfOwned() {
    if (!autoClose) return;
    if (earlyTried && quic && quic.whenConfirmed) quic.whenConfirmed(function () { setTimeout(closeConnection, 100); });
    else setTimeout(closeConnection, 100);
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
      ':authority': hostname + (port !== 443 ? ':' + port : ''),
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
    if (!h3 || !connected || cancelled || finished || requestSent) return;
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
    if (!h3 || cancelled || finished || requestSent) return;
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
      hostname: parsed.hostname,
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


export { request, get };
