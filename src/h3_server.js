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

import { Duplex } from 'node:stream';
import { X509Certificate } from 'node:crypto';
import { readVarInt, writeVarInt, wt_datagram_payload } from './utils.js';
import { observeH3 } from './h2_fingerprint.js';
// The Emitter from http_common, not the one in utils.js. Two differences that
// matter here: it has listenerCount (needed to tell whether anyone wants an
// 'upgrade'), and it does NOT swallow exceptions thrown by listeners — the
// utils.js one wraps every call in a try/catch and discards what it catches,
// which is how a handler that throws becomes silence.
import { Emitter, isConnectionSpecific, runRequestHandler, validateHeaderName, validateHeaderValue, validateStatus,
         DEFAULT_HEADERS_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, startDeadline, responsePriority,
         sfString, parseSfStringList, maxRequestsPerSocket, trailerFields, statusHasNoBody, runEarlyDataFilter, httpDate, streamResetLimiter } from './http_common.js';
import { createQuicServer } from './quic_server.js';
import { pickTlsOptions } from './tls_options.js';
import { _makeSocketStub } from './streams.js';
import { H3Connection, H3_ERR, wtCloseCapsule, wtDrainCapsule, createCapsuleReader, h3SettingsContext } from './h3.js';
import { createWtStream, openWtStream, createSendGroup, wtScheduling, createDatagrams, sessionStats,
         exporterArgs, exportSessionKeyingMaterial } from './wt_stream.js';
import { contextZero, datagramCapsule, STREAM_QUEUE_MAX } from './connect_udp.js';


// ============================================================
//  createServer(options, handler)
// ============================================================

function createServer(options, handler) {
  options = options || {};

  var ev = Emitter();

  // node:http's shouldUpgradeCallback, for extended CONNECT (RFC 9220): taken
  // up as an 'upgrade' (true) or handled as an ordinary request (false).
  // Default: true when something listens for 'upgrade' — counted here, since
  // this Emitter has no listenerCount (so the old "nobody listens" check
  // could never fire).
  var upgradeListeners = 0;
  var shouldUpgradeCallback = typeof options.shouldUpgradeCallback === 'function'
    ? options.shouldUpgradeCallback
    : function () { return upgradeListeners > 0; };

  // CONNECT-UDP (RFC 9298), from server.js: { wants(req), handle(req,
  // carrier) } — whether a request is to be proxied, and the proxy
  // (connect_udp.js) that takes it with the carrier built here.
  var connectUdp = options.connectUdpHandler || null;

  // Transport-only QUIC server owns the UDP socket(s), demux, connection
  // map and lifecycle. h3_server layers HTTP/3 on top by listening for its
  // 'connection' event (see below) and wrapping each raw QUICConnection in
  // an H3Connection. ALPN is 'h3'. External-socket (shared-port) mode and
  // the handlePacket/hasConnection demux hooks are provided by the
  // transport server and re-exported on this server's API.
  // 'h3' plus whatever else the application asked the handshake to accept.
  // Anything but 'h3' is closed once the handshake settles on it — see the
  // 'connect' handler below.
  var alpn = options.alpn || ['h3'];

  // Datagrams an application sends between accepting a WebTransport session
  // and its 200 leaving, kept — the oldest dropped past this many.
  var WT_DATAGRAMS_HELD = 256;

  // ---- How long a request may take to arrive (see http_common) ----
  //
  // headersTimeout: from a request stream's first byte to its whole HEADERS
  // frame. Its streams are independent, so a slow head costs only itself:
  // reset, H3_REQUEST_INCOMPLETE, before any request exists. It was not
  // timed at all — a HEADERS frame sent a byte at a time held its stream, and
  // its share of the connection's stream limit, for as long as it went on.
  // requestTimeout: from the head to the request's last byte; past it the
  // stream is reset both ways and the request ends as a cancelled one does.
  // Not for CONNECT (a WebSocket or a WebTransport session): its stream is
  // meant to stay open.
  var headersTimeout = options.headersTimeout != null ? options.headersTimeout : DEFAULT_HEADERS_TIMEOUT;
  // Rapid Reset (http_common streamResetLimiter): the options checked now.
  streamResetLimiter(options);
  // 0-RTT requests: the application's judge (earlyGate), or the default.
  if (options.earlyDataFilter != null && typeof options.earlyDataFilter !== 'function') {
    var efe = new TypeError('earlyDataFilter must be a function (req, callback)'); efe.code = 'ERR_INVALID_ARG_TYPE'; throw efe;
  }
  var earlyDataFilter = options.earlyDataFilter || null;
  // node:http's maxRequestsPerSocket: GOAWAY after the Nth request (0: none).
  var maxRequests = maxRequestsPerSocket(options.maxRequestsPerSocket);
  var requestTimeout = options.requestTimeout != null ? options.requestTimeout : DEFAULT_REQUEST_TIMEOUT;

  function armHeadersDeadline(conn, streamId) {
    var t = startDeadline(headersTimeout, function () {
      if (conn.headerDeadlines[streamId] !== t) return;
      delete conn.headerDeadlines[streamId];
      // H3_REQUEST_REJECTED: nothing of the request was processed — no
      // headers to process — so the client may send it again (RFC 9114
      // §4.1.1), as it may not after H3_REQUEST_INCOMPLETE.
      if (conn.h3) conn.h3.abortStream(streamId, H3_ERR.H3_REQUEST_REJECTED);
    });
    if (t) conn.headerDeadlines[streamId] = t;
  }
  function clearHeadersDeadline(conn, streamId) {
    var t = conn.headerDeadlines[streamId];
    if (t) { clearTimeout(t); delete conn.headerDeadlines[streamId]; }
  }

  function armRequestDeadline(conn, streamId, stream) {
    stream.deadline = startDeadline(requestTimeout, function () {
      stream.deadline = null;
      if (conn.http_streams[streamId] !== stream || stream.req._ended) return;
      if (conn.h3) conn.h3.abortStream(streamId, H3_ERR.H3_REQUEST_INCOMPLETE);
      releaseHttpStream(conn, streamId, true);
    });
  }
  function clearRequestDeadline(stream) {
    if (stream && stream.deadline) { clearTimeout(stream.deadline); stream.deadline = null; }
  }
  if (!Array.isArray(alpn)) alpn = [alpn];
  if (alpn.indexOf('h3') === -1) alpn = ['h3'].concat(alpn);

  var qserver = createQuicServer(Object.assign({
    alpn: alpn,
    SNICallback: options.SNICallback || null,
    ticketKeys: options.ticketKeys || null,
    ticketData: options.ticketData || null,
    ech: options.ech || null,
    ocspRequest: options.ocspRequest || null,
    resetTokenSecret: options.resetTokenSecret || null,
    tokenSecret: options.tokenSecret || null,
    validateAddress: options.validateAddress === true,
    handshakeLoadThreshold: options.handshakeLoadThreshold,
    earlyData: options.earlyData, earlyDataMaxAge: options.earlyDataMaxAge, earlyDataReplay: options.earlyDataReplay,
    // 0-RTT is taken only under the SETTINGS this server sends now: a client
    // may send early data under the ones it remembered (RFC 9114 §7.2.4.2).
    earlyDataAppContext: h3SettingsContext({ enableWebTransport: true, maxWebTransportSessions: options.maxWebTransportSessions }),
    maxHandshakesPerAddress: options.maxHandshakesPerAddress,
    key: options.key,
    cert: options.cert,
    ca: options.ca,
    maxConnections: options.maxConnections || 10000,
    transportParams: options.transportParams || null,
    initialCongestionWindow: options.initialCongestionWindow,
    carefulResume: options.carefulResume,
    startupCap: options.startupCap,
    pmtuDiscovery: options.pmtuDiscovery,
    maxUdpPayloadSize: options.maxUdpPayloadSize,
    initialRtt: options.initialRtt,
    reorderWindow: options.reorderWindow,
    connectionOptions: options.connectionOptions,
    quicVersions: options.quicVersions,
    socket: options.socket || null,
    socket6: options.socket6 || null,
    greaseQuicBit: options.greaseQuicBit,
    // The server's counters (server_stats.js), when it keeps them.
    stats: options.stats || null
  }, pickTlsOptions(options)));   // node:tls's options (tls_options.js)

  // Surface transport-level (UDP socket / send) errors on this server.
  qserver.on('error', function (err) { ev.emit('error', err); });
  qserver.on('handshakeLoad', function (e) { ev.emit('handshakeLoad', e); });


  // ============================================================
  //  WebTransport helpers
  // ============================================================

  function _emitOnReq(req, event, data) {
    // If unified server wrapped the req, emit on the wrapper (IncomingMessage/EventEmitter)
    if (req._wrapper && typeof req._wrapper.emit === 'function') {
      req._wrapper.emit(event, data);
      return;
    }
    // Fallback: emit on raw req's _listeners
    var listeners = req._listeners[event] || [];
    for (var i = 0; i < listeners.length; i++) {
      try { if (data !== undefined) listeners[i](data); else listeners[i](); } catch (e) {}
    }
  }

  // ── Stream lifecycle: one exit ────────────────────────────────────────
  //
  // releaseHttpStream is the ONLY place this server drops what it holds for
  // a stream — an entry in conn.http_streams (a request, a tunnel, a
  // WebTransport session) or in conn._wtStreamObjects (a WebTransport
  // stream) — and every way a stream can end comes through it:
  //
  //   normally (aborted = false)
  //     a request over in both directions        → releaseIfDone
  //     a tunnel's FIN, or a refused tunnel      → tunnel_data / reject / 501
  //     a WebTransport stream's FIN              → wt_stream / wt_data
  //     our own WT stream finished               → its 'close'
  //     a session's FIN (CONNECT stream)         → request_end
  //   cut short (aborted = true)
  //     the peer cancelled (RESET / STOP_SENDING) → reportCancel
  //     we ended it over what the peer sent       → 'stream_error'
  //     its WebTransport session ended            → releaseSessionStreams
  //     the connection closed                     → quic 'close'
  //
  // What each kind hears is decided here, once:
  //   a request cut short   → 'aborted' — the counterpart of h2_server's
  //                            abortStream; the unified server turns it into
  //                            IncomingMessage 'aborted' and ServerResponse
  //                            'close'. Never an Error: a browser cancelling
  //                            a request is ordinary traffic, and an uncaught
  //                            error for it would take the process down.
  //   a tunnel cut short    → its Duplex destroyed
  //   a WT stream cut short → destroyed
  //   a WT session, however → 'close' once (and 'aborted' if cut short), and
  //                            every stream still open in it released too
  // Idempotent: a second end for the same stream finds nothing.
  function releaseHttpStream(conn, streamId, aborted) {
    var wtStream = conn._wtStreamObjects[streamId];
    if (wtStream) {
      delete conn._wtStreamObjects[streamId];
      if (aborted) { try { wtStream.destroy(); } catch (e) {} }
    }

    var stream = conn.http_streams[streamId];
    if (!stream) return;
    delete conn.http_streams[streamId];
    clearRequestDeadline(stream);
    var req = stream.req;
    // Its body's credit, if the layer above was returning it as it read: the
    // request is over, so nothing more is waited for.
    if (conn.h3) conn.h3.releaseBody(streamId);

    if (stream.tunnel) {
      if (aborted) { try { stream.tunnel.destroy(); } catch (e) {} }
      if (conn.goaway) closeAfterGoaway(conn);
      return;
    }
    if (stream.udp) {
      var quarter = Math.floor(Number(streamId) / 4);
      if (conn.udpByQuarter[quarter] === Number(streamId)) delete conn.udpByQuarter[quarter];
      // Cut short under the tunnel (a reset, the connection gone): it closes.
      if (aborted && stream.udp.sink) stream.udp.sink.abort();
      if (conn.goaway) closeAfterGoaway(conn);
      return;
    }
    if (aborted && !req.aborted) {
      req.aborted = true;
      var listeners = req._listeners['aborted'] || [];
      for (var i = 0; i < listeners.length; i++) {
        try { listeners[i](); } catch (e) {}
      }
    }
    if (req._isWebTransport) {
      if (conn.wtByQuarter[Math.floor(Number(streamId) / 4)] === Number(streamId)) delete conn.wtByQuarter[Math.floor(Number(streamId) / 4)];
      // FIN on the CONNECT stream ends the WebTransport session — it is what
      // a browser's wt.close() sends — as does a reset of it, or the
      // connection going. 'close' used to come only with the whole QUIC
      // connection, and a browser that closed the session but kept the
      // connection for its fetches left the session standing here.
      if (!req._wtClosed) {
        req._wtClosed = true;
        if (req._wtDatagrams) req._wtDatagrams._close();
        _emitOnReq(req, 'close');
      }
      releaseSessionStreams(conn, Number(streamId));
    }
    if (conn.goaway) closeAfterGoaway(conn);
  }

  // ---- Graceful shutdown (RFC 9114 §5.2) ----
  //
  // The intents shared with h2_server's handle (CONN_OVERLOADED is
  // 'overloaded'), as HTTP/3 connection error codes: one piece of limiting
  // code drives both versions.
  function h3ConnCode(code) {
    if (typeof code === 'number') return code;
    if (code === 'overloaded') return H3_ERR.H3_EXCESSIVE_LOAD;
    return H3_ERR.H3_NO_ERROR;
  }

  // After GOAWAY, once the last request accepted has finished and everything
  // sent on the connection has been acknowledged, the connection is closed
  // ("MAY initiate an immediate closure", §5.2). Not at the last res.end():
  // CONNECTION_CLOSE stops all sending, and the last responses would be cut
  // off in flight.
  function closeAfterGoaway(conn) {
    if (conn.goaway.closing || Object.keys(conn.http_streams).length > 0) return;
    conn.goaway.closing = true;
    conn.quic.whenAllSent(function () {
      try { conn.quic.close(conn.goaway.code, 'goaway', true); } catch (e) {}
    });
  }

  // Every WebTransport stream still open in a session that has ended.
  // Each goes with WT_SESSION_GONE (draft-ietf-webtrans-http3 §4.6) — not
  // with application code 0, which it got when its session's end reached it
  // here before h3's endWtSession did (the peer's STOP_SENDING on the CONNECT
  // stream: released first, then stopped).
  function releaseSessionStreams(conn, sessionId) {
    for (var k in conn._wtStreamObjects) {
      var child = conn._wtStreamObjects[k];
      if (child && child._sessionId === sessionId) {
        if (child._sessionGone) child._sessionGone();
        releaseHttpStream(conn, k, true);
      }
    }
  }

  /**
   * Release a request's entry once it is over in both directions: the
   * request fully received (FIN, 'request_end') and the response ended
   * (res.end).
   *
   * Nothing removed it before, except a cancel, a tunnel's end, or a 501 —
   * so every request served stayed here, with the IncomingMessage and
   * ServerResponse wrapped around it, for as long as the QUIC connection
   * lived. A browser keeps that connection open while a WebTransport session
   * runs on it, and sends every fetch for the origin over it too: the map grew
   * without bound, and the datagram handler below walks it for every datagram.
   *
   * A tunnel and a WebTransport session have their own ends (tunnel_data FIN,
   * 'request_end' on the CONNECT stream) and are left to them.
   */
  function releaseIfDone(conn, streamId) {
    var stream = conn.http_streams[streamId];
    if (!stream || stream.tunnel || stream.udp || stream.req._isWebTransport) return;
    if (stream.req._ended && stream.res._finished) releaseHttpStream(conn, streamId, false);
  }

  // A WebTransport stream (wt_stream.js — the client builds its own the same
  // way), recorded on its connection so a session's end can find it, and
  // forgotten when it closes.
  // prefixLength: on a stream we opened, the prefix h3 wrote on it.
  function _createWtStream(conn, quic, wtStreamId, sessionId, kind, prefixLength) {
    var session = conn.http_streams[sessionId];
    var stream = createWtStream(quic, wtStreamId, kind, function () {
      if (conn._wtStreamObjects[wtStreamId] === stream) delete conn._wtStreamObjects[wtStreamId];
      if (conn.h3) conn.h3.releaseWebTransportStream(wtStreamId);
    }, prefixLength, session && session.req._wtSched, sessionId);
    conn._wtStreamObjects[wtStreamId] = stream;
    return stream;
  }


  /**
   * A Duplex over one QUIC stream, for an extended-CONNECT tunnel.
   *
   * The same shape h2_server builds over an HTTP/2 stream, and for the same
   * reason: ws_server was written against a socket, so handing it one of these
   * is the whole integration — the WebSocket framing never learns whether its
   * bytes are TCP, HTTP/2 DATA frames, or QUIC stream bytes.
   *
   * What QUIC adds for free is worth naming: each of these is an independent
   * QUIC stream, so a WebSocket that stalls does not hold up the others on the
   * connection. Over HTTP/2 they all share one TCP byte stream and it does.
   */
  function _createTunnelDuplex(conn, streamId, req) {
    var accepted = false;

    var duplex = new Duplex({
      read: function () {},
      // Destroyed by the application (ws.terminate(), socket.destroy()) while
      // the tunnel is open: the stream cancelled both ways. It was left open
      // — the peer never heard the tunnel had gone. Destroyed because the
      // stream already ended (releaseHttpStream), it is no longer listed.
      destroy: function (err, cb) {
        if (conn.http_streams[streamId] && conn.http_streams[streamId].tunnel === duplex) {
          if (conn.h3) conn.h3.abortStream(streamId, err ? H3_ERR.H3_INTERNAL_ERROR : H3_ERR.H3_REQUEST_CANCELLED);
          releaseHttpStream(conn, streamId, false);
        }
        cb(err);
      },
      write: function (chunk, encoding, cb) {
        if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
        var u8 = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        if (conn.h3) conn.h3.sendTunnelData(streamId, u8, false);
        // Backpressure, as for a response (whenStreamSent in quic_connection).
        if (conn.quic) conn.quic.whenStreamSent(Number(streamId), duplex.writableHighWaterMark, cb); else cb();
      },
      final: function (cb) {
        if (conn.h3) conn.h3.sendTunnelData(streamId, new Uint8Array(0), true);
        cb();
      }
    });

    duplex._streamId = streamId;
    duplex.encrypted = true;          // QUIC is always encrypted
    duplex.setNoDelay = function () { return duplex; };
    duplex.setKeepAlive = function () { return duplex; };
    duplex.setTimeout = function () { return duplex; };

    /**
     * Accept the tunnel.
     *
     * HTTP/3 has no 101 any more than HTTP/2 does: a 2xx accepts (RFC 9220
     * §3). The headers go out WITHOUT FIN — the stream stays open in both
     * directions, which is the entire point — and only then does the stream
     * leave HTTP/3 framing.
     */
    duplex._h2Accept = function (extraHeaders) {
      if (accepted) return;
      accepted = true;
      var h = { ':status': '200' };
      for (var n in (extraHeaders || {})) h[String(n).toLowerCase()] = extraHeaders[n];
      if (conn.h3) {
        conn.h3.sendHeaders(streamId, h, false);
        conn.h3.registerTunnelStream(streamId);
      }
    };

    /** Refuse it, with a status. */
    duplex._h2Reject = function (status, message) {
      if (accepted) return;
      accepted = true;
      if (conn.h3) {
        conn.h3.sendHeaders(streamId, { ':status': String(status) }, true);
        // Whatever the client sent ahead of our answer is held for a tunnel
        // that will now never open: drop it and stop reading.
        conn.h3.stopReading(streamId, H3_ERR.H3_REQUEST_REJECTED);
      }
      releaseHttpStream(conn, streamId, false);
    };

    return duplex;
  }


  // ============================================================
  //  CONNECT-UDP over HTTP/3 — the carrier (see connect_udp.js)
  //
  //  UDP payloads travel as HTTP Datagrams: a QUIC DATAGRAM frame each —
  //  Quarter Stream ID, Context ID 0, the payload — when both sides
  //  negotiated them (SETTINGS_H3_DATAGRAM, and QUIC's max_datagram_frame_
  //  size); otherwise as DATAGRAM capsules in the stream's DATA frames. A
  //  payload larger than a datagram can carry is dropped, not moved to the
  //  stream (RFC 9298 §5: "SHOULD NOT send the UDP payload in a DATAGRAM
  //  capsule") — a reliable, ordered copy of a UDP packet is not one.
  // ============================================================

  var UDP_HELD_MAX = 64;   // datagrams waiting for the 2xx to leave

  function startConnectUdp(conn, streamId, stream) {
    var sid = Number(streamId);
    var quarter = Math.floor(sid / 4);
    var accepted = false, closed = false, busy = false;
    var held = null;   // until the 2xx has left: a datagram before it is one the client drops

    function datagramsOn() {
      return !!(conn.h3 && conn.h3.context.remote_datagram_support === true && conn.quic.maxDatagramSize() > 0);
    }
    function done() {
      if (conn.http_streams[streamId] === stream) releaseHttpStream(conn, streamId, false);
    }

    var carrier = {
      httpVersion: '3.0',
      connKey: conn,
      sink: null,          // set by the proxy: datagram(u8), data(u8), end(), abort()
      peerEnded: false,    // the client's FIN came
      mode: function () { return datagramsOn() ? 'datagram' : 'capsule'; },

      accept: function (headers) {
        if (accepted || closed || !conn.h3) return;
        accepted = true;
        var h = { ':status': '200' };
        for (var n in (headers || {})) h[n] = String(headers[n]);
        conn.h3.sendHeaders(streamId, h, false);
        held = [];
        conn.quic.whenStreamSent(sid, 0, function () {
          var list = held; held = null;
          for (var i = 0; list && i < list.length; i++) conn.quic.sendDatagram(list[i], null, null);
        });
      },

      reject: function (status, headers) {
        if (accepted || closed || !conn.h3) return;
        closed = true;
        var h = { ':status': String(status) };
        for (var n in (headers || {})) h[n] = String(headers[n]);
        conn.h3.sendHeaders(streamId, h, true);
        if (!carrier.peerEnded) conn.h3.stopReading(streamId, H3_ERR.H3_NO_ERROR);
        done();
      },

      sendPayload: function (u8) {
        if (!accepted || closed || !conn.h3) return false;
        if (datagramsOn()) {
          var ctx = contextZero(u8);
          var q = writeVarInt(quarter);
          var dg = new Uint8Array(q.byteLength + ctx.byteLength);
          dg.set(q, 0); dg.set(ctx, q.byteLength);
          if (dg.byteLength > conn.quic.maxDatagramSize()) return false;
          if (held) { if (held.length >= UDP_HELD_MAX) return false; held.push(dg); return true; }
          return conn.quic.sendDatagram(dg, null, null);
        }
        // Capsules: as much waiting on the stream as STREAM_QUEUE_MAX, and
        // past it dropped, as a full UDP queue drops.
        if (busy) return false;
        conn.h3.sendBody(streamId, datagramCapsule(u8), false);
        busy = true;
        conn.quic.whenStreamSent(sid, STREAM_QUEUE_MAX, function () { busy = false; });
        return true;
      },

      // Ours ends: FIN — and, if the client has not ended its side, it is told
      // to stop sending (H3_NO_ERROR: nothing went wrong). Over.
      end: function () {
        if (closed || !conn.h3) return;
        closed = true;
        if (!accepted) conn.h3.sendHeaders(streamId, { ':status': '503' }, true);
        else conn.h3.sendBody(streamId, null, true);
        if (!carrier.peerEnded) conn.h3.stopReading(streamId, H3_ERR.H3_NO_ERROR);
        done();
      },

      // Broken: the stream reset both ways (H3_CONNECT_ERROR, RFC 9114 §4.4).
      abort: function () {
        if (closed) return;
        closed = true;
        if (conn.h3 && conn.http_streams[streamId] === stream) {
          try { conn.h3.abortStream(streamId, H3_ERR.H3_CONNECT_ERROR); } catch (e) {}
        }
        done();
      }
    };

    stream.udp = carrier;
    // The stream's bytes are capsules, credited as they arrive (as a
    // WebTransport session's).
    if (conn.h3) conn.h3.releaseBody(sid);
    conn.udpByQuarter[quarter] = sid;
    connectUdp.handle(stream.req, carrier);
  }



  // ============================================================
  //  set_http_stream — reactive HTTP stream builder
  //  Creates req/res on first call, fires handler when ready.
  //  Same pattern as old quico h3_server.js
  // ============================================================

  function set_http_stream(conn, streamId, params) {
    if (!conn) return;

    var is_new = false;

    // Create req/res on first encounter of this stream — and only for its
    // HEADERS. Body bytes or an end for a stream with no entry belong to a
    // request that does not exist (never started, already cancelled, or
    // already done); creating one for them built a request with no method
    // and no URL, called the handler, and left an entry nothing would remove.
    if (!(streamId in conn.http_streams)) {
      if (!params || typeof params !== 'object' || !('request_headers' in params)) return;

      // After GOAWAY: a request at or above its stream id is not processed
      // (§5.2) — refused with H3_REQUEST_REJECTED, which tells the client it
      // may safely retry it on another connection.
      if (conn.goaway && Number(streamId) >= conn.goaway.id) {
        if (conn.h3) conn.h3.abortStream(streamId, H3_ERR.H3_REQUEST_REJECTED);
        return;
      }

      var req = {
        method: null,
        url: null,
        headers: {},
        httpVersion: '3.0',
        stream_id: Number(streamId),
        _listeners: {},
        _isWebTransport: false,

        // The connection's socket — one object for every request on it, as
        // over TCP (see makeConnSocket).
        h3Fingerprint: function () {
          return conn.getH3Fingerprint ? conn.getH3Fingerprint() : null;
        },

        socket: conn.socket,

        on: function (event, fn) {
          (req._listeners[event] = req._listeners[event] || []).push(fn);
        },

        // The body's flow-control credit, returned as the layer above reads
        // it rather than as it arrives (h3's holdBody): what that layer has
        // not read yet bounds what the client may send.
        _holdBody: function () { if (conn.h3) conn.h3.holdBody(streamId); },
        _creditBody: function (n) { if (conn.h3) conn.h3.creditBody(streamId, n); },
        _releaseBody: function () { if (conn.h3) conn.h3.releaseBody(streamId); },

        // Set by the layer above: whether it still wants the rest of the body
        // once the response is complete (see res.end). Unset, the rest is
        // wanted if anything listens for it.
        _wantsRest: null
      };

      var res = {
        statusCode: 200,
        headers: {},
        headersSent: false,
        _finished: false,
        // A response to HEAD, or a 204 or 304, has no content (RFC 9110 §9.3.2,
        // §15.3.5, §15.4.5): what the application writes is dropped, as Node
        // does over HTTP/1.1 and HTTP/2 (and these layers did already). Sent,
        // it is DATA a client must reject: nghttp3 (curl, the h3 checkers)
        // failed the request with ERR_MALFORMED_HTTP_MESSAGING. Set at
        // writeHead, when the status is known.
        _bodyAllowed: true,

        // A list is kept a list, and goes as one field line per value, as
        // HTTP/1.1 and HTTP/2 send it here and as Node's http does. It was
        // String(list): two cookies became one "a=1,b=2", which a browser
        // reads as a single cookie a with the value "1,b=2" (Set-Cookie
        // never combines, RFC 9110 §5.3).
        setHeader: function (name, value) {
          validateHeaderName(name);
          validateHeaderValue(name, value);
          res.headers[name.toLowerCase()] = Array.isArray(value) ? value.map(String) : String(value);
        },

        getHeader: function (name) {
          return res.headers[name.toLowerCase()];
        },

        writeHead: function (statusCode, headers) {
          if (res.headersSent) return res;
          validateStatus(statusCode);
          res.statusCode = statusCode;
          res._bodyAllowed = !statusHasNoBody(statusCode) && req.headers[':method'] !== 'HEAD';

          if (typeof headers === 'object') {
            for (var name in headers) res.setHeader(name, headers[name]);
          }

          // Connection-specific fields are dropped, as HTTP/2's responses
          // drop them (buildResponsePseudoHeaders): RFC 9114 §4.2 makes a
          // message carrying one malformed, and a client may fail the request
          // over it — an application's `Connection: close` or a WebSocket
          // `Upgrade` meant for HTTP/1.1 cost the response. nginx fixed the
          // same in 1.31.3.
          var h3Headers = { ':status': String(statusCode) };
          for (var name in res.headers) {
            if (isConnectionSpecific(name) || name.charCodeAt(0) === 58) continue;
            h3Headers[name] = res.headers[name];
          }
          // Date (RFC 9110 §6.6.1), as HTTP/2 and HTTP/1.1 send it — HTTP/3's
          // responses had none.
          if (!('date' in h3Headers) && statusCode >= 200 && !(res._wrapper && res._wrapper.sendDate === false)) h3Headers['date'] = httpDate();

          if (conn.h3) {
            // Send headers WITHOUT FIN for WT (session stays open)
            var isWt = req.headers[':protocol'] === 'webtransport';
            conn.h3.sendHeaders(streamId, h3Headers, isWt ? false : undefined);
          }
          res.headersSent = true;

          // A WT CONNECT turned down: streams it already had are refused.
          if (req.headers[':protocol'] === 'webtransport' && !(statusCode >= 200 && statusCode < 300) && conn.h3) {
            conn.h3.rejectWebTransportSession(Number(streamId));
          }
          // If this is a WT CONNECT with 200 → register session
          if (req.headers[':protocol'] === 'webtransport' && statusCode === 200 && conn.h3) {
            req._isWebTransport = true;
            req._wtSched = wtScheduling(conn.quic, Number(streamId));
            // The session as wt_stream's createDatagrams / sessionStats take
            // it — the client's WebTransport hands in the same.
            req._wtOwner = { maxAge: null, expired: 0 };
            req._wtSession = {
              quic: conn.quic,
              connected: function () { return req._isWebTransport && !req._wtClosed; },
              send: function (u8, options) { return res.sendDatagram(u8, options); },
              maxDatagramSize: function () { return res.maxDatagramSize(); },
              owner: req._wtOwner,
              dgStats: { droppedIncoming: 0, expiredIncoming: 0 }
            };
            conn.h3.registerWebTransportSession(Number(streamId));
            // Its datagrams carry Number(streamId) / 4 (RFC 9297 §2.1).
            conn.wtByQuarter[Math.floor(Number(streamId) / 4)] = Number(streamId);
            // From here the CONNECT stream carries capsules, not a body: read
            // here (onSessionCapsules), and credited as they arrive.
            conn.h3.releaseBody(Number(streamId));
            req._capsules = createCapsuleReader(function (info) { sessionClosed(info, false); },
                                                function () { _emitOnReq(req, 'draining'); });
            // Datagrams wait until the 200 has left (see sendDatagram).
            req._wtDatagramsHeld = [];
            conn.quic.whenStreamSent(Number(streamId), 0, function () {
              var held = req._wtDatagramsHeld;
              req._wtDatagramsHeld = null;
              for (var i = 0; held && i < held.length; i++) conn.quic.sendDatagram(held[i].payload, held[i].prio, req._wtOwner);
            });
          }

          return res;
        },

        // 103 Early Hints (RFC 8297): a HEADERS frame with :status 103 and
        // no FIN — the final response follows on the same stream. A list of
        // links goes as one field, comma-joined, which Link allows (RFC 8288).
        writeEarlyHints: function (hints, callback) {
          if (!res.headersSent && !res._finished && conn.h3) {
            var h = { ':status': '103' };
            for (var n in (hints || {})) {
              if (!Object.prototype.hasOwnProperty.call(hints, n) || hints[n] == null) continue;
              h[String(n).toLowerCase()] = Array.isArray(hints[n]) ? hints[n].join(', ') : String(hints[n]);
            }
            try { conn.h3.sendHeaders(streamId, h, false); } catch (e) { /* stream gone */ }
          }
          if (typeof callback === 'function') process.nextTick(callback);
        },

        // 102 Processing (node:http's writeProcessing): as Early Hints go.
        writeProcessing: function () {
          if (res.headersSent || res._finished || !conn.h3) return;
          try { conn.h3.sendHeaders(streamId, { ':status': '102' }, false); } catch (e) { /* stream gone */ }
        },

        write: function (chunk) {
          if (!res.headersSent) res.writeHead(res.statusCode);
          if (!res._bodyAllowed) return true;
          if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
          if (conn.h3) conn.h3.sendBody(streamId, chunk, false);
          return true;
        },

        // Backpressure: cb once the stream has sent all but `bytes` of what
        // was written (see whenStreamSent in quic_connection).
        whenSent: function (bytes, cb) {
          if (!conn.quic || !conn.quic.whenStreamSent) { cb(); return; }
          conn.quic.whenStreamSent(Number(streamId), bytes, cb);
        },

        // `trailers`: fields after the body (res.addTrailers) — a HEADERS
        // frame closing the stream (RFC 9114 §4.1). What gRPC answers with:
        // grpc-status and grpc-message come only there.
        end: function (chunk, trailers) {
          if (res._finished) return;
          if (!res.headersSent) res.writeHead(res.statusCode);
          if (!res._bodyAllowed) { chunk = null; trailers = null; }
          trailers = trailerFields(trailers);
          var withTrailers = !!trailers;
          if (conn.h3) {
            if (chunk) {
              if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
              conn.h3.sendBody(streamId, chunk, !withTrailers);
            } else if (!withTrailers) {
              conn.h3.sendBody(streamId, null, true);
            }
            if (withTrailers) conn.h3.sendHeaders(streamId, trailers, true);
          }
          res._finished = true;

          // The response is complete and the request is not (RFC 9114
          // §4.1.2): a 413, a 401, a refusal answered before the upload is
          // read. Unless something still reads the body, the client is told
          // to stop sending it — STOP_SENDING with H3_NO_ERROR, which does
          // not touch the response — and the request is over. It used to
          // stay open: the client went on uploading into a window nobody
          // would open again, holding its stream until it gave up.
          if (!req._ended && !req._isWebTransport && conn.h3 && conn.http_streams[streamId] && !conn.http_streams[streamId].tunnel) {
            var wants = typeof req._wantsRest === 'function' ? req._wantsRest()
                      : !!(req._listeners['data'] && req._listeners['data'].length);
            if (!wants) {
              conn.h3.stopReading(streamId, H3_ERR.H3_NO_ERROR);
              releaseHttpStream(conn, streamId, false);
              return;
            }
          }
          releaseIfDone(conn, streamId);
        },

        // The application gave the exchange up (res.destroy(), req.destroy()
        // — unified server): the response not finished, the stream is
        // cancelled both ways (RFC 9114 §4.1.1), `code` H3_REQUEST_CANCELLED
        // or, for a failure of ours, H3_INTERNAL_ERROR; the response already
        // complete, only what is left of the request body is refused
        // (STOP_SENDING H3_NO_ERROR, §4.1.2), the response left to arrive.
        // The request is then over here, as at any other end. Without this
        // the client waited for the rest of a response that would never come
        // and the stream stayed listed until the connection closed.
        abort: function (code) {
          if (!conn.http_streams[streamId]) return;
          if (!res._finished) {
            res._finished = true;
            if (conn.h3) conn.h3.abortStream(streamId, code);
          } else if (!req._ended) {
            if (conn.h3) conn.h3.stopReading(streamId, H3_ERR.H3_NO_ERROR);
          } else {
            return;
          }
          releaseHttpStream(conn, streamId, false);
        },

        // The response's priority, as the server decides it: { urgency
        // (0..7, 0 first), incremental } — RFC 9218's parameters. It replaces
        // what the client asked for (its `priority` header, PRIORITY_UPDATE),
        // and later requests from the client do not override it. For a
        // WebTransport session, its urgency is its streams' too.
        setPriority: function (p) {
          if (conn.quic) conn.quic.setStreamPriority(Number(streamId), responsePriority(p));
        },

        // ---- WebTransport methods on res ----

        // true: queued, and sent if room comes in time (quic_connection's
        // sendDatagram — never retransmitted, the oldest dropped first when
        // the path cannot keep up). false: it cannot be — no session, or
        // larger than the peer takes (res.maxDatagramSize()).
        //
        // Held until the 200 that opens the session has left: a datagram the
        // browser receives before it knows the session exists is dropped.
        // Sent at once, they all were — every one the application sent right
        // after accepting the session, 3000 of 3000, since the 200 waits for
        // the end of the tick and a datagram did not.
        //
        // options { sendOrder, sendGroup }: as the browser's
        // datagrams.createWritable(options) — its place among the session's
        // streams (wtScheduling); without them, ahead of every stream.
        sendDatagram: function (data, options) {
          if (!req._isWebTransport || !conn.quic) return false;
          if (typeof data === 'string') data = Buffer.from(data);
          if (Buffer.isBuffer(data)) data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
          var payload = wt_datagram_payload(Number(streamId), data);
          if (payload.byteLength > conn.quic.maxDatagramSize()) return false;
          var prio = req._wtSched.forDatagram(options);
          if (req._wtDatagramsHeld) {
            req._wtDatagramsHeld.push({ payload: payload, prio: prio });
            if (req._wtDatagramsHeld.length > WT_DATAGRAMS_HELD) req._wtDatagramsHeld.shift();   // the oldest goes
            return true;
          }
          return conn.quic.sendDatagram(payload, prio, req._wtOwner);
        },

        // The largest datagram this session can send, in bytes of payload.
        maxDatagramSize: function () {
          if (!req._isWebTransport || !conn.quic) return 0;
          return Math.max(0, conn.quic.maxDatagramSize() - (wt_datagram_payload(Number(streamId), new Uint8Array(0)).byteLength));
        },

        // Close the session with a code (32-bit) and a reason (UTF-8, up to
        // 1024 bytes): CLOSE_WEBTRANSPORT_SESSION, then the CONNECT stream's
        // end — what a browser's wt.close({ closeCode, reason }) sends, and
        // what its wt.closed resolves with. Its streams are reset with
        // WEBTRANSPORT_SESSION_GONE. There was no way to close a session but
        // to close the whole QUIC connection under it.
        closeSession: function (code, reason) {
          if (!req._isWebTransport || req._wtClosed || !conn.h3) return;
          conn.h3.sendBody(streamId, wtCloseCapsule(code || 0, reason), true);
          sessionClosed({ closeCode: Number(code) || 0, reason: reason == null ? '' : String(reason) }, true);
        },

        // DRAIN_WEBTRANSPORT_SESSION: the peer should finish what it is doing
        // and start nothing new; the session stays open.
        drainSession: function () {
          if (!req._isWebTransport || req._wtClosed || !conn.h3) return;
          conn.h3.sendBody(streamId, wtDrainCapsule(), false);
        },

        // The application protocol chosen for the session, one of those the
        // client offered (req.webTransportProtocols): sent as WT-Protocol
        // with the 200, and what the browser's wt.protocol then says. Before
        // writeHead; a name the client did not offer throws — the client
        // would fail the session over it.
        setWebTransportProtocol: function (name) {
          if (res.headersSent) throw new Error('setWebTransportProtocol() after the response head was sent');
          var offered = req.webTransportProtocols || [];
          if (offered.indexOf(name) < 0) throw new TypeError('the client did not offer the protocol ' + JSON.stringify(name));
          res.setHeader('wt-protocol', sfString(name));
        },

        // The browser's getStats(), as the client's wt.getStats(): the
        // connection's figures and this session's datagrams (wt_stream's
        // sessionStats).
        getStats: function () {
          if (!req._wtSession) return Promise.resolve(null);
          return sessionStats(req._wtSession);
        },

        // The browser's WebTransportSendGroup, for a stream's sendGroup or a
        // datagram's.
        createSendGroup: function () { return createSendGroup(); },

        // The browser's exportKeyingMaterial, as the client's: this session's
        // keying material from the TLS exporter — the same bytes the client
        // gets for the same label and context.
        exportKeyingMaterial: function (label, context, outputLength) {
          var a;
          try { a = exporterArgs(arguments); } catch (e) { return Promise.reject(e); }
          if (!req._isWebTransport || req._wtClosed) return Promise.reject(new DOMException('the session is closed', 'InvalidStateError'));
          try { return Promise.resolve(exportSessionKeyingMaterial(conn.quic, Number(streamId), a)); }
          catch (e) { return Promise.reject(e); }
        },

        // A stream of ours: a Duplex, or a Writable — recorded with its
        // session, so the session's end destroys it. options { sendOrder,
        // sendGroup, waitUntilAvailable }, the browser's (wt_stream's
        // openWtStream): null, without waitUntilAvailable, when the client
        // allows no more streams now (res.canOpenStream()).
        //
        // callback(err, stream): once it is open — at once, or (with
        // waitUntilAvailable) when the client allows it; err if it closed
        // first. stream.pending and its 'ready' say the same.
        createBidirectionalStream: function (options, callback) { return openSessionStream(true, options, callback); },
        createUnidirectionalStream: function (options, callback) { return openSessionStream(false, options, callback); },

        // Whether a stream of ours could be opened now, within the client's
        // MAX_STREAMS. options { bidirectional }.
        canOpenStream: function (options) {
          return !!(req._isWebTransport && !req._wtClosed && conn.quic && conn.quic.canOpenStream(!!(options && options.bidirectional)));
        }
      };

      // The browser's datagrams object (readable, writable, createWritable,
      // the age limits), as the client's wt.datagrams — made on first use.
      Object.defineProperty(res, 'datagrams', { enumerable: true, get: function () {
        if (!req._wtSession) return null;
        return req._wtDatagrams || (req._wtDatagrams = createDatagrams(req._wtSession));
      } });

      var openSessionStream = function (bidi, options, callback) {
        if (typeof options === 'function') { callback = options; options = null; }
        if (!req._isWebTransport || req._wtClosed || !conn.h3) return null;
        return openWtStream(conn.h3, conn.quic, Number(streamId), bidi, options, function (id, kind, prefix) {
          return _createWtStream(conn, conn.quic, id, Number(streamId), kind, prefix);
        }, callback);
      };

      // A WebTransport session ended by CLOSE_WEBTRANSPORT_SESSION — the
      // peer's capsule, or ours (res.closeSession). req.closeInfo holds the
      // code and reason, as a browser's wt.closed resolves with them; then
      // 'close', and the session's streams go (WEBTRANSPORT_SESSION_GONE).
      // After the peer's, our side of the CONNECT stream ends too (§5).
      var sessionClosed = function (info, byUs) {
        if (req._wtClosed || !req._isWebTransport) return;
        req.closeInfo = info;
        if (req._wrapper) req._wrapper.closeInfo = info;
        req._capsules = null;
        if (!byUs && conn.h3) conn.h3.sendBody(streamId, null, true);
        if (conn.h3) conn.h3.endWebTransportSession(Number(streamId));
        releaseHttpStream(conn, streamId, false);
      };

      conn.http_streams[streamId] = { req: req, res: res };
      is_new = true;
    }

    // Apply params
    if (typeof params === 'object') {

      if ('request_headers' in params) {
        var stream = conn.http_streams[streamId];
        for (var name in params.request_headers) {
          stream.req.headers[name] = params.request_headers[name];
        }
        // The field lines as they came (validateFieldSection), which the
        // copy above leaves behind — not enumerable: req.rawHeaders and
        // headersDistinct are built from them. Without it they were rebuilt
        // from the joined values, two x-a lines one "1, 2".
        if (params.request_headers._rawHeaders && !stream.req.headers._rawHeaders) {
          Object.defineProperty(stream.req.headers, '_rawHeaders', { value: params.request_headers._rawHeaders, enumerable: false });
        }

        // Extract :method and :path
        if (stream.req.method === null && ':method' in stream.req.headers) {
          stream.req.method = stream.req.headers[':method'];
        }
        if (stream.req.url === null && ':path' in stream.req.headers) {
          stream.req.url = stream.req.headers[':path'];
        }
        // A WebTransport CONNECT: the application protocols the client
        // offers (WT-Available-Protocols), in its order of preference.
        if (stream.req.headers[':protocol'] === 'webtransport') {
          stream.req.webTransportProtocols = parseSfStringList(stream.req.headers['wt-available-protocols']);
        }
      }

      if ('request_body_chunk' in params) {
        var stream = conn.http_streams[streamId];
        // A 0-RTT request being judged (earlyGate): later.
        if (stream.req._paused) { stream.req._paused.push({ request_body_chunk: params.request_body_chunk }); return; }
        // An open WebTransport session's CONNECT stream: capsules, not a body.
        if (stream.req._capsules) { stream.req._capsules(params.request_body_chunk); return; }
        // A CONNECT-UDP tunnel's: capsules too, for the proxy.
        if (stream.udp) { if (stream.udp.sink) stream.udp.sink.data(params.request_body_chunk); return; }
        var listeners = stream.req._listeners['data'] || [];
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](params.request_body_chunk); } catch (e) { }
        }
      }

      if ('request_end' in params) {
        var stream = conn.http_streams[streamId];
        if (stream.req._paused) { stream.req._paused.push({ request_end: true }); return; }
        clearRequestDeadline(stream);
        // The client closed the tunnel (§3.1 of RFC 9298).
        if (stream.udp) { stream.udp.peerEnded = true; if (stream.udp.sink) stream.udp.sink.end(); return; }
        var listeners = stream.req._listeners['end'] || [];
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](); } catch (e) { }
        }
        stream.req._ended = true;

        // A session ends with its CONNECT stream's FIN (releaseHttpStream
        // says so and closes its streams); a request, once its response is
        // done too.
        if (stream.req._isWebTransport) releaseHttpStream(conn, streamId, false);
        else releaseIfDone(conn, streamId);
      }
    }

    // Fire handler on new stream (after headers are set). A request that
    // came in 0-RTT is judged first (earlyGate): it may be a replay.
    if (is_new) {
      var newStream = conn.http_streams[streamId];
      newStream.req.earlyData = !!(conn.quic && conn.quic.isEarlyStream && conn.quic.isEarlyStream(streamId));
      if (newStream.req.earlyData) { earlyGate(conn, streamId, newStream, function () { dispatchNewRequest(newStream); }); return; }
      dispatchNewRequest(newStream);
    }

    function dispatchNewRequest(stream) {

      // ---- Extended CONNECT for something other than WebTransport ----
      //
      // RFC 9220 bootstraps WebSocket over HTTP/3 exactly as RFC 8441 does
      // over HTTP/2: a CONNECT carrying :protocol, answered with a 2xx. The
      // two differ only in what runs on the stream afterwards — WebTransport
      // turns it into a session that later streams join, WebSocket just sends
      // frames on it — so a WebSocket must NOT be registered as a session, or
      // unrelated streams carrying its id would be mistaken for members of it.
      var proto = stream.req.headers[':protocol'];
      // CONNECT-UDP, when the application proxies UDP: not a tunnel of raw
      // bytes — after the 2xx the stream still carries HTTP/3 DATA frames,
      // holding capsules (RFC 9297 §3.2), as a WebTransport session's does.
      if (proto && connectUdp && String(proto).toLowerCase() === 'connect-udp' && connectUdp.wants(stream.req)) {
        startConnectUdp(conn, streamId, stream);
        return;
      }
      if (proto && String(proto).toLowerCase() !== 'webtransport' && shouldUpgradeCallback(stream.req)) {
        // Stop HTTP/3 framing on this stream NOW, before the application has
        // decided anything: a client may already be sending WebSocket frames,
        // and they must not reach the frame parser.
        if (conn.h3) conn.h3.beginTunnelStream(streamId);
        var duplex = _createTunnelDuplex(conn, streamId, stream.req);
        stream.tunnel = duplex;

        if (upgradeListeners === 0) {
          // Accepted by shouldUpgradeCallback, yet nobody listens. Answer
          // rather than leave the peer waiting for a 2xx that will never come.
          if (conn.h3) {
            conn.h3.sendHeaders(streamId, { ':status': '501' }, true);
            conn.h3.stopReading(streamId, H3_ERR.H3_REQUEST_REJECTED);
          }
          releaseHttpStream(conn, streamId, false);
          return;
        }
        stream.req.upgrade = true;
        ev.emit('upgrade', stream.req, duplex, Buffer.alloc(0));
        return;
      }

      if (stream.req.method !== 'CONNECT' && !stream.req._ended) armRequestDeadline(conn, streamId, stream);

      // A handler that throws loses its own stream — reset both ways,
      // H3_INTERNAL_ERROR — not the connection (see runRequestHandler). A
      // response it had already ended is left to finish.
      // maxRequestsPerSocket: after the Nth request, GOAWAY — those in flight
      // finish, the client takes the next to a new connection (as HTTP/2).
      if (maxRequests > 0 && ++conn.served === maxRequests && conn.handle) conn.handle.goaway();
      runRequestHandler(function () {
        if (typeof handler === 'function') handler(stream.req, stream.res);
        ev.emit('request', stream.req, stream.res);
      }, function () {
        var w = stream.res && stream.res._wrapper;
        if (w ? w.writableEnded : stream.res._finished) return;
        if (conn.http_streams[streamId] !== stream) return;
        if (conn.h3) conn.h3.abortStream(streamId, H3_ERR.H3_INTERNAL_ERROR);
        releaseHttpStream(conn, streamId, true);
      });
    }
  }

  // ── 0-RTT requests (RFC 8470) ──────────────────────────────────────────
  //
  // A request that came in 0-RTT (req.earlyData) may be a replay: whoever
  // captured the client's first flight can send it again. Each one is asked
  // about first — earlyDataFilter(req, callback(err, allow)), the
  // application's, or by default: GET, HEAD and OPTIONS go on, anything else
  // is answered 425 Too Early, which a client sends again once its handshake
  // is done (the browsers do, and quico's client). No answer within
  // EARLY_FILTER_TIMEOUT_MS, an error, a throw: 425 — the request is not
  // lost, only later. Meanwhile what more arrives on the stream (a body, its
  // end) waits, for the handler to find.
  // (The filter and its timeout: http_common's runEarlyDataFilter.)
  function earlyGate(conn, streamId, stream, proceed) {
    var req = stream.req;
    req._paused = [];
    runEarlyDataFilter(earlyDataFilter, req, function (allow) {
      var queued = req._paused;
      req._paused = null;
      if (conn.http_streams[streamId] !== stream) return;   // gone meanwhile (reset, closed)
      if (!allow) { tooEarly(conn, streamId, stream); return; }
      proceed();
      for (var i = 0; i < queued.length; i++) set_http_stream(conn, streamId, queued[i]);
    });
  }
  function tooEarly(conn, streamId, stream) {
    if (options.stats) options.stats.earlyData.tooEarly++;
    if (conn.h3) {
      conn.h3.sendHeaders(streamId, { ':status': '425', 'content-length': '0' }, true);
      if (!stream.req._ended) conn.h3.stopReading(streamId, H3_ERR.H3_NO_ERROR);
    }
    releaseHttpStream(conn, streamId, false);
  }


  // ============================================================
  //  HTTP/3 over each accepted QUIC connection
  //  The transport server hands us a raw QUICConnection per peer; we wrap
  //  it in an H3Connection once the handshake completes and bridge HTTP/3 +
  //  WebTransport events to req/res via set_http_stream. Per-connection
  //  state lives in this closure — the transport server owns the UDP
  //  socket, demux and connection lifecycle.
  // ============================================================

  /**
   * A stand-in for the TLSSocket that TCP requests carry — ONE per QUIC
   * connection, shared by every request on it.
   *
   * Over TCP, req.socket is the connection: every request on it gets the
   * same object, which is how an application tells that two requests came in
   * on one connection, and hears 'close' when it goes. It used to be built
   * per request here, so over HTTP/3 no two requests shared one and nothing
   * ever closed.
   *
   * There is no real socket: the TLS handshake happens inside the QUIC
   * connection, so what an application reaches for on req.socket is answered
   * from it. `encrypted` is always true — QUIC has no unencrypted mode.
   * The address follows the connection when the client moves (migration,
   * RFC 9000 §9) — once the new address is validated.
   */
  function makeConnSocket(conn, quic, peer) {
    // A real Duplex (streams.js), not a bare emitter: Express reads
    // socket.readable / socket.writable to decide whether a request is still
    // open (on-finished — body-parser, express.static), and listens on it with
    // on/removeListener. Without them every HTTP/3 request looked finished
    // before it started: a POST body was skipped and a static file never sent.
    var sock = _makeSocketStub();
    sock.alpnProtocol = 'h3';
    // The connection's QUIC version (1, or 0x6b3343cf for v2) — after
    // compatible version negotiation, the one negotiated.
    Object.defineProperty(sock, 'quicVersion', { configurable: true, enumerable: true,
      get: function () { return quic.version; } });
    // Live, as net.Socket's are: a client whose NAT changes its port is
    // followed by the connection (RFC 9000 §9.3), and a copy taken here
    // would go on naming the address it left.
    Object.defineProperty(sock, 'remoteAddress', { configurable: true, enumerable: true,
      get: function () { return quic.remoteAddress || (peer && peer.address) || null; } });
    Object.defineProperty(sock, 'remotePort', { configurable: true, enumerable: true,
      get: function () { return quic.remotePort || (peer && peer.port) || null; } });
    // TLS fingerprints and the certificate presented, as on a TLSSocket.
    sock.getJA4 = function (opts) { return quic.getJA4 ? quic.getJA4(opts) : null; };
    sock.getJA5 = function (opts) { return quic.getJA5 ? quic.getJA5(opts) : null; };
    sock.getJA4S = function (opts) { return quic.getJA4S ? quic.getJA4S(opts) : null; };
    // What the handshake settled, as a lemon-tls TLSSocket answers over
    // HTTP/2 and HTTP/1.1 — among it whether the certificates went compressed.
    sock.getNegotiationResult = function () { return quic.getNegotiationResult ? quic.getNegotiationResult() : null; };
    sock.getCertificate = function () { return quic.getCertificate ? quic.getCertificate() : {}; };
    // The client's certificate and its verification, as a TLSSocket's
    // (requestCert). The stub said `authorized: true` and `{}` for every
    // connection: harmless while QUIC could not ask for a certificate, and
    // an open door once it could — an application checking
    // req.socket.authorized would have let in a client that sent none.
    Object.defineProperty(sock, 'authorized', { configurable: true, enumerable: true,
      get: function () { return !!(quic.isAuthorized && quic.isAuthorized()); } });
    Object.defineProperty(sock, 'authorizationError', { configurable: true, enumerable: true,
      get: function () { return quic.authorizationError ? quic.authorizationError() : null; } });
    sock.getPeerCertificate = function () { return quic.getPeerCertificate ? quic.getPeerCertificate() : {}; };
    sock.getPeerX509Certificate = function () {
      var c = sock.getPeerCertificate();
      try { return c && c.raw ? new X509Certificate(c.raw) : undefined; } catch (e) { return undefined; }
    };
    // The session ticket, { data, resumed, offered } — the same method a
    // TLSSocket has over TCP, so req.socket answers it on every HTTP version.
    sock.getTicketInfo = function () { return quic.getTicketInfo ? quic.getTicketInfo() : null; };
    // This connection's options while it runs (quic_connection's
    // setOptions): every request on the connection shares them.
    sock.setOptions = function (o) { quic.setOptions(o); return sock; };
    sock.getOptions = function () { return quic.getOptions(); };
    // And the rest of a TLSSocket's session questions.
    sock.isSessionReused = function () { return !!(quic.isSessionReused && quic.isSessionReused()); };
    sock.getProtocol = function () { return quic.getProtocol ? quic.getProtocol() : null; };
    sock.getCipher = function () { return quic.getCipher ? quic.getCipher() : null; };
    // The protocol-layer fingerprint, alongside the TLS one above. Named to
    // match req.h2Fingerprint on the TCP side so an application can reach for
    // whichever is present without branching on version.
    sock.h3Fingerprint = function () { return conn.getH3Fingerprint ? conn.getH3Fingerprint() : null; };
    // The SNI the client sent, or false — known once the ClientHello is in,
    // which is before any request, so read live rather than copied now.
    Object.defineProperty(sock, 'servername', {
      get: function () { return quic.servername || false; },
      enumerable: true
    });
    // Encrypted Client Hello, as over TCP (lemon-tls TLSSocket): null when
    // not offered, 'accepted' — servername is then the name that was hidden
    // — or 'rejected' (servername is the public name).
    Object.defineProperty(sock, 'echStatus', {
      get: function () { return quic.echStatus; },
      enumerable: true
    });
    Object.defineProperty(sock, 'echAccepted', {
      get: function () { return quic.echStatus === 'accepted'; },
      enumerable: true
    });
    // Gone with the connection: destroy() turns readable/writable off, sets
    // destroyed, and emits 'close' — as a socket does.
    quic.on('close', function () {
      if (!sock.destroyed) sock.destroy();
    });
    return sock;
  }

  // Every connection, for closing them (closeIdleConnections, close()).
  var conns = new Set();
  var closingServer = null;     // close()'s callback, once every connection is gone

  qserver.on('connection', function (quic, peer) {
    var conn = { quic: quic, h3: null, http_streams: {}, _wtStreamObjects: {}, served: 0,
                 headerDeadlines: {},   // request streams whose HEADERS is still arriving
                 wtByQuarter: {},       // WebTransport sessions by Quarter Stream ID → stream id
                 udpByQuarter: {} };    // CONNECT-UDP tunnels, the same way
    conn.socket = makeConnSocket(conn, quic, peer);

    // The connection is gone — CONNECTION_CLOSE from either side, or the
    // idle timeout. Every WebTransport session on it ends with it, and says
    // so with 'close' on its request, as a session the browser closes does.
    // Without this the application never heard of a peer that vanished.
    //
    // So does everything else still open on it. A request whose body was
    // still arriving, or whose response was still being written, or a
    // WebSocket tunnel, used to hear nothing at all: the application waited
    // for an end that could not come, until a timeout of its own. Each is
    // ended the way a cancelled stream is — releaseHttpStream, aborted:
    // 'aborted' on the request and 'close' on the response, a tunnel
    // destroyed, a session closed with its streams. Requests that had
    // finished in both directions are already gone (releaseIfDone).
    conns.add(conn);
    // Over for the application ('closing'), or its draining done ('close').
    var gone = function () { if (conns.delete(conn)) connGone(); };
    quic.on('closing', gone);
    quic.on('close', function () {
      gone();
      for (var hid in conn.headerDeadlines) clearHeadersDeadline(conn, hid);
      for (var sid in conn.http_streams) releaseHttpStream(conn, sid, true);
      for (var wid in conn._wtStreamObjects) releaseHttpStream(conn, wid, true);
    });

    // Registered HERE, not after the handshake completes.
    //
    // The peer's QUIC transport parameters arrive inside its ClientHello,
    // which is processed long before 'connect' fires — a listener attached
    // afterwards has already missed them, and the transport section of the
    // fingerprint comes out empty. The HTTP/3 SETTINGS arrive later still, on
    // the control stream, so observeH3 is given the QUIC connection now and
    // the H3 connection as soon as it exists.
    var h3Observer = observeH3(null, quic);
    conn.getH3Fingerprint = function () { return h3Observer(); };

    /**
     * The same handle h2_server builds, so that one piece of rate-limiting
     * code works against both protocols without branching on version.
     */
    var connHandle = {
      httpVersion: '3.0',
      // quic_server attaches the address to the connection, but the listener
      // is handed it directly too — `peer` — and that one does not depend on
      // which version of quic_server is installed. Without the fallback an
      // older quic_server gives null here, and an IP screen that reads it
      // skips the connection silently rather than failing.
      get remoteAddress() { return quic.remoteAddress || (peer && peer.address) || null; },
      get remotePort() { return quic.remotePort || (peer && peer.port) || null; },

      // Read by anything that checks before it acts, the way checkIpBlacklist
      // does with a TCP socket: its answer arrives asynchronously, and by then
      // the peer may already have gone.
      get destroyed() {
        var st = quic.state;
        return st === 'closed' || st === 'draining' || st === 'closing';
      },
      encrypted: true,
      fingerprint: function () { return h3Observer(); },
      getTicketInfo: function () { return quic.getTicketInfo ? quic.getTicketInfo() : null; },
      isSessionReused: function () { return !!(quic.isSessionReused && quic.isSessionReused()); },
      // This connection's options while it runs: { startupCap, reorderWindow,
      // pmtuDiscovery, maxUdpPayloadSize, initialRtt, initialCongestionWindow,
      // carefulResume } (quic_connection's setOptions).
      setOptions: function (o) { quic.setOptions(o); return connHandle; },
      getOptions: function () { return quic.getOptions(); },

      // Refuse or cancel a stream: RESET_STREAM and STOP_SENDING both ways,
      // as RFC 9114 §4.1.1 describes. The intents are h2_server's — 'refused'
      // for a request never processed, which the client may safely retry
      // (H3_REQUEST_REJECTED), 'cancelled' for one abandoned part way
      // (H3_REQUEST_CANCELLED); a number is passed through as is.
      //
      // It used to answer 429 instead: QUIC could not reset a stream until
      // control frames became reliable. A 429 still costs a response, and
      // leaves the stream open until the client reads it.
      sendRstStream: function (streamId, code) {
        var h3code = typeof code === 'number' ? code
                   : code === 'cancelled' ? H3_ERR.H3_REQUEST_CANCELLED
                   : H3_ERR.H3_REQUEST_REJECTED;
        if (conn.h3) conn.h3.abortStream(streamId, h3code);
        clearHeadersDeadline(conn, streamId);
        releaseHttpStream(conn, streamId, true);
      },

      // Stop new requests; the ones in flight finish — as h2_server's
      // goaway(), whose semantics a rate limiter is written against. This
      // closed the connection on the spot, so the same limiter code that let
      // HTTP/2 requests in progress complete cut HTTP/3 ones off mid-response.
      //
      // The GOAWAY carries the first request stream id NOT processed: one past
      // the highest the client has opened, so every request already started —
      // even one whose HEADERS are still arriving — is answered. When they
      // have all finished and been delivered, the connection is closed:
      // H3_NO_ERROR, or H3_EXCESSIVE_LOAD for goaway('overloaded') (HTTP/2's
      // ENHANCE_YOUR_CALM). Before the handshake there is no HTTP/3 to speak
      // of: refused, as destroy() does.
      goaway: function (code) {
        if (conn.goaway) return;
        if (!conn.h3) { try { quic.close(0x02, 'refused', false); } catch (e) {} return; }
        conn.goaway = { id: (quic.context.peer_max_opened_bidi + 1) * 4, code: h3ConnCode(code), closing: false };
        conn.h3.sendGoaway(conn.goaway.id);
        closeAfterGoaway(conn);
      },

      destroy: function (code) {
        // Two different closes, because the right one depends on WHEN.
        //
        // Before the handshake completes there is no HTTP/3 yet — an
        // application error code has no meaning to the peer, and RFC 9000
        // §10.2.3 forbids sending one in the Initial or Handshake packet
        // spaces. CONNECTION_REFUSED (0x02) is the transport error that says
        // exactly what happened: the server declined the connection. That is
        // the case for an IP screen, which runs on the very first packet.
        //
        // After it, the application space, with the intent as for goaway():
        // H3_NO_ERROR, H3_EXCESSIVE_LOAD for 'overloaded', or a number. It sent
        // 0x10c — H3_REQUEST_CANCELLED, a stream's code, which says nothing
        // about why a connection ended.
        try {
          if (!conn.h3) quic.close(0x02, 'refused', false);
          else          quic.close(h3ConnCode(code), 'closed', true);
        } catch (e) {}
      }
    };
    conn.handle = connHandle;

    // Announced upward, before the handshake — the QUIC counterpart of
    // tcp_listener's 'connection', and there for the same reason.
    //
    // It is the one point where a server can refuse a peer before any crypto
    // is done on its behalf. It fires on the first Initial packet, so a
    // listener that calls destroy() here stops the connection before the TLS
    // handshake, just as destroying a TCP socket in 'connection' does.
    //
    // Without it, nothing above this file learns that a QUIC connection
    // exists, and screening that is wired to 'connection' — an IP blacklist,
    // a rate limit on new connections — applies to HTTP/1.1 and HTTP/2 and
    // silently not to HTTP/3.
    //
    // The handle carries remoteAddress, destroyed and destroy(), which is what
    // such a listener uses on a TCP socket, so the same function serves both.
    ev.emit('connection', connHandle);

    // A handshake that failed — a TLS alert (a client certificate refused, no
    // common cipher, a size limit) or the handshake timeout: node:tls's
    // 'tlsClientError', with the handle in place of the socket. The QUIC
    // connection reports 'error' for exactly these and nothing else; it was
    // not listened to, so a failed handshake left no trace.
    //
    // Also when it is the client that ended the handshake with an alert (a
    // browser that does not trust the certificate): in QUIC that arrives as
    // CONNECTION_CLOSE with CRYPTO_ERROR, 0x100 + the alert (RFC 9001 §4.8),
    // where node:tls would report the alert itself — even after 'connect',
    // which a server reaches with its own Finished, before the client has
    // checked anything. A CRYPTO_ERROR can only come from TLS, and TLS in
    // QUIC is the handshake. Once per connection.
    var tlsErrorReported = false;
    function reportTlsError(err) {
      if (tlsErrorReported) return;
      tlsErrorReported = true;
      ev.emit('tlsClientError', err, connHandle);
    }
    quic.on('error', reportTlsError);
    quic.on('close', function () {
      var pc = quic.context && quic.context.peer_close;
      // The transport's CONNECTION_CLOSE only (0x1c): in the application's
      // (0x1d) the same numbers are HTTP/3's — 0x100 is H3_NO_ERROR, a
      // client closing a connection it is done with. Reported as TLS alert 0
      // since HTTP/3 clients began to say goodbye (h3_client's
      // CONNECTION_CLOSE used to be lost with its socket).
      if (pc && !pc.application && pc.error >= 0x100 && pc.error < 0x200) {
        var err = new Error('the client ended the handshake: TLS alert ' + (pc.error - 0x100) + (pc.reason ? ' (' + pc.reason + ')' : ''));
        err.code = 'ERR_TLS_ALERT_RECEIVED';
        err.alert = pc.error - 0x100;
        reportTlsError(err);
      }
    });

    // 'secureConnection': the handshake is complete — the client's Finished
    // verified, the name and the moment node:tls uses (it was emitted when
    // the server's own Finished went, a round trip early, before the client
    // had proven anything). 'connection' fired before any TLS, knowing only
    // an address; here the connection can be asked what the handshake
    // decided (isSessionReused(), getTicketInfo()), which is what a caller
    // needs to tell a returning client from a new one. Before any request:
    // the client's are held until now. A listener may destroy() it. The same
    // handle as 'connection' carries — over QUIC there is no socket to hand
    // out.
    quic.on('handshake_ended', function (confirmed) {
      if (confirmed) ev.emit('secureConnection', connHandle);
    });

    // Our side of the handshake done (our Finished sent): HTTP/3 set up —
    // its SETTINGS go with the handshake's last datagram.
    quic.on('connect', function () {
      if (connHandle.destroyed) return;

      // The handshake may have settled on something other than HTTP/3 when
      // the server accepts more than one ALPN name. Such a connection is not
      // ours to speak: the application only asked that the handshake agree to
      // the name. Close it instead of treating its streams as HTTP/3.
      var negotiated = quic.alpnProtocol;
      if (negotiated && negotiated !== 'h3') {
        try { quic.close(0, 'alpn ' + negotiated + ' is not served here'); } catch (e) {}
        return;
      }

      var h3 = new H3Connection({
        quicConnection: quic,
        enableWebTransport: true,
        maxWebTransportSessions: options.maxWebTransportSessions,
        // Report-only mode for the checks added with the error layer. See the
        // note in h3.js: these turn conditions that were previously ignored
        // into connection errors, so a bug they expose looks like a regression.
        qpackLenient: options.qpackLenient === true
      });
      conn.h3 = h3;
      // The H3 half of the observer, now that the connection exists. The QUIC
      // half was attached before the handshake, above.
      h3Observer = observeH3(h3, quic, h3Observer.state);

      // Surface HTTP/3-level failures on the server. Without this the error
      // raised by connectionError() is emitted into a connection object nobody
      // listens to, and the peer's ERR_QUIC_PROTOCOL_ERROR is the only sign
      // anything happened — invisible on this side, which is the exact failure
      // mode the error layer exists to remove.
      h3.on('error', function (err) { ev.emit('error', err); });

      // HTTP request headers received → set_http_stream (reactive)
      h3.on('http_headers', function (streamId, headers) {
        clearHeadersDeadline(conn, streamId);
        set_http_stream(conn, streamId, { request_headers: headers });
      });

      // The request's trailers (after its body, before its end): on req, as
      // node:http's req.trailers — read once 'end' has fired.
      h3.on('http_trailers', function (streamId, trailers) {
        var st = conn.http_streams[streamId];
        if (st && st.req) st.req.trailers = trailers;
      });

      // HTTP request body chunk → set_http_stream
      h3.on('http_body', function (streamId, data) {
        set_http_stream(conn, streamId, { request_body_chunk: data });
      });

      // HTTP request complete → fire req.on('end')
      h3.on('http_end', function (streamId) {
        set_http_stream(conn, streamId, { request_end: true });
      });

      // Bytes on an accepted extended-CONNECT tunnel: WebSocket frames, not
      // HTTP/3 frames. They go straight to the Duplex the upgrade handler was
      // given.
      h3.on('stream_open', function (streamId) {
        armHeadersDeadline(conn, streamId);
        ev.emit('stream_open', connHandle, streamId);
      });
      // The client cancelled a stream. Same event and arguments as
      // h2_server's 'stream_reset', so a Rapid Reset detector is written once
      // for both protocols.
      //
      // HTTP/2 has one frame for it (RST_STREAM); HTTP/3 has two, one per
      // direction, and which ones arrive depends on the request. A browser
      // cancelling a GET sends only STOP_SENDING — its side of the stream is
      // already finished, so there is nothing to reset — while cancelling an
      // upload sends both. Reporting only RESET_STREAM made every cancelled
      // GET invisible, and GET-then-cancel is exactly what a Rapid Reset
      // attack sends. So: either frame reports the cancellation, once per
      // stream.
      var cancelReported = new Set();
      // Rapid Reset: past streamResetBurst / streamResetRate cancelled
      // request streams, the connection is closed with H3_EXCESSIVE_LOAD.
      var resetTooMany = streamResetLimiter(options);
      function reportCancel(streamId, code, kind) {
        clearHeadersDeadline(conn, streamId);
        // A WebTransport stream: the direction the peer gave up on ends, with
        // the application's code (wt_stream's _peerCancelled); the stream
        // object decides what that leaves of it, and is forgotten when it
        // closes. Its two directions are independent — destroying it here
        // reset the one the peer had not touched.
        var wtCancelled = conn._wtStreamObjects[streamId];
        var isWtStream = !!(wtCancelled && wtCancelled._peerCancelled);
        if (isWtStream) {
          wtCancelled._peerCancelled(kind, code);
        } else {
          var hadRequest = streamId in conn.http_streams;
          var cancelled = conn.http_streams[streamId];
          var sendingOpen = !!cancelled && !(cancelled.res && cancelled.res._finished);
          releaseHttpStream(conn, streamId, true);
          // The client reset its request (RESET_STREAM alone — an upload
          // abandoned): the request is aborted above, and with it whatever
          // response was still to come (a tunnel, a WebTransport session, a
          // response not yet ended). Our sending part is reset with it
          // (H3_REQUEST_CANCELLED): left open, nothing would ever end it —
          // the stream never closed, and the client's stream credit with it.
          // A response already ended goes on to arrive.
          if (kind === 'stream_reset' && sendingOpen && conn.quic && conn.quic.resetStream) {
            try { conn.quic.resetStream(Number(streamId), H3_ERR.H3_REQUEST_CANCELLED); } catch (e) {}
          }
          // The client will not read the response (STOP_SENDING): the request
          // is cancelled, so stop reading its stream too (RFC 9114 §4.1.1).
          // Body or trailers still parsed on it would otherwise reach
          // set_http_stream for a request no longer there. Our sending part
          // was already reset by the transport, in answer to the STOP_SENDING.
          //
          // Not for RESET_STREAM: nothing more is read after it anyway, and
          // a client that only cut its request short may still want the
          // response (§4.1.1's early response) — resetting it would discard a
          // reply the handler already wrote.
          if (kind === 'stop_sending' && hadRequest && conn.h3) {
            try { conn.h3.stopReading(streamId, H3_ERR.H3_REQUEST_CANCELLED); } catch (e) {}
          }
        }
        if (cancelReported.has(streamId)) return;
        cancelReported.add(streamId);
        if (cancelReported.size > 4096) cancelReported.delete(cancelReported.values().next().value);
        ev.emit('stream_reset', connHandle, streamId, code);
        // Request streams only: a WebTransport application cancels its own
        // streams as a matter of course (a media frame gone stale), and those
        // reach no request handler.
        if (!isWtStream && resetTooMany()) {
          try { quic.close(H3_ERR.H3_EXCESSIVE_LOAD, 'too many stream resets', true); } catch (e) {}
        }
      }
      h3.on('stream_reset', function (sid, code) { reportCancel(sid, code, 'stream_reset'); });
      h3.on('stop_sending', function (sid, code) { reportCancel(sid, code, 'stop_sending'); });

      // We ended a stream over what the peer sent on it (h3 streamError):
      // whatever request was built for it is aborted, as for a cancel.
      h3.on('stream_error', function (streamId) {
        clearHeadersDeadline(conn, streamId);
        releaseHttpStream(conn, streamId, true);
      });

      // A WebTransport session ended in the HTTP/3 layer — its CONNECT stream
      // finished or was reset — and its streams were reset there. Here, the
      // same end: the session's streams are released (destroyed).
      h3.on('wt_session_closed', function (sessionId) {
        releaseSessionStreams(conn, Number(sessionId));
      });

      h3.on('tunnel_data', function (streamId, data, fin) {
        var stream = conn.http_streams[streamId];
        if (!stream || !stream.tunnel) return;
        if (data && data.byteLength) {
          stream.tunnel.push(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
        }
        if (fin) {
          stream.tunnel.push(null);
          releaseHttpStream(conn, streamId, false);
        }
      });

      // ---- WebTransport stream events ----

      // New WT stream (bidi or uni from client)
      h3.on('wt_stream', function (sessionId, wtStreamId, data, fin, isBidi) {
        var session = conn.http_streams[sessionId];
        // No session to give it to: nothing will read it, so nothing holds
        // its credit either.
        if (!session || !session.req._isWebTransport) { quic.releaseStreamCredit(wtStreamId); return; }

        // Create a Duplex-like stream for the WT stream
        var wtStream = _createWtStream(conn, quic, wtStreamId, sessionId, isBidi ? 'bidi' : 'uni-in');

        // Emit on req
        if (isBidi) {
          _emitOnReq(session.req, 'stream', wtStream);
        } else {
          _emitOnReq(session.req, 'unidirectionalStream', wtStream);
        }

        // If initial data, push to stream
        if (data.byteLength > 0) wtStream._pushData(data);
        // Released at FIN, as 'wt_data' below does — a stream whose whole
        // content came in its first delivery never reaches that handler.
        if (fin) { wtStream._endData(); releaseHttpStream(conn, wtStreamId, false); }
      });

      // Subsequent data on WT stream
      h3.on('wt_data', function (sessionId, wtStreamId, data, fin) {
        var wtStream = conn._wtStreamObjects[wtStreamId];
        if (!wtStream) return;
        if (data.byteLength > 0) wtStream._pushData(data);
        if (fin) { wtStream._endData(); releaseHttpStream(conn, wtStreamId, false); }
      });

      // Datagrams: to the session their Quarter Stream ID names (RFC 9297
      // §2.1), looked up — not searched for among every request on the
      // connection, once per datagram.
      quic.on('datagram', function (rawData) {
        if (!rawData || rawData.byteLength === 0) return;
        var result = readVarInt(rawData, 0);
        if (!result) return;
        // A CONNECT-UDP tunnel's: the rest is Context ID and payload.
        var udpSid = conn.udpByQuarter[result.value];
        if (udpSid !== undefined) {
          var ust = conn.http_streams[udpSid];
          if (ust && ust.udp && ust.udp.sink) ust.udp.sink.datagram(rawData.subarray(result.byteLength));
          return;
        }
        var session = conn.http_streams[conn.wtByQuarter[result.value]];
        if (!session || !session.req._isWebTransport) return;
        // One copy, into a buffer of its own: exact size, byteOffset 0.
        // This was slice() then Buffer.from() — two copies, and a
        // Buffer.from() under 4KB is carved out of Node's shared 8KB
        // pool: a consumer that hands the datagram to another thread
        // (postMessage) then clones the whole 8KB pool for every one.
        var payload = new Uint8Array(rawData.byteLength - result.byteLength);
        payload.set(rawData.subarray(result.byteLength));
        if (session.req._wtDatagrams) session.req._wtDatagrams._push(payload);
        _emitOnReq(session.req, 'datagram', Buffer.from(payload.buffer));
      });
    });
  });


  // ============================================================
  //  Server API
  //  Transport concerns (UDP sockets, demux, connection lifecycle,
  //  shared-port handlePacket/hasConnection) are delegated to the QUIC
  //  server. This layer adds HTTP/3 request events on top.
  // ============================================================

  // ---- Closing, as node:http (see h1_server) ----
  //
  // Idle: no request open on it — before its handshake too, as node:http
  // counts a connection that has not sent a request. GOAWAY, and closed at
  // once (closeAfterGoaway: nothing to wait for); before the handshake,
  // refused (goaway() does that).
  function isIdle(conn) { return Object.keys(conn.http_streams).length === 0; }
  // GOAWAY and CONNECTION_CLOSE together (§5.2 allows closing at once when
  // nothing is in flight): waiting for the GOAWAY's acknowledgement, a
  // client that had gone held the close until its idle timeout.
  function closeIdle(conn) {
    if (!conn.handle) return;
    conn.handle.goaway();
    conn.handle.destroy();
  }
  function closeIdleConnections() {
    for (var conn of conns) if (isIdle(conn)) closeIdle(conn);
  }
  function closeAllConnections() {
    for (var conn of conns) if (conn.handle) conn.handle.destroy();
  }
  // No new connections; GOAWAY on each — the requests in flight finish, then
  // the connection closes (closeAfterGoaway) — and once none is left, the
  // UDP sockets. It closed every connection on the spot: a response being
  // sent was cut off, and its client waited for the rest until a timeout.
  function close(callback) {
    qserver.stopAccepting();
    closingServer = typeof callback === 'function' ? callback : function () {};
    for (var conn of conns) {
      if (isIdle(conn)) closeIdle(conn);
      else if (conn.handle) conn.handle.goaway();
    }
    connGone();
  }
  function connGone() {
    if (!closingServer || conns.size > 0) return;
    var cb = closingServer;
    closingServer = null;
    qserver.close(cb);
  }
  function setLimits(o) {
    if (o.headersTimeout !== undefined) headersTimeout = o.headersTimeout;
    if (o.requestTimeout !== undefined) requestTimeout = o.requestTimeout;
    if (o.maxRequestsPerSocket !== undefined) maxRequests = maxRequestsPerSocket(o.maxRequestsPerSocket);
  }

  return {
    listen: function (p, h, cb) { closingServer = null; return qserver.listen(p, h, cb); },
    close: close,
    closeIdleConnections: closeIdleConnections,
    closeAllConnections: closeAllConnections,
    setLimits: setLimits,
    get connectionCount() { return conns.size; },
    ref: qserver.ref,
    unref: qserver.unref,
    on: function (name, fn) { if (name === 'upgrade') upgradeListeners++; ev.on(name, fn); },
    setTimeout: function () { /* TODO */ },

    /** Feed an incoming UDP packet when running in external-socket mode.
     *  rinfo must be in Node's dgram format: { address, port, family, size }. */
    handlePacket: qserver.handlePacket,

    /** Returns true if the 5-tuple matches an active QUIC connection.
     *  Used by demuxers for routing decisions on shared UDP ports. */
    hasConnection: qserver.hasConnection,

    getTicketKeys: qserver.getTicketKeys,
    setTicketKeys: qserver.setTicketKeys,
    getEchKeys: qserver.getEchKeys,
    setEchKeys: qserver.setEchKeys,
    getValidateAddress: qserver.getValidateAddress,
    setValidateAddress: qserver.setValidateAddress,
    getPendingHandshakes: qserver.getPendingHandshakes,
    getOptions: qserver.getOptions,
    setOptions: qserver.setOptions,
    getResetTokenSecret: qserver.getResetTokenSecret,
    setResetTokenSecret: qserver.setResetTokenSecret,
    getTokenSecret: qserver.getTokenSecret,
    setTokenSecret: qserver.setTokenSecret
  };
}


export { createServer };
