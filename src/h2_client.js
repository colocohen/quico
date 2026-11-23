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
import { EventEmitter } from 'node:events';
import { URL } from 'node:url';
import lemonTls from 'lemon-tls';

import { H2Connection, SOCKET_HIGH_WATER, H2_STREAM_CODES, addSessionOps, toWire, validateSettings, checkRemoteCustomSettings } from './h2.js';
import * as F from './h2_frames.js';
import { buildRequestPseudoHeaders, corkForTick, trailerFields, formatPriority,
         argType, sessionGone, sessionCodeError, pendingCancel, formatAuthority, urlHostname, StreamBase, http2RequestFields } from './http_common.js';
import { withPfx } from './tls_options.js';
import { connectH3 } from './h3_client.js';
import { IncomingMessage } from './streams.js';
import { tlsIdentity } from './agent.js';


// ============================================================
//  HTTP/2 client.
//
//  The pool here is the OPPOSITE shape to h1_client's, and the difference is
//  the whole point of the protocol. HTTP/1.1 carries one request per socket,
//  so its pool maps an origin to a LIST of idle sockets and concurrency means
//  more sockets. HTTP/2 multiplexes, so this pool maps an origin to ONE
//  session and concurrency means more streams on it.
//
//  agent.js already keeps _h1Pool, _h2Pool and _h3Pool as separate maps for
//  exactly this reason. Forcing the two shapes into one abstraction would
//  distort both — and the H3 pool, which is the same shape as this one, is
//  where the coalescing logic worth copying already lives.
// ============================================================


function H2Pool(options) {
  options = options || {};
  var sessions = {};    // "host:port" -> session
  var pending = {};     // "host:port" -> [callbacks] while one is being established

  function key(host, port) { return host + ':' + port; }

  return {
    get: function (host, port) {
      var s = sessions[key(host, port)];
      if (!s) return null;
      if (s.destroyed || s.goingAway) { delete sessions[key(host, port)]; return null; }
      return s;
    },

    set: function (host, port, session) {
      var k = key(host, port);
      sessions[k] = session;
      session.on('close', function () { if (sessions[k] === session) delete sessions[k]; });
    },

    /**
     * Coalesce concurrent connection attempts to one origin.
     *
     * Without this, N requests issued in the same tick each miss the pool and
     * open N sessions to the same host — N handshakes, N HPACK table pairs,
     * zero multiplexing. It is the exact failure the H3 agent already guards
     * against, and it is invisible in any test that issues requests one at a
     * time.
     *
     * Returns false to the first caller, which becomes the lead and MUST call
     * settle(); true to every later one, whose callback fires when the lead
     * finishes and which then simply retries its pool lookup.
     */
    join: function (host, port, cb) {
      var k = key(host, port);
      if (pending[k]) { pending[k].push(cb); return true; }
      pending[k] = [];
      return false;
    },

    settle: function (host, port, session) {
      var k = key(host, port);
      var waiters = pending[k] || [];
      delete pending[k];
      if (session) this.set(host, port, session);
      for (var i = 0; i < waiters.length; i++) {
        try { waiters[i](); } catch (e) { /* a waiter's failure is its own */ }
      }
    },

    destroy: function () {
      for (var k in sessions) { try { sessions[k].destroy(); } catch (e) {} }
      sessions = {};
      pending = {};
    }
  };
}

var globalPool = new H2Pool();


// ============================================================
//  Session — one connection, many streams
// ============================================================

function H2Session(socket, options) {
  var ev = new EventEmitter();
  var h2 = new H2Connection({
    isServer: false,
    // The stream window a response may fill before we return credit: 6 MB,
    // Chrome's. HTTP/2's own default, 64 KB, holds one response to 64 KB a
    // round trip — 5 Mbps over 100 ms — and brings a WINDOW_UPDATE every
    // 32 KB. Credit still goes back only as the application reads
    // (autoWindowUpdate false), so a response nobody reads stops at 6 MB.
    // The server's side keeps HTTP/2's default (h2_server): what it
    // advertises bounds every client's uploads.
    initialWindowSize: options.initialWindowSize != null ? options.initialWindowSize : 6 * 1024 * 1024,
    maxHeaderListSize: options.maxHeaderListSize,
    // node:http2's: entries a server's SETTINGS may carry (32).
    maxSettings: options.maxSettings,
    // node:http2's: refused frames a server may send before the session ends (1000).
    maxSessionInvalidFrames: options.maxSessionInvalidFrames,
    // node:http2's: the longest header block sent (64 KB); past it, 'frameError'.
    maxSendHeaderBlockLength: options.maxSendHeaderBlockLength,
    // node:http2's: the server's stream limit until its SETTINGS says (100).
    peerMaxConcurrentStreams: options.peerMaxConcurrentStreams,
    // node:http2's paddingStrategy (0 none, 1 aligned, 2 max).
    paddingStrategy: options.paddingStrategy,
    // node:http2's `settings` option (connect()), by the RFC's names.
    settings: options.settings ? toWire(options.settings) : null,
    autoWindowUpdate: false,
    // DATA is held while the socket's unsent bytes are over this mark, as on
    // the server (h2_server): the flow-control windows bound what the SERVER
    // may receive, this what we queue for a socket that is not draining.
    // Without it every request body went straight into the socket, whatever
    // the network took — an upload to a slow server sat in memory whole.
    isWriteBlocked: function () { return socket.writableLength >= SOCKET_HIGH_WATER; }
  });
  // node:http2's maxSessionMemory (MB, default 10): what may be queued on the
  // socket. DATA waits (above); what can pile up is everything else — the
  // replies a server provokes (PING and SETTINGS acknowledgements) while it
  // does not read. Past the bound the session goes.
  var maxSessionMemory = (options.maxSessionMemory > 0 ? options.maxSessionMemory : 10) * 1024 * 1024;

  var streams = {};
  var closers = {};      // id -> called (a tick later) once the stream has closed on the wire
  var destroyed = false;
  var goingAway = false;

  h2.on('send', function (data) {
    if (destroyed || !socket.writable) return;
    corkForTick(socket);
    try { socket.write(data); } catch (e) { fail(e); return; }
    if (socket.writableLength > maxSessionMemory) {
      var e = new Error('server is not reading: ' + socket.writableLength + ' bytes queued');
      e.code = 'ERR_HTTP2_SESSION_MEMORY';
      fail(e);
    }
  });
  // DATA was waiting for the socket; it has room again.
  socket.on('drain', function () { if (!destroyed) h2.flushAll(); });

  // A connection error: h2 has queued the GOAWAY that says why; the socket
  // is ended, not destroyed, so it leaves (as h2_server does). It was
  // destroyed with the GOAWAY unsent: the server never learned the reason.
  h2.on('error', function (err) { fail(err, false, true); });

  h2.on('goaway', function (lastStreamId, code, debugData) {
    goingAway = true;
    session.goingAway = true;
    // Streams above lastStreamId were never processed, so they are safe to
    // retry on a fresh connection — that is what the id is FOR.
    for (var id in streams) {
      if (Number(id) > lastStreamId) {
        var e = new Error('stream not processed before GOAWAY');
        e.code = 'ERR_HTTP2_GOAWAY_UNPROCESSED';
        e.retryable = true;
        rejectStream(Number(id), e);
      }
    }
    ev.emit('goaway', lastStreamId, code, debugData);
  });

  h2.on('headers', function (streamId, headers, endStream) {
    var st = streams[streamId];
    if (!st) return;

    var status = parseInt(headers[':status'], 10);

    // 1xx other than 101 is informational: the real response follows on the
    // same stream, so it must not be delivered as THE response.
    if (status >= 100 && status < 200) {
      ev.emit('information', streamId, headers);
      // And on the request, as node:http's 'information' (103 Early Hints).
      if (st.onInformation) {
        var ih = {}, raw = [];
        for (var hn in headers) { if (hn[0] !== ':') { ih[hn] = headers[hn]; raw.push(hn, String(headers[hn])); } }
        st.onInformation({ statusCode: status, statusMessage: '', httpVersion: '2.0', httpVersionMajor: 2, httpVersionMinor: 0, headers: ih, rawHeaders: raw }, headers);
      }
      return;
    }

    var flat = {};
    for (var name in headers) { if (name[0] !== ':') flat[name] = headers[name]; }

    var res = new IncomingMessage({
      httpVersion: '2.0',
      statusCode: status,
      statusMessage: '',      // HTTP/2 has no reason phrase
      headers: flat,
      streamId: streamId,
      socket: socket
    });
    res.on('data', function (chunk) { h2.consume(streamId, chunk.length); });

    st.res = res;
    // The decoded header block and its END_STREAM go with it, for connect()'s
    // streams (connect(), below): node:http2's 'response' (headers, flags).
    st.onResponse(res, headers, !!endStream);
  });

  h2.on('data', function (streamId, chunk) {
    var st = streams[streamId];
    if (st && st.res) st.res._pushData(chunk);
  });

  h2.on('trailers', function (streamId, trailers) {
    var st = streams[streamId];
    if (st && st.res) st.res.trailers = trailers;
    if (st && st.onTrailers) st.onTrailers(trailers);
  });

  h2.on('end', function (streamId) {
    var st = streams[streamId];
    if (!st) return;
    if (st.res) st.res._endData();
    delete streams[streamId];
  });

  // After this tick's 'rst' and 'end', which say how it closed.
  h2.on('stream_close', function (streamId) {
    var f = closers[streamId];
    if (!f) return;
    delete closers[streamId];
    process.nextTick(f);
  });

  // A request's HEADERS not sent — too long (maxSendHeaderBlockLength,
  // FRAME_SIZE_ERROR), or the server's GOAWAY came before its turn: h2
  // reports it, then closes the stream REFUSED_STREAM ('rst' below).
  h2.on('frame_error', function (streamId, type, code) {
    var st = streams[streamId];
    if (!st) return;
    if (code === F.ERROR.FRAME_SIZE_ERROR) st.frameError = true;
    if (st.onFrameError) st.onFrameError(type, code);
  });

  h2.on('rst', function (streamId, code) {
    var e = new Error('stream reset: ' + (F.ERROR_NAME[code] || code));
    e.code = 'ERR_HTTP2_STREAM_ERROR';
    // REFUSED_STREAM specifically means the server never processed it —
    // unless it is ours for HEADERS that could not be sent: the same request
    // fails the same way on any connection.
    var st0 = streams[streamId];
    e.retryable = (code === F.ERROR.REFUSED_STREAM) && !(st0 && st0.frameError);
    // Any other code: the server had the request and ended it — it is the
    // answer, not a failure to reach the server. Not sent again over HTTP/1.1
    // (a POST would have run twice) under "all protocols failed".
    if (!e.retryable) e.requestError = true;
    e.rstCode = code;
    rejectStream(streamId, e);
  });

  socket.on('data', function (chunk) {
    if (destroyed) return;
    try { h2.execute(chunk); } catch (err) { fail(err); }
  });
  socket.on('error', fail);
  // A close is not an error of the session's ('close' without one, below).
  socket.on('close', function () { fail(new Error('socket closed'), true); });

  // The connection lost under a request already sent, before its response:
  // the server may have acted on it. An idempotent one may go again over
  // another protocol (RFC 9110 §9.2.2); any other is not sent twice — the
  // error is the request's (requestError: the unified client tries no other
  // protocol). A POST lost so was sent again over HTTP/1.1.
  var IDEMPOTENT = { GET: 1, HEAD: 1, OPTIONS: 1, TRACE: 1, PUT: 1, DELETE: 1 };
  function sentAndLost(st, err) {
    if (!st.sent || (err && (err.retryable || err.requestError)) || IDEMPOTENT[st.method]) return err;
    var e = new Error('the connection was lost after the request was sent: ' + (err && err.message), { cause: err });
    e.code = (err && err.code) || 'ECONNRESET';
    e.requestError = true;
    return e;
  }

  function rejectStream(streamId, err) {
    var st = streams[streamId];
    if (!st) return;
    delete streams[streamId];
    if (st.res) st.res._abort(err);
    else st.onError(err);
  }

  // `benign`: the connection ended without anything going wrong (its socket
  // closed, destroy()): 'close' carries no error. Otherwise 'close' (err).
  // `linger`: end the socket rather than destroy it, so that what was
  // written last (a GOAWAY) leaves first; destroyed if it is not gone in 1 s.
  function fail(err, benign, linger) {
    if (destroyed) return;
    destroyed = true;
    session.destroyed = true;
    for (var id in streams) {
      var st = streams[id];
      if (st.res) st.res._abort(err);
      else st.onError(sentAndLost(st, err));
    }
    streams = {};
    closers = {};
    if (linger) {
      try { socket.end(); } catch (e) {}
      var t = setTimeout(function () { try { socket.destroy(); } catch (e) {} }, 1000);
      if (t.unref) t.unref();
    } else {
      try { socket.destroy(); } catch (e) {}
    }
    ev.emit('close', benign ? null : err);
  }

  h2.sendPreface();

  var session = {
    destroyed: false,
    goingAway: false,
    on: function (n, f) { ev.on(n, f); return session; },

    request: function (headerList, callbacks) {
      if (destroyed) { callbacks.onError(new Error('session destroyed')); return null; }
      if (goingAway) {
        var e = new Error('session is going away');
        e.retryable = true;
        callbacks.onError(e);
        return null;
      }
      var streamId = h2.nextStreamId();
      streams[streamId] = { onResponse: callbacks.onResponse, onError: callbacks.onError, onInformation: callbacks.onInformation,
                            onFrameError: callbacks.onFrameError || null,
                            onTrailers: callbacks.onTrailers || null, res: null, method: callbacks.method || null, sent: false };
      if (callbacks.onClose) closers[streamId] = callbacks.onClose;
      return streamId;
    },

    sendHeaders: function (streamId, list, endStream) { if (streams[streamId]) streams[streamId].sent = true; h2.sendHeaders(streamId, list, endStream); },
    sendData: function (streamId, data, endStream) { return h2.sendData(streamId, data, endStream); },
    // A request's trailers (node:http's addTrailers): HEADERS with END_STREAM.
    sendTrailers: function (streamId, fields) { h2.sendTrailers(streamId, fields); },
    // A request's new priority, after it went (RFC 9218 §7.1).
    sendPriorityUpdate: function (streamId, p) { h2.sendPriorityUpdate(streamId, p); },
    // Only a stream still open: RST_STREAM on one already closed is not ours
    // to send. Forgotten before the RST goes: h2 reports a reset it sends as
    // it does one it receives ('rst'), and a cancellation of our own read as
    // the server's reset — the response destroyed with an error nobody was
    // listening for.
    cancel: function (streamId, code) {
      delete closers[streamId];
      if (!(streamId in streams)) return;
      delete streams[streamId];
      h2.sendRstStream(streamId, code === undefined ? F.ERROR.CANCEL : code);
    },
    onDrain: function (fn) { h2.on('drain', fn); },
    offDrain: function (fn) { h2.off('drain', fn); },
    ping: function (payload) { h2.sendPing(payload); },
    // h2.js's goaway(code, lastStreamId, debugData) (connect()'s session).
    goaway: function (code, lastStreamId, debugData) { if (!destroyed) h2.goaway(code, lastStreamId, debugData); },
    // With `err`, the streams still open fail with it.
    destroy: function (err, linger) { fail(err || new Error('destroyed'), !err, linger); },
    get socket() { return socket; },
    // The H2Connection itself, for connect()'s session operations
    // (h2.js addSessionOps: settings, ping, windows, state).
    get connection() { return h2; },

    get activeStreams() { return Object.keys(streams).length; }
  };

  return session;
}


// ============================================================
//  request()
// ============================================================

/**
 * request(options, callback) -> an EventEmitter that emits 'response' with an
 * IncomingMessage. The same shape as h1_client's, so the unified client can
 * treat the two interchangeably.
 */
function request(options, callback) {
  options = options || {};

  var hostname = options.hostname || options.host || 'localhost';
  var port = parseInt(options.port, 10) || (options.tls ? 443 : 80);
  var method = String(options.method || 'GET').toUpperCase();
  var pool = options.pool || globalPool;
  // The pool's name for this origin: the host, and over TLS what decides the
  // connection's identity (agent.js tlsIdentity) — one opened without
  // verification, or with another client certificate, carries no other
  // request. The connection itself goes to `hostname`.
  var poolHost = options.tls ? hostname + '#' + tlsIdentity(options) : hostname;

  var ev = new EventEmitter();
  // The body. Written before the stream exists (the connection is still
  // being made), it waits here; once the stream exists, each write goes out
  // as it comes (streaming), and write() answers as a stream's does — false
  // while the send window or the socket is full, then 'drain'. It used to
  // keep the whole body until end() and answer true to every write: an
  // upload was held in memory entire, with nothing telling the writer to
  // slow down.
  var bodyChunks = [];
  var bodyBuffered = 0;
  var needDrain = false;
  var streaming = false;          // HEADERS sent without END_STREAM; DATA follows as written
  var drainHooked = false;
  var BODY_HIGH_WATER = 64 * 1024;   // what write() takes before the stream exists, before saying wait
  var ended = false;
  var settled = false;
  var failed = false;           // settled by a failure (not by the response)
  var timeoutTimer = null;
  var session = null;
  var streamId = null;
  var sent = false;
  // 0-RTT (TLS early data, RFC 8446 §4.2.10): with earlyData and a session
  // whose ticket allows it, a GET, HEAD or OPTIONS goes in the first flight
  // — the preface, SETTINGS and HEADERS with the ClientHello. Not taken, the
  // TLS layer sends them again after the handshake; answered 425 (RFC 8470),
  // the request fails retryable, and the unified client sends it again on
  // the connection, now up. this.earlyData: 'accepted', 'rejected' or null.
  // Decided when a connection is made (connect): the session is read there,
  // so a request on a pooled session uses none up (the unified client's is
  // taken from its agent on that read).
  var wantEarly = false;
  var sentEarly = false;
  ev.earlyData = null;
  var reqTrailers = null;

  function fail(err) {
    if (settled) return;
    settled = true;
    failed = true;
    clearTimer();
    ev.emit('error', err);
  }
  function clearTimer() { if (timeoutTimer) { clearTimeout(timeoutTimer); timeoutTimer = null; } }

  function connect() {
    var existing = pool.get(poolHost, port);
    if (existing) { start(existing); return; }

    if (pool.join(poolHost, port, function () {
      // The lead settled; retry from the top. On success the pool lookup now
      // hits and we multiplex on its session; on failure we become the next
      // lead — a serial retry, never a thundering herd.
      if (!settled) connect();
    })) return;

    var socket, earlySession = null;
    var sessionNow = options.session;
    wantEarly = options.earlyData === true && !!sessionNow && !!options.tls && (method === 'GET' || method === 'HEAD' || method === 'OPTIONS');
    var onReady = function () {
      var s = new H2Session(socket, options);
      pool.settle(poolHost, port, s);
      start(s);
    };

    try {
      if (options.tls) {
        socket = options.tls.connect({
          host: hostname,
          port: port,
          servername: options.servername || hostname,
          // ALPN is not optional for h2 over TLS (RFC 9113 §3.2): a server
          // that does not select 'h2' is not speaking it, and sending the
          // preface anyway would be talking past it.
          ALPNProtocols: ['h2'],
          rejectUnauthorized: options.rejectUnauthorized !== false,
          ca: options.ca,
          // A client certificate, for a server that asks (tls.connect's names).
          key: options.key, cert: options.cert, passphrase: options.passphrase,
          // A saved session to resume with (tls.connect's `session`).
          session: sessionNow,
          // The server's certificate chain may come compressed (RFC 8879):
          // brotli, zstd, zlib — as the HTTP/3 client and the browsers offer.
          certificateCompression: true,
          // The server's stapled OCSP response ('OCSPResponse').
          requestOCSP: options.requestOCSP === true,
          // Encrypted Client Hello: the server's ECHConfigList, or GREASE ECH.
          ech: options.ech || undefined,
          echGrease: options.echGrease === true,
          // The key-exchange groups to offer (tls.connect's ecdhCurve).
          ecdhCurve: options.ecdhCurve,
          sigalgs: options.sigalgs,
          earlyData: wantEarly,
          // TCP_NODELAY, as node:http's client sets it (its noDelay, default true).
          // Without it Nagle held a small write — a request's HEADERS behind the
          // preface, a WINDOW_UPDATE, a body after its head — until the last one
          // was acknowledged, and the server's delayed ACK made that up to 40 ms:
          // 3000 small HTTP/2 requests took 2.8 s instead of 0.5.
          noDelay: options.noDelay !== false
        }, function () {
          if (socket.alpnProtocol !== 'h2') {
            pool.settle(poolHost, port, null);
            fail(new Error('server did not negotiate h2 (got ' +
                           JSON.stringify(socket.alpnProtocol) + ')'));
            try { socket.destroy(); } catch (e) {}
            return;
          }
          // Started early: the session is the pool's now that it is up —
          // not before, or a request that is not safe to replay would ride
          // in the early data.
          if (earlySession) { pool.settle(poolHost, port, earlySession); return; }
          onReady();
        });
        // The ClientHello is built a turn after connect(): by then the socket
        // knows whether it offered early data (the ticket allows it).
        if (wantEarly) setTimeout(function () {
          if (settled || earlySession || !socket || socket.destroyed || socket.isEarlyData !== true) return;
          sentEarly = true;
          earlySession = new H2Session(socket, options);
          start(earlySession);
        }, 0);
      } else {
        // h2c with prior knowledge (§3.3): no ALPN, the preface speaks for us.
        socket = net.connect({ host: hostname, port: port, noDelay: options.noDelay !== false }, onReady);
      }
      // The request that opened the connection has the TLS socket's
      // 'session' events — each a session to resume with, as Node's socket
      // gives them. A request on a pooled session sees no handshake.
      if (options.tls) socket.on('session', function (s) { ev.emit('session', s); });
      if (options.tls) socket.on('OCSPResponse', function (r) { ev.emit('OCSPResponse', r); });
    } catch (err) {
      pool.settle(poolHost, port, null);
      fail(err);
      return;
    }

    socket.on('error', function (err) {
      pool.settle(poolHost, port, null);
      fail(err);
    });
  }

  function start(s) {
    if (settled) return;
    // options.onReady (the unified client) may turn the request down here —
    // another protocol was ready first and carries it: no stream is opened,
    // and 'superseded' says so; the session stays in the pool.
    if (typeof options.onReady === 'function' && !options.onReady()) {
      settled = true;
      process.nextTick(function () { ev.emit('superseded'); });
      return;
    }
    session = s;
    streamId = session.request(null, {
      method: method,
      onInformation: function (info) { ev.emit('information', info); },
      onResponse: function (res) {
        if (settled) return;
        if (sentEarly) {
          var st = res.socket && res.socket.earlyDataStatus ? res.socket.earlyDataStatus : (session && session.socket ? session.socket.earlyDataStatus : null);
          ev.earlyData = st === 'accepted' ? 'accepted' : 'rejected';
          if (res.statusCode === 425) {
            var tooEarly = new Error('425 Too Early: the request is sent again after the handshake');
            tooEarly.code = 'ERR_HTTP_TOO_EARLY';
            tooEarly.retryable = true;
            try { res.resume(); } catch (e) {}
            fail(tooEarly);
            return;
          }
        }
        settled = true;
        clearTimer();
        ev.emit('response', res);
        if (typeof callback === 'function') { callback(res); callback = null; }
      },
      onError: fail
    });
    if (streamId === null) return;
    if (ended) { sendRequest(); return; }
    // Written while connecting: out now, as a stream.
    if (bodyChunks.length) {
      var held = bodyChunks; bodyChunks = []; bodyBuffered = 0;
      var more = true;
      for (var i = 0; i < held.length; i++) more = streamChunk(held[i]);
      if (more && needDrain) { needDrain = false; ev.emit('drain'); }
    }
  }

  function requestHeaderList(contentLength) {
    var headers = Object.assign({}, options.headers);
    if (contentLength !== null && headers['content-length'] === undefined &&
        headers['Content-Length'] === undefined) {
      headers['content-length'] = String(contentLength);
    }
    return buildRequestPseudoHeaders({
      method: method,
      scheme: options.tls ? 'https' : 'http',
      hostname: hostname,
      port: port,
      path: options.path || '/',
      headers: headers
    });
  }

  // One chunk of a streamed body: HEADERS first if not yet (without a
  // content-length — HTTP/2 frames the body itself, RFC 9113 §8.1.1), then
  // DATA. Returns whether more may be written now.
  function streamChunk(chunk) {
    try {
      if (!streaming) { streaming = true; sent = true; session.sendHeaders(streamId, requestHeaderList(null), false); }
      var more = session.sendData(streamId, chunk, false);
      if (!more) waitDrain();
      return more;
    } catch (err) { fail(err); return false; }
  }

  // The stream's send window (or the socket) has room again: 'drain'.
  function waitDrain() {
    needDrain = true;
    if (drainHooked) return;
    drainHooked = true;
    var onDrain = function (id) {
      if (id !== streamId) return;
      session.offDrain(onDrain);
      drainHooked = false;
      if (needDrain) { needDrain = false; ev.emit('drain'); }
    };
    session.onDrain(onDrain);
  }

  // The whole request at once — ended before the stream existed, or with
  // nothing streamed: a content-length, as before, and the body (if any).
  function sendRequest() {
    if (sent || streamId === null) return;
    sent = true;
    var body = bodyChunks.length ? Buffer.concat(bodyChunks) : null;
    bodyChunks = []; bodyBuffered = 0;
    try {
      session.sendHeaders(streamId, requestHeaderList(body ? body.length : null), !body && !reqTrailers);
      if (body) session.sendData(streamId, body, !reqTrailers);
      if (reqTrailers) session.sendTrailers(streamId, reqTrailers);
    } catch (err) {
      fail(err);
    }
  }

  var clientReq = {
    on: function (n, f) { ev.on(n, f); return clientReq; },
    once: function (n, f) { ev.once(n, f); return clientReq; },
    emit: function () { ev.emit.apply(ev, arguments); return clientReq; },

    write: function (chunk, encoding) {
      // The response may come before the request has all gone (an early
      // answer to an upload, a bidirectional stream): the body goes on, as
      // on node:http2. It was refused once the response had begun — a
      // streamed body stopped at its first write after the response, and
      // its end() then closed the stream short.
      if (ended || failed || (settled && streamId === null)) return false;
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding || 'utf8');
      if (!chunk || chunk.length === 0) return !needDrain;
      if (streamId === null) {
        bodyChunks.push(chunk);
        bodyBuffered += chunk.length;
        if (bodyBuffered >= BODY_HIGH_WATER) { needDrain = true; return false; }
        return true;
      }
      return streamChunk(chunk);
    },

    // RFC 9218: the `priority` header while HEADERS have not gone, a
    // PRIORITY_UPDATE after.
    setPriority: function (p) {
      if (sent || streaming) { if (session && streamId !== null && !settled) session.sendPriorityUpdate(streamId, p); return; }
      var h = options.headers || (options.headers = {});
      for (var k in h) if (k.toLowerCase() === 'priority') delete h[k];
      var v = formatPriority(p);
      if (v) h.priority = v;
    },

    // `trailers` (node:http's addTrailers, through the unified client): a
    // HEADERS frame after the body, with END_STREAM (RFC 9113 §8.1).
    end: function (chunk, encoding, trailers) {
      if (ended) return clientReq;
      if (encoding && typeof encoding === 'object') { trailers = encoding; encoding = undefined; }
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding || 'utf8');
      reqTrailers = trailerFields(trailers);
      if (streaming) {
        // The body went as it was written: its last piece, and END_STREAM —
        // on the trailers when there are some.
        ended = true;
        try {
          if (reqTrailers) {
            if (chunk && chunk.length) session.sendData(streamId, chunk, false);
            session.sendTrailers(streamId, reqTrailers);
          } else session.sendData(streamId, chunk && chunk.length ? chunk : null, true);
        } catch (err) { fail(err); }
        return clientReq;
      }
      if (chunk && chunk.length) { bodyChunks.push(chunk); bodyBuffered += chunk.length; }
      ended = true;
      if (streamId !== null) sendRequest();
      return clientReq;
    },

    abort: function () {
      if (session && streamId !== null) session.cancel(streamId);
      fail(new Error('Request aborted'));
    },
    destroy: function (err) {
      if (session && streamId !== null) session.cancel(streamId);
      fail(err || new Error('Request destroyed'));
    },

    // 'timeout' after `ms` without a response (as h1_client's): one timer,
    // replaced by the next call and cleared when the request settles. Each
    // call added a timer, none was cleared, and 'timeout' came after the
    // response too.
    setTimeout: function (ms, cb) {
      if (cb) ev.once('timeout', cb);
      clearTimer();
      if (ms > 0 && !settled) {
        timeoutTimer = setTimeout(function () { timeoutTimer = null; ev.emit('timeout'); }, ms);
        if (timeoutTimer.unref) timeoutTimer.unref();
      }
      return clientReq;
    },

    get session() { return session; },
    // 0-RTT: 'accepted', 'rejected', or null (not sent early).
    get earlyData() { return ev.earlyData; }
  };

  process.nextTick(function () { if (!settled) connect(); });

  return clientReq;
}


function get(options, callback) {
  var req = request(Object.assign({}, options, { method: 'GET' }), callback);
  req.end();
  return req;
}


// ============================================================
//  connect(): node:http2's client session API.
//
//  quico.request() pools connections and hides them: a request goes on
//  whatever connection the agent has, and comes back as a node:http
//  IncomingMessage. node:http2's connect() is the other shape — the caller
//  owns one connection, opens streams on it, and sees the connection's own
//  life: 'connect', 'goaway', 'close', close(), destroy(). Code written for
//  node:http2 (gRPC clients, proxies) is written against that shape.
//
//  This is that API over the same H2Session the pool uses (h2_client.js) —
//  no second HTTP/2 client. The session here is not the pool's: it is the
//  caller's, as node:http2's is, and closes when the caller says.
//
//  Names, events, argument checks and error codes are node:http2's
//  (lib/internal/http2/core.js), so the same client code runs on either.
// ============================================================


var NO_ERROR = F.ERROR.NO_ERROR;
var INTERNAL_ERROR = F.ERROR.INTERNAL_ERROR;
var CANCEL = F.ERROR.CANCEL;

// node:http2: a request with one of these methods has no body, and its
// HEADERS ends the stream unless options.endStream says otherwise.
var NO_PAYLOAD = { GET: 1, HEAD: 1, DELETE: 1 };

// node:http2's flags on 'response' / 'headers' / 'trailers'.
var FLAG_END_STREAM = 0x1;
var FLAG_END_HEADERS = 0x4;

function nodeError(Ctor, code, message) {
  var e = new Ctor(message);
  e.code = code;
  return e;
}

// A decoded header block as node:http2 hands it to the application: the
// status a number, a repeated field joined with ', ' (set-cookie stays a list).
function headersObject(headers) {
  var out = Object.create(null);
  for (var name in headers) {
    var v = headers[name];
    if (name === ':status') out[name] = parseInt(v, 10);
    else if (Array.isArray(v)) out[name] = name === 'set-cookie' ? v.slice() : v.join(', ');
    else out[name] = v;
  }
  return out;
}

function rstError(code) {
  var e = new Error('Stream closed with error code ' + ('NGHTTP2_' + (F.ERROR_NAME[code] || 'UNKNOWN_CODE')));
  e.code = 'ERR_HTTP2_STREAM_ERROR';
  return e;
}


// ============================================================
//  The stream — node:http2's ClientHttp2Stream
// ============================================================

class ClientStream extends StreamBase {
  constructor(session, list, method, endStream, waitForTrailers) {
    super(session, H2_STREAM_CODES);
    this.id = undefined;
    this.sentHeaders = headersObject(Object.fromEntries(list.map(function (f) { return [f[0], f[1]]; })));
    this._list = list;
    this._method = method;
    // END_STREAM on the HEADERS — not when the end is the trailers'.
    this._headersEnd = endStream && !waitForTrailers;
    this._waitTrailers = !!waitForTrailers;
    this._h2 = null;
    this._res = null;
    this._whenStarted = [];         // writes waiting for the stream to exist
    this._wantRead = false;
    this._sessCode = 0;             // the session's code, when it ended under the stream
  }

  get pending() { return this.id === undefined; }
  get headersSent() { return true; }

  // The connection is up: the stream is opened and its HEADERS go.
  _start(h2) {
    if (this.destroyed || this.closed) return;
    var self = this;
    var id = h2.request(null, {
      method: this._method,
      onResponse: function (res, headers, endStream) { self._onResponse(res, headers, endStream); },
      onInformation: function (info, headers) {
        self._touch();
        self.emit('headers', headersObject(headers), FLAG_END_HEADERS);
      },
      onTrailers: function (trailers) {
        self._touch();
        self.emit('trailers', headersObject(trailers), FLAG_END_HEADERS | FLAG_END_STREAM);
      },
      onError: function (err) { self._onError(err); },
      // node:http2's 'frameError' (type, code, id): HEADERS too long to send.
      onFrameError: function (type, code) { self.emit('frameError', type, code, self.id); },
      // Closed on the wire, both ways (or reset: _onError said so first).
      onClose: function () { self._gone(NO_ERROR); }
    });
    if (id === null || this.destroyed) return;
    this._h2 = h2;
    this.id = id;
    try { h2.sendHeaders(id, this._list, this._headersEnd); }
    catch (err) { this.destroy(err); return; }
    if (this.destroyed || this.closed) return;   // refused (frameError)
    this.emit('ready');
    // What was written while connecting goes a turn later, as node:http2's:
    // the HEADERS of every request made meanwhile go first.
    var self2 = this;
    process.nextTick(function () {
      var waiting = self2._whenStarted;
      self2._whenStarted = [];
      for (var i = 0; i < waiting.length; i++) waiting[i]();
    });
  }

  _onResponse(res, headers, endStream) {
    var self = this;
    this._res = res;
    this._touch();
    this.emit('response', headersObject(headers), FLAG_END_HEADERS | (endStream ? FLAG_END_STREAM : 0));
    res.on('data', function (chunk) { self._touch(); if (!self.push(chunk)) res.pause(); });
    res.on('end', function () { self.push(null); });
    res.on('error', function (err) { self._onError(err); });
    if (!this._wantRead) res.pause();
  }

  // The stream ended other than by its END_STREAMs: RST_STREAM from the
  // server, or its connection gone.
  _onError(err) {
    if (this.destroyed) return;
    this._h2 = null;
    if (err && err.rstCode !== undefined) {
      // RST_STREAM NO_ERROR: the server needs no more of the request (RFC
      // 9113 §8.1) — not a failure; what came of the response stands.
      if (err.rstCode === NO_ERROR && !this._readableState.ended) this.push(null);
      // node's rules from here: CANCEL is no error ('aborted' covers it).
      this._gone(err.rstCode);
      return;
    }
    this.destroy(err);
  }

  // A clean close: the reads end with the response's own end.
  _endReads() {
    if (!this._res) { this.push(null); return; }
    this._res.resume();
  }

  _read() {
    this._wantRead = true;
    if (this._res) this._res.resume();
  }

  _write(chunk, encoding, cb) {
    var self = this;
    if (this.id === undefined) { this._whenStarted.push(function () { self._write(chunk, encoding, cb); }); return; }
    if (this.closed) { cb(); return; }
    if (!this._h2) { cb(nodeError(Error, 'ERR_STREAM_WRITE_AFTER_END', 'write after end')); return; }
    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    this._touch();
    var more;
    try { more = this._h2.sendData(this.id, chunk, false); }
    catch (err) { cb(err); return; }
    if (more) { cb(); return; }
    var h2 = this._h2, id = this.id;
    var onDrain = function (sid) {
      if (sid !== id) return;
      h2.offDrain(onDrain);
      cb();
    };
    h2.onDrain(onDrain);
  }

  _final(cb) {
    var self = this;
    if (this.id === undefined && !this.closed) { this._whenStarted.push(function () { self._final(cb); }); return; }
    if (this._headersEnd || !this._h2 || this.closed) { cb(); return; }
    if (this._waitTrailers) { this._wantTrailers(); cb(); return; }
    try { this._h2.sendData(this.id, null, true); cb(); }
    catch (err) { cb(err); }
  }

  _sendRst(code) {
    if (this._h2 && this.id !== undefined) { try { this._h2.cancel(this.id, code); } catch (e) {} }
    this._h2 = null;
  }
  _sendTrailers(list) {
    if (!this._h2) return;
    if (list.length) this._h2.sendTrailers(this.id, list);
    else this._h2.sendData(this.id, null, true);
  }
  _streamState() { return this._h2 && this.id !== undefined ? this._h2.connection.getStreamInfo(this.id) : null; }
  _sessionCode() { return this._sessCode; }
  _release() {
    this._h2 = null;
    var session = this.session;
    if (session) session._streamGone(this);
  }

  // Its session ended: with `err`, and `code` the stream's (its GOAWAY's, or
  // the session's).
  _closeWith(err, code) {
    if (this.destroyed) return;
    this._h2 = null;
    this._sessCode = code;
    this.destroy(err || undefined);
  }
}


// ============================================================
//  The session — node:http2's ClientHttp2Session
// ============================================================

class ClientSession extends EventEmitter {
  constructor(url, options) {
    super();
    this._url = url;
    this._options = options;
    this._tls = url.protocol === 'https:';
    this._h2 = null;
    this._socket = null;
    this._streams = new Set();
    this._pending = [];         // requests made while connecting
    this.connecting = true;
    this._goaway = null;        // the last GOAWAY received: { code, lastStreamId }
    this.closed = false;
    this.destroyed = false;
    this.type = 1;              // NGHTTP2_SESSION_CLIENT
    var self = this;
    // settings(), ping(), setLocalWindowSize(), state, setTimeout() — the
    // server's session has them too (h2.js addSessionOps).
    this._ops = addSessionOps(this, {
      h2: function () { return self._h2 ? self._h2.connection : null; },
      destroyed: function () { return self.destroyed; },
      connecting: function () { return self.connecting; },
      closed: function () { return self.closed; },
      whenUp: function (fn) { self.once('connect', fn); },
      fail: function (err) { self.destroy(err); },
      isServer: false,
      encrypted: function () { return self._tls; },
      // node:http2's: the TLS servername (the address when there is none) and the port.
      originBase: function () {
        var sk = self._socket || {};
        var host = sk.servername || (sk.remoteFamily === 'IPv6' ? '[' + sk.remoteAddress + ']' : sk.remoteAddress);
        return 'https://' + host + (sk.remotePort != null ? ':' + sk.remotePort : '');
      },
      options: options
    });
    this._connect();
  }

  get encrypted() { return this._tls; }
  get alpnProtocol() { return this._tls ? (this._socket && this._socket.alpnProtocol) || 'h2' : 'h2c'; }
  get socket() { return this._socket; }

  _connect() {
    var self = this;
    var url = this._url, o = this._options;
    var host = urlHostname(url.hostname);
    var port = parseInt(url.port, 10) || (this._tls ? 443 : 80);
    var socket;
    var onUp = function () {
      if (self.destroyed) return;
      self._up(socket);
    };
    try {
      if (this._tls) {
        socket = lemonTls.connect(withPfx(Object.assign({}, o, {
          host: host,
          port: port,
          // SNI is a host name; an address has none (RFC 6066 §3).
          servername: o.servername !== undefined ? o.servername : (net.isIP(host) ? undefined : host),
          ALPNProtocols: ['h2'],
          rejectUnauthorized: o.rejectUnauthorized !== false,
          certificateCompression: true,
          noDelay: o.noDelay !== false
        })), onUp);
      } else {
        // h2c with prior knowledge (RFC 9113 §3.3).
        socket = net.connect({ host: host, port: port, noDelay: o.noDelay !== false }, onUp);
      }
    } catch (err) {
      process.nextTick(function () { self._fail(err); });
      return;
    }
    this._socket = socket;
    socket.on('error', function (err) { if (self.connecting) self._fail(err); });
    if (this._tls) socket.on('session', function (s) { self.emit('session', s); });
  }

  _up(socket) {
    var self = this;
    var h2 = new H2Session(socket, this._options);
    this._h2 = h2;
    this.connecting = false;
    this._ops.attach(h2.connection);
    h2.on('goaway', function (lastStreamId, code, debugData) {
      // The same GOAWAY again — a server's graceful close sends one, then
      // another as it ends — is no news. node:http2 never reports it: its
      // session has gone with its last stream before the second is read.
      // A lower last-stream-id, or another code, is reported.
      var prev = self._goaway;
      if (prev && prev.code === code && prev.lastStreamId === lastStreamId) return;
      self._goaway = { code: code, lastStreamId: lastStreamId };
      self.emit('goaway', code, lastStreamId, debugData || Buffer.alloc(0));
      // node:http2: GOAWAY NO_ERROR, the session winds down (close());
      // any other code, it is over — an error of the server's, answered
      // with NO_ERROR, for nothing went wrong on this side.
      if (code === NO_ERROR) self.close();
      else self.destroy(sessionCodeError(code), NO_ERROR);
    });
    h2.on('close', function (err) {
      // The connection went by itself: its socket closed, or failed.
      if (self.destroyed) return;
      self._end(err || null, err ? INTERNAL_ERROR : NO_ERROR, false);
    });
    this.emit('connect', this, socket);
    var pending = this._pending;
    this._pending = [];
    for (var i = 0; i < pending.length; i++) pending[i]._start(h2);
    if (this.closed) this._goawayAndMaybeEnd();
  }

  // Not connected, and never will be.
  _fail(err) {
    if (this.destroyed) return;
    var pending = this._pending;
    this._pending = [];
    for (var i = 0; i < pending.length; i++) {
      pending[i]._closeWith(pendingCancel(err), CANCEL);
    }
    this._end(err, CANCEL, false);
  }

  // The end of the session, once: its streams with it (with `err` and `code`),
  // then 'error' (with an error) and 'close'.
  _end(err, code, sendGoaway) {
    if (this.destroyed) return;
    this.destroyed = true;
    this.connecting = false;
    this._ops.end();
    var streams = Array.from(this._streams).concat(this._pending);
    this._pending = [];
    // A stream's code is the GOAWAY's the server sent, when it sent one, and
    // the session's otherwise (node:http2's rstCode).
    var streamCode = this._goaway ? this._goaway.code : code;
    // A stream still waiting for the connection is cancelled, as node:http2's
    // pending streams are (ERR_HTTP2_STREAM_CANCEL, with the cause).
    for (var i = 0; i < streams.length; i++) {
      if (streams[i].id === undefined && !streams[i].destroyed) streams[i]._closeWith(pendingCancel(err), streamCode);
      else streams[i]._closeWith(err, streamCode);
    }
    this._streams.clear();
    var self = this;
    var reported = false;
    var report = function () {
      if (reported) return;
      reported = true;
      // A turn of the event loop, not a tick: the socket's own events go first.
      setImmediate(emitEnd);
    };
    var h2 = this._h2, socket = this._socket;
    if (h2) {
      if (sendGoaway) { try { h2.goaway(code); } catch (e) {} }
      // 'error' and 'close' once what was written has gone (the GOAWAY), as
      // node:http2's come after its socket's end().
      if (socket && !socket.destroyed) {
        socket.once('finish', report);
        socket.once('close', report);
        var t = setTimeout(report, 1000);
        if (t.unref) t.unref();
      }
      h2.destroy(err || null, true);
    } else if (socket) {
      try { socket.destroy(); } catch (e) {}
    }
    if (!h2 || !socket || socket.destroyed) report();
    function emitEnd() {
      if (err) self.emit('error', err);
      self.emit('close');
    }
  }

  _streamGone(stream) {
    this._streams.delete(stream);
    var i = this._pending.indexOf(stream);
    if (i >= 0) this._pending.splice(i, 1);
    if (this.closed && !this.destroyed && this._streams.size === 0 && this._pending.length === 0) {
      var self = this;
      process.nextTick(function () { if (self._streams.size === 0) self._end(null, NO_ERROR, false); });
    }
  }

  _goawayAndMaybeEnd() {
    if (this._h2) { try { this._h2.goaway(NO_ERROR); } catch (e) {} }
    if (this._streams.size === 0 && this._pending.length === 0) this._end(null, NO_ERROR, false);
  }

  request(headers, options) {
    if (headers === undefined || headers === null) headers = {};
    else if (typeof headers !== 'object' || Array.isArray(headers)) throw argType('headers', 'object', headers);
    if (options !== undefined && (options === null || typeof options !== 'object')) throw argType('options', 'object', options);
    options = options || {};

    var authority = formatAuthority(urlHostname(this._url.hostname), this._url.port, this._tls ? 443 : 80);
    var fields = http2RequestFields(headers, this._url.protocol.slice(0, -1), authority);
    var list = fields.list, method = fields.method;

    var endStream = options.endStream !== undefined ? !!options.endStream : NO_PAYLOAD[method] === 1;
    var stream = new ClientStream(this, list, method, endStream, !!options.waitForTrailers);

    // node:http2: a request on a session that has ended, or is ending, is a
    // stream that fails — not a throw.
    if (this.destroyed || this.closed) {
      var e = this.destroyed ? sessionGone() : nodeError(Error, 'ERR_HTTP2_GOAWAY_SESSION', 'New streams cannot be created after receiving a GOAWAY');
      process.nextTick(function () { stream.destroy(e); });
      return stream;
    }
    this._streams.add(stream);
    if (endStream) stream.end();
    if (this._h2) stream._start(this._h2);
    else this._pending.push(stream);
    return stream;
  }

  // node:http2's close(callback): GOAWAY (NO_ERROR), no new streams, and the
  // session ends with its last stream — then 'close', and the callback.
  close(callback) {
    if (this.closed || this.destroyed) return;
    this.closed = true;
    if (typeof callback === 'function') this.once('close', callback);
    if (!this.connecting) this._goawayAndMaybeEnd();
  }

  // node:http2's destroy(error, code): at once, GOAWAY with `code` —
  // INTERNAL_ERROR with an error, NO_ERROR without; a number in place of
  // the error is the code (an error of its own unless NO_ERROR).
  destroy(error, code) {
    if (this.destroyed) return;
    if (typeof error === 'number') {
      code = error;
      error = code !== NO_ERROR ? sessionCodeError(code) : undefined;
    }
    if (code === undefined) code = error ? INTERNAL_ERROR : NO_ERROR;
    this._end(error || null, code, true);
  }

  // node:http2's goaway(code, lastStreamId, opaqueData), with its checks.
  goaway(code, lastStreamId, opaqueData) {
    if (this.destroyed) throw sessionGone();
    if (code !== undefined && typeof code !== 'number') throw argType('code', 'number', code);
    if (lastStreamId !== undefined && typeof lastStreamId !== 'number') throw argType('lastStreamId', 'number', lastStreamId);
    if (opaqueData !== undefined && !ArrayBuffer.isView(opaqueData)) throw argType('opaqueData', 'Buffer, TypedArray, or DataView', opaqueData);
    if (!this._h2) return;
    var data = opaqueData && Buffer.from(opaqueData.buffer, opaqueData.byteOffset, opaqueData.byteLength);
    this._h2.goaway(code === undefined ? NO_ERROR : code, lastStreamId, data);
  }

  // The socket keeps the process alive, as node:http2's does.
  ref() { if (this._socket && this._socket.ref) this._socket.ref(); }
  unref() { if (this._socket && this._socket.unref) this._socket.unref(); }
}


/**
 * connect(authority[, options][, listener]) — node:http2's: a session to
 * `authority` ('https://host:port', or 'http://' for h2c with prior
 * knowledge; a URL or { protocol, hostname, port } too). `listener` is a
 * 'connect' listener. The options are tls.connect's (ca, servername,
 * rejectUnauthorized, key/cert, session, ...) and H2Session's
 * (initialWindowSize, maxHeaderListSize, maxSessionMemory).
 */
function connect(authority, options, listener) {
  if (typeof options === 'function') { listener = options; options = undefined; }
  if (options !== undefined && (options === null || typeof options !== 'object')) throw argType('options', 'object', options);
  options = Object.assign({}, options);
  if (options.settings !== undefined) {
    if (options.settings === null || typeof options.settings !== 'object') throw argType('options.settings', 'object', options.settings);
    validateSettings(options.settings);
  }
  checkRemoteCustomSettings(options.remoteCustomSettings);
  var url;
  if (typeof authority === 'string') url = new URL(authority);
  else if (authority instanceof URL) url = authority;
  else if (authority && typeof authority === 'object') {
    var proto = authority.protocol || 'https:';
    var h = authority.hostname || authority.host || 'localhost';
    if (h.indexOf(':') >= 0 && h[0] !== '[') h = '[' + h + ']';
    url = new URL(proto + '//' + h + (authority.port ? ':' + authority.port : ''));
  } else throw argType('authority', 'string or URL', authority);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw nodeError(Error, 'ERR_HTTP2_UNSUPPORTED_PROTOCOL', 'protocol "' + url.protocol + '" is unsupported.');
  }
  // { http3: true }: the same session API over HTTP/3 (h3_client) — QUIC,
  // so https: only.
  if (options.http3 === true) {
    if (url.protocol !== 'https:') throw nodeError(Error, 'ERR_HTTP2_UNSUPPORTED_PROTOCOL', 'protocol "' + url.protocol + '" is unsupported over HTTP/3.');
    return connectH3(url, options, listener);
  }
  var session = new ClientSession(url, options);
  if (typeof listener === 'function') session.once('connect', listener);
  return session;
}



export { request, get, H2Pool, H2Session, globalPool, connect, ClientSession, ClientStream };
