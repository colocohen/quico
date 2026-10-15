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

import { H2Connection, SOCKET_HIGH_WATER } from './h2.js';
import * as F from './h2_frames.js';
import { buildRequestPseudoHeaders, corkForTick, trailerFields, formatPriority } from './http_common.js';
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

  h2.on('error', function (err) { fail(err); });

  h2.on('goaway', function (lastStreamId, code) {
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
    ev.emit('goaway', lastStreamId, code);
  });

  h2.on('headers', function (streamId, headers) {
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
        st.onInformation({ statusCode: status, statusMessage: '', httpVersion: '2.0', httpVersionMajor: 2, httpVersionMinor: 0, headers: ih, rawHeaders: raw });
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
    st.onResponse(res);
  });

  h2.on('data', function (streamId, chunk) {
    var st = streams[streamId];
    if (st && st.res) st.res._pushData(chunk);
  });

  h2.on('trailers', function (streamId, trailers) {
    var st = streams[streamId];
    if (st && st.res) st.res.trailers = trailers;
  });

  h2.on('end', function (streamId) {
    var st = streams[streamId];
    if (!st) return;
    if (st.res) st.res._endData();
    delete streams[streamId];
  });

  h2.on('rst', function (streamId, code) {
    var e = new Error('stream reset: ' + (F.ERROR_NAME[code] || code));
    e.code = 'ERR_HTTP2_STREAM_ERROR';
    // REFUSED_STREAM specifically means the server never processed it.
    e.retryable = (code === F.ERROR.REFUSED_STREAM);
    // Any other code: the server had the request and ended it — it is the
    // answer, not a failure to reach the server. Not sent again over HTTP/1.1
    // (a POST would have run twice) under "all protocols failed".
    if (!e.retryable) e.requestError = true;
    rejectStream(streamId, e);
  });

  socket.on('data', function (chunk) {
    if (destroyed) return;
    try { h2.execute(chunk); } catch (err) { fail(err); }
  });
  socket.on('error', fail);
  socket.on('close', function () { fail(new Error('socket closed')); });

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

  function fail(err) {
    if (destroyed) return;
    destroyed = true;
    session.destroyed = true;
    for (var id in streams) {
      var st = streams[id];
      if (st.res) st.res._abort(err);
      else st.onError(sentAndLost(st, err));
    }
    streams = {};
    try { socket.destroy(); } catch (e) {}
    ev.emit('close');
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
      streams[streamId] = { onResponse: callbacks.onResponse, onError: callbacks.onError, onInformation: callbacks.onInformation, res: null, method: callbacks.method || null, sent: false };
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
    cancel: function (streamId) {
      if (!(streamId in streams)) return;
      delete streams[streamId];
      h2.sendRstStream(streamId, F.ERROR.CANCEL);
    },
    onDrain: function (fn) { h2.on('drain', fn); },
    offDrain: function (fn) { h2.off('drain', fn); },
    ping: function (payload) { h2.sendPing(payload); },
    destroy: function () { fail(new Error('destroyed')); },

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
    ev.emit('error', err);
  }

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
      if (ended || settled) return false;
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

    setTimeout: function (ms, cb) {
      if (cb) ev.once('timeout', cb);
      if (ms > 0) {
        var t = setTimeout(function () { ev.emit('timeout'); }, ms);
        if (t.unref) t.unref();
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


export { request, get, H2Pool, H2Session, globalPool };
