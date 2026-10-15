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

import { H1Parser, buildRequestHead, encodeChunk, encodeLastChunk } from './h1.js';
import { IncomingMessage } from './streams.js';
import { tlsIdentity } from './agent.js';
import { validateHeaderName, validateHeaderValue, validateRequestTarget, trailerFields, formatPriority } from './http_common.js';

// What the body takes before write() says wait, while the socket is not yet
// the request's.
var BODY_HIGH_WATER = 64 * 1024;


// ============================================================
//  HTTP/1.1 client.
//
//  request(options, callback) -> an EventEmitter that emits 'response' with an
//  IncomingMessage, mirroring node:http.request. The unified client in
//  client.js calls this where it currently calls nodeHttps.request.
//
//  The connection pool here is deliberately NOT the H2/H3 pool. Those
//  multiplex: one connection serves every concurrent request, so the pool maps
//  origin -> connection. HTTP/1.1 does not. A socket carries one request at a
//  time, so the pool maps origin -> a LIST of idle sockets, and concurrency
//  means more sockets. Forcing both shapes into one abstraction would distort
//  each; agent.js keeps them as separate maps for the same reason.
// ============================================================

// The module's own pool (requests made with no agent): unlimited, as it has
// always behaved — a limit nobody chose would queue requests without warning.
// An agent passes its own maxSockets.
var DEFAULT_MAX_SOCKETS = Infinity;
var DEFAULT_IDLE_TIMEOUT = 5000;     // node:https.globalAgent's free-socket timeout
var DEFAULT_MAX_FREE_SOCKETS = 256;  // node:http.Agent's default


//  The pool follows node:http.Agent's rules, option for option:
//
//    maxSockets      sockets in use per origin at once. A request beyond it
//                    waits for one to be released — it is not refused, and not
//                    sent on a socket of its own. (This was not enforced at
//                    all: canOpen() existed, and nothing called it.)
//    keepAlive       keep a socket for the next request once its response is
//                    done. false: close it — unless a request is already
//                    waiting for this origin, which takes it, as Node does.
//    maxFreeSockets  idle sockets kept per origin; beyond, closed.
//    idleTimeout     how long an idle socket is kept (Node: the agent's
//                    `timeout`, which it applies to free sockets).
//    keepAliveMsecs  TCP keep-alive on kept sockets: the initial delay before
//                    the first probe (Node's meaning; it was used here as the
//                    idle timeout).
function H1Pool(options) {
  options = options || {};
  var idle = {};        // "host:port" -> [ { socket, parser, timer } ]
  var active = {};      // "host:port" -> count
  var waiting = {};     // "host:port" -> [ fn ] — requests waiting for a socket
  var maxSockets = options.maxSockets || DEFAULT_MAX_SOCKETS;
  var idleTimeout = options.idleTimeout != null ? options.idleTimeout : DEFAULT_IDLE_TIMEOUT;
  var keepAlive = options.keepAlive !== false;
  var maxFreeSockets = options.maxFreeSockets != null ? options.maxFreeSockets : DEFAULT_MAX_FREE_SOCKETS;
  var keepAliveMsecs = options.keepAliveMsecs != null ? options.keepAliveMsecs : 1000;

  function key(host, port) { return host + ':' + port; }

  // A slot was freed (or a socket parked): the next waiting request runs. A
  // waiter answers whether it took the slot — one cancelled while it waited
  // does not, and the next one is tried.
  function wake(k) {
    var list = waiting[k];
    while (list && list.length && (active[k] || 0) < maxSockets) {
      var fn = list.shift();
      if (fn() !== false) break;
    }
    if (list && !list.length) delete waiting[k];
  }

  return {
    /** An idle socket for this origin, or null. */
    take: function (host, port) {
      var k = key(host, port);
      var list = idle[k];
      while (list && list.length) {
        var entry = list.pop();
        if (entry.timer) clearTimeout(entry.timer);
        // Between being parked and being taken the peer may have closed. A
        // socket that looks writable but is half-closed produces the classic
        // intermittent ECONNRESET on the first request after an idle period.
        if (!entry.socket.destroyed && entry.socket.writable) {
          entry.socket.removeAllListeners('data');
          entry.socket.removeAllListeners('error');
          entry.socket.removeAllListeners('close');
          entry.socket.removeAllListeners('end');
          return entry.socket;
        }
        try { entry.socket.destroy(); } catch (e) {}
      }
      return null;
    },

    /** Park a reusable socket — or close it, when the pool keeps none. */
    put: function (host, port, socket) {
      if (socket.destroyed || !socket.writable) return;
      var k = key(host, port);
      var someoneWaiting = !!(waiting[k] && waiting[k].length);
      if ((!keepAlive && !someoneWaiting) ||
          (idle[k] && idle[k].length >= maxFreeSockets)) {
        try { socket.destroy(); } catch (e) {}
        return;
      }
      if (!idle[k]) idle[k] = [];
      if (keepAlive && typeof socket.setKeepAlive === 'function') {
        try { socket.setKeepAlive(true, keepAliveMsecs); } catch (e) {}
      }

      var entry = { socket: socket, timer: null };
      // An idle socket must be watched: if the peer closes it while parked and
      // nobody is listening, the 'error' surfaces as an uncaught exception.
      socket.removeAllListeners('data');
      socket.on('error', function () { drop(k, entry); });
      socket.on('close', function () { drop(k, entry); });
      socket.on('end',   function () { drop(k, entry); });

      if (idleTimeout > 0) {
        entry.timer = setTimeout(function () { drop(k, entry); }, idleTimeout);
        if (entry.timer.unref) entry.timer.unref();
      }
      idle[k].push(entry);
    },

    canOpen: function (host, port) {
      return (active[key(host, port)] || 0) < maxSockets;
    },
    /** Wait for a slot: `fn` runs once one is free, and returns false if it
     *  no longer wants it. */
    wait: function (host, port, fn) {
      var k = key(host, port);
      (waiting[k] = waiting[k] || []).push(fn);
    },
    acquire: function (host, port) {
      var k = key(host, port);
      active[k] = (active[k] || 0) + 1;
    },
    release: function (host, port) {
      var k = key(host, port);
      if (active[k]) { active[k]--; if (active[k] <= 0) delete active[k]; }
      // On the next tick: the releasing request parks its socket right after
      // releasing, and the waiter should find it there.
      if (waiting[k]) process.nextTick(function () { wake(k); });
    },

    destroy: function () {
      for (var k in idle) {
        for (var i = 0; i < idle[k].length; i++) {
          if (idle[k][i].timer) clearTimeout(idle[k][i].timer);
          try { idle[k][i].socket.destroy(); } catch (e) {}
        }
      }
      idle = {}; active = {}; waiting = {};
    }
  };

  function drop(k, entry) {
    if (entry.timer) { clearTimeout(entry.timer); entry.timer = null; }
    var list = idle[k];
    if (list) {
      var i = list.indexOf(entry);
      if (i !== -1) list.splice(i, 1);
    }
    try { entry.socket.destroy(); } catch (e) {}
  }
}


var globalPool = new H1Pool();


/**
 * request(options, callback)
 *
 * options: hostname/host, port, method, path, headers, body-writing via the
 *          returned object's write()/end(), tls (lemon-tls module), pool,
 *          timeout, socket (use this Duplex instead of connecting).
 */
function request(options, callback) {
  options = options || {};

  var hostname = options.hostname || options.host || 'localhost';
  var port = parseInt(options.port, 10) || (options.tls ? 443 : 80);
  // As node:http, thrown from request() itself (see validateRequestTarget).
  validateRequestTarget(options.path, options.method);
  var method = String(options.method || 'GET').toUpperCase();
  var path = options.path || '/';
  var pool = options.pool || globalPool;
  // The pool's name for this origin: the host, and over TLS what decides the
  // connection's identity (agent.js tlsIdentity) — one opened without
  // verification, or with another client certificate, carries no other
  // request. The connection itself goes to `hostname`.
  var poolHost = options.tls ? hostname + '#' + tlsIdentity(options) : hostname;

  var ev = new EventEmitter();
  var bodyChunks = [];
  var bodyBuffered = 0;
  var ended = false;
  var sent = false;
  var readyDone = false;      // the socket is this request's to send on (onSocketReady)
  var streaming = false;      // the head went out before the body ended: the body follows as written
  var framing = null;         // streaming: 'chunked', or 'length' (the caller's Content-Length)
  var declaredLength = 0, sentLength = 0;
  var needDrain = false;
  var reqTrailers = null;
  var socket = null;
  var parser = null;
  var reused = false;
  var settled = false;
  var sentEarly = false;       // the request went in TLS early data (see connect)
  ev.earlyData = null;         // 'accepted', 'rejected' or null (not sent early)
  var timeoutTimer = null;

  // Headers are collected case-insensitively but sent with the caller's
  // casing: some servers (and more middleboxes) are sensitive to it, and there
  // is no reason to normalise what the caller chose.
  var headers = {};
  var headerNames = {};
  function setHeader(name, value) {
    validateHeaderName(name);
    validateHeaderValue(name, value);
    var lower = String(name).toLowerCase();
    headers[lower] = value;
    headerNames[lower] = name;
  }
  if (options.headers) {
    for (var n in options.headers) setHeader(n, options.headers[n]);
  }

  var headSent = false;
  var IDEMPOTENT = { GET: 1, HEAD: 1, OPTIONS: 1, TRACE: 1, PUT: 1, DELETE: 1 };

  function fail(err) {
    if (settled) return;
    settled = true;
    cleanupTimer();
    releaseSocket(true);
    ev.emit('error', err);
  }

  function cleanupTimer() {
    if (timeoutTimer) { clearTimeout(timeoutTimer); timeoutTimer = null; }
  }

  function releaseSocket(destroy) {
    if (!socket) return;
    var s = socket;
    socket = null;
    pool.release(poolHost, port);
    if (destroy) { try { s.destroy(); } catch (e) {} }
  }


  // ---- Connect ----

  // Returns false when the request no longer wants a socket (it was
  // cancelled while waiting for one) — the pool then offers the slot on.
  function connect() {
    if (settled) return false;
    if (options.socket) {                      // caller supplied a Duplex
      socket = options.socket;
      pool.acquire(poolHost, port);
      onSocketReady();
      return true;
    }

    // maxSockets: every socket for this origin is busy — wait for one.
    if (pool.canOpen && !pool.canOpen(poolHost, port)) {
      pool.wait(poolHost, port, connect);
      return true;
    }

    var pooled = pool.take(poolHost, port);
    if (pooled) {
      socket = pooled;
      reused = true;
      pool.acquire(poolHost, port);
      onSocketReady();
      return true;
    }

    pool.acquire(poolHost, port);

    if (options.tls) {
      // lemon-tls. ALPN offers http/1.1 only — an h2 offer here would be a
      // promise this client cannot keep.
      var tlsOpts = {
        host: hostname,
        port: port,
        servername: options.servername || hostname,
        ALPNProtocols: ['http/1.1'],
        rejectUnauthorized: options.rejectUnauthorized !== false,
        // The server's certificate chain may come compressed (RFC 8879):
        // brotli, zstd, zlib — as the HTTP/3 client and the browsers offer.
        certificateCompression: true,
        // The server's stapled OCSP response ('OCSPResponse').
        requestOCSP: options.requestOCSP === true,
        // Encrypted Client Hello: the server's ECHConfigList, or GREASE ECH.
        echGrease: options.echGrease === true,
      // TCP_NODELAY, as node:http's client sets it (its noDelay, default true).
      // Without it Nagle held a small write — a request's HEADERS behind the
      // preface, a WINDOW_UPDATE, a body after its head — until the last one
      // was acknowledged, and the server's delayed ACK made that up to 40 ms:
      // 3000 small HTTP/2 requests took 2.8 s instead of 0.5.
        noDelay: options.noDelay !== false
      };
      if (options.ech) tlsOpts.ech = options.ech;
      // The key-exchange groups to offer (tls.connect's ecdhCurve).
      if (options.ecdhCurve != null) tlsOpts.ecdhCurve = options.ecdhCurve;
      if (options.sigalgs != null) tlsOpts.sigalgs = options.sigalgs;
      if (options.ca) tlsOpts.ca = options.ca;
      // A client certificate, for a server that asks (tls.connect's names).
      if (options.key && options.cert) { tlsOpts.key = options.key; tlsOpts.cert = options.cert; if (options.passphrase != null) tlsOpts.passphrase = options.passphrase; }
      // A saved session to resume with (tls.connect's `session`); the
      // socket's 'session' events, each one to resume with next time, on the
      // request that opened it.
      if (options.session) tlsOpts.session = options.session;
      // 0-RTT (TLS early data): a GET, HEAD or OPTIONS with a session whose
      // ticket allows it goes in the first flight — see h2_client.
      var wantEarly = options.earlyData === true && !!options.session && (method === 'GET' || method === 'HEAD' || method === 'OPTIONS');
      if (wantEarly) tlsOpts.earlyData = true;
      socket = options.tls.connect(tlsOpts, function () { if (!sentEarly) onSocketReady(); });
      if (wantEarly) {
        var early = socket;
        setTimeout(function () {
          if (settled || socket !== early || early.destroyed || early.isEarlyData !== true) return;
          sentEarly = true;
          onSocketReady();
        }, 0);
      }
      socket.on('session', function (s) { ev.emit('session', s); });
      socket.on('OCSPResponse', function (r) { ev.emit('OCSPResponse', r); });
      socket.on('error', fail);
      return;
    }

    socket = net.connect({ host: hostname, port: port, noDelay: options.noDelay !== false }, onSocketReady);
    socket.on('error', fail);
  }


  function onSocketReady() {
    if (settled) { releaseSocket(true); return; }

    socket.removeAllListeners('data');
    socket.on('error', fail);

    parser = new H1Parser({ isServer: false });
    // Response framing depends on the request method: a HEAD reply carries the
    // Content-Length of a body it does not send, and a 2xx to CONNECT is a
    // tunnel. Without this the parser would read the next response's head as
    // this one's body.
    parser.pushRequestMethod(method);

    var res = null;

    parser.on('headers', function (info) {
      if (sentEarly && info.statusCode >= 200) {
        ev.earlyData = socket && socket.earlyDataStatus === 'accepted' ? 'accepted' : 'rejected';
        if (info.statusCode === 425) {
          // RFC 8470: sent again after the handshake (the unified client,
          // on this failure being retryable); this socket goes.
          var tooEarly = new Error('425 Too Early: the request is sent again after the handshake');
          tooEarly.code = 'ERR_HTTP_TOO_EARLY';
          tooEarly.retryable = true;
          fail(tooEarly);     // settles first, then lets the socket go (its close is no news)
          return;
        }
      }
      res = new IncomingMessage({
        httpVersion: info.httpVersion,
        statusCode: info.statusCode,
        statusMessage: info.statusMessage,
        headers: info.headers,
        socket: socket
      });
      res.rawHeaders = info.rawHeaders;
      res._keepAlive = info.keepAlive;

      // 1xx other than 101 is informational: the real response follows on the
      // same connection, so it must not be delivered as THE response.
      if (info.statusCode >= 100 && info.statusCode < 200 && info.statusCode !== 101) {
        if (info.statusCode === 100) ev.emit('continue');
        else ev.emit('information', info);
        res = null;
        return;
      }

      settled = true;
      cleanupTimer();
      ev.emit('response', res);
      if (typeof callback === 'function') { callback(res); callback = null; }
    });

    parser.on('body', function (chunk) { if (res) res._pushData(chunk); });
    parser.on('trailers', function (t) { if (res) res.trailers = t; });

    parser.on('end', function () {
      if (!res) return;
      var keepAlive = res._keepAlive;
      res._endData();
      res = null;

      if (keepAlive && socket && !socket.destroyed) {
        var s = socket;
        releaseSocket(false);
        pool.put(poolHost, port, s);
      } else {
        releaseSocket(true);
      }
    });

    parser.on('upgrade', function (info, head) {
      settled = true;
      cleanupTimer();
      var s = socket;
      releaseSocket(false);
      if (s) { s.removeAllListeners('data'); s.removeAllListeners('error'); }
      ev.emit('upgrade', info, s, head);
    });

    // Once the response has begun, a failure is the response's: fail()
    // reports only on the request, and a body cut short — the socket closed
    // mid-body, or bytes the parser refused — neither ended nor failed: it hung.
    function abortResponse(err) {
      if (!res) return;
      var r = res;
      res = null;
      r._abort(err);
    }

    parser.on('error', function (err) { abortResponse(err); fail(err); });

    socket.on('data', function (chunk) {
      try { parser.execute(chunk); } catch (err) { fail(err); }
    });

    socket.on('end', function () {
      try { parser.eof(); } catch (e) {}
    });

    socket.on('close', function () {
      if (!settled) {
        var lost = new Error('socket closed before response');
        lost.code = 'ECONNRESET';
        // Sent and not idempotent: the server may have acted on it, so it is
        // not sent again over another protocol (RFC 9110 §9.2.2) — the
        // unified client tried HTTP/2 and HTTP/3 with the same POST.
        if (headSent && !IDEMPOTENT[method]) lost.requestError = true;
        fail(lost);
        return;
      }
      var err = new Error('socket closed before the response ended');
      err.code = 'ECONNRESET';
      abortResponse(err);
    });

    // options.onReady (the unified client) may turn the request down here —
    // another protocol was ready first and carries it: the socket goes (it
    // is not known idle to anyone else), and 'superseded' says so.
    if (typeof options.onReady === 'function' && !options.onReady()) {
      settled = true;
      releaseSocket(true);
      process.nextTick(function () { ev.emit('superseded'); });
      return;
    }
    readyDone = true;
    if (ended) sendRequest();
    else if (bodyChunks.length) startStreaming();
  }


  // ---- Sending ----

  // The defaults every request head gets, unless the caller set them.
  function defaultHeaders() {
    if (!('host' in headers)) {
      // RFC 9112 §3.2. The default port for the scheme is omitted, as every
      // client does — including it changes the origin as far as many servers
      // and virtual hosts are concerned.
      var defaultPort = options.tls ? 443 : 80;
      setHeader('Host', port === defaultPort ? hostname : hostname + ':' + port);
    }
    if (!('user-agent' in headers)) setHeader('User-Agent', 'quico/1.0');
    if (!('accept' in headers)) setHeader('Accept', '*/*');
  }

  function headOut() {
    var out = {};
    for (var lower in headers) out[headerNames[lower] || lower] = headers[lower];
    return out;
  }

  function lengthMismatch(actual, declared) {
    var mismatch = new Error('Response body\'s content-length of ' + actual + ' byte(s) does not match the content-length of ' + declared + ' byte(s) in header');
    mismatch.code = 'ERR_HTTP_CONTENT_LENGTH_MISMATCH';
    mismatch.requestError = true;   // not the protocol's fault: no other is tried (client.js)
    return mismatch;
  }

  // The request whole: ended before the socket was its own.
  function sendRequest() {
    if (sent || !socket) return;
    sent = true;

    var body = bodyChunks.length ? Buffer.concat(bodyChunks) : null;
    bodyChunks = []; bodyBuffered = 0;
    defaultHeaders();

    // Trailers go after the last chunk: chunked, unless the caller declared
    // a Content-Length (then they are dropped, as node:http drops them).
    if (reqTrailers && !('content-length' in headers) && !('transfer-encoding' in headers)) {
      setHeader('Transfer-Encoding', 'chunked');
    }

    // Framing. If the caller declared neither and there is a body, state its
    // length: chunked would work too, but a plain Content-Length is understood
    // by every server including HTTP/1.0 ones.
    if (!('content-length' in headers) && !('transfer-encoding' in headers)) {
      if (body) setHeader('Content-Length', String(body.length));
      else if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        setHeader('Content-Length', '0');
      }
    }

    var out = headOut();

    var chunked = String(headers['transfer-encoding'] || '').toLowerCase().indexOf('chunked') !== -1;

    // A Content-Length the caller set must be the body's. The body is whole
    // here, so it can be checked, and it has to be: bytes past the length are
    // read by the server as the start of the NEXT request on this connection
    // — which the agent reuses — and too few leave the server waiting for
    // bytes that become the next request's start. Either way a request is
    // injected into the connection (nginx's CVE-2026-42926 is this, in a
    // proxy). node:http checks it with strictContentLength; a library that
    // pools connections cannot afford not to.
    if (!chunked && 'content-length' in headers) {
      var declared = String(headers['content-length']).trim();
      var actual = body ? body.length : 0;
      if (!/^\d+$/.test(declared) || Number(declared) !== actual) {
        fail(lengthMismatch(actual, declared));
        return;
      }
    }

    try {
      socket.write(buildRequestHead(method, path, out));
      if (body) socket.write(chunked ? Buffer.concat(encodeChunk(body).concat([encodeLastChunk(reqTrailers)])) : body);
      else if (chunked) socket.write(encodeLastChunk(reqTrailers));
    } catch (err) {
      fail(err);
    }
  }
  // The body streamed: the head now — chunked, or the caller's
  // Content-Length, which the bytes must then add up to (checked as they go
  // and at the end: too many or too few, and the next request on this
  // connection would be read wrong) — then what was held.
  function startStreaming() {
    if (sent || !socket) return;
    sent = true;
    streaming = true;
    defaultHeaders();
    if ('content-length' in headers && String(headers['transfer-encoding'] || '').toLowerCase().indexOf('chunked') === -1) {
      var declared = String(headers['content-length']).trim();
      if (!/^\d+$/.test(declared)) { fail(lengthMismatch(bodyBuffered, declared)); releaseSocket(true); return; }
      framing = 'length';
      declaredLength = Number(declared);
    } else {
      framing = 'chunked';
      if (!('transfer-encoding' in headers)) setHeader('Transfer-Encoding', 'chunked');
    }
    try { socket.write(buildRequestHead(method, path, headOut())); } catch (err) { fail(err); return; }
    headSent = true;
    var held = bodyChunks; bodyChunks = []; bodyBuffered = 0;
    var more = true;
    for (var i = 0; i < held.length; i++) more = writeOut(held[i]);
    if (more && needDrain) { needDrain = false; ev.emit('drain'); }
  }

  function writeOut(chunk) {
    if (!socket) return false;
    if (framing === 'length') {
      sentLength += chunk.length;
      if (sentLength > declaredLength) { fail(lengthMismatch(sentLength, declaredLength)); releaseSocket(true); return false; }
      return socketWrite(chunk);
    }
    return socketWrite(Buffer.concat(encodeChunk(chunk)));
  }

  function socketWrite(buf) {
    var ok;
    try { ok = socket.write(buf); } catch (err) { fail(err); return false; }
    if (!ok && !needDrain) {
      needDrain = true;
      socket.once('drain', function () { if (needDrain) { needDrain = false; ev.emit('drain'); } });
    }
    return ok;
  }

  function finishStream() {
    if (!socket) return;
    if (framing === 'chunked') { socketWrite(encodeLastChunk(reqTrailers)); return; }
    if (sentLength !== declaredLength) { fail(lengthMismatch(sentLength, declaredLength)); releaseSocket(true); }
  }



  // ---- Public surface (node:http.ClientRequest shape) ----

  var clientReq = {
    on: function (name, fn) { ev.on(name, fn); return clientReq; },
    once: function (name, fn) { ev.once(name, fn); return clientReq; },
    off: function (name, fn) { ev.off(name, fn); return clientReq; },
    emit: function () { ev.emit.apply(ev, arguments); return clientReq; },

    setHeader: setHeader,
    getHeader: function (name) { return headers[String(name).toLowerCase()]; },
    removeHeader: function (name) {
      var l = String(name).toLowerCase();
      delete headers[l]; delete headerNames[l];
    },

    // The body, as node:http's: held while connecting (write() false past
    // BODY_HIGH_WATER, then 'drain'), then streamed — the head on the first
    // write once the socket is the request's, chunked unless the caller set
    // a Content-Length — with the socket's backpressure.
    write: function (chunk, encoding) {
      if (ended || settled) return false;
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding || 'utf8');
      if (!chunk || chunk.length === 0) return !needDrain;
      if (!streaming && readyDone && !sent) startStreaming();
      if (streaming) return writeOut(chunk);
      bodyChunks.push(chunk);
      bodyBuffered += chunk.length;
      if (bodyBuffered >= BODY_HIGH_WATER) { needDrain = true; return false; }
      return true;
    },

    // RFC 9218 §5: the `priority` header, while the head has not gone;
    // HTTP/1.1 has no frame to change it after.
    setPriority: function (p) {
      if (sent) return;
      var v = formatPriority(p);
      if (v) setHeader('Priority', v);
      else { delete headers.priority; delete headerNames.priority; }
    },

    // `trailers` (node:http's addTrailers, through the unified client): after
    // the last chunk — so only with chunked encoding, as in node:http.
    end: function (chunk, encoding, trailers) {
      if (ended) return clientReq;
      if (encoding && typeof encoding === 'object') { trailers = encoding; encoding = undefined; }
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding || 'utf8');
      reqTrailers = trailerFields(trailers);
      if (streaming) {
        if (chunk && chunk.length) writeOut(chunk);
        ended = true;
        finishStream();
        return clientReq;
      }
      if (chunk && chunk.length) { bodyChunks.push(chunk); bodyBuffered += chunk.length; }
      ended = true;
      if (readyDone) sendRequest();
      return clientReq;
    },

    abort: function () { fail(new Error('Request aborted')); },
    destroy: function (err) {
      if (!settled) { fail(err || new Error('Request destroyed')); return; }
      // The response has begun (settled): the rest of it is abandoned, and
      // the socket with it — mid-body it cannot go back to the pool. fail()
      // returned early here, so the body went on downloading and the socket
      // was pooled when it ended.
      cleanupTimer();
      releaseSocket(true);
    },

    setTimeout: function (ms, cb) {
      if (cb) ev.once('timeout', cb);
      cleanupTimer();
      if (ms > 0) {
        timeoutTimer = setTimeout(function () { ev.emit('timeout'); }, ms);
        if (timeoutTimer.unref) timeoutTimer.unref();
      }
      return clientReq;
    },

    get reusedSocket() { return reused; },
    get socket() { return socket; },
    // 0-RTT: 'accepted', 'rejected', or null (not sent early).
    get earlyData() { return ev.earlyData; }
  };

  // Connect on the next tick so the caller can attach listeners and write a
  // body first — the same ordering guarantee node:http gives.
  process.nextTick(function () {
    if (!settled) connect();
  });

  return clientReq;
}


function get(options, callback) {
  var req = request(Object.assign({}, options, { method: 'GET' }), callback);
  req.end();
  return req;
}


export { request, get, H1Pool, globalPool };
