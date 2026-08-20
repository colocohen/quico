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

var DEFAULT_MAX_SOCKETS = 6;      // what browsers use per origin
var DEFAULT_IDLE_TIMEOUT = 5000;


function H1Pool(options) {
  options = options || {};
  var idle = {};        // "host:port" -> [ { socket, parser, timer } ]
  var active = {};      // "host:port" -> count
  var maxSockets = options.maxSockets || DEFAULT_MAX_SOCKETS;
  var idleTimeout = options.idleTimeout != null ? options.idleTimeout : DEFAULT_IDLE_TIMEOUT;

  function key(host, port) { return host + ':' + port; }

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

    /** Park a reusable socket. */
    put: function (host, port, socket) {
      if (socket.destroyed || !socket.writable) return;
      var k = key(host, port);
      if (!idle[k]) idle[k] = [];

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
    acquire: function (host, port) {
      var k = key(host, port);
      active[k] = (active[k] || 0) + 1;
    },
    release: function (host, port) {
      var k = key(host, port);
      if (active[k]) { active[k]--; if (active[k] <= 0) delete active[k]; }
    },

    destroy: function () {
      for (var k in idle) {
        for (var i = 0; i < idle[k].length; i++) {
          if (idle[k][i].timer) clearTimeout(idle[k][i].timer);
          try { idle[k][i].socket.destroy(); } catch (e) {}
        }
      }
      idle = {}; active = {};
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
  var method = String(options.method || 'GET').toUpperCase();
  var path = options.path || '/';
  var pool = options.pool || globalPool;

  var ev = new EventEmitter();
  var bodyChunks = [];
  var ended = false;
  var sent = false;
  var socket = null;
  var parser = null;
  var reused = false;
  var settled = false;
  var timeoutTimer = null;

  // Headers are collected case-insensitively but sent with the caller's
  // casing: some servers (and more middleboxes) are sensitive to it, and there
  // is no reason to normalise what the caller chose.
  var headers = {};
  var headerNames = {};
  function setHeader(name, value) {
    var lower = String(name).toLowerCase();
    headers[lower] = value;
    headerNames[lower] = name;
  }
  if (options.headers) {
    for (var n in options.headers) setHeader(n, options.headers[n]);
  }

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
    pool.release(hostname, port);
    if (destroy) { try { s.destroy(); } catch (e) {} }
  }


  // ---- Connect ----

  function connect() {
    if (options.socket) {                      // caller supplied a Duplex
      socket = options.socket;
      pool.acquire(hostname, port);
      onSocketReady();
      return;
    }

    var pooled = pool.take(hostname, port);
    if (pooled) {
      socket = pooled;
      reused = true;
      pool.acquire(hostname, port);
      onSocketReady();
      return;
    }

    pool.acquire(hostname, port);

    if (options.tls) {
      // lemon-tls. ALPN offers http/1.1 only — an h2 offer here would be a
      // promise this client cannot keep.
      var tlsOpts = {
        host: hostname,
        port: port,
        servername: options.servername || hostname,
        ALPNProtocols: ['http/1.1'],
        rejectUnauthorized: options.rejectUnauthorized !== false
      };
      if (options.ca) tlsOpts.ca = options.ca;
      socket = options.tls.connect(tlsOpts, onSocketReady);
      socket.on('error', fail);
      return;
    }

    socket = net.connect({ host: hostname, port: port }, onSocketReady);
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
        pool.put(hostname, port, s);
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

    parser.on('error', function (err) { fail(err); });

    socket.on('data', function (chunk) {
      try { parser.execute(chunk); } catch (err) { fail(err); }
    });

    socket.on('end', function () {
      try { parser.eof(); } catch (e) {}
    });

    socket.on('close', function () {
      if (!settled) fail(new Error('socket closed before response'));
    });

    if (ended) sendRequest();
  }


  // ---- Sending ----

  function sendRequest() {
    if (sent || !socket) return;
    sent = true;

    var body = bodyChunks.length ? Buffer.concat(bodyChunks) : null;

    if (!('host' in headers)) {
      // RFC 9112 §3.2. The default port for the scheme is omitted, as every
      // client does — including it changes the origin as far as many servers
      // and virtual hosts are concerned.
      var defaultPort = options.tls ? 443 : 80;
      setHeader('Host', port === defaultPort ? hostname : hostname + ':' + port);
    }
    if (!('user-agent' in headers)) setHeader('User-Agent', 'quico/1.0');
    if (!('accept' in headers)) setHeader('Accept', '*/*');

    // Framing. If the caller declared neither and there is a body, state its
    // length: chunked would work too, but a plain Content-Length is understood
    // by every server including HTTP/1.0 ones.
    if (!('content-length' in headers) && !('transfer-encoding' in headers)) {
      if (body) setHeader('Content-Length', String(body.length));
      else if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
        setHeader('Content-Length', '0');
      }
    }

    var out = {};
    for (var lower in headers) out[headerNames[lower] || lower] = headers[lower];

    var chunked = String(headers['transfer-encoding'] || '').toLowerCase().indexOf('chunked') !== -1;

    try {
      socket.write(buildRequestHead(method, path, out));
      if (body) socket.write(chunked ? Buffer.concat([encodeChunk(body), encodeLastChunk()]) : body);
      else if (chunked) socket.write(encodeLastChunk());
    } catch (err) {
      fail(err);
    }
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

    write: function (chunk, encoding) {
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding || 'utf8');
      bodyChunks.push(chunk);
      return true;
    },

    end: function (chunk, encoding) {
      if (chunk) clientReq.write(chunk, encoding);
      if (ended) return clientReq;
      ended = true;
      if (socket) sendRequest();
      return clientReq;
    },

    abort: function () { fail(new Error('Request aborted')); },
    destroy: function (err) { fail(err || new Error('Request destroyed')); },

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
    get socket() { return socket; }
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
