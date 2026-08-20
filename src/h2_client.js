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

import { H2Connection } from './h2.js';
import * as F from './h2_frames.js';
import { buildRequestPseudoHeaders } from './http_common.js';
import { IncomingMessage } from './streams.js';


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
    initialWindowSize: options.initialWindowSize,
    maxHeaderListSize: options.maxHeaderListSize,
    autoWindowUpdate: false
  });

  var streams = {};
  var destroyed = false;
  var goingAway = false;

  h2.on('send', function (data) {
    if (destroyed || !socket.writable) return;
    try { socket.write(data); } catch (e) { fail(e); }
  });

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
    rejectStream(streamId, e);
  });

  socket.on('data', function (chunk) {
    if (destroyed) return;
    try { h2.execute(chunk); } catch (err) { fail(err); }
  });
  socket.on('error', fail);
  socket.on('close', function () { fail(new Error('socket closed')); });

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
      else st.onError(err);
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
      streams[streamId] = { onResponse: callbacks.onResponse, onError: callbacks.onError, res: null };
      return streamId;
    },

    sendHeaders: function (streamId, list, endStream) { h2.sendHeaders(streamId, list, endStream); },
    sendData: function (streamId, data, endStream) { return h2.sendData(streamId, data, endStream); },
    cancel: function (streamId) { h2.sendRstStream(streamId, F.ERROR.CANCEL); delete streams[streamId]; },
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

  var ev = new EventEmitter();
  var bodyChunks = [];
  var ended = false;
  var settled = false;
  var session = null;
  var streamId = null;
  var sent = false;

  function fail(err) {
    if (settled) return;
    settled = true;
    ev.emit('error', err);
  }

  function connect() {
    var existing = pool.get(hostname, port);
    if (existing) { start(existing); return; }

    if (pool.join(hostname, port, function () {
      // The lead settled; retry from the top. On success the pool lookup now
      // hits and we multiplex on its session; on failure we become the next
      // lead — a serial retry, never a thundering herd.
      if (!settled) connect();
    })) return;

    var socket;
    var onReady = function () {
      var s = new H2Session(socket, options);
      pool.settle(hostname, port, s);
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
          ca: options.ca
        }, function () {
          if (socket.alpnProtocol !== 'h2') {
            pool.settle(hostname, port, null);
            fail(new Error('server did not negotiate h2 (got ' +
                           JSON.stringify(socket.alpnProtocol) + ')'));
            try { socket.destroy(); } catch (e) {}
            return;
          }
          onReady();
        });
      } else {
        // h2c with prior knowledge (§3.3): no ALPN, the preface speaks for us.
        socket = net.connect({ host: hostname, port: port }, onReady);
      }
    } catch (err) {
      pool.settle(hostname, port, null);
      fail(err);
      return;
    }

    socket.on('error', function (err) {
      pool.settle(hostname, port, null);
      fail(err);
    });
  }

  function start(s) {
    if (settled) return;
    session = s;
    streamId = session.request(null, {
      onResponse: function (res) {
        if (settled) return;
        settled = true;
        ev.emit('response', res);
        if (typeof callback === 'function') { callback(res); callback = null; }
      },
      onError: fail
    });
    if (streamId === null) return;
    if (ended) sendRequest();
  }

  function sendRequest() {
    if (sent || streamId === null) return;
    sent = true;

    var body = bodyChunks.length ? Buffer.concat(bodyChunks) : null;
    var headers = Object.assign({}, options.headers);

    if (body && headers['content-length'] === undefined &&
        headers['Content-Length'] === undefined) {
      headers['content-length'] = String(body.length);
    }

    var list = buildRequestPseudoHeaders({
      method: method,
      scheme: options.tls ? 'https' : 'http',
      hostname: hostname,
      port: port,
      path: options.path || '/',
      headers: headers
    });

    try {
      session.sendHeaders(streamId, list, !body);
      if (body) session.sendData(streamId, body, true);
    } catch (err) {
      fail(err);
    }
  }

  var clientReq = {
    on: function (n, f) { ev.on(n, f); return clientReq; },
    once: function (n, f) { ev.once(n, f); return clientReq; },
    emit: function () { ev.emit.apply(ev, arguments); return clientReq; },

    write: function (chunk, encoding) {
      if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding || 'utf8');
      bodyChunks.push(chunk);
      return true;
    },

    end: function (chunk, encoding) {
      if (chunk) clientReq.write(chunk, encoding);
      if (ended) return clientReq;
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

    get session() { return session; }
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
