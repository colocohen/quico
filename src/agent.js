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


// ============================================================
//  Agent — connection pooling + protocol discovery
//
//  Mirrors node:https.Agent API surface.
//  Caches which protocol works per host so subsequent requests
//  skip the discovery step.
//
//  Options:
//    http2: true (default) — allow HTTP/2 in fallback chain
//    http1: true (default) — allow HTTP/1.1 in fallback chain
//    h3Timeout: 3000       — ms before falling back from H3
// ============================================================

class Agent extends EventEmitter {

  constructor(options) {
    super();

    options = options || {};

    this.keepAlive = options.keepAlive !== false;
    this.keepAliveMsecs = options.keepAliveMsecs || 1000;
    this.maxSockets = options.maxSockets || 256;
    this.maxFreeSockets = options.maxFreeSockets || 32;
    this.timeout = options.timeout || 30000;

    // Protocol flags (defaults for all requests through this agent)
    this.http2 = options.http2 !== false;
    this.http1 = options.http1 !== false;

    // H3 connect timeout before falling back (ms)
    this.h3Timeout = options.h3Timeout || 3000;

    // Protocol cache:  "host:port" → { protocol, ts, altSvcMaxAge }
    //   protocol: 'h3' | 'h2' | 'https'
    this._protocolCache = {};

    // Active QUIC connections: "host:port" → QUICConnection
    // Allows multiplexing multiple requests over one QUIC connection
    this._h3Pool = {};

    // Connections still being ESTABLISHED: "host:port" → [waiter callbacks].
    // Without this third state the pool only knows "have one" / "don't", so N
    // requests issued in the same tick each see an empty pool and open N
    // separate QUIC connections to the same origin — N handshakes, N
    // congestion controllers, zero multiplexing (the QUIC interop runner's
    // http3 test flags exactly this: "Expected exactly 1 handshake. Got: 3").
    // The first request to miss the pool becomes the lead and creates the
    // entry; requests arriving before it finishes park a callback here and
    // are replayed once the lead settles.
    this._h3Pending = {};

    // Active HTTP/2 sessions: "host:port" → http2.ClientHttp2Session
    this._h2Pool = {};

    // Request count per host (for maxSockets enforcement)
    this._activeCounts = {};

    // Sweep interval — clean stale pool entries
    this._sweepTimer = setInterval(() => this._sweep(), 15000);
    if (this._sweepTimer.unref) this._sweepTimer.unref();
  }


  // ============================================================
  //  Protocol cache
  // ============================================================

  /**
   * Get cached protocol for a host, or null if unknown.
   */
  getProtocol(host, port) {
    var key = host + ':' + (port || 443);
    var entry = this._protocolCache[key];
    if (!entry) return null;

    // Check expiry (Alt-Svc max-age, default 24h)
    var maxAge = entry.altSvcMaxAge || 86400000;
    if (Date.now() - entry.ts > maxAge) {
      delete this._protocolCache[key];
      return null;
    }

    return entry.protocol;
  }

  /**
   * Record which protocol works for a host.
   */
  setProtocol(host, port, protocol, altSvcMaxAge) {
    var key = host + ':' + (port || 443);
    this._protocolCache[key] = {
      protocol: protocol,
      ts: Date.now(),
      altSvcMaxAge: altSvcMaxAge || 86400000
    };
  }


  // ============================================================
  //  Alt-Svc header parsing
  // ============================================================

  /**
   * Parse Alt-Svc header from an HTTP/1.1 or HTTP/2 response.
   * If it advertises h3, cache it for future requests.
   *
   * Examples:
   *   Alt-Svc: h3=":443"; ma=86400
   *   Alt-Svc: h3=":443", h3-29=":443"
   */
  parseAltSvc(host, port, altSvcValue) {
    if (!altSvcValue || altSvcValue === 'clear') {
      var key = host + ':' + (port || 443);
      delete this._protocolCache[key];
      return;
    }

    var entries = altSvcValue.split(',');
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i].trim();
      var match = entry.match(/^h3(?:-\d+)?="([^"]*)"(.*)$/);
      if (match) {
        var authority = match[1];
        var params = match[2] || '';

        var maMatch = params.match(/ma=(\d+)/);
        var maxAge = maMatch ? parseInt(maMatch[1]) * 1000 : 86400000;

        var h3Port = port;
        var colonIdx = authority.lastIndexOf(':');
        if (colonIdx >= 0) {
          var parsed = parseInt(authority.substring(colonIdx + 1));
          if (!isNaN(parsed)) h3Port = parsed;
        }

        this.setProtocol(host, h3Port, 'h3', maxAge);
        return;
      }
    }
  }


  // ============================================================
  //  H3 connection pool
  //  Stores { quic, h3, udpSocket, _nextStreamId } objects
  //  from h3_client.js for multiplexing.
  // ============================================================

  getH3Connection(host, port) {
    var key = host + ':' + (port || 443);
    var conn = this._h3Pool[key];
    if (!conn) return null;
    var state = conn.quic ? conn.quic.state : 'closed';
    if (state === 'closed' || state === 'draining' || state === 'closing') {
      delete this._h3Pool[key];
      return null;
    }
    return conn;
  }

  /**
   * Coalesce concurrent connection attempts to one origin.
   *
   * Returns false if the caller is the LEAD: no connection exists and nobody
   * else is establishing one. The lead MUST eventually call
   * resolveH3Pending(host, port, connOrNull) — on success, failure, or
   * abandonment — or every later request to this origin parks forever.
   *
   * Returns true if the caller was parked as a follower; `cb` fires (with no
   * arguments) once the lead settles, and the caller should simply retry its
   * pool lookup: on success the connection is already registered, and on
   * failure the retry becomes the next lead — serial retry, no thundering
   * herd.
   */
  joinH3Pending(host, port, cb) {
    var key = host + ':' + (port || 443);
    if (this._h3Pending[key]) {
      this._h3Pending[key].push(cb);
      return true;
    }
    this._h3Pending[key] = [];
    return false;
  }

  /** Lead's settlement. Registers the connection (if any) BEFORE waking the
   *  waiters, so their retried pool lookups succeed synchronously. */
  resolveH3Pending(host, port, conn) {
    var key = host + ':' + (port || 443);
    var waiters = this._h3Pending[key] || [];
    delete this._h3Pending[key];
    if (conn) this.setH3Connection(host, port, conn);
    for (var i = 0; i < waiters.length; i++) {
      try { waiters[i](); } catch (e) { /* a waiter's failure is its own */ }
    }
  }

  setH3Connection(host, port, conn) {
    var key = host + ':' + (port || 443);
    this._h3Pool[key] = conn;
    if (conn.quic) {
      conn.quic.on('close', () => {
        if (this._h3Pool[key] === conn) delete this._h3Pool[key];
      });
    }
    // RFC 9114 §5.2: once the peer sends GOAWAY it won't accept new requests, so
    // stop reusing this connection for new ones. In-flight requests keep running
    // on it; they just won't be joined by new requests (which open a fresh conn).
    if (conn.h3 && typeof conn.h3.on === 'function') {
      conn.h3.on('goaway', () => {
        if (this._h3Pool[key] === conn) delete this._h3Pool[key];
      });
    }
  }


  // ============================================================
  //  H2 session pool
  // ============================================================

  getH2Session(host, port) {
    var key = host + ':' + (port || 443);
    var session = this._h2Pool[key];
    if (!session) return null;
    if (session.closed || session.destroyed) {
      delete this._h2Pool[key];
      return null;
    }
    return session;
  }

  setH2Session(host, port, session) {
    var key = host + ':' + (port || 443);
    this._h2Pool[key] = session;
    session.on('close', () => {
      if (this._h2Pool[key] === session) delete this._h2Pool[key];
    });
    session.on('error', () => {
      if (this._h2Pool[key] === session) delete this._h2Pool[key];
    });
  }


  // ============================================================
  //  Active request tracking
  // ============================================================

  canCreateSocket(host, port) {
    var key = host + ':' + (port || 443);
    return (this._activeCounts[key] || 0) < this.maxSockets;
  }

  trackRequest(host, port) {
    var key = host + ':' + (port || 443);
    this._activeCounts[key] = (this._activeCounts[key] || 0) + 1;
  }

  releaseRequest(host, port) {
    var key = host + ':' + (port || 443);
    if (this._activeCounts[key]) {
      this._activeCounts[key]--;
      if (this._activeCounts[key] <= 0) delete this._activeCounts[key];
    }
  }


  // ============================================================
  //  Sweep stale entries
  // ============================================================

  _sweep() {
    var now = Date.now();

    for (var key in this._protocolCache) {
      var entry = this._protocolCache[key];
      var maxAge = entry.altSvcMaxAge || 86400000;
      if (now - entry.ts > maxAge) delete this._protocolCache[key];
    }

    for (var key in this._h3Pool) {
      var conn = this._h3Pool[key];
      var state = conn.quic ? conn.quic.state : 'closed';
      if (state === 'closed' || state === 'draining') delete this._h3Pool[key];
    }

    for (var key in this._h2Pool) {
      var session = this._h2Pool[key];
      if (session.closed || session.destroyed) delete this._h2Pool[key];
    }
  }

  destroy() {
    if (this._sweepTimer) { clearInterval(this._sweepTimer); this._sweepTimer = null; }

    // Wake anyone parked on an in-flight connection attempt; their retried
    // pool lookup will find nothing and proceed (or fail) on its own.
    for (var key in this._h3Pending) {
      var waiters = this._h3Pending[key];
      delete this._h3Pending[key];
      for (var i = 0; i < waiters.length; i++) {
        try { waiters[i](); } catch (e) {}
      }
    }
    this._h3Pending = {};

    for (var key in this._h3Pool) {
      try { this._h3Pool[key].quic.close(0, 'agent destroy'); } catch (e) {}
    }
    this._h3Pool = {};

    for (var key in this._h2Pool) {
      try { this._h2Pool[key].close(); } catch (e) {}
    }
    this._h2Pool = {};

    this._protocolCache = {};
    this._activeCounts = {};
  }
}


var globalAgent = new Agent();

export { Agent, globalAgent };
