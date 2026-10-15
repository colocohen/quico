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
import { createHash } from 'node:crypto';
import lemonTls from 'lemon-tls';


// ============================================================
//  Which connections a request may share — node:https.Agent's getName
//
//  A pooled connection was looked up by host and port alone. One opened with
//  rejectUnauthorized: false — to a server whose certificate was never
//  checked — then carried the next request to that origin that does check,
//  and that request went over an unverified connection without a word; one
//  verified against a private `ca` served a request that trusts only the
//  public roots. node:https puts what decides a connection's TLS into the
//  pool's name (getName): ca, cert, key, rejectUnauthorized, servername.
//  So does this, for every pool — the agent's HTTP/3 connections, the HTTP/2
//  sessions and HTTP/1.1 sockets, and their TLS sessions — the values
//  hashed, not spelled out, so a key or a CA bundle is not in a map key.
//
//  A request with a client certificate shared no connection at all, since
//  the name could not tell one certificate from another; now it shares those
//  opened with the same one, as in Node.
// ============================================================

function digestOf(v) {
  if (v === undefined || v === null || v === '') return '';
  var h = createHash('sha256');
  (Array.isArray(v) ? v : [v]).forEach(function (x) {
    h.update(typeof x === 'string' || Buffer.isBuffer(x) || x instanceof Uint8Array ? x : String(x));
    h.update('\0');
  });
  return h.digest('hex').slice(0, 16);
}

/** The TLS identity part of a pool name: '' for a cleartext connection. */
// Sessions kept per origin (see _takeSession).
var ECH_RETRY_TTL = 24 * 3600 * 1000;   // ms: how long a server's retry_configs are used for
var TICKETS_PER_ORIGIN = 4;

function tlsIdentity(options) {
  options = options || {};
  // With ECH, its own connections: a request asking for its name to be
  // hidden does not ride one opened without (or with another server's keys).
  // With other key-exchange groups (ecdhCurve, as node:https names it), its
  // own connections too: one asking for post-quantum does not ride a
  // classical one.
  var curve = options.ecdhCurve == null ? '' : String(options.ecdhCurve).trim().toUpperCase().replace(/[\s,]+/g, ':');
  // And with other signature schemes (sigalgs): the certificate a server
  // presents can depend on them (an ML-DSA one, asked for first).
  var sigalgs = options.sigalgs == null ? '' : String(options.sigalgs).trim().toUpperCase().replace(/[\s,]+/g, ':');
  return [options.servername || '', options.rejectUnauthorized === false ? 'noverify' : 'verify',
          digestOf(options.ca), digestOf(options.cert), digestOf(options.key)].join(':') +
         (options.ech ? ':ech:' + digestOf(options.ech) : '') +
         (sigalgs ? ':sigalgs:' + sigalgs : '') +
         (curve && curve !== 'AUTO' ? ':curve:' + curve : '');
}


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
//
//  and node:http.Agent's, with Node's meanings. They govern HTTP/1.1, the one
//  version that needs a socket per request; HTTP/2 and HTTP/3 multiplex every
//  request to an origin over one connection, which the agent always keeps.
//    keepAlive: true       — keep a socket for the next request (Node's
//                            globalAgent default; `new http.Agent()` is false)
//    keepAliveMsecs: 1000  — TCP keep-alive initial delay on kept sockets
//    maxSockets: 256       — sockets per origin at once; more requests wait
//    maxFreeSockets: 256   — idle sockets kept per origin
//    timeout               — how long an idle socket is kept (5000 when unset,
//                            as node:https.globalAgent)
//    maxCachedSessions: 100 — TLS sessions kept to resume with, as
//                            node:https.Agent's; 0 keeps none
// ============================================================

class Agent extends EventEmitter {

  constructor(options) {
    super();

    options = options || {};

    this.keepAlive = options.keepAlive !== false;
    this.keepAliveMsecs = options.keepAliveMsecs || 1000;
    this.maxSockets = options.maxSockets || 256;
    this.maxFreeSockets = options.maxFreeSockets != null ? options.maxFreeSockets : 256;
    this.timeout = options.timeout;   // unset: idle sockets kept 5 s (see agentH1Pool)

    // Protocol flags (defaults for all requests through this agent)
    this.http2 = options.http2 !== false;
    this.http1 = options.http1 !== false;

    // H3 connect timeout before falling back (ms)
    this.h3Timeout = options.h3Timeout || 3000;

    // The key-exchange groups its requests offer, unless a request names its
    // own (tls.connect's ecdhCurve; 'X25519MLKEM768:X25519' for the
    // post-quantum hybrid). Checked here, as tls.connect checks it.
    if (options.ecdhCurve != null) lemonTls.parseEcdhCurve(options.ecdhCurve);
    this.ecdhCurve = options.ecdhCurve != null ? options.ecdhCurve : undefined;
    // The signature schemes they offer (tls.connect's sigalgs; 'mldsa65:…'
    // first asks a server holding an ML-DSA certificate for it).
    if (options.sigalgs != null) lemonTls.parseSigalgs(options.sigalgs);
    this.sigalgs = options.sigalgs != null ? options.sigalgs : undefined;

    // TLS sessions to resume with, as node:https.Agent keeps them: the
    // latest per origin, the oldest dropped past maxCachedSessions.
    this.maxCachedSessions = options.maxCachedSessions != null ? options.maxCachedSessions : 100;
    if (!(Number.isInteger(this.maxCachedSessions) && this.maxCachedSessions >= 0))
      throw new TypeError('maxCachedSessions must be a non-negative integer, got ' + options.maxCachedSessions);
    this._sessionCache = new Map();
    this._tokenCache = new Map();   // NEW_TOKEN tokens (_takeToken)
    this._echCache = new Map();     // ECH keys a server sent on rejecting (_getEchRetry)

    // Protocol cache:  "host:port" → { protocol, ts, altSvcMaxAge }
    //   protocol: 'h3' | 'h2' | 'https'
    this._protocolCache = {};

    // Alt-Svc advertisements: "host:port" (the origin) → { port, expires, brokenUntil }
    this._altSvc = {};

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
  //  Alt-Svc (RFC 7838): where else an origin can be reached
  //
  //  An HTTP/1.1 or HTTP/2 response saying `Alt-Svc: h3=":443"; ma=86400`
  //  tells us the same origin is also served over HTTP/3, on that port, for
  //  the next `ma` seconds. That is what lets a client move to HTTP/3 at all.
  //
  //  Kept apart from the protocol cache on purpose. The two answer different
  //  questions — "what worked here last time" and "what does the origin
  //  advertise" — and when they shared one entry, the request that carried
  //  the Alt-Svc header recorded its own protocol ('h2') a line later,
  //  overwriting the advertisement: a client never moved to HTTP/3 through
  //  Alt-Svc. An advertisement for another port was stored under that port,
  //  where no lookup for the origin ever looked.
  //
  //  Keyed by origin. Only alternatives on the same host are used: one on
  //  another host would need the connection to be authenticated for the
  //  origin, not for the host it goes to (RFC 7838 §2.1), which the HTTP/3
  //  client does not do.
  // ============================================================

  /**
   * Record what an origin advertises. `value` is the Alt-Svc header.
   *   Alt-Svc: h3=":443"; ma=86400
   *   Alt-Svc: h3=":8443", h3-29=":8443"
   *   Alt-Svc: clear
   */
  parseAltSvc(host, port, value) {
    var key = host + ':' + (port || 443);
    if (!value) return;
    if (String(value).trim() === 'clear') { delete this._altSvc[key]; return; }

    var entries = String(value).split(',');
    for (var i = 0; i < entries.length; i++) {
      var match = entries[i].trim().match(/^h3="([^"]*)"(.*)$/);   // RFC 9114 h3 only, not drafts
      if (!match) continue;
      var authority = match[1];
      var colonIdx = authority.lastIndexOf(':');
      if (colonIdx < 0) continue;
      var altHost = authority.substring(0, colonIdx);
      var altPort = parseInt(authority.substring(colonIdx + 1), 10);
      if (!(altPort > 0 && altPort < 65536)) continue;
      if (altHost && altHost.toLowerCase() !== String(host).toLowerCase()) continue;
      var maMatch = (match[2] || '').match(/(?:^|;)\s*ma=(\d+)/);
      var maxAge = maMatch ? parseInt(maMatch[1], 10) * 1000 : 86400000;   // default 24h (§3.1)
      var prev = this._altSvc[key];
      this._altSvc[key] = {
        port: altPort,
        expires: Date.now() + maxAge,
        // A fresh advertisement does not clear a recent failure of the same
        // alternative: the origin keeps advertising it on every response.
        brokenUntil: prev && prev.port === altPort ? prev.brokenUntil : 0
      };
      return;
    }
  }

  /** The HTTP/3 alternative to use for an origin now: { port }, or null. */
  getAltSvc(host, port) {
    var key = host + ':' + (port || 443);
    var alt = this._altSvc[key];
    if (!alt) return null;
    var now = Date.now();
    if (now > alt.expires) { delete this._altSvc[key]; return null; }
    if (now < alt.brokenUntil) return null;
    return { port: alt.port };
  }

  /**
   * The alternative failed: don't try it again for a while (RFC 7838 §2.4
   * lets a client mark an alternative broken). Five minutes, as browsers do
   * for a first failure; requests in the meantime go straight to the
   * origin's own protocol.
   */
  markAltSvcBroken(host, port) {
    var alt = this._altSvc[host + ':' + (port || 443)];
    if (alt) alt.brokenUntil = Date.now() + 5 * 60 * 1000;
  }


  // ============================================================
  //  TLS sessions (node:https.Agent's _getSession / _cacheSession /
  //  _evictSession)
  //
  //  Every connection used to start with a full handshake — certificate
  //  chain, signature, its verification — though the server had sent a
  //  ticket to skip all that next time; node:https.Agent resumes. And the
  //  ticket is where a QUICO server keeps what it learned about the path
  //  (Careful Resume, quic_connection.js): without resumption a returning
  //  client was a stranger again, its transfer starting from the initial
  //  window.
  //
  //  The key says which connections a session may serve: the transport (a
  //  ticket from TLS over TCP is not offered to QUIC, RFC 9001 §4.6.1 keeps
  //  them apart), and the pool name (tlsIdentity above) — a session from a
  //  connection that did not verify the server, or verified it against
  //  another `ca`, is not offered to one that does (lemon-tls checks that
  //  too, from the session).
  // ============================================================

  _sessionKey(transport, host, port, options) {
    return transport + ':' + host + ':' + (port || 443) + ':' + tlsIdentity(options);
  }

  /** node:https.Agent's getName: what the agent keys a connection by. */
  getName(options) {
    options = options || {};
    return (options.hostname || options.host || 'localhost') + ':' + (options.port || 443) + ':' + tlsIdentity(options);
  }

  // Each origin's sessions — the tickets its server sent, up to
  // TICKETS_PER_ORIGIN, newest last — and each used ONCE (RFC 8446 §C.4: a
  // ticket offered twice links the two connections, and its 0-RTT is
  // refused as a replay). The latest alone was kept and offered to every
  // connection: two at once resumed with the same ticket, and the second's
  // early data was always refused. A QUICO server sends two per full
  // handshake, as OpenSSL and BoringSSL do. Expired ones are not offered
  // (lemon-tls sessionInfo). maxCachedSessions bounds the origins.

  /** The newest session for `key`, left in the cache (to look at). */
  _getSession(key) {
    var list = this._sessionCache.get(key);
    return list && list.length ? list[list.length - 1] : undefined;
  }

  /** The newest unexpired session for `key`, taken: a new connection's. */
  _takeSession(key) {
    var list = this._sessionCache.get(key);
    var now = Date.now();
    while (list && list.length) {
      var s = list.pop();
      var info = lemonTls.sessionInfo ? lemonTls.sessionInfo(s) : null;
      if (info && info.expiresAt != null && info.expiresAt <= now) continue;
      if (!list.length) this._sessionCache.delete(key);
      return s;
    }
    this._sessionCache.delete(key);
    return undefined;
  }

  _cacheSession(key, session) {
    if (this.maxCachedSessions === 0 || !session) return;
    var list = this._sessionCache.get(key) || [];
    this._sessionCache.delete(key);              // the newest origin goes last
    list.push(session);
    while (list.length > TICKETS_PER_ORIGIN) list.shift();
    this._sessionCache.set(key, list);
    while (this._sessionCache.size > this.maxCachedSessions) {
      this._sessionCache.delete(this._sessionCache.keys().next().value);
    }
  }

  _evictSession(key) {
    this._sessionCache.delete(key);
  }

  // ECH keys a server sent when it rejected the ones the caller had
  // (retry_configs, RFC 9849 §6.1.6), kept for the next connections (§6.1.8:
  // "Clients MAY use information learned from a rejected ECH for future
  // connections"): a server that rotated its keys was asked with the old
  // ones on every connection until the caller's DNS caught up — rejected,
  // retried, a round trip lost each time. Kept under what PSKs are (§6.1.8:
  // "the same lifetime and scope restrictions"): the key is the session key
  // of the config the caller gave (the same source), the origin, the TLS
  // identity; a day at most (ECH_RETRY_TTL); none with maxCachedSessions 0;
  // bounded by it. A caller that gives another config — its DNS updated —
  // finds nothing kept for it.
  _getEchRetry(key) {
    var e = this._echCache.get(key);
    if (!e) return null;
    if (Date.now() - e.at > ECH_RETRY_TTL) { this._echCache.delete(key); return null; }
    return e.configs;
  }

  _cacheEchRetry(key, configs) {
    if (this.maxCachedSessions === 0 || !configs) return;
    this._echCache.delete(key);
    this._echCache.set(key, { configs: configs, at: Date.now() });
    while (this._echCache.size > this.maxCachedSessions) {
      this._echCache.delete(this._echCache.keys().next().value);
    }
  }

  _evictEchRetry(key) {
    this._echCache.delete(key);
  }

  // NEW_TOKEN tokens (RFC 9000 §8.1.3), per server: the latest one a QUIC
  // connection to it was given, for the next connection's Initial — which
  // then needs no proof of address, so the server's whole first flight goes
  // out in one round trip. Each is used once (§8.1.3: a reused token links
  // the connections that carry it), and the server gives another each time.
  _takeToken(key) {
    var t = this._tokenCache.get(key);
    this._tokenCache.delete(key);
    return t;
  }

  _cacheToken(key, token) {
    if (this.maxCachedSessions === 0 || !token) return;
    this._tokenCache.delete(key);
    this._tokenCache.set(key, token);
    while (this._tokenCache.size > this.maxCachedSessions) {
      this._tokenCache.delete(this._tokenCache.keys().next().value);
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
    // GOAWAY'd (RFC 9114 §5.2) — the event below can come before the
    // connection is pooled, so asked here too.
    if (state === 'closed' || state === 'draining' || state === 'closing' || conn.goingAway) {
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

    for (var key in this._altSvc) {
      if (now > this._altSvc[key].expires) delete this._altSvc[key];
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
      // Pooled connections are HTTP/3 — close with H3_NO_ERROR (RFC 9114 §5.2).
      try { this._h3Pool[key].quic.close(0x0100, 'agent destroy', true); } catch (e) {}
    }
    this._h3Pool = {};

    for (var key in this._h2Pool) {
      try { this._h2Pool[key].close(); } catch (e) {}
    }
    this._h2Pool = {};

    // The pools client.js keeps on the agent for HTTP/2 sessions and HTTP/1.1
    // sockets. destroy() left them open: a destroyed agent kept its sockets.
    if (this._h2ClientPool) { try { this._h2ClientPool.destroy(); } catch (e) {} this._h2ClientPool = null; }
    if (this._h1ClientPool) { try { this._h1ClientPool.destroy(); } catch (e) {} this._h1ClientPool = null; }

    this._protocolCache = {};
    this._altSvc = {};
    this._activeCounts = {};
    this._sessionCache.clear();
    this._tokenCache.clear();
    this._echCache.clear();
  }
}


var globalAgent = new Agent();

export { Agent, globalAgent, tlsIdentity };
