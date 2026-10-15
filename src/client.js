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

import { URL } from 'node:url';
import lemonTls from 'lemon-tls';

import { request as h3Request } from './h3_client.js';
import { request as h2Request, H2Pool } from './h2_client.js';
import { request as h1Request, H1Pool } from './h1_client.js';
import { ClientRequest, IncomingMessage } from './streams.js';
import { creditAsRead } from './utils.js';
import { globalAgent, tlsIdentity } from './agent.js';


// ============================================================
//  Unified request(url, options, callback)
//
//  Mirrors node:https.request() signature.
//  Returns a ClientRequest (Writable stream).
//
//  HTTP/3 is always tried first. Fallback chain depends on flags:
//    options.http2 (default: agent.http2 or true)
//    options.http1 (default: agent.http1 or true)
// ============================================================

/**
 * The agent's H2 and H1 pools, created on first use.
 *
 * They are deliberately different objects with different shapes — see the note
 * at the top of h2_client.js. H2 maps an origin to ONE session and gets
 * concurrency from streams; H1 maps an origin to a LIST of sockets and gets
 * concurrency from more sockets. agent.js already kept _h2Pool and _h3Pool
 * separate for the same reason.
 */
function agentH2Pool(agent) {
  if (!agent._h2ClientPool) agent._h2ClientPool = new H2Pool({});
  return agent._h2ClientPool;
}

function agentH1Pool(agent) {
  if (!agent._h1ClientPool) {
    // node:http.Agent's options, with Node's meanings. keepAliveMsecs used to
    // be passed as the idle timeout; in Node it is the TCP keep-alive delay,
    // and how long a free socket is kept is the agent's `timeout`.
    agent._h1ClientPool = new H1Pool({
      maxSockets: agent.maxSockets,
      keepAlive: agent.keepAlive,
      maxFreeSockets: agent.maxFreeSockets,
      keepAliveMsecs: agent.keepAliveMsecs,
      idleTimeout: agent.timeout != null ? agent.timeout : undefined
    });
  }
  return agent._h1ClientPool;
}


function request(url, options, callback) {

  // ---- Normalize arguments (same overloads as node:https) ----
  if (typeof url === 'string') {
    var parsed = new URL(url);
    var fromUrl = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port ? parseInt(parsed.port) : 443,
      path: parsed.pathname + parsed.search
    };
    if (typeof options === 'function') {
      callback = options;
      options = fromUrl;
    } else {
      options = Object.assign(fromUrl, options || {});
    }
  } else if (typeof url === 'object') {
    if (typeof options === 'function') { callback = options; }
    options = url;
  }

  options = options || {};

  var hostname = options.hostname || options.host || 'localhost';
  // Strip port suffix from host (e.g. "example.com:443")
  var colonIdx = hostname.lastIndexOf(':');
  if (colonIdx > 0) {
    var afterColon = hostname.substring(colonIdx + 1);
    if (/^\d+$/.test(afterColon)) {
      if (!options.port) options.port = parseInt(afterColon);
      hostname = hostname.substring(0, colonIdx);
    }
  }

  var port = parseInt(options.port) || 443;
  var method = (options.method || 'GET').toUpperCase();
  var path = options.path || '/';
  var headers = options.headers || {};
  var agent = options.agent !== undefined ? options.agent : globalAgent;
  // The agent's connections, to reuse — those opened with this request's TLS
  // identity (ca, client certificate, rejectUnauthorized, servername), as
  // node:https names them (agent.js tlsIdentity): a connection opened without
  // verification, or with another certificate, does not carry this one.
  // The key-exchange groups to offer (tls.connect's ecdhCurve): the
  // request's, or its agent's. Checked now — a name not implemented throws
  // here, as tls.connect does — and part of which connections it may share.
  if (options.ecdhCurve == null && agent && agent.ecdhCurve != null) options = Object.assign({}, options, { ecdhCurve: agent.ecdhCurve });
  if (options.ecdhCurve != null) lemonTls.parseEcdhCurve(options.ecdhCurve);
  // The signature schemes to offer (tls.connect's sigalgs), the same way.
  if (options.sigalgs == null && agent && agent.sigalgs != null) options = Object.assign({}, options, { sigalgs: agent.sigalgs });
  if (options.sigalgs != null) lemonTls.parseSigalgs(options.sigalgs);
  var pool = agent;
  var poolHost = hostname + '#' + tlsIdentity(options);

  // The TLS session to resume with on a new connection over `transport`
  // ('quic' or 'tcp'): the caller's `session` (https.request's), or the
  // agent's latest for this origin — and the agent keeps each new one the
  // server sends (the request's 'session' event), as node:https.Agent does.
  // A session the handshake then fails with is dropped (Node's
  // _evictSession), so the next connection starts afresh.
  //
  // Taken from the agent only when a connection is actually made (the
  // getter, read by the transport at connect): a request on a pooled
  // connection uses none, and each session is used once (agent.js). TCP's
  // are kept per ALPN — 'tcp:h2', 'tcp:http/1.1' — since each path offers
  // one, and a ticket can carry 0-RTT only for the protocol it was issued
  // under: an HTTP/2 ticket offered to the HTTP/1.1 path resumed without it.
  // Each session the server sends is also the request's 'session' event, as
  // on node:https.
  function tlsSession(transport, sessPort) {
    var key = (pool && typeof pool._sessionKey === 'function') ? pool._sessionKey(transport, hostname, sessPort, options) : null;
    var taken = false, offered;
    function take() {
      if (options.session) return options.session;
      if (!taken) { taken = true; offered = key ? (pool._takeSession ? pool._takeSession(key) : pool._getSession(key)) : undefined; }
      return offered;
    }
    return {
      // Defines `session` on the transport's options, read at connect.
      into: function (o) { Object.defineProperty(o, 'session', { configurable: true, enumerable: true, get: take }); return o; },
      keep: function (req) {
        req.on('session', function (s) {
          if (key) pool._cacheSession(key, s);
          clientReq.emit('session', s);
        });
      },
      failed: function () { if (key && taken && offered && !options.session) pool._evictSession(key); }
    };
  }

  // ---- Resolve protocol flags: options → agent → true ----
  var enableH2 = options.http2 !== undefined ? options.http2
               : (agent && agent.http2 !== undefined) ? agent.http2
               : true;
  var enableH1 = options.http1 !== undefined ? options.http1
               : (agent && agent.http1 !== undefined) ? agent.http1
               : true;

  var h3Timeout = options.h3Timeout
               || (agent && agent.h3Timeout)
               || 3000;

  // ---- Encrypted Client Hello (RFC 9849) ----
  // options.ech: the server's ECHConfigList (bytes, or base64 — the `ech=`
  // of its DNS HTTPS record): the real ClientHello, with the name, goes
  // encrypted, on every version. Rejected by a server that sent new keys,
  // the request is tried once more with them (it was never sent: ECH fails
  // before the handshake completes). Without a config, GREASE ECH — as the
  // browsers send, so that a client with one does not stand out — unless
  // echGrease is false.
  //
  // The keys a server sent on rejecting the caller's (retry_configs) are
  // kept by the agent (_getEchRetry) and used first on the next requests
  // given the same config: a server that rotated its keys cost a rejection
  // and a retry on every connection until the caller's DNS had the new
  // ones. Kept keys rejected in their turn are forgotten, and the caller's
  // config tried again — whose rejection may bring new keys; a rejection of
  // a connection made with retry_configs never does (RFC 9849 §6.1.6:
  // "Clients SHOULD NOT accept retry_config in response to a connection
  // initiated in response to a retry_config").
  var echOriginal = options.ech || null;
  var echKey = (echOriginal && agent && typeof agent._getEchRetry === 'function') ? agent._sessionKey('ech', hostname, port, options) : null;
  var echKept = echKey ? agent._getEchRetry(echKey) : null;
  var echConfig = echKept || echOriginal;
  var echRetried = false;
  var echGrease = !echConfig && options.echGrease !== false;

  // ---- Create ClientRequest (returned immediately) ----
  var clientReq = new ClientRequest({
    method: method,
    path: path,
    hostname: hostname,
    port: port,
    headers: headers,
    _responseCallback: callback
  });

  // RFC 9218: the request's priority, from the start (setPriority changes it).
  if (options.priority) clientReq.setPriority(options.priority);

  // Track if response was already delivered (prevent double-delivery)
  var responded = false;
  var _fallbackTimer = null;

  // ---- Connect at once; the body follows as it is written ----
  // It waited for end(): a body was held whole in memory, and nothing went
  // out — not even the connection was begun — until it was complete.
  process.nextTick(function () { doProtocolSelection(); });

  // ---- The transport that carries the request ----
  // Several may be tried at once (HTTP/3, and TCP after h3Timeout), and the
  // first to be ready to send takes the request (claim, from each
  // transport's onReady): the body goes to it, and to it only. One ready
  // later is turned down and sends nothing ('superseded'). Both used to
  // send it — the timer that starts TCP ran until the RESPONSE, so a POST
  // whose answer took HTTP/3 more than h3Timeout went to the server twice.
  var owner = null;
  function attempt(name) { return { name: name, req: null }; }
  function claim(token) {
    if (responded || clientReq.destroyed || clientReq.aborted) return false;
    if (owner) return owner === token;
    owner = token;
    // HTTP/3 has it: no TCP attempt is needed any more.
    if (token.name === 'h3' && _fallbackTimer) { clearTimeout(_fallbackTimer); _fallbackTimer = null; }
    if (token.req) clientReq._attachSink(token.req);
    return true;
  }
  // The transport's request exists (claim may have come from inside it,
  // a pooled connection being ready at once): the body to it if it has it.
  function bind(token, req) {
    token.req = req;
    if (owner === token) clientReq._attachSink(req);
  }
  // The attempt failed. If it carried the request, the body comes back for
  // another — unless more of it went than was kept (ClientRequest's
  // REPLAY_MAX): then no other can carry it, and the request fails.
  function release(token) {
    if (owner !== token) return true;
    if (!clientReq._detachSink()) return false;
    owner = null;
    return true;
  }
  function failOver(token, err, again, onFail) {
    if (!release(token)) { if (!responded) clientReq.emit('error', err); return; }
    if (again && retryUnprocessed(err, again)) return;
    onFail(err);
  }


  // ============================================================
  //  Build fallback chain based on flags + cache
  // ============================================================

  function doProtocolSelection() {
    var cached = agent ? agent.getProtocol(hostname, port) : null;

    // The origin advertised HTTP/3 (Alt-Svc): try it first, at the advertised
    // port, whatever worked here before — that is how a client that met the
    // origin over TCP moves to HTTP/3. Should the alternative fail, it is
    // marked broken for a while and the request goes on over TCP.
    var alt = agent && agent.getAltSvc ? agent.getAltSvc(hostname, port) : null;
    if (alt && alt.port !== port) {
      var tryAlt = function (onFail) {
        tryH3(function (err) { agent.markAltSvcBroken(hostname, port); onFail(err); }, alt.port);
      };
      // Then the origin itself: over TCP as it last worked, and over HTTP/3 at
      // its own port — an origin that answered over HTTP/3 may have sent the
      // advertisement.
      var rest = [];
      if (cached === 'https' && enableH1) { rest.push(tryHttps); if (enableH2) rest.push(tryH2); }
      else { if (enableH2) rest.push(tryH2); if (enableH1) rest.push(tryHttps); }
      if (cached === 'h3') rest.unshift(tryH3); else rest.push(tryH3);
      runChainWithH3Timeout([tryAlt].concat(rest), h3Timeout);
      return;
    }

    // Build ordered fallback chain
    // H3 is always first (that's the point of quico)
    var chain = [tryH3];
    if (enableH2) chain.push(tryH2);
    if (enableH1) chain.push(tryHttps);

    // If we have a cached protocol, try it first (skip discovery)
    if (cached === 'h3') {
      runChain(chain, 0);
    } else if (cached === 'h2' && enableH2) {
      runChain([tryH2, tryH3, enableH1 ? tryHttps : null].filter(Boolean), 0);
    } else if (cached === 'https' && enableH1) {
      runChain([tryHttps, tryH3, enableH2 ? tryH2 : null].filter(Boolean), 0);
    } else {
      // No cache — H3 first with timeout, then fallbacks
      runChainWithH3Timeout(chain, h3Timeout);
    }
  }

  /**
   * Run through the fallback chain. If step N fails, try step N+1.
   */
  function runChain(chain, index, lastErr) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;
    if (index >= chain.length) {
      // All protocols failed — the last one's reason as the `cause`; it was
      // dropped, and "all protocols failed" was all a caller could learn.
      clientReq.emit('error', new Error('All protocols failed for ' + hostname + ':' + port, lastErr ? { cause: lastErr } : undefined));
      return;
    }

    chain[index](function onFail(err) {
      if (responded) return;
      if (isRequestError(err)) { clientReq.emit('error', err); return; }
      runChain(chain, index + 1, err);
    });
  }

  // An error about the request itself — not about reaching the server over
  // one protocol — fails the request as it is: another protocol would only
  // send the same faulty request again, and the caller would be told "all
  // protocols failed" instead of what is wrong.
  // ECH rejected (after the one retry with new keys, or with none offered)
  // ends the request with that reason: the same server, proven for its
  // public name, would decline it over every protocol — and "all protocols
  // failed" would hide why.
  function isRequestError(err) {
    return !!(err && (err.requestError || err.code === 'ERR_ECH_REJECTED'));
  }

  /**
   * Special first-run: try H3 with a timeout.
   * If H3 doesn't connect in time, start fallbacks in parallel.
   */
  function runChainWithH3Timeout(chain, timeout) {
    if (chain.length <= 1) {
      // H3 only, no fallback — just run it
      runChain(chain, 0);
      return;
    }

    var h3Done = false;
    var timer = setTimeout(function () {
      if (!h3Done && !responded) {
        h3Done = true;
        // H3 timed out — try rest of chain
        runChain(chain.slice(1), 0);
      }
    }, timeout);
    _fallbackTimer = timer;
    if (timer.unref) timer.unref(); // Don't prevent process exit

    // Try H3 (the chain's first step)
    chain[0](function onFail(err) {
      clearTimeout(timer);
      if (isRequestError(err) && !responded) { h3Done = true; clientReq.emit('error', err); return; }
      if (!h3Done && !responded) {
        h3Done = true;
        runChain(chain.slice(1), 0, err);
      }
    });
  }


  // ============================================================
  //  H3 transport (wraps existing h3_client.js)
  // ============================================================

  // h3Port: where to try HTTP/3 — the origin's own port unless an Alt-Svc
  // alternative is being tried.
  // A request the server did not process — refused (HTTP/2's
  // REFUSED_STREAM, HTTP/3's H3_REQUEST_REJECTED) or past its GOAWAY — may be
  // sent again (RFC 9113 §8.7, RFC 9114 §4.1.1, §5.2): once, on the same
  // protocol, so a new connection. It fell to the next protocol in the
  // chain, or with none left failed — a server that closes its connections
  // after N requests (maxRequestsPerSocket) failed the requests in flight
  // as it did. The body is back here (release), whole — or the request fails.
  var retriedUnprocessed = false;
  // TLS early data (HTTP/2, HTTP/1.1): what became of it — the transport's
  // word, or 'rejected' when a 425 sent the request again after the handshake.
  var tooEarlyRetried = false;
  function earlyOutcome(transportReq) {
    if (tooEarlyRetried) return 'rejected';
    return transportReq && transportReq.earlyData ? transportReq.earlyData : null;
  }

  function retryUnprocessed(err, again) {
    if (err && err.code === 'ERR_HTTP_TOO_EARLY') tooEarlyRetried = true;
    // ECH rejected, with the server's current keys (lemon-tls's
    // ERR_ECH_REJECTED): once more, with them. A rejection without keys is
    // the server's ECH turned off — going on without ECH is the caller's
    // decision, so it fails.
    if (err && err.code === 'ERR_ECH_REJECTED' && echKept &&
        !responded && !clientReq.destroyed && !clientReq.aborted) {
      agent._evictEchRetry(echKey);
      echKept = null;
      echConfig = echOriginal;
      process.nextTick(function () {
        if (responded || clientReq.destroyed || clientReq.aborted) return;
        again();
      });
      return true;
    }
    if (err && err.code === 'ERR_ECH_REJECTED' && err.retryConfigs && !echRetried &&
        !responded && !clientReq.destroyed && !clientReq.aborted) {
      echRetried = true;
      echConfig = err.retryConfigs;
      process.nextTick(function () {
        if (responded || clientReq.destroyed || clientReq.aborted) return;
        again();
      });
      return true;
    }
    if (!err || !err.retryable || retriedUnprocessed) return false;
    if (responded || clientReq.destroyed || clientReq.aborted) return false;
    retriedUnprocessed = true;
    // After the event that failed it has reached every listener — the
    // agent's among them, which takes the connection out of its pool; run
    // inside it, the retry was handed the same GOAWAY'd connection.
    process.nextTick(function () {
      if (responded || clientReq.destroyed || clientReq.aborted) return;
      again();
    });
    return true;
  }

  // res.socket over HTTP/3: there is no TLS socket — the handshake ran in
  // the QUIC connection — so what an application asks a TLSSocket for here
  // is answered from that connection: as over HTTP/2 and HTTP/1.1, whose
  // res.socket is the lemon-tls socket.
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

  function tryH3(onFail, h3Port) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;
    h3Port = h3Port || port;

    try {
      var h3Opts = {
        hostname: hostname,
        port: h3Port,
        path: path,
        method: method,
        headers: Object.assign({}, headers),
        // The H2 and HTTPS fallbacks below honour this; dropping it here made
        // H3 — alone of the three — unable to talk to self-signed or
        // private-CA servers, and every such request silently fell back to
        // TCP (or hung when the server was QUIC-only).
        rejectUnauthorized: options.rejectUnauthorized,
        ca: options.ca,
        // The name for SNI and the certificate check, as over TCP (tls.connect's
        // servername) — HTTP/3 used the hostname whatever was given, so a
        // request to an address with a name of its own worked over TCP alone.
        servername: options.servername,
        key: options.key, cert: options.cert, passphrase: options.passphrase,
        requestOCSP: options.requestOCSP === true,
        ech: echConfig, echGrease: echGrease, ecdhCurve: options.ecdhCurve, sigalgs: options.sigalgs,
        startupCap: options.startupCap, pmtuDiscovery: options.pmtuDiscovery,
        maxUdpPayloadSize: options.maxUdpPayloadSize, initialRtt: options.initialRtt,
        reorderWindow: options.reorderWindow, initialCongestionWindow: options.initialCongestionWindow,
        // 0-RTT with the saved session (below), off unless asked for.
        earlyData: options.earlyData === true
      };
      h3Opts.quicVersions = options.quicVersions;
      var sess = tlsSession('quic', h3Port);
      sess.into(h3Opts);
      // The server's NEW_TOKEN token from the last connection, used once.
      var tokenKey = (pool && typeof pool._takeToken === 'function') ? pool._sessionKey('quic', hostname, h3Port, options) : null;

      // Check Agent for existing QUIC connection (multiplexing).
      // With an agent, the connection's lifecycle is owned by the pool
      // (sweep / idle timer / agent.destroy), so signal h3_client not to
      // auto-close it when this request finishes — otherwise the first
      // request would tear down a connection still pooled for reuse.
      if (pool) {
        h3Opts._managed = true;
        var existing = pool.getH3Connection(poolHost, h3Port);
        if (existing) {
          h3Opts._connection = existing;
        } else if (pool.joinH3Pending &&
                   pool.joinH3Pending(poolHost, h3Port, function () {
                     // The lead settled. Retry from the top: on success the
                     // pool lookup now hits and we multiplex on the lead's
                     // connection; on failure we become the next lead — a
                     // serial retry, never a thundering herd.
                     tryH3(onFail, h3Port);
                   })) {
          return; // parked as a follower until the lead settles
        }
        // else: we are the LEAD for this origin. _settleH3Pending below MUST
        // run on every exit path, or followers park forever.
      }

      var _pendingLead = !!(pool && !h3Opts._connection);
      function _settleH3Pending(conn) {
        if (!_pendingLead) return;
        _pendingLead = false;
        if (pool.resolveH3Pending) pool.resolveH3Pending(poolHost, h3Port, conn);
        else if (conn) pool.setH3Connection(poolHost, h3Port, conn);
      }

      if (tokenKey && !h3Opts._connection) h3Opts.token = pool._takeToken(tokenKey);
      var token = attempt('h3');
      h3Opts.onReady = function () { return claim(token); };
      var h3Req = h3Request(h3Opts, function (h3Res) {
        if (responded) return;

        // Register the connection and wake coalesced followers.
        if (h3Req._connection && !h3Opts._connection) {
          _settleH3Pending(h3Req._connection);
        }

        var res = new IncomingMessage({
          httpVersion: '3.0',
          statusCode: h3Res.statusCode,
          statusMessage: '',
          headers: h3Res.headers || {},
          socket: h3SocketInfo(h3Req._connection || h3Opts._connection)
        });
        // 0-RTT: 'accepted', 'rejected' (it went again after the handshake), or null.
        res.earlyData = h3Res.earlyData != null ? h3Res.earlyData : null;

        clientReq.protocol = 'h3';
        // "HTTP/3 works at the origin's own port" — not true of an alternative
        // elsewhere, which Alt-Svc already records.
        if (agent && h3Port === port) agent.setProtocol(hostname, port, 'h3');
        // An HTTP/3 response may carry Alt-Svc too (a change, or `clear`).
        if (agent && h3Res.headers && h3Res.headers['alt-svc']) {
          agent.parseAltSvc(hostname, port, h3Res.headers['alt-svc']);
        }

        // Credit for what the application has read, not for what arrived
        // (utils' creditAsRead), as the server does with request bodies: the
        // server sends no faster than this response is consumed.
        var received = null;
        if (typeof h3Res._holdBody === 'function') {
          h3Res._holdBody();
          received = creditAsRead(res, function (n) { h3Res._creditBody(n); });
          res.on('close', function () { h3Res._releaseBody(); });
        }
        h3Res.on('data', function (chunk) { if (received) received(chunk.length); res._pushData(chunk); });
        h3Res.on('end', function () {
          // Trailers arrive before the end (gRPC's grpc-status): on res by 'end'.
          if (h3Res.trailers && Object.keys(h3Res.trailers).length) {
            res.trailers = h3Res.trailers;
            res.rawTrailers = h3Res.rawTrailers || [];
          }
          res._endData();
        });
        h3Res.on('error', function (err) { res._abort(err); });

        deliverResponse(res);
      });

      sess.keep(h3Req);
      if (tokenKey) h3Req.on('newToken', function (t) { pool._cacheToken(tokenKey, t); });
      // tls.connect's requestOCSP: the server's stapled response, on this request.
      h3Req.on('OCSPResponse', function (r) { clientReq.emit('OCSPResponse', r); });
      // 1xx (103 Early Hints): node:http's 'information', on every version.
      h3Req.on('information', function (info) { clientReq.emit('information', info); });
      h3Req.on('error', function (err) {
        if (!h3Opts._connection && !err.retryable) sess.failed();
        _settleH3Pending(null);   // release followers before failing over
        failOver(token, err, function () { tryH3(onFail, h3Port); }, onFail);
      });
      // Another protocol had the request first: this connection is kept for
      // the pool (and the requests parked behind it), and nothing is sent.
      h3Req.on('superseded', function () { _settleH3Pending(h3Req._connection || null); });
      // req.destroy(): cancel this attempt's stream. A pool lead hands its
      // connection (if it has one yet) to the requests parked behind it.
      clientReq._onCancel(function () {
        _settleH3Pending(h3Req._connection || null);
        h3Req.destroy();
      });

      bind(token, h3Req);

    } catch (err) {
      if (typeof _settleH3Pending === 'function') _settleH3Pending(null);
      onFail(err);
    }
  }


  // ============================================================
  //  H2 transport (ours)
  //
  //  Was node:http2. h2_client speaks the same shape — an emitter that emits
  //  'response' with an IncomingMessage — so the fallback chain around it is
  //  unchanged. Sessions are pooled and coalesced per origin by the agent, the
  //  same way H3 connections are.
  // ============================================================

  // agent: false (or null) — node:https's meaning: a connection of this
  // request's own, closed when it is done. HTTP/2 and HTTP/1.1 fell back
  // to their modules' shared pools instead: a request with agent: false
  // went on another's connection, kept open after it (and its `session`
  // option, read only when a connection is made, was never used).
  function oneOffH2() {
    var p = new H2Pool({});
    function done() { setImmediate(function () { p.destroy(); }); }
    clientReq.once('response', function (res) { res.once('end', done); res.once('close', done); });
    clientReq.once('error', done);
    clientReq.once('close', done);
    return p;
  }

  function tryH2(onFail) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;

    try {
      var sess = tlsSession('tcp:h2', port);
      var token = attempt('h2');
      var h2Req = h2Request(sess.into({
        onReady: function () { return claim(token); },
        hostname: hostname,
        port: port,
        path: path,
        method: method,
        headers: Object.assign({}, headers),
        tls: lemonTls,
        ca: options.ca,
        rejectUnauthorized: options.rejectUnauthorized,
        servername: options.servername,
        key: options.key, cert: options.cert, passphrase: options.passphrase,
        requestOCSP: options.requestOCSP === true,
        ech: echConfig, echGrease: echGrease, ecdhCurve: options.ecdhCurve, sigalgs: options.sigalgs,
        // One session per origin, shared with every other request through this
        // agent — that is what multiplexing means and why the H1 pool cannot
        // be reused here.
        pool: pool ? agentH2Pool(pool) : oneOffH2(),
        // 0-RTT over TLS (see h2_client); not again after a 425.
        earlyData: options.earlyData === true && !tooEarlyRetried
      }), function (res) {
        if (responded) return;

        if (agent && res.headers['alt-svc']) {
          agent.parseAltSvc(hostname, port, res.headers['alt-svc']);
        }

        clientReq.protocol = 'h2';
        if (agent) agent.setProtocol(hostname, port, 'h2');
        res.earlyData = earlyOutcome(h2Req);
        deliverResponse(res);
      });

      sess.keep(h2Req);
      h2Req.on('OCSPResponse', function (r) { clientReq.emit('OCSPResponse', r); });
      h2Req.on('information', function (info) { clientReq.emit('information', info); });
      h2Req.on('error', function (err) {
        if (!err.retryable) sess.failed();
        failOver(token, err, function () { tryH2(onFail); }, onFail);
      });
      clientReq._onCancel(function () { h2Req.destroy(); });   // RST_STREAM (CANCEL)

      bind(token, h2Req);

    } catch (err) {
      onFail(err);
    }
  }


  // ============================================================
  //  HTTPS transport (ours — HTTP/1.1 over lemon-tls)
  // ============================================================

  function tryHttps(onFail) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;

    try {
      var sess = tlsSession('tcp:http/1.1', port);
      var token = attempt('https');
      var httpsReq = h1Request(sess.into({
        onReady: function () { return claim(token); },
        hostname: hostname,
        port: port,
        path: path,
        method: method,
        headers: Object.assign({}, headers),
        tls: lemonTls,
        ca: options.ca,
        rejectUnauthorized: options.rejectUnauthorized,
        servername: options.servername,
        key: options.key, cert: options.cert, passphrase: options.passphrase,
        requestOCSP: options.requestOCSP === true,
        ech: echConfig, echGrease: echGrease, ecdhCurve: options.ecdhCurve, sigalgs: options.sigalgs,
        pool: pool ? agentH1Pool(pool) : new H1Pool({ keepAlive: false }),
        earlyData: options.earlyData === true && !tooEarlyRetried
      }), function (res) {
        if (responded) return;

        if (agent && res.headers['alt-svc']) {
          agent.parseAltSvc(hostname, port, res.headers['alt-svc']);
        }

        clientReq.protocol = 'https';
        if (agent) agent.setProtocol(hostname, port, 'https');
        res.earlyData = earlyOutcome(httpsReq);
        deliverResponse(res);
      });

      sess.keep(httpsReq);
      httpsReq.on('OCSPResponse', function (r) { clientReq.emit('OCSPResponse', r); });
      httpsReq.on('information', function (info) { clientReq.emit('information', info); });
      // A retryable failure (425 Too Early to a request sent in TLS early
      // data) goes again, as over HTTP/2; anything else falls over.
      httpsReq.on('error', function (err) {
        if (!err.retryable) sess.failed();
        failOver(token, err, err.retryable ? function () { tryHttps(onFail); } : null, onFail);
      });
      clientReq._onCancel(function () { httpsReq.destroy(); });   // the socket goes

      bind(token, httpsReq);

    } catch (err) {
      onFail(err);
    }
  }


  // ============================================================
  //  Deliver response
  // ============================================================

  function deliverResponse(res) {
    if (responded) return;
    responded = true;
    // The server's new ECH keys worked: kept for the next requests.
    if (echRetried && echKey) agent._cacheEchRetry(echKey, echConfig);
    clientReq.res = res;
    // The application destroying the response mid-way gives the request up
    // with it — the stream cancelled (STOP_SENDING and RESET_STREAM over
    // HTTP/3, RST_STREAM over HTTP/2), the socket over HTTP/1.1 — as
    // node:http's res.destroy() destroys the socket. The rest of the body
    // kept coming, at full speed, into a response nobody read.
    if (typeof res._onDestroy === 'function') res._onDestroy(function () { if (!res.complete && !clientReq.destroyed) clientReq.destroy(); });

    if (clientReq._timeoutTimer) {
      clearTimeout(clientReq._timeoutTimer);
      clientReq._timeoutTimer = null;
    }
    if (_fallbackTimer) {
      clearTimeout(_fallbackTimer);
      _fallbackTimer = null;
    }

    clientReq.emit('response', res);
    if (clientReq._responseCallback) clientReq._responseCallback(res);
  }


  // ---- Auto-end GET/HEAD on next tick ----
  if (method === 'GET' || method === 'HEAD') {
    process.nextTick(function () {
      if (!clientReq.finished && !clientReq.writableEnded) {
        clientReq.end();
      }
    });
  }

  return clientReq;
}


// ============================================================
//  get() — convenience for GET requests
// ============================================================

function get(url, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof url === 'object' && !options) { options = url; url = undefined; }
  var opts = url ? { method: 'GET' } : Object.assign({}, options, { method: 'GET' });
  var req = url ? request(url, opts, callback) : request(opts, callback);
  return req;
}


export { request, get };
