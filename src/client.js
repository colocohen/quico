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

import nodeHttps from 'node:https';
import nodeHttp2 from 'node:http2';
import { URL } from 'node:url';

import { request as h3Request } from './h3_client.js';
import { ClientRequest, IncomingMessage } from './streams.js';
import { globalAgent } from './agent.js';


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

  // ---- Create ClientRequest (returned immediately) ----
  var clientReq = new ClientRequest({
    method: method,
    path: path,
    hostname: hostname,
    port: port,
    headers: headers,
    _responseCallback: callback
  });

  // Track if response was already delivered (prevent double-delivery)
  var responded = false;
  var _fallbackTimer = null;

  // ---- Wait for body if needed, then connect ----
  var bodyReady = (method === 'GET' || method === 'HEAD');

  if (!bodyReady) {
    clientReq.once('_bodyReady', function () {
      bodyReady = true;
      maybeConnect();
    });
  }

  process.nextTick(function () { maybeConnect(); });

  function maybeConnect() {
    if (method !== 'GET' && method !== 'HEAD' && !bodyReady) return;
    doProtocolSelection();
  }


  // ============================================================
  //  Build fallback chain based on flags + cache
  // ============================================================

  function doProtocolSelection() {
    var cached = agent ? agent.getProtocol(hostname, port) : null;

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
  function runChain(chain, index) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;
    if (index >= chain.length) {
      // All protocols failed
      clientReq.emit('error', new Error('All protocols failed for ' + hostname + ':' + port));
      return;
    }

    chain[index](function onFail(err) {
      if (responded) return;
      runChain(chain, index + 1);
    });
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

    // Try H3
    tryH3(function onFail(err) {
      clearTimeout(timer);
      if (!h3Done && !responded) {
        h3Done = true;
        runChain(chain.slice(1), 0);
      }
    });
  }


  // ============================================================
  //  H3 transport (wraps existing h3_client.js)
  // ============================================================

  function tryH3(onFail) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;

    try {
      var h3Opts = {
        hostname: hostname,
        port: port,
        path: path,
        method: method,
        headers: Object.assign({}, headers)
      };

      // Check Agent for existing QUIC connection (multiplexing).
      // With an agent, the connection's lifecycle is owned by the pool
      // (sweep / idle timer / agent.destroy), so signal h3_client not to
      // auto-close it when this request finishes — otherwise the first
      // request would tear down a connection still pooled for reuse.
      if (agent) {
        h3Opts._managed = true;
        var existing = agent.getH3Connection(hostname, port);
        if (existing) h3Opts._connection = existing;
      }

      var h3Req = h3Request(h3Opts, function (h3Res) {
        if (responded) return;

        // Store connection for future reuse
        if (agent && h3Req._connection && !h3Opts._connection) {
          agent.setH3Connection(hostname, port, h3Req._connection);
        }

        var res = new IncomingMessage({
          httpVersion: '3.0',
          statusCode: h3Res.statusCode,
          statusMessage: '',
          headers: h3Res.headers || {}
        });

        clientReq.protocol = 'h3';
        if (agent) agent.setProtocol(hostname, port, 'h3');

        h3Res.on('data', function (chunk) { res._pushData(chunk); });
        h3Res.on('end', function () { res._endData(); });
        h3Res.on('error', function (err) { res._abort(err); });

        deliverResponse(res);
      });

      h3Req.on('error', function (err) {
        onFail(err);
      });

      var body = clientReq._getBody();
      if (body) h3Req.write(body);
      h3Req.end();

    } catch (err) {
      onFail(err);
    }
  }


  // ============================================================
  //  H2 transport (node:http2)
  // ============================================================

  function tryH2(onFail) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;

    try {
      var session = agent ? agent.getH2Session(hostname, port) : null;

      if (!session) {
        var authority = 'https://' + hostname + ':' + port;
        session = nodeHttp2.connect(authority, {
          rejectUnauthorized: options.rejectUnauthorized !== false
        });

        session.on('error', function (err) {
          onFail(err);
        });

        if (agent) agent.setH2Session(hostname, port, session);
      }

      var h2Headers = {
        ':method': method,
        ':path': path,
        ':authority': hostname,
        ':scheme': 'https'
      };
      for (var name in headers) {
        if (name[0] !== ':') h2Headers[name.toLowerCase()] = headers[name];
      }

      var h2Req = session.request(h2Headers);

      h2Req.on('response', function (responseHeaders) {
        if (responded) return;

        var statusCode = responseHeaders[':status'] || 200;
        var flatHeaders = {};
        for (var k in responseHeaders) {
          if (k[0] !== ':') flatHeaders[k] = responseHeaders[k];
        }

        // Alt-Svc discovery
        if (agent && flatHeaders['alt-svc']) {
          agent.parseAltSvc(hostname, port, flatHeaders['alt-svc']);
        }

        var res = new IncomingMessage({
          httpVersion: '2.0',
          statusCode: statusCode,
          headers: flatHeaders
        });

        clientReq.protocol = 'h2';
        if (agent) agent.setProtocol(hostname, port, 'h2');

        h2Req.on('data', function (chunk) { res._pushData(chunk); });
        h2Req.on('end', function () { res._endData(); });
        h2Req.on('error', function (err) { res._abort(err); });

        deliverResponse(res);
      });

      h2Req.on('error', function (err) {
        onFail(err);
      });

      var body = clientReq._getBody();
      if (body) h2Req.write(Buffer.from(body));
      h2Req.end();

    } catch (err) {
      onFail(err);
    }
  }


  // ============================================================
  //  HTTPS transport (node:https — HTTP/1.1)
  // ============================================================

  function tryHttps(onFail) {
    if (responded || clientReq.destroyed || clientReq.aborted) return;

    try {
      var httpsOpts = {
        hostname: hostname,
        port: port,
        path: path,
        method: method,
        headers: Object.assign({}, headers),
        rejectUnauthorized: options.rejectUnauthorized !== false
      };

      var httpsReq = nodeHttps.request(httpsOpts, function (httpsRes) {
        if (responded) return;

        if (agent && httpsRes.headers['alt-svc']) {
          agent.parseAltSvc(hostname, port, httpsRes.headers['alt-svc']);
        }

        var res = new IncomingMessage({
          httpVersion: httpsRes.httpVersion || '1.1',
          statusCode: httpsRes.statusCode,
          statusMessage: httpsRes.statusMessage || '',
          headers: httpsRes.headers || {}
        });

        clientReq.protocol = 'https';
        if (agent) agent.setProtocol(hostname, port, 'https');

        httpsRes.on('data', function (chunk) { res._pushData(chunk); });
        httpsRes.on('end', function () { res._endData(); });
        httpsRes.on('error', function (err) { res._abort(err); });

        deliverResponse(res);
      });

      httpsReq.on('error', function (err) {
        onFail(err);
      });

      var body = clientReq._getBody();
      if (body) httpsReq.write(Buffer.from(body));
      httpsReq.end();

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
