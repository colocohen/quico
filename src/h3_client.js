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

import dns from 'node:dns';
import { DEBUG } from './utils.js';
import { H3Connection } from './h3.js';
import { createQuicClientSocket } from './quic_socket.js';


// ============================================================
//  quico.request(options, callback)
//  API mirrors Node.js https.request()
// ============================================================

function request(options, callback) {
  if (typeof options === 'string') {
    var url = new URL(options);
    options = {
      hostname: url.hostname,
      port: parseInt(url.port) || 443,
      path: url.pathname + url.search
    };
  }

  var hostname = options.hostname || options.host || 'localhost';
  var port = options.port || 443;
  var path = options.path || '/';
  var method = (options.method || 'GET').toUpperCase();
  var headers = options.headers || {};

  // Connection reuse: pass _connection = { quic, h3, udpSocket, nextStreamId }
  var existingConn = options._connection || null;
  // Auto-close the QUIC connection when this request finishes ONLY when we own
  // it — i.e. a fresh, standalone connection. Reused connections (existingConn)
  // and connections whose lifecycle is managed by an external pool
  // (options._managed, set by the unified client/agent) are left open; closing
  // them here would tear down a connection still pooled for reuse. Managed
  // connections are reaped by the agent (sweep/destroy) and the QUIC idle timer.
  var autoClose = !existingConn && !options._managed;

  // ---- Client Request object ----
  var reqBody = [];
  var reqFinished = false;
  var reqListeners = {};
  var quic = existingConn ? existingConn.quic : null;
  var h3 = existingConn ? existingConn.h3 : null;
  var udpSocket = existingConn ? existingConn.udpSocket : null;
  var streamId = null; // assigned when connection is ready
  var connected = existingConn ? true : false;

  var clientReq = {
    on: function (event, fn) {
      (reqListeners[event] = reqListeners[event] || []).push(fn);
      return clientReq;
    },

    write: function (chunk) {
      if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
      reqBody.push(chunk);
      return true;
    },

    end: function (chunk) {
      if (chunk) clientReq.write(chunk);
      reqFinished = true;
      if (connected) sendRequest();
      return clientReq;
    },

    destroy: function () {
      if (quic) quic.close(0, 'client destroy');
      if (udpSocket) { try { udpSocket.close(); } catch (e) {} }
    }
  };

  // ---- Client Response object ----
  var clientRes = {
    statusCode: 0,
    headers: {},
    _listeners: {},
    _headersReceived: false,

    on: function (event, fn) {
      (clientRes._listeners[event] = clientRes._listeners[event] || []).push(fn);
      return clientRes;
    }
  };

  function emit(obj, event, data) {
    var listeners = (obj._listeners || obj)[event] || [];
    // For reqListeners which is a plain object
    if (obj === reqListeners) listeners = reqListeners[event] || [];
    for (var i = 0; i < listeners.length; i++) {
      try { if (data !== undefined) listeners[i](data); else listeners[i](); } catch (e) {}
    }
  }


  // ---- Resolve hostname and connect (or reuse existing) ----
  if (existingConn) {
    // Reuse existing connection — allocate stream ID and send when ready.
    // The shared dispatch listeners were installed when the connection was
    // first created; installSharedHandlers() is idempotent.
    streamId = allocateStreamId(existingConn);
    installSharedHandlers(existingConn);
    setupResponseHandlers(existingConn);
    if (reqFinished) sendRequest();
  } else {
    resolveAndConnect(hostname, port);
  }


  function resolveAndConnect(host, port) {
    // If already IP, skip DNS
    if (/^[\d.]+$/.test(host) || host.indexOf(':') >= 0 || host === 'localhost') {
      var ip = (host === 'localhost') ? '127.0.0.1' : host;
      startConnection(ip, port);
      return;
    }

    dns.lookup(host, function (err, address) {
      if (err) {
        emit(reqListeners, 'error', err);
        return;
      }
      startConnection(address, port);
    });
  }


  function startConnection(remoteIp, remotePort) {
    udpSocket = createQuicClientSocket({
      remoteIp: remoteIp,
      remotePort: remotePort,
      hostname: hostname,

      onError: function (err) {
        emit(reqListeners, 'error', err);
      },

      onConnect: function (q, s) {
        quic = q;
        udpSocket = s;
        if (DEBUG) console.log('[client] QUIC connected');

        h3 = new H3Connection({ quicConnection: quic, isServer: false });
        connected = true;

        // Build connection object for reuse
        var conn = { quic: quic, h3: h3, udpSocket: udpSocket, _nextStreamId: 0 };

        // Install the shared per-connection dispatch listeners ONCE, then
        // register this request in the connection's stream-handler map.
        installSharedHandlers(conn);
        streamId = allocateStreamId(conn);

        // Store on clientReq so caller (unified client) can reuse
        clientReq._connection = conn;

        setupResponseHandlers(conn);

        // Send request if body is ready
        if (reqFinished) sendRequest();
      }
      // onClose: the helper closes the UDP socket; nothing extra needed here.
    });
  }


  /**
   * Allocate next client-initiated bidi stream ID.
   * Client bidi stream IDs: 0, 4, 8, 12, ... (id = n * 4)
   */
  function allocateStreamId(conn) {
    var id = conn._nextStreamId;
    conn._nextStreamId += 4;
    return id;
  }


  /**
   * Install the three HTTP/3 event listeners ONCE per connection. They dispatch
   * each event to the right request via the connection's stream-handler map
   * (keyed by stream id), so multiplexing many requests over a single
   * connection does NOT pile up listeners on the H3 emitter (previously every
   * request added another set of listeners that were never removed).
   * Idempotent per connection.
   */
  function installSharedHandlers(conn) {
    if (conn._streamHandlers) return;  // already installed for this connection
    conn._streamHandlers = {};
    var h3c = conn.h3;

    h3c.on('http_headers', function (sid, hdrs) {
      var h = conn._streamHandlers[sid];
      if (h) h.onHeaders(hdrs);
    });
    h3c.on('http_body', function (sid, data) {
      var h = conn._streamHandlers[sid];
      if (h) h.onBody(data);
    });
    h3c.on('http_end', function (sid) {
      var h = conn._streamHandlers[sid];
      if (!h) return;
      delete conn._streamHandlers[sid];  // free per-stream state before dispatch
      h.onEnd();
    });
  }


  /**
   * Register this request's response handlers in the connection's stream map,
   * keyed by its streamId. Replaces per-request h3.on(...) registration —
   * routing is now by map key, so no per-listener streamId check is needed.
   */
  function setupResponseHandlers(conn) {
    conn._streamHandlers[streamId] = {
      onHeaders: function (hdrs) {
        clientRes.headers = hdrs;
        clientRes.statusCode = parseInt(hdrs[':status']) || 0;
        clientRes._headersReceived = true;

        // Fire callback with response (once)
        if (typeof callback === 'function') {
          callback(clientRes);
          callback = null;
        }
        emit(reqListeners, 'response', clientRes);
      },

      onBody: function (data) {
        emit(clientRes, 'data', data);
      },

      onEnd: function () {
        emit(clientRes, 'end');

        // Auto-close only if we own the connection (see `autoClose` above).
        if (autoClose) {
          setTimeout(function () {
            if (quic) quic.close(0, 'done');
            if (udpSocket) { try { udpSocket.close(); } catch (e) {} }
          }, 100);
        }
      }
    };
  }


  function sendRequest() {
    if (!h3 || !connected) return;

    if (DEBUG) console.log('[client] sendRequest method=' + method + ' path=' + path + ' stream=' + streamId);

    // MUST send control streams (SETTINGS) before any request
    h3.sendControlStreams();

    // Build H3 request headers
    var h3Headers = {
      ':method': method,
      ':scheme': 'https',
      ':authority': hostname + (port !== 443 ? ':' + port : ''),
      ':path': path
    };

    // Add user headers
    for (var name in headers) {
      h3Headers[name.toLowerCase()] = String(headers[name]);
    }

    // Default headers
    if (!h3Headers['user-agent']) h3Headers['user-agent'] = 'quico/1.0';
    if (!h3Headers['accept']) h3Headers['accept'] = '*/*';
    if (!h3Headers['accept-encoding']) h3Headers['accept-encoding'] = 'identity';

    // Send body if any
    if (reqBody.length > 0) {
      // Send headers without FIN, then body chunks
      h3.sendHeaders(streamId, h3Headers, false);
      for (var i = 0; i < reqBody.length; i++) {
        var isLast = (i === reqBody.length - 1);
        h3.sendBody(streamId, reqBody[i], isLast);
      }
    } else {
      // No body — send headers with FIN directly
      h3.sendHeaders(streamId, h3Headers, true);
    }
  }


  return clientReq;
}


// ============================================================
//  quico.get(url, callback)
//  Shortcut — like https.get()
// ============================================================

function get(url, callback) {
  var opts;
  if (typeof url === 'string') {
    var parsed = new URL(url);
    opts = {
      hostname: parsed.hostname,
      port: parseInt(parsed.port) || 443,
      path: parsed.pathname + parsed.search,
      method: 'GET'
    };
  } else {
    opts = url;
    opts.method = 'GET';
  }

  var req = request(opts, callback);
  req.end();
  return req;
}


export { request, get };
