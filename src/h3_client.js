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

import dgram from 'node:dgram';
import dns from 'node:dns';
import { QUICConnection } from './quic_connection.js';
import { H3Connection } from './h3.js';


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
  var rejectUnauthorized = options.rejectUnauthorized !== false;

  // Connection reuse: pass _connection = { quic, h3, udpSocket, nextStreamId }
  var existingConn = options._connection || null;
  var autoClose = existingConn ? false : true;

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
    // Reuse existing connection — allocate stream ID and send when ready
    streamId = allocateStreamId(existingConn);
    setupResponseHandlers();
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
    // Create UDP socket
    var isIPv6 = remoteIp.indexOf(':') >= 0;
    udpSocket = dgram.createSocket(isIPv6 ? 'udp6' : 'udp4');

    udpSocket.on('message', function (msg, rinfo) {
      if (quic) quic.feedDatagram(rinfo.address, rinfo.port, new Uint8Array(msg));
    });

    udpSocket.on('error', function (err) {
      emit(reqListeners, 'error', err);
    });

    // Bind to random port
    udpSocket.bind(0, function () {
      // Create QUIC connection (client mode)
      quic = new QUICConnection({
        isServer: false,
        SNICallback: null,
        hostname: hostname
      });

      // Send packets via UDP
      quic.on('packet', function (data) {
        udpSocket.send(data, remotePort, remoteIp, function (err) {
          if (err) emit(reqListeners, 'error', err);
        });
      });

      // QUIC connected → set up H3
      quic.on('connect', function () {
        console.log('[client] QUIC connected');

        h3 = new H3Connection({ quicConnection: quic, isServer: false });
        connected = true;

        // Build connection object for reuse
        var conn = { quic: quic, h3: h3, udpSocket: udpSocket, _nextStreamId: 0 };
        streamId = allocateStreamId(conn);

        // Store on clientReq so caller (unified client) can reuse
        clientReq._connection = conn;

        setupResponseHandlers();

        // Send request if body is ready
        if (reqFinished) sendRequest();
      });

      quic.on('close', function () {
        if (udpSocket) { try { udpSocket.close(); } catch (e) {} }
      });

      // Start QUIC handshake
      quic.connect();
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
   * Set up HTTP/3 response handlers for this request's streamId.
   * Works for both new and reused connections.
   */
  function setupResponseHandlers() {
    // HTTP response headers
    h3.on('http_headers', function (sid, hdrs) {
      if (sid !== streamId) return;
      clientRes.headers = hdrs;
      clientRes.statusCode = parseInt(hdrs[':status']) || 0;
      clientRes._headersReceived = true;

      // Fire callback with response
      if (typeof callback === 'function') {
        callback(clientRes);
        callback = null; // only once
      }
      emit(reqListeners, 'response', clientRes);
    });

    // HTTP response body
    h3.on('http_body', function (sid, data) {
      if (sid !== streamId) return;
      emit(clientRes, 'data', data);
    });

    // HTTP response end
    h3.on('http_end', function (sid) {
      if (sid !== streamId) return;
      emit(clientRes, 'end');

      // Auto-close only if we own the connection (not reusing)
      if (autoClose) {
        setTimeout(function () {
          if (quic) quic.close(0, 'done');
          if (udpSocket) { try { udpSocket.close(); } catch (e) {} }
        }, 100);
      }
    });
  }


  function sendRequest() {
    if (!h3 || !connected) return;

    console.log('[client] sendRequest method=' + method + ' path=' + path + ' stream=' + streamId);

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
