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
import { Duplex, Readable, Writable } from 'node:stream';
import { Emitter, readVarInt, writeVarInt } from './utils.js';
import { parse_quic_datagram } from './transport.js';
import { QUICConnection } from './quic_connection.js';
import { H3Connection } from './h3.js';
import { createSecureContext } from './tls_bridge.js';


// ============================================================
//  createServer(options, handler)
// ============================================================

function createServer(options, handler) {
  options = options || {};

  var ev = Emitter();
  var udp4 = null;
  var udp6 = null;
  var port = null;

  // Build SNICallback
  var sniCallback = options.SNICallback || null;

  if (!sniCallback && options.key && options.cert) {
    var defaultCtx = createSecureContext({ key: options.key, cert: options.cert, ca: options.ca });
    sniCallback = function (servername, cb) { cb(null, defaultCtx); };
  }

  // ---- Connection tracking ----
  var connections = {};     // connId → { quic, h3, http_streams }
  var addressMap = {};      // "ip:port" → connId
  var maxConnections = options.maxConnections || 10000;
  var sweepTimer = null;


  // ============================================================
  //  WebTransport helpers
  // ============================================================

  function _emitOnReq(req, event, data) {
    // If unified server wrapped the req, emit on the wrapper (IncomingMessage/EventEmitter)
    if (req._wrapper && typeof req._wrapper.emit === 'function') {
      req._wrapper.emit(event, data);
      return;
    }
    // Fallback: emit on raw req's _listeners
    var listeners = req._listeners[event] || [];
    for (var i = 0; i < listeners.length; i++) {
      try { if (data !== undefined) listeners[i](data); else listeners[i](); } catch (e) {}
    }
  }

  function _createWtStream(conn, quic, wtStreamId, sessionId, isBidi) {
    if (!conn._wtStreamObjects) conn._wtStreamObjects = {};

    var stream;
    if (isBidi) {
      stream = new Duplex({
        read: function () {},
        write: function (chunk, encoding, cb) {
          if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
          quic.sendStream(wtStreamId, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength), false);
          cb();
        },
        final: function (cb) {
          quic.sendStream(wtStreamId, new Uint8Array(0), true);
          cb();
        }
      });
    } else {
      stream = new Readable({ read: function () {} });
    }

    stream._streamId = wtStreamId;
    stream._sessionId = sessionId;
    stream._pushData = function (data) {
      if (data instanceof Uint8Array) data = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
      stream.push(data);
    };
    stream._endData = function () { stream.push(null); };

    conn._wtStreamObjects[wtStreamId] = stream;
    return stream;
  }


  // ============================================================
  //  set_http_stream — reactive HTTP stream builder
  //  Creates req/res on first call, fires handler when ready.
  //  Same pattern as old quico h3_server.js
  // ============================================================

  function set_http_stream(connId, streamId, params) {
    var conn = connections[connId];
    if (!conn) return;

    var is_new = false;

    // Create req/res on first encounter of this stream
    if (!(streamId in conn.http_streams)) {

      var req = {
        method: null,
        url: null,
        headers: {},
        httpVersion: '3.0',
        stream_id: Number(streamId),
        _listeners: {},
        _isWebTransport: false,

        on: function (event, fn) {
          (req._listeners[event] = req._listeners[event] || []).push(fn);
        }
      };

      var res = {
        statusCode: 200,
        headers: {},
        headersSent: false,
        _finished: false,

        setHeader: function (name, value) {
          res.headers[name.toLowerCase()] = String(value);
        },

        getHeader: function (name) {
          return res.headers[name.toLowerCase()];
        },

        writeHead: function (statusCode, headers) {
          if (res.headersSent) return res;
          res.statusCode = statusCode;

          if (typeof headers === 'object') {
            for (var name in headers) {
              res.headers[name.toLowerCase()] = String(headers[name]);
            }
          }

          var h3Headers = { ':status': String(statusCode) };
          for (var name in res.headers) {
            h3Headers[name] = res.headers[name];
          }

          if (conn.h3) {
            // Send headers WITHOUT FIN for WT (session stays open)
            var isWt = req.headers[':protocol'] === 'webtransport';
            conn.h3.sendHeaders(streamId, h3Headers, isWt ? false : undefined);
          }
          res.headersSent = true;

          // If this is a WT CONNECT with 200 → register session
          if (req.headers[':protocol'] === 'webtransport' && statusCode === 200 && conn.h3) {
            req._isWebTransport = true;
            conn.h3.registerWebTransportSession(Number(streamId));
          }

          return res;
        },

        write: function (chunk) {
          if (!res.headersSent) res.writeHead(res.statusCode);
          if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
          if (conn.h3) conn.h3.sendBody(streamId, chunk, false);
          return true;
        },

        end: function (chunk) {
          if (res._finished) return;
          if (!res.headersSent) res.writeHead(res.statusCode);
          if (conn.h3) {
            if (chunk) {
              if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
              conn.h3.sendBody(streamId, chunk, true);
            } else {
              conn.h3.sendBody(streamId, null, true);
            }
          }
          res._finished = true;
        },

        // ---- WebTransport methods on res ----

        sendDatagram: function (data) {
          if (!req._isWebTransport) return;
          if (typeof data === 'string') data = Buffer.from(data);
          if (Buffer.isBuffer(data)) data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
          var quarterSid = Math.floor(Number(streamId) / 4);
          var prefix = writeVarInt(quarterSid);
          var frame = new Uint8Array(prefix.length + data.byteLength);
          frame.set(prefix, 0);
          frame.set(data, prefix.length);
          conn.quic.sendDatagram(frame);
        },

        createBidirectionalStream: function () {
          if (!req._isWebTransport || !conn.h3) return null;
          var wtStreamId = conn.h3.createWebTransportStream(Number(streamId), true);
          return _createWtStream(conn, conn.quic, wtStreamId, Number(streamId), true);
        },

        createUnidirectionalStream: function () {
          if (!req._isWebTransport || !conn.h3) return null;
          var wtStreamId = conn.h3.createWebTransportStream(Number(streamId), false);
          var stream = new Writable({
            write: function (chunk, encoding, cb) {
              if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
              conn.quic.sendStream(wtStreamId, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength), false);
              cb();
            },
            final: function (cb) {
              conn.quic.sendStream(wtStreamId, new Uint8Array(0), true);
              cb();
            }
          });
          stream._streamId = wtStreamId;
          return stream;
        }
      };

      conn.http_streams[streamId] = { req: req, res: res };
      is_new = true;
    }

    // Apply params
    if (typeof params === 'object') {

      if ('request_headers' in params) {
        var stream = conn.http_streams[streamId];
        for (var name in params.request_headers) {
          stream.req.headers[name] = params.request_headers[name];
        }

        // Extract :method and :path
        if (stream.req.method === null && ':method' in stream.req.headers) {
          stream.req.method = stream.req.headers[':method'];
        }
        if (stream.req.url === null && ':path' in stream.req.headers) {
          stream.req.url = stream.req.headers[':path'];
        }
      }

      if ('request_body_chunk' in params) {
        var stream = conn.http_streams[streamId];
        var listeners = stream.req._listeners['data'] || [];
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](params.request_body_chunk); } catch (e) { }
        }
      }

      if ('request_end' in params) {
        var stream = conn.http_streams[streamId];
        var listeners = stream.req._listeners['end'] || [];
        for (var i = 0; i < listeners.length; i++) {
          try { listeners[i](); } catch (e) { }
        }
      }
    }

    // Fire handler on new stream (after headers are set)
    if (is_new) {
      var stream = conn.http_streams[streamId];
      if (typeof handler === 'function') {
        handler(stream.req, stream.res);
      }
      ev.emit('request', stream.req, stream.res);
    }
  }


  // ============================================================
  //  UDP → connection routing
  // ============================================================

  function onUdpMessage(msg, rinfo) {
    var data = new Uint8Array(msg);
    var fromIp = rinfo.address;
    var fromPort = rinfo.port;
    console.log('[server] UDP from ' + fromIp + ':' + fromPort + ' len=' + data.length);

    var addressKey = fromIp + ':' + fromPort;
    var packets = parse_quic_datagram(data);
    if (packets.length === 0) return;

    for (var i = 0; i < packets.length; i++) {
      var pkt = packets[i];
      if (!pkt) continue;

      var connId = findConnectionId(pkt, addressKey);

      if (!(connId in connections)) {
        // Reject new connections when at capacity
        if (Object.keys(connections).length >= maxConnections) return;
        createConnection(connId, fromIp, fromPort, addressKey);
      }

      connections[connId].quic.feedDatagram(fromIp, fromPort, pkt.raw);
    }
  }


  function findConnectionId(pkt, addressKey) {
    var dcidStr = null;
    if (pkt.dcid && pkt.dcid.byteLength > 0) {
      dcidStr = Array.from(pkt.dcid).join('');
    }

    if (dcidStr && dcidStr in connections) return dcidStr;
    if (addressKey in addressMap && addressMap[addressKey] in connections) return addressMap[addressKey];

    var id = dcidStr || String(Math.floor(Math.random() * 9007199254740991));
    addressMap[addressKey] = id;
    return id;
  }


  function createConnection(connId, fromIp, fromPort, addressKey) {
    var quic = new QUICConnection({ SNICallback: sniCallback });

    connections[connId] = {
      quic: quic,
      h3: null,
      http_streams: {}
    };

    addressMap[addressKey] = connId;

    // Send packets back via UDP
    quic.on('packet', function (data) {
      sendUdp(fromIp, fromPort, data);
    });

    // QUIC handshake complete → set up H3
    quic.on('connect', function () {
      var h3 = new H3Connection({ quicConnection: quic, enableWebTransport: true });
      connections[connId].h3 = h3;

      // HTTP request headers received → set_http_stream (reactive)
      h3.on('http_headers', function (streamId, headers) {
        set_http_stream(connId, streamId, { request_headers: headers });
      });

      // HTTP request body chunk → set_http_stream
      h3.on('http_body', function (streamId, data) {
        set_http_stream(connId, streamId, { request_body_chunk: data });
      });

      // HTTP request complete → fire req.on('end')
      h3.on('http_end', function (streamId) {
        set_http_stream(connId, streamId, { request_end: true });
      });

      // ---- WebTransport stream events ----

      // New WT stream (bidi or uni from client)
      h3.on('wt_stream', function (sessionId, wtStreamId, data, fin, isBidi) {
        var conn = connections[connId];
        if (!conn) return;
        var session = conn.http_streams[sessionId];
        if (!session || !session.req._isWebTransport) return;

        // Create a Duplex-like stream for the WT stream
        var wtStream = _createWtStream(conn, quic, wtStreamId, sessionId, isBidi);

        // Push initial data
        if (data.byteLength > 0) _emitOnReq(session.req, 'data:' + wtStreamId, data);
        if (fin) _emitOnReq(session.req, 'end:' + wtStreamId);

        // Emit on req
        if (isBidi) {
          _emitOnReq(session.req, 'stream', wtStream);
        } else {
          _emitOnReq(session.req, 'unidirectionalStream', wtStream);
        }

        // If initial data, push to stream
        if (data.byteLength > 0) wtStream._pushData(data);
        if (fin) wtStream._endData();
      });

      // Subsequent data on WT stream
      h3.on('wt_data', function (sessionId, wtStreamId, data, fin) {
        var conn = connections[connId];
        if (!conn || !conn._wtStreamObjects) return;
        var wtStream = conn._wtStreamObjects[wtStreamId];
        if (!wtStream) return;
        if (data.byteLength > 0) wtStream._pushData(data);
        if (fin) { wtStream._endData(); delete conn._wtStreamObjects[wtStreamId]; }
      });

      // Datagrams
      quic.on('datagram', function (_contextId, rawData) {
        if (!rawData || rawData.byteLength === 0) return;
        var result = readVarInt(rawData, 0);
        if (!result) return;
        var quarterSid = result.value;
        var payload = rawData.slice(result.byteLength);

        // Find the session: quarter_stream_id = session_stream_id / 4
        var conn = connections[connId];
        if (!conn) return;
        for (var sid in conn.http_streams) {
          var session = conn.http_streams[sid];
          if (session.req._isWebTransport && Math.floor(Number(sid) / 4) === quarterSid) {
            _emitOnReq(session.req, 'datagram', Buffer.from(payload));
            break;
          }
        }
      });
    });

    quic.on('close', function () {
      delete connections[connId];
      if (addressMap[addressKey] === connId) delete addressMap[addressKey];
    });
  }


  // ============================================================
  //  UDP send
  // ============================================================

  function sendUdp(toIp, toPort, data) {
    var socket = toIp.indexOf(':') >= 0 ? udp6 : udp4;
    if (!socket) return;
    socket.send(data, toPort, toIp, function (err) {
      if (err) ev.emit('error', err);
    });
  }


  // ============================================================
  //  listen / close
  // ============================================================

  function listen(listenPort, host, callback) {
    if (typeof host === 'function') { callback = host; host = null; }
    port = listenPort || 443;
    host = host || '::';

    udp4 = dgram.createSocket('udp4');
    udp4.on('message', onUdpMessage);
    udp4.on('error', function (err) { ev.emit('error', err); });
    var host4 = host.indexOf('.') !== -1 ? host : '0.0.0.0';
    udp4.bind(port, host4);

    udp6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
    udp6.on('message', onUdpMessage);
    udp6.on('error', function (err) { ev.emit('error', err); });
    var host6 = host.indexOf(':') !== -1 ? host : '::';
    udp6.bind(port, host6, function () {
      if (typeof callback === 'function') callback();
    });

    // Periodic sweep for dead connections (safety net)
    sweepTimer = setInterval(function () {
      for (var id in connections) {
        var st = connections[id].quic.state;
        if (st === 'closed') {
          delete connections[id];
          // Clean address map
          for (var addr in addressMap) {
            if (addressMap[addr] === id) delete addressMap[addr];
          }
        }
      }
    }, 30000);
  }

  function close(callback) {
    // Stop sweep
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }

    // Close all connections
    for (var id in connections) {
      try { connections[id].quic.close(0, 'server closing'); } catch (e) { }
    }
    connections = {};
    addressMap = {};

    var closed = 0;
    var total = (udp4 ? 1 : 0) + (udp6 ? 1 : 0);
    if (total === 0) { if (callback) callback(); return; }

    function onClose() {
      closed++;
      if (closed >= total && typeof callback === 'function') callback();
    }

    if (udp4) { udp4.close(onClose); udp4 = null; }
    if (udp6) { udp6.close(onClose); udp6 = null; }
  }


  // ============================================================
  //  Server API
  // ============================================================

  return {
    listen: listen,
    close: close,
    on: function (name, fn) { ev.on(name, fn); },
    setTimeout: function () { /* TODO */ }
  };
}


export { createServer };
