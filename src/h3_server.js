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

import { Duplex, Readable, Writable } from 'node:stream';
import { Emitter, readVarInt, wt_datagram_payload } from './utils.js';
import { createQuicServer } from './quic_server.js';
import { H3Connection } from './h3.js';


// ============================================================
//  createServer(options, handler)
// ============================================================

function createServer(options, handler) {
  options = options || {};

  var ev = Emitter();

  // Transport-only QUIC server owns the UDP socket(s), demux, connection
  // map and lifecycle. h3_server layers HTTP/3 on top by listening for its
  // 'connection' event (see below) and wrapping each raw QUICConnection in
  // an H3Connection. ALPN is 'h3'. External-socket (shared-port) mode and
  // the handlePacket/hasConnection demux hooks are provided by the
  // transport server and re-exported on this server's API.
  var qserver = createQuicServer({
    alpn: 'h3',
    SNICallback: options.SNICallback || null,
    key: options.key,
    cert: options.cert,
    ca: options.ca,
    maxConnections: options.maxConnections || 10000,
    socket: options.socket || null,
    socket6: options.socket6 || null
  });

  // Surface transport-level (UDP socket / send) errors on this server.
  qserver.on('error', function (err) { ev.emit('error', err); });


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

  function set_http_stream(conn, streamId, params) {
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
          conn.quic.sendDatagram(wt_datagram_payload(Number(streamId), data));
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
  //  HTTP/3 over each accepted QUIC connection
  //  The transport server hands us a raw QUICConnection per peer; we wrap
  //  it in an H3Connection once the handshake completes and bridge HTTP/3 +
  //  WebTransport events to req/res via set_http_stream. Per-connection
  //  state lives in this closure — the transport server owns the UDP
  //  socket, demux and connection lifecycle.
  // ============================================================

  qserver.on('connection', function (quic, peer) {
    var conn = { quic: quic, h3: null, http_streams: {} };

    // QUIC handshake complete → set up H3
    quic.on('connect', function () {
      var h3 = new H3Connection({ quicConnection: quic, enableWebTransport: true });
      conn.h3 = h3;

      // HTTP request headers received → set_http_stream (reactive)
      h3.on('http_headers', function (streamId, headers) {
        set_http_stream(conn, streamId, { request_headers: headers });
      });

      // HTTP request body chunk → set_http_stream
      h3.on('http_body', function (streamId, data) {
        set_http_stream(conn, streamId, { request_body_chunk: data });
      });

      // HTTP request complete → fire req.on('end')
      h3.on('http_end', function (streamId) {
        set_http_stream(conn, streamId, { request_end: true });
      });

      // ---- WebTransport stream events ----

      // New WT stream (bidi or uni from client)
      h3.on('wt_stream', function (sessionId, wtStreamId, data, fin, isBidi) {
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
        if (!conn._wtStreamObjects) return;
        var wtStream = conn._wtStreamObjects[wtStreamId];
        if (!wtStream) return;
        if (data.byteLength > 0) wtStream._pushData(data);
        if (fin) { wtStream._endData(); delete conn._wtStreamObjects[wtStreamId]; }
      });

      // Datagrams
      quic.on('datagram', function (rawData) {
        if (!rawData || rawData.byteLength === 0) return;
        var result = readVarInt(rawData, 0);
        if (!result) return;
        var quarterSid = result.value;
        var payload = rawData.slice(result.byteLength);

        // Find the session: quarter_stream_id = session_stream_id / 4
        for (var sid in conn.http_streams) {
          var session = conn.http_streams[sid];
          if (session.req._isWebTransport && Math.floor(Number(sid) / 4) === quarterSid) {
            _emitOnReq(session.req, 'datagram', Buffer.from(payload));
            break;
          }
        }
      });
    });
  });


  // ============================================================
  //  Server API
  //  Transport concerns (UDP sockets, demux, connection lifecycle,
  //  shared-port handlePacket/hasConnection) are delegated to the QUIC
  //  server. This layer adds HTTP/3 request events on top.
  // ============================================================

  return {
    listen: qserver.listen,
    close: qserver.close,
    on: function (name, fn) { ev.on(name, fn); },
    setTimeout: function () { /* TODO */ },

    /** Feed an incoming UDP packet when running in external-socket mode.
     *  rinfo must be in Node's dgram format: { address, port, family, size }. */
    handlePacket: qserver.handlePacket,

    /** Returns true if the 5-tuple matches an active QUIC connection.
     *  Used by demuxers for routing decisions on shared UDP ports. */
    hasConnection: qserver.hasConnection
  };
}


export { createServer };
