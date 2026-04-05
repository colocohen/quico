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
import { EventEmitter } from 'node:events';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { QUICConnection } from './quic_connection.js';
import { H3Connection } from './h3.js';
import { writeVarInt, readVarInt } from './utils.js';


// ============================================================
//  WebTransportBidiStream — Duplex + WHATWG .readable/.writable
//
//  Node.js style:
//    stream.write(data);
//    stream.on('data', chunk => { ... });
//    stream.pipe(dest);
//
//  WHATWG style:
//    const writer = stream.writable.getWriter();
//    const reader = stream.readable.getReader();
// ============================================================

class WebTransportBidiStream extends Duplex {

  constructor(options) {
    super({ highWaterMark: (options && options.highWaterMark) || 64 * 1024 });

    this._streamId = options.streamId;
    this._quic = options.quic;
    this._sessionId = options.sessionId;
    this._prefixSent = options.prefixSent || false;

    // Lazy WHATWG wrappers
    this._whatwgReadable = null;
    this._whatwgWritable = null;
  }

  // ---- WHATWG getters ----

  get readable() {
    if (!this._whatwgReadable) {
      var self = this;
      this._whatwgReadable = new ReadableStream({
        start(controller) {
          self.on('data', function (chunk) {
            controller.enqueue(chunk);
          });
          self.on('end', function () {
            controller.close();
          });
          self.on('error', function (err) {
            controller.error(err);
          });
        }
      });
    }
    return this._whatwgReadable;
  }

  get writable() {
    if (!this._whatwgWritable) {
      var self = this;
      this._whatwgWritable = new WritableStream({
        write(chunk) {
          return new Promise(function (resolve, reject) {
            self.write(chunk, function (err) { err ? reject(err) : resolve(); });
          });
        },
        close() {
          return new Promise(function (resolve) { self.end(resolve); });
        }
      });
    }
    return this._whatwgWritable;
  }

  // ---- Node.js Duplex implementation ----

  _read(_size) { /* data pushed externally via _pushData */ }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    if (Buffer.isBuffer(chunk)) {
      chunk = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }

    // First write on this stream: prepend VarInt(0x41) + VarInt(session_id)
    if (!this._prefixSent) {
      this._prefixSent = true;
      var typePrefix = writeVarInt(0x41);     // WEBTRANSPORT_STREAM bidi type
      var sessionPrefix = writeVarInt(this._sessionId);
      var combined = new Uint8Array(typePrefix.length + sessionPrefix.length + chunk.byteLength);
      combined.set(typePrefix, 0);
      combined.set(sessionPrefix, typePrefix.length);
      combined.set(chunk, typePrefix.length + sessionPrefix.length);
      this._quic.sendStream(this._streamId, combined, false);
    } else {
      this._quic.sendStream(this._streamId, chunk, false);
    }
    callback();
  }

  _final(callback) {
    // Send FIN (with type + session_id prefix if nothing was written yet)
    if (!this._prefixSent) {
      this._prefixSent = true;
      var typePrefix = writeVarInt(0x41);
      var sessionPrefix = writeVarInt(this._sessionId);
      var header = new Uint8Array(typePrefix.length + sessionPrefix.length);
      header.set(typePrefix, 0);
      header.set(sessionPrefix, typePrefix.length);
      this._quic.sendStream(this._streamId, header, true);
    } else {
      this._quic.sendStream(this._streamId, new Uint8Array(0), true);
    }
    callback();
  }

  /**
   * Called by WebTransport when data arrives for this stream.
   */
  _pushData(chunk) {
    if (Buffer.isBuffer(chunk)) this.push(chunk);
    else if (chunk instanceof Uint8Array) this.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    else this.push(chunk);
  }

  _endData() {
    this.push(null);
  }
}


// ============================================================
//  WebTransportUniStream — Writable (outgoing) or Readable (incoming)
// ============================================================

class WebTransportUniWriteStream extends Writable {

  constructor(options) {
    super({ highWaterMark: (options && options.highWaterMark) || 64 * 1024 });
    this._streamId = options.streamId;
    this._quic = options.quic;
    this._sessionId = options.sessionId;
    this._headerSent = false;
  }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    if (Buffer.isBuffer(chunk)) {
      chunk = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }

    if (!this._headerSent) {
      this._headerSent = true;
      // Uni stream: VarInt(0x54) (WEBTRANSPORT_STREAM) + VarInt(session_id) + data
      var typePrefix = writeVarInt(0x54);
      var sessionPrefix = writeVarInt(this._sessionId);
      var header = new Uint8Array(typePrefix.length + sessionPrefix.length + chunk.byteLength);
      header.set(typePrefix, 0);
      header.set(sessionPrefix, typePrefix.length);
      header.set(chunk, typePrefix.length + sessionPrefix.length);
      this._quic.sendStream(this._streamId, header, false);
    } else {
      this._quic.sendStream(this._streamId, chunk, false);
    }
    callback();
  }

  _final(callback) {
    if (!this._headerSent) {
      this._headerSent = true;
      var typePrefix = writeVarInt(0x54);
      var sessionPrefix = writeVarInt(this._sessionId);
      var header = new Uint8Array(typePrefix.length + sessionPrefix.length);
      header.set(typePrefix, 0);
      header.set(sessionPrefix, typePrefix.length);
      this._quic.sendStream(this._streamId, header, true);
    } else {
      this._quic.sendStream(this._streamId, new Uint8Array(0), true);
    }
    callback();
  }

  // WHATWG getter
  get writable() {
    if (!this._whatwgWritable) {
      var self = this;
      this._whatwgWritable = new WritableStream({
        write(chunk) {
          return new Promise(function (resolve, reject) {
            self.write(chunk, function (err) { err ? reject(err) : resolve(); });
          });
        },
        close() {
          return new Promise(function (resolve) { self.end(resolve); });
        }
      });
    }
    return this._whatwgWritable;
  }
}


class WebTransportUniReadStream extends Readable {

  constructor(options) {
    super({ highWaterMark: (options && options.highWaterMark) || 64 * 1024 });
    this._streamId = options.streamId;
  }

  _read(_size) { /* data pushed externally */ }

  _pushData(chunk) {
    if (Buffer.isBuffer(chunk)) this.push(chunk);
    else if (chunk instanceof Uint8Array) this.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    else this.push(chunk);
  }

  _endData() { this.push(null); }

  // WHATWG getter
  get readable() {
    if (!this._whatwgReadable) {
      var self = this;
      this._whatwgReadable = new ReadableStream({
        start(controller) {
          self.on('data', function (chunk) { controller.enqueue(chunk); });
          self.on('end', function () { controller.close(); });
          self.on('error', function (err) { controller.error(err); });
        }
      });
    }
    return this._whatwgReadable;
  }
}


// ============================================================
//  WebTransport — Client
//
//  Usage:
//    var wt = new WebTransport('https://server:4433/path');
//    await wt.ready;
//
//    // Bidi stream (Duplex)
//    var stream = await wt.createBidirectionalStream();
//    stream.write('hello');
//    stream.on('data', chunk => console.log(chunk));
//
//    // Also works as WHATWG:
//    var writer = stream.writable.getWriter();
//    var reader = stream.readable.getReader();
//
//    // Uni stream (outgoing only)
//    var uni = await wt.createUnidirectionalStream();
//    uni.write('one-way data');
//    uni.end();
//
//    // Datagrams
//    wt.sendDatagram(Buffer.from('ping'));
//    wt.on('datagram', data => console.log('pong:', data));
//
//    // Incoming streams
//    wt.on('stream', stream => { ... });          // bidi from server
//    wt.on('unidirectionalStream', stream => { ... }); // uni from server
//
//    wt.close();
// ============================================================

class WebTransport extends EventEmitter {

  constructor(url, options) {
    super();

    // Parse URL
    var parsed = new URL(url);
    this._hostname = parsed.hostname;
    this._port = parseInt(parsed.port) || 443;
    this._path = parsed.pathname + (parsed.search || '');
    this._options = options || {};

    // State
    this._state = 'connecting'; // connecting → connected → closed
    this._sessionId = null;     // stream ID of the CONNECT request
    this._quic = null;
    this._h3 = null;
    this._udpSocket = null;

    // Stream tracking
    this._streams = {};            // streamId → WebTransportBidiStream | ReadStream
    this._claimedStreams = new Set(); // stream IDs owned by WT (not H3)

    // Client-initiated stream ID counters
    // Bidi: 0 used for CONNECT, so WT bidi starts at 4, 8, 12...
    // Uni: 2, 6, 10 used for H3 control/qpack, so WT uni starts at 14, 18, 22...
    this._nextBidiStreamId = 4;
    this._nextUniStreamId = 14;

    // Incoming stream prefix buffers (for parsing session_id)
    this._incomingBuffers = {};

    // Promises (browser-compatible API)
    var self = this;
    this.ready = new Promise(function (resolve, reject) {
      self._readyResolve = resolve;
      self._readyReject = reject;
    });

    this.closed = new Promise(function (resolve) {
      self._closedResolve = resolve;
    });

    // Start connection
    this._connect();
  }


  // ---- Connection setup ----

  _connect() {
    var host = this._hostname;
    var self = this;

    if (/^[\d.]+$/.test(host) || host.indexOf(':') >= 0 || host === 'localhost') {
      var ip = (host === 'localhost') ? '127.0.0.1' : host;
      this._startQuic(ip);
    } else {
      dns.lookup(host, function (err, address) {
        if (err) { self._readyReject(err); self.emit('error', err); return; }
        self._startQuic(address);
      });
    }
  }

  _startQuic(remoteIp) {
    var self = this;
    var remotePort = this._port;
    var isIPv6 = remoteIp.indexOf(':') >= 0;

    this._udpSocket = dgram.createSocket(isIPv6 ? 'udp6' : 'udp4');

    this._udpSocket.on('message', function (msg, rinfo) {
      if (self._quic) self._quic.feedDatagram(rinfo.address, rinfo.port, new Uint8Array(msg));
    });

    this._udpSocket.on('error', function (err) {
      if (self._state === 'connecting') self._readyReject(err);
      self.emit('error', err);
    });

    this._udpSocket.bind(0, function () {
      self._quic = new QUICConnection({
        isServer: false,
        hostname: self._hostname
      });

      self._quic.on('packet', function (data) {
        self._udpSocket.send(data, remotePort, remoteIp);
      });

      self._quic.on('connect', function () {
        self._h3 = new H3Connection({ quicConnection: self._quic, isServer: false, enableWebTransport: true });
        self._setupH3Handlers();
        self._sendConnect();
      });

      self._quic.on('close', function () {
        self._state = 'closed';
        self._closedResolve();
        self.emit('close');
        if (self._udpSocket) { try { self._udpSocket.close(); } catch (e) {} }
      });

      self._quic.connect();
    });
  }


  // ---- H3 + QUIC event handlers ----

  _setupH3Handlers() {
    var self = this;

    // CONNECT response headers
    this._h3.on('http_headers', function (streamId, headers) {
      if (streamId === self._sessionId) {
        var status = parseInt(headers[':status']) || 0;
        if (status === 200) {
          self._state = 'connected';
          self._readyResolve();
          self.emit('ready');
        } else {
          var err = new Error('WebTransport CONNECT failed: HTTP ' + status);
          self._readyReject(err);
          self.emit('error', err);
        }
      }
    });

    // Raw QUIC stream data — intercept WT streams before H3 processes them
    // We register on QUIC directly. H3 will also receive these events,
    // but we call h3.claimStream() for WT streams so H3 skips them.
    this._quic.on('stream', function (streamId, data, fin) {
      // Skip streams owned by H3 (CONNECT stream, control streams)
      if (streamId === self._sessionId) return; // H3 handles CONNECT response
      if (!self._isWebTransportStream(streamId)) return;

      self._handleStreamData(streamId, data, fin);
    });

    // Datagrams — QUIC DATAGRAM payload = VarInt(quarter_stream_id) + app data (RFC 9297)
    this._quic.on('datagram', function (_contextId, rawData) {
      if (!rawData || rawData.byteLength === 0) return;

      // Always parse VarInt quarter_stream_id from payload
      var result = readVarInt(rawData, 0);
      if (!result) return;
      var qsid = result.value;
      var payload = rawData.slice(result.byteLength);

      var expectedQsid = Math.floor(self._sessionId / 4);
      if (self._sessionId !== null && qsid === expectedQsid) {
        self.emit('datagram', Buffer.from(payload));
      }
    });
  }

  _isWebTransportStream(streamId) {
    // Already claimed
    if (this._claimedStreams.has(streamId)) return true;

    // Server-initiated bidi: 1, 5, 9, 13... (could be WT)
    // Server-initiated uni: 3, 7, 11, 15... (11+ could be WT, 3/7/11 are H3)
    // Client-initiated bidi: 4+ are WT (0 is CONNECT)
    // Client-initiated uni: 14+ are WT (2/6/10 are H3)
    var type = streamId & 0x3;

    if (type === 0x0) {
      // Client bidi — stream 0 is CONNECT, 4+ are WT
      return streamId >= 4;
    } else if (type === 0x1) {
      // Server bidi — all are potentially WT
      return true;
    } else if (type === 0x2) {
      // Client uni — 2/6/10 are H3, 14+ are WT
      return streamId >= 14;
    } else {
      // Server uni — 3/7/11 are H3, 15+ are potentially WT
      return streamId >= 15;
    }
  }

  _handleStreamData(streamId, data, fin) {
    // Already have a stream object?
    if (streamId in this._streams) {
      var stream = this._streams[streamId];
      if (data.byteLength > 0) stream._pushData(data);
      if (fin) { stream._endData(); delete this._streams[streamId]; }
      return;
    }

    // New incoming stream — need to parse session_id prefix
    if (!(streamId in this._incomingBuffers)) {
      this._incomingBuffers[streamId] = { chunks: [], totalLen: 0 };
    }

    var buf = this._incomingBuffers[streamId];
    buf.chunks.push(data);
    buf.totalLen += data.byteLength;

    // Try to parse prefix
    var combined = buf.totalLen === data.byteLength ? data : this._combineChunks(buf.chunks, buf.totalLen);
    var isBidi = (streamId & 0x2) === 0;
    var offset = 0;

    // Parse stream type as VarInt (0x41=bidi WT, 0x54=uni WT)
    var typeResult = readVarInt(combined, 0);
    if (!typeResult) { if (fin) delete this._incomingBuffers[streamId]; return; }
    var streamType = typeResult.value;
    offset = typeResult.byteLength;

    if (!isBidi) {
      if (streamType !== 0x54) {
        // Not a WT uni stream — let H3 handle it
        delete this._incomingBuffers[streamId];
        return;
      }
    } else {
      if (streamType !== 0x41) {
        delete this._incomingBuffers[streamId];
        return;
      }
    }

    // Parse VarInt session_id
    if (offset >= combined.byteLength) { if (fin) delete this._incomingBuffers[streamId]; return; }
    var result = readVarInt(combined, offset);
    if (!result) { if (fin) delete this._incomingBuffers[streamId]; return; }

    var sessionId = result.value;
    var afterPrefix = offset + result.byteLength;

    // Verify it matches our session
    if (sessionId !== this._sessionId) {
      delete this._incomingBuffers[streamId];
      return;
    }

    // Claim stream — tell H3 to skip it
    this._claimedStreams.add(streamId);
    if (this._h3 && this._h3.claimStream) this._h3.claimStream(streamId);
    delete this._incomingBuffers[streamId];

    // Create stream object
    var remaining = combined.byteLength > afterPrefix
      ? combined.slice(afterPrefix)
      : new Uint8Array(0);

    if (isBidi) {
      var stream = new WebTransportBidiStream({
        streamId: streamId,
        quic: this._quic,
        sessionId: this._sessionId,
        prefixSent: false // server-initiated, prefix not needed for writes back
      });
      this._streams[streamId] = stream;
      if (remaining.byteLength > 0) stream._pushData(remaining);
      if (fin) { stream._endData(); delete this._streams[streamId]; }
      this.emit('stream', stream);

    } else {
      var stream = new WebTransportUniReadStream({ streamId: streamId });
      this._streams[streamId] = stream;
      if (remaining.byteLength > 0) stream._pushData(remaining);
      if (fin) { stream._endData(); delete this._streams[streamId]; }
      this.emit('unidirectionalStream', stream);
    }
  }

  _combineChunks(chunks, totalLen) {
    if (chunks.length === 1) return chunks[0];
    var out = new Uint8Array(totalLen);
    var off = 0;
    for (var i = 0; i < chunks.length; i++) {
      out.set(chunks[i], off);
      off += chunks[i].byteLength;
    }
    return out;
  }


  // ---- Send CONNECT ----

  _sendConnect() {
    // Send H3 control streams (SETTINGS)
    this._h3.sendControlStreams();

    // CONNECT uses stream 0 (first client bidi)
    this._sessionId = 0;

    // Send Extended CONNECT — no FIN (session stays open)
    var headers = {
      ':method': 'CONNECT',
      ':protocol': 'webtransport',
      ':scheme': 'https',
      ':authority': this._hostname + (this._port !== 443 ? ':' + this._port : ''),
      ':path': this._path
    };

    this._h3.sendHeaders(this._sessionId, headers, false);
  }


  // ============================================================
  //  Public API
  // ============================================================

  /**
   * Create a bidirectional stream.
   * Returns a Duplex stream (Node.js) with .readable/.writable (WHATWG).
   */
  createBidirectionalStream() {
    var self = this;
    return new Promise(function (resolve, reject) {
      if (self._state !== 'connected') {
        return reject(new Error('WebTransport is not connected'));
      }

      var streamId = self._nextBidiStreamId;
      self._nextBidiStreamId += 4;

      // Claim this stream so H3 doesn't process it
      self._claimedStreams.add(streamId);
      if (self._h3 && self._h3.claimStream) self._h3.claimStream(streamId);

      var stream = new WebTransportBidiStream({
        streamId: streamId,
        quic: self._quic,
        sessionId: self._sessionId,
        prefixSent: false
      });

      self._streams[streamId] = stream;

      // Listen for incoming data on this bidi stream
      // (already handled by _handleStreamData via QUIC stream event)

      resolve(stream);
    });
  }

  /**
   * Create a unidirectional stream (outgoing only).
   * Returns a Writable stream (Node.js) with .writable (WHATWG).
   */
  createUnidirectionalStream() {
    var self = this;
    return new Promise(function (resolve, reject) {
      if (self._state !== 'connected') {
        return reject(new Error('WebTransport is not connected'));
      }

      var streamId = self._nextUniStreamId;
      self._nextUniStreamId += 4;

      // Claim this stream
      self._claimedStreams.add(streamId);
      if (self._h3 && self._h3.claimStream) self._h3.claimStream(streamId);

      var stream = new WebTransportUniWriteStream({
        streamId: streamId,
        quic: self._quic,
        sessionId: self._sessionId
      });

      resolve(stream);
    });
  }

  /**
   * Send an unreliable datagram.
   */
  sendDatagram(data) {
    if (this._state !== 'connected') throw new Error('WebTransport is not connected');
    if (typeof data === 'string') data = Buffer.from(data);
    if (Buffer.isBuffer(data)) data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

    // Quarter stream ID as context ID (RFC 9297)
    var contextId = Math.floor(this._sessionId / 4);

    // Build datagram: VarInt(contextId) + payload
    var contextPrefix = writeVarInt(contextId);
    var frame = new Uint8Array(contextPrefix.length + data.byteLength);
    frame.set(contextPrefix, 0);
    frame.set(data, contextPrefix.length);

    // Send via QUIC DATAGRAM frame
    if (this._quic && this._quic.sendDatagram) {
      this._quic.sendDatagram(frame);
    }
  }

  /**
   * Close the WebTransport session.
   */
  close(info) {
    if (this._state === 'closed') return;
    this._state = 'closed';

    // Send CLOSE_WEBTRANSPORT_SESSION on CONNECT stream (optional)
    // Then close QUIC connection
    if (this._quic) {
      this._quic.close(0, (info && info.reason) || 'WebTransport closed');
    }
  }

  /**
   * Current state.
   */
  get state() {
    return this._state;
  }

  /**
   * URL this session connected to.
   */
  get url() {
    return 'https://' + this._hostname + ':' + this._port + this._path;
  }
}


export { WebTransport, WebTransportBidiStream, WebTransportUniWriteStream, WebTransportUniReadStream };
