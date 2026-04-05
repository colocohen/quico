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

import { Readable, Writable, Duplex } from 'node:stream';


// ============================================================
//  IncomingMessage — extends Readable
//
//  Wraps incoming HTTP data:
//    - On server: the request body  (req)
//    - On client: the response body (res)
//
//  Data is pushed in from the H3 layer via _pushData / _endData.
//  Consumers use pipe(), for-await-of, on('data'), etc.
// ============================================================

class IncomingMessage extends Readable {

  constructor(options) {
    super({ highWaterMark: (options && options.highWaterMark) || 64 * 1024 });

    options = options || {};

    this.httpVersion = options.httpVersion || '3.0';
    this.httpVersionMajor = parseInt(this.httpVersion) || 3;
    this.httpVersionMinor = parseInt((this.httpVersion.split('.')[1]) || '0') || 0;

    this.complete = false;
    this.aborted = false;

    this.headers = options.headers || {};
    this.rawHeaders = [];
    this.trailers = {};
    this.rawTrailers = [];

    // Client-side (response)
    this.statusCode = options.statusCode || null;
    this.statusMessage = options.statusMessage || '';

    // Server-side (request)
    this.method = options.method || null;
    this.url = options.url || null;

    // QUIC has no TCP socket — stub so libraries don't crash
    this.socket = options.socket || _makeSocketStub();
    this.connection = this.socket;

    // H3 stream id (internal)
    this._streamId = options.streamId != null ? options.streamId : null;
    this._timeoutTimer = null;

    // Build rawHeaders
    for (var name in this.headers) {
      this.rawHeaders.push(name, String(this.headers[name]));
    }
  }

  // Readable requires _read — data is pushed externally, so no-op.
  _read(_size) { /* no-op */ }

  /**
   * Called by H3 layer when a body chunk arrives.
   */
  _pushData(chunk) {
    if (this.complete) return;
    if (typeof chunk === 'string') chunk = Buffer.from(chunk);
    if (chunk instanceof Uint8Array && !Buffer.isBuffer(chunk)) {
      chunk = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }
    this.push(chunk);
  }

  /**
   * Called by H3 layer when the stream ends (FIN received).
   */
  _endData() {
    if (this.complete) return;
    this.complete = true;
    this.push(null);
  }

  /**
   * Abort the stream (error / timeout / reset).
   */
  _abort(err) {
    if (this.complete) return;
    this.aborted = true;
    this.complete = true;
    if (err) this.destroy(err);
    else this.push(null);
  }

  setTimeout(msecs, callback) {
    if (callback) this.once('timeout', callback);
    if (this._timeoutTimer) clearTimeout(this._timeoutTimer);
    if (msecs > 0) {
      this._timeoutTimer = setTimeout(() => this.emit('timeout'), msecs);
    }
    return this;
  }
}


// ============================================================
//  ServerResponse — extends Writable
//
//  Wraps outgoing HTTP response on the server side.
//  write() / pipe(res) / end() → h3.sendHeaders + h3.sendBody
// ============================================================

class ServerResponse extends Writable {

  constructor(options) {
    super({ highWaterMark: (options && options.highWaterMark) || 64 * 1024 });

    options = options || {};

    this.statusCode = 200;
    this.statusMessage = 'OK';
    this.headersSent = false;
    this.finished = false;
    this._headers = {};
    this._headerNames = {};  // lowercase → original-case

    // H3 references (set by server when creating the response)
    this._streamId = options.streamId != null ? options.streamId : null;
    this._h3 = options.h3 || null;

    // Paired request (Express compat: res.req)
    this.req = options.req || null;

    this.socket = options.socket || _makeSocketStub();
    this.connection = this.socket;

    this.on('finish', () => {
      this.finished = true;
      this.emit('close');
    });

    // Express does res.__proto__ = app.response (http.ServerResponse.prototype)
    // which kills our class methods. Bind them to the instance so they survive.
    this.setHeader = this.setHeader.bind(this);
    this.getHeader = this.getHeader.bind(this);
    this.getHeaders = this.getHeaders.bind(this);
    this.getHeaderNames = this.getHeaderNames.bind(this);
    this.hasHeader = this.hasHeader.bind(this);
    this.removeHeader = this.removeHeader.bind(this);
    this.writeHead = this.writeHead.bind(this);
    this.flushHeaders = this.flushHeaders.bind(this);
    this._flushHeaders = this._flushHeaders.bind(this);
    this.write = this.write.bind(this);
    this.end = this.end.bind(this);
  }

  // ---- Header management (mirrors node:http) ----

  setHeader(name, value) {
    if (this.headersSent) throw new Error('Cannot set headers after they are sent to the client');
    var lower = name.toLowerCase();
    this._headers[lower] = value;
    this._headerNames[lower] = name;
    return this;
  }

  getHeader(name) {
    return this._headers[name.toLowerCase()];
  }

  getHeaders() {
    var out = {};
    for (var k in this._headers) out[k] = this._headers[k];
    return out;
  }

  getHeaderNames() {
    return Object.keys(this._headers);
  }

  hasHeader(name) {
    return name.toLowerCase() in this._headers;
  }

  removeHeader(name) {
    if (this.headersSent) throw new Error('Cannot remove headers after they are sent to the client');
    var lower = name.toLowerCase();
    delete this._headers[lower];
    delete this._headerNames[lower];
    return this;
  }

  // ---- writeHead ----

  writeHead(statusCode, statusMessage, headers) {
    if (this.headersSent) return this;

    if (typeof statusMessage === 'object' && !headers) {
      headers = statusMessage;
      statusMessage = undefined;
    }

    this.statusCode = statusCode;
    if (statusMessage !== undefined) this.statusMessage = String(statusMessage);

    if (typeof headers === 'object' && headers !== null) {
      for (var name in headers) this.setHeader(name, headers[name]);
    }

    this._flushHeaders();
    return this;
  }

  flushHeaders() {
    if (!this.headersSent) this._flushHeaders();
  }

  _flushHeaders() {
    if (this.headersSent || !this._h3) return;

    var h3h = { ':status': String(this.statusCode) };
    for (var lower in this._headers) h3h[lower] = String(this._headers[lower]);

    this._h3.sendHeaders(this._streamId, h3h);
    this.headersSent = true;
  }

  // ---- Writable implementation ----

  _write(chunk, encoding, callback) {
    if (!this.headersSent) this._flushHeaders();

    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    if (Buffer.isBuffer(chunk)) {
      chunk = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }

    if (this._h3) this._h3.sendBody(this._streamId, chunk, false);
    callback();
  }

  _final(callback) {
    if (!this.headersSent) this._flushHeaders();
    if (this._h3) this._h3.sendBody(this._streamId, null, true);
    callback();
  }

  // ---- node:http compat overrides ----

  write(chunk, encoding, callback) {
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    return super.write(chunk, encoding, callback);
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') { callback = data; data = undefined; encoding = undefined; }
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (data != null) this.write(data, encoding);
    return super.end(callback);
  }

  writeContinue() { /* HTTP/3 doesn't use 100-continue — stub */ }

  setTimeout(msecs, callback) {
    if (callback) this.once('timeout', callback);
    return this;
  }
}


// ============================================================
//  ClientRequest — extends Writable
//
//  Wraps outgoing HTTP request on the client side.
//  write() / pipe(req) buffers body data.
//  _final() signals body-complete so the transport can send.
//
//  The 'response' event delivers an IncomingMessage.
// ============================================================

class ClientRequest extends Writable {

  constructor(options) {
    super({ highWaterMark: (options && options.highWaterMark) || 64 * 1024 });

    options = options || {};

    this.method = (options.method || 'GET').toUpperCase();
    this.path = options.path || '/';
    this.host = options.hostname || options.host || 'localhost';
    this.port = options.port || 443;

    this.headersSent = false;
    this.finished = false;
    this.aborted = false;
    this.reusedSocket = false;

    this._headers = {};
    this._headerNames = {};

    // Copy initial headers
    if (options.headers) {
      for (var name in options.headers) this.setHeader(name, options.headers[name]);
    }

    // Body buffer — accumulated via write/pipe, sent when _final fires
    this._bodyChunks = [];

    // H3 internals — set by unified client after protocol selection
    this._h3 = null;
    this._streamId = null;
    this._quic = null;

    // The callback from request(opts, cb)
    this._responseCallback = options._responseCallback || null;

    // Protocol that was actually used (filled after connect)
    this.protocol = null;  // 'h3', 'h2', 'https'

    this.socket = options.socket || _makeSocketStub();
    this.connection = this.socket;

    this._timeoutTimer = null;
    this._timeoutMs = 0;
  }

  // ---- Header management ----

  setHeader(name, value) {
    var lower = name.toLowerCase();
    this._headers[lower] = value;
    this._headerNames[lower] = name;
    return this;
  }

  getHeader(name) {
    return this._headers[name.toLowerCase()];
  }

  getHeaders() {
    var out = {};
    for (var k in this._headers) out[k] = this._headers[k];
    return out;
  }

  removeHeader(name) {
    var lower = name.toLowerCase();
    delete this._headers[lower];
    delete this._headerNames[lower];
    return this;
  }

  hasHeader(name) {
    return name.toLowerCase() in this._headers;
  }

  setNoDelay() { return this; }
  setSocketKeepAlive() { return this; }

  // ---- Writable implementation ----

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    if (Buffer.isBuffer(chunk)) {
      chunk = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }
    this._bodyChunks.push(chunk);
    callback();
  }

  _final(callback) {
    this.finished = true;
    this.emit('_bodyReady');
    callback();
  }

  // ---- Convenience overrides ----

  write(chunk, encoding, callback) {
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    return super.write(chunk, encoding, callback);
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') { callback = data; data = undefined; encoding = undefined; }
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (data != null) this.write(data, encoding);
    return super.end(callback);
  }

  abort() {
    this.aborted = true;
    this.destroy(new Error('Request aborted'));
  }

  setTimeout(msecs, callback) {
    if (callback) this.once('timeout', callback);
    this._timeoutMs = msecs;
    if (this._timeoutTimer) clearTimeout(this._timeoutTimer);
    if (msecs > 0) {
      this._timeoutTimer = setTimeout(() => this.emit('timeout'), msecs);
    }
    return this;
  }

  /**
   * Collect all buffered body chunks into one Uint8Array.
   * Returns null if nothing was written (GET / HEAD).
   */
  _getBody() {
    if (this._bodyChunks.length === 0) return null;
    if (this._bodyChunks.length === 1) return this._bodyChunks[0];
    var total = 0;
    for (var i = 0; i < this._bodyChunks.length; i++) total += this._bodyChunks[i].byteLength;
    var merged = new Uint8Array(total);
    var off = 0;
    for (var i = 0; i < this._bodyChunks.length; i++) {
      merged.set(this._bodyChunks[i], off);
      off += this._bodyChunks[i].byteLength;
    }
    return merged;
  }
}


// ============================================================
//  Socket stub — for libraries that check req.socket / res.socket
//  Must be a real Stream so Node's eos() / Express don't crash.
// ============================================================

function _makeSocketStub() {
  var sock = new Duplex({
    read(_size) { /* no-op — no data from QUIC socket */ },
    write(_chunk, _encoding, callback) { callback(); }
  });

  // TLS properties
  sock.encrypted = true;
  sock.authorized = true;
  sock.remoteAddress = null;
  sock.remotePort = null;
  sock.localAddress = null;
  sock.localPort = null;
  sock.alpnProtocol = 'h3';

  sock.setNoDelay = function () { return sock; };
  sock.setKeepAlive = function () { return sock; };
  sock.setTimeout = function () { return sock; };
  sock.ref = function () { return sock; };
  sock.unref = function () { return sock; };

  // TLS methods (Express / Helmet / etc.)
  sock.getPeerCertificate = function () { return {}; };
  sock.getProtocol = function () { return 'TLSv1.3'; };
  sock.getCipher = function () { return { name: 'TLS_AES_128_GCM_SHA256', version: 'TLSv1.3' }; };

  return sock;
}


export { IncomingMessage, ServerResponse, ClientRequest, _makeSocketStub };
