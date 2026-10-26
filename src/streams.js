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
import { validateHeaderName, validateHeaderValue, validateStatus, validateRequestTarget, headersSentError, responsePriority } from './http_common.js';


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
    // HTTP/3: the request came in 0-RTT (it may be a replay). Never over TCP.
    this.earlyData = false;

    // QUIC has no TCP socket — stub so libraries don't crash
    this.socket = options.socket || _makeSocketStub();
    this.connection = this.socket;
    this.client = this.socket;      // node:http's older alias
    // node:http's: true on a request handed to 'upgrade' (an HTTP/1.1
    // Upgrade, an extended CONNECT over HTTP/2 and HTTP/3).
    this.upgrade = false;

    // H3 stream id (internal)
    this._streamId = options.streamId != null ? options.streamId : null;
    this._timeoutTimer = null;

    // Build rawHeaders: one name and value per field line, as node:http has
    // them — the field lines as they came when the decoder kept them
    // (validateFieldSection's _rawHeaders); otherwise from the map, a list
    // (Set-Cookie) one entry per value. String(list) made two cookies one
    // "a=1,b=2".
    var rawList = this.headers._rawHeaders;
    if (Array.isArray(rawList)) {
      for (var ri = 0; ri < rawList.length; ri++) this.rawHeaders.push(rawList[ri]);
    } else {
      for (var name in this.headers) {
        var hv = this.headers[name];
        if (Array.isArray(hv)) { for (var hi = 0; hi < hv.length; hi++) this.rawHeaders.push(name, String(hv[hi])); }
        else this.rawHeaders.push(name, String(hv));
      }
    }
  }

  // node:http's headersDistinct / trailersDistinct: each name (lower case)
  // with every value it came with, as an array, nothing joined — from the
  // field lines as they arrived (rawHeaders, rawTrailers).
  get headersDistinct() { return distinctFields(this.rawHeaders); }
  get trailersDistinct() { return distinctFields(this.rawTrailers); }

  // Readable requires _read — data is pushed externally, so no-op.
  _read(_size) { /* no-op */ }

  /**
   * Called by H3 layer when a body chunk arrives.
   */
  // push()'s answer: false once the buffer is full — the caller stops
  // reading until _read asks for more.
  _pushData(chunk) {
    if (this.complete) return true;
    if (typeof chunk === 'string') chunk = Buffer.from(chunk);
    if (chunk instanceof Uint8Array && !Buffer.isBuffer(chunk)) {
      chunk = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    }
    return this.push(chunk);
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
   * The exchange ended before its body did — the peer reset the stream or
   * went away, or (client side) req.destroy(). The one place this is decided,
   * as node:http's IncomingMessage does it:
   *
   *   'aborted' — always, once;
   *   'error'   — ('aborted', ECONNRESET, or the cause given) only to a
   *               listener that asked for one: unheard, it would take the
   *               process down, and node:http teaches 'aborted'/'close';
   *   'close'   — and never 'end', which would say the body is whole.
   *
   * It ended the stream with push(null) — 'end', a cut-off upload read as a
   * complete one — and each caller decided the 'error' question for itself,
   * one (h1_server) not at all, so a client vanishing mid-upload threw.
   * A body that had already arrived in full is left as it is: 'aborted', and
   * nothing to cut.
   */
  _abort(err) {
    if (this.aborted) return;
    this.aborted = true;
    if (this._timeoutTimer) { clearTimeout(this._timeoutTimer); this._timeoutTimer = null; }
    this.emit('aborted');
    if (this.complete) return;
    this.complete = true;
    if (!err) { err = new Error('aborted'); err.code = 'ECONNRESET'; }
    this.destroy(this.listenerCount('error') > 0 ? err : null);
  }

  setTimeout(msecs, callback) {
    if (callback) this.once('timeout', callback);
    if (this._timeoutTimer) clearTimeout(this._timeoutTimer);
    if (msecs > 0) {
      this._timeoutTimer = setTimeout(() => this.emit('timeout'), msecs);
    }
    return this;
  }

  /**
   * What destroy() by the application means on the wire, given by the
   * transport that made this message: a request's body the server no longer
   * wants (STOP_SENDING / RST_STREAM; over HTTP/1.1, the socket), a response
   * the client gave up on mid-way. Not run when the stream itself ended it
   * (_abort: the peer's reset, the connection gone); each hook decides what
   * is left to stop (a body that arrived whole: nothing). destroy() was
   * local only: the body kept coming, at full speed once its credit was
   * released, into a message nobody read.
   */
  _onDestroy(fn) {
    (this._destroyHooks || (this._destroyHooks = [])).push(fn);
  }

  _destroy(err, cb) {
    if (this._timeoutTimer) { clearTimeout(this._timeoutTimer); this._timeoutTimer = null; }
    var hooks = this._destroyHooks;
    this._destroyHooks = null;
    // Not after 'end': that is autoDestroy closing a body read to the end,
    // not the application giving anything up.
    if (hooks && !this.aborted && !this.readableEnded) {
      for (var i = 0; i < hooks.length; i++) { try { hooks[i](err); } catch (e) {} }
    }
    cb(err);
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
    // Unset, as node:http has it: the standard reason phrase for whatever the
    // status ends up being. It was 'OK', so a status set without one —
    // res.statusCode = 404, writeHead(425, headers) — went out as '404 OK'.
    this.statusMessage = undefined;
    this.headersSent = false;
    this.finished = false;
    this._headers = {};
    this._headerNames = {};  // lowercase → original-case
    // node:http's: a Date header unless false (RFC 9110 §6.6.1); and, when
    // true, a body that does not match its Content-Length throws.
    this.sendDate = true;
    this.strictContentLength = false;
    this._bodyBytes = 0;

    // H3 references (set by server when creating the response)
    this._streamId = options.streamId != null ? options.streamId : null;
    this._h3 = options.h3 || null;

    // Paired request (Express compat: res.req)
    this.req = options.req || null;

    this.socket = options.socket || _makeSocketStub();
    this.connection = this.socket;

    // 'close' comes from the Writable itself (autoDestroy), once, after
    // 'finish' — node's order. It was also emitted here, from a 'finish'
    // listener registered first: the application saw close, finish, close.
    this.on('finish', () => {
      this.finished = true;
    });

    // Express does res.__proto__ = app.response (http.ServerResponse.prototype)
    // which kills our class methods. Bind them to the instance so they survive.
    this.setHeader = this.setHeader.bind(this);
    this.getHeader = this.getHeader.bind(this);
    this.getHeaders = this.getHeaders.bind(this);
    this.getHeaderNames = this.getHeaderNames.bind(this);
    this.hasHeader = this.hasHeader.bind(this);
    this.removeHeader = this.removeHeader.bind(this);
    this.appendHeader = this.appendHeader.bind(this);
    this.setHeaders = this.setHeaders.bind(this);
    this.getRawHeaderNames = this.getRawHeaderNames.bind(this);
    this.writeHead = this.writeHead.bind(this);
    this.flushHeaders = this.flushHeaders.bind(this);
    this._flushHeaders = this._flushHeaders.bind(this);
    this.write = this.write.bind(this);
    this.end = this.end.bind(this);
  }

  /**
   * The peer is gone — the stream reset, the connection lost — while this
   * response was still being written. As node:http: 'close', once; later
   * writes are dropped without an error, so a handler mid-flight is not
   * taken down, and a pipe() into the response stops. Without it a response
   * whose connection died never closed, and a pipe() kept reading its source
   * into a connection that was gone.
   */
  _abortResponse() {
    if (this.writableFinished || this.destroyed) return;
    this._aborted = true;
    this.destroy();
  }

  /**
   * res.destroy([err]) by the application, mid-response: the transport ends
   * the stream so the client hears it — RESET_STREAM over HTTP/3, RST_STREAM
   * over HTTP/2, the socket over HTTP/1.1 (as node:http) — with an internal
   * error's code when there is an err (a failed pipeline), a cancel's
   * otherwise. It was local only: the client waited for the rest of a
   * response that would never come, and over HTTP/3 and HTTP/2 the stream
   * stayed open until the connection closed. As node:http, the err is not
   * re-emitted as 'error' to a response nobody listens to.
   */
  _onDestroy(fn) {
    (this._destroyHooks || (this._destroyHooks = [])).push(fn);
  }

  _destroy(err, cb) {
    var hooks = this._destroyHooks;
    this._destroyHooks = null;
    if (hooks && !this._aborted && !this.writableFinished) {
      for (var i = 0; i < hooks.length; i++) { try { hooks[i](err); } catch (e) {} }
    }
    cb(err && this.listenerCount('error') > 0 ? err : null);
  }

  // ---- Header management (mirrors node:http) ----

  setHeader(name, value) {
    if (this.headersSent) throw headersSentError('set', this.req && this.req.httpVersion);
    validateHeaderName(name);
    validateHeaderValue(name, value);
    var lower = name.toLowerCase();
    this._headers[lower] = value;
    this._headerNames[lower] = name;
    return this;
  }

  getHeader(name) {
    return this._headers[name.toLowerCase()];
  }

  // An object with no prototype, as node:http's: a header named
  // "constructor" or "__proto__" is a header, not a property it inherits.
  getHeaders() {
    var out = Object.create(null);
    for (var k in this._headers) out[k] = this._headers[k];
    return out;
  }

  getHeaderNames() {
    return Object.keys(this._headers);
  }

  // node:http's: the names as they were set, in their case.
  getRawHeaderNames() {
    var out = [];
    for (var k in this._headers) out.push(this._headerNames[k] || k);
    return out;
  }

  // node:http's: a value added to a header's (both kept), not in its place.
  appendHeader(name, value) {
    if (this.headersSent) throw headersSentError('append', this.req && this.req.httpVersion);
    return this._appendHeader(name, value);
  }

  // node:http's: several at once, from a Headers or a Map — each replacing
  // that name's value (Set-Cookie: every one of a Headers' cookies).
  setHeaders(headers) {
    if (this.headersSent) throw headersSentError('set', this.req && this.req.httpVersion);
    var isHeaders = typeof Headers !== 'undefined' && headers instanceof Headers;
    if (!isHeaders && !(headers instanceof Map)) {
      var e = new TypeError('The "headers" argument must be an instance of Headers or Map');
      e.code = 'ERR_INVALID_ARG_TYPE';
      throw e;
    }
    var self = this, cookies = null;
    headers.forEach(function (value, name) {
      if (isHeaders && String(name).toLowerCase() === 'set-cookie') { cookies = headers.getSetCookie(); return; }
      self.setHeader(name, value);
    });
    if (cookies) this.setHeader('set-cookie', cookies);
    return this;
  }

  hasHeader(name) {
    return name.toLowerCase() in this._headers;
  }

  removeHeader(name) {
    if (this.headersSent) throw headersSentError('remove', this.req && this.req.httpVersion);
    var lower = name.toLowerCase();
    delete this._headers[lower];
    delete this._headerNames[lower];
    return this;
  }

  // A value added to what a name has (kept as a list), not in its place.
  _appendHeader(name, value) {
    var lower = String(name).toLowerCase();
    if (!(lower in this._headers)) return this.setHeader(name, value);
    validateHeaderName(name);
    validateHeaderValue(name, value);
    this._headers[lower] = [].concat(this._headers[lower], value);
    return this;
  }

  /**
   * node:http's res.addTrailers(headers): fields sent after the body — an
   * object, or an array of [name, value] pairs. Over HTTP/1.1 they go in the
   * last chunk (chunked responses only, as node); over HTTP/2 as a trailing
   * HEADERS frame. The layers read res.trailers, but the method an application
   * calls was missing: it threw a TypeError inside the handler, and over
   * HTTP/2 that tore down the whole connection.
   */
  addTrailers(headers) {
    if (!this.trailers) this.trailers = {};
    var pairs = Array.isArray(headers) ? headers : Object.keys(headers || {}).map(function (k) { return [k, headers[k]]; });
    for (var i = 0; i < pairs.length; i++) {
      var name = pairs[i][0], value = pairs[i][1];
      validateHeaderName(name, 'Trailer name');
      validateHeaderValue(name, value);
      this.trailers[String(name).toLowerCase()] = value;
    }
  }

  // ---- writeHead ----

  writeHead(statusCode, statusMessage, headers) {
    if (this.headersSent) return this;

    if (typeof statusMessage === 'object' && !headers) {
      headers = statusMessage;
      statusMessage = undefined;
    }

    validateStatus(statusCode, statusMessage);
    this.statusCode = statusCode;
    if (statusMessage !== undefined) this.statusMessage = String(statusMessage);

    // node:http's three forms: an object; a flat array [name, value, name,
    // value]; an array of [name, value] pairs. The arrays may repeat a name
    // and every value is kept (two Set-Cookie lines). An array went through
    // for…in: headers named "0", "1", … — over HTTP/3 the response failed.
    if (Array.isArray(headers)) {
      var tuples = headers.length > 0 && Array.isArray(headers[0]);
      if (!tuples && headers.length % 2 !== 0) {
        var bad = new TypeError('The argument \'headers\' is invalid: an array of names and values must have an even length');
        bad.code = 'ERR_INVALID_ARG_VALUE';
        throw bad;
      }
      for (var i = 0; i < headers.length; i += tuples ? 1 : 2) {
        var hn = tuples ? headers[i][0] : headers[i], hv = tuples ? headers[i][1] : headers[i + 1];
        if (hn) this._appendHeader(hn, hv);
      }
    } else if (typeof headers === 'object' && headers !== null) {
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
    this._wrote = true;
    this._countBody(chunk, encoding, false);
    return super.write(chunk, encoding, callback);
  }

  // strictContentLength (node:http's): the body may not go past its
  // Content-Length, nor end short of it — ERR_HTTP_CONTENT_LENGTH_MISMATCH,
  // thrown from the write() or end() that shows it.
  // Counted only once checked: a write that threw sent nothing.
  _countBody(chunk, encoding, ending) {
    var total = this._bodyBytes;
    if (chunk != null && !this.writableEnded) {
      total += typeof chunk === 'string' ? Buffer.byteLength(chunk, encoding) : (chunk.byteLength || 0);
    }
    var declared = this.strictContentLength ? this.getHeader('content-length') : undefined;
    if (declared !== undefined && !Array.isArray(declared) && !(this.req && this.req.method === 'HEAD') && Number(declared) >= 0) {
      declared = Number(declared);
      if (total > declared || (ending && total !== declared)) {
        var e = new Error('Response body\'s content-length of ' + total + ' byte(s) does not match the content-length of ' + declared + ' byte(s) set in header');
        e.code = 'ERR_HTTP_CONTENT_LENGTH_MISMATCH';
        throw e;
      }
    }
    this._bodyBytes = total;
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') { callback = data; data = undefined; encoding = undefined; }
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (!this.writableEnded) {
      if (data != null) this._countBody(data, encoding, true);
      else this._countBody(null, null, true);
    }
    // The whole body, when nothing was written before it and the head has
    // not gone: its length, for HTTP/1.1 to send as Content-Length rather
    // than chunk it (node:http's end() does the same). HTTP/2 and HTTP/3
    // frame the body themselves and do not read it.
    if (!this.headersSent && !this._wrote && !this.writableEnded) {
      var len = data == null ? 0
        : typeof data === 'string' ? Buffer.byteLength(data, encoding)
        : data.byteLength;
      if (typeof len === 'number') this._endLength = len;   // else write() rejects it
    }
    if (data != null) this._writeCounted(data, encoding);
    // The callback runs at 'finish', after the listeners already on it — as
    // node:http's end(cb), a once('finish'). Given to Writable's end() it
    // ran before them.
    if (typeof callback === 'function') {
      if (this.writableFinished) process.nextTick(callback);
      else this.once('finish', callback);
    }
    super.end();
    return this;
  }

  // The last write, its bytes already counted by end().
  _writeCounted(data, encoding) {
    this._wrote = true;
    return super.write(data, encoding);
  }

  writeContinue() { /* HTTP/3 doesn't use 100-continue — stub */ }

  /**
   * 103 Early Hints (RFC 8297) — node:http's response.writeEarlyHints(hints[,
   * callback]). `hints` is a header object; `link` a string or an array of
   * them. The protocol layer that made this response replaces this with the
   * real thing (h1_server, h2_server, h3_server); this one, on a response
   * nothing wired, sends nothing and still calls back.
   */
  writeEarlyHints(hints, callback) {
    if (typeof callback === 'function') process.nextTick(callback);
  }

  /**
   * 102 Processing — node:http's response.writeProcessing(). Replaced by the
   * layer that made the response, as writeEarlyHints is; here, nothing.
   */
  writeProcessing() {}

  /**
   * The response's priority, { urgency, incremental } (RFC 9218). HTTP/2 and
   * HTTP/3 replace this with the real thing (h2_server, h3_server); over
   * HTTP/1.1 a connection carries one response at a time, so there is
   * nothing to order, and it does nothing. It was missing there: the same
   * handler, reached over HTTP/1.1, threw a TypeError.
   */
  setPriority(priority) {}

  setTimeout(msecs, callback) {
    if (callback) this.once('timeout', callback);
    return this;
  }
}


// ============================================================
//  ClientRequest — extends Writable
//
//  Wraps outgoing HTTP request on the client side.
//  The body flows as it is written, as node:http's does: held here only
//  until a transport takes the request (_attachSink — the first of the
//  protocols tried to be ready to send), then handed to it, with its
//  backpressure (write() false, 'drain'). What was handed is kept, up to
//  REPLAY_MAX, so that a request another protocol must carry after all — the
//  first failed before the server processed it — can be sent again whole.
//
//  The 'response' event delivers an IncomingMessage.
// ============================================================

// How much of a request body is kept, once handed to a transport, for
// sending again over another — what a request refused unprocessed (REFUSED_
// STREAM, H3_REQUEST_REJECTED, past a GOAWAY) or whose first protocol failed
// may need. Past it, the body streams without a copy.
var REPLAY_MAX = 64 * 1024;

class ClientRequest extends Writable {

  constructor(options) {
    super({
      highWaterMark: (options && options.highWaterMark) || 64 * 1024,
      // Node's Writable default (autoDestroy: true) marks the stream
      // destroyed the moment the request BODY finishes — i.e. milliseconds
      // after end(), on every GET. But a ClientRequest outlives its body: the
      // transport keeps working on it until the response completes, and
      // node:http's ClientRequest behaves exactly that way. With the default,
      // `destroyed` stops meaning "aborted" and starts meaning "body written",
      // and every liveness guard built on it silently kills healthy requests:
      // the H3→H2/H1 fallback after the 3s timeout hit such a guard and died
      // for every GET, and coalesced requests parked on a shared connection
      // being established were dropped at wake-up the same way. abort() still
      // calls destroy() explicitly, so real cancellations are unaffected.
      autoDestroy: false
    });

    options = options || {};

    // node:http throws these from http.request() itself: the path (no CR, LF,
    // space or other control character — CVE-2018-12116 was a request split
    // through it) and the method (a token).
    validateRequestTarget(options.path, options.method);

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

    // The body: held until a transport takes the request, then streamed to it.
    this._bodyChunks = [];
    this._bodyBuffered = 0;
    this._pendingWriteCb = null;   // a write held for room (before a transport)
    this._sink = null;             // the transport request carrying the body
    this._sinkWaitCb = null;       // a write waiting for the sink's 'drain'
    this._replay = [];             // what the sink was handed, while ≤ REPLAY_MAX
    this._replayBytes = 0;
    this._replayable = true;
    this._trailers = null;         // addTrailers()
    this._priority = null;         // setPriority()

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

    // The response, once there is one (node:http's req.res), and how to stop
    // each transport attempt that carries this request (see _destroy).
    this.res = null;
    this._cancels = [];
  }

  // ---- Cancellation ----
  //
  // destroy() / abort() stop the exchange where it is carried, as node:http's
  // do by destroying the socket. Without this they only marked the request:
  // the transport went on, and the response kept downloading in the
  // background. Each transport attempt registers how to stop itself — over
  // HTTP/3 and HTTP/2 that is the request's stream, not the (shared)
  // connection; over HTTP/1.1, the socket, which cannot be reused mid-exchange.

  _onCancel(fn) {
    if (this.destroyed) { fn(); return; }
    this._cancels.push(fn);
  }

  // node:http: destroyed before a response, the request fails with 'socket
  // hang up' (ECONNRESET) unless given its own error.
  destroy(err) {
    if (this.destroyed) return this;
    if (!err && !this.res && !this.aborted) { err = new Error('socket hang up'); err.code = 'ECONNRESET'; }
    return super.destroy(err);
  }

  _destroy(err, cb) {
    var cancels = this._cancels;
    this._cancels = [];
    for (var i = 0; i < cancels.length; i++) { try { cancels[i](); } catch (e) {} }
    if (this._timeoutTimer) { clearTimeout(this._timeoutTimer); this._timeoutTimer = null; }
    if (this.res && !this.res.complete) this.res._abort(err && err.code !== 'ECONNRESET' ? err : null);
    cb(err);
  }

  // ---- Header management ----

  setHeader(name, value) {
    validateHeaderName(name);
    validateHeaderValue(name, value);
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
    if (this._sink && this._wholeBody) {
      // end(data) with nothing written before it: the body whole, handed to
      // the transport as its end — sent with a content-length, as node:http
      // sends end(data). Written, then ended, a transport already able to
      // send had begun streaming on the write: no length, and a server that
      // goes by the headers (Express's body-parser) saw no body. It happened
      // whenever the connection was ready at once — a pooled one.
      this._wholeBody = false;
      this._sinkEnded = true;
      this._remember(chunk);
      this._sink.end(chunk, this._trailers);
      callback();
      return;
    }
    this._wholeBody = false;
    if (this._sink) { this._toSink(chunk, callback); return; }
    // No transport yet (still connecting): held — and the writer told to wait
    // past the high-water mark, as a socket not yet connected would.
    this._bodyChunks.push(chunk);
    this._bodyBuffered += chunk.byteLength;
    if (this._bodyBuffered < this.writableHighWaterMark) callback();
    else this._pendingWriteCb = callback;
  }

  _final(callback) {
    this.finished = true;
    if (this._sink && !this._sinkEnded) { this._sinkEnded = true; this._sink.end(null, this._trailers); }
    callback();
  }

  // node:http's addTrailers(): fields sent after the body (a HEADERS frame
  // over HTTP/2 and HTTP/3; with chunked encoding over HTTP/1.1). An object,
  // or a list of [name, value] pairs.
  addTrailers(headers) {
    var t = this._trailers || (this._trailers = {});
    var pairs = Array.isArray(headers) ? headers : Object.keys(headers || {}).map(function (k) { return [k, headers[k]]; });
    for (var i = 0; i < pairs.length; i++) {
      var name = pairs[i][0], value = pairs[i][1];
      validateHeaderName(name);
      validateHeaderValue(name, value);
      t[String(name).toLowerCase()] = value;
    }
  }

  // The request's priority (RFC 9218): { urgency: 0-7 (3), incremental
  // (false) } — the `priority` header while the request has not gone, a
  // PRIORITY_UPDATE after it (HTTP/2, HTTP/3), as res.setPriority is the
  // server's. Normalized the same way.
  setPriority(p) {
    this._priority = responsePriority(p);
    if (this._sink && typeof this._sink.setPriority === 'function') this._sink.setPriority(this._priority);
    return this;
  }

  // ---- The transport that carries the body (client.js) ----

  // `sink` (a transport's request: write → more?, 'drain', end(chunk,
  // trailers)) takes the request: what is held goes to it, and from now on
  // every write.
  _attachSink(sink) {
    var self = this;
    this._sink = sink;
    if (this._priority && typeof sink.setPriority === 'function') sink.setPriority(this._priority);
    sink.on('drain', function () {
      if (self._sink !== sink || !self._sinkWaitCb) return;
      var cb = self._sinkWaitCb; self._sinkWaitCb = null; cb();
    });
    var held = this._bodyChunks, more = true;
    this._bodyChunks = []; this._bodyBuffered = 0;
    this._sinkEnded = false;
    if (this.finished) {
      // Ended before a transport took it: the body is known whole — one
      // end(), so it goes with its length rather than streamed.
      for (var j = 0; j < held.length; j++) this._remember(held[j]);
      var whole = held.length === 0 ? null : held.length === 1 ? held[0] : Buffer.concat(held);
      this._sinkEnded = true;
      sink.end(whole, this._trailers);
      return;
    }
    for (var i = 0; i < held.length; i++) { this._remember(held[i]); more = sink.write(held[i]); }
    if (this._pendingWriteCb) {
      var cb = this._pendingWriteCb; this._pendingWriteCb = null;
      if (more) cb(); else this._sinkWaitCb = cb;
    }
  }

  // The transport failed before the server processed the request: the body
  // back here, whole, for the next — or false if it cannot be (more than
  // REPLAY_MAX was handed over: not kept).
  _detachSink() {
    if (!this._replayable) return false;
    this._sink = null;
    this._bodyChunks = this._replay; this._bodyBuffered = this._replayBytes;
    this._replay = []; this._replayBytes = 0;
    if (this._sinkWaitCb) { this._pendingWriteCb = this._sinkWaitCb; this._sinkWaitCb = null; }
    return true;
  }

  _toSink(chunk, callback) {
    this._remember(chunk);
    if (this._sink.write(chunk)) callback();
    else this._sinkWaitCb = callback;
  }

  _remember(chunk) {
    if (!this._replayable) return;
    this._replayBytes += chunk.byteLength;
    if (this._replayBytes > REPLAY_MAX) { this._replayable = false; this._replay = []; this._replayBytes = 0; return; }
    this._replay.push(chunk);
  }

  // ---- Convenience overrides ----

  write(chunk, encoding, callback) {
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    this._wroteBody = true;
    return super.write(chunk, encoding, callback);
  }

  end(data, encoding, callback) {
    if (typeof data === 'function') { callback = data; data = undefined; encoding = undefined; }
    if (typeof encoding === 'function') { callback = encoding; encoding = undefined; }
    if (data != null) {
      // Nothing written before: this chunk is the body whole (_write).
      this._wholeBody = !this._wroteBody && !this.writableEnded;
      this.write(data, encoding);
    }
    return super.end(callback);
  }

  // node:http: 'abort', then 'close' — no error.
  abort() {
    if (this.aborted || this.destroyed) return;
    this.aborted = true;
    var self = this;
    process.nextTick(function () { self.emit('abort'); });
    this.destroy();
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
}


// ============================================================
//  Socket stub — for libraries that check req.socket / res.socket
//  Must be a real Stream so Node's eos() / Express don't crash.
// ============================================================

/**
 * Make an Express application (or anything built the same way) run on these
 * streams.
 *
 * Express does not use the req and res it is handed as they are: on every
 * request it swaps their prototype for its own (Object.setPrototypeOf(req,
 * app.request)), and that chain ends in node:http's IncomingMessage and
 * ServerResponse. Every method of these classes is gone after that — a
 * request body arrived through _pushData, which no longer existed, and the
 * server fell over on the first POST. The response survived only because its
 * methods are also bound onto each instance (see the constructor), and even
 * so it ran on node:http's getters for its state.
 *
 * So the chain is re-parented instead, once per application:
 *
 *   before   app.response → express's response methods → http.ServerResponse
 *   after    app.response → a copy of those methods    → quico ServerResponse
 *
 * Express's methods — req.get, res.json, res.send, res.cookie,
 * express.static — sit on top and call the ones below, which are now ours:
 * the same object, on HTTP/1.1, HTTP/2 and HTTP/3.
 *
 * A COPY, because the object holding Express's methods is shared by every
 * Express application in the process: re-parenting it would move them all,
 * including any served by node:http. The copy belongs to this application
 * alone. A sub-application inherits from its parent's objects when it is
 * mounted, so the root is the only one that needs it.
 *
 * Recognised by shape — a function with `request` and `response` objects —
 * not by name; left alone when already adopted or not that shape. Returns
 * the handler, for chaining.
 */
function adoptApp(handler) {
  if (typeof handler !== 'function') return handler;
  reparent(handler.request, IncomingMessage);
  reparent(handler.response, ServerResponse);
  return handler;
}

// Put `Base` under obj's prototype chain in place of the class it ends in: the
// objects between obj and the first class prototype (one owning a
// `constructor`) are copied, the last copy inheriting from Base.prototype.
function reparent(obj, Base) {
  if (!obj || typeof obj !== 'object' || obj instanceof Base) return;
  var between = [];
  var p = Object.getPrototypeOf(obj);
  while (p && !Object.prototype.hasOwnProperty.call(p, 'constructor')) {
    between.push(p);
    p = Object.getPrototypeOf(p);
  }
  if (!p || p === Object.prototype) return;   // not a class chain: not ours to change
  var top = Base.prototype;
  for (var i = between.length - 1; i >= 0; i--) {
    top = Object.create(top, Object.getOwnPropertyDescriptors(between[i]));
  }
  Object.setPrototypeOf(obj, top);
}

// rawHeaders' pairs as node:http's headersDistinct: name → [values].
function distinctFields(raw) {
  var out = {};
  for (var i = 0; raw && i + 1 < raw.length; i += 2) {
    var n = String(raw[i]).toLowerCase();
    (out[n] || (out[n] = [])).push(String(raw[i + 1]));
  }
  return out;
}

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


export { IncomingMessage, ServerResponse, ClientRequest, _makeSocketStub, adoptApp };
