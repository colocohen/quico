/*
 * quico: a full HTTP stack in JavaScript
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://github.com/colocohen/quico
 */

import { Blob } from 'node:buffer';

import {
  WSParser, encodeFrame, acceptKey,
  OPCODE, CLOSE,
  installEventSurfaces, emitBoth, nodeMessagePayload,
  userCloseCode, closeReasonBytes, sendInOrder, queueCloseFrame
} from './ws.js';
import { isToken, STATUS_TEXT } from './http_common.js';


// ============================================================
//  WebSocket server.
//
//  The connection object handed to the application is the SAME WebSocket the
//  browser defines and the same one ws_client.js produces — same events, same
//  readyState, same close semantics, same binaryType. A function written to
//  handle a socket works unchanged on either side, which is the whole reason
//  for choosing the browser interface over the `ws` package's shape.
//
//  What has no browser equivalent is *accepting* a connection, because a
//  browser never does. That part is modelled on Deno and Cloudflare Workers,
//  which return a standard WebSocket from a server-side upgrade — and on the
//  `ws` package for the handshake validation itself, which is worth copying
//  precisely: it answers a bad handshake with a real HTTP response rather than
//  dropping the socket, so a client learns WHY it was refused instead of
//  seeing a connection reset.
// ============================================================

var CONNECTING = 0, OPEN = 1, CLOSING = 2, CLOSED = 3;
var CLOSE_TIMEOUT = 30000;

// A Sec-WebSocket-Key is 16 random bytes in base64 — always 24 characters
// ending in '=='. Checking the shape (as `ws` does) catches a client that is
// not really speaking WebSocket before any state is built for it.
var KEY_RE = /^[+/0-9A-Za-z]{22}==$/;

var CloseEventCtor = typeof CloseEvent !== 'undefined' ? CloseEvent : function (type, init) {
  init = init || {};
  var ev = new Event(type, init);
  Object.defineProperties(ev, {
    code:     { value: init.code === undefined ? 0 : init.code, enumerable: true },
    reason:   { value: init.reason === undefined ? '' : init.reason, enumerable: true },
    wasClean: { value: !!init.wasClean, enumerable: true }
  });
  return ev;
};


// ============================================================
//  ServerWebSocket — the WHATWG interface, server side
// ============================================================

class ServerWebSocket extends EventTarget {

  static get CONNECTING() { return CONNECTING; }
  static get OPEN()       { return OPEN; }
  static get CLOSING()    { return CLOSING; }
  static get CLOSED()     { return CLOSED; }

  constructor(socket, options) {
    super();
    options = options || {};

    this._socket = socket;
    this._readyState = OPEN;      // the handshake is already complete
    this._bufferedAmount = 0;
    this._binaryType = 'blob';    // the browser's default
    this._protocol = options.protocol || '';
    this._extensions = '';
    this._url = options.url || '';
    try { this._origin = new URL(this._url).origin; } catch (e) { this._origin = ''; }

    this._closeSent = false;
    this._closeReceived = false;
    this._closeCode = CLOSE.ABNORMAL;
    this._closeReason = '';
    this._closeTimer = null;

    this._onopen = null; this._onmessage = null;
    this._onerror = null; this._onclose = null; this._onpong = null;

    // Adds .on/.once/.off and the _emitNode helper. See ws.js (installEventSurfaces) for why
    // the two surfaces receive different arguments for the same event.
    installEventSurfaces(this);

    var self = this;
    // isServer: true — incoming frames MUST be masked and outgoing ones must
    // NOT be. The parser enforces the direction; getting it backwards is a
    // protocol error the peer will close on.
    var parser = new WSParser({ isServer: true, maxPayload: options.maxPayload });
    this._parser = parser;

    parser.on('message', function (data, isBinary) {
      if (self._readyState !== OPEN) return;
      emitBoth(self, 'message',
        new MessageEvent('message', {
          data: isBinary ? self._toBinary(data) : data,
          // The URL's origin, as the client's (not the whole URL).
          origin: self._origin
        }),
        // The ws surface gets the raw payload, NOT self._toBinary(data): `ws`
        // has no binaryType and its handlers always receive a Buffer.
        [nodeMessagePayload(data, isBinary), isBinary]);
    });

    parser.on('ping', function (payload) {
      // Answered automatically, as a browser does — but `ws` DOES surface
      // pings to its listeners, so the ws-side event fires. The WHATWG side
      // has no 'ping' event at all, which is why this one is emitted on that
      // surface only.
      if (self._readyState === OPEN) self._sendFrame(OPCODE.PONG, payload);
      self._emitNode('ping', [payload]);
    });

    parser.on('pong', function (payload) {
      self._pongSeen = true;
      emitBoth(self, 'pong', new MessageEvent('pong', { data: payload }), [payload]);
    });

    parser.on('close', function (code, reason) {
      self._closeReceived = true;
      self._closeCode = code;
      // Only take the peer's reason when we did not supply one. When WE
      // started the handshake, the reason belongs to us: a peer that echoes an
      // empty reason (or a different one) must not overwrite what the
      // application asked to report.
      if (!self._closeSent || !self._closeReason) self._closeReason = reason;
      if (!self._closeSent) {
        // Echo the peer's code AND reason back (RFC 6455 §5.5.1 allows any
        // reason; `ws` echoes the one it received, and matching it matters:
        // the peer reports what comes back in ITS close event, so replying
        // with an empty reason silently erases the reason the peer just gave).
        self._readyState = CLOSING;
        self._sendCloseFrame(code === CLOSE.NO_STATUS ? undefined : code,
                             Buffer.from(reason || '', 'utf8'), true);
      }
      self._teardown(true);
    });

    parser.on('error', function (err) {
      self._sendCloseFrame(err.closeCode || CLOSE.PROTOCOL_ERROR, Buffer.alloc(0));
      self._closeCode = err.closeCode || CLOSE.PROTOCOL_ERROR;
      self._fail(err);
    });

    socket.on('data', function (chunk) { parser.execute(chunk); });
    socket.on('error', function (err) { self._fail(err); });
    socket.on('close', function () { self._teardown(self._closeSent && self._closeReceived); });
    socket.on('end', function () { self._teardown(self._closeSent && self._closeReceived); });

    if (socket.setNoDelay) socket.setNoDelay(true);

    // Frames that shared a TCP segment with the handshake request. A client
    // may legitimately send its first frame immediately after the request, and
    // dropping these loses it — a bug that only appears under load, when
    // segments happen to coalesce.
    //
    // Deferred, and that is not a detail. The application attaches onmessage
    // from the connection handler, which cannot run until this constructor
    // returns — so feeding the head here would emit a 'message' with nobody
    // listening and the frame would be silently swallowed. The failure looks
    // exactly like the bug this code exists to prevent: the first frame goes
    // missing, only when segments coalesce.
    // A server-side socket is open the moment it exists, but `ws` code written
    // for the client side still waits for 'open'. Fire it once, asynchronously,
    // so a handler attached right after construction sees it.
    queueMicrotask(function () {
      if (self._readyState === OPEN) emitBoth(self, 'open', new Event('open'), []);
    });

    if (options.head && options.head.length) {
      var head = options.head;
      queueMicrotask(function () {
        if (self._readyState === OPEN) parser.execute(head);
      });
    }
  }

  get url() { return this._url; }
  get readyState() { return this._readyState; }
  get bufferedAmount() { return this._bufferedAmount; }
  get protocol() { return this._protocol; }
  get extensions() { return this._extensions; }

  get CONNECTING() { return CONNECTING; }
  get OPEN()       { return OPEN; }
  get CLOSING()    { return CLOSING; }
  get CLOSED()     { return CLOSED; }

  get binaryType() { return this._binaryType; }
  set binaryType(v) {
    if (v !== 'blob' && v !== 'arraybuffer' && v !== 'nodebuffer') return;
    this._binaryType = v;
  }

  get onopen() { return this._onopen; }
  set onopen(fn) { this._setHandler('open', '_onopen', fn); }
  get onmessage() { return this._onmessage; }
  set onmessage(fn) { this._setHandler('message', '_onmessage', fn); }
  get onerror() { return this._onerror; }
  set onerror(fn) { this._setHandler('error', '_onerror', fn); }
  get onclose() { return this._onclose; }
  set onclose(fn) { this._setHandler('close', '_onclose', fn); }
  /** Not in the browser — see ping() below. */
  get onpong() { return this._onpong; }
  set onpong(fn) { this._setHandler('pong', '_onpong', fn); }

  _setHandler(type, slot, fn) {
    if (this[slot]) this.removeEventListener(type, this[slot]);
    this[slot] = typeof fn === 'function' ? fn : null;
    if (this[slot]) this.addEventListener(type, this[slot]);
  }

  /**
   * send(data[, options])
   *
   * `options` is the ws extension, not WHATWG — a browser's send() takes one
   * argument and infers text-vs-binary from the type. That inference is wrong
   * for the ws surface, where every message arrives as a Buffer: echoing one
   * back would turn a text message into a binary one, and the peer would
   * report isBinary: true for something the sender called text.
   *
   * So `{ binary: false }` forces a Buffer to go out as a text frame, and
   * `{ binary: true }` forces a string to go out as binary. Omitted, the
   * browser's inference applies and browser code is unaffected.
   */
  send(data, options) {
    if (this._readyState === CONNECTING) {
      throw new DOMException('Still in CONNECTING state.', 'InvalidStateError');
    }
    var forced = options && typeof options.binary === 'boolean' ? options.binary : null;
    var opcode, payload;
    if (typeof data === 'string') { opcode = forced === true ? OPCODE.BINARY : OPCODE.TEXT; payload = Buffer.from(data, 'utf8'); }
    else if (data instanceof Blob) { opcode = forced === false ? OPCODE.TEXT : OPCODE.BINARY; payload = data; }
    else if (ArrayBuffer.isView(data)) { opcode = forced === false ? OPCODE.TEXT : OPCODE.BINARY; payload = Buffer.from(data.buffer, data.byteOffset, data.byteLength); }
    else if (data instanceof ArrayBuffer) { opcode = forced === false ? OPCODE.TEXT : OPCODE.BINARY; payload = Buffer.from(data); }
    else { opcode = OPCODE.TEXT; payload = Buffer.from(String(data), 'utf8'); }
    if (this._readyState !== OPEN) {
      this._bufferedAmount += payload instanceof Blob ? payload.size : payload.length;   // as the client's
      return;
    }
    // In the order sent, a Blob included (ws.js sendInOrder): a Blob was
    // sent whenever it had been read, after messages sent later.
    sendInOrder(this, opcode, payload);
  }

  /**
   * Not in the browser, and a server cannot do without it.
   *
   * A browser answers pings itself and its connections are supervised by the
   * page lifecycle. A server holding thousands of long-lived sockets has no
   * such supervision: a peer that vanishes without a FIN — a laptop lid, a NAT
   * timeout — leaves a socket that looks perfectly healthy for many minutes.
   * A ping with no pong is the only way to notice.
   */
  ping(data) {
    if (this._readyState !== OPEN) return;
    this._pongSeen = false;
    this._sendFrame(OPCODE.PING, data == null ? Buffer.alloc(0)
                  : Buffer.isBuffer(data) ? data : Buffer.from(data));
  }

  _sendFrame(opcode, payload, cb) {
    if (!this._socket || this._socket.destroyed) { if (cb) cb(new Error('the WebSocket is closed')); return; }
    var frame;
    // mask: false — a SERVER must never mask (RFC 6455 §5.1). This is the one
    // line that differs from the client, and a client will close the
    // connection with 1002 if it is wrong.
    try { frame = encodeFrame(opcode, payload, { mask: false }); }
    catch (e) { if (cb) cb(e); this._fail(e); return; }

    var self = this;
    if (opcode < 0x8) this._bufferedAmount += payload.length;
    this._socket.write(frame, function (err) {
      if (opcode < 0x8) self._bufferedAmount -= payload.length;
      if (cb) cb(err || null);
    });
  }

  close(code, reason) {
    // As the client's (ws.js): a code given, null too, is clamped and checked.
    if (code !== undefined) code = userCloseCode(code);
    var reasonBuf = reason !== undefined ? closeReasonBytes(reason) : Buffer.alloc(0);
    if (this._readyState === CLOSING || this._readyState === CLOSED) return;

    this._readyState = CLOSING;
    this._closeCode = code === undefined ? CLOSE.NORMAL : code;
    // As it goes on the wire: a lone surrogate is U+FFFD there (USVString).
    this._closeReason = reasonBuf.toString('utf8');
    this._sendCloseFrame(code === undefined ? undefined : code, reasonBuf);

    var self = this;
    this._closeTimer = setTimeout(function () { self._teardown(false); }, CLOSE_TIMEOUT);
    if (this._closeTimer.unref) this._closeTimer.unref();
  }

  // `now`: answering the peer's close — what is still queued (a Blob being
  // read) is dropped, the connection is over. Otherwise the close frame goes
  // after the messages sent before close(), never ahead of them: a Blob still
  // being read went out after the close frame, which a peer takes as a
  // protocol error.
  _sendCloseFrame(code, reasonBuf, now) {
    if (this._closeSent) return;
    this._closeSent = true;
    var payload;
    if (code === undefined) payload = Buffer.alloc(0);
    else {
      payload = Buffer.alloc(2 + (reasonBuf ? reasonBuf.length : 0));
      payload.writeUInt16BE(code, 0);
      if (reasonBuf && reasonBuf.length) reasonBuf.copy(payload, 2);
    }
    if (queueCloseFrame(this, payload, now)) return;
    if (this._socket && !this._socket.destroyed) {
      try { this._socket.write(encodeFrame(OPCODE.CLOSE, payload, { mask: false })); } catch (e) {}
    }
  }

  _toBinary(buf) {
    if (this._binaryType === 'nodebuffer') return buf;
    if (this._binaryType === 'arraybuffer') {
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }
    return new Blob([buf]);
  }

  _fail(err) {
    if (this._readyState === CLOSED) return;
    var event = new Event('error');
    try { Object.defineProperty(event, 'error', { value: err, enumerable: true }); } catch (e) {}
    try { Object.defineProperty(event, 'message', { value: err && err.message, enumerable: true }); } catch (e) {}
    // WHATWG gets an Event; ws gets the Error itself.
    emitBoth(this, 'error', event, [err]);
    this._teardown(false);
  }

  _teardown(wasClean) {
    if (this._readyState === CLOSED) return;
    this._readyState = CLOSED;
    if (this._closeTimer) { clearTimeout(this._closeTimer); this._closeTimer = null; }
    if (this._socket) {
      var s = this._socket;
      this._socket = null;
      try { s.removeAllListeners('data'); } catch (e) {}
      try { s.destroy(); } catch (e) {}
    }
    var code = wasClean ? this._closeCode : (this._closeReceived ? this._closeCode : CLOSE.ABNORMAL);
    var reason = this._closeReason || '';
    emitBoth(this, 'close',
      new CloseEventCtor('close', { code: code, reason: reason, wasClean: !!wasClean }),
      // `ws` passes the reason as a Buffer, not a string. Kept as it is:
      // handlers written against ws call .toString() on it.
      [code, Buffer.from(reason, 'utf8')]);
  }
}


// ============================================================
//  Handshake
// ============================================================

/**
 * Refuse an upgrade with a real HTTP response.
 *
 * Worth doing rather than destroying the socket: a client that gets a 400 with
 * a reason can be fixed, while one that gets a connection reset cannot tell a
 * rejected handshake from a network fault. Modelled on how the `ws` package
 * handles this.
 */
function abortHandshake(socket, code, message, extraHeaders) {
  message = message || STATUS_TEXT[code] || '';
  var headers = {
    'Connection': 'close',
    'Content-Type': 'text/plain',
    'Content-Length': String(Buffer.byteLength(message))
  };
  for (var h in (extraHeaders || {})) headers[h] = extraHeaders[h];

  var lines = ['HTTP/1.1 ' + code + ' ' + (STATUS_TEXT[code] || '')];
  for (var name in headers) lines.push(name + ': ' + headers[name]);

  try {
    socket.once('finish', function () { try { socket.destroy(); } catch (e) {} });
    socket.end(lines.join('\r\n') + '\r\n\r\n' + message);
  } catch (e) {
    try { socket.destroy(); } catch (e2) {}
  }
}


/**
 * Refuse an upgrade on whichever transport it arrived over.
 *
 * HTTP/1.1 gets a status line on the raw socket; HTTP/2 gets a response on the
 * stream. Same intent, and the caller should not have to care which — the only
 * reason this function exists is that the two cannot share bytes.
 */
function rejectUpgrade(socket, isH2, code, message, extraHeaders) {
  if (isH2 && typeof socket._h2Reject === 'function') {
    socket._h2Reject(code, message);
    return;
  }
  abortHandshake(socket, code, message, extraHeaders);
}


/** Parse Sec-WebSocket-Protocol into an ordered list, rejecting duplicates. */
function parseSubprotocols(header) {
  var out = [];
  var seen = Object.create(null);
  var parts = String(header).split(',');
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (!isToken(p)) throw new Error('invalid subprotocol: ' + JSON.stringify(p));
    if (seen[p]) throw new Error('duplicate subprotocol: ' + p);
    seen[p] = true;
    out.push(p);
  }
  return out;
}


/**
 * Complete a WebSocket handshake on an upgraded socket and return the
 * WebSocket.
 *
 * The primitive: `server.on('upgrade', (req, socket, head) => ...)` gives all
 * three arguments this needs, so an application can accept a WebSocket
 * anywhere it can see an upgrade, without a WebSocketServer at all.
 *
 * Returns null and answers the client itself if the handshake is invalid.
 */
function upgradeWebSocket(req, socket, head, options) {
  options = options || {};

  var headers = req.headers || {};
  var version = parseInt(headers['sec-websocket-version'], 10);

  // ---- Which transport is this? ----
  //
  // Over HTTP/1.1 a WebSocket arrives as an Upgrade: a GET with
  // Sec-WebSocket-Key, answered with 101 and a computed Accept.
  //
  // Over HTTP/2 it arrives as extended CONNECT (RFC 8441): a CONNECT with
  // `:protocol: websocket`, answered with 200 — and with NO Sec-WebSocket-Key
  // and no Accept at all. §5 removes them deliberately: the key exists only to
  // stop a naive HTTP/1.1 server being tricked into completing a handshake by
  // echoing a header, and HTTP/2 has no such confusion to prevent because the
  // stream is already framed.
  //
  // Everything after this point — subprotocols, origin, and every frame — is
  // identical, which is why the two transports share this function rather than
  // having one each.
  var isH2 = typeof socket._h2Accept === 'function';
  var key = headers['sec-websocket-key'];
  var upgrade = headers['upgrade'];

  if (isH2) {
    if (String(headers[':protocol'] || '').toLowerCase() !== 'websocket') {
      rejectUpgrade(socket, isH2, 400, 'Extended CONNECT is not for websocket');
      return null;
    }
  } else {
    // Each of these is checked before any state is built, and each answers with
    // the status RFC 6455 §4.2.1 calls for.
    if (req.method !== 'GET') {
      abortHandshake(socket, 405, 'Invalid HTTP method');
      return null;
    }
    if (upgrade === undefined || String(upgrade).toLowerCase() !== 'websocket') {
      abortHandshake(socket, 400, 'Invalid Upgrade header');
      return null;
    }
    if (key === undefined || !KEY_RE.test(String(key))) {
      // 16 random bytes in base64 is always 24 chars ending '=='. A client
      // that sends anything else is not really speaking WebSocket.
      abortHandshake(socket, 400, 'Missing or invalid Sec-WebSocket-Key header');
      return null;
    }
  }

  // Over HTTP/1.1 the header is mandatory: it is the only thing that
  // distinguishes a WebSocket handshake from an ordinary Upgrade, and a
  // request without it is not one.
  //
  // Over HTTP/2 and HTTP/3, `:protocol: websocket` has already said so
  // unambiguously, and browsers do not reliably send Sec-WebSocket-Version on
  // the extended CONNECT — Chrome's own network log of a WebSocket request
  // shows five pseudo-headers and nothing else. RFC 8441 §5 asks for it, but
  // refusing over it costs far more than it protects: the browser gets a 400,
  // silently abandons HTTP/2, and reopens the WebSocket over HTTP/1.1. The
  // connection still works, so nothing looks broken — it just never uses the
  // multiplexed path, and the reason is invisible from both ends.
  //
  // So it is required where it carries meaning and merely validated where it
  // does not: present and wrong is still an error, absent over h2/h3 is not.
  if (isH2) {
    if (headers['sec-websocket-version'] !== undefined && version !== 13) {
      rejectUpgrade(socket, isH2, 400, 'Unsupported Sec-WebSocket-Version',
                    { 'Sec-WebSocket-Version': '13' });
      return null;
    }
  } else if (version !== 13) {
    // Only version 13 exists. The header tells the client which we accept
    // (RFC 6455 §4.2.2).
    abortHandshake(socket, 400, 'Unsupported Sec-WebSocket-Version',
                   { 'Sec-WebSocket-Version': '13' });
    return null;
  }

  var offered = [];
  if (headers['sec-websocket-protocol'] !== undefined) {
    try {
      offered = parseSubprotocols(headers['sec-websocket-protocol']);
    } catch (err) {
      rejectUpgrade(socket, isH2, 400, 'Invalid Sec-WebSocket-Protocol header');
      return null;
    }
  }

  // ---- Origin ----
  //
  // The same-origin policy does NOT apply to WebSocket: a browser will happily
  // open one from any page to any host, and it sends the user's cookies with
  // the handshake. Without an origin check, any site the user visits can talk
  // to this server as that user — "cross-site WebSocket hijacking".
  //
  // So the check is opt-in but the default is a refusal to guess: with no
  // `origin` option nothing is enforced (a server behind a gateway, or one
  // that authenticates per message, is entitled to that), and the moment an
  // allowlist is given it is enforced strictly.
  if (options.origin !== undefined) {
    var origin = headers['origin'];
    var allowed = options.origin;
    var ok;
    if (typeof allowed === 'function') ok = !!allowed(origin, req);
    else if (Array.isArray(allowed)) ok = allowed.indexOf(origin) !== -1;
    else ok = (origin === allowed);
    if (!ok) {
      rejectUpgrade(socket, isH2, 403, 'Origin not allowed');
      return null;
    }
  }

  if (typeof options.verifyClient === 'function') {
    var verdict = options.verifyClient(req);
    if (verdict === false) { rejectUpgrade(socket, isH2, 401, 'Unauthorized'); return null; }
    if (verdict && verdict.code) {
      rejectUpgrade(socket, isH2, verdict.code, verdict.message, verdict.headers);
      return null;
    }
  }

  // A server may only select a protocol the client offered (§4.2.2).
  var chosen = null;
  if (options.protocol !== undefined && options.protocol !== null) {
    var want = typeof options.protocol === 'function'
             ? options.protocol(offered, req)
             : options.protocol;
    if (want) {
      if (offered.indexOf(want) === -1) {
        rejectUpgrade(socket, isH2, 400, 'Requested subprotocol was not offered by the client');
        return null;
      }
      chosen = want;
    }
  } else if (options.protocols && offered.length) {
    for (var i = 0; i < options.protocols.length && chosen === null; i++) {
      if (offered.indexOf(options.protocols[i]) !== -1) chosen = options.protocols[i];
    }
  }

  try {
    if (isH2) {
      // §5: a 2xx accepts the channel. No 101, no Accept — see the note above.
      var h2Headers = {};
      if (chosen) h2Headers['sec-websocket-protocol'] = chosen;
      for (var hn2 in (options.headers || {})) h2Headers[hn2] = options.headers[hn2];
      socket._h2Accept(h2Headers);
    } else {
      var responseLines = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        // The one value that proves we are a WebSocket server and not an HTTP
        // server tricked into echoing a header (§1.3).
        'Sec-WebSocket-Accept: ' + acceptKey(String(key))
      ];
      if (chosen) responseLines.push('Sec-WebSocket-Protocol: ' + chosen);
      for (var hn in (options.headers || {})) responseLines.push(hn + ': ' + options.headers[hn]);
      socket.write(responseLines.join('\r\n') + '\r\n\r\n');
    }
  } catch (err) {
    try { socket.destroy(); } catch (e) {}
    return null;
  }

  var scheme = (socket.encrypted || req.socket && req.socket.encrypted) ? 'wss' : 'ws';
  return new ServerWebSocket(socket, {
    protocol: chosen || '',
    head: head,
    maxPayload: options.maxPayload,
    // The origin the client asked for: Host over HTTP/1.1, :authority over
    // HTTP/2 and HTTP/3 (RFC 9113 §8.3.1, RFC 9114 §4.3.1) — over HTTP/3 the
    // request carries no Host at all, and the URL came out as "wss:///path".
    url: scheme + '://' + (headers['host'] || headers[':authority'] || '') + (req.url || '')
  });
}


// ============================================================
//  WebSocketServer
// ============================================================

/**
 * Attach to a quico (or node:http) server and hand out WebSockets.
 *
 *   const wss = new WebSocketServer({ server, path: '/chat' });
 *   wss.onconnection = (ws, req) => {
 *     ws.onmessage = e => ws.send(e.data);
 *   };
 *
 * `onconnection` rather than on('connection'): if the connection object is the
 * browser's WebSocket, the surface around it should read the same way.
 * addEventListener works too, for the same reason.
 */
class WebSocketServer extends EventTarget {

  constructor(options) {
    super();
    options = options || {};
    this.options = options;
    this.clients = new Set();
    this._onconnection = null;
    this._pingTimer = null;

    // The server object gets both surfaces as well: wss.onconnection is the
    // browser-style spelling, wss.on('connection') the ws one, and both
    // receive the same two arguments — there is no payload disagreement here
    // to preserve.
    installEventSurfaces(this);

    // `noServer: true` is the ws spelling of "I will call handleUpgrade
    // myself". Nothing to do for it here — not passing a `server` already has
    // that effect — but accepting the option means ws code reads the same.
    if (options.server && !options.noServer) {
      var self = this;
      options.server.on('upgrade', function (req, socket, head) {
        self.handleUpgrade(req, socket, head);
      });
    }

    // Keepalive. Off unless asked for, because it costs a frame per socket per
    // interval — but a long-lived server almost always wants it: see ping().
    if (options.pingInterval > 0) this.startAutoPing(options.pingInterval);
  }

  get onconnection() { return this._onconnection; }
  set onconnection(fn) {
    if (this._onconnection) this.removeEventListener('connection', this._onconnection);
    this._onconnection = typeof fn === 'function' ? fn : null;
    if (this._onconnection) this.addEventListener('connection', this._onconnection);
  }

  /**
   * Accept (or refuse) one upgrade. Public so an application can route
   * upgrades itself and hand only some of them here.
   */
  /**
   * Accept (or refuse) one upgrade.
   *
   * `cb` is the ws-compatible form: `handleUpgrade(req, socket, head, ws => …)`
   * hands the socket to the callback and does NOT fire the connection event,
   * because that is what `ws` does — with noServer the callback is the whole
   * delivery, and code written against it emits 'connection' itself if it
   * wants to. Omit the callback and the connection event fires as usual.
   */
  handleUpgrade(req, socket, head, cb) {
    if (this.options.path !== undefined) {
      var path = String(req.url || '').split('?')[0];
      if (path !== this.options.path) {
        // Not ours. Another WebSocketServer on the same server may want it, so
        // do not refuse on its behalf — but do not simply walk away either:
        // the socket has been handed over by the HTTP layer and nothing else
        // owns it, so an unclaimed upgrade hangs until the client times out.
        //
        // Refusing after a turn of the event loop gives any other handler
        // registered on the same 'upgrade' event a chance to claim it first;
        // if none did, the client gets a 404 and knows immediately.
        var isH2Stream = typeof socket._h2Reject === 'function';
        queueMicrotask(function () {
          if (socket.destroyed || socket._quicoWsClaimed) return;
          // Transport-aware, for the same reason every other refusal is: over
          // HTTP/2 there is no socket to write a status line onto, and writing
          // one would put HTTP/1.1 bytes into a DATA frame. The h2 path
          // answers on the stream instead.
          rejectUpgrade(socket, isH2Stream, 404, 'No WebSocket endpoint at ' + path);
        });
        return false;
      }
      socket._quicoWsClaimed = true;
    }

    var ws = upgradeWebSocket(req, socket, head, this.options);
    if (!ws) return false;

    var self = this;
    this.clients.add(ws);
    ws.addEventListener('close', function () { self.clients.delete(ws); });

    if (typeof cb === 'function') { cb(ws, req); return true; }

    // dispatchEvent carries one argument and a connection handler needs two —
    // the socket and the request that produced it — so the handler is called
    // directly, and the Event is dispatched as well (carrying both on itself)
    // so addEventListener still sees the connection.
    if (this._onconnection) this._onconnection(ws, req);

    var ev = new Event('connection');
    try {
      Object.defineProperty(ev, 'webSocket', { value: ws, enumerable: true });
      Object.defineProperty(ev, 'request', { value: req, enumerable: true });
    } catch (e) {}
    var handler = this._onconnection;
    if (handler) this.removeEventListener('connection', handler);
    this.dispatchEvent(ev);
    if (handler) this.addEventListener('connection', handler);

    // ws-style listeners get (ws, req), the signature every ws example uses.
    this._emitNode('connection', [ws, req]);

    return true;
  }

  /**
   * Ping every client on an interval and drop the ones that stop answering.
   *
   * The reason a server needs this and a browser does not: a peer that
   * disappears without a FIN — a closed laptop, a NAT that forgot the mapping
   * — leaves a socket that reads as healthy indefinitely. Nothing else
   * notices.
   */
  startAutoPing(intervalMs) {
    var self = this;
    this.stopAutoPing();
    this._pingTimer = setInterval(function () {
      for (var ws of self.clients) {
        if (ws.readyState !== OPEN) continue;
        if (ws._awaitingPong && !ws._pongSeen) {
          // Missed the previous round: the peer is gone.
          ws._fail(new Error('no pong received'));
          continue;
        }
        ws._awaitingPong = true;
        ws.ping();
      }
    }, intervalMs);
    if (this._pingTimer.unref) this._pingTimer.unref();
  }

  stopAutoPing() {
    if (this._pingTimer) { clearInterval(this._pingTimer); this._pingTimer = null; }
  }

  /**
   * Close every client, then stop.
   *
   * 1001 "going away" is exactly the right code for a server shutting down —
   * and the WHATWG close() refuses it, because the browser reserves 1001 for
   * the browser itself (a tab being closed) and only lets a page pass 1000 or
   * 3000-4999. The server is not a page, and RFC 6455 §7.4.1 defines 1001 for
   * precisely this situation, so it goes out through the internal path rather
   * than through the browser-facing method.
   *
   * The first version called ws.close(1001) inside a try/catch and swallowed
   * the DOMException it raised on every client: close() did nothing at all,
   * silently, and the sockets stayed open.
   */
  close(code, reason) {
    this.stopAutoPing();
    var reasonBuf = reason ? Buffer.from(String(reason), 'utf8') : Buffer.alloc(0);
    if (reasonBuf.length > 123) reasonBuf = reasonBuf.subarray(0, 123);
    var finalCode = code === undefined ? 1001 : code;

    for (var ws of this.clients) {
      if (ws.readyState !== OPEN) continue;
      ws._readyState = CLOSING;
      ws._closeCode = finalCode;
      ws._closeReason = reasonBuf.toString('utf8');
      ws._sendCloseFrame(finalCode, reasonBuf);

      // The peer should echo the close frame; if it does not, do not hold the
      // socket open forever on a server that is shutting down.
      (function (sock) {
        var t = setTimeout(function () { sock._teardown(false); }, 5000);
        if (t.unref) t.unref();
        sock._closeTimer = t;
      })(ws);
    }
  }
}


export { WebSocketServer, ServerWebSocket, upgradeWebSocket, abortHandshake };
