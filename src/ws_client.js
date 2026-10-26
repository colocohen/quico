/*
 * quico: HTTP/3 and QUIC implementation for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://github.com/colocohen/quico
 */

import net from 'node:net';
import { Blob } from 'node:buffer';

import { request as h1Request } from './h1_client.js';
import lemonTls from 'lemon-tls';
import { globalAgent } from './agent.js';
import {
  WSParser, encodeFrame, generateKey, acceptKey,
  OPCODE, CLOSE,
  installEventSurfaces, emitBoth, nodeMessagePayload,
  userCloseCode, closeReasonBytes, subprotocolList, sendInOrder, queueCloseFrame, isBadPort
} from './ws.js';


// ============================================================
//  WebSocket — the WHATWG interface, unchanged.
//
//    https://websockets.spec.whatwg.org/#the-websocket-interface
//
//  Code written against a browser runs here as-is: same constructor, same
//  readyState constants, same events, same close semantics, same errors. That
//  is the whole design goal, and where Node lacks something the browser has
//  (Blob, CloseEvent) we supply it rather than inventing a different shape.
//
//  Two deliberate ADDITIONS, both invisible to browser code:
//    - a third constructor argument for options a browser cannot express
//      (custom headers, a CA for a private certificate). The browser ignores
//      extra arguments, so passing two stays portable.
//    - ping() and an onpong handler. A browser never needs these because it
//      answers pings itself and its connections are supervised; a long-lived
//      server-side client has no such supervision, and without a keepalive a
//      dead TCP connection looks healthy for many minutes.
// ============================================================


// Node has no CloseEvent (it has Event and MessageEvent). Define the missing
// piece rather than emitting a plain object: browser code reads
// `event.wasClean` and instanceof checks should behave.
var CloseEventCtor = typeof CloseEvent !== 'undefined' ? CloseEvent : (function () {
  function CloseEventPolyfill(type, init) {
    init = init || {};
    var ev = new Event(type, init);
    Object.defineProperties(ev, {
      code:      { value: init.code === undefined ? 0 : init.code, enumerable: true },
      reason:    { value: init.reason === undefined ? '' : init.reason, enumerable: true },
      wasClean:  { value: !!init.wasClean, enumerable: true }
    });
    return ev;
  }
  return CloseEventPolyfill;
})();


var CONNECTING = 0, OPEN = 1, CLOSING = 2, CLOSED = 3;

// The close handshake is two-sided: after sending our close frame we wait for
// the peer's before dropping TCP (RFC 6455 §7.1.4). A peer that never answers
// must not hold the socket open forever.
var CLOSE_TIMEOUT = 30000;


class WebSocket extends EventTarget {

  static get CONNECTING() { return CONNECTING; }
  static get OPEN()       { return OPEN; }
  static get CLOSING()    { return CLOSING; }
  static get CLOSED()     { return CLOSED; }

  constructor(url, protocols, options) {
    super();
    if (arguments.length === 0) throw new TypeError('Failed to construct \'WebSocket\': 1 argument required, but only 0 present.');
    // The second argument may be an options bag, { protocols } (WPT
    // websockets/constructor/option-bag; WebSocketStream takes the same).
    // The third is QUICO's: what a browser cannot express (headers, ca).
    if (protocols !== null && typeof protocols === 'object' && typeof protocols[Symbol.iterator] !== 'function') {
      protocols = protocols.protocols;
    }

    // ---- URL parsing, per the spec's constructor steps ----
    var parsed;
    try {
      parsed = new URL(String(url));
    } catch (e) {
      throw new DOMException('The URL \'' + url + '\' is invalid.', 'SyntaxError');
    }

    // http/https are accepted and upgraded, which the spec added so that a
    // relative or copied URL does not have to be rewritten by hand.
    if (parsed.protocol === 'http:')  parsed.protocol = 'ws:';
    if (parsed.protocol === 'https:') parsed.protocol = 'wss:';

    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
      throw new DOMException(
        'The URL\'s scheme must be either \'ws\' or \'wss\'. \'' +
        parsed.protocol.replace(':', '') + '\' is not allowed.', 'SyntaxError');
    }
    // A fragment, even an empty one ("…/#"), is a SyntaxError: parsed.hash
    // is "" for both "no fragment" and "#", so it is read from the URL itself.
    if (parsed.href.indexOf('#') >= 0) {
      throw new DOMException('The URL contains a fragment identifier (\'' +
        parsed.hash + '\'). Fragment identifiers are not allowed in WebSocket URLs.',
        'SyntaxError');
    }

    protocols = subprotocolList(protocols);

    options = options || {};

    // ---- Public state (spec attributes) ----
    this._url = parsed.href;
    this._origin = parsed.origin;    // a message event's origin (the URL's, not the URL)
    this._readyState = CONNECTING;
    this._bufferedAmount = 0;
    this._binaryType = 'blob';       // the browser's default
    this._protocol = '';
    this._extensions = '';

    // ---- Internals ----
    this._socket = null;
    this._parser = null;
    this._req = null;
    this._closeSent = false;
    this._closeReceived = false;
    this._closeCode = CLOSE.ABNORMAL;
    this._closeReason = '';
    this._closeTimer = null;
    this._options = options;
    this._protocols = protocols;
    this._pendingPongs = [];

    this._onopen = null;
    this._onmessage = null;
    this._onerror = null;
    this._onclose = null;
    this._onpong = null;

    // Adds .on/.once/.off alongside the WHATWG properties. Both surfaces fire
    // for every event, with the arguments each interface promises — see
    // ws.js (installEventSurfaces).
    installEventSurfaces(this);

    // The spec's "establish a WebSocket connection" runs in parallel — the
    // constructor returns before anything is on the wire, so a listener
    // attached on the next line still sees 'open'.
    var self = this;
    queueMicrotask(function () { self._connect(parsed); });
  }


  // ============================================================
  //  Spec attributes
  // ============================================================

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
  set binaryType(value) {
    // The spec permits exactly these two. 'nodebuffer' is accepted as well
    // because it costs nothing and is what server-side code usually wants —
    // but it is NOT the default, so browser code keeps browser behaviour.
    if (value !== 'blob' && value !== 'arraybuffer' && value !== 'nodebuffer') return;
    this._binaryType = value;
  }

  // on<event> properties. Assigning replaces the previous handler, which is
  // what the browser does; addEventListener stacks, and both work together.
  get onopen() { return this._onopen; }
  set onopen(fn) { this._setHandler('open', '_onopen', fn); }
  get onmessage() { return this._onmessage; }
  set onmessage(fn) { this._setHandler('message', '_onmessage', fn); }
  get onerror() { return this._onerror; }
  set onerror(fn) { this._setHandler('error', '_onerror', fn); }
  get onclose() { return this._onclose; }
  set onclose(fn) { this._setHandler('close', '_onclose', fn); }
  /** Not in the browser — see the note at the top of the file. */
  get onpong() { return this._onpong; }
  set onpong(fn) { this._setHandler('pong', '_onpong', fn); }

  _setHandler(type, slot, fn) {
    if (this[slot]) this.removeEventListener(type, this[slot]);
    this[slot] = typeof fn === 'function' ? fn : null;
    if (this[slot]) this.addEventListener(type, this[slot]);
  }


  // ============================================================
  //  send()
  // ============================================================

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
      // The one place the spec throws rather than ignoring: sending before
      // 'open' is a programming error, not a race the runtime can absorb.
      throw new DOMException('Still in CONNECTING state.', 'InvalidStateError');
    }
    var forced = options && typeof options.binary === 'boolean' ? options.binary : null;
    var opcode, payload;
    if (typeof data === 'string') { opcode = forced === true ? OPCODE.BINARY : OPCODE.TEXT; payload = Buffer.from(data, 'utf8'); }
    else if (data instanceof Blob) { opcode = forced === false ? OPCODE.TEXT : OPCODE.BINARY; payload = data; }
    else if (ArrayBuffer.isView(data)) { opcode = forced === false ? OPCODE.TEXT : OPCODE.BINARY; payload = Buffer.from(data.buffer, data.byteOffset, data.byteLength); }
    else if (data instanceof ArrayBuffer) { opcode = forced === false ? OPCODE.TEXT : OPCODE.BINARY; payload = Buffer.from(data); }
    else { opcode = OPCODE.TEXT; payload = Buffer.from(String(data), 'utf8'); }   // stringified, as the browser does

    if (this._readyState !== OPEN) {
      // After close() the message is dropped, but bufferedAmount grows by it
      // all the same — the spec's way of telling a sender that nothing goes.
      this._bufferedAmount += payload instanceof Blob ? payload.size : payload.length;
      return;
    }
    // In the order sent, a Blob included (ws.js sendInOrder).
    sendInOrder(this, opcode, payload);
  }

  /** Not in the browser: keepalive for a long-lived server-side connection. */
  ping(data) {
    if (this._readyState !== OPEN) return;
    this._sendFrame(OPCODE.PING, data == null ? Buffer.alloc(0)
                  : Buffer.isBuffer(data) ? data : Buffer.from(data));
  }

  // cb(err): once the frame is handed to the socket (WebSocketStream's
  // write() resolves there: its backpressure), or err if it cannot be.
  _sendFrame(opcode, payload, cb) {
    if (!this._socket || this._socket.destroyed) { if (cb) cb(new Error('the WebSocket is closed')); return; }
    var frame;
    try {
      // mask: true — every client-to-server frame is masked (RFC 6455 §5.1).
      frame = encodeFrame(opcode, payload, { mask: true });
    } catch (e) {
      if (cb) cb(e);
      this._fail(e);
      return;
    }

    var self = this;
    if (opcode < 0x8) this._bufferedAmount += payload.length;
    this._socket.write(frame, function (err) {
      if (opcode < 0x8) self._bufferedAmount -= payload.length;
      if (cb) cb(err || null);
    });
  }


  // ============================================================
  //  close()
  // ============================================================

  close(code, reason) {
    // As WebIDL takes them: a code given (null too) is clamped and checked,
    // a reason is at most 123 bytes of UTF-8 (ws.js).
    if (code !== undefined) code = userCloseCode(code);
    var reasonBuf = reason !== undefined ? closeReasonBytes(reason) : Buffer.alloc(0);

    if (this._readyState === CLOSING || this._readyState === CLOSED) return;

    if (this._readyState === CONNECTING) {
      // The spec: "fail the WebSocket connection". Nothing was established,
      // so there is no closing handshake: the attempt is abandoned, and —
      // in a task of its own, after close() has returned — 'error', then
      // 'close' with 1006, not clean. They used to fire inside close(), so a
      // listener added on the next line missed them, and 'error' never came.
      this._readyState = CLOSING;
      this._closeCode = CLOSE.ABNORMAL;
      this._closeReason = '';
      if (this._req) { try { this._req.destroy(); } catch (e) {} }
      var failing = this;
      setImmediate(function () { failing._fail(new Error('WebSocket closed before the connection was established')); });
      return;
    }

    this._readyState = CLOSING;
    this._sendCloseFrame(code === undefined ? undefined : code, reasonBuf);

    // The peer should answer with its own close frame; when it does,
    // _teardown runs with wasClean = true. This timer is the backstop.
    var self = this;
    this._closeTimer = setTimeout(function () {
      self._teardown(false);
    }, CLOSE_TIMEOUT);
    if (this._closeTimer.unref) this._closeTimer.unref();
  }

  // `now`: answering the peer's close (what is still queued is dropped).
  // Otherwise behind the messages sent before close() — see ws_server.js.
  _sendCloseFrame(code, reasonBuf, now) {
    if (this._closeSent) return;
    this._closeSent = true;

    var payload;
    if (code === undefined) {
      payload = Buffer.alloc(0);
    } else {
      payload = Buffer.alloc(2 + (reasonBuf ? reasonBuf.length : 0));
      payload.writeUInt16BE(code, 0);
      if (reasonBuf && reasonBuf.length) reasonBuf.copy(payload, 2);
    }
    if (queueCloseFrame(this, payload, now)) return;

    if (this._socket && !this._socket.destroyed) {
      try { this._socket.write(encodeFrame(OPCODE.CLOSE, payload, { mask: true })); } catch (e) {}
    }
  }


  // ============================================================
  //  Connection
  // ============================================================

  _connect(parsed) {
    if (this._readyState !== CONNECTING) return;   // closed before we started

    var self = this;
    var secure = parsed.protocol === 'wss:';
    var port = parsed.port ? parseInt(parsed.port, 10) : (secure ? 443 : 80);
    // A port the browser will not connect to (ws.js isBadPort): the
    // connection fails — 'error', then 'close' — without being attempted.
    if (isBadPort(port)) { this._fail(new Error('WebSocket connection to port ' + port + ' is not allowed (a blocked port)')); return; }
    var key = generateKey();

    var headers = {
      'Upgrade': 'websocket',
      'Connection': 'Upgrade',
      'Sec-WebSocket-Key': key,
      'Sec-WebSocket-Version': '13'
    };
    if (this._protocols.length) {
      headers['Sec-WebSocket-Protocol'] = this._protocols.join(', ');
    }
    // The browser sends Origin automatically; here it is the caller's choice,
    // because a server-side client has no origin to speak of.
    if (this._options.origin) headers['Origin'] = this._options.origin;
    // A user name and password in the URL (wss://user:pass@host/) go as
    // HTTP Basic authentication, as the browser sends them; they were
    // dropped. An Authorization the caller set wins.
    if (parsed.username || parsed.password) {
      headers['Authorization'] = 'Basic ' + Buffer.from(decodeURIComponent(parsed.username) + ':' +
                                                       decodeURIComponent(parsed.password), 'utf8').toString('base64');
    }
    if (this._options.headers) {
      for (var h in this._options.headers) {
        if (h.toLowerCase() === 'authorization') delete headers['Authorization'];
        headers[h] = this._options.headers[h];
      }
    }

    // TLS session resumption, as quico.request has it: a session from the
    // agent's cache (options.agent, or the global one) — each used once — and
    // each the server sends kept there, and emitted as 'session'. An
    // explicit options.session wins. wss:// began with a full handshake
    // every time.
    var sAgent = secure ? (this._options.agent && this._options.agent._sessionKey ? this._options.agent : globalAgent) : null;
    var sKey = sAgent && this._options.agent !== false ? sAgent._sessionKey('tcp:http/1.1', parsed.hostname, port, this._options) : null;
    var explicitSession = this._options.session, sessionTaken = false, sessionNow;
    var reqOptions = {
      hostname: parsed.hostname,
      port: port,
      path: (parsed.pathname || '/') + (parsed.search || ''),
      method: 'GET',
      headers: headers,
      // wss:// means TLS whether or not the caller passed a TLS module. It
      // took options.tls alone, and without one h1_client connected over
      // plain TCP: to a real server the handshake hung (it waits for a
      // ClientHello), and to anyone answering in the clear the upgrade —
      // headers, cookies, tokens — went out unencrypted under a wss:// URL.
      tls: secure ? (this._options.tls || lemonTls) : null,
      ca: this._options.ca,
      rejectUnauthorized: this._options.rejectUnauthorized,
      // The key-exchange groups to offer (tls.connect's ecdhCurve).
      ecdhCurve: this._options.ecdhCurve,
      sigalgs: this._options.sigalgs,
      // A WebSocket handshake must not come off a reused keep-alive socket:
      // the socket is about to leave HTTP entirely, and the pool would hand it
      // to another request.
      pool: freshPool()
    };
    Object.defineProperty(reqOptions, 'session', { enumerable: true, get: function () {
      if (explicitSession) return explicitSession;
      if (!sessionTaken) { sessionTaken = true; sessionNow = sKey ? sAgent._takeSession(sKey) : undefined; }
      return sessionNow;
    } });
    var req = h1Request(reqOptions);
    this._req = req;
    req.on('session', function (s) {
      if (sKey) sAgent._cacheSession(sKey, s);
      self._emitNode('session', [s]);   // .on('session'), as on node:tls
    });

    req.on('upgrade', function (info, socket, head) {
      self._onHandshake(info, socket, head, key);
    });

    req.on('response', function (res) {
      // Any non-101 answer means the server declined the upgrade.
      self._fail(new Error('Unexpected server response: ' + res.statusCode));
    });

    req.on('error', function (err) { self._fail(err); });

    req.end();
  }

  _onHandshake(info, socket, head, key) {
    var h = info.headers;

    // §4.1 client validation. Each of these is a real check, not ceremony: a
    // wrong Sec-WebSocket-Accept means whatever answered is not a WebSocket
    // server, and continuing would feed frames to something that will
    // interpret them as something else.
    var expected = acceptKey(key);
    if (String(h['sec-websocket-accept'] || '') !== expected) {
      this._fail(new Error('Invalid Sec-WebSocket-Accept header'));
      try { socket.destroy(); } catch (e) {}
      return;
    }
    if (String(h['upgrade'] || '').toLowerCase() !== 'websocket') {
      this._fail(new Error('Invalid Upgrade header'));
      try { socket.destroy(); } catch (e) {}
      return;
    }

    // A server may only name a subprotocol we offered (§4.1).
    var chosen = h['sec-websocket-protocol'];
    if (chosen !== undefined) {
      chosen = String(chosen).trim();
      if (this._protocols.indexOf(chosen) === -1) {
        this._fail(new Error('Server sent a subprotocol that was not requested: ' + chosen));
        try { socket.destroy(); } catch (e) {}
        return;
      }
      this._protocol = chosen;
    }

    // We negotiate no extensions, so the server must claim none.
    if (h['sec-websocket-extensions']) {
      this._fail(new Error('Server sent an extension that was not requested'));
      try { socket.destroy(); } catch (e) {}
      return;
    }

    if (this._readyState !== CONNECTING) { try { socket.destroy(); } catch (e) {} return; }

    this._socket = socket;
    this._setupParser();

    socket.setNoDelay && socket.setNoDelay(true);

    this._readyState = OPEN;
    emitBoth(this, 'open', new Event('open'), []);

    // Frames that shared a TCP segment with the handshake response. Dropping
    // them loses whatever the server sent immediately after the 101 — a bug
    // that only appears when segments happen to coalesce.
    if (head && head.length) this._parser.execute(head);
  }

  _setupParser() {
    var self = this;
    // isServer: false — we are the client, so incoming frames must NOT be
    // masked and the parser enforces that direction.
    var parser = new WSParser({ isServer: false, maxPayload: this._options.maxPayload });
    this._parser = parser;

    parser.on('message', function (data, isBinary) {
      if (self._readyState !== OPEN) return;
      emitBoth(self, 'message',
        new MessageEvent('message', {
          data: isBinary ? self._toBinary(data) : data,
          origin: self._origin
        }),
        // Raw payload for the ws surface: `ws` has no binaryType and always
        // hands its listeners a Buffer.
        [nodeMessagePayload(data, isBinary), isBinary]);
    });

    parser.on('ping', function (payload) {
      // Answered automatically, as a browser does. `ws` surfaces pings to its
      // listeners, so the ws-side event fires; WHATWG has no 'ping' event.
      if (self._readyState === OPEN) self._sendFrame(OPCODE.PONG, payload);
      self._emitNode('ping', [payload]);
    });

    parser.on('pong', function (payload) {
      emitBoth(self, 'pong', new MessageEvent('pong', { data: payload }), [payload]);
    });

    parser.on('close', function (code, reason) {
      self._closeReceived = true;
      self._closeCode = code;
      // Only take the peer's reason when we did not supply one. When WE
      // started the handshake the reason belongs to us, and a peer that echoes
      // an empty reason must not erase what the application asked to report.
      if (!self._closeSent || !self._closeReason) self._closeReason = reason;

      if (!self._closeSent) {
        // The peer started the handshake; echo its code AND reason back and
        // finish (§7.1.4). `ws` echoes the reason too, and matching it matters:
        // the peer reports what comes back in its own close event.
        self._readyState = CLOSING;
        self._sendCloseFrame(code === CLOSE.NO_STATUS ? undefined : code,
                             Buffer.from(reason || '', 'utf8'), true);
      }
      self._teardown(true);
    });

    parser.on('error', function (err) {
      // A protocol violation: tell the peer why, then fail the connection.
      self._sendCloseFrame(err.closeCode || CLOSE.PROTOCOL_ERROR, Buffer.alloc(0));
      self._closeCode = err.closeCode || CLOSE.PROTOCOL_ERROR;
      self._fail(err);
    });

    this._socket.on('data', function (chunk) { parser.execute(chunk); });

    this._socket.on('error', function (err) { self._fail(err); });

    this._socket.on('close', function () {
      // TCP closed. If no close frame was exchanged this is abnormal (1006) —
      // the code the spec reserves for "the connection dropped".
      self._teardown(self._closeSent && self._closeReceived);
    });

    this._socket.on('end', function () { self._teardown(self._closeSent && self._closeReceived); });
  }

  _toBinary(buf) {
    if (this._binaryType === 'nodebuffer') return buf;
    if (this._binaryType === 'arraybuffer') {
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }
    return new Blob([buf]);   // 'blob', the spec default
  }

  _fail(err) {
    if (this._readyState === CLOSED) return;

    // The browser's error event carries no detail, deliberately, to avoid
    // leaking cross-origin information. That reason does not apply on a
    // server, and a developer debugging a handshake needs to know what broke —
    // so `error` is attached as an extra property. Browser code reading
    // nothing from the event is unaffected.
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
      // ws passes the reason as a Buffer.
      [code, Buffer.from(reason, 'utf8')]);
  }
}


// A WebSocket handshake takes the socket away from HTTP for good, so it must
// never come from — or return to — the keep-alive pool.
function freshPool() {
  return {
    take: function () { return null; },
    put: function (h, p, socket) { try { socket.destroy(); } catch (e) {} },
    canOpen: function () { return true; },
    acquire: function () {},
    release: function () {},
    destroy: function () {}
  };
}


export { WebSocket };
export default WebSocket;