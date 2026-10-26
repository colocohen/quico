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

import crypto from 'node:crypto';
import { Emitter } from './http_common.js';


// ============================================================
//  WebSocket framing (RFC 6455 §5).
//
//  No I/O, same as h1.js: feed bytes to execute(), get events. The socket, the
//  handshake and the browser-facing API all live above this.
//
//  Everything here refuses rather than repairs. A WebSocket frame is simple
//  enough that any deviation is a bug or an attack, and RFC 6455 §7.4.1 gives
//  a close code for each case — so a violation is answered with the right code
//  and the connection ends, never with a guess about what the peer meant.
// ============================================================

var OPCODE = {
  CONTINUATION: 0x0,
  TEXT:         0x1,
  BINARY:       0x2,
  CLOSE:        0x8,
  PING:         0x9,
  PONG:         0xa
};

// RFC 6455 §7.4.1 plus the WHATWG additions.
var CLOSE = {
  NORMAL:            1000,
  GOING_AWAY:        1001,
  PROTOCOL_ERROR:    1002,
  UNSUPPORTED_DATA:  1003,
  NO_STATUS:         1005,   // never sent on the wire
  ABNORMAL:          1006,   // never sent on the wire
  INVALID_PAYLOAD:   1007,
  POLICY_VIOLATION:  1008,
  MESSAGE_TOO_BIG:   1009,
  MISSING_EXTENSION: 1010,
  INTERNAL_ERROR:    1011,
  TLS_HANDSHAKE:     1015    // never sent on the wire
};

// RFC 6455 §1.3. Fixed by the spec; the only reason it exists is to make a
// WebSocket handshake impossible to produce by tricking a naive HTTP server
// into echoing a header.
// Fixed by RFC 6455 §1.3, and worth checking against the RFC's own worked
// example rather than trusting the transcription: with one character out of
// place every handshake fails with "Invalid Sec-WebSocket-Accept", which reads
// like a broken server rather than a typo here. ws.test.mjs asserts that
// acceptKey('dGhlIHNhbXBsZSBub25jZQ==') is 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='.
var WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

var MAX_CONTROL_PAYLOAD = 125;
var DEFAULT_MAX_PAYLOAD = 100 * 1024 * 1024;

var EMPTY = Buffer.alloc(0);


// ============================================================
//  Handshake helpers
// ============================================================

/** 16 random bytes, base64. RFC 6455 §4.1 requires them to be unpredictable. */
function generateKey() {
  return crypto.randomBytes(16).toString('base64');
}

/** base64(sha1(key + GUID)) — the value the server must echo (§4.2.2). */
function acceptKey(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

/**
 * Is a close code allowed to appear on the wire (§7.4)?
 *
 * 1005/1006/1015 are statuses the local endpoint reports to its own
 * application when there was no code, the connection dropped, or TLS failed.
 * A peer sending one is claiming a local condition it cannot know about.
 */
function isValidCloseCode(code) {
  if (code >= 3000 && code <= 4999) return true;    // application / registered
  if (code < 1000 || code > 1015) return false;
  if (code === 1004 || code === 1005 || code === 1006 || code === 1015) return false;
  return true;
}

/** Codes an application may pass to close() (WHATWG: 1000 or 3000-4999). */
function isValidUserCloseCode(code) {
  return code === 1000 || (code >= 3000 && code <= 4999);
}


// ============================================================
//  Masking (RFC 6455 §5.3)
//
//  Every client-to-server frame is XORed with a fresh 32-bit key. It is not
//  confidentiality — the key travels in the clear — it exists so an attacker
//  who controls a page cannot make a browser emit chosen bytes on the wire and
//  poison an intermediary's cache. That only holds if the key is
//  unpredictable, which is why it comes from crypto.randomBytes and not
//  Math.random.
// ============================================================

function applyMask(payload, mask, offset) {
  offset = offset || 0;
  for (var i = 0; i < payload.length; i++) {
    payload[i] ^= mask[(offset + i) & 3];
  }
  return payload;
}


// ============================================================
//  Frame encoding
// ============================================================

/**
 * Build one frame.
 *
 * `mask` must be true for every frame a CLIENT sends (§5.1) and false for
 * every frame a server sends. A server that masks, or a client that does not,
 * is closed by the peer with 1002.
 */
function encodeFrame(opcode, payload, options) {
  options = options || {};
  var fin = options.fin !== false;
  var mask = !!options.mask;

  if (payload == null) payload = EMPTY;
  else if (typeof payload === 'string') payload = Buffer.from(payload, 'utf8');
  else if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);

  if (opcode >= 0x8 && payload.length > MAX_CONTROL_PAYLOAD) {
    throw new Error('control frame payload exceeds ' + MAX_CONTROL_PAYLOAD + ' bytes');
  }

  var len = payload.length;
  var header;

  if (len < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.allocUnsafe(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 127;
    // 64-bit length. The high word is always zero here: a frame longer than
    // 4 GiB is not something this library will build.
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(len, 6);
  }

  header[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);

  if (!mask) {
    return Buffer.concat([header, payload], header.length + len);
  }

  header[1] |= 0x80;
  var maskKey = crypto.randomBytes(4);
  // Copy before masking: the caller's buffer must not be mutated. A user who
  // sends the same Buffer twice would otherwise send garbage the second time,
  // and the bug would look like corruption on the network.
  var masked = Buffer.from(payload);
  applyMask(masked, maskKey);
  return Buffer.concat([header, maskKey, masked], header.length + 4 + len);
}


// ============================================================
//  WSParser
//
//  Events:
//    'message' (data, isBinary)  — a complete message, fragments reassembled
//    'ping'    (payload)
//    'pong'    (payload)
//    'close'   (code, reason)    — peer's close frame
//    'error'   (err)             — err.closeCode is the code to answer with
// ============================================================

function WSParser(options) {
  if (!(this instanceof WSParser)) return new WSParser(options);
  options = options || {};

  var isServer = !!options.isServer;
  var maxPayload = options.maxPayload || DEFAULT_MAX_PAYLOAD;

  var ev = Emitter();
  var on = ev.on, emit = ev.emit;

  var buf = EMPTY;
  var dead = false;

  // A frame whose payload is still arriving. Its length is known from its
  // header, so the bytes it still needs are known too: later chunks wait in
  // `waiting` and are joined once, when there are enough of them. Joining on
  // every chunk instead re-copied the whole partial frame each time — O(n^2):
  // a 5MB message over WebSocket-over-HTTP/3, where each chunk is one QUIC
  // packet (~1.2KB), took over two seconds of CPU to parse.
  var need = 0;            // bytes `buf` must hold before parsing resumes; 0 = not waiting
  var waiting = [];
  var waitingLen = 0;

  // Fragmented message in progress.
  var fragments = [];
  var fragmentsLen = 0;
  var fragmentOpcode = 0;
  var textDecoder = null;
  var textSoFar = '';

  function fatal(message, closeCode) {
    if (dead) return;
    dead = true;
    var err = new Error(message);
    err.closeCode = closeCode || CLOSE.PROTOCOL_ERROR;
    emit('error', err);
  }

  /**
   * Feed bytes. Never throws; violations arrive as 'error' with a closeCode.
   */
  function execute(chunk) {
    if (dead) return;
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);

    if (need > 0 && buf.length + waitingLen + chunk.length < need) {
      waiting.push(chunk);
      waitingLen += chunk.length;
      return;
    }
    if (waitingLen > 0) {
      waiting.unshift(buf);
      waiting.push(chunk);
      buf = Buffer.concat(waiting, buf.length + waitingLen + chunk.length);
      waiting = [];
      waitingLen = 0;
    } else {
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    }
    need = 0;

    while (!dead) {
      if (buf.length < 2) return;

      var b0 = buf[0], b1 = buf[1];
      var fin = (b0 & 0x80) !== 0;
      var rsv = b0 & 0x70;
      var opcode = b0 & 0x0f;
      var masked = (b1 & 0x80) !== 0;
      var len = b1 & 0x7f;
      var offset = 2;

      // RSV bits are reserved for extensions. We negotiate none, so a peer
      // setting one is either using an extension we never agreed to or is
      // corrupt (§5.2).
      if (rsv !== 0) { fatal('reserved bits set without a negotiated extension', CLOSE.PROTOCOL_ERROR); return; }

      // Masking direction is fixed and asymmetric (§5.1): client frames are
      // always masked, server frames never are. Accepting the wrong direction
      // removes the cache-poisoning protection the mask exists for.
      if (isServer && !masked) { fatal('client frame is not masked', CLOSE.PROTOCOL_ERROR); return; }
      if (!isServer && masked) { fatal('server frame must not be masked', CLOSE.PROTOCOL_ERROR); return; }

      if (len === 126) {
        if (buf.length < offset + 2) return;
        len = buf.readUInt16BE(offset);
        offset += 2;
      } else if (len === 127) {
        if (buf.length < offset + 8) return;
        var hi = buf.readUInt32BE(offset);
        var lo = buf.readUInt32BE(offset + 4);
        // Beyond 2^53 a length cannot be represented exactly, and nothing
        // legitimate is that large. Refuse rather than silently truncate.
        if (hi > 0x1fffff) { fatal('frame length exceeds Number.MAX_SAFE_INTEGER', CLOSE.MESSAGE_TOO_BIG); return; }
        len = hi * 4294967296 + lo;
        offset += 8;
      }

      if (opcode >= 0x8) {
        // Control frames: never fragmented, never longer than 125 bytes
        // (§5.5). They may be interleaved between the fragments of a data
        // message, which is why they are handled before the fragment state.
        if (!fin) { fatal('control frame must not be fragmented', CLOSE.PROTOCOL_ERROR); return; }
        if (len > MAX_CONTROL_PAYLOAD) { fatal('control frame payload too long', CLOSE.PROTOCOL_ERROR); return; }
      }

      if (len > maxPayload) { fatal('message exceeds maxPayload', CLOSE.MESSAGE_TOO_BIG); return; }

      var maskKey = null;
      if (masked) {
        if (buf.length < offset + 4) return;
        maskKey = buf.subarray(offset, offset + 4);
        offset += 4;
      }

      if (buf.length < offset + len) { need = offset + len; return; }   // payload incomplete

      var payload = Buffer.from(buf.subarray(offset, offset + len));
      buf = buf.subarray(offset + len);
      if (maskKey) applyMask(payload, maskKey);

      if (!handleFrame(fin, opcode, payload)) return;
    }
  }

  function handleFrame(fin, opcode, payload) {
    switch (opcode) {

      case OPCODE.PING:
        emit('ping', payload);
        return true;

      case OPCODE.PONG:
        emit('pong', payload);
        return true;

      case OPCODE.CLOSE: {
        if (payload.length === 1) {
          // A close code is two bytes or nothing at all (§5.5.1).
          fatal('close frame with a 1-byte payload', CLOSE.PROTOCOL_ERROR);
          return false;
        }
        var code = CLOSE.NO_STATUS;
        var reason = '';
        if (payload.length >= 2) {
          code = payload.readUInt16BE(0);
          if (!isValidCloseCode(code)) {
            fatal('invalid close code ' + code, CLOSE.PROTOCOL_ERROR);
            return false;
          }
          try {
            reason = new TextDecoder('utf-8', { fatal: true }).decode(payload.subarray(2));
          } catch (e) {
            fatal('close reason is not valid UTF-8', CLOSE.INVALID_PAYLOAD);
            return false;
          }
        }
        dead = true;
        emit('close', code, reason);
        return false;
      }

      case OPCODE.TEXT:
      case OPCODE.BINARY: {
        if (fragments.length > 0) {
          // A new data frame while a fragmented message is open. §5.4 allows
          // only continuation frames there.
          fatal('data frame received while a fragmented message is open', CLOSE.PROTOCOL_ERROR);
          return false;
        }
        if (fin) return deliver(opcode, payload, true);

        fragmentOpcode = opcode;
        fragments = [payload];
        fragmentsLen = payload.length;
        if (opcode === OPCODE.TEXT) {
          // Validate UTF-8 as fragments arrive rather than at the end: a peer
          // streaming a huge invalid message should be cut off at the first
          // bad byte, not after we have buffered all of it.
          textDecoder = new TextDecoder('utf-8', { fatal: true });
          textSoFar = '';
          if (!feedText(payload)) return false;
        }
        return true;
      }

      case OPCODE.CONTINUATION: {
        if (fragments.length === 0) {
          fatal('continuation frame with no message to continue', CLOSE.PROTOCOL_ERROR);
          return false;
        }
        fragmentsLen += payload.length;
        if (fragmentsLen > maxPayload) {
          fatal('fragmented message exceeds maxPayload', CLOSE.MESSAGE_TOO_BIG);
          return false;
        }
        fragments.push(payload);
        if (fragmentOpcode === OPCODE.TEXT && !feedText(payload)) return false;

        if (!fin) return true;

        var whole = Buffer.concat(fragments, fragmentsLen);
        var op = fragmentOpcode;
        resetFragments();
        return deliver(op, whole, false);
      }

      default:
        fatal('unknown opcode 0x' + opcode.toString(16), CLOSE.PROTOCOL_ERROR);
        return false;
    }
  }

  function feedText(chunk) {
    try {
      textSoFar += textDecoder.decode(chunk, { stream: true });
      return true;
    } catch (e) {
      // §8.1: a text message that is not valid UTF-8 is 1007, not a protocol
      // error — the framing was fine, the content was not.
      fatal('text message is not valid UTF-8', CLOSE.INVALID_PAYLOAD);
      return false;
    }
  }

  function deliver(opcode, payload, single) {
    if (opcode === OPCODE.BINARY) {
      emit('message', payload, true);
      return true;
    }

    var text;
    if (single) {
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(payload);
      } catch (e) {
        fatal('text message is not valid UTF-8', CLOSE.INVALID_PAYLOAD);
        return false;
      }
    } else {
      try {
        // Flush: catches a message that ends mid-sequence, which the streaming
        // decode above cannot know about until it is told there is no more.
        text = textSoFar + textDecoder.decode();
      } catch (e) {
        fatal('text message ends mid UTF-8 sequence', CLOSE.INVALID_PAYLOAD);
        return false;
      }
      textDecoder = null;
      textSoFar = '';
    }
    emit('message', text, false);
    return true;
  }

  function resetFragments() {
    fragments = [];
    fragmentsLen = 0;
    fragmentOpcode = 0;
  }

  this.on = on;
  this.execute = execute;
  Object.defineProperty(this, 'dead', { get: function () { return dead; } });

  return this;
}


// ============================================================
//  Two event surfaces on one WebSocket.
//
//  A WebSocket here answers to both of the interfaces people actually write
//  against, and each one behaves the way its own users expect:
//
//    WHATWG  — onmessage / onclose / addEventListener. Handlers receive an
//              Event: MessageEvent with .data, CloseEvent with .code and
//              .wasClean. This is what browser code is written against, and
//              such code runs here unchanged.
//
//    ws      — .on('message') / .on('close') / .once / .off. Handlers receive
//              the data directly: (data, isBinary), (code, reason), (err).
//              This is what Node code is written against, and such code also
//              runs here unchanged.
//
//  BOTH FIRE FOR THE SAME EVENT, WITH DIFFERENT ARGUMENTS. That is the
//  deliberate part and the one thing to know before reading anything else:
//
//      ws.onmessage = e => e.data;                    // MessageEvent
//      ws.on('message', (data, isBinary) => data);    // Buffer or string
//
//  The alternative was to make .on() an alias for addEventListener, so that
//  everything received an Event. That is more consistent with itself and worse
//  in practice: every `ws` example on the internet would then be subtly wrong
//  here — `data.length` on a MessageEvent is undefined, not an error — and a
//  method that looks familiar while meaning something else is a worse trap
//  than one that does not exist.
//
//  Two places where the interfaces disagree and both are kept as they are:
//
//    binaryType governs the WHATWG surface only. `ws` has no such concept and
//    always hands over a Buffer, so .on('message') always gets a Buffer even
//    when onmessage is producing Blobs.
//
//    close reason is a string in CloseEvent and a Buffer in ws's
//    .on('close', (code, reason)).
// ============================================================


/**
 * Install the `ws`-style surface on an object that already extends
 * EventTarget, and give it the emit helpers both surfaces go through.
 *
 * The class keeps its own `_onmessage` etc. slots for the WHATWG `on<event>`
 * properties; this only adds the second surface and the dispatch that feeds
 * both, so ws_client and ws_server do not each grow a copy.
 */
function installEventSurfaces(target) {
  // ws-style listeners, kept apart from EventTarget's own registry: they
  // receive different arguments, so they cannot share a list.
  var nodeListeners = Object.create(null);

  function add(type, fn, once) {
    if (typeof fn !== 'function') return target;
    (nodeListeners[type] = nodeListeners[type] || []).push({ fn: fn, once: !!once });
    return target;
  }

  target.on = function (type, fn) { return add(type, fn, false); };
  target.once = function (type, fn) { return add(type, fn, true); };
  target.addListener = target.on;

  target.off = function (type, fn) {
    var a = nodeListeners[type];
    if (!a) return target;
    for (var i = 0; i < a.length; i++) {
      if (a[i].fn === fn) { a.splice(i, 1); break; }
    }
    return target;
  };
  target.removeListener = target.off;

  target.removeAllListeners = function (type) {
    if (type === undefined) nodeListeners = Object.create(null);
    else delete nodeListeners[type];
    return target;
  };

  target.listenerCount = function (type) {
    return (nodeListeners[type] || []).length;
  };

  target.eventNames = function () { return Object.keys(nodeListeners); };

  /** Call the ws-style listeners for `type` with the given arguments. */
  target._emitNode = function (type, args) {
    var a = nodeListeners[type];
    if (!a || a.length === 0) return false;
    // Copied before iterating: a listener may remove itself (once) or another,
    // and mutating the array mid-loop silently skips one.
    var list = a.slice();
    for (var i = 0; i < list.length; i++) {
      if (list[i].once) target.off(type, list[i].fn);
      list[i].fn.apply(target, args);
    }
    return true;
  };

  return target;
}


/**
 * Fire one event on both surfaces.
 *
 * `event` is dispatched to the WHATWG side; `nodeArgs` is spread into the
 * ws-style listeners. Every emission in ws_client and ws_server goes through
 * here, so the two surfaces cannot drift apart — a new event added to one is
 * added to both or to neither.
 */
function emitBoth(target, type, event, nodeArgs) {
  if (event) target.dispatchEvent(event);
  target._emitNode(type, nodeArgs || []);
}


/**
 * The payload `ws` hands to .on('message'), regardless of binaryType.
 *
 * ALWAYS a Buffer, text included. That is not an oversight in `ws`: since v8 it
 * emits a Buffer for every message and passes `isBinary` alongside, leaving the
 * decision to decode to the consumer — which is why `ws` handlers are full of
 * `data.toString()`. Handing a string to a text message here would look more
 * convenient and would break exactly those handlers, silently, because
 * `.toString()` on a string is a no-op but `.length` and `.subarray()` are not.
 *
 * The differential test in ws_compat.test.mjs is what caught this: the same
 * handler recorded `Buffer(text)` against `ws` and `string(text)` against us.
 *
 * binaryType is deliberately not consulted. `ws` has no such concept, so a
 * Blob must never reach this surface even when the WHATWG side is producing
 * them.
 */
function nodeMessagePayload(data, isBinary) {
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return data;
}


// ============================================================
//  What the browser's WebSocket and WebSocketStream share
// ============================================================

// close(code)'s code, as WebIDL's [Clamp] unsigned short takes it — a number
// (NaN, a string, null: 0), clamped to 0..65535, rounded half to even — then
// 1000 or 3000..4999, or an InvalidAccessError. null was passed over as if
// no code had been given; the browser throws.
function userCloseCode(code) {
  var n = Number(code);
  if (isNaN(n)) n = 0;
  n = Math.min(Math.max(n, 0), 65535);
  var f = Math.floor(n), d = n - f;
  n = d > 0.5 || (d === 0.5 && f % 2 === 1) ? f + 1 : f;
  if (!isValidUserCloseCode(n)) {
    throw new DOMException('The close code must be 1000 or between 3000 and 4999.', 'InvalidAccessError');
  }
  return n;
}

// A close reason, as the browser checks it: at most 123 bytes of UTF-8 (a
// close frame's 125, less the code), or a SyntaxError. Lone surrogates become
// U+FFFD, as USVString has them.
function closeReasonBytes(reason) {
  var buf = Buffer.from(String(reason), 'utf8');
  if (buf.length > 123) {
    throw new DOMException('The close reason must not be greater than 123 UTF-8 bytes.', 'SyntaxError');
  }
  return buf;
}

// The subprotocols a client offers, as the browser checks them: a string or
// a list of them (WebSocketStream: a list only — a string is a TypeError);
// each an HTTP token, none twice — compared without regard to case, as the
// header's values are — or a SyntaxError.
function subprotocolList(protocols, listOnly) {
  if (protocols === undefined || protocols === null && listOnly) return [];
  if (typeof protocols === 'string') {
    if (listOnly) throw new TypeError('protocols must be a sequence of strings');
    protocols = [protocols];
  } else if (protocols === null || typeof protocols !== 'object' || typeof protocols[Symbol.iterator] !== 'function') {
    if (listOnly) throw new TypeError('protocols must be a sequence of strings');
    protocols = [String(protocols)];   // WebIDL: (DOMString or sequence<DOMString>)
  } else {
    protocols = Array.from(protocols, String);
  }
  var seen = Object.create(null);
  for (var i = 0; i < protocols.length; i++) {
    var p = protocols[i];
    if (p.length === 0 || /[^\x21\x23-\x27\x2a\x2b\x2d\x2e0-9\x41-\x5a\x5e-\x7a\x7c\x7e]/.test(p)) {
      throw new DOMException('The subprotocol \'' + p + '\' is invalid.', 'SyntaxError');
    }
    var k = p.toLowerCase();
    if (seen[k]) throw new DOMException('The subprotocol \'' + p + '\' is duplicated.', 'SyntaxError');
    seen[k] = true;
  }
  return protocols;
}

// Messages leave in the order they were sent. A Blob has to be read first,
// asynchronously, and was sent whenever that finished: send(blob) and then
// send('x') put 'x' first. Each send now joins the socket's queue; one behind
// a Blob still being read waits for it. bufferedAmount counts a message from
// send() on, as the spec does, until it is handed to the socket.
//   ws._sendFrame(opcode, payload, cb) writes one frame.
function sendInOrder(ws, opcode, data, cb) {
  var q = ws._sendQueue || (ws._sendQueue = []);
  var item = { opcode: opcode, data: data, cb: cb || null, size: data instanceof Blob ? data.size : data.length };
  ws._bufferedAmount += item.size;
  q.push(item);
  if (q.length === 1) drainSendQueue(ws);
}
function drainSendQueue(ws) {
  var q = ws._sendQueue;
  while (q.length > 0) {
    var it = q[0];
    if (it.data instanceof Blob) {
      if (it.reading) return;
      it.reading = true;
      it.data.arrayBuffer().then(function (ab) { it.data = Buffer.from(ab); it.reading = false; drainSendQueue(ws); },
                                 function () { q.shift(); ws._bufferedAmount -= it.size; drainSendQueue(ws); });
      return;
    }
    q.shift();
    ws._bufferedAmount -= it.size;   // _sendFrame counts it again until written
    ws._sendFrame(it.opcode, it.data, it.cb);
  }
}

// The close frame, when messages sent before it are still queued (a Blob
// being read): it waits its turn, so it is the last frame out. With `now` (the
// peer closed first) the queue is dropped instead, and the caller writes it.
// true: queued, the caller writes nothing.
function queueCloseFrame(ws, payload, now) {
  var q = ws._sendQueue;
  if (!q || q.length === 0) return false;
  if (now) {
    for (var i = 0; i < q.length; i++) { ws._bufferedAmount -= q[i].size; if (q[i].cb) q[i].cb(new Error('the WebSocket is closed')); }
    q.length = 0;
    return false;
  }
  q.push({ opcode: OPCODE.CLOSE, data: payload, cb: null, size: 0 });
  return true;
}

// Ports the browser will not connect to (Fetch, "bad port"): services where a
// request someone else's page made could be taken for that protocol's commands
// — SMTP, IRC, SSH. Node's fetch refuses them as well.
var BAD_PORTS = new Set([0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
  101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512,
  513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720,
  1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080]);
function isBadPort(port) { return BAD_PORTS.has(Number(port)); }

export {
  userCloseCode,
  subprotocolList,
  closeReasonBytes,
  sendInOrder,
  queueCloseFrame,
  isBadPort,
  WSParser,
  encodeFrame,
  applyMask,
  generateKey,
  acceptKey,
  isValidCloseCode,
  isValidUserCloseCode,
  OPCODE,
  CLOSE,
  WS_GUID,
  // The two event surfaces, for ws_client and ws_server.
  installEventSurfaces,
  emitBoth,
  nodeMessagePayload
};
