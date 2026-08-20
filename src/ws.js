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
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);

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

      if (buf.length < offset + len) return;   // payload incomplete

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


export {
  WSParser,
  encodeFrame,
  applyMask,
  generateKey,
  acceptKey,
  isValidCloseCode,
  isValidUserCloseCode,
  OPCODE,
  CLOSE,
  WS_GUID
};
