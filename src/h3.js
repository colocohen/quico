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

import {
  createQpackTable,
  createQpackHistory,
  encodeHeaderBlock as qpackEncodeHeaderBlock,
  encodeInsert as qpackEncodeInsert,
  encodeSetCapacity as qpackEncodeSetCapacity,
  parseDecoderInstructions as qpackParseDecoderInstructions,
  encodeInsertCountIncrement as qpackEncodeAck,
  encodeStreamCancellation as qpackEncodeStreamCancel,
  decodeRequiredInsertCount,
  encodeSectionAck as qpackEncodeSectionAck,
  entrySize as qpackEntrySize
} from './qpack.js';
import { validateFieldSection, parseContentLength, parsePriority, formatPriority } from './http_common.js';

// ============================================================
//  QPACK dynamic table (RFC 9204): ON.
//
//  A kill switch rather than a constant, because the dynamic table is the one
//  part of HTTP/3 whose failure is invisible to a quico-to-quico test: both
//  ends of such a test share this file's encoder and decoder, so a mistake
//  made the same way on both sides passes. That is exactly what happened
//  once — the Required Insert Count was sent raw and read raw, the two agreed,
//  and every real browser failed from its fourth request on.
//
//  Verified since against independent implementations in both directions:
//  aioquic/ls-qpack and Chromium. Set to false to fall back to static-table
//  and Huffman compression only, with no other change.
// ============================================================
var QPACK_DYNAMIC_TABLE = true;

// The dynamic table's size, both ways: what we let the peer's encoder use, and
// the most our encoder uses of what the peer allows. 4096 is what browsers
// advertise, and it is enough: the fields that repeat and are not in the
// static table — user-agent, accept, sec-ch-ua — total a few hundred bytes.
var QPACK_TABLE_BYTES = 4096;

// Streams that may wait for the peer's encoder stream at once (SETTINGS_
// QPACK_BLOCKED_STREAMS, RFC 9204 §2.1.2): a field section may then
// reference an entry the encoder has only just inserted — its insertion and
// the section travel on different streams, and either can arrive first —
// rather than wait a round trip for our acknowledgement, or not compress the
// field at all. 0 was advertised. Chromium advertises 100.
var QPACK_BLOCKED_STREAMS = 100;

import {
  DEBUG,
  Emitter,
  concatUint8Arrays,
  writeVarInt,
  readVarInt,
  wt_stream_header
} from './utils.js';
import {
  QPACK_STATIC,
  readPrefixedInt,
  decodeStringLiteral
} from './hpack_primitives.js';


// ============================================================
//  QPACK header blocks (RFC 9204)
//
//  The wire primitives — Huffman, prefixed integers, string literals — now live
//  in hpack_primitives.js, because RFC 9204 defines them by reference to
//  RFC 7541 and HTTP/2's HPACK needs byte-identical code. What stays here is
//  what is genuinely QPACK: the RIC/base-index prefix, the encoder-stream
//  instructions, and the static table's own contents.
//
//  Names and values are turned into text with TextDecoder (UTF-8), which is
//  what this file has always done. hpack_primitives exports bytesToLatin1 as a
//  lossless alternative; switching to it is a deliberate behaviour change and
//  deliberately NOT part of this move.
// ============================================================

// One decoder for the module: decode() holds no state between calls (no
// `stream` option), and constructing one per name and per value cost more
// than the decoding itself.
var _utf8Decoder = new TextDecoder();
function _text(bytes) {
  return _utf8Decoder.decode(bytes);
}

// Every decodeStringLiteral() call below passes strict = true, enabling the
// padding checks of RFC 7541 §5.2: padding over 7 bits, padding that is not the
// EOS prefix, and a literal EOS symbol are all rejected. Without it an all-ones
// run decodes to symbol 256, which then silently truncates to a zero byte and
// lands in a header value — a malformed block quietly becomes a valid-looking
// request. Every peer that matters (nghttp2, quiche, msquic, Chrome) pads
// correctly, and the QPACK interop tests check that a decoder rejects the ones
// that do not.
//
// Note what strict does NOT cover: a literal cut short by the end of the
// available bytes still returns null and the parser waits for more, because on
// a QUIC stream that is ordinary partial delivery, not corruption. Telling the
// two apart needs the stream's FIN — a block still incomplete at FIN is a real
// error, and that check belongs with the per-stream state, not here.



function parseQpackHeaderBlock(buf, dynamicTable, totalInserts, maxEntries, maxSectionSize) {
  // RFC 9204 §4.5. `dynamicTable` is newest-first; `totalInserts` is how many
  // entries the peer has ever inserted, so absolute index A (zero-based) sits
  // at array position totalInserts - 1 - A — if it has not been evicted.
  //
  // This used to read the Required Insert Count raw, compute Base with the
  // sign bit's meaning reversed, and index the array by the absolute index.
  // None of it ran while our advertised table capacity was 0; the moment it
  // was raised, every conforming encoder broke on its first dynamic reference.
  var pos = 0;
  var ricEnc = readPrefixedInt(buf, 8, pos); if (!ricEnc) throw new Error('QPACK: truncated field section prefix');
  pos = ricEnc.next;
  if (pos >= buf.length) throw new Error('QPACK: truncated field section prefix');
  var sign = (buf[pos] & 0x80) !== 0;
  var db = readPrefixedInt(buf, 7, pos); if (!db) throw new Error('QPACK: truncated field section prefix');
  pos = db.next;

  var ric = decodeRequiredInsertCount(ricEnc.value, maxEntries || 0, totalInserts || 0);

  // A section past the inserts received waits before it is decoded (the
  // caller, sectionBlocked): here, it is one that should not have come.
  if (ric > (totalInserts || 0)) {
    throw new Error('QPACK: section needs ' + ric + ' inserts, have ' + (totalInserts || 0));
  }

  // §4.5.1.2: sign 0 → Base = RIC + Delta; sign 1 → Base = RIC - Delta - 1.
  var base = sign ? ric - db.value - 1 : ric + db.value;
  if (base < 0) throw new Error('QPACK: negative Base');

  function entryAt(absolute) {
    // Only entries below the declared Required Insert Count may be referenced.
    if (absolute < 0 || absolute >= ric) {
      throw new Error('QPACK: dynamic reference ' + absolute + ' outside Required Insert Count ' + ric);
    }
    var p = totalInserts - 1 - absolute;
    if (!dynamicTable || p < 0 || p >= dynamicTable.length) {
      throw new Error('QPACK: dynamic entry ' + absolute + ' unresolvable (evicted or never inserted)');
    }
    return dynamicTable[p];
  }

  var headers = {};
  // The field names in the order they were decoded.
  //
  // An object cannot carry it — pseudo-headers and regular fields end up in
  // whatever order the engine chooses — and the order is the strongest single
  // signal in a protocol fingerprint: Chrome sends m,a,s,p, Firefox m,p,a,s,
  // Safari m,s,p,a, each a constant in its own source. Attached as a
  // non-enumerable property so nothing that iterates the headers is affected.
  var _order = [];
  // And every field as decoded, repeats included: the object kept only the
  // last of a repeated name (two cookie fields, one survived), and has no
  // way to say a name came twice. The section is validated, and the request's
  // headers built, from this list (validateFieldSection, http_common).
  var _list = [];
  // The section's size as RFC 9114 §4.2.2 measures it: decoded, name and
  // value in bytes plus 32 per field — what SETTINGS_MAX_FIELD_SECTION_SIZE
  // limits. Only the ENCODED size of a HEADERS frame was bounded, and a
  // reference to a dynamic-table entry is one byte however long the entry:
  // 64 KB of references to one 4 KB entry decoded to 256 MB, joined into a
  // single field value (HPACK's "decompression bomb", which HTTP/2 here
  // bounds by MAX_HEADER_LIST_SIZE the same way).
  var sectionSize = 0;
  function field(name, value) {
    if (maxSectionSize) {
      sectionSize += qpackEntrySize(name, value);
      if (sectionSize > maxSectionSize) {
        var big = new Error('QPACK: field section exceeds ' + maxSectionSize + ' bytes decoded');
        big.excessive = true;
        throw big;
      }
    }
    _order.push(name); _list.push([name, value]); if (name !== '__proto__') headers[name] = value;
  }

  while (pos < buf.length) {
    var byte = buf[pos];
    var idx, nameIdx, val, e;

    if ((byte & 0x80) === 0x80) {
      // Indexed field line: 1 T xxxxxx
      idx = readPrefixedInt(buf, 6, pos); if (!idx) throw new Error('QPACK: truncated field line');
      pos = idx.next;
      if (byte & 0x40) {
        if (idx.value >= QPACK_STATIC.length) throw new Error('QPACK: static index ' + idx.value + ' out of range');
        field(QPACK_STATIC[idx.value][0], QPACK_STATIC[idx.value][1]);
      } else {
        e = entryAt(base - 1 - idx.value);
        field(e[0], e[1]);
      }

    } else if ((byte & 0xc0) === 0x40) {
      // Literal with name reference: 01 N T xxxx
      nameIdx = readPrefixedInt(buf, 4, pos); if (!nameIdx) throw new Error('QPACK: truncated field line');
      pos = nameIdx.next;
      val = decodeStringLiteral(buf, 7, pos, true); if (!val) throw new Error('QPACK: truncated field line');
      pos = val.next;
      var name;
      if (byte & 0x10) {
        if (nameIdx.value >= QPACK_STATIC.length) throw new Error('QPACK: static name index ' + nameIdx.value + ' out of range');
        name = QPACK_STATIC[nameIdx.value][0];
      } else {
        name = entryAt(base - 1 - nameIdx.value)[0];
      }
      field(name, _text(val.bytes));

    } else if ((byte & 0xe0) === 0x20) {
      // Literal with literal name: 001 N H xxx
      var nameLit = decodeStringLiteral(buf, 3, pos, true); if (!nameLit) throw new Error('QPACK: truncated field line');
      pos = nameLit.next;
      val = decodeStringLiteral(buf, 7, pos, true); if (!val) throw new Error('QPACK: truncated field line');
      pos = val.next;
      field(_text(nameLit.bytes), _text(val.bytes));

    } else if ((byte & 0xf0) === 0x10) {
      // Indexed field line with post-base index: 0001 xxxx (§4.5.3)
      idx = readPrefixedInt(buf, 4, pos); if (!idx) throw new Error('QPACK: truncated field line');
      pos = idx.next;
      e = entryAt(base + idx.value);
      field(e[0], e[1]);

    } else {
      // Literal with post-base name reference: 0000 N xxx (§4.5.5)
      nameIdx = readPrefixedInt(buf, 3, pos); if (!nameIdx) throw new Error('QPACK: truncated field line');
      pos = nameIdx.next;
      val = decodeStringLiteral(buf, 7, pos, true); if (!val) throw new Error('QPACK: truncated field line');
      pos = val.next;
      field(entryAt(base + nameIdx.value)[0], _text(val.bytes));
    }
  }

  Object.defineProperty(headers, '_order', { value: _order, enumerable: false });
  Object.defineProperty(headers, '_list', { value: _list, enumerable: false });
  // For the Section Acknowledgment the decoder owes when this is non-zero.
  Object.defineProperty(headers, '_ric', { value: ric, enumerable: false });
  return headers;
}



// ============================================================
//  H3 Frame build
//
//  Frames are read in place, from each stream's own buffer, as the bytes
//  arrive: processBidiStream and processControlStream in H3Connection.
// ============================================================

function buildH3Frames(frames) {
  var parts = [];
  for (var i = 0; i < frames.length; i++) {
    parts.push(writeVarInt(frames[i].frame_type));
    parts.push(writeVarInt(frames[i].payload.length));
    parts.push(frames[i].payload);
  }
  return concatUint8Arrays(parts);
}

// ============================================================
//  H3 Settings
// ============================================================

var H3_SETTINGS_MAP = {
  SETTINGS_QPACK_MAX_TABLE_CAPACITY: 0x01,
  SETTINGS_QPACK_BLOCKED_STREAMS: 0x07,
  SETTINGS_MAX_FIELD_SECTION_SIZE: 0x06,
  SETTINGS_ENABLE_CONNECT_PROTOCOL: 0x08,
  SETTINGS_H3_DATAGRAM: 0x33,
  SETTINGS_ENABLE_WEBTRANSPORT: 0x2b603742,
  SETTINGS_WT_MAX_SESSIONS: 0x14e9cd29
};

var H3_ID_TO_NAME = {};
for (var k in H3_SETTINGS_MAP) H3_ID_TO_NAME[H3_SETTINGS_MAP[k]] = k;

function buildSettingsPayload(settings) {
  var payload = [];
  for (var name in settings) {
    var id = H3_SETTINGS_MAP[name];
    if (id === undefined) continue;
    payload.push.apply(payload, Array.from(writeVarInt(id)));
    payload.push.apply(payload, Array.from(writeVarInt(settings[name])));
  }
  return new Uint8Array(payload);
}

function parseSettingsPayload(buf) {
  var out = {}, offset = 0;
  // The same settings as an ordered list, on a non-enumerable property so it
  // does not disturb anything that iterates the result. Order and unknown
  // identifiers are both discarded by the object form and both matter for
  // fingerprinting: which settings a peer sends, and in which order, is a
  // property of its implementation.
  var list = [];
  var seen = {};
  while (offset < buf.length) {
    // A payload that ends inside an identifier or before its value is
    // H3_FRAME_ERROR (RFC 9114 §7.1). It was cut short silently: the setting
    // dropped, the connection on.
    var id = readVarInt(buf, offset);
    var val = id ? readVarInt(buf, offset + id.byteLength) : null;
    if (!id || !val) {
      var te = new Error('SETTINGS payload ends inside a setting (' + (buf.length - offset) + ' byte(s) left)');
      te.h3ErrorCode = 0x0106;
      throw te;
    }
    offset += id.byteLength + val.byteLength;
    // RFC 9114 §7.2.4: an identifier twice, or one of HTTP/2's that HTTP/3
    // reserves (0x02-0x05), is H3_SETTINGS_ERROR.
    if (seen[id.value] || (id.value >= 0x02 && id.value <= 0x05)) {
      var se = new Error('SETTINGS identifier 0x' + id.value.toString(16) + (seen[id.value] ? ' repeated' : ' is reserved'));
      se.h3ErrorCode = 0x0109;
      throw se;
    }
    seen[id.value] = true;
    // Settings that are a yes or no: SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC
    // 8441 §3, by RFC 9220 §3 for HTTP/3) and SETTINGS_H3_DATAGRAM (RFC 9297
    // §2.1.1: "...any value other than 0 or 1 ... as a connection error of
    // type H3_SETTINGS_ERROR").
    if ((id.value === 0x08 || id.value === 0x33) && val.value > 1) {
      var ve = new Error('SETTINGS identifier 0x' + id.value.toString(16) + ' with value ' + val.value + ', not 0 or 1');
      ve.h3ErrorCode = 0x0109;
      throw ve;
    }
    var name = H3_ID_TO_NAME[id.value] || ('UNKNOWN_0x' + id.value.toString(16));
    out[name] = val.value;
    list.push({ id: id.value, value: val.value });
  }
  Object.defineProperty(out, '_ordered', { value: list, enumerable: false });
  return out;
}


// ============================================================
//  QPACK Encoder Instructions (from peer's encoder stream)
// ============================================================

// Parse the encoder-stream instructions in `combined` — the stream's unparsed
// bytes, from its read position. Returns the complete instructions, how many
// bytes they took (consumed), and, when the last one is cut short, how many
// bytes it needs (need). It used to take the stream's chunks and an offset
// and join them itself; the one caller already hands it a single buffer.
function parseQpackEncoderInstructions(combined, maxLiteral) {
  if (!combined || combined.length === 0) return { instructions: [], consumed: 0, need: 0 };
  if (maxLiteral === undefined) maxLiteral = Infinity;
  var pos = 0;
  var instructions = [];
  // When the last instruction is cut short: how many bytes, from its start,
  // it needs before parsing it can succeed (0 = unknown, try on any byte).
  // The caller waits for that many instead of re-parsing on every arrival —
  // a literal arriving a byte at a time was re-joined and re-parsed whole
  // each time: quadratic.
  var needAbs = 0;

  // Thin wrappers over the shared primitives that advance the local `pos` and
  // return the value (or null on truncation), preserving call-site usage.
  function safeVarInt(prefixBits) {
    var r = readPrefixedInt(combined, prefixBits, pos);
    if (!r) return null;
    pos = r.next;
    return r.value;
  }

  // A string literal's length is checked before its bytes are awaited. No
  // entry larger than the table capacity we advertised can ever be inserted
  // (RFC 9204 §3.2.2), so a longer literal is an error now — waiting for it
  // let a peer make us buffer an encoder stream of any size. Huffman can
  // expand a byte to at most 30 bits, so its bound is 30/8 of that.
  function safeLiteral(prefixBits) {
    if (pos >= combined.length) return null;
    var huffman = (combined[pos] & (1 << prefixBits)) !== 0;
    var len = readPrefixedInt(combined, prefixBits, pos);
    if (!len) return null;
    var limit = huffman ? Math.ceil(maxLiteral * 30 / 8) + 1 : maxLiteral;
    if (len.value > limit) {
      throw new Error('literal of ' + len.value + ' bytes cannot fit a table of ' + maxLiteral);
    }
    if (len.next + len.value > combined.length) { needAbs = len.next + len.value; return null; }
    var r = decodeStringLiteral(combined, prefixBits, pos, true);
    pos = r.next;
    return _text(r.bytes);
  }

  while (pos < combined.length) {
    var startPos = pos;
    var byte = combined[pos];

    if ((byte & 0x80) === 0x80) {
      // Insert with name reference
      var fromStatic = (byte & 0x40) !== 0;
      var nameIdx = safeVarInt(6); if (nameIdx === null) { pos = startPos; break; }
      var value = safeLiteral(7); if (value === null) { pos = startPos; break; }
      instructions.push({ type: 'insert_name_ref', from_static: fromStatic, name_index: nameIdx, value: value });

    } else if ((byte & 0xc0) === 0x40) {
      // Insert without name reference: 01 H NNNNN, 5-bit prefix on the name
      var name = safeLiteral(5); if (name === null) { pos = startPos; break; }
      var value = safeLiteral(7); if (value === null) { pos = startPos; break; }
      instructions.push({ type: 'insert_literal', name: name, value: value });

    } else if ((byte & 0xe0) === 0x20) {
      // Set dynamic table capacity
      var capacity = safeVarInt(5); if (capacity === null) { pos = startPos; break; }
      instructions.push({ type: 'set_capacity', capacity: capacity });

    } else {
      // Duplicate: 000 xxxxx, relative index (§4.3.4). This used to `break`,
      // which stopped reading the encoder stream for good: every instruction
      // after it went unread, and our table fell permanently out of step with
      // the peer's. Chrome duplicates entries it wants to keep alive.
      var dupIdx = safeVarInt(5); if (dupIdx === null) { pos = startPos; break; }
      instructions.push({ type: 'duplicate', index: dupIdx });
    }
  }

  return { instructions: instructions, consumed: pos,
           need: needAbs > pos ? needAbs - pos : 0 };
}


// ============================================================
//  Error codes (RFC 9114 §8.1, RFC 9204 §6)
//
//  These live in QUIC's APPLICATION error space and must be sent in a 0x1d
//  CONNECTION_CLOSE — see the note on QUICConnection.close().
//
//  RFC 9114 splits failures into two kinds, and they are NOT interchangeable:
//
//    Connection errors — the whole connection is unusable, because the shared
//      state it depends on is now unknown. Every QPACK failure is here: the
//      dynamic table is a running total of the peer's inserts, so one bad
//      header block means every later block on every stream decodes to
//      garbage. There is nothing to salvage per-stream. CONNECTION_CLOSE.
//
//    Stream errors — one request is malformed but the connection is fine.
//      RESET_STREAM / STOP_SENDING on that stream id, everything else
//      continues. H3_MESSAGE_ERROR is the common case.
//
//  Both are wired: a stream error is abortStream (STOP_SENDING and
//  RESET_STREAM, both reliable control frames of quic_connection's —
//  resetStream / stopSending, retransmitted until acknowledged) or
//  stopReading (STOP_SENDING alone). H3 resets a stream by asking QUIC, which
//  owns streams; the error code is an opaque varint QUIC never reads. HTTP/2
//  has no layer beneath it to ask — its RST_STREAM is its own frame on one
//  TCP byte stream — so the two share the idea, not the code.
// ============================================================

var H3_ERR = {
  H3_NO_ERROR:                0x0100,
  H3_GENERAL_PROTOCOL_ERROR:  0x0101,
  H3_INTERNAL_ERROR:          0x0102,
  H3_STREAM_CREATION_ERROR:   0x0103,
  H3_CLOSED_CRITICAL_STREAM:  0x0104,
  H3_FRAME_UNEXPECTED:        0x0105,
  H3_FRAME_ERROR:             0x0106,
  H3_EXCESSIVE_LOAD:          0x0107,
  H3_ID_ERROR:                0x0108,
  H3_SETTINGS_ERROR:          0x0109,
  H3_MISSING_SETTINGS:        0x010a,
  H3_REQUEST_REJECTED:        0x010b,
  H3_REQUEST_CANCELLED:       0x010c,
  H3_REQUEST_INCOMPLETE:      0x010d,
  H3_MESSAGE_ERROR:           0x010e,
  H3_CONNECT_ERROR:           0x010f,
  H3_VERSION_FALLBACK:        0x0110,

  QPACK_DECOMPRESSION_FAILED: 0x0200,
  QPACK_ENCODER_STREAM_ERROR: 0x0201,
  QPACK_DECODER_STREAM_ERROR: 0x0202
};

// An exception from inside this code — a read past an end, a property of
// undefined — and not one of the protocol's: none of these is thrown on
// purpose on the paths that read a peer's bytes. It is our failure, and goes
// as H3_INTERNAL_ERROR (as HTTP/2 sends INTERNAL_ERROR for one), not under a
// code that blames the peer: H3_FRAME_ERROR, QPACK_DECOMPRESSION_FAILED.
function isInternalError(err) {
  return err instanceof TypeError || err instanceof RangeError || err instanceof ReferenceError || err instanceof SyntaxError;
}

var H3_ERR_NAME = {};
for (var _ec in H3_ERR) H3_ERR_NAME[H3_ERR[_ec]] = _ec;


// ============================================================
//  H3Connection — reactive pattern
// ============================================================
//
//  Events:
//    'http_headers'  (stream_id, headers)   — new HTTP request headers
//    'http_body'     (stream_id, data)      — request body chunk
//

// The SETTINGS a connection with these local values sends.
function localSettings(c) {
  var o = { SETTINGS_MAX_FIELD_SECTION_SIZE: c.local_max_header_size };
  if (c.local_qpack_max_table_capacity > 0) {
    o.SETTINGS_QPACK_MAX_TABLE_CAPACITY = c.local_qpack_max_table_capacity;
    o.SETTINGS_QPACK_BLOCKED_STREAMS = QPACK_BLOCKED_STREAMS;
  }
  if (c.local_datagram_support) {
    o.SETTINGS_H3_DATAGRAM = 1;
    o.SETTINGS_ENABLE_CONNECT_PROTOCOL = 1;
  }
  if (c.local_webtransport) {
    o.SETTINGS_ENABLE_WEBTRANSPORT = 1;
    if (c.local_wt_max_sessions !== null) o.SETTINGS_WT_MAX_SESSIONS = c.local_wt_max_sessions;
  }
  return o;
}
function localValues(options) {
  return {
    local_max_header_size: 65536,
    local_qpack_max_table_capacity: QPACK_DYNAMIC_TABLE ? QPACK_TABLE_BYTES : 0,
    local_datagram_support: !!(options.enableWebTransport || options.enableDatagrams),
    local_webtransport: !!options.enableWebTransport,
    local_wt_max_sessions: options.maxWebTransportSessions > 0 ? Math.floor(options.maxWebTransportSessions) : null
  };
}

// 0-RTT (RFC 9114 §7.2.4.2): a client that remembered our SETTINGS may send
// early data under them — accepted only while they are the ones we send now.
// What a server built with these H3Connection options sends, as a string for
// the tickets' early-data context.
function settingsContext(options) {
  var o = localSettings(localValues(options || {})), keys = Object.keys(o).sort(), parts = [];
  for (var i = 0; i < keys.length; i++) parts.push(keys[i] + '=' + o[keys[i]]);
  return 'h3:' + parts.join(',');
}

function H3Connection(options) {
  if (!(this instanceof H3Connection)) return new H3Connection(options);
  options = options || {};

  var ev = Emitter();
  var quic = options.quicConnection;

  // Set once a connection error has been raised. Everything downstream stops:
  // the peer is getting a CONNECTION_CLOSE, and continuing to decode against a
  // dynamic table we no longer trust can only produce more wrong headers.
  var _fatal = false;

  /**
   * Raise an HTTP/3 connection error: tell the owner, then close the QUIC
   * connection with the application error code.
   *
   * Before this existed, a malformed header block threw out of the QPACK
   * decoder, up through processBidiStream, into the quic.on('stream') listener
   * — where Emitter's catch swallowed it. No error, no close, no RESET_STREAM.
   * The request simply hung until the idle timeout, and the peer was never told
   * why. Silently dropping a stream is the one response RFC 9114 does not allow.
   */
  // Report-only escape hatch for the checks added alongside this error layer
  // (strict Huffman padding, unresolvable table indices, post-base field
  // lines). Every one of them turns something previously ignored into a closed
  // connection — correct per RFC, but it means any latent bug they touch now
  // presents as a hard failure against a real peer. With qpackLenient the
  // condition is logged and the field skipped, restoring the old behaviour, so
  // a regression can be isolated without reverting the whole layer.
  var _lenient = options.qpackLenient === true;

  function connectionError(code, reason) {
    if (_fatal) return;
    var name = H3_ERR_NAME[code] || ('0x' + code.toString(16));

    if (_lenient) {
      console.warn('[h3] qpackLenient: ignoring ' + name + ': ' + reason);
      return;
    }

    _fatal = true;
    // Logged unconditionally, not behind DEBUG: this closes the connection, and
    // the peer only ever sees a generic protocol error. One line here is the
    // difference between a five-minute diagnosis and a packet capture.
    console.error('[h3] connection error ' + name + ': ' + reason);
    var err = new Error('HTTP/3 ' + name + ': ' + reason);
    err.code = name;
    err.errorCode = code;
    ev.emit('error', err);
    // `true` = application error space (0x1d). H3/QPACK codes are meaningless
    // in the transport space.
    try { quic.close(code, name, true); } catch (e) { /* already closing */ }
  }


  // ---- Context ----

  var lv = localValues(options);
  var context = {
    isServer: options.isServer !== false,

    // Local settings (what we advertise; localValues, as settingsContext sees them)
    local_max_header_size: lv.local_max_header_size,
    // QPACK_TABLE_BYTES. Measured against a real Chrome header set, a subresource request drops
    // from 412 bytes to 80 once these are in the table. The encoder is the
    // conservative one described in qpack.js, so this costs no risk of
    // head-of-line blocking.
    local_qpack_max_table_capacity: lv.local_qpack_max_table_capacity,
    // SETTINGS_H3_DATAGRAM (RFC 9297): WebTransport needs it, and so does a
    // CONNECT-UDP client (enableDatagrams) that is not WebTransport.
    local_datagram_support: lv.local_datagram_support,
    local_webtransport: lv.local_webtransport,
    // How many WebTransport sessions a peer may have open at once on this
    // connection (SETTINGS_WT_MAX_SESSIONS); null: no limit, and none sent.
    local_wt_max_sessions: lv.local_wt_max_sessions,

    // Remote settings (from peer's SETTINGS frame)
    remote_max_header_size: 0,
    remote_qpack_max_table_capacity: 0,
    remote_datagram_support: null,

    // QPACK dynamic table (peer's encoder inserts into this)
    remote_qpack_dynamic_table: [],
    remote_qpack_table_base_index: 0,
    remote_qpack_table_capacity: 0,
    remote_qpack_table_size: 0,      // bytes, by name + value + 32

    // Stream tracking
    streams: {},  // stream_id → { chunks, from_offset, type }

    // Control stream state
    control_streams_sent: false,
    remote_settings_received: false,
  };


  // ---- set_context ----

  // ---- QPACK outbound state ----
  //
  // Declared here, above set_context, because set_context opens the table when
  // the peer's SETTINGS arrives and would otherwise read an undefined `var`
  // that is hoisted but not yet assigned — a silent no-op rather than an
  // error, which is how the table stayed closed and nothing compressed.
  //
  // Separate from remote_qpack_dynamic_table, which is the PEER's table for
  // what we receive. The two are independent: each side runs its own with its
  // own capacity, and they are never in step.
  var encoderTable = createQpackTable(0);
  var encoderHistory = createQpackHistory(QPACK_TABLE_BYTES);   // insert on second sighting
  var encoderStreamId = null;
  var decoderStreamId = null;
  var qpackKnownReceived = 0;               // insertions the peer has acknowledged
  var qpackPendingAcks = 0;                 // insertions of THEIRS we owe an ack for
  // Field sections we sent with a non-zero Required Insert Count, not yet
  // acknowledged: stream id → [RIC, …] in the order sent (RFC 9204 §2.1.1).
  // The decoder acknowledges each (Section Acknowledgment), or cancels the
  // stream's; an acknowledgment for none is an error (§4.4.1).
  var qpackUnacked = new Map();

  // ---- SETTINGS remembered for 0-RTT (RFC 9114 §7.2.4.2) ----
  //
  // A client keeps the server's SETTINGS with the sessions it saves; its
  // early requests may then rely on them before this connection's arrive —
  // datagrams, the field-section limit (the QPACK table stays closed until
  // the real ones: using less is always compatible). With 0-RTT accepted,
  // the server's new SETTINGS must not take back what was remembered: a
  // known setting with a non-default value omitted, or one now smaller, is
  // H3_SETTINGS_ERROR. Nothing was kept, and early requests went on the
  // defaults with no check. Known identifiers only, as '0x…' keys.
  function knownSettings(list) {
    var out = {};
    for (var i = 0; i < list.length; i++) if (H3_ID_TO_NAME[list[i].id]) out['0x' + list[i].id.toString(16)] = list[i].value;
    return out;
  }
  var rememberedSettings = null;
  function useRememberedSettings() {
    var app = !context.isServer && quic && quic.earlyDataStatus === 'offered' ? quic.rememberedApplicationSettings : null;
    if (!app || !app.h3 || typeof app.h3 !== 'object') return;
    rememberedSettings = app.h3;
    var u = {};
    if (typeof rememberedSettings['0x6'] === 'number') u.remote_max_header_size = rememberedSettings['0x6'];
    if (typeof rememberedSettings['0x33'] === 'number') u.remote_datagram_support = rememberedSettings['0x33'] > 0;
    set_context(u);
  }
  function checkRememberedSettings(list) {
    if (!rememberedSettings || !quic || quic.earlyDataStatus !== 'accepted') return;
    var now = knownSettings(list);
    for (var k in rememberedSettings) {
      var was = rememberedSettings[k];
      if (typeof was !== 'number' || !H3_ID_TO_NAME[parseInt(k, 16)]) continue;
      if (!(k in now) ? was !== 0 : now[k] < was) {
        throw h3Error(H3_ERR.H3_SETTINGS_ERROR, '0-RTT accepted, and SETTINGS ' + (H3_ID_TO_NAME[parseInt(k, 16)]) +
          (!(k in now) ? ' omitted' : ' reduced') + ' (' + was + ' remembered' + ((k in now) ? ', ' + now[k] + ' now' : '') + ')');
      }
    }
  }

  function set_context(updates) {
    if (!updates || typeof updates !== 'object') return;

    var changed = {};

    if ('remote_max_header_size' in updates && updates.remote_max_header_size !== context.remote_max_header_size) {
      context.remote_max_header_size = updates.remote_max_header_size;
      changed.remote_max_header_size = true;
    }

    if ('remote_qpack_max_table_capacity' in updates && updates.remote_qpack_max_table_capacity !== context.remote_qpack_max_table_capacity) {
      context.remote_qpack_max_table_capacity = updates.remote_qpack_max_table_capacity;
      changed.remote_qpack_max_table_capacity = true;

      // Only now may we insert anything. The capacity is the PEER's — it
      // decides how much it is willing to hold for us — and inserting before
      // it has said so would produce references it cannot resolve.
      //
      // The Set Dynamic Table Capacity instruction goes first on the encoder
      // stream, before any insertion (§4.3.1).
      var cap = QPACK_DYNAMIC_TABLE ? Math.min(updates.remote_qpack_max_table_capacity, QPACK_TABLE_BYTES) : 0;
      if (cap > 0 && encoderTable.capacity === 0 && encoderStreamId !== null) {
        encoderTable.setCapacity(cap);
        quic.sendStream(encoderStreamId,
                        new Uint8Array(qpackEncodeSetCapacity(cap)), false);
        if (DEBUG) console.log('[h3] qpack encoder table opened at ' + cap);
      }
    }

    if ('remote_datagram_support' in updates) {
      context.remote_datagram_support = !!updates.remote_datagram_support;
      changed.remote_datagram_support = true;
    }

    if ('remote_settings_received' in updates && !context.remote_settings_received) {
      context.remote_settings_received = true;
      changed.remote_settings_received = true;
    }

    // ---- Reactive ----

    // (The peer's table — insertions, capacity, eviction, acknowledgements —
    // is maintained by processQpackEncoderStream directly, one instruction at
    // a time. It used to go through here in batches; see that function.)

    if (changed.remote_settings_received) {
      // Could trigger QPACK table capacity update etc.
    }
  }


  /**
   * The peer's decoder stream: what it has acknowledged.
   *
   * The only instruction that matters to this encoder is Insert Count
   * Increment. Each one raises the watermark below which an entry is safe to
   * reference — and until an entry is below it, we send a literal instead.
   * That single number is what makes this encoder non-blocking.
   *
   * Each instruction is held to what we actually sent (RFC 9204 §4.4): a
   * Section Acknowledgment for a section we have outstanding on that stream,
   * an Insert Count Increment of at least 1 that does not pass the entries we
   * inserted. Anything else is QPACK_DECODER_STREAM_ERROR.
   */
  function processQpackDecoderStream(s) {
    if (s.buffered === 0) return;
    // Only the unparsed bytes; at most one instruction's worth (a few bytes)
    // is ever left over between arrivals.
    var buf = Buffer.from(copyBytes(s, s.buffered));

    var r = qpackParseDecoderInstructions(buf, 0);
    for (var k = 0; k < r.instructions.length; k++) {
      var ins = r.instructions[k];
      if (ins.type === 'section_ack') {
        var pend = qpackUnacked.get(ins.value);
        if (!pend || pend.length === 0) {
          throw qpackDecoderStreamError('Section Acknowledgment for stream ' + ins.value +
                                        ', which has no field section awaiting one');
        }
        var ric = pend.shift();
        if (pend.length === 0) qpackUnacked.delete(ins.value);
        // §4.4.1: the acknowledged section's entries are now known received.
        if (ric > qpackKnownReceived) qpackKnownReceived = ric;
      } else if (ins.type === 'stream_cancel') {
        qpackUnacked.delete(ins.value);
      } else {
        // §4.4.3: zero, or past what was inserted, is an error.
        if (ins.value === 0) throw qpackDecoderStreamError('Insert Count Increment of 0');
        if (qpackKnownReceived + ins.value > encoderTable.insertCount) {
          throw qpackDecoderStreamError('Insert Count Increment to ' + (qpackKnownReceived + ins.value) +
                                        ', beyond the ' + encoderTable.insertCount + ' entries inserted');
        }
        qpackKnownReceived += ins.value;
      }
    }
    if (DEBUG && r.instructions.length) console.log('[h3] qpack decoder instructions ' + r.instructions.length +
                                                    ' (known=' + qpackKnownReceived + ')');
    consumeBytes(s, r.consumed);
  }

  function qpackDecoderStreamError(msg) {
    var err = new Error('QPACK decoder stream: ' + msg);
    err.h3ErrorCode = H3_ERR.QPACK_DECODER_STREAM_ERROR;
    return err;
  }

  function evictQpackTable(limit) {
    // Oldest first, until what remains fits. Sizes in BYTES: measuring by
    // string length, as this did, undercounts any non-ASCII header value and
    // lets our table drift out of step with the peer's.
    var entries = context.remote_qpack_dynamic_table;
    if (limit === undefined) limit = context.remote_qpack_table_capacity;
    while (context.remote_qpack_table_size > limit && entries.length > 0) {
      var removed = entries.pop();
      context.remote_qpack_table_size -= qpackEntrySize(removed[0], removed[1]);
    }
  }

  function qpackEncoderStreamError(msg) {
    var err = new Error('QPACK encoder stream: ' + msg);
    err.h3ErrorCode = H3_ERR.QPACK_ENCODER_STREAM_ERROR;
    return err;
  }

  // One insertion into the PEER's table, applied immediately — the next
  // instruction on the same stream may refer to it by relative index.
  function remoteTableInsert(name, value) {
    var need = qpackEntrySize(name, value);
    if (need > context.remote_qpack_table_capacity) {
      throw qpackEncoderStreamError('entry of ' + need + ' bytes exceeds capacity ' +
                                    context.remote_qpack_table_capacity);
    }
    evictQpackTable(context.remote_qpack_table_capacity - need);
    context.remote_qpack_dynamic_table.unshift([name, value]);
    context.remote_qpack_table_size += need;
    context.remote_qpack_table_base_index++;
    qpackPendingAcks++;
  }

  // On the encoder stream a relative index counts back from the most recent
  // insertion (§3.2.5): 0 is the newest entry, which is also position 0 of
  // this newest-first array. The old code computed an absolute index here
  // instead, and named the inserted entry after the wrong one.
  function remoteEntryByRelative(rel) {
    var e = context.remote_qpack_dynamic_table[rel];
    if (!e) throw qpackEncoderStreamError('relative index ' + rel + ' unresolvable');
    return e;
  }

  // Tell the peer what we now hold, so it may reference it.
  function flushQpackAcks() {
    if (qpackPendingAcks > 0 && decoderStreamId !== null) {
      quic.sendStream(decoderStreamId, new Uint8Array(qpackEncodeAck(qpackPendingAcks)), false);
      qpackPendingAcks = 0;
    }
  }



  // ---- Send initial control + QPACK streams ----

  /**
   * Send queued insertions on the encoder stream.
   *
   * Before the header block that will eventually use them, and never for the
   * block being sent now — nothing is referenced until acknowledged, so an
   * insertion is always for a later request.
   */
  function flushQpackInserts(inserts) {
    if (!inserts.length || encoderStreamId === null) return;
    var chunks = [];
    for (var i = 0; i < inserts.length; i++) {
      // Never evict: an entry that does not fit as things stand is not
      // inserted. insert() would make room by dropping old entries, and one of
      // those may still be referenced by a section the peer has not decoded
      // yet — which RFC 9204 §2.1.1 forbids. (It used to do exactly that, and
      // on "did not fit" also emptied our table without telling the peer.)
      if (!encoderTable.fits(inserts[i].name, inserts[i].value)) continue;
      encoderTable.insert(inserts[i].name, inserts[i].value);
      chunks.push(qpackEncodeInsert(inserts[i].name, inserts[i].value));
    }
    if (chunks.length) {
      quic.sendStream(encoderStreamId, new Uint8Array(Buffer.concat(chunks)), false);
    }
  }

  function sendControlStreams() {
    if (context.control_streams_sent) return;
    context.control_streams_sent = true;

    // A reserved identifier among them, of a random N (RFC 9114 §7.2.4.1,
    // 0x1f·N + 0x21): peers must ignore it — sending one keeps them honest.
    // Not part of localSettings: 0-RTT's context (settingsContext) holds the
    // ones that mean something, and this one changes every connection.
    var greaseId = 0x1f * Math.floor(Math.random() * 0x10000) + 0x21;
    var settings = concatUint8Arrays([
      buildSettingsPayload(localSettings(context)),
      writeVarInt(greaseId), writeVarInt(Math.floor(Math.random() * 64))
    ]);

    var controlFrame = buildH3Frames([{ frame_type: 0x04, payload: settings }]);

    // Uni stream IDs: server=3,7,11  client=2,6,10
    var ctrlId  = context.isServer ? 3 : 2;
    var encId   = context.isServer ? 7 : 6;
    var decId   = context.isServer ? 11 : 10;

    if (DEBUG) console.log('[h3] sendControlStreams ctrl=' + ctrlId + ' enc=' + encId + ' dec=' + decId);
    if (DEBUG) console.log('[h3] SETTINGS hex: ' + Array.from(controlFrame).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' '));

    // Send type byte + SETTINGS together as one chunk (some implementations need this)
    var ctrlData = new Uint8Array(1 + controlFrame.byteLength);
    ctrlData[0] = 0x00;  // control stream type
    ctrlData.set(controlFrame, 1);
    // Ahead of every request and WebTransport stream (urgency -1, below
    // RFC 9218's range): SETTINGS, GOAWAY, PRIORITY_UPDATE, and the QPACK
    // instructions the header blocks on request streams depend on — a block
    // that refers to an entry still waiting behind response bytes blocks.
    quic.setStreamPriority(ctrlId, { urgency: -1 });
    quic.setStreamPriority(encId, { urgency: -1 });
    quic.setStreamPriority(decId, { urgency: -1 });
    quic.sendStream(ctrlId, ctrlData, false);
    quic.sendStream(encId, new Uint8Array([0x02]), false);    // QPACK encoder
    quic.sendStream(decId, new Uint8Array([0x03]), false);    // QPACK decoder
    encoderStreamId = encId;
    decoderStreamId = decId;
  }


  // Our control and QPACK streams (sendControlStreams).
  function isOwnCriticalStream(sid) {
    return sid === (context.isServer ? 3 : 2) || sid === encoderStreamId || sid === decoderStreamId;
  }

  // ---- Graceful shutdown: GOAWAY (RFC 9114 §5.2) ----

  function sendGoaway(id) {
    sendControlStreams();  // idempotent — ensures the control stream + its type byte exist
    var ctrlId = context.isServer ? 3 : 2;
    var frame = buildH3Frames([{ frame_type: 0x07, payload: writeVarInt(id || 0) }]);
    if (DEBUG) console.log('[h3] → GOAWAY id=' + (id || 0));
    quic.sendStream(ctrlId, frame, false);
  }


  // ---- Incoming stream data ----

  var _claimedStreams = new Set(); // streams owned by WebTransport (skip H3 processing)
  var _wtSessions = new Set();    // active WT session stream IDs
  var _wtStreams = {};             // streamId → { sessionId, isBidi }
  var _wtLocalUni = {};            // our own WT uni streams: streamId → sessionId

  // WebTransport streams that arrive before their session is accepted. The
  // client may open them as soon as it has sent the CONNECT (draft-ietf-
  // webtrans-http3 §4.6), and they travel on streams of their own, so one can
  // be read before the CONNECT itself — or before the application has
  // answered it. They used to be read as unknown streams and their bytes
  // dropped, without a word to either side. Now they are held — their bytes
  // in the stream's own buffer, uncredited, so the peer is held to one
  // stream window each — until the session is accepted (then delivered as if
  // just arrived) or turned down, or too many wait (then reset with
  // WEBTRANSPORT_BUFFERED_STREAM_REJECTED, as the draft has it).
  var WT_BUFFERED_STREAM_REJECTED = 0x3994bd84;
  var MAX_HELD_WT_STREAMS = 64;
  var _wtHeld = new Map();         // streamId → the session ID it names
  var _wtConnects = new Set();     // WebTransport CONNECTs read, not yet answered (server)

  // Could this name a session still to be accepted? A CONNECT read and not
  // answered, or a client stream still open whose request is not read yet.
  function wtSessionMayCome(sessionId) {
    if (!context.isServer || sessionId % 4 !== 0) return false;
    if (_wtConnects.has(sessionId)) return true;
    if (!quic.isReceiving || !quic.isReceiving(sessionId)) return false;
    var cs = context.streams[sessionId];
    return !cs || (cs.type !== 'wt_held' && !cs.final_head_seen);
  }

  function holdWtStream(s, sessionId) {
    if (_wtHeld.size >= MAX_HELD_WT_STREAMS) { abortStream(s.sid, WT_BUFFERED_STREAM_REJECTED); return; }
    s.type = 'wt_held';
    _wtHeld.set(s.sid, sessionId);
  }

  // The session is accepted (go on) or not: its held streams, read again
  // from their start, or reset.
  function settleHeldWt(sessionId, accepted) {
    var ids = [];
    _wtHeld.forEach(function (sess, sid) { if (sess === sessionId) ids.push(sid); });
    if (ids.length === 0) return;
    if (!accepted) { for (var i = 0; i < ids.length; i++) abortStream(ids[i], WT_BUFFERED_STREAM_REJECTED); return; }
    // After the caller's accept returns — the layer above finishes setting up
    // the session (and the application its listeners) first.
    queueMicrotask(function () {
      for (var j = 0; j < ids.length; j++) {
        var hs = context.streams[ids[j]];
        if (!hs || _wtHeld.get(ids[j]) !== sessionId) continue;
        _wtHeld.delete(ids[j]);
        hs.type = null;
        onStream(ids[j], new Uint8Array(0), false);
      }
    });
  }

  // Streams running an extended-CONNECT protocol that is NOT WebTransport —
  // in practice WebSocket (RFC 9220). Their bytes are the inner protocol's,
  // not HTTP/3 frames, so they bypass the frame parser entirely.
  //
  // Kept apart from _wtSessions on purpose. A WebTransport session makes every
  // LATER stream that carries its id a member of that session; a WebSocket
  // does not, and registering one as a session would make unrelated streams
  // look like they belong to it.
  var _tunnelStreams = new Set();

  // Request bodies whose flow-control credit the application returns as it
  // reads them (holdBody / creditBody / releaseBody). On the server every
  // request stream's credit is held at the QUIC layer from its first byte
  // (setCreditPolicy below); this layer credits what it consumes itself —
  // frame headers, HEADERS, frames it skips — at once, and a body chunk
  // either as it hands it up (the default) or, for a stream in this set, when
  // the application has read it. The peer then sends a body no faster than
  // it is read: a handler that had not read yet — waiting on an
  // authorization check, say — had the whole upload held in memory, as fast
  // as the client could send it.
  var _bodyHeld = new Set();
  // The peer's control and QPACK streams, by type → stream ID.
  var _criticalStreams = {};
  //
  // WebTransport streams the same way: the client's unidirectional streams
  // are held too from their first byte, since what a stream is shows only in
  // those bytes — and our own bidirectional ones, which only WebTransport
  // opens, for what the client sends back on them. Control and QPACK streams (and ones of unknown type) give
  // their credit back the moment they are recognised; a WebTransport stream,
  // bidirectional or not, keeps it held, and h3_server returns it as the
  // application reads. Credited on delivery, a stream nobody read was taken
  // in whole: 40 MB from a browser, all of it in memory.
  //
  // The same on either side — a WebTransport client reads the server's
  // streams as the server reads the client's: every stream the peer can send
  // on, so all but our own unidirectional ones.
  if (quic.setCreditPolicy) {
    var ownUni = context.isServer ? 3 : 2;
    quic.setCreditPolicy(function (sid) { return (sid % 4) !== ownUni; });
  }
  function creditRecv(sid, n) { if (n > 0 && quic.creditStream) quic.creditStream(sid, n); }
  function releaseRecvCredit(sid) { if (quic.releaseStreamCredit) quic.releaseStreamCredit(sid); }

  // Bytes on a stream we have decided is a tunnel but have not yet accepted.
  //
  // The window is real and unavoidable: the client learns the CONNECT was
  // accepted only when our 2xx reaches it, but nothing stops it sending frames
  // the moment it sent the CONNECT — and an eager client (or a slow network in
  // the other direction) does exactly that. Those bytes are not HTTP/3 frames,
  // so they cannot go to the frame parser; they are held here and replayed, in
  // order, the instant the tunnel opens.
  var _tunnelPending = {};
  var _tunnelPendingBytes = {};
  var _tunnelPendingIds = new Set();
  // QUIC returns flow-control credit as it delivers bytes, so bytes held
  // here are not bounded by it: a client that never waits for the 2xx could
  // fill memory. Past this, the tunnel is refused.
  var MAX_TUNNEL_PENDING = 1024 * 1024;           // per stream
  var MAX_TUNNEL_PENDING_TOTAL = 4 * 1024 * 1024; // per connection
  var _tunnelPendingTotal = 0;
  var _tunnelPendingFin = new Set();

  // Frames on the control stream are read whole (SETTINGS, GOAWAY); no real
  // one comes near this. Anything else there is skipped as it arrives.
  var MAX_CONTROL_FRAME = 16384;

  // ── Stream lifecycle: one exit ────────────────────────────────────────
  //
  // releaseStream is the ONLY place per-stream state is dropped, and every
  // way a stream can end comes through it:
  //
  //   FIN, on whichever path read the stream (HTTP/3 frames, a tunnel, a
  //     WebTransport stream — including a FIN that arrived with its prefix —,
  //     a claimed or an ignored stream)        → the 'stream' handler
  //   RESET_STREAM from the peer               → quic 'stream_reset'
  //   cancelled or refused by us               → abortStream / stopReading
  //   its WebTransport session ended           → endWtSession → abortStream
  //   the connection closed                    → quic 'close'
  //
  // It drops only what this layer holds for the stream's RECEIVING side; a
  // response still being written is QUIC's, and unaffected. Idempotent. The
  // state used to be dropped piecemeal at each of those sites, each with its
  // own subset — which is how entries came to outlive their streams.
  function releaseStream(sid, keepBody) {
    sid = Number(sid);
    // Credit still held for it goes back — unless the stream ended normally
    // (keepBody) and the application still has its body to read: then it is
    // returned as that is read, or by releaseBody.
    if (!(keepBody && _bodyHeld.has(sid))) { _bodyHeld.delete(sid); releaseRecvCredit(sid); }
    delete context.streams[sid];
    _blocked.delete(sid);
    _prioPending.delete(sid);
    _wtHeld.delete(sid);
    // A CONNECT that ends unanswered: the streams waiting for it will not
    // get a session.
    if (_wtConnects.delete(sid) || !_wtSessions.has(sid)) settleHeldWt(sid, false);
    _tunnelStreams.delete(sid);
    _tunnelPendingIds.delete(sid);
    dropTunnelPending(sid);
    delete _wtStreams[sid];
    _claimedStreams.delete(sid);
    delete _wtLocalUni[sid];
    endWtSession(sid);   // a CONNECT stream's end is its session's end
  }

  // The connection is gone: every stream with it. No frames are sent — there
  // is no one to send them to — but the layer above still hears of each
  // What this layer listens to on the QUIC connection, so that it can stop
  // (detach): a client whose 0-RTT the server refused starts HTTP/3 over on
  // the same connection, and the layer that spoke early must not hear it.
  var _quicListeners = [];
  function listenQuic(name, fn) { _quicListeners.push([name, fn]); quic.on(name, fn); }

  // WebTransport session ending, through the same path as any other end.
  var _connClosed = false;
  listenQuic('close', function () {
    _connClosed = true;
    var ids = new Set();
    [context.streams, _wtStreams, _tunnelPending, _wtLocalUni].forEach(function (m) {
      for (var k in m) ids.add(Number(k));
    });
    [_tunnelStreams, _tunnelPendingIds, _claimedStreams, _wtSessions, _bodyHeld].forEach(function (set) {
      set.forEach(function (k) { ids.add(Number(k)); });
    });
    ids.forEach(releaseStream);
  });

  function dropTunnelPending(sid) {
    if (_tunnelPendingBytes[sid]) _tunnelPendingTotal -= _tunnelPendingBytes[sid];
    delete _tunnelPending[sid];
    delete _tunnelPendingBytes[sid];
    _tunnelPendingFin.delete(sid);
  }

  // Bytes held for a tunnel, handed over in order — with the FIN, if it came.
  function replayTunnelPending(sid) {
    var pend = _tunnelPending[sid];
    var fin = _tunnelPendingFin.has(sid);
    dropTunnelPending(sid);
    if (pend) for (var i = 0; i < pend.length; i++) ev.emit('tunnel_data', sid, pend[i], false);
    if (fin) { ev.emit('tunnel_data', sid, new Uint8Array(0), true); releaseStream(sid); }
  }

  // A WebTransport session is over (its CONNECT stream ended or was reset).
  // Its streams go with it: reset and stopped with WEBTRANSPORT_SESSION_GONE
  // (draft-ietf-webtrans-http3 §4.6), and reported so whoever holds them can
  // destroy them. They used to stay in _wtStreams / _claimedStreams, routed
  // to a session that no longer existed, until each one happened to end.
  var WT_SESSION_GONE = 0x170d7b68;
  function endWtSession(sessionId) {
    if (!_wtSessions.delete(sessionId)) return;
    var children = [];
    for (var k in _wtStreams) {
      if (_wtStreams[k].sessionId === sessionId) children.push(Number(k));
    }
    for (var u in _wtLocalUni) {
      if (_wtLocalUni[u] === sessionId) children.push(Number(u));
    }
    for (var i = 0; i < children.length; i++) {
      if (_connClosed) releaseStream(children[i]);
      else abortStream(children[i], WT_SESSION_GONE);
    }
    ev.emit('wt_session_closed', sessionId, children);
  }

  // A request stream announces itself as soon as it is one — its first bytes
  // read as HTTP/3, not WebTransport — before its HEADERS frame has even
  // arrived whole: the position of h2's 'stream_open', for the same reasons.
  // A refusal here costs nothing decoded, and the clock on a request's head
  // (h3_server's headersTimeout) starts with its first byte, not with a
  // HEADERS frame that a slow peer may never finish sending. It was announced
  // at that frame's decode, so a HEADERS trickled a byte at a time was
  // invisible for as long as it lasted.
  // Emitted unconditionally: a listenerCount guard once stood here, when
  // h3's emitter had no such method, and the event never fired at all.
  function announceRequestStream(s) {
    if (s.announced) return;
    s.announced = true;
    ev.emit('stream_open', Number(s.sid));
  }

  // A stream WE end because of what the peer sent on it — a stream error
  // (RFC 9114 §8). The stream is cancelled both ways, and reported: a
  // request above may already exist for it, and would otherwise wait for
  // an end that is never coming.
  function streamError(sid, code, reason) {
    if (DEBUG) console.log('[h3] stream error on ' + sid + ' (' + (H3_ERR_NAME[code] || code) + '): ' + reason);
    abortStream(sid, code);
    ev.emit('stream_error', sid, code, reason);
  }

  // Streams WE cancelled (abortStream). The peer's replies to that — it MUST
  // answer our STOP_SENDING with a RESET_STREAM (RFC 9000 §3.5) — are not the
  // peer cancelling anything, and must not be reported as if it were: a rate
  // limiter counting cancellations would charge clients for our refusals.
  // Bounded; a stream's echo arrives within a round trip or two.
  var _abortedHere = new Set();
  function rememberAborted(sid) {
    _abortedHere.add(sid);
    if (_abortedHere.size > 4096) _abortedHere.delete(_abortedHere.values().next().value);
  }

  // The peer reset its sending part (RESET_STREAM). For a request stream that
  // is the client cancelling the request — RFC 9114 §4.1.1 — and whoever is
  // handling it needs to know. The WebTransport session is passed along for
  // a WT stream, so it can be routed to its session.
  listenQuic('stream_reset', function (streamId, code) {
    var sid = Number(streamId);
    // The peer's control or QPACK stream, reset: closed, which RFC 9114
    // §6.2.1 and RFC 9204 §4.2 make a connection error however it happens.
    // Only a FIN was caught (processStream); a RESET_STREAM left the
    // connection serving on without them.
    var crit = context.streams[sid];
    if (crit && (crit.type === 'control' || crit.type === 'qpack_enc' || crit.type === 'qpack_dec')) {
      connectionError(H3_ERR.H3_CLOSED_CRITICAL_STREAM, 'the peer reset its ' + crit.type + ' stream');
      return;
    }
    var wt = _wtStreams[sid];
    var wasParsing = sid in context.streams;
    // A client's request stream reset before its HEADERS came: there is no
    // request, and no one above to end the response side — it stayed open
    // for good, its slot of the client's stream limit with it (and what the
    // transport keeps per stream until both sides end). Ended here, as a
    // cancelled request (RFC 9114 §4.1.1). Not a WebTransport stream: its
    // session's.
    var noRequest = context.isServer && (sid & 3) === 0 && !wt && !_wtHeld.has(sid) &&
                    !(wasParsing && context.streams[sid].headers_seen);
    releaseStream(sid);
    if (noRequest && quic.resetStream) quic.resetStream(sid, H3_ERR.H3_REQUEST_CANCELLED);
    if (_abortedHere.has(sid)) return;
    if (wasParsing) sendStreamCancel(sid);
    ev.emit('stream_reset', sid, code, wt ? wt.sessionId : null);
  });

  // The peer will not read what we send (STOP_SENDING). quic_connection has
  // already answered with RESET_STREAM, as RFC 9000 §3.5 requires. This is
  // how a browser cancels a GET: its own side of the stream is already
  // finished, so there is nothing for it to reset — STOP_SENDING is the
  // whole cancellation.
  listenQuic('stop_sending', function (streamId, code) {
    var sid = Number(streamId);
    // Asked to stop one of OUR critical streams: QUIC has answered with
    // RESET_STREAM, so it is closed — the same connection error (§6.2.1:
    // "A receiver MUST NOT request that the sender close the control stream").
    if (context.control_streams_sent && isOwnCriticalStream(sid)) {
      connectionError(H3_ERR.H3_CLOSED_CRITICAL_STREAM, 'the peer stopped our ' + (sid === encoderStreamId ? 'QPACK encoder' : sid === decoderStreamId ? 'QPACK decoder' : 'control') + ' stream');
      return;
    }
    if (_abortedHere.has(sid)) return;
    ev.emit('stop_sending', sid, code);
  });

  /**
   * Cancel a stream, both directions — RFC 9114 §4.1.1: "reset the sending
   * parts of streams and abort reading on the receiving parts". For a request
   * the server declines to process, `code` is H3_REQUEST_REJECTED (the
   * client may safely retry it); for one abandoned part way,
   * H3_REQUEST_CANCELLED.
   */
  function abortStream(streamId, code) {
    var sid = Number(streamId);
    rememberAborted(sid);
    var stopped = quic.stopSending ? quic.stopSending(sid, code) : false;
    if (quic.resetStream) quic.resetStream(sid, code);
    if (stopped) sendStreamCancel(sid);
    releaseStream(sid);
  }

  // Stop reading a stream, leaving our sending part alone — for a stream
  // whose response is already written (a refused tunnel: the 4xx/5xx went
  // out with FIN, and resetting would discard it).
  function stopReading(streamId, code) {
    var sid = Number(streamId);
    rememberAborted(sid);
    var stopped = quic.stopSending ? quic.stopSending(sid, code) : false;
    if (stopped) sendStreamCancel(sid);
    releaseStream(sid);
  }

  // RFC 9204 §2.2.2.2: reading of a request stream was abandoned (by us, or
  // by the peer's reset), so the peer's encoder must hear that any section
  // on it will never be acknowledged — or the entries it references can
  // never be evicted. Header sections live on client-initiated
  // bidirectional streams, whichever side we are.
  function sendStreamCancel(sid) {
    if ((sid % 4) !== 0) return;
    if (context.local_qpack_max_table_capacity > 0 && decoderStreamId !== null) {
      quic.sendStream(decoderStreamId, new Uint8Array(qpackEncodeStreamCancel(sid)), false);
    }
  }

  listenQuic('stream', onStream);
  function onStream(streamId, data, fin) {
    if (_fatal) return;   // connection is closing; decoding further is pointless
    var sid = Number(streamId);

    // An extended-CONNECT tunnel: after the CONNECT is accepted, everything on
    // this stream belongs to the protocol running inside it. RFC 9220 §3 —
    // WebSocket frames, not DATA frames, and reading them as HTTP/3 would fail
    // on the first opcode.
    if (_tunnelStreams.has(sid)) {
      // Bytes that arrived before the application accepted the CONNECT
      // (normally replayed at accept already). They go first, in order.
      if (_tunnelPending[sid]) replayTunnelPending(sid);
      ev.emit('tunnel_data', sid, data, fin);
      if (fin) releaseStream(sid);
      return;
    }

    // Route data for already-detected WT streams
    if (sid in _wtStreams) {
      var ws = _wtStreams[sid];
      ev.emit('wt_data', ws.sessionId, sid, data, fin);
      // Nothing arrives after a FIN (quic_connection's recv_final), so the
      // claim is not needed past it. Kept, both grew by one entry for every
      // WebTransport stream the connection ever carried.
      if (fin) releaseStream(sid);
      return;
    }

    if (_tunnelPendingIds.has(sid)) {
      // Marked as a tunnel-to-be by the application, not yet accepted.
      if (!_tunnelPending[sid]) { _tunnelPending[sid] = []; _tunnelPendingBytes[sid] = 0; }
      if (data && data.byteLength) {
        _tunnelPendingBytes[sid] += data.byteLength;
        _tunnelPendingTotal += data.byteLength;
        if (_tunnelPendingBytes[sid] > MAX_TUNNEL_PENDING || _tunnelPendingTotal > MAX_TUNNEL_PENDING_TOTAL) {
          streamError(sid, H3_ERR.H3_EXCESSIVE_LOAD, 'tunnel data held before the CONNECT was accepted exceeds the limit');
          return;
        }
        _tunnelPending[sid].push(data);
      }
      // The FIN is kept too: nothing more arrives after it, so it has to be
      // replayed at accept, not on a next delivery that never comes.
      if (fin) _tunnelPendingFin.add(sid);
      return;
    }

    // Owned by the WebTransport client (webtransport.js reads it itself);
    // released at its FIN like any other — it used to be kept for good.
    if (_claimedStreams.has(sid)) { if (fin) releaseStream(sid); return; }
    if (DEBUG) console.log('[h3] stream ' + streamId + ' data=' + data.byteLength + ' fin=' + fin);
    if (!(streamId in context.streams)) {
      context.streams[streamId] = { sid: sid, chunks: [], from_offset: 0, type: null, fin_received: false,
                                   buffered: 0,       // bytes held past from_offset
                                   data_left: 0, skip_left: 0,
                                   headers_seen: false, need: 0 };
      if (context.isServer && sid % 4 === 0 && sid > _maxPeerBidi) _maxPeerBidi = sid;
    }

    var s = context.streams[streamId];
    if (data && data.byteLength) { s.chunks.push(data); s.buffered += data.byteLength; }
    if (fin) s.fin_received = true;

    // Identify the stream type — from its first bytes, however QUIC splits
    // them. The type used to be read from the first DELIVERY: one that was
    // empty (a zero-length STREAM frame) left the stream typeless for good,
    // holding every byte sent on it; a WebTransport prefix split across two
    // deliveries was read as HTTP/3 frames. Only the first few bytes are
    // copied, never the whole buffer.
    if (s.type === null) {
      var isUni = (sid % 4) >= 2;
      var head = copyBytes(s, Math.min(s.buffered, 16));
      var st = readVarInt(head, 0);

      if (!st) {
        // Not even the first varint yet.
        if (!s.fin_received) return;
        if (isUni) { releaseStream(sid); return; }   // empty: nothing to do
        s.type = 'bidi';    // processBidiStream reports what is wrong with it
        announceRequestStream(s);
      } else {
        // ---- WT stream detection ----
        var wtType = isUni ? 0x54 : 0x41;
        if (context.local_webtransport && st.value === wtType) {
          var sidResult = readVarInt(head, st.byteLength);
          if (!sidResult && !s.fin_received) return;    // the session ID is still to come
          if (sidResult && !_wtSessions.has(sidResult.value)) {
            // Not a session (yet): held for one that may come, refused
            // for one that will not.
            if (wtSessionMayCome(sidResult.value)) holdWtStream(s, sidResult.value);
            else abortStream(sid, WT_BUFFERED_STREAM_REJECTED);
            return;
          }
          if (sidResult) {
            var sessionId = sidResult.value;
            var prefixLen = st.byteLength + sidResult.byteLength;
            consumeBytes(s, prefixLen);
            var remaining = s.buffered > 0 ? copyBytes(s, s.buffered) : new Uint8Array(0);

            delete context.streams[sid];   // no longer parsed as HTTP/3: a WT stream now
            // The prefix was ours, and consumeBytes credited it; the rest is
            // the application's, credited as it reads it (h3_server).
            _claimedStreams.add(sid);
            _wtStreams[sid] = { sessionId: sessionId, isBidi: !isUni };

            if (DEBUG) console.log('[h3] WT stream detected: stream=' + sid + ' session=' + sessionId + ' bidi=' + !isUni + ' dataLen=' + remaining.byteLength);
            ev.emit('wt_stream', sessionId, sid, remaining, s.fin_received, !isUni);
            if (s.fin_received) releaseStream(sid);   // the FIN came with the prefix
            return;
          }
        }

        if (isUni) {
          if (st.value === 0x00)      s.type = 'control';
          else if (st.value === 0x02) s.type = 'qpack_enc';
          else if (st.value === 0x03) s.type = 'qpack_dec';
          else if (st.value === 0x01) {
            // A push stream (§4.6, §6.2.2). Only a server pushes: one from a
            // client is H3_STREAM_CREATION_ERROR. A client allowed none (it
            // sends no MAX_PUSH_ID): "...receipt of a push stream as a
            // connection error of type H3_ID_ERROR when no MAX_PUSH_ID frame
            // has been sent".
            releaseRecvCredit(sid);
            if (context.isServer) connectionError(H3_ERR.H3_STREAM_CREATION_ERROR, 'a push stream from the client');
            else connectionError(H3_ERR.H3_ID_ERROR, 'a push stream, none allowed');
            return;
          }
          else                        s.type = 'unknown';
          if (s.type !== 'unknown') consumeBytes(s, st.byteLength);
          // Not a WebTransport stream: its credit is not the application's
          // to return (see setCreditPolicy above).
          releaseRecvCredit(sid);
          // One of each per peer (RFC 9114 §6.2.1, RFC 9204 §4.2): a second
          // control or QPACK stream is H3_STREAM_CREATION_ERROR. Read, a
          // second encoder stream fed the same dynamic table from two
          // directions (nginx CVE-2026-42530 was a reopened encoder stream).
          if (s.type !== 'unknown') {
            if (_criticalStreams[s.type] !== undefined && _criticalStreams[s.type] !== sid) {
              connectionError(H3_ERR.H3_STREAM_CREATION_ERROR, 'a second ' + s.type + ' stream');
              return;
            }
            _criticalStreams[s.type] = sid;
          }
        } else if ((sid % 4) === 1) {
          // Server-initiated bidirectional: HTTP/3 itself never opens one
          // (RFC 9114 §6.1) — only an extension such as WebTransport, whose
          // client side (webtransport.js) reads these streams itself. Parsed
          // as request frames, a WT payload starting with 0x00 read as DATA
          // before HEADERS and closed the whole connection.
          s.type = 'unknown';
          releaseRecvCredit(sid);   // not read: nothing will return its credit
        } else {
          s.type = 'bidi';
          announceRequestStream(s);
        }
      }
    }

    // Process by type.
    //
    // Each processor decodes attacker-controlled bytes, so each can throw:
    // a bad prefixed integer, an invalid Huffman code, a truncated literal.
    // The catch turns that into the connection error RFC 9114 requires,
    // instead of letting it unwind into Emitter's swallow.
    try {
      if ((s.type === 'control' || s.type === 'qpack_enc' || s.type === 'qpack_dec') && s.fin_received) {
        // RFC 9114 §6.2.1, RFC 9204 §4.2: these live as long as the connection.
        throw h3Error(H3_ERR.H3_CLOSED_CRITICAL_STREAM, 'the peer closed its ' + s.type + ' stream');
      }
      if (s.type === 'control') {
        processControlStream(s);

      } else if (s.type === 'qpack_enc') {
        processQpackEncoderStream(s);

      } else if (s.type === 'qpack_dec') {
        processQpackDecoderStream(s);

      } else if (s.type === 'bidi') {
        processBidiStream(streamId, s);

      } else if (s.type === 'unknown') {
        // A unidirectional stream of a type we do not know — GREASE, or an
        // extension we do not speak. RFC 9114 §6.2: its data is ignored. It
        // used to be kept all the same, every byte, for the connection's life.
        s.chunks.length = 0;
        s.from_offset = 0;
        s.buffered = 0;
        if (s.fin_received) releaseStream(sid);
      }

      // The processors read s.chunks from s.from_offset onward; what lies
      // before it is done with. Drop those chunks and rebase the offset, so
      // the array holds only bytes not yet parsed. Kept, every arrival walked
      // the whole history to find its place and re-copied the unparsed part
      // of it: O(n^2) over a large upload, and over the connection's life on
      // the control and QPACK streams, which never end.
      while (s.chunks.length > 0 && s.from_offset >= s.chunks[0].length) {
        s.from_offset -= s.chunks[0].length;
        s.chunks.shift();
      }
    } catch (err) {
      // A code already chosen at the throw site (see decodeHeaders below) wins;
      // an exception of our own is H3_INTERNAL_ERROR (isInternalError), and
      // counted as the QUIC layer counts its own; anything else is a framing
      // failure on whichever stream we were reading.
      if (!err.h3ErrorCode && isInternalError(err) && quic.countInternalError) quic.countInternalError(err);
      connectionError(err.h3ErrorCode || (isInternalError(err) ? H3_ERR.H3_INTERNAL_ERROR : H3_ERR.H3_FRAME_ERROR),
                      err.message || 'stream processing failed');
    }
  }


  listenQuic('connect', function () {
    sendControlStreams();
  });

  // If QUIC already connected (client creates H3 after connect), send now
  if (quic.state === 'connected') {
    sendControlStreams();
  }


  // ---- Stream processors ----

  // The control stream is read frame by frame, like a request stream. It
  // used to re-join everything unparsed on every arrival and wait for each
  // frame whole: a frame of an unknown type (legal — RFC 9114 §9 says to
  // ignore it) announcing a huge length made us buffer all of it, with a full
  // copy per packet. Now frames we do not read are skipped as they arrive,
  // and the ones we do read are bounded.
  function h3Error(code, msg) {
    var e = new Error(msg);
    e.h3ErrorCode = code;
    return e;
  }

  // Frame types of HTTP/2 that HTTP/3 reserves (RFC 9114 §7.2.8, §11.2.1):
  // PRIORITY, PING, WINDOW_UPDATE, CONTINUATION. On any stream:
  // H3_FRAME_UNEXPECTED.
  function reservedH2Frame(t) { return t === 0x02 || t === 0x06 || t === 0x08 || t === 0x09; }

  // Server push (RFC 9114 §4.6). Neither side here takes part in it: the
  // client sends no MAX_PUSH_ID, so no push ID is allowed it; the server
  // sends no PUSH_PROMISE, so no push ID exists to cancel. What each side
  // received of the peer's push frames, to hold them to their own rules.
  var _peerMaxPushId = -1;       // server: the highest MAX_PUSH_ID received
  var _peerGoawayId = -1;        // the last GOAWAY's identifier

  // A frame payload that is one varint and nothing else (CANCEL_PUSH,
  // GOAWAY, MAX_PUSH_ID): its value, or H3_FRAME_ERROR (§7.1: "...contain
  // additional bytes after the identified fields or a frame payload that
  // terminates before the end of the identified fields").
  function oneVarint(payload, what) {
    var v = readVarInt(payload, 0);
    if (!v || v.byteLength !== payload.length) throw h3Error(H3_ERR.H3_FRAME_ERROR, what + ' payload is not one integer');
    return v.value;
  }

  function processControlStream(s) {
    while (true) {
      if (s.skip_left > 0) {
        var skipNow = Math.min(s.skip_left, s.buffered);
        if (skipNow === 0) return;
        consumeBytes(s, skipNow);
        s.skip_left -= skipNow;
        continue;
      }
      if (s.buffered === 0) return;
      var head = copyBytes(s, Math.min(s.buffered, 16));
      var ft = readVarInt(head, 0);
      if (!ft) return;
      var flen = readVarInt(head, ft.byteLength);
      if (!flen) return;
      var headLen = ft.byteLength + flen.byteLength;

      // RFC 9114 §7.2.1, §7.2.2, §7.2.5: DATA, HEADERS and PUSH_PROMISE on
      // the control stream are H3_FRAME_UNEXPECTED.
      if (ft.value === 0x00 || ft.value === 0x01 || ft.value === 0x05 || reservedH2Frame(ft.value)) {
        throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'frame type 0x' + ft.value.toString(16) + ' on the control stream');
      }
      // RFC 9114 §6.2.1, §7.2.4: SETTINGS first, and once.
      if (!s.settings_seen && ft.value !== 0x04) throw h3Error(H3_ERR.H3_MISSING_SETTINGS, 'the control stream did not begin with SETTINGS');
      if (s.settings_seen && ft.value === 0x04) throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'a second SETTINGS frame');
      // MAX_PUSH_ID from a server (§7.2.7): H3_FRAME_UNEXPECTED, on sight.
      if (ft.value === 0x0d && !context.isServer) {
        throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'MAX_PUSH_ID from the server');
      }
      if (ft.value !== 0x04 && ft.value !== 0x07 && ft.value !== 0x03 && ft.value !== 0x0d &&
          ft.value !== PRIORITY_UPDATE_REQUEST && ft.value !== PRIORITY_UPDATE_PUSH) {
        consumeBytes(s, headLen);
        s.skip_left = flen.value;
        continue;
      }
      if (flen.value > MAX_CONTROL_FRAME) {
        throw h3Error(H3_ERR.H3_EXCESSIVE_LOAD, 'control frame of ' + flen.value + ' bytes');
      }
      if (s.buffered < headLen + flen.value) return;
      consumeBytes(s, headLen);
      var payload = copyBytes(s, flen.value);
      consumeBytes(s, flen.value);
      if (ft.value === 0x04) s.settings_seen = true;
      handleControlFrame(ft.value, payload);
      if (_fatal) return;
    }
  }

  function handleControlFrame(frameType, payload) {
    if (DEBUG) console.log('[h3] control: frame 0x' + frameType.toString(16) + ' len=' + payload.length);
    if (frameType === 0x04) {
      var settings = parseSettingsPayload(payload);
      checkRememberedSettings(settings._ordered || []);
      // Kept with the sessions saved from now on (a client's).
      if (!context.isServer && quic && quic.rememberApplicationSettings) quic.rememberApplicationSettings({ h3: knownSettings(settings._ordered || []) });
      var updates = { remote_settings_received: true };

      if ('SETTINGS_QPACK_MAX_TABLE_CAPACITY' in settings) {
        updates.remote_qpack_max_table_capacity = settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'];
      }
      if ('SETTINGS_MAX_FIELD_SECTION_SIZE' in settings) {
        updates.remote_max_header_size = settings['SETTINGS_MAX_FIELD_SECTION_SIZE'];
      }
      if ('SETTINGS_H3_DATAGRAM' in settings) {
        updates.remote_datagram_support = settings['SETTINGS_H3_DATAGRAM'] > 0;
      }

      set_context(updates);

      // Surfaced separately from the context update: this is an observation
      // about the peer, not a setting that changes our behaviour.
      ev.emit('peer_settings', settings._ordered || []);

    } else if (frameType === 0x07) {
      // GOAWAY (RFC 9114 §5.2): the peer will not process requests/pushes
      // with an identifier >= this value. Surface it so consumers (e.g. the
      // agent) can stop sending new requests on this connection.
      var gid = oneVarint(payload, 'GOAWAY');
      // From a server, a client-initiated bidirectional stream ID — "...of
      // any other type as a connection error of type H3_ID_ERROR"; from a
      // client, a push ID. Either way it may only stay or go down: "...an
      // identifier greater than that sent in a previous GOAWAY frame ...
      // MUST treat this as a connection error of type H3_ID_ERROR".
      if (!context.isServer && gid % 4 !== 0) throw h3Error(H3_ERR.H3_ID_ERROR, 'GOAWAY with stream ' + gid + ', not a request stream');
      if (_peerGoawayId >= 0 && gid > _peerGoawayId) throw h3Error(H3_ERR.H3_ID_ERROR, 'GOAWAY went up, ' + _peerGoawayId + ' to ' + gid);
      _peerGoawayId = gid;
      if (DEBUG) console.log('[h3] ← GOAWAY id=' + gid);
      ev.emit('goaway', gid);
    } else if (frameType === 0x03) {
      // CANCEL_PUSH (§7.2.3). At a server, of a push it never promised — it
      // promises none: "...a push ID that has not yet been mentioned by a
      // PUSH_PROMISE frame, this MUST be treated as a connection error of
      // type H3_ID_ERROR". At a client, of a push ID above the maximum it
      // allowed — it allowed none: H3_ID_ERROR.
      var cp = oneVarint(payload, 'CANCEL_PUSH');
      throw h3Error(H3_ERR.H3_ID_ERROR, 'CANCEL_PUSH for push ' + cp + (context.isServer ? ', never promised' : ', none allowed'));
    } else if (frameType === 0x0d) {
      // MAX_PUSH_ID at the server (§7.2.7; the client's case is refused
      // above): "...a MAX_PUSH_ID frame that contains a smaller value than
      // previously received MUST be treated as a connection error of type
      // H3_ID_ERROR." Kept, though no push follows.
      var mp = oneVarint(payload, 'MAX_PUSH_ID');
      if (mp < _peerMaxPushId) throw h3Error(H3_ERR.H3_ID_ERROR, 'MAX_PUSH_ID went down, ' + _peerMaxPushId + ' to ' + mp);
      _peerMaxPushId = mp;
    } else {
      handlePriorityUpdate(frameType, payload);
    }
  }

  // ---- Priorities (RFC 9218) ────────────────────────────────────────────
  //
  // The client's signals, read here and handed to QUIC's scheduler as the
  // peer's (setStreamPriority's fromPeer): the `priority` header of a
  // request, and PRIORITY_UPDATE on its control stream, which replaces it.
  // What the application sets for a response (h3_server's res.setPriority)
  // is the server's decision, and a signal does not override it. A request
  // with no signal keeps the scheduler's default: urgency 3, sharing turns.
  //
  // A PRIORITY_UPDATE may arrive before its request (§7.1 — they travel on
  // different streams): held until the request's head is read, then applied
  // over it. Bounded, oldest out; a client has no reason to run far ahead.
  var PRIORITY_UPDATE_REQUEST = 0xF0700, PRIORITY_UPDATE_PUSH = 0xF0701;
  var PRIORITY_PENDING_MAX = 128;
  var _prioPending = new Map();   // sid -> Priority Field Value
  var _maxPeerBidi = -1;          // highest request stream the client has opened

  function handlePriorityUpdate(frameType, payload) {
    // §7.2: the server sends none.
    if (!context.isServer) throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'PRIORITY_UPDATE from the server');
    var id = readVarInt(payload, 0);
    if (!id) throw h3Error(H3_ERR.H3_FRAME_ERROR, 'PRIORITY_UPDATE without an element ID');
    // §7.2: no push was ever allowed (we send no MAX_PUSH_ID), so any push ID
    // is beyond the limit; a request ID must be a client-initiated
    // bidirectional stream.
    if (frameType === PRIORITY_UPDATE_PUSH) throw h3Error(H3_ERR.H3_ID_ERROR, 'PRIORITY_UPDATE for a push');
    var sid = id.value;
    if (sid % 4 !== 0) throw h3Error(H3_ERR.H3_ID_ERROR, 'PRIORITY_UPDATE for stream ' + sid + ', not a request stream');
    var value = Buffer.from(payload.subarray(id.byteLength)).toString('latin1');
    var s = context.streams[sid];
    if (sid > _maxPeerBidi || (s && s.type !== 'bidi') || (s && !s.final_head_seen)) {
      _prioPending.delete(sid);
      _prioPending.set(sid, value);
      if (_prioPending.size > PRIORITY_PENDING_MAX) _prioPending.delete(_prioPending.keys().next().value);
      return;
    }
    quic.setStreamPriority(sid, parsePriority(value), true);   // false for a stream already over: nothing to do
  }

  // A request's head is read: its signals, the header first and any update
  // that came ahead of it over it.
  function applyRequestPriority(sid, headers) {
    if (headers.priority != null) quic.setStreamPriority(sid, parsePriority(headers.priority), true);
    if (_prioPending.has(sid)) {
      quic.setStreamPriority(sid, parsePriority(_prioPending.get(sid)), true);
      _prioPending.delete(sid);
    }
  }

  // The client's side: change a request's priority after it was sent (§7).
  function sendPriorityUpdate(streamId, p) {
    if (context.isServer) return false;
    sendControlStreams();
    var field = new Uint8Array(Buffer.from(formatPriority(p), 'latin1'));
    var idv = writeVarInt(Number(streamId));
    var payload = new Uint8Array(idv.byteLength + field.byteLength);
    payload.set(idv, 0); payload.set(field, idv.byteLength);
    quic.sendStream(context.isServer ? 3 : 2, buildH3Frames([{ frame_type: PRIORITY_UPDATE_REQUEST, payload: payload }]), false);
    return true;
  }

  function processQpackEncoderStream(s) {
    // An instruction cut short said how many bytes it needs; until they are
    // here, there is nothing to parse.
    if (s.buffered === 0 || (s.need > 0 && s.buffered < s.need)) return;
    var ext;
    try {
      // Only the unparsed bytes are copied (once per completed instruction,
      // given `need`), and no literal larger than our table can hold is
      // waited for.
      ext = parseQpackEncoderInstructions(copyBytes(s, s.buffered),
                                          context.local_qpack_max_table_capacity);
    } catch (err) {
      // RFC 9204 §4.2: a malformed encoder stream is QPACK_ENCODER_STREAM_ERROR,
      // not a decompression failure — nothing was being decompressed yet.
      err.h3ErrorCode = H3_ERR.QPACK_ENCODER_STREAM_ERROR;
      throw err;
    }
    consumeBytes(s, ext.consumed);
    s.need = ext.need;
    if (ext.instructions.length === 0) return;

    // Each instruction is applied before the next is read. They used to be
    // collected and inserted together, so an instruction naming an entry
    // inserted earlier in the same batch found the wrong one. And one that
    // could not be resolved was skipped — leaving our insert count one short
    // of the peer's, and every later reference pointing at the wrong entry.
    // Both are errors the peer must hear about, not things to paper over.
    for (var i = 0; i < ext.instructions.length; i++) {
      var inst = ext.instructions[i];

      if (inst.type === 'set_capacity') {
        if (inst.capacity > context.local_qpack_max_table_capacity) {
          throw qpackEncoderStreamError('capacity ' + inst.capacity + ' exceeds the ' +
                                        context.local_qpack_max_table_capacity + ' we advertised');
        }
        context.remote_qpack_table_capacity = inst.capacity;
        evictQpackTable();

      } else if (inst.type === 'insert_name_ref') {
        var name;
        if (inst.from_static) {
          if (inst.name_index >= QPACK_STATIC.length) {
            throw qpackEncoderStreamError('static name index ' + inst.name_index + ' out of range');
          }
          name = QPACK_STATIC[inst.name_index][0];
        } else {
          name = remoteEntryByRelative(inst.name_index)[0];
        }
        remoteTableInsert(name, inst.value);

      } else if (inst.type === 'insert_literal') {
        remoteTableInsert(inst.name, inst.value);

      } else if (inst.type === 'duplicate') {
        var dup = remoteEntryByRelative(inst.index);
        remoteTableInsert(dup[0], dup[1]);
      }
    }

    flushQpackAcks();
    unblockStreams();
  }

  // ---- Blocked streams (RFC 9204 §2.1.2) ----
  //
  // A HEADERS frame whose section needs inserts not yet received waits — its
  // bytes stay in the stream's buffer, uncredited, and nothing behind it on
  // the stream is read — until the encoder stream brings them. At most
  // QPACK_BLOCKED_STREAMS at once; one more is the peer breaking the limit
  // we set: QPACK_DECOMPRESSION_FAILED (§2.2.1).
  var _blocked = new Map();   // stream id → the Required Insert Count it waits for

  // The Required Insert Count of a field section, from its prefix.
  function sectionRequiredInsertCount(payload) {
    var ricEnc = readPrefixedInt(payload, 8, 0);
    if (!ricEnc) return 0;
    return decodeRequiredInsertCount(ricEnc.value, Math.floor(context.local_qpack_max_table_capacity / 32), context.remote_qpack_table_base_index);
  }

  // Whether stream `sid` must wait for this section; registers it if so.
  function sectionBlocked(sid, payload) {
    var ric;
    try { ric = sectionRequiredInsertCount(payload); }
    catch (e) { return false; }   // malformed: decodeHeaders reports it
    if (ric <= context.remote_qpack_table_base_index) { _blocked.delete(sid); return false; }
    if (!_blocked.has(sid) && _blocked.size >= QPACK_BLOCKED_STREAMS) {
      throw h3Error(H3_ERR.QPACK_DECOMPRESSION_FAILED, 'more than ' + QPACK_BLOCKED_STREAMS + ' blocked streams');
    }
    _blocked.set(sid, ric);
    return true;
  }

  // Inserts arrived: every stream they unblock is read on, in turn.
  function unblockStreams() {
    if (_blocked.size === 0) return;
    var ready = [];
    _blocked.forEach(function (ric, sid) { if (ric <= context.remote_qpack_table_base_index) ready.push(sid); });
    for (var i = 0; i < ready.length; i++) {
      _blocked.delete(ready[i]);
      var bs = context.streams[ready[i]];
      if (bs && bs.type === 'bidi') processBidiStream(ready[i], bs);
    }
  }


  /**
   * Decode a QPACK header block, re-tagging any failure as
   * QPACK_DECOMPRESSION_FAILED (RFC 9204 §2.2.3) rather than the generic
   * framing error. The distinction matters to whoever reads the peer's logs:
   * a decompression failure says the two dynamic tables have diverged, which
   * is a different bug from a malformed frame.
   */
  function decodeHeaders(payload, streamId) {
    var headers;
    try {
      headers = parseQpackHeaderBlock(
        payload,
        context.remote_qpack_dynamic_table,
        context.remote_qpack_table_base_index,
        // MaxEntries from the capacity WE advertised (§4.5.1.1).
        Math.floor(context.local_qpack_max_table_capacity / 32),
        context.local_max_header_size
      );
    } catch (err) {
      // Too large is this message's fault, not the tables': the stream goes,
      // the connection stays (see the caller).
      if (!err.excessive && !isInternalError(err)) err.h3ErrorCode = H3_ERR.QPACK_DECOMPRESSION_FAILED;
      throw err;
    }
    // §4.4.1: a section that used the dynamic table is acknowledged, so the
    // peer's encoder knows those references are done with.
    // Not for a stream we have abandoned: abortStream sent a Stream
    // Cancellation for it, and an acknowledgement after that names a section
    // the encoder no longer has — QPACK_DECODER_STREAM_ERROR on its side.
    if (headers._ric > 0 && decoderStreamId !== null && streamId !== undefined &&
        !_abortedHere.has(Number(streamId))) {
      quic.sendStream(decoderStreamId, new Uint8Array(qpackEncodeSectionAck(streamId)), false);
    }
    return headers;
  }


  // ---- Reading a request stream ----
  //
  // A request stream is a sequence of frames — HEADERS, DATA, perhaps trailing
  // HEADERS — and the bytes arrive in whatever pieces QUIC delivers, about one
  // packet each, cut with no regard for where a frame begins or ends.
  //
  // HEADERS is decoded whole, so it waits until all of it is here. DATA is not:
  // its bytes are handed to the application as they arrive, and s.data_left
  // counts down what is still to come of the frame. It used to wait for the
  // whole frame like HEADERS, re-joining everything received so far on every
  // packet — a 10MB DATA frame took some 20 seconds of CPU to parse, while the
  // application received nothing and the whole body sat in memory. One DATA
  // frame per write is exactly what h3_client sends.
  //
  // Frames of any other type carry nothing for a request stream; their bytes
  // are skipped the same way (s.skip_left), not buffered. They were ignored
  // before too, once complete.

  // Bytes buffered on stream `s` past its read position.
  function bufferedBytes(s) {
    return s.buffered;     // kept current by the push and consumeBytes — O(1)
  }

  // Move the read position on by `n` bytes, dropping chunks read to the end.
  // A body chunk (isBody) is credited by the caller; anything else consumed
  // here is credited at once.
  function consumeBytes(s, n, isBody) {
    if (!isBody && s.sid !== undefined) creditRecv(s.sid, n);
    s.from_offset += n;
    s.buffered -= n;
    while (s.chunks.length > 0 && s.from_offset >= s.chunks[0].length) {
      s.from_offset -= s.chunks[0].length;
      s.chunks.shift();
    }
  }

  // Copy `n` bytes from the read position; the caller has checked they are here.
  function copyBytes(s, n) {
    var out = new Uint8Array(n);
    var got = 0, skip = s.from_offset;
    for (var i = 0; got < n; i++) {
      var c = s.chunks[i];
      if (skip >= c.length) { skip -= c.length; continue; }
      var take = Math.min(c.length - skip, n - got);
      out.set(c.subarray(skip, skip + take), got);
      got += take;
      skip = 0;
    }
    return out;
  }

  // The bytes from the read position to the end of the chunk holding it, at
  // most `max` — a view, not a copy. null when nothing is buffered.
  function nextPiece(s, max) {
    var skip = s.from_offset;
    for (var i = 0; i < s.chunks.length; i++) {
      var c = s.chunks[i];
      if (skip >= c.length) { skip -= c.length; continue; }
      return c.subarray(skip, skip + Math.min(c.length - skip, max));
    }
    return null;
  }

  function processBidiStream(streamId, s) {
    while (true) {
      // Inside a DATA frame: hand over whatever of it is here.
      if (s.data_left > 0) {
        var piece = nextPiece(s, s.data_left);
        if (!piece) break;
        consumeBytes(s, piece.length, true);
        if (!_bodyHeld.has(Number(streamId))) creditRecv(Number(streamId), piece.length);
        s.data_left -= piece.length;
        if (s.content_length !== null && s.content_length !== undefined) {
          s.body_received += piece.length;
          if (s.body_received > s.content_length) {
            streamError(Number(streamId), H3_ERR.H3_MESSAGE_ERROR, 'body longer than content-length');
            return;
          }
        }
        ev.emit('http_body', Number(streamId), piece);
        if (context.streams[streamId] !== s) return;
        continue;
      }

      // Inside a frame of another type: skip whatever of it is here.
      if (s.skip_left > 0) {
        var skipNow = Math.min(s.skip_left, bufferedBytes(s));
        if (skipNow === 0) break;
        consumeBytes(s, skipNow);
        s.skip_left -= skipNow;
        continue;
      }

      // The next frame header: type and length, two varints of at most 8
      // bytes each.
      var avail = bufferedBytes(s);
      if (avail === 0) break;
      var head = copyBytes(s, Math.min(avail, 16));
      var ft = readVarInt(head, 0);
      if (!ft) break;
      var len = readVarInt(head, ft.byteLength);
      if (!len) break;
      var headLen = ft.byteLength + len.byteLength;

      if (ft.value === 0) {
        // DATA
        // RFC 9114 §4.1: a message starts with HEADERS; DATA before it is an
        // invalid frame sequence — H3_FRAME_UNEXPECTED, a connection error.
        // It used to be delivered, and h3_server built a request around it:
        // empty method and URL, handler called, and an entry nothing would
        // ever remove.
        if (!s.headers_seen) {
          throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'DATA before HEADERS on stream ' + streamId);
        }
        // Nor after the trailers, which end the message (§4.1): taken as more
        // body, the message read here was not the one framed — what a proxy
        // in front would have passed on.
        if (s.trailers_seen) {
          throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'DATA after trailers on stream ' + streamId);
        }
        consumeBytes(s, headLen);
        s.data_left = len.value;
        if (len.value === 0) {
          // An empty one is still reported, as it always was.
          ev.emit('http_body', Number(streamId), new Uint8Array(0));
          if (context.streams[streamId] !== s) return;
        }
        continue;
      }
      // Frames of the control stream, and HTTP/2's reserved ones, are
      // H3_FRAME_UNEXPECTED on a request stream (§7.2.3, §7.2.4, §7.2.6,
      // §7.2.7, §7.2.8; RFC 9218 §7.2 for PRIORITY_UPDATE).
      if (ft.value === 0x03 || ft.value === 0x04 || ft.value === 0x07 || ft.value === 0x0d ||
          ft.value === PRIORITY_UPDATE_REQUEST || ft.value === PRIORITY_UPDATE_PUSH || reservedH2Frame(ft.value)) {
        throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'frame type 0x' + ft.value.toString(16) + ' on request stream ' + streamId);
      }
      // PUSH_PROMISE (§7.2.5): from a client, H3_FRAME_UNEXPECTED; at a
      // client, a push ID above the maximum it allowed — none — H3_ID_ERROR.
      if (ft.value === 0x05) {
        if (context.isServer) throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'PUSH_PROMISE from the client on stream ' + streamId);
        throw h3Error(H3_ERR.H3_ID_ERROR, 'PUSH_PROMISE on stream ' + streamId + ', no push allowed');
      }
      if (ft.value !== 1) {
        consumeBytes(s, headLen);
        s.skip_left = len.value;
        continue;
      }

      // HEADERS — whole, or wait for the rest. Waiting is bounded: QUIC
      // returns flow-control credit as it hands bytes up, so it does not stop
      // a peer from announcing a frame of any length and sending it all. One
      // larger than the field section size we advertised (SETTINGS_MAX_
      // FIELD_SECTION_SIZE) is refused on sight, before it is buffered. The
      // encoded size is the right thing to compare: literals count their
      // full length plus 32 bytes per field there, more than they take here.
      // A field section after the trailers: §4.1, H3_FRAME_UNEXPECTED.
      if (s.trailers_seen) {
        throw h3Error(H3_ERR.H3_FRAME_UNEXPECTED, 'HEADERS after trailers on stream ' + streamId);
      }
      if (len.value > context.local_max_header_size) {
        streamError(Number(streamId), H3_ERR.H3_EXCESSIVE_LOAD,
                    'HEADERS of ' + len.value + ' bytes exceeds ' + context.local_max_header_size);
        return;
      }
      if (avail < headLen + len.value) break;
      // Waits for the encoder stream when it must (see sectionBlocked): the
      // frame stays in the buffer, read again once unblocked.
      // Already waiting, and the inserts it needs are not here yet: nothing
      // to do. The frame was copied and its prefix decoded again on every
      // packet that arrived on the stream meanwhile.
      if (_blocked.has(Number(streamId)) &&
          _blocked.get(Number(streamId)) > context.remote_qpack_table_base_index) return;
      var whole = copyBytes(s, headLen + len.value);
      var payload = whole.subarray(headLen);
      if (sectionBlocked(Number(streamId), payload)) return;
      consumeBytes(s, headLen + len.value);
      s.headers_seen = true;

      // HEADERS

      var headers;
      try { headers = decodeHeaders(payload, Number(streamId)); }
      catch (e) {
        if (!e.excessive) throw e;
        streamError(Number(streamId), H3_ERR.H3_EXCESSIVE_LOAD, e.message);
        return;
      }

      // Refused in 'stream_open' (abortStream forgot the stream): stop
      // here, before the request exists. The block is still decoded — the
      // QPACK state is shared with the peer and has to see every section —
      // but nothing above this layer hears of it. The comment above
      // promised exactly this; the code went on to emit http_headers, and
      // a refused request reached its handler all the same.
      if (context.streams[streamId] !== s) return;

      // The section must be well formed (RFC 9114 §4.1.2, §4.2, §4.3), by the
      // rules HTTP/2 uses too (validateFieldSection). None were checked here:
      // a value with CR LF, a connection-specific field, a request without
      // :path reached the handler as it came. Malformed: H3_MESSAGE_ERROR on
      // this stream. A section after the final head is trailers; a 1xx
      // response (103 Early Hints) is not the final head.
      var isTrailers = !!s.final_head_seen;
      var r;
      try {
        r = validateFieldSection(headers._list || [], {
          isServer: context.isServer,
          trailers: isTrailers,
          connectProtocol: !!context.local_datagram_support
        });
      } catch (e) {
        streamError(Number(streamId), H3_ERR.H3_MESSAGE_ERROR, e.message);
        return;
      }
      if (!isTrailers && !(!context.isServer && /^1/.test(r.headers[':status']))) s.final_head_seen = true;
      if (isTrailers) s.trailers_seen = true;

      // content-length against the body that actually comes (§4.1.2) — for
      // requests: a response to HEAD, or a 304, carries a length and no body.
      if (context.isServer) {
        if (!isTrailers) {
          try { s.content_length = parseContentLength(r.headers['content-length']); }
          catch (e) { streamError(Number(streamId), H3_ERR.H3_MESSAGE_ERROR, e.message); return; }
          s.body_received = 0;
        } else if (s.content_length !== null && s.content_length !== undefined && s.body_received !== s.content_length) {
          streamError(Number(streamId), H3_ERR.H3_MESSAGE_ERROR, 'body shorter than content-length');
          return;
        }
      }

      // The pseudo-header order, for the protocol fingerprint — once the
      // section is known to be well formed. Emitted separately because by the
      // time the headers reach an application they are an object and the
      // order is gone; this decode is the only place that sees the sequence.
      if (r.pseudoOrder.length) ev.emit('pseudo_order', r.pseudoOrder);
      if (context.isServer && !isTrailers) applyRequestPriority(Number(streamId), r.headers);
      if (context.isServer && !isTrailers && context.local_webtransport &&
          r.headers[':method'] === 'CONNECT' && r.headers[':protocol'] === 'webtransport') {
        // One session more than we said the peer may have: refused before
        // the application hears of it — H3_REQUEST_REJECTED, so it may try
        // again later, or on another connection.
        if (context.local_wt_max_sessions !== null && _wtSessions.size + _wtConnects.size >= context.local_wt_max_sessions) {
          streamError(Number(streamId), H3_ERR.H3_REQUEST_REJECTED, 'more WebTransport sessions than SETTINGS_WT_MAX_SESSIONS');
          return;
        }
        _wtConnects.add(Number(streamId));
      }

      // Trailers (a field section after the final head, RFC 9114 §4.1) are
      // their own event. As 'http_headers' they reached the layers above as a
      // second head: the client took them for the response's headers — its
      // status read 0 and 'response' fired twice — and the server merged
      // them into the request's headers.
      ev.emit(isTrailers ? 'http_trailers' : 'http_headers', Number(streamId), r.headers);
      // A handler may cancel the stream the moment it sees the headers;
      // DATA behind them in this batch must not surface as a body for a
      // request that no longer exists — h3_server would build a new one.
      if (context.streams[streamId] !== s) return;
    }

    // FIN received → stream complete (emitted only once)
    if (s.fin_received && !s.http_end_emitted) {
      // Every byte of the stream is here once its FIN is: anything left
      // unread is a frame cut short by the end of the stream. RFC 9114 §7.1:
      // H3_FRAME_ERROR. Ending the request quietly instead would hand the
      // application a truncated body as a complete one — the more so now that
      // DATA is delivered as it arrives.
      if (s.data_left > 0 || s.skip_left > 0 || bufferedBytes(s) > 0) {
        var truncated = new Error('stream ' + streamId + ' ended inside a frame');
        truncated.h3ErrorCode = H3_ERR.H3_FRAME_ERROR;
        throw truncated;
      }
      // A stream that ended without ever carrying HEADERS holds no message:
      // RFC 9114 §4.1.2, H3_REQUEST_INCOMPLETE. Reporting its end made the
      // layer above build a request out of nothing.
      if (!s.headers_seen) {
        streamError(Number(streamId), H3_ERR.H3_REQUEST_INCOMPLETE, 'stream ended without HEADERS');
        return;
      }
      if (s.content_length !== null && s.content_length !== undefined && s.body_received !== s.content_length) {
        streamError(Number(streamId), H3_ERR.H3_MESSAGE_ERROR, 'body shorter than content-length');
        return;
      }
      s.http_end_emitted = true;
      ev.emit('http_end', Number(streamId));
      // Its receiving side is over, and nothing more can arrive on it:
      // quic_connection discards every frame after the FIN (recv_final). Kept,
      // the entry held every byte the stream ever carried — a whole upload —
      // until the connection closed. Only this side is done; responses are
      // sent without this entry.
      // If it was a WebTransport CONNECT stream, its FIN ended the session:
      // a later stream naming it belongs to nothing, and the streams still
      // open in it are closed with it (releaseStream → endWtSession).
      if (context.streams[streamId] === s) releaseStream(Number(streamId), true);
    }
  }


  // ---- Send methods ----

  // One encoder whatever the peer allows. With no dynamic table — the peer
  // advertised capacity 0, or its SETTINGS have not arrived yet, and
  // encoderTable's capacity is still 0 — it uses the static table and Huffman
  // alone, and references and inserts nothing. (A second,
  // static-only encoder used to serve that case, without Huffman: a typical
  // page's response headers came out 313 bytes instead of 245.)
  function sendHeaders(streamId, headers, fin) {
    var list = [];
    for (var hname in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, hname)) {
        // A list: one field line per value (Set-Cookie above all, which may
        // not be combined), not String(list).
        var hv = headers[hname];
        if (Array.isArray(hv)) { for (var hi = 0; hi < hv.length; hi++) list.push([hname, String(hv[hi])]); }
        else list.push([hname, hv]);
      }
    }
    var enc = qpackEncodeHeaderBlock(list, encoderTable, {
      knownReceivedCount: qpackKnownReceived,
      history: encoderHistory,
      // The Required Insert Count is encoded against the capacity the PEER
      // advertised, not the smaller one this encoder uses (§4.5.1.1).
      peerMaxTableCapacity: context.remote_qpack_max_table_capacity || 0,
      // authorization and cookie carry secrets, and compressed size is
      // observable — the CRIME attack. They are never inserted.
      neverIndex: { 'authorization': true, 'cookie': true,
                    'proxy-authorization': true, 'set-cookie': true }
    });
    // Insertions FIRST, on their own stream: they are for the next request,
    // not this one.
    flushQpackInserts(enc.inserts);
    if (enc.requiredInsertCount > 0) {
      var pend = qpackUnacked.get(streamId);
      if (pend) pend.push(enc.requiredInsertCount);
      else qpackUnacked.set(streamId, [enc.requiredInsertCount]);
    }

    var frame = buildH3Frames([{ frame_type: 1, payload: new Uint8Array(enc.block) }]);
    if (DEBUG) console.log('[h3] sendHeaders stream=' + streamId + ' len=' + frame.byteLength + ' fin=' + !!fin);
    quic.sendStream(streamId, frame, !!fin);
  }

  function sendBody(streamId, data, fin) {
    if (DEBUG) console.log('[h3] sendBody stream=' + streamId + ' data=' + (data ? data.byteLength : 'null') + ' fin=' + fin);
    if (data === null || data === undefined) {
      // Just set FIN on the stream (no additional H3 frame needed for empty body)
      quic.sendStream(streamId, new Uint8Array(0), true);
      return;
    }
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    // The DATA frame header and the payload go down as two pieces: the payload
    // is queued by reference rather than copied behind a few header bytes.
    var header = concatUint8Arrays([writeVarInt(0), writeVarInt(data.byteLength)]);
    quic.sendStream(streamId, [header, data], !!fin);
  }


  // ---- Public API ----

  useRememberedSettings();

  var api = {
    /** Stop listening to the QUIC connection: this HTTP/3 layer is done
     *  with it, another may take over (a client's refused 0-RTT). */
    detach: function () {
      for (var i = 0; i < _quicListeners.length; i++) if (quic.off) quic.off(_quicListeners[i][0], _quicListeners[i][1]);
      _quicListeners = [];
    },
    context: context,

    on: function (name, fn) { ev.on(name, fn); },
    set_context: set_context,

    sendHeaders: sendHeaders,
    sendBody: sendBody,
    abortStream: abortStream,
    sendControlStreams: sendControlStreams,
    sendPriorityUpdate: sendPriorityUpdate,
    sendGoaway: sendGoaway,

    // WebTransport server-side API
    registerWebTransportSession: function (sessionStreamId) {
      var id = Number(sessionStreamId);
      _wtSessions.add(id);
      _wtConnects.delete(id);
      settleHeldWt(id, true);   // its streams that came early
    },

    // The application answered a WebTransport CONNECT with something other
    // than 2xx: streams that came early for it are refused.
    rejectWebTransportSession: function (sessionStreamId) {
      var id = Number(sessionStreamId);
      _wtConnects.delete(id);
      settleHeldWt(id, false);
    },

    // We closed it (CLOSE_WEBTRANSPORT_SESSION): its streams go now, reset
    // with WEBTRANSPORT_SESSION_GONE as when the peer ends it.
    endWebTransportSession: function (sessionStreamId) { endWtSession(Number(sessionStreamId)); },

    /**
     * Take a stream out of HTTP/3 framing and hand its bytes through raw.
     *
     * Called once an extended CONNECT has been accepted with a 2xx. From then
     * on the stream carries whatever protocol `:protocol` named — WebSocket
     * frames, for RFC 9220 — and 'tunnel_data' delivers them verbatim.
     */
    registerTunnelStream: function (streamId) {
      var id = Number(streamId);
      _tunnelStreams.add(id);
      _tunnelPendingIds.delete(id);
      // Anything that arrived before the accept is delivered now — after the
      // caller's accept returns — rather than on the next arrival, which may
      // never come (the client's FIN may already be here).
      if (_tunnelPending[id] || _tunnelPendingFin.has(id)) {
        queueMicrotask(function () { if (_tunnelStreams.has(id)) replayTunnelPending(id); });
      }
    },

    /** Stop reading a stream without resetting what we sent on it. */
    stopReading: stopReading,

    /** A WebTransport stream we opened has ended on our side. */
    releaseWebTransportStream: function (streamId) { releaseStream(streamId); },

    /**
     * Mark a stream as a tunnel-in-progress: stop feeding it to the HTTP/3
     * frame parser, but hold its bytes until registerTunnelStream() accepts.
     *
     * Called the moment `:protocol` is seen, which is before the application
     * has decided whether to accept. Without it, a client that sends its first
     * WebSocket frame immediately after the CONNECT has that frame parsed as
     * an HTTP/3 frame and lost.
     */
    beginTunnelStream: function (streamId) {
      _tunnelPendingIds.add(Number(streamId));
      // Its bytes are the tunnel's, bounded by MAX_TUNNEL_PENDING until the
      // accept: credited as delivered from here on.
      _bodyHeld.delete(Number(streamId));
      releaseRecvCredit(Number(streamId));
    },

    /**
     * The application returns a request body's flow-control credit itself, as
     * it reads (see _bodyHeld): from now on, `creditBody(id, n)` for each n
     * bytes read, and `releaseBody(id)` when it will read no more.
     */
    holdBody: function (streamId) {
      var id = Number(streamId);
      if (context.streams[id]) _bodyHeld.add(id);
    },
    creditBody: function (streamId, n) { if (_bodyHeld.has(Number(streamId))) creditRecv(Number(streamId), n); },
    releaseBody: function (streamId) {
      var id = Number(streamId);
      if (!_bodyHeld.delete(id)) return;
      releaseRecvCredit(id);
    },

    /** Write raw bytes onto a tunnel stream. */
    sendTunnelData: function (streamId, data, fin) {
      quic.sendStream(Number(streamId), data, !!fin);
    },

    // A WebTransport stream of our own, on either side: the next free stream
    // number (quic's nextLocalStreamId), opened now with its prefix —
    // VarInt(0x41 or 0x54) + VarInt(session ID) — as a browser does.
    createWebTransportStream: function (sessionId, isBidi) {
      var streamId = quic.nextLocalStreamId(!!isBidi);
      quic.sendStream(streamId, wt_stream_header(isBidi, sessionId), false);

      // Claimed for what the peer sends back on it — so only a bidirectional
      // one. Nothing ever arrives on our own unidirectional stream, so no FIN
      // ever released a claim made for it.
      if (isBidi) {
        _claimedStreams.add(streamId);
        _wtStreams[streamId] = { sessionId: sessionId, isBidi: isBidi };
      } else {
        // Tracked only so the session's end can reset it (released by the
        // writer at its end: releaseWebTransportStream).
        _wtLocalUni[streamId] = Number(sessionId);
      }

      return streamId;
    }
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }
  return this;
}


// ============================================================
//  WebTransport stream error codes (draft-ietf-webtrans-http3 §4.4)
// ============================================================
//
// A WebTransport application resets or stops a stream with a 32-bit code of
// its own; on the wire it is an HTTP/3 error code, in a range reserved for
// it, which skips the codes reserved for greasing (0x1f * N + 0x21). Sent
// raw, a WebTransport code collided with HTTP/3's own (H3_NO_ERROR is
// 0x100), and the browser read neither.
var WT_ERR_FIRST = 0x52e4a40fa8db;
var WT_ERR_LAST  = 0x52e5ac983162;

function wtErrorToH3(code) {
  code = Number(code);
  if (!(code >= 0 && code <= 0xffffffff) || Math.floor(code) !== code) code = 0;
  return WT_ERR_FIRST + code + Math.floor(code / 0x1e);
}

// The WebTransport code an HTTP/3 code carries; null if it carries none.
function h3ErrorToWt(h3code) {
  h3code = Number(h3code);
  if (!(h3code >= WT_ERR_FIRST && h3code <= WT_ERR_LAST)) return null;
  if ((h3code - 0x21) % 0x1f === 0) return null;   // a grease code
  var shifted = h3code - WT_ERR_FIRST;
  return shifted - Math.floor(shifted / 0x1f);
}

// ============================================================
//  WebTransport session capsules (RFC 9297; draft-ietf-webtrans-http3 §5)
// ============================================================
//
// After the 2xx, a session's CONNECT stream carries capsules — type, length,
// value — in HTTP/3 DATA frames. Two concern the session:
//   CLOSE_WEBTRANSPORT_SESSION (0x2843): a 32-bit application code and a
//     UTF-8 reason of up to 1024 bytes; the sender then ends the stream;
//   DRAIN_WEBTRANSPORT_SESSION (0x78ae): empty — finish up, no new work.
// Any other type is skipped (RFC 9297 §3.2), without being buffered.
var CAPSULE_CLOSE_WT = 0x2843;
var CAPSULE_DRAIN_WT = 0x78ae;
var WT_CLOSE_REASON_MAX = 1024;

function encodeCapsule(type, value) {
  return concatUint8Arrays([writeVarInt(type), writeVarInt(value.byteLength), value]);
}

function wtCloseCapsule(code, reason) {
  code = Number(code);
  if (!(code >= 0 && code <= 0xffffffff) || Math.floor(code) !== code) code = 0;
  var r = Buffer.from(String(reason == null ? '' : reason), 'utf8');
  if (r.length > WT_CLOSE_REASON_MAX) {
    // Cut on a character boundary: back off continuation bytes (10xxxxxx).
    var end = WT_CLOSE_REASON_MAX;
    while (end > 0 && (r[end] & 0xc0) === 0x80) end--;
    r = r.subarray(0, end);
  }
  var v = new Uint8Array(4 + r.length);
  v[0] = code >>> 24; v[1] = (code >>> 16) & 0xff; v[2] = (code >>> 8) & 0xff; v[3] = code & 0xff;
  v.set(r, 4);
  return encodeCapsule(CAPSULE_CLOSE_WT, v);
}

function wtDrainCapsule() { return encodeCapsule(CAPSULE_DRAIN_WT, new Uint8Array(0)); }

// Reads a CONNECT stream's capsules as they arrive, however they are split:
// onClose({ closeCode, reason }) and onDrain(). A CLOSE whose value is
// malformed (shorter than its code, or a reason past the limit) is still a
// close — with code 0 and no reason.
function createCapsuleReader(onClose, onDrain) {
  var buf = new Uint8Array(0), skip = 0;
  return function feed(data) {
    if (skip > 0) {
      var n = Math.min(skip, data.byteLength);
      skip -= n; data = data.subarray(n);
    }
    if (data.byteLength === 0) return;
    buf = buf.byteLength ? concatUint8Arrays([buf, data]) : data;
    for (;;) {
      var t = readVarInt(buf, 0); if (!t) return;
      var l = readVarInt(buf, t.byteLength); if (!l) return;
      var head = t.byteLength + l.byteLength;
      var known = t.value === CAPSULE_CLOSE_WT || t.value === CAPSULE_DRAIN_WT;
      if (!known || l.value > 4 + WT_CLOSE_REASON_MAX) {
        if (known) onClose({ closeCode: 0, reason: '' });   // oversized: a close all the same
        var have = buf.byteLength - head;
        if (have >= l.value) { buf = buf.subarray(head + l.value); continue; }
        skip = l.value - have; buf = new Uint8Array(0); return;
      }
      if (buf.byteLength < head + l.value) return;   // the rest is still to come
      var v = buf.subarray(head, head + l.value);
      buf = buf.subarray(head + l.value);
      if (t.value === CAPSULE_DRAIN_WT) { onDrain(); continue; }
      if (v.byteLength < 4) { onClose({ closeCode: 0, reason: '' }); continue; }
      onClose({ closeCode: ((v[0] << 24) >>> 0) + (v[1] << 16) + (v[2] << 8) + v[3],
                reason: Buffer.from(v.subarray(4)).toString('utf8') });
    }
  };
}

// parseQpackHeaderBlock is exported for the QPACK tests, which check it
// against sections from an independent encoder.
export { settingsContext as h3SettingsContext };
export { H3Connection, H3_ERR, H3_ERR_NAME, parseQpackHeaderBlock, wtErrorToH3, h3ErrorToWt,
         wtCloseCapsule, wtDrainCapsule, createCapsuleReader };