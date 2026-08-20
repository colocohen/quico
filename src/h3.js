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
  DEBUG,
  Emitter,
  concatUint8Arrays,
  writeVarInt,
  readVarInt,
  wt_stream_header
} from './utils.js';
import {
  QPACK_STATIC,
  buildStaticLookup,
  readPrefixedInt,
  encodePrefixedInt,
  decodeStringLiteral,
  encodeStringLiteral
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

function _text(bytes) {
  return new TextDecoder().decode(bytes);
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

// Static-table lookup maps for the encoder, built once. QPACK indexes from 0.
var _qpackLookup = buildStaticLookup(QPACK_STATIC, 0);
var _qpackFullMatch = _qpackLookup.full;   // "name\0value" → index
var _qpackNameMatch = _qpackLookup.name;   // "name" → first index


function parseQpackHeaderBlock(buf, dynamicTable, baseIndex) {
  var pos = 0;
  var ric = readPrefixedInt(buf, 8, pos); if (!ric) return {}; pos = ric.next;
  var postBase = (buf[pos] & 0x80) !== 0;
  var db = readPrefixedInt(buf, 7, pos); if (!db) return {}; pos = db.next;
  var bi = postBase ? ric.value + db.value : ric.value - db.value;

  var headers = {};
  while (pos < buf.length) {
    var byte = buf[pos];

    if ((byte & 0x80) === 0x80) {
      // Indexed
      var fromStatic = (byte & 0x40) !== 0;
      var idx = readPrefixedInt(buf, 6, pos); if (!idx) break; pos = idx.next;
      if (fromStatic) {
        if (idx.value >= QPACK_STATIC.length) {
          throw new Error('QPACK: static index ' + idx.value + ' out of range');
        }
        headers[QPACK_STATIC[idx.value][0]] = QPACK_STATIC[idx.value][1];
      } else {
        // An index the dynamic table cannot satisfy means our copy of the
        // peer's table has diverged from theirs — RFC 9204 §2.2.3 calls that
        // QPACK_DECOMPRESSION_FAILED. Skipping the field instead (what this did
        // before) hands the application a request with a header silently
        // missing, which is worse than refusing it: the peer believes it sent
        // an Authorization or a Host that never arrived.
        var di = bi - 1 - idx.value;
        if (!dynamicTable || di < 0 || di >= dynamicTable.length) {
          throw new Error('QPACK: dynamic index ' + idx.value + ' unresolvable');
        }
        headers[dynamicTable[di][0]] = dynamicTable[di][1];
      }

    } else if ((byte & 0xc0) === 0x40) {
      // Literal with name ref
      var fromStatic = (byte & 0x10) !== 0;
      var nameIdx = readPrefixedInt(buf, 4, pos); if (!nameIdx) break; pos = nameIdx.next;
      var val = decodeStringLiteral(buf, 7, pos, true); if (!val) break; pos = val.next;

      var name;
      if (fromStatic) {
        if (nameIdx.value >= QPACK_STATIC.length) {
          throw new Error('QPACK: static name index ' + nameIdx.value + ' out of range');
        }
        name = QPACK_STATIC[nameIdx.value][0];
      } else {
        var di = bi - 1 - nameIdx.value;
        if (!dynamicTable || di < 0 || di >= dynamicTable.length) {
          throw new Error('QPACK: dynamic name index ' + nameIdx.value + ' unresolvable');
        }
        name = dynamicTable[di][0];
      }
      headers[name] = _text(val.bytes);

    } else if ((byte & 0xe0) === 0x20) {
      // Literal with literal name
      var nameLit = decodeStringLiteral(buf, 3, pos, true); if (!nameLit) break; pos = nameLit.next;
      var val = decodeStringLiteral(buf, 7, pos, true); if (!val) break; pos = val.next;
      headers[_text(nameLit.bytes)] = _text(val.bytes);

    } else {
      // Everything below 0x20 is a post-base field line (RFC 9204 §4.5.3 /
      // §4.5.5): an index counted forward from the base rather than back from
      // it, which an encoder may only use for entries inserted after the base.
      //
      // Reaching one here means the peer inserted into its dynamic table — but
      // we advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY 0 (or omit it), so it
      // was never allowed to. Our table is empty and the reference is
      // unresolvable, exactly like the out-of-range cases above.
      //
      // `break` (what this did before) is the worst possible answer: it drops
      // this field AND every field after it in the block, silently, and hands
      // the application a truncated header set that looks complete.
      throw new Error('QPACK: post-base field line 0x' + byte.toString(16) +
                      ' but our advertised table capacity is 0');
    }
  }

  return headers;
}

/**
 * Encode a header set as a QPACK header block.
 *
 * Static table only: RIC = 0 and delta-base = 0 in the prefix, so nothing here
 * references the dynamic table and no encoder-stream instructions are needed.
 * That costs some bytes and blocks nothing — a decoder never has to wait on an
 * insert that has not arrived (QPACK's whole head-of-line hazard).
 *
 * Literals are sent unencoded (useHuffman = false), which is what this encoder
 * has always done; the bytes on the wire are unchanged by the move to shared
 * primitives. Flipping the three `false` arguments below to `undefined` turns
 * on Huffman-when-it-helps and is a self-contained, separately testable change.
 */
function buildQpackHeaderBlock(headers) {
  var out = [0x00, 0x00]; // QPACK prefix: RIC=0, delta base=0

  function push(bytes) {
    for (var i = 0; i < bytes.length; i++) out.push(bytes[i]);
  }

  for (var name in headers) {
    var lname = name.toLowerCase();
    var value = String(headers[name]);

    // (1) Full match: name + value both in the static table → 1-byte indexed
    var idx = _qpackFullMatch[lname + '\0' + value];
    if (idx !== undefined) {
      // Indexed field line: 1 T NNNNNN, T=1 (static), 6-bit prefix
      var enc = encodePrefixedInt(idx, 6);
      enc[0] |= 0xc0;
      push(enc);
      continue;
    }

    // (2) Name match → literal with name reference
    var nameIdx = _qpackNameMatch[lname];
    if (nameIdx !== undefined) {
      // Literal with name reference: 01 N T PPPP, N=0, T=1 (static), 4-bit prefix
      var nameEnc = encodePrefixedInt(nameIdx, 4);
      nameEnc[0] |= 0x50;
      push(nameEnc);
      push(encodeStringLiteral(value, 7, false));
      continue;
    }

    // (3) Neither → literal with literal name: 001 N H PPP, 3-bit prefix
    var litName = encodeStringLiteral(lname, 3, false);
    litName[0] |= 0x20;
    push(litName);
    push(encodeStringLiteral(value, 7, false));
  }

  return new Uint8Array(out);
}


// ============================================================
//  H3 Frame build/parse
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

function extractH3Frames(chunks, fromOffset) {
  if (!chunks || chunks.length === 0) return { frames: [], new_from_offset: fromOffset };

  var buffers = [];
  var acc = 0;
  for (var i = 0; i < chunks.length; i++) {
    var nextAcc = acc + chunks[i].length;
    if (fromOffset < nextAcc) {
      buffers.push(chunks[i].slice(fromOffset - acc));
      for (var j = i + 1; j < chunks.length; j++) buffers.push(chunks[j]);
      break;
    }
    acc = nextAcc;
  }

  if (buffers.length === 0) return { frames: [], new_from_offset: fromOffset };

  var combined = concatUint8Arrays(buffers);
  var offset = 0, frames = [];

  while (offset < combined.length) {
    var start = offset;
    var ft = readVarInt(combined, offset);
    if (!ft) break;
    offset += ft.byteLength;
    var len = readVarInt(combined, offset);
    if (!len) { offset = start; break; }
    offset += len.byteLength;
    if (offset + len.value > combined.length) { offset = start; break; }
    frames.push({ frame_type: ft.value, payload: combined.slice(offset, offset + len.value) });
    offset += len.value;
  }

  return { frames: frames, new_from_offset: fromOffset + offset };
}


// ============================================================
//  H3 Settings
// ============================================================

var H3_SETTINGS_MAP = {
  SETTINGS_QPACK_MAX_TABLE_CAPACITY: 0x01,
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
  while (offset < buf.length) {
    var id = readVarInt(buf, offset); if (!id) break; offset += id.byteLength;
    var val = readVarInt(buf, offset); if (!val) break; offset += val.byteLength;
    var name = H3_ID_TO_NAME[id.value] || ('UNKNOWN_0x' + id.value.toString(16));
    out[name] = val.value;
  }
  return out;
}


// ============================================================
//  QPACK Encoder Instructions (from peer's encoder stream)
// ============================================================

function parseQpackEncoderInstructions(chunks, fromOffset) {
  if (!chunks || chunks.length === 0) return { instructions: [], new_from_offset: fromOffset };

  var buffers = [];
  var acc = 0;
  for (var i = 0; i < chunks.length; i++) {
    var nextAcc = acc + chunks[i].length;
    if (fromOffset < nextAcc) {
      buffers.push(chunks[i].slice(fromOffset - acc));
      for (var j = i + 1; j < chunks.length; j++) buffers.push(chunks[j]);
      break;
    }
    acc = nextAcc;
  }
  if (buffers.length === 0) return { instructions: [], new_from_offset: fromOffset };

  var combined = concatUint8Arrays(buffers);
  var pos = 0;
  var instructions = [];

  // Thin wrappers over the shared primitives that advance the local `pos` and
  // return the value (or null on truncation), preserving call-site usage.
  function safeVarInt(prefixBits) {
    var r = readPrefixedInt(combined, prefixBits, pos);
    if (!r) return null;
    pos = r.next;
    return r.value;
  }

  function safeLiteral(prefixBits) {
    var r = decodeStringLiteral(combined, prefixBits, pos, true);
    if (!r) return null;
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
      break;
    }
  }

  return { instructions: instructions, new_from_offset: fromOffset + pos };
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
//  Only the connection-error path is wired up below. The stream-error path
//  needs QUICConnection to be able to *send* RESET_STREAM, which it currently
//  cannot (transport.js builds the frame and quic_connection.js handles it on
//  receive, but nothing emits one) — and RESET_STREAM must survive loss, while
//  this stack has no generic control-frame retransmission: MAX_DATA recovers
//  via BLOCKED frames, CRYPTO has its own bespoke buffer, stream bytes are
//  reconciled. A fire-and-forget RESET_STREAM would silently strand the peer
//  on a stream it thinks is still open.
//
//  That work belongs in quic_connection.js next to sendStream(), and it does
//  NOT generalise to HTTP/2. QUIC owns streams, so H3 resets one by asking the
//  transport; the error code is an opaque varint QUIC never reads. HTTP/2 has
//  no such layer beneath it — its streams, its stream ids and its RST_STREAM
//  frame are all inventions of HTTP/2 itself, sitting on one TCP byte stream
//  that has nothing to reset. Same idea, different layer, no shared code.
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

  var context = {
    isServer: options.isServer !== false,

    // Local settings (what we advertise)
    local_max_header_size: 65536,
    local_qpack_max_table_capacity: 0,
    local_datagram_support: !!options.enableWebTransport,
    local_webtransport: !!options.enableWebTransport,

    // Remote settings (from peer's SETTINGS frame)
    remote_max_header_size: 0,
    remote_qpack_max_table_capacity: 0,
    remote_datagram_support: null,

    // QPACK dynamic table (peer's encoder inserts into this)
    remote_qpack_dynamic_table: [],
    remote_qpack_table_base_index: 0,
    remote_qpack_table_capacity: 0,

    // Stream tracking
    streams: {},  // stream_id → { chunks, from_offset, type }

    // Control stream state
    control_streams_sent: false,
    remote_settings_received: false,
  };


  // ---- set_context ----

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
    }

    if ('remote_datagram_support' in updates) {
      context.remote_datagram_support = !!updates.remote_datagram_support;
      changed.remote_datagram_support = true;
    }

    if ('remote_qpack_table_capacity' in updates) {
      context.remote_qpack_table_capacity = updates.remote_qpack_table_capacity;
      changed.remote_qpack_table_capacity = true;
    }

    if ('remote_settings_received' in updates && !context.remote_settings_received) {
      context.remote_settings_received = true;
      changed.remote_settings_received = true;
    }

    if ('add_qpack_entries' in updates) {
      var entries = updates.add_qpack_entries;
      for (var i = 0; i < entries.length; i++) {
        context.remote_qpack_dynamic_table.unshift(entries[i]);
        context.remote_qpack_table_base_index++;
      }
      changed.qpack_table = true;
    }

    // ---- Reactive ----

    if (changed.remote_qpack_table_capacity) {
      evictQpackTable();
    }

    if (changed.remote_settings_received) {
      // Could trigger QPACK table capacity update etc.
    }
  }


  function evictQpackTable() {
    var entries = context.remote_qpack_dynamic_table;
    var capacity = context.remote_qpack_table_capacity;
    var totalSize = 0;
    for (var i = 0; i < entries.length; i++) {
      totalSize += entries[i][0].length + entries[i][1].length + 32;
    }
    while (totalSize > capacity && entries.length > 0) {
      var removed = entries.pop();
      totalSize -= removed[0].length + removed[1].length + 32;
    }
  }


  // ---- Send initial control + QPACK streams ----

  function sendControlStreams() {
    if (context.control_streams_sent) return;
    context.control_streams_sent = true;

    var settingsObj = {
      SETTINGS_MAX_FIELD_SECTION_SIZE: context.local_max_header_size
    };
    if (context.local_qpack_max_table_capacity > 0) {
      settingsObj.SETTINGS_QPACK_MAX_TABLE_CAPACITY = context.local_qpack_max_table_capacity;
    }
    if (context.local_datagram_support) {
      settingsObj.SETTINGS_H3_DATAGRAM = 1;
      settingsObj.SETTINGS_ENABLE_CONNECT_PROTOCOL = 1;
    }
    if (context.local_webtransport) {
      settingsObj.SETTINGS_ENABLE_WEBTRANSPORT = 1;
    }
    var settings = buildSettingsPayload(settingsObj);

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
    quic.sendStream(ctrlId, ctrlData, false);
    quic.sendStream(encId, new Uint8Array([0x02]), false);    // QPACK encoder
    quic.sendStream(decId, new Uint8Array([0x03]), false);    // QPACK decoder
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

  quic.on('stream', function (streamId, data, fin) {
    if (_fatal) return;   // connection is closing; decoding further is pointless
    var sid = Number(streamId);

    // Route data for already-detected WT streams
    if (sid in _wtStreams) {
      var ws = _wtStreams[sid];
      ev.emit('wt_data', ws.sessionId, sid, data, fin);
      if (fin) delete _wtStreams[sid];
      return;
    }

    if (_claimedStreams.has(sid)) return; // owned by WebTransport client
    if (DEBUG) console.log('[h3] stream ' + streamId + ' data=' + data.byteLength + ' fin=' + fin);
    if (!(streamId in context.streams)) {
      context.streams[streamId] = { chunks: [], from_offset: 0, type: null, fin_received: false };
    }

    var s = context.streams[streamId];
    s.chunks.push(data);
    if (fin) s.fin_received = true;

    // Identify stream type
    if (s.type === null) {
      var isUni = (Number(streamId) & 0x2) !== 0;

      // ---- WT stream detection ----
      if (context.local_webtransport && _wtSessions.size > 0) {
        var allData = concatUint8Arrays(s.chunks);
        if (DEBUG) console.log('[h3] WT check: stream=' + sid + ' firstByte=0x' + (allData[0] || 0).toString(16) + ' len=' + allData.byteLength + ' sessions=' + Array.from(_wtSessions));
        if (allData.byteLength >= 2 && allData[0] === 0x40) {
          var typeResult = readVarInt(allData, 0);
          if (typeResult) {
            var expectedType = isUni ? 0x54 : 0x41;
            if (typeResult.value === expectedType) {
              var afterType = allData.slice(typeResult.byteLength);
              var sidResult = readVarInt(afterType, 0);
              if (sidResult && _wtSessions.has(sidResult.value)) {
                // WT stream detected
                var sessionId = sidResult.value;
                var prefixLen = typeResult.byteLength + sidResult.byteLength;
                var remaining = allData.byteLength > prefixLen ? allData.slice(prefixLen) : new Uint8Array(0);

                _claimedStreams.add(sid);
                _wtStreams[sid] = { sessionId: sessionId, isBidi: !isUni };
                delete context.streams[streamId];

                if (DEBUG) console.log('[h3] WT stream detected: stream=' + sid + ' session=' + sessionId + ' bidi=' + !isUni + ' dataLen=' + remaining.byteLength);
                ev.emit('wt_stream', sessionId, sid, remaining, fin, !isUni);
                if (fin) delete _wtStreams[sid];
                return;
              }
            }
          }
        }
      }

      if (isUni) {
        if (s.chunks[0].length > 0) {
          var first = s.chunks[0][0];
          if (first === 0x00)      { s.type = 'control';    s.from_offset = 1; }
          else if (first === 0x02) { s.type = 'qpack_enc';  s.from_offset = 1; }
          else if (first === 0x03) { s.type = 'qpack_dec';  s.from_offset = 1; }
          else                     { s.type = 'unknown'; }
        }
      } else {
        s.type = 'bidi';
      }
    }

    // Process by type.
    //
    // Each processor decodes attacker-controlled bytes, so each can throw:
    // a bad prefixed integer, an invalid Huffman code, a truncated literal.
    // The catch turns that into the connection error RFC 9114 requires,
    // instead of letting it unwind into Emitter's swallow.
    try {
      if (s.type === 'control') {
        processControlStream(s);

      } else if (s.type === 'qpack_enc') {
        processQpackEncoderStream(s);

      } else if (s.type === 'bidi') {
        processBidiStream(streamId, s);
      }
    } catch (err) {
      // A code already chosen at the throw site (see decodeHeaders below) wins;
      // anything else is a framing failure on whichever stream we were reading.
      connectionError(err.h3ErrorCode || H3_ERR.H3_FRAME_ERROR,
                      err.message || 'stream processing failed');
    }
  });


  quic.on('connect', function () {
    sendControlStreams();
  });

  // If QUIC already connected (client creates H3 after connect), send now
  if (quic.state === 'connected') {
    sendControlStreams();
  }


  // ---- Stream processors ----

  function processControlStream(s) {
    var ext = extractH3Frames(s.chunks, s.from_offset);
    if (DEBUG) console.log('[h3] control: extracted ' + ext.frames.length + ' H3 frames');
    if (ext.frames.length === 0) return;
    s.from_offset = ext.new_from_offset;

    for (var i = 0; i < ext.frames.length; i++) {
      if (ext.frames[i].frame_type === 0x04) {
        var settings = parseSettingsPayload(ext.frames[i].payload);
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

      } else if (ext.frames[i].frame_type === 0x07) {
        // GOAWAY (RFC 9114 §5.2): the peer will not process requests/pushes
        // with an identifier >= this value. Surface it so consumers (e.g. the
        // agent) can stop sending new requests on this connection.
        var gp = readVarInt(ext.frames[i].payload, 0);
        if (DEBUG) console.log('[h3] ← GOAWAY id=' + (gp ? gp.value : '?'));
        ev.emit('goaway', gp ? gp.value : 0);
      }
    }
  }

  function processQpackEncoderStream(s) {
    var ext;
    try {
      ext = parseQpackEncoderInstructions(s.chunks, s.from_offset);
    } catch (err) {
      // RFC 9204 §4.2: a malformed encoder stream is QPACK_ENCODER_STREAM_ERROR,
      // not a decompression failure — nothing was being decompressed yet.
      err.h3ErrorCode = H3_ERR.QPACK_ENCODER_STREAM_ERROR;
      throw err;
    }
    if (ext.instructions.length === 0) return;
    s.from_offset = ext.new_from_offset;

    var inserts = [];
    for (var i = 0; i < ext.instructions.length; i++) {
      var inst = ext.instructions[i];
      if (inst.type === 'set_capacity') {
        set_context({ remote_qpack_table_capacity: inst.capacity });

      } else if (inst.type === 'insert_name_ref') {
        var name = null;
        if (inst.from_static && inst.name_index < QPACK_STATIC.length) {
          name = QPACK_STATIC[inst.name_index][0];
        } else if (!inst.from_static) {
          var di = context.remote_qpack_table_base_index - 1 - inst.name_index;
          if (di >= 0 && di < context.remote_qpack_dynamic_table.length) {
            name = context.remote_qpack_dynamic_table[di][0];
          }
        }
        if (name) inserts.push([name, inst.value]);

      } else if (inst.type === 'insert_literal') {
        inserts.push([inst.name, inst.value]);
      }
    }

    if (inserts.length > 0) {
      set_context({ add_qpack_entries: inserts });
    }
  }

  /**
   * Decode a QPACK header block, re-tagging any failure as
   * QPACK_DECOMPRESSION_FAILED (RFC 9204 §2.2.3) rather than the generic
   * framing error. The distinction matters to whoever reads the peer's logs:
   * a decompression failure says the two dynamic tables have diverged, which
   * is a different bug from a malformed frame.
   */
  function decodeHeaders(payload) {
    try {
      return parseQpackHeaderBlock(
        payload,
        context.remote_qpack_dynamic_table,
        context.remote_qpack_table_base_index
      );
    } catch (err) {
      err.h3ErrorCode = H3_ERR.QPACK_DECOMPRESSION_FAILED;
      throw err;
    }
  }

  function processBidiStream(streamId, s) {
    var ext = extractH3Frames(s.chunks, s.from_offset);
    if (DEBUG) console.log('[h3] bidi stream ' + streamId + ': extracted ' + ext.frames.length + ' H3 frames, types=' + ext.frames.map(function(f){ return '0x' + f.frame_type.toString(16); }).join(','));

    if (ext.frames.length > 0) {
      s.from_offset = ext.new_from_offset;

      for (var i = 0; i < ext.frames.length; i++) {
        if (ext.frames[i].frame_type === 1) {
          // HEADERS
          var headers = decodeHeaders(ext.frames[i].payload);
          ev.emit('http_headers', Number(streamId), headers);

        } else if (ext.frames[i].frame_type === 0) {
          // DATA
          ev.emit('http_body', Number(streamId), ext.frames[i].payload);
        }
      }
    }

    // FIN received → stream complete (emitted only once)
    if (s.fin_received && !s.http_end_emitted) {
      s.http_end_emitted = true;
      ev.emit('http_end', Number(streamId));
    }
  }


  // ---- Send methods ----

  function sendHeaders(streamId, headers, fin) {
    var payload = buildQpackHeaderBlock(headers);
    var frame = buildH3Frames([{ frame_type: 1, payload: payload }]);
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
    var frame = buildH3Frames([{ frame_type: 0, payload: data }]);
    quic.sendStream(streamId, frame, !!fin);
  }


  // ---- Public API ----

  var api = {
    context: context,

    on: function (name, fn) { ev.on(name, fn); },
    set_context: set_context,

    sendHeaders: sendHeaders,
    sendBody: sendBody,
    sendControlStreams: sendControlStreams,
    sendGoaway: sendGoaway,
    claimStream: function (streamId) { _claimedStreams.add(Number(streamId)); },

    // WebTransport server-side API
    registerWebTransportSession: function (sessionStreamId) {
      _wtSessions.add(Number(sessionStreamId));
    },

    createWebTransportStream: function (sessionId, isBidi) {
      // Allocate next stream ID (server-initiated)
      // Server bidi: 1, 5, 9, 13... (type 0x1)
      // Server uni: 3, 7, 11, 15... (type 0x3) — but 3,7,11 used by H3
      var streamId;
      if (isBidi) {
        if (!context._nextServerBidiId) context._nextServerBidiId = 1;
        streamId = context._nextServerBidiId;
        context._nextServerBidiId += 4;
      } else {
        if (!context._nextServerUniId) context._nextServerUniId = 15;
        streamId = context._nextServerUniId;
        context._nextServerUniId += 4;
      }

      // Send WT prefix: VarInt(type) + VarInt(session_id)
      quic.sendStream(streamId, wt_stream_header(isBidi, sessionId), false);

      _claimedStreams.add(streamId);
      _wtStreams[streamId] = { sessionId: sessionId, isBidi: isBidi };

      return streamId;
    }
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }
  return this;
}


export { H3Connection, H3_ERR, H3_ERR_NAME };
