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


// ============================================================
//  Debug flag — set QUICO_DEBUG=1 to enable verbose logging.
//  Read once at module load. Call sites guard with `if (DEBUG)`
//  so the (expensive) log-string construction is skipped entirely
//  when debugging is off.
// ============================================================

var DEBUG = !!(typeof process !== 'undefined' && process.env && process.env.QUICO_DEBUG);


// ============================================================
//  Emitter — lightweight event emitter (single shared copy)
// ============================================================

function Emitter() {
  var listeners = {};
  return {
    on: function (name, fn) {
      (listeners[name] = listeners[name] || []).push(fn);
    },
    off: function (name, fn) {
      var arr = listeners[name];
      if (arr) {
        var idx = arr.indexOf(fn);
        if (idx !== -1) arr.splice(idx, 1);
      }
    },
    emit: function (name) {
      var args = Array.prototype.slice.call(arguments, 1);
      var arr = listeners[name] || [];
      for (var i = 0; i < arr.length; i++) {
        try { arr[i].apply(null, args); } catch (e) { /* swallow */ }
      }
    }
  };
}


// ============================================================
//  QUIC Variable-Length Integer (RFC 9000 §16)
// ============================================================

function writeVarInt(value) {
  if (value < 0x40) {
    return new Uint8Array([value]);
  }
  if (value < 0x4000) {
    return new Uint8Array([
      0x40 | (value >> 8),
      value & 0xff
    ]);
  }
  if (value < 0x40000000) {
    return new Uint8Array([
      0x80 | (value >> 24),
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff
    ]);
  }
  if (value <= Number.MAX_SAFE_INTEGER) {
    var hi = Math.floor(value / 2 ** 32);
    var lo = value >>> 0;
    return new Uint8Array([
      0xc0 | (hi >> 24),
      (hi >> 16) & 0xff,
      (hi >> 8) & 0xff,
      hi & 0xff,
      (lo >> 24) & 0xff,
      (lo >> 16) & 0xff,
      (lo >> 8) & 0xff,
      lo & 0xff
    ]);
  }
  throw new Error('Value too large for QUIC VarInt');
}


function readVarInt(array, offset) {
  if (offset >= array.length) return null;

  var first = array[offset];
  var prefix = first >> 6;

  if (prefix === 0) {
    return { value: first & 0x3f, byteLength: 1 };
  }
  if (prefix === 1) {
    if (offset + 1 >= array.length) return null;
    return {
      value: ((first & 0x3f) << 8) | array[offset + 1],
      byteLength: 2
    };
  }
  if (prefix === 2) {
    if (offset + 3 >= array.length) return null;
    return {
      value: (
        ((first & 0x3f) << 24) |
        (array[offset + 1] << 16) |
        (array[offset + 2] << 8) |
        array[offset + 3]
      ) >>> 0,
      byteLength: 4
    };
  }
  if (prefix === 3) {
    if (offset + 7 >= array.length) return null;
    var hi = (
      ((first & 0x3f) << 24) |
      (array[offset + 1] << 16) |
      (array[offset + 2] << 8) |
      array[offset + 3]
    ) >>> 0;
    var lo = (
      (array[offset + 4] << 24) |
      (array[offset + 5] << 16) |
      (array[offset + 6] << 8) |
      array[offset + 7]
    ) >>> 0;
    var full = BigInt(hi) * 4294967296n + BigInt(lo);
    // Always return a Number. QUIC fields (lengths, offsets, IDs, limits) never
    // legitimately exceed 2^53, and a malicious 8-byte value that does will be
    // rejected by the parsers' bounds checks anyway. Returning a BigInt here
    // would throw "Cannot mix BigInt and other types" the moment the value is
    // combined with a Number offset during parsing.
    return { value: Number(full), byteLength: 8 };
  }

  return null;
}


// ============================================================
//  Binary helpers
// ============================================================

function concatUint8Arrays(arrays) {
  var totalLength = 0;
  for (var i = 0; i < arrays.length; i++) {
    totalLength += arrays[i].length;
  }
  var result = new Uint8Array(totalLength);
  var offset = 0;
  for (var i = 0; i < arrays.length; i++) {
    result.set(arrays[i], offset);
    offset += arrays[i].length;
  }
  return result;
}


function uint8Equal(a, b) {
  if (a === b) return true;
  if (!a || !b) return false;
  if (a.byteLength !== b.byteLength) return false;
  for (var i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}


// ============================================================
//  WebTransport framing helpers (draft-ietf-webtrans-http3 / RFC 9297)
//
//  Both client (webtransport.js) and server (h3.js) build the same
//  byte layouts, so they live here to avoid duplicating the prefix
//  construction across the stream and datagram send paths.
// ============================================================

/**
 * Build a WebTransport stream header: VarInt(streamType) + VarInt(sessionId) [+ data].
 * streamType is 0x41 for a bidirectional WT stream, 0x54 for a unidirectional one.
 * The header prefixes the FIRST chunk on a WT stream (or a lone FIN frame); pass
 * `data` for "header + payload", omit it for a header-only (e.g. FIN) frame.
 */
function wt_stream_header(isBidi, sessionId, data) {
  var typePrefix = writeVarInt(isBidi ? 0x41 : 0x54);
  var sessionPrefix = writeVarInt(sessionId);
  var dataLen = (data && data.byteLength) ? data.byteLength : 0;
  var out = new Uint8Array(typePrefix.length + sessionPrefix.length + dataLen);
  out.set(typePrefix, 0);
  out.set(sessionPrefix, typePrefix.length);
  if (dataLen) out.set(data, typePrefix.length + sessionPrefix.length);
  return out;
}

/**
 * Build a WebTransport datagram payload: VarInt(quarter_stream_id) + data.
 * The quarter-stream-id is the session's CONNECT stream id divided by 4
 * (RFC 9297 §2.1). Pass the session stream id; the division is done here.
 */
function wt_datagram_payload(sessionStreamId, data) {
  var prefix = writeVarInt(Math.floor(sessionStreamId / 4));
  var dataLen = (data && data.byteLength) ? data.byteLength : 0;
  var out = new Uint8Array(prefix.length + dataLen);
  out.set(prefix, 0);
  if (dataLen) out.set(data, prefix.length);
  return out;
}


// ============================================================
//  ACK range helpers (flat [from,to, from,to, ...] format)
// ============================================================

function ack_frame_to_ranges(ackFrame) {
  var flat = [];
  if (!ackFrame || ackFrame.type !== 'ack') return flat;

  var largest = Number(ackFrame.largest);
  var firstRange = Number(ackFrame.firstRange);
  if (!isFinite(largest) || !isFinite(firstRange)) return flat;

  var rangesDesc = [];

  // First range
  var rangeEnd = largest;
  var rangeStart = rangeEnd - firstRange;
  if (rangeStart <= rangeEnd) {
    rangesDesc.push([rangeStart, rangeEnd]);
  }

  // Additional ranges
  var more = ackFrame.ranges || [];
  var prevStart = rangeStart;
  for (var i = 0; i < more.length; i++) {
    var gap = Number(more[i].gap);
    var length = Number(more[i].length);
    if (!isFinite(gap) || !isFinite(length)) continue;

    rangeEnd = prevStart - gap - 2;
    rangeStart = rangeEnd - length;
    if (rangeStart <= rangeEnd) {
      rangesDesc.push([rangeStart, rangeEnd]);
      prevStart = rangeStart;
    }
  }

  // Sort ascending, merge, and flatten
  rangesDesc.sort(function (a, b) { return a[0] - b[0]; });

  var merged = [];
  for (var j = 0; j < rangesDesc.length; j++) {
    var s = rangesDesc[j][0], e = rangesDesc[j][1];
    if (merged.length === 0) {
      merged.push([s, e]);
    } else {
      var last = merged[merged.length - 1];
      if (s <= last[1] + 1) {
        if (e > last[1]) last[1] = e;
      } else {
        merged.push([s, e]);
      }
    }
  }

  for (var k = 0; k < merged.length; k++) {
    flat.push(merged[k][0], merged[k][1]);
  }
  return flat;
}


function ranges_to_ack_frame(flatRanges, ecnStats, ackDelay) {
  if (!flatRanges || flatRanges.length === 0) return null;
  if (flatRanges.length % 2 !== 0) throw new Error('flatRanges must be [from,to,...] pairs');

  // flat_ranges uses exclusive end: [from, to) → convert to inclusive [start, end]
  var ranges = [];
  for (var i = 0; i < flatRanges.length; i += 2) {
    if (flatRanges[i + 1] > flatRanges[i]) {
      ranges.push({ start: flatRanges[i], end: flatRanges[i + 1] - 1 });
    }
  }

  if (ranges.length === 0) return null;

  ranges.sort(function (a, b) { return b.end - a.end; });

  // Merge overlapping/adjacent
  var merged = [ranges[0]];
  for (var i = 1; i < ranges.length; i++) {
    var last = merged[merged.length - 1];
    var curr = ranges[i];
    if (curr.end >= last.start - 1) {
      last.start = Math.min(last.start, curr.start);
    } else {
      merged.push(curr);
    }
  }

  var largest = merged[0].end;
  var firstRange = largest - merged[0].start;
  var ackRanges = [];

  for (var i = 1; i < merged.length; i++) {
    var gap = merged[i - 1].start - merged[i].end - 2;
    var length = merged[i].end - merged[i].start;
    ackRanges.push({ gap: gap, length: length });
  }

  return {
    type: 'ack',
    largest: largest,
    delay: ackDelay || 0,
    firstRange: firstRange,
    ranges: ackRanges,
    ecn: ecnStats ? {
      ect0: ecnStats.ect0 || 0,
      ect1: ecnStats.ect1 || 0,
      ce: ecnStats.ce || 0
    } : null
  };
}


export {
  DEBUG,
  Emitter,
  writeVarInt,
  readVarInt,
  concatUint8Arrays,
  uint8Equal,
  wt_stream_header,
  wt_datagram_payload,
  ack_frame_to_ranges,
  ranges_to_ack_frame
};
