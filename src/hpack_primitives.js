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
//  Field-compression primitives shared by HPACK and QPACK.
//
//  QPACK (RFC 9204, HTTP/3) is a reworking of HPACK (RFC 7541, HTTP/2) for
//  out-of-order delivery. The two differ in how the dynamic table is indexed
//  and updated — but the *wire primitives* underneath are the same document:
//
//    - Huffman code            RFC 7541 Appendix B   (QPACK cites it verbatim)
//    - Prefixed integers       RFC 7541 §5.1         (QPACK §4.1.1: identical)
//    - String literals         RFC 7541 §5.2         (QPACK §4.1.2: identical)
//
//  Only the static tables differ (RFC 7541 Appendix A vs RFC 9204 Appendix A),
//  and even those are built and searched the same way — hence the shared
//  buildStaticLookup() below.
//
//  The file is named for HPACK because HPACK is where these primitives are
//  *defined*; QPACK imports them by reference. Nothing here is HTTP/2-specific.
// ============================================================


// ============================================================
//  Huffman (RFC 7541 Appendix B)
//
//  257 entries: symbols 0..255 plus EOS at 256. EOS never appears in a
//  well-formed encoding — it exists only as the source of the padding bit
//  pattern (its code is all-ones), so decoding it is a protocol error.
// ============================================================

var HUFF_CODES = new Uint32Array([
  0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,
  0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,
  0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,
  0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,
  0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,0x3fa,0x3fb,0xf9,0x7fb,0xfa,
  0x16,0x17,0x18,0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x5c,0xfb,
  0x7ffc,0x20,0xffb,0x3fc,0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,
  0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0xfc,
  0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,
  0x26,0x27,0x6,0x74,0x75,0x28,0x29,0x2a,0x7,0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,
  0x78,0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,0xffffffc,0xfffe6,0x3fffd2,
  0xfffe7,0xfffe8,0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,0x3fffd6,0x7fffda,0x7fffdb,
  0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,0xffffec,0xffffed,0x3fffd7,0x7fffe0,
  0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,
  0x7fffe6,0x7fffe7,0xffffef,0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,
  0x7fffe9,0x1fffde,0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,
  0x7fffec,0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,0x3fffe1,0x7fffee,0x7fffef,
  0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,0x3ffffe0,
  0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,0x3ffffe2,0x3ffffe3,
  0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,0x7fff2,0x1fffe3,
  0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,0xfffff2,0x1fffe4,0x1fffe5,
  0x3ffffe8,0x3ffffe9,0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,0xfffec,0xfffff3,
  0xfffed,0x1fffe6,0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,0x3fffea,0x3fffeb,0x1ffffee,
  0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,0x3ffffeb,0x7ffffe6,0x3ffffec,
  0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,0x7ffffeb,0xffffffe,0x7ffffec,
  0x7ffffed,0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee,0x3fffffff
]);

var HUFF_BITS = new Uint8Array([
  13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,28,
  28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,
  6,6,6,7,8,15,6,12,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,
  8,13,19,13,14,6,15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,
  11,14,13,28,20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,24,24,22,23,24,
  23,23,23,23,21,22,23,22,23,23,24,22,21,20,22,22,23,23,21,23,22,22,24,21,22,
  23,23,21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,26,26,20,19,22,23,22,
  25,26,26,26,27,27,26,24,25,19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,
  20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,26,27,26,26,27,27,27,27,27,
  28,27,27,27,27,27,26,30
]);

var HUFF_EOS = 256;   // index of the EOS symbol; decoding it is an error

var _huffRoot = (function () {
  var root = {};
  for (var i = 0; i < HUFF_CODES.length; i++) {
    var code = HUFF_CODES[i], bits = HUFF_BITS[i], node = root;
    for (var j = bits - 1; j >= 0; j--) {
      var bit = (code >> j) & 1;
      if (!node[bit]) node[bit] = {};
      node = node[bit];
    }
    node.sym = i;
  }
  return root;
})();


/**
 * Decode a Huffman-coded byte string (RFC 7541 §5.2). Returns the raw
 * Uint8Array, NOT a string.
 *
 * Field names and values are opaque octets on the wire, and the two callers
 * disagree about how to turn them into text — so that decision stays with
 * them. (QPACK in this codebase has always used TextDecoder/UTF-8; a stricter
 * HPACK may prefer a lossless latin-1 mapping. Baking either one in here would
 * silently change the other.)
 *
 * `strict` turns on the three padding checks the RFC mandates (§5.2): padding
 * longer than 7 bits, padding that is not the EOS prefix (all ones), and an
 * actual EOS symbol in the stream must all be treated as errors. They are off
 * by default so that existing callers keep their current lenient behaviour;
 * decoders that must answer a malformed peer with COMPRESSION_ERROR pass true.
 */
function huffDecode(buf, strict) {
  var out = [];
  var node = _huffRoot;
  var nbits = 0, current = 0;
  var sincePadStart = 0;   // bits consumed since the last complete symbol
  var padIsOnes = true;    // were all of those bits 1?

  for (var i = 0; i < buf.length; i++) {
    current = (current << 8) | buf[i];
    nbits += 8;
    while (nbits > 0) {
      var bit = (current >> (nbits - 1)) & 1;
      node = node[bit];
      if (!node) throw new Error('Invalid Huffman code');
      nbits--;
      sincePadStart++;
      if (bit === 0) padIsOnes = false;
      if (node.sym !== undefined) {
        if (strict && node.sym === HUFF_EOS) {
          throw new Error('Huffman: EOS symbol in input');
        }
        out.push(node.sym);
        node = _huffRoot;
        sincePadStart = 0;
        padIsOnes = true;
      }
    }
  }

  if (strict && node !== _huffRoot) {
    // Trailing bits that did not complete a symbol are padding. They must be
    // at most 7 bits and must be the most-significant bits of the EOS code.
    if (sincePadStart > 7) throw new Error('Huffman: padding longer than 7 bits');
    if (!padIsOnes) throw new Error('Huffman: padding is not the EOS prefix');
  }

  return Uint8Array.from(out);
}


/** Byte length huffEncode() would produce, without producing it. */
function huffEncodedLength(bytes) {
  var bits = 0;
  for (var i = 0; i < bytes.length; i++) bits += HUFF_BITS[bytes[i]];
  return (bits + 7) >> 3;
}


// Powers of two as floats, used wherever a shift would exceed 32 bits.
// huffEncode accumulates up to 7 leftover bits plus one 30-bit code = 37 bits;
// readPrefixedInt walks a continuation chain whose shift reaches 7 bits per
// byte, so the table has to cover the full continuation limit below (an
// undersized table silently yields undefined → NaN, which readPrefixedInt then
// reports as "too large").
var _POW2 = (function () {
  var p = new Float64Array(80);
  for (var i = 0; i < 80; i++) p[i] = Math.pow(2, i);
  return p;
})();


/**
 * Huffman-encode a byte array (RFC 7541 §5.2). Pads the final byte with the
 * most-significant bits of the EOS code, i.e. ones.
 */
function huffEncode(bytes) {
  var out = new Uint8Array(huffEncodedLength(bytes));
  var pos = 0;
  var cur = 0, nbits = 0;

  for (var i = 0; i < bytes.length; i++) {
    var sym = bytes[i];
    cur = cur * _POW2[HUFF_BITS[sym]] + HUFF_CODES[sym];
    nbits += HUFF_BITS[sym];
    while (nbits >= 8) {
      var shift = _POW2[nbits - 8];
      out[pos++] = Math.floor(cur / shift) & 0xff;
      cur = cur % shift;
      nbits -= 8;
    }
  }

  if (nbits > 0) {
    var pad = 8 - nbits;
    out[pos++] = ((cur * _POW2[pad]) + (_POW2[pad] - 1)) & 0xff;
  }

  return out;
}


// ============================================================
//  Prefixed integers (RFC 7541 §5.1, QPACK §4.1.1)
// ============================================================

// A malicious peer can send an unbounded run of continuation bytes to make the
// decoder spin. RFC 7541 §5.1 notes that implementations must limit the value
// they will decode; ten continuation bytes already exceed 2^53, so anything
// longer is either an attack or a value we could not represent anyway.
var _MAX_CONTINUATION_BYTES = 10;

/**
 * Read a prefixed integer at buf[pos].
 * Returns { value, next } or null if the buffer ends mid-integer (truncated).
 *
 * Used by the QPACK header-block parser, the QPACK encoder-instruction parser,
 * and the HPACK header-block parser — the encoding is byte-identical in all
 * three.
 */
function readPrefixedInt(buf, prefixBits, pos) {
  if (pos >= buf.length) return null;
  var max = (1 << prefixBits) - 1;
  var value = buf[pos] & max;
  pos++;
  if (value < max) return { value: value, next: pos };

  var m = 0;
  var seen = 0;
  while (pos < buf.length) {
    var byte = buf[pos++];
    // Multiplication rather than `<< m`: m reaches 28+ on large values, where
    // the 32-bit shift wraps and silently produces a wrong (often negative)
    // integer.
    value += (byte & 0x7f) * _POW2[m];
    if ((byte & 0x80) === 0) {
      if (!isFinite(value) || value > Number.MAX_SAFE_INTEGER) {
        throw new Error('Prefixed integer too large');
      }
      return { value: value, next: pos };
    }
    m += 7;
    if (++seen > _MAX_CONTINUATION_BYTES) {
      throw new Error('Prefixed integer too long');
    }
  }
  return null; // truncated mid-integer
}


/**
 * Encode a prefixed integer (RFC 7541 §5.1). Returns a plain Array of bytes;
 * the caller ORs its opcode bits into byte 0, which is why the high bits above
 * the prefix are left clear here.
 */
function encodePrefixedInt(value, prefixBits) {
  var max = (1 << prefixBits) - 1;
  if (value < max) return [value];
  var bytes = [max];
  value -= max;
  while (value >= 128) {
    bytes.push((value % 128) | 0x80);
    value = Math.floor(value / 128);
  }
  bytes.push(value);
  return bytes;
}


// ============================================================
//  String literals (RFC 7541 §5.2, QPACK §4.1.2)
//
//  Layout: one bit H (Huffman?), then a (prefixBits)-wide prefixed integer
//  holding the byte length, then that many bytes. H sits immediately above the
//  length prefix, so its mask is 1 << prefixBits — 0x80 for the usual 7-bit
//  prefix, 0x08 for the 3-bit prefix QPACK uses for literal names.
// ============================================================

/**
 * Decode a string literal at buf[pos].
 * Returns { bytes, huffman, next }, or null if the literal is truncated.
 *
 * `bytes` is a Uint8Array for the same reason huffDecode returns one: the text
 * codec is the caller's decision.
 */
function decodeStringLiteral(buf, prefixBits, pos, strict) {
  if (pos >= buf.length) return null;
  var huffman = (buf[pos] & (1 << prefixBits)) !== 0;
  var len = readPrefixedInt(buf, prefixBits, pos);
  if (!len) return null;
  pos = len.next;
  if (pos + len.value > buf.length) return null;   // truncated payload
  var raw = buf.subarray(pos, pos + len.value);
  pos += len.value;
  return {
    bytes: huffman ? huffDecode(raw, strict) : raw,
    huffman: huffman,
    next: pos
  };
}


/**
 * Encode a string literal. Returns a plain Array of bytes whose byte 0 already
 * carries the H bit; the caller ORs in the opcode bits above it.
 *
 * `input` may be a Uint8Array (used as-is) or a string (UTF-8 encoded).
 *
 * useHuffman:
 *   undefined  — Huffman only when it actually shrinks the string. This is what
 *                browsers and nghttp2 do: Huffman can *grow* a run of unusual
 *                bytes, and an encoder is free to send either form.
 *   true/false — force. `false` is what QPACK here has always done; leaving it
 *                that way keeps the bytes on the wire unchanged.
 */
function encodeStringLiteral(input, prefixBits, useHuffman) {
  var raw = (typeof input === 'string') ? _utf8(input) : input;
  var body = raw;
  var huffman = false;

  if (useHuffman !== false) {
    var encoded = huffEncode(raw);
    if (useHuffman === true || encoded.length < raw.length) {
      body = encoded;
      huffman = true;
    }
  }

  var out = encodePrefixedInt(body.length, prefixBits);
  if (huffman) out[0] |= (1 << prefixBits);
  for (var i = 0; i < body.length; i++) out.push(body[i]);
  return out;
}


// ============================================================
//  Static tables
// ============================================================

/**
 * HPACK static table — RFC 7541 Appendix A. 61 entries, indexed from 1.
 * Stored 0-based here; buildStaticLookup(HPACK_STATIC, 1) yields wire indices.
 */
var HPACK_STATIC = [
  [':authority',''], [':method','GET'], [':method','POST'], [':path','/'],
  [':path','/index.html'], [':scheme','http'], [':scheme','https'],
  [':status','200'], [':status','204'], [':status','206'], [':status','304'],
  [':status','400'], [':status','404'], [':status','500'],
  ['accept-charset',''], ['accept-encoding','gzip, deflate'],
  ['accept-language',''], ['accept-ranges',''], ['accept',''],
  ['access-control-allow-origin',''], ['age',''], ['allow',''],
  ['authorization',''], ['cache-control',''], ['content-disposition',''],
  ['content-encoding',''], ['content-language',''], ['content-length',''],
  ['content-location',''], ['content-range',''], ['content-type',''],
  ['cookie',''], ['date',''], ['etag',''], ['expect',''], ['expires',''],
  ['from',''], ['host',''], ['if-match',''], ['if-modified-since',''],
  ['if-none-match',''], ['if-range',''], ['if-unmodified-since',''],
  ['last-modified',''], ['link',''], ['location',''], ['max-forwards',''],
  ['proxy-authenticate',''], ['proxy-authorization',''], ['range',''],
  ['referer',''], ['refresh',''], ['retry-after',''], ['server',''],
  ['set-cookie',''], ['strict-transport-security',''],
  ['transfer-encoding',''], ['user-agent',''], ['vary',''], ['via',''],
  ['www-authenticate','']
];

/**
 * QPACK static table — RFC 9204 Appendix A. 99 entries, indexed from 0.
 * Unrelated to the HPACK table above: different membership, different order.
 */
var QPACK_STATIC = [
  [':authority',''], [':path','/'], ['age','0'], ['content-disposition',''],
  ['content-length','0'], ['cookie',''], ['date',''], ['etag',''],
  ['if-modified-since',''], ['if-none-match',''], ['last-modified',''],
  ['link',''], ['location',''], ['referer',''], ['set-cookie',''],
  [':method','CONNECT'], [':method','DELETE'], [':method','GET'],
  [':method','HEAD'], [':method','OPTIONS'], [':method','POST'],
  [':method','PUT'], [':scheme','http'], [':scheme','https'],
  [':status','103'], [':status','200'], [':status','304'],
  [':status','404'], [':status','503'], ['accept','*/*'],
  ['accept','application/dns-message'], ['accept-encoding','gzip, deflate, br'],
  ['accept-ranges','bytes'], ['access-control-allow-headers','cache-control'],
  ['access-control-allow-headers','content-type'],
  ['access-control-allow-origin','*'], ['cache-control','max-age=0'],
  ['cache-control','max-age=2592000'], ['cache-control','max-age=604800'],
  ['cache-control','no-cache'], ['cache-control','no-store'],
  ['cache-control','public, max-age=31536000'], ['content-encoding','br'],
  ['content-encoding','gzip'], ['content-type','application/dns-message'],
  ['content-type','application/javascript'], ['content-type','application/json'],
  ['content-type','application/x-www-form-urlencoded'],
  ['content-type','image/gif'], ['content-type','image/jpeg'],
  ['content-type','image/png'], ['content-type','text/css'],
  ['content-type','text/html; charset=utf-8'], ['content-type','text/plain'],
  ['content-type','text/plain;charset=utf-8'], ['range','bytes=0-'],
  ['strict-transport-security','max-age=31536000'],
  ['strict-transport-security','max-age=31536000; includesubdomains'],
  ['strict-transport-security','max-age=31536000; includesubdomains; preload'],
  ['vary','accept-encoding'], ['vary','origin'],
  ['x-content-type-options','nosniff'], ['x-xss-protection','1; mode=block'],
  [':status','100'], [':status','204'], [':status','206'], [':status','302'],
  [':status','400'], [':status','403'], [':status','421'], [':status','425'],
  [':status','500'], ['accept-language',''],
  ['access-control-allow-credentials','FALSE'],
  ['access-control-allow-credentials','TRUE'],
  ['access-control-allow-headers','*'],
  ['access-control-allow-methods','get'],
  ['access-control-allow-methods','get, post, options'],
  ['access-control-allow-methods','options'],
  ['access-control-expose-headers','content-length'],
  ['access-control-request-headers','content-type'],
  ['access-control-request-method','get'],
  ['access-control-request-method','post'], ['alt-svc','clear'],
  ['authorization',''],
  ['content-security-policy',"script-src 'none'; object-src 'none'; base-uri 'none'"],
  ['early-data','1'], ['expect-ct',''], ['forwarded',''], ['if-range',''],
  ['origin',''], ['purpose','prefetch'], ['server',''],
  ['timing-allow-origin','*'], ['upgrade-insecure-requests','1'],
  ['user-agent',''], ['x-forwarded-for',''],
  ['x-frame-options','deny'], ['x-frame-options','sameorigin']
];


/**
 * Build the two lookup maps an encoder needs for a static table:
 *   full: "name\0value" → index   (exact entry → single indexed field)
 *   name: "name"        → index   (name only → literal with name reference)
 *
 * `offset` is added to every index: 0 for QPACK (indexed from 0), 1 for HPACK
 * (indexed from 1). Earlier entries win, so the lowest index is kept for a
 * duplicated name — smaller on the wire, and it matches what other encoders do.
 */
function buildStaticLookup(table, offset) {
  offset = offset || 0;
  var full = {}, name = {};
  for (var i = 0; i < table.length; i++) {
    var key = table[i][0] + '\0' + table[i][1];
    if (!(key in full)) full[key] = i + offset;
    if (!(table[i][0] in name)) name[table[i][0]] = i + offset;
  }
  return { full: full, name: name };
}


// ============================================================
//  Text helpers
//
//  Offered, not imposed — see the note on huffDecode. TextDecoder('utf-8')
//  replaces any non-UTF-8 byte with U+FFFD and loses it; latin-1 is a lossless
//  byte↔char mapping, which is also how node:http surfaces header values. A new
//  decoder should prefer bytesToLatin1; QPACK below stays on UTF-8 because that
//  is what it has always done and this refactor is not the place to change it.
// ============================================================

function bytesToLatin1(bytes) {
  var s = '';
  // Chunked to stay clear of the argument-count limit on very long values.
  for (var i = 0; i < bytes.length; i += 4096) {
    s += String.fromCharCode.apply(null, Array.prototype.slice.call(bytes, i, i + 4096));
  }
  return s;
}

function _utf8(str) {
  return new TextEncoder().encode(str);
}


export {
  // Huffman
  HUFF_CODES,
  HUFF_BITS,
  HUFF_EOS,
  huffDecode,
  huffEncode,
  huffEncodedLength,

  // Prefixed integers
  readPrefixedInt,
  encodePrefixedInt,

  // String literals
  decodeStringLiteral,
  encodeStringLiteral,

  // Static tables
  HPACK_STATIC,
  QPACK_STATIC,
  buildStaticLookup,

  // Text
  bytesToLatin1
};
