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


// ============================================================
//  QPACK Static Table (RFC 9204 Appendix A)
// ============================================================

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


// ============================================================
//  Huffman (RFC 7541 Appendix B)
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

function huffDecode(buf) {
  var out = [], node = _huffRoot, nbits = 0, current = 0;
  for (var i = 0; i < buf.length; i++) {
    current = (current << 8) | buf[i];
    nbits += 8;
    while (nbits > 0) {
      node = node[(current >> (nbits - 1)) & 1];
      if (!node) throw new Error('Invalid Huffman');
      nbits--;
      if (node.sym !== undefined) { out.push(node.sym); node = _huffRoot; }
    }
  }
  return new TextDecoder().decode(Uint8Array.from(out));
}


// ============================================================
//  QPACK parse/build helpers
// ============================================================

// Read a QPACK/HPACK prefixed integer at buf[pos]. Returns { value, next } or
// null if the buffer ends mid-integer (truncated). Used by both the header
// block parser and the encoder-instruction parser.
function readPrefixedInt(buf, prefixBits, pos) {
  if (pos >= buf.length) return null;
  var max = (1 << prefixBits) - 1;
  var value = buf[pos] & max;
  pos++;
  if (value < max) return { value: value, next: pos };
  var m = 0;
  while (pos < buf.length) {
    var byte = buf[pos++];
    value += (byte & 0x7f) << m;
    if ((byte & 0x80) === 0) return { value: value, next: pos };
    m += 7;
  }
  return null; // truncated mid-integer
}

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
      if (fromStatic && idx.value < QPACK_STATIC.length) {
        headers[QPACK_STATIC[idx.value][0]] = QPACK_STATIC[idx.value][1];
      } else if (!fromStatic && dynamicTable) {
        var di = bi - 1 - idx.value;
        if (di >= 0 && di < dynamicTable.length) {
          headers[dynamicTable[di][0]] = dynamicTable[di][1];
        }
      }

    } else if ((byte & 0xc0) === 0x40) {
      // Literal with name ref
      var fromStatic = (byte & 0x10) !== 0;
      var nameIdx = readPrefixedInt(buf, 4, pos); if (!nameIdx) break; pos = nameIdx.next;
      var valH = (buf[pos] & 0x80) !== 0;
      var valLen = readPrefixedInt(buf, 7, pos); if (!valLen) break; pos = valLen.next;
      var valBytes = buf.slice(pos, pos + valLen.value); pos += valLen.value;
      var value = valH ? huffDecode(valBytes) : new TextDecoder().decode(valBytes);

      var name = null;
      if (fromStatic && nameIdx.value < QPACK_STATIC.length) {
        name = QPACK_STATIC[nameIdx.value][0];
      } else if (!fromStatic && dynamicTable) {
        var di = bi - 1 - nameIdx.value;
        if (di >= 0 && di < dynamicTable.length) name = dynamicTable[di][0];
      }
      if (name) headers[name] = value;

    } else if ((byte & 0xe0) === 0x20) {
      // Literal with literal name
      var nameH = (byte & 0x08) !== 0;
      var nameLen = readPrefixedInt(buf, 3, pos); if (!nameLen) break; pos = nameLen.next;
      var nameBytes = buf.slice(pos, pos + nameLen.value); pos += nameLen.value;
      var name = nameH ? huffDecode(nameBytes) : new TextDecoder().decode(nameBytes);
      var valH = (buf[pos] & 0x80) !== 0;
      var valLen = readPrefixedInt(buf, 7, pos); if (!valLen) break; pos = valLen.next;
      var valBytes = buf.slice(pos, pos + valLen.value); pos += valLen.value;
      var value = valH ? huffDecode(valBytes) : new TextDecoder().decode(valBytes);
      headers[name] = value;

    } else {
      break;
    }
  }

  return headers;
}

function encodeQpackInt(value, prefixBits) {
  var max = (1 << prefixBits) - 1;
  if (value < max) return [value];
  var bytes = [max];
  value -= max;
  while (value >= 128) { bytes.push((value & 0x7f) | 0x80); value >>= 7; }
  bytes.push(value);
  return bytes;
}


// ---- Static table lookup maps (built once) ----

var _qpackFullMatch = {};   // "name\0value" → index
var _qpackNameMatch = {};   // "name" → first index

for (var _i = 0; _i < QPACK_STATIC.length; _i++) {
  var _key = QPACK_STATIC[_i][0] + '\0' + QPACK_STATIC[_i][1];
  if (!(_key in _qpackFullMatch)) _qpackFullMatch[_key] = _i;
  if (!(QPACK_STATIC[_i][0] in _qpackNameMatch)) _qpackNameMatch[QPACK_STATIC[_i][0]] = _i;
}


function buildQpackHeaderBlock(headers) {
  var out = [0x00, 0x00]; // QPACK prefix: RIC=0, delta base=0

  for (var name in headers) {
    var lname = name.toLowerCase();
    var value = String(headers[name]);

    // (1) Try full match: name + value in static table → indexed (1 byte)
    var fullKey = lname + '\0' + value;
    if (fullKey in _qpackFullMatch) {
      var idx = _qpackFullMatch[fullKey];
      // Indexed: 1 1 NNNNNN (T=1 static, 6-bit prefix)
      var enc = encodeQpackInt(idx, 6);
      out.push(0xc0 | enc[0]);
      for (var i = 1; i < enc.length; i++) out.push(enc[i]);
      continue;
    }

    // (2) Try name match: name in static table → literal with name ref
    if (lname in _qpackNameMatch) {
      var nameIdx = _qpackNameMatch[lname];
      // Literal with name reference: 01 N T PPPP (N=0, T=1 static, 4-bit prefix)
      var nameEnc = encodeQpackInt(nameIdx, 4);
      out.push(0x50 | nameEnc[0]);
      for (var i = 1; i < nameEnc.length; i++) out.push(nameEnc[i]);
      // Value: H=0 (no huffman), 7-bit length prefix
      var valBytes = new TextEncoder().encode(value);
      var valLenEnc = encodeQpackInt(valBytes.length, 7);
      out.push(valLenEnc[0]);
      for (var i = 1; i < valLenEnc.length; i++) out.push(valLenEnc[i]);
      for (var i = 0; i < valBytes.length; i++) out.push(valBytes[i]);
      continue;
    }

    // (3) No match: literal with literal name (fallback)
    var nameBytes = new TextEncoder().encode(lname);
    var nameLenEnc = encodeQpackInt(nameBytes.length, 3);
    out.push(0x20 | nameLenEnc[0]);
    for (var i = 1; i < nameLenEnc.length; i++) out.push(nameLenEnc[i]);
    for (var i = 0; i < nameBytes.length; i++) out.push(nameBytes[i]);
    var valBytes = new TextEncoder().encode(value);
    var valLenEnc = encodeQpackInt(valBytes.length, 7);
    out.push(valLenEnc[0]);
    for (var i = 1; i < valLenEnc.length; i++) out.push(valLenEnc[i]);
    for (var i = 0; i < valBytes.length; i++) out.push(valBytes[i]);
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

  // Thin wrapper over the shared readPrefixedInt that advances the local `pos`
  // and returns the value (or null on truncation), preserving call-site usage.
  function safeVarInt(prefixBits) {
    var r = readPrefixedInt(combined, prefixBits, pos);
    if (!r) return null;
    pos = r.next;
    return r.value;
  }

  while (pos < combined.length) {
    var startPos = pos;
    var byte = combined[pos];

    if ((byte & 0x80) === 0x80) {
      // Insert with name reference
      var fromStatic = (byte & 0x40) !== 0;
      var nameIdx = safeVarInt(6); if (nameIdx === null) { pos = startPos; break; }
      var valH = (combined[pos] & 0x80) !== 0;
      var valLen = safeVarInt(7); if (valLen === null) { pos = startPos; break; }
      if (pos + valLen > combined.length) { pos = startPos; break; }
      var valBytes = combined.slice(pos, pos + valLen); pos += valLen;
      var value = valH ? huffDecode(valBytes) : new TextDecoder().decode(valBytes);
      instructions.push({ type: 'insert_name_ref', from_static: fromStatic, name_index: nameIdx, value: value });

    } else if ((byte & 0xc0) === 0x40) {
      // Insert without name reference
      var nameH = (byte & 0x20) !== 0;
      var nameLen = safeVarInt(5); if (nameLen === null) { pos = startPos; break; }
      if (pos + nameLen > combined.length) { pos = startPos; break; }
      var nameBytes = combined.slice(pos, pos + nameLen); pos += nameLen;
      var name = nameH ? huffDecode(nameBytes) : new TextDecoder().decode(nameBytes);
      var valH = (combined[pos] & 0x80) !== 0;
      var valLen = safeVarInt(7); if (valLen === null) { pos = startPos; break; }
      if (pos + valLen > combined.length) { pos = startPos; break; }
      var valBytes = combined.slice(pos, pos + valLen); pos += valLen;
      var value = valH ? huffDecode(valBytes) : new TextDecoder().decode(valBytes);
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

    // Process by type
    if (s.type === 'control') {
      processControlStream(s);

    } else if (s.type === 'qpack_enc') {
      processQpackEncoderStream(s);

    } else if (s.type === 'bidi') {
      processBidiStream(streamId, s);
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
    var ext = parseQpackEncoderInstructions(s.chunks, s.from_offset);
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

  function processBidiStream(streamId, s) {
    var ext = extractH3Frames(s.chunks, s.from_offset);
    if (DEBUG) console.log('[h3] bidi stream ' + streamId + ': extracted ' + ext.frames.length + ' H3 frames, types=' + ext.frames.map(function(f){ return '0x' + f.frame_type.toString(16); }).join(','));

    if (ext.frames.length > 0) {
      s.from_offset = ext.new_from_offset;

      for (var i = 0; i < ext.frames.length; i++) {
        if (ext.frames[i].frame_type === 1) {
          // HEADERS
          var headers = parseQpackHeaderBlock(
            ext.frames[i].payload,
            context.remote_qpack_dynamic_table,
            context.remote_qpack_table_base_index
          );
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


export { H3Connection };
