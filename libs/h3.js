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
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

var {
  concatUint8Arrays,
  writeVarInt,
  readVarInt
} = require('./utils');


var huffman_codes = new Uint32Array([
  0x1ff8,//(0)
  0x7fffd8,//(1)
  0xfffffe2,//(2)
  0xfffffe3,//(3)
  0xfffffe4,//(4)
  0xfffffe5,//(5)
  0xfffffe6,//(6)
  0xfffffe7,//(7)
  0xfffffe8,//(8)
  0xffffea,//(9)
  0x3ffffffc,//(10)
  0xfffffe9,//(11)
  0xfffffea,//(12)
  0x3ffffffd,//(13)
  0xfffffeb,//(14)
  0xfffffec,//(15)
  0xfffffed,//(16)
  0xfffffee,//(17)
  0xfffffef,//(18)
  0xffffff0,//(19)
  0xffffff1,//(20)
  0xffffff2,//(21)
  0x3ffffffe,//(22)
  0xffffff3,//(23)
  0xffffff4,//(24)
  0xffffff5,//(25)
  0xffffff6,//(26)
  0xffffff7,//(27)
  0xffffff8,//(28)
  0xffffff9,//(29)
  0xffffffa,//(30)
  0xffffffb,//(31)
  0x14,//' ' (32)
  0x3f8,//'!' (33)
  0x3f9,//'"' (34)
  0xffa,//'#' (35)
  0x1ff9,//'$' (36)
  0x15,//'%' (37)
  0xf8,//'&' (38)
  0x7fa,//''' (39)
  0x3fa,//'(' (40)
  0x3fb,//')' (41)
  0xf9,//'*' (42)
  0x7fb,//'+' (43)
  0xfa,//',' (44)
  0x16,//'-' (45)
  0x17,//'.' (46)
  0x18,//'/' (47)
  0x0,//'0' (48)
  0x1,//'1' (49)
  0x2,//'2' (50)
  0x19,//'3' (51)
  0x1a,//'4' (52)
  0x1b,//'5' (53)
  0x1c,//'6' (54)
  0x1d,//'7' (55)
  0x1e,//'8' (56)
  0x1f,//'9' (57)
  0x5c,//':' (58)
  0xfb,//';' (59)
  0x7ffc,//'<' (60)
  0x20,//'=' (61)
  0xffb,//'>' (62)
  0x3fc,//'?' (63)
  0x1ffa,//'@' (64)
  0x21,//'A' (65)
  0x5d,//'B' (66)
  0x5e,//'C' (67)
  0x5f,//'D' (68)
  0x60,//'E' (69)
  0x61,//'F' (70)
  0x62,//'G' (71)
  0x63,//'H' (72)
  0x64,//'I' (73)
  0x65,//'J' (74)
  0x66,//'K' (75)
  0x67,//'L' (76)
  0x68,//'M' (77)
  0x69,//'N' (78)
  0x6a,//'O' (79)
  0x6b,//'P' (80)
  0x6c,//'Q' (81)
  0x6d,//'R' (82)
  0x6e,//'S' (83)
  0x6f,//'T' (84)
  0x70,//'U' (85)
  0x71,//'V' (86)
  0x72,//'W' (87)
  0xfc,//'X' (88)
  0x73,//'Y' (89)
  0xfd,//'Z' (90)
  0x1ffb,//'[' (91)
  0x7fff0,//'\' (92)
  0x1ffc,//']' (93)
  0x3ffc,//'^' (94)
  0x22,//'_' (95)
  0x7ffd,//'`' (96)
  0x3,//'a' (97)
  0x23,//'b' (98)
  0x4,//'c' (99)
  0x24,//'d' (100)
  0x5,//'e' (101)
  0x25,//'f' (102)
  0x26,//'g' (103)
  0x27,//'h' (104)
  0x6,//'i' (105)
  0x74,//'j' (106)
  0x75,//'k' (107)
  0x28,//'l' (108)
  0x29,//'m' (109)
  0x2a,//'n' (110)
  0x7,//'o' (111)
  0x2b,//'p' (112)
  0x76,//'q' (113)
  0x2c,//'r' (114)
  0x8,//'s' (115)
  0x9,//'t' (116)
  0x2d,//'u' (117)
  0x77,//'v' (118)
  0x78,//'w' (119)
  0x79,//'x' (120)
  0x7a,//'y' (121)
  0x7b,//'z' (122)
  0x7ffe,//'{' (123)
  0x7fc,//'|' (124)
  0x3ffd,//'}' (125)
  0x1ffd,//'~' (126)
  0xffffffc,//(127)
  0xfffe6,//(128)
  0x3fffd2,//(129)
  0xfffe7,//(130)
  0xfffe8,//(131)
  0x3fffd3,//(132)
  0x3fffd4,//(133)
  0x3fffd5,//(134)
  0x7fffd9,//(135)
  0x3fffd6,//(136)
  0x7fffda,//(137)
  0x7fffdb,//(138)
  0x7fffdc,//(139)
  0x7fffdd,//(140)
  0x7fffde,//(141)
  0xffffeb,//(142)
  0x7fffdf,//(143)
  0xffffec,//(144)
  0xffffed,//(145)
  0x3fffd7,//(146)
  0x7fffe0,//(147)
  0xffffee,//(148)
  0x7fffe1,//(149)
  0x7fffe2,//(150)
  0x7fffe3,//(151)
  0x7fffe4,//(152)
  0x1fffdc,//(153)
  0x3fffd8,//(154)
  0x7fffe5,//(155)
  0x3fffd9,//(156)
  0x7fffe6,//(157)
  0x7fffe7,//(158)
  0xffffef,//(159)
  0x3fffda,//(160)
  0x1fffdd,//(161)
  0xfffe9,//(162)
  0x3fffdb,//(163)
  0x3fffdc,//(164)
  0x7fffe8,//(165)
  0x7fffe9,//(166)
  0x1fffde,//(167)
  0x7fffea,//(168)
  0x3fffdd,//(169)
  0x3fffde,//(170)
  0xfffff0,//(171)
  0x1fffdf,//(172)
  0x3fffdf,//(173)
  0x7fffeb,//(174)
  0x7fffec,//(175)
  0x1fffe0,//(176)
  0x1fffe1,//(177)
  0x3fffe0,//(178)
  0x1fffe2,//(179)
  0x7fffed,//(180)
  0x3fffe1,//(181)
  0x7fffee,//(182)
  0x7fffef,//(183)
  0xfffea,//(184)
  0x3fffe2,//(185)
  0x3fffe3,//(186)
  0x3fffe4,//(187)
  0x7ffff0,//(188)
  0x3fffe5,//(189)
  0x3fffe6,//(190)
  0x7ffff1,//(191)
  0x3ffffe0,//(192)
  0x3ffffe1,//(193)
  0xfffeb,//(194)
  0x7fff1,//(195)
  0x3fffe7,//(196)
  0x7ffff2,//(197)
  0x3fffe8,//(198)
  0x1ffffec,//(199)
  0x3ffffe2,//(200)
  0x3ffffe3,//(201)
  0x3ffffe4,//(202)
  0x7ffffde,//(203)
  0x7ffffdf,//(204)
  0x3ffffe5,//(205)
  0xfffff1,//(206)
  0x1ffffed,//(207)
  0x7fff2,//(208)
  0x1fffe3,//(209)
  0x3ffffe6,//(210)
  0x7ffffe0,//(211)
  0x7ffffe1,//(212)
  0x3ffffe7,//(213)
  0x7ffffe2,//(214)
  0xfffff2,//(215)
  0x1fffe4,//(216)
  0x1fffe5,//(217)
  0x3ffffe8,//(218)
  0x3ffffe9,//(219)
  0xffffffd,//(220)
  0x7ffffe3,//(221)
  0x7ffffe4,//(222)
  0x7ffffe5,//(223)
  0xfffec,//(224)
  0xfffff3,//(225)
  0xfffed,//(226)
  0x1fffe6,//(227)
  0x3fffe9,//(228)
  0x1fffe7,//(229)
  0x1fffe8,//(230)
  0x7ffff3,//(231)
  0x3fffea,//(232)
  0x3fffeb,//(233)
  0x1ffffee,//(234)
  0x1ffffef,//(235)
  0xfffff4,//(236)
  0xfffff5,//(237)
  0x3ffffea,//(238)
  0x7ffff4,//(239)
  0x3ffffeb,//(240)
  0x7ffffe6,//(241)
  0x3ffffec,//(242)
  0x3ffffed,//(243)
  0x7ffffe7,//(244)
  0x7ffffe8,//(245)
  0x7ffffe9,//(246)
  0x7ffffea,//(247)
  0x7ffffeb,//(248)
  0xffffffe,//(249)
  0x7ffffec,//(250)
  0x7ffffed,//(251)
  0x7ffffee,//(252)
  0x7ffffef,//(253)
  0x7fffff0,//(254)
  0x3ffffee,//(255)
  0x3fffffff,//EOS (256)
]);


var huffman_bits = new Uint8Array([13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,30]);




function buildHuffmanDecodeTrie() {
  var root = {};
  for (var i = 0; i < huffman_codes.length; i++) {
    var code = huffman_codes[i];
    var length = huffman_bits[i];
    var node = root;
    for (var j = length - 1; j >= 0; j--) {
      var bit = (code >> j) & 1;
      if (!node[bit]) node[bit] = {};
      node = node[bit];
    }
    node.symbol = i;
  }
  return root;
}

var huffman_flat_decode_tables = buildHuffmanDecodeTrie();



var qpack_static_table_entries = [
  [":authority", ""],
  [":path", "/"],
  ["age", "0"],
  ["content-disposition", ""],
  ["content-length", "0"],
  ["cookie", ""],
  ["date", ""],
  ["etag", ""],
  ["if-modified-since", ""],
  ["if-none-match", ""],
  ["last-modified", ""],
  ["link", ""],
  ["location", ""],
  ["referer", ""],
  ["set-cookie", ""],
  [":method", "CONNECT"],
  [":method", "DELETE"],
  [":method", "GET"],
  [":method", "HEAD"],
  [":method", "OPTIONS"],
  [":method", "POST"],
  [":method", "PUT"],
  [":scheme", "http"],
  [":scheme", "https"],
  [":status", "103"],
  [":status", "200"],
  [":status", "304"],
  [":status", "404"],
  [":status", "503"],
  ["accept", "*/*"],
  ["accept", "application/dns-message"],
  ["accept-encoding", "gzip, deflate, br"],
  ["accept-ranges", "bytes"],
  ["access-control-allow-headers", "cache-control"],
  ["access-control-allow-headers", "content-type"],
  ["access-control-allow-origin", "*"],
  ["cache-control", "max-age=0"],
  ["cache-control", "max-age=2592000"],
  ["cache-control", "max-age=604800"],
  ["cache-control", "no-cache"],
  ["cache-control", "no-store"],
  ["cache-control", "public, max-age=31536000"],
  ["content-encoding", "br"],
  ["content-encoding", "gzip"],
  ["content-type", "application/dns-message"],
  ["content-type", "application/javascript"],
  ["content-type", "application/json"],
  ["content-type", "application/x-www-form-urlencoded"],
  ["content-type", "image/gif"],
  ["content-type", "image/jpeg"],
  ["content-type", "image/png"],
  ["content-type", "text/css"],
  ["content-type", "text/html; charset=utf-8"],
  ["content-type", "text/plain"],
  ["content-type", "text/plain;charset=utf-8"],
  ["range", "bytes=0-"],
  ["strict-transport-security", "max-age=31536000"],
  ["strict-transport-security", "max-age=31536000; includesubdomains"],
  ["strict-transport-security", "max-age=31536000; includesubdomains; preload"],
  ["vary", "accept-encoding"],
  ["vary", "origin"],
  ["x-content-type-options", "nosniff"],
  ["x-xss-protection", "1; mode=block"],
  [":status", "100"],
  [":status", "204"],
  [":status", "206"],
  [":status", "302"],
  [":status", "400"],
  [":status", "403"],
  [":status", "421"],
  [":status", "425"],
  [":status", "500"],
  ["accept-language", ""],
  ["access-control-allow-credentials", "FALSE"],
  ["access-control-allow-credentials", "TRUE"],
  ["access-control-allow-headers", "*"],
  ["access-control-allow-methods", "get"],
  ["access-control-allow-methods", "get, post, options"],
  ["access-control-allow-methods", "options"],
  ["access-control-expose-headers", "content-length"],
  ["access-control-request-headers", "content-type"],
  ["access-control-request-method", "get"],
  ["access-control-request-method", "post"],
  ["alt-svc", "clear"],
  ["authorization", ""],
  ["content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"],
  ["early-data", "1"],
  ["expect-ct", ""],
  ["forwarded", ""],
  ["if-range", ""],
  ["origin", ""],
  ["purpose", "prefetch"],
  ["server", ""],
  ["timing-allow-origin", "*"],
  ["upgrade-insecure-requests", "1"],
  ["user-agent", ""],
  ["x-forwarded-for", ""],
  ["x-frame-options", "deny"],
  ["x-frame-options", "sameorigin"]
];




function decodeVarInt(buf, prefixBits, pos) {
  const maxPrefix = (1 << prefixBits) - 1;
  let byte  = buf[pos];
  let value = byte & maxPrefix;
  pos++;

  if (value < maxPrefix)  // נגמר במרווח-הבייט הראשון
    return { value, next: pos };

  let m = 0;
  while (true) {
    byte  = buf[pos++];
    value += (byte & 0x7f) << m;
    if ((byte & 0x80) === 0) break;
    m += 7;
  }
  return { value, next: pos };
}


function huffmanEncode(text) {
  var input = new TextEncoder().encode(text); // UTF-8 -> bytes
  var bitBuffer = 0;
  var bitLen = 0;
  var output = [];

  for (var i = 0; i < input.length; i++) {
    var sym = input[i];
    var code = huffman_codes[sym];
    var nbits = huffman_bits[sym];

    bitBuffer = (bitBuffer << nbits) | code;
    bitLen += nbits;

    while (bitLen >= 8) {
      bitLen -= 8;
      output.push((bitBuffer >> bitLen) & 0xff);
    }
  }

  // Padding: לפי התקן, ממלאים 1-ים עד סוף בייט
  if (bitLen > 0) {
    bitBuffer = (bitBuffer << (8 - bitLen)) | ((1 << (8 - bitLen)) - 1);
    output.push(bitBuffer & 0xff);
  }

  return new Uint8Array(output);
}



// פונקציית פיענוח לפי עץ
function decodeHuffman(buf) {
  var output = [];
  var node = huffman_flat_decode_tables;
  var current = 0;
  var nbits = 0;

  for (var i = 0; i < buf.length; i++) {
    current = (current << 8) | buf[i];
    nbits += 8;

    while (nbits > 0) {
      var bit = (current >> (nbits - 1)) & 1;
      node = node[bit];
      if (!node) throw new Error("Invalid Huffman encoding");
      nbits--;

      if (node.symbol !== undefined) {
        output.push(node.symbol);
        node = huffman_flat_decode_tables;
      }
    }
  }

  // בדיקה לסיומת padding חוקית (לפי התקן — רק 1s מותר בסוף)
  var padding = (1 << nbits) - 1;
  if ((current & padding) !== padding) {
    throw new Error("Invalid Huffman padding");
  }

  return new TextDecoder().decode(Uint8Array.from(output));
}



function parse_qpack_header_block(buf) {
  let pos = 0;
  const headers = [];

  // Required Insert Count (prefix-8)
  const ric = decodeVarInt(buf, 8, pos);
  pos = ric.next;

  // Delta Base (prefix-7 + S-bit)
  const firstDbByte = buf[pos];
  const postBase = (firstDbByte & 0x80) !== 0; // S-bit
  const db = decodeVarInt(buf, 7, pos);
  pos = db.next;

  // Base Index = RIC ± DB לפי S-bit
  const baseIndex = postBase
    ? ric.value + db.value
    : ric.value - db.value;

  // Header Field Lines
  while (pos < buf.length) {
    const byte = buf[pos];

    // A. Indexed Field Line – 1xxxxxxx
    if ((byte & 0x80) === 0x80) {
      const fromStatic = (byte & 0x40) !== 0;         // T-bit
      const idx = decodeVarInt(buf, 6, pos);          // prefix-6
      pos = idx.next;
      headers.push({
        type: "indexed",
        from_static_table: fromStatic,
        index: idx.value
      });
      continue;
    }

    // B. Literal With Name Reference – 01xxxxxx
    if ((byte & 0xC0) === 0x40) {
      const neverIndexed = (byte & 0x20) !== 0;       // N-bit
      const fromStatic   = (byte & 0x10) !== 0;       // T-bit
      const nameIdx      = decodeVarInt(buf, 4, pos); // prefix-4
      pos = nameIdx.next;

      const valH   = (buf[pos] & 0x80) !== 0;
      const valLen = decodeVarInt(buf, 7, pos);       // prefix-7
      pos = valLen.next;

      const valBytes = buf.slice(pos, pos + valLen.value);
      pos += valLen.value;
      const value = valH ? decodeHuffman(valBytes)
                         : new TextDecoder().decode(valBytes);

      headers.push({
        type: "literal_with_name_ref",
        never_indexed: neverIndexed,
        from_static_table: fromStatic,
        name_index: nameIdx.value,
        value
      });

      continue;
    }

    // C. Literal With Literal Name – 001xxxxx
    if ((byte & 0xE0) === 0x20) {
      const neverIndexed = (byte & 0x10) !== 0;       // N-bit
      const nameH        = (byte & 0x08) !== 0;       // H-bit
      const nameLen      = decodeVarInt(buf, 3, pos); // prefix-3
      pos = nameLen.next;

      const nameBytes = buf.slice(pos, pos + nameLen.value);
      pos += nameLen.value;
      const name = nameH ? decodeHuffman(nameBytes)
                         : new TextDecoder().decode(nameBytes);

      const valH   = (buf[pos] & 0x80) !== 0;         // H-bit
      const valLen = decodeVarInt(buf, 7, pos);       // prefix-7
      pos = valLen.next;

      const valBytes = buf.slice(pos, pos + valLen.value);
      pos += valLen.value;
      const value = valH ? decodeHuffman(valBytes)
                         : new TextDecoder().decode(valBytes);

      headers.push({
        type: "literal_with_literal_name",
        never_indexed: neverIndexed,
        name,
        value
      });
      continue;
    }

    // לא אמור להגיע לכאן – תקלה לפי התקן
    throw new Error(
      `Unknown header-block instruction at byte ${pos} (0x${byte.toString(16)})`
    );
  }

  return {
    insert_count: ric.value,
    delta_base: db.value,
    post_base: postBase,
    base_index: baseIndex,
    headers
  };
}


function parse_qpack_header_block_old(buf) {
  let pos = 0;
  const headers = [];

  /* 1) Field-section prefix */
  const ric = decodeVarInt(buf, 8, pos);   // Required Insert Count (prefix-8)
  pos = ric.next;

  const db = decodeVarInt(buf, 7, pos);    // Delta Base (prefix-7)
  pos = db.next;

  /* 2) Field-line representations */
  while (pos < buf.length) {
    const byte = buf[pos];

    /* A. Indexed Field Line  – 1xxxxxxx */
    if ((byte & 0x80) === 0x80) {
      const fromStatic = (byte & 0x40) !== 0;         // T-bit
      const idx = decodeVarInt(buf, 6, pos);          // prefix-6
      pos = idx.next;
      headers.push({
        type: "indexed",
        from_static_table: fromStatic,
        index: idx.value
      });
      continue;
    }

    /* B. Literal Field Line + Name Reference – 01xxxxxx */
    if ((byte & 0xC0) === 0x40) {
      const neverIndexed = (byte & 0x20) !== 0;       // N-bit
      const fromStatic   = (byte & 0x10) !== 0;       // T-bit
      const nameIdx      = decodeVarInt(buf, 4, pos); // prefix-4
      pos = nameIdx.next;

      const valH   = (buf[pos] & 0x80) !== 0;
      const valLen = decodeVarInt(buf, 7, pos);       // prefix-7
      pos = valLen.next;

      const valBytes = buf.slice(pos, pos + valLen.value);
      pos += valLen.value;
      const value = valH ? decodeHuffman(valBytes)
                         : new TextDecoder().decode(valBytes);

      headers.push({
        type: "literal_with_name_ref",
        never_indexed: neverIndexed,
        from_static_table: fromStatic,
        name_index: nameIdx.value,
        value
      });

      continue;
    }

    /* C. Literal Field Line + Literal Name – 001xxxxx */
    if ((byte & 0xE0) === 0x20) {
      const neverIndexed = (byte & 0x10) !== 0;       // N-bit
      const nameH        = (byte & 0x08) !== 0;       // H-bit (שם) :contentReference[oaicite:0]{index=0}
      const nameLen      = decodeVarInt(buf, 3, pos); // prefix-3
      pos = nameLen.next;

      const nameBytes = buf.slice(pos, pos + nameLen.value);
      pos += nameLen.value;
      const name = nameH ? decodeHuffman(nameBytes)
                         : new TextDecoder().decode(nameBytes);

      const valH   = (buf[pos] & 0x80) !== 0;         // H-bit (ערך)
      const valLen = decodeVarInt(buf, 7, pos);       // prefix-7
      pos = valLen.next;

      const valBytes = buf.slice(pos, pos + valLen.value);
      pos += valLen.value;
      const value = valH ? decodeHuffman(valBytes)
                         : new TextDecoder().decode(valBytes);

      headers.push({
        type: "literal_with_literal_name",
        never_indexed: neverIndexed,
        name,
        value
      });
      continue;
    }

    /* לא אמור להגיע לכאן – פסילה לפי התקן */
    throw new Error(
      `Unknown header-block instruction at byte ${pos} (0x${byte.toString(16)})`
    );
  }

  return {
    insert_count: ric.value,
    delta_base: db.value,
    headers: headers
  };
}






function extract_h3_frames_from_chunks(chunks, from_offset) {
  var offsets = Object.keys(chunks).map(Number).sort((a, b) => a - b);
  var buffers = [];
  var totalLength = 0;

  // מחברים את כל הצ’אנקים החל מ־from_offset
  for (var i = 0; i < offsets.length; i++) {
    var base = offsets[i];
    var chunk = chunks[base];
    if (from_offset >= base && from_offset < base + chunk.length) {
      var start = from_offset - base;
      var sliced = chunk.slice(start);
      buffers.push(sliced);
      totalLength += sliced.length;

      for (var j = i + 1; j < offsets.length; j++) {
        buffers.push(chunks[offsets[j]]);
        totalLength += chunks[offsets[j]].length;
      }

      break;
    }
  }

  if (buffers.length === 0) return { frames: [], new_from_offset: from_offset };

  var combined = concatUint8Arrays(buffers);
  var offset = 0;
  var frames = [];

  // פונקציית עזר בטוחה לקריאת VarInt
  function safeReadVarInt() {
    if (offset >= combined.length) return null;
    var firstByte = combined[offset];
    var lengthBits = firstByte >> 6;
    var neededLength = 1 << lengthBits;
    if (offset + neededLength > combined.length) return null;
    var res = readVarInt(combined, offset);
    if (!res || typeof res.byteLength !== 'number') return null;
    offset += res.byteLength;
    return res;
  }

  while (offset < combined.length) {
    var startOffset = offset;

    var frameType = safeReadVarInt();
    if (!frameType) break;

    var lengthInfo = safeReadVarInt();
    if (!lengthInfo) {
      offset = startOffset; // rollback – אי אפשר אפילו לקרוא אורך
      break;
    }

    var payloadLength = lengthInfo.value;
    if (offset + payloadLength > combined.length) {
      offset = startOffset; // rollback
      break;
    }

    var payload = combined.slice(offset, offset + payloadLength);
    frames.push({ frame_type: frameType.value, payload });
    offset += payloadLength;
  }

  // עדכון chunks כדי להסיר את מה שקראנו
  if (offset > 0) {
    var bytesToRemove = offset;
    var newChunks = {};
    var processed = 0;
    var currentOffset = from_offset;

    for (var k = 0; k < offsets.length; k++) {
      var base = offsets[k];
      var chunk = chunks[base];

      if (currentOffset >= base + chunk.length) continue;

      var relStart = Math.max(currentOffset - base, 0);
      var relEnd = Math.min(chunk.length, currentOffset + bytesToRemove - base);
      if (relEnd < chunk.length) {
        var leftover = chunk.slice(relEnd);
        var newBase = base + relEnd;
        newChunks[newBase] = leftover;
      }

      bytesToRemove -= (relEnd - relStart);
      if (bytesToRemove <= 0) break;
    }

    for (var key in chunks) delete chunks[key];
    for (var key in newChunks) chunks[key] = newChunks[key];
    from_offset += offset;
  }

  return { frames, new_from_offset: from_offset };
}




function build_h3_frames(frames) {
  var parts = [];

  for (var i = 0; i < frames.length; i++) {
    var frame = frames[i];

    // כל חלק מהפריים כ־Uint8Array
    var typeBytes = writeVarInt(frame.frame_type);
    var lenBytes  = writeVarInt(frame.payload.length);
    var payload   = frame.payload;

    parts.push(typeBytes, lenBytes, payload);
  }

  return concatUint8Arrays(parts);
  
}



/* חישוב אורך varint לפי HPACK/QPACK (prefix-N)  */
function computeVarIntLen(buf, pos, prefixBits) {
  if (pos >= buf.length) return null;
  var first = buf[pos];
  var prefixMask = (1 << prefixBits) - 1;
  var prefixVal = first & prefixMask;

  // אם הערך קטן מהמקסימום – varint של בייט אחד
  if (prefixVal < prefixMask) return 1;

  // אחרת ממשיכים ב-Base128 עד שבייט בלי MSB=1
  var len = 1;
  var idx = pos + 1;
  while (idx < buf.length) {
    len++;
    if ((buf[idx] & 0x80) === 0) return len; // הסתיים
    idx++;
  }
  return null; // חסר נתונים
}

/* קריאה בטוחה של varint  */
function safeDecodeVarInt(buf, posRef, prefixBits) {
  var len = computeVarIntLen(buf, posRef.pos, prefixBits);
  if (len === null) return null; // לא שלם

  var res = decodeVarInt(buf, prefixBits, posRef.pos); // הפונקציה שלך
  posRef.pos = res.next;
  return res.value;
}

/* ---------- פונקציית החילוץ העיקרית ---------- */

function extract_qpack_encoder_instructions_from_chunks(chunks, from_offset) {
  /* 1) חיבור הצ’אנקים החל מ-from_offset */
  var offsets = Object.keys(chunks).map(Number).sort(function (a, b) { return a - b; });
  var buffers = [];
  var totalLen = 0;

  for (var i = 0; i < offsets.length; i++) {
    var base = offsets[i];
    var chunk = chunks[base];
    if (from_offset >= base && from_offset < base + chunk.length) {
      var start = from_offset - base;
      var sliced = chunk.slice(start);
      buffers.push(sliced);
      totalLen += sliced.length;

      for (var j = i + 1; j < offsets.length; j++) {
        buffers.push(chunks[offsets[j]]);
        totalLen += chunks[offsets[j]].length;
      }
      break;
    }
  }

  if (buffers.length === 0) {
    return { instructions: [], new_from_offset: from_offset };
  }

  var combined = concatUint8Arrays(buffers);
  var posRef = { pos: 0 };
  var instructions = [];

  /* 2) לולאת פיענוח ההוראות */
  while (posRef.pos < combined.length) {
    var startPos = posRef.pos;
    var byte = combined[posRef.pos];

    /* --- A. Insert With Name Reference (1xxxxxxx) --- */
    if ((byte & 0x80) === 0x80) {
      var fromStatic = (byte & 0x40) !== 0;
      var nameIdx = safeDecodeVarInt(combined, posRef, 6);
      if (nameIdx === null) break; // לא שלם

      // value length
      var valHuffman = (combined[posRef.pos] & 0x80) !== 0;
      var valLen = safeDecodeVarInt(combined, posRef, 7);
      if (valLen === null || posRef.pos + valLen > combined.length) {
        posRef.pos = startPos; break;
      }

      var valBytes = combined.slice(posRef.pos, posRef.pos + valLen);
      posRef.pos += valLen;

      var value = valHuffman ? decodeHuffman(valBytes)
                             : new TextDecoder().decode(valBytes);

      instructions.push({
        type: 'insert_with_name_ref',
        from_static_table: fromStatic,
        name_index: nameIdx,
        value: value
      });
      continue;
    }

    /* --- B. Insert Without Name Reference (01xxxxxx) --- */
    if ((byte & 0xC0) === 0x40) {
      var nameH = (byte & 0x20) !== 0;
      var nameLen = safeDecodeVarInt(combined, posRef, 5);
      if (nameLen === null || posRef.pos + nameLen > combined.length) {
        posRef.pos = startPos; break;
      }
      var nameBytes = combined.slice(posRef.pos, posRef.pos + nameLen);
      posRef.pos += nameLen;

      var valH = (combined[posRef.pos] & 0x80) !== 0;
      var valLen2 = safeDecodeVarInt(combined, posRef, 7);
      if (valLen2 === null || posRef.pos + valLen2 > combined.length) {
        posRef.pos = startPos; break;
      }
      var valBytes2 = combined.slice(posRef.pos, posRef.pos + valLen2);
      posRef.pos += valLen2;

      var nameStr = nameH ? decodeHuffman(nameBytes)
                          : new TextDecoder().decode(nameBytes);
      var valueStr = valH ? decodeHuffman(valBytes2)
                          : new TextDecoder().decode(valBytes2);

      instructions.push({
        type: 'insert_without_name_ref',
        name: nameStr,
        value: valueStr
      });
      continue;
    }

    /* --- C. Set Dynamic Table Capacity (001xxxxx) --- */
    if ((byte & 0xE0) === 0x20) {
      var capacity = safeDecodeVarInt(combined, posRef, 5);
      if (capacity === null) { posRef.pos = startPos; break; }

      instructions.push({
        type: 'set_dynamic_table_capacity',
        capacity: capacity
      });
      continue;
    }

    /* --- D. Duplicate (0000xxxx) --- */
    if ((byte & 0xF0) === 0x00) {
      var dupIndex = safeDecodeVarInt(combined, posRef, 4);
      if (dupIndex === null) { posRef.pos = startPos; break; }

      instructions.push({
        type: 'duplicate',
        index: dupIndex
      });
      continue;
    }

    /* לא מוכר - נעצור */
    break;
  }

  var consumed = posRef.pos; // כמה בייטים הצלחנו לפרש

  /* 3) ניקוי הצ’אנקים והתקדמות from_offset */
  if (consumed > 0) {
    var bytesLeft = consumed;
    var newChunks = {};
    var currOff = from_offset;

    for (var k = 0; k < offsets.length; k++) {
      var base = offsets[k];
      var chunk = chunks[base];

      if (currOff >= base + chunk.length) continue;

      var relStart = Math.max(currOff - base, 0);
      var relEnd = Math.min(chunk.length, currOff + bytesLeft - base);

      if (relEnd < chunk.length) {
        var leftover = chunk.slice(relEnd);
        newChunks[base + relEnd] = leftover;
      }

      bytesLeft -= (relEnd - relStart);
      if (bytesLeft <= 0) break;
    }

    for (var key in chunks) delete chunks[key];
    for (var nk in newChunks) chunks[nk] = newChunks[nk];

    from_offset += consumed;
  }

  return { instructions: instructions, new_from_offset: from_offset };
}



var h3_settings_frame_params = [
  [0x01, "SETTINGS_QPACK_MAX_TABLE_CAPACITY"],
  [0x06, "SETTINGS_MAX_FIELD_SECTION_SIZE"],
  [0x07, "SETTINGS_QPACK_BLOCKED_STREAMS"],
  [0x08, "SETTINGS_ENABLE_CONNECT_PROTOCOL"],
  [0x33, "SETTINGS_H3_DATAGRAM"],
  [0x2b603742, "SETTINGS_ENABLE_WEBTRANSPORT"],  // תקני לפי draft
  [0x0d, "SETTINGS_NO_RFC9114_LEGACY_CODEPOINT"],
  [0x14E9CD29, "SETTINGS_WT_MAX_SESSIONS"],
  [0x4d44, "SETTINGS_ENABLE_METADATA"]           // provisional
];

var h3_name_to_id = {};
var h3_id_to_name = {};

for (var i = 0; i < h3_settings_frame_params.length; i++) {
  var [id, name] = h3_settings_frame_params[i];
  h3_name_to_id[name] = id;
  h3_id_to_name[id] = name;
}



function parse_h3_settings_frame(buf) {
  var settings = {};
  var offset = 0;

  while (offset < buf.length) {
    var idRes = readVarInt(buf, offset);
    if (!idRes) break;
    offset += idRes.byteLength;

    var valRes = readVarInt(buf, offset);
    if (!valRes) break;
    offset += valRes.byteLength;

    var id = idRes.value;
    var value = valRes.value;

    var name = h3_id_to_name[id] || `UNKNOWN_0x${id.toString(16)}`;
    settings[name] = value;
  }

  return settings;
}


function build_settings_frame(settings_named) {
  var frame_payload = [];

  for (var name in settings_named) {
    var id = h3_name_to_id[name];
    if (id === undefined) {
      throw new Error("Unknown setting name: " + name);
    }
    var value = settings_named[name];

    frame_payload.push(...writeVarInt(id));
    frame_payload.push(...writeVarInt(value));
  }

  return new Uint8Array(frame_payload);
}



function build_control_stream_old(settings_named) {
    var setting_ids = {
    SETTINGS_QPACK_MAX_TABLE_CAPACITY: 0x01,
    SETTINGS_MAX_FIELD_SECTION_SIZE: 0x06,
    SETTINGS_ENABLE_WEBTRANSPORT: 0x2b603742,   // תקני לפי draft
    SETTINGS_H3_DATAGRAM: 0x33,                 // תקני לפי RFC 9297
    SETTINGS_NO_RFC9114_LEGACY_CODEPOINT: 0x0d,
    SETTINGS_ENABLE_CONNECT_PROTOCOL: 0x08,      // תקני לפי RFC 9220
    SETTINGS_WT_MAX_SESSIONS: 0x14E9CD29
    };

    var frame_payload = [];

    for (var name in settings_named) {
    var id = setting_ids[name];
    if (id === undefined) {
        throw new Error("Unknown setting name: " + name);
    }

    var value = settings_named[name];
    frame_payload.push(...writeVarInt(id));
    frame_payload.push(...writeVarInt(value));
    }

    var frame_header = [
    ...writeVarInt(0x04), // SETTINGS frame type
    ...writeVarInt(frame_payload.length)
    ];

    return new Uint8Array([
    0x00, // Stream Type: Control Stream
    ...frame_header,
    ...frame_payload
    ]);
}


function encodeInt(value, prefixBits) {
  const max = (1 << prefixBits) - 1;
  if (value < max) return [value];           // נכנס כולו בפריפיקס
  const bytes = [max];
  value -= max;
  while (value >= 128) {                     // המשך varint (7-bit groups)
    bytes.push((value & 0x7F) | 0x80);
    value >>= 7;
  }
  bytes.push(value);
  return bytes;
}

function encodeStringLiteral(bytes, hFlag /* 0/1 */) {
  const lenBytes = encodeInt(bytes.length, 7);         // prefix-7
  lenBytes[0] |= (hFlag << 7);                         // מוסיפים H
  return lenBytes.concat(Array.from(bytes));
}

/* ---------- בניית HEADERS (Literal) ---------- */
function build_http3_literal_headers_frame(headers) {
  const out = [];
  out.push(0x00, 0x00);                                // QPACK prefix

  for (var header_name in headers) {
    const nameBytes  = new TextEncoder().encode(header_name.toLowerCase());
    const valueBytes = new TextEncoder().encode(String(headers[header_name]));
    
    /* בייט ראשון: 001 | N=0 | H=0 | NameLen(3+) */
    const nameLenEnc = encodeInt(nameBytes.length, 3); // prefix-3
    const firstByte  = 0x20 | nameLenEnc[0];           // 0b0010_0000
    out.push(firstByte, ...nameLenEnc.slice(1), ...nameBytes);

    /* value: H=0 + prefix-7 */
    out.push(...encodeStringLiteral(valueBytes, 0));
  }
  return new Uint8Array(out);
}


function build_qpack_block_header_ack(stream_id) {
  return concatUint8Arrays([
    Uint8Array.from([0x81]),        // instruction type
    writeVarInt(stream_id)          // full VarInt
  ]);
}
function build_qpack_known_received_count(count) {
  if (count <= 0) return null;          // אין מה לשלוח
  var buf = writeVarInt(count);       // VarInt עם prefix-6
  buf[0] &= 0x3F;                           // מוודא ששני הביטים העליונים 00
  return buf;
}


function parse_webtransport_datagram(payload) {
  var result = readVarInt(payload, 0);
  if (!result) {
    throw new Error("Invalid VarInt at beginning of payload");
  }

  var stream_id = result.value;
  var data = payload.slice(result.byteLength); // שאר ה־payload זה הנתונים

  return {
    stream_id: stream_id,
    data: data
  };
}

module.exports = {
  build_h3_frames,
  build_settings_frame,
  parse_h3_settings_frame,
  extract_qpack_encoder_instructions_from_chunks,
  extract_h3_frames_from_chunks,
  parse_qpack_header_block,
  build_http3_literal_headers_frame,
  parse_webtransport_datagram,
  build_qpack_block_header_ack,
  build_qpack_known_received_count,
  qpack_static_table_entries
};