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
  HPACK_STATIC,
  buildStaticLookup,
  readPrefixedInt,
  encodePrefixedInt,
  decodeStringLiteral,
  encodeStringLiteral,
  bytesToLatin1,
  entrySize,
  ENTRY_OVERHEAD
} from './hpack_primitives.js';


// ============================================================
//  HPACK — header compression for HTTP/2 (RFC 7541).
//
//  The wire primitives (Huffman, prefixed integers, string literals) are
//  shared with QPACK and live in hpack_primitives.js. What is HPACK's own, and
//  what lives here, is the dynamic table: how entries are indexed, when they
//  are inserted, and how they are evicted.
//
//  The difference from QPACK is worth stating, because the two look alike and
//  are not. HPACK assumes ordered delivery — TCP — so a header block may
//  modify the dynamic table INLINE, and the decoder is guaranteed to have
//  applied every earlier block before this one. QPACK cannot assume that, so
//  it moves table updates onto a separate stream and carries an insert count
//  in every block. That is why h3.js does not simply use this file.
//
//  Two endpoints, two tables, four in total: each endpoint's ENCODER table
//  mirrors the peer's DECODER table. They stay in step only because every
//  block is applied exactly once and in order; a single desync corrupts every
//  header that follows, on every stream, which is why the decoder below treats
//  any inconsistency as fatal rather than skipping a field.
// ============================================================


// RFC 7541 §4.1. The 32 is an allowance for the entry's own bookkeeping, fixed
// by the spec so that both peers compute the same size for the same entry.
// From hpack_primitives — shared with QPACK, which defines it identically.

// SETTINGS_HEADER_TABLE_SIZE default (RFC 7540 §6.5.2).
var DEFAULT_TABLE_SIZE = 4096;

// A decoded header list can be far larger than the block that encoded it: an
// indexed field is one byte and may expand to kilobytes, and a block may
// repeat it thousands of times. Without a ceiling a few hundred bytes on the
// wire become gigabytes in memory — the "HPACK bomb". RFC 7541 §7.3 names the
// hazard; the limit is ours to choose and is announced to the peer as
// SETTINGS_MAX_HEADER_LIST_SIZE.
var DEFAULT_MAX_HEADER_LIST_SIZE = 128 * 1024;

var _staticLookup = buildStaticLookup(HPACK_STATIC, 1);   // HPACK indexes from 1
var STATIC_FULL = _staticLookup.full;
var STATIC_NAME = _staticLookup.name;


function hpackError(message) {
  var err = new Error(message);
  err.code = 'HPACK_COMPRESSION_ERROR';
  // RFC 7540 §4.3: a header-block failure is a CONNECTION error of type
  // COMPRESSION_ERROR, never a stream error. The tables are connection-wide,
  // so once they diverge nothing on any stream can be trusted.
  err.h2ErrorCode = 0x9;   // COMPRESSION_ERROR
  return err;
}



// ============================================================
//  Dynamic table
//
//  Index 1..61 is the static table; the dynamic table continues from 62 with
//  the NEWEST entry first, so every insertion renumbers every existing entry.
//  Storing newest-first in a plain array makes that renumbering free.
// ============================================================

function DynamicTable(maxSize) {
  var entries = [];       // [ [name, value, size], ... ] newest first
  var size = 0;
  var limit = maxSize === undefined ? DEFAULT_TABLE_SIZE : maxSize;

  // The largest size the peer has allowed us via SETTINGS_HEADER_TABLE_SIZE.
  // `limit` may be reduced below this by a dynamic table size update, but
  // never raised above it.
  var settingsLimit = limit;

  function evict() {
    while (size > limit && entries.length > 0) {
      size -= entries.pop()[2];
    }
  }

  return {
    get size() { return size; },
    get limit() { return limit; },
    get length() { return entries.length; },

    /**
     * Insert at the front (RFC 7541 §4.4).
     *
     * An entry larger than the whole table is not an error: the table is
     * simply emptied and the entry is not stored. Treating it as an error
     * would break a legal encoder.
     */
    add: function (name, value) {
      var s = entrySize(name, value);
      if (s > limit) { entries = []; size = 0; return; }
      entries.unshift([name, value, s]);
      size += s;
      evict();
    },

    /** 1-based index across static then dynamic, or null. */
    get: function (index) {
      if (index >= 1 && index <= HPACK_STATIC.length) {
        return HPACK_STATIC[index - 1];
      }
      var di = index - HPACK_STATIC.length - 1;
      if (di < 0 || di >= entries.length) return null;
      return entries[di];
    },

    /** Search for an exact or name-only match. Returns { index, full }. */
    find: function (name, value) {
      var full = STATIC_FULL[name + '\u0000' + value];
      if (full !== undefined) return { index: full, full: true };

      var nameIdx = STATIC_NAME[name];
      for (var i = 0; i < entries.length; i++) {
        if (entries[i][0] === name) {
          var idx = HPACK_STATIC.length + 1 + i;
          if (entries[i][1] === value) return { index: idx, full: true };
          if (nameIdx === undefined) nameIdx = idx;
        }
      }
      if (nameIdx !== undefined) return { index: nameIdx, full: false };
      return null;
    },

    /** A dynamic table size update from the peer, or a local decision. */
    setLimit: function (newLimit) {
      if (newLimit > settingsLimit) {
        // §6.3: an update above what SETTINGS permitted is a decoder error.
        // Allowing it would let a peer force unbounded memory use with a
        // two-byte instruction.
        throw hpackError('dynamic table size update ' + newLimit +
                         ' exceeds the agreed maximum ' + settingsLimit);
      }
      limit = newLimit;
      evict();
    },

    /** SETTINGS_HEADER_TABLE_SIZE changed. */
    setSettingsLimit: function (newLimit) {
      settingsLimit = newLimit;
      if (limit > settingsLimit) { limit = settingsLimit; evict(); }
    },

    _entries: function () { return entries; }
  };
}


// ============================================================
//  Decoder
// ============================================================

function HpackDecoder(options) {
  if (!(this instanceof HpackDecoder)) return new HpackDecoder(options);
  options = options || {};

  var table = new DynamicTable(options.maxTableSize);
  var maxHeaderListSize = options.maxHeaderListSize || DEFAULT_MAX_HEADER_LIST_SIZE;

  /**
   * Decode one header block into [ [name, value], ... ].
   *
   * Order is preserved: HTTP/2 pseudo-headers must come first and repeated
   * fields keep their order, so an object would be the wrong shape here.
   * Throws on any inconsistency — see hpackError.
   */
  this.decode = function (block) {
    if (!Buffer.isBuffer(block)) block = Buffer.from(block);

    var out = [];
    var listSize = 0;
    var pos = 0;

    // §4.2: dynamic table size updates may only appear at the very start of a
    // block. A peer that slips one in later is trying to resize the table
    // between two fields, which the encoder's own view cannot reflect.
    var allowSizeUpdate = true;

    while (pos < block.length) {
      var byte = block[pos];

      if ((byte & 0x80) === 0x80) {
        // ---- Indexed Header Field (§6.1) ----
        var idx = readPrefixedInt(block, 7, pos);
        if (!idx) throw hpackError('truncated indexed field');
        pos = idx.next;
        if (idx.value === 0) {
          // Index 0 is not a valid entry — the encoding exists but the RFC
          // reserves it precisely so that a zero cannot be mistaken for one.
          throw hpackError('indexed field with index 0');
        }
        var entry = table.get(idx.value);
        if (!entry) throw hpackError('index ' + idx.value + ' is not in the table');
        out.push([entry[0], entry[1]]);
        listSize += entrySize(entry[0], entry[1]);
        allowSizeUpdate = false;

      } else if ((byte & 0xc0) === 0x40) {
        // ---- Literal with Incremental Indexing (§6.2.1) ----
        var r = readLiteral(block, pos, 6);
        pos = r.next;
        table.add(r.name, r.value);
        out.push([r.name, r.value]);
        listSize += entrySize(r.name, r.value);
        allowSizeUpdate = false;

      } else if ((byte & 0xe0) === 0x20) {
        // ---- Dynamic Table Size Update (§6.3) ----
        if (!allowSizeUpdate) {
          throw hpackError('dynamic table size update must precede the fields in a block');
        }
        var sz = readPrefixedInt(block, 5, pos);
        if (!sz) throw hpackError('truncated table size update');
        pos = sz.next;
        table.setLimit(sz.value);

      } else if ((byte & 0xf0) === 0x10) {
        // ---- Literal Never Indexed (§6.2.3) ----
        var n = readLiteral(block, pos, 4);
        pos = n.next;
        out.push([n.name, n.value, true]);   // third slot: never-index flag
        listSize += entrySize(n.name, n.value);
        allowSizeUpdate = false;

      } else {
        // ---- Literal without Indexing (§6.2.2) ----
        var w = readLiteral(block, pos, 4);
        pos = w.next;
        out.push([w.name, w.value]);
        listSize += entrySize(w.name, w.value);
        allowSizeUpdate = false;
      }

      if (listSize > maxHeaderListSize) {
        throw hpackError('decoded header list exceeds ' + maxHeaderListSize + ' bytes');
      }
    }

    return out;
  };

  function readLiteral(block, pos, prefixBits) {
    var nameIdx = readPrefixedInt(block, prefixBits, pos);
    if (!nameIdx) throw hpackError('truncated literal field');
    pos = nameIdx.next;

    var name;
    if (nameIdx.value === 0) {
      var nameLit = decodeStringLiteral(block, 7, pos, true);
      if (!nameLit) throw hpackError('truncated literal name');
      pos = nameLit.next;
      name = bytesToLatin1(nameLit.bytes);
      if (name.length === 0) throw hpackError('empty header name');
      // §8.1.2: field names in HTTP/2 are lowercase, and a mismatch must be
      // treated as malformed. Checking it here catches it before the value
      // reaches an application that compares names case-sensitively.
      if (/[A-Z]/.test(name)) throw hpackError('header name is not lowercase: ' + name);
    } else {
      var entry = table.get(nameIdx.value);
      if (!entry) throw hpackError('name index ' + nameIdx.value + ' is not in the table');
      name = entry[0];
    }

    var valLit = decodeStringLiteral(block, 7, pos, true);
    if (!valLit) throw hpackError('truncated literal value');
    return { name: name, value: bytesToLatin1(valLit.bytes), next: valLit.next };
  }

  /** The peer changed SETTINGS_HEADER_TABLE_SIZE. */
  this.setMaxTableSize = function (size) { table.setSettingsLimit(size); };
  this.setMaxHeaderListSize = function (size) { maxHeaderListSize = size; };

  Object.defineProperty(this, 'tableSize', { get: function () { return table.size; } });
  Object.defineProperty(this, 'table', { get: function () { return table; } });

  return this;
}


// ============================================================
//  Encoder
// ============================================================

/**
 * Header names whose values must never enter the dynamic table.
 *
 * CRIME-style attacks recover a secret by observing how the compressed size
 * changes when an attacker-controlled header sits next to it: a guess that
 * matches compresses better. Marking these never-indexed (§7.1.3) removes the
 * signal. The cost is a few bytes per request on exactly the headers where
 * that is the right trade.
 */
var NEVER_INDEX = {
  'authorization': true,
  'proxy-authorization': true,
  'cookie': true,
  'set-cookie': true
};

function HpackEncoder(options) {
  if (!(this instanceof HpackEncoder)) return new HpackEncoder(options);
  options = options || {};

  var table = new DynamicTable(options.maxTableSize);
  var pendingSizeUpdate = null;
  var useHuffman = options.huffman !== false;

  /**
   * Encode a header list.
   *
   * `headers` may be [ [name, value], ... ] — order preserved, repeats kept —
   * or a plain object, which is convenient but cannot express either.
   */
  this.encode = function (headers) {
    var list = normalize(headers);
    var out = [];

    // A pending size update goes first, because §4.2 requires it to precede
    // the fields.
    if (pendingSizeUpdate !== null) {
      var upd = encodePrefixedInt(pendingSizeUpdate, 5);
      upd[0] |= 0x20;
      push(out, upd);
      pendingSizeUpdate = null;
    }

    for (var i = 0; i < list.length; i++) {
      var name = list[i][0];
      var value = list[i][1];
      var neverIndex = list[i][2] === true || NEVER_INDEX[name] === true;

      var hit = table.find(name, value);

      if (hit && hit.full && !neverIndex) {
        // Indexed Header Field: 1xxxxxxx
        var idx = encodePrefixedInt(hit.index, 7);
        idx[0] |= 0x80;
        push(out, idx);
        continue;
      }

      var nameIndex = hit ? hit.index : 0;

      if (neverIndex) {
        // Literal Never Indexed: 0001xxxx. Deliberately NOT added to the
        // table — that is the entire point.
        var nx = encodePrefixedInt(nameIndex, 4);
        nx[0] |= 0x10;
        push(out, nx);
        if (nameIndex === 0) push(out, encodeStringLiteral(name, 7, huff()));
        push(out, encodeStringLiteral(value, 7, huff()));
        continue;
      }

      // Literal with Incremental Indexing: 01xxxxxx
      var li = encodePrefixedInt(nameIndex, 6);
      li[0] |= 0x40;
      push(out, li);
      if (nameIndex === 0) push(out, encodeStringLiteral(name, 7, huff()));
      push(out, encodeStringLiteral(value, 7, huff()));
      table.add(name, value);
    }

    return Buffer.from(out);
  };

  function huff() { return useHuffman ? undefined : false; }

  function push(out, bytes) {
    for (var i = 0; i < bytes.length; i++) out.push(bytes[i]);
  }

  function normalize(headers) {
    if (Array.isArray(headers)) {
      var list = [];
      for (var i = 0; i < headers.length; i++) {
        var h = headers[i];
        list.push([String(h[0]).toLowerCase(), String(h[1]), h[2]]);
      }
      return list;
    }
    var out = [];
    for (var name in headers) {
      if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
      var v = headers[name];
      if (v === undefined || v === null) continue;
      var lower = String(name).toLowerCase();
      if (Array.isArray(v)) {
        for (var j = 0; j < v.length; j++) out.push([lower, String(v[j])]);
      } else {
        out.push([lower, String(v)]);
      }
    }
    return out;
  }

  /**
   * Change our table size and tell the peer in the next block.
   *
   * The update must be ANNOUNCED before it takes effect on the wire, so the
   * table is not resized here — the instruction is queued and applied when the
   * next block is built, keeping our table and the peer's decoder in step.
   */
  this.setMaxTableSize = function (size) {
    table.setSettingsLimit(size);
    pendingSizeUpdate = Math.min(size, table.limit);
  };

  Object.defineProperty(this, 'tableSize', { get: function () { return table.size; } });
  Object.defineProperty(this, 'table', { get: function () { return table; } });

  return this;
}


export {
  HpackEncoder,
  HpackDecoder,
  DynamicTable,
  HPACK_STATIC,
  NEVER_INDEX,
  entrySize,
  hpackError,
  DEFAULT_TABLE_SIZE,
  DEFAULT_MAX_HEADER_LIST_SIZE
};
