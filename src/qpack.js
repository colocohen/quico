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
  QPACK_STATIC,
  buildStaticLookup,
  encodeStringLiteral,
  encodePrefixedInt,
  readPrefixedInt,
  entrySize,
  ENTRY_OVERHEAD
} from './hpack_primitives.js';


// ============================================================
//  QPACK dynamic table (RFC 9204).
//
//  HPACK's table and this one solve the same problem and are not the same
//  thing, because the transport underneath is different. In HTTP/2 both sides
//  process header blocks in order, so a shared table stays in step for free.
//  Over QUIC there is no order between streams: a request that references an
//  entry can arrive before the instruction that created it.
//
//  QPACK's answer is to move insertions onto their own unidirectional stream
//  and to make every reference explicit about what it depends on. That is
//  where the complexity comes from, and it is also where the risk comes from:
//  a reference to an entry that has not arrived yet BLOCKS the decoder — the
//  precise thing QUIC exists to avoid.
//
//  THIS ENCODER TAKES NO SUCH RISK.
//
//  RFC 9204 §2.1.2 names both strategies: an encoder may reference entries
//  that are still in flight and compress better, or it may reference only
//  entries the peer has acknowledged and never block. This one does the
//  second. Concretely:
//
//    - We advertise SETTINGS_QPACK_BLOCKED_STREAMS = 0, promising never to
//      send a reference the peer cannot resolve immediately.
//    - An entry becomes usable only after the peer acknowledges its insertion
//      on the decoder stream.
//    - Until then the field goes out as a literal, exactly as before.
//
//  What that costs is the first request on a connection, which is no better
//  than it is today. What it buys is every request after it: measured against
//  a real Chrome header set, a subresource request drops from 412 bytes to 80
//  — the repeated user-agent, accept and sec-ch-ua fields are most of a
//  request and none of them are in the static table.
//
//  It also sidesteps a second hazard for free. RFC 9204 §2.1.3 warns about
//  flow-control deadlock: the encoder stream is flow controlled, so an
//  insertion can stall, and a request that depends on it stalls with it.
//  Here a stalled insertion is simply an unacknowledged one, and an
//  unacknowledged entry is never referenced.
// ============================================================


// buildStaticLookup returns { full, name } — two separate maps, not one flat
// object. `full` is keyed by "name\0value" and `name` by the name alone, and
// treating the result as a single map makes every lookup return undefined:
// no crash, no error, just an encoder that silently never finds anything and
// emits literals for fields that are one byte in the static table.
var STATIC = buildStaticLookup(QPACK_STATIC, 0);
var STATIC_FULL = STATIC.full;
var STATIC_NAME = STATIC.name;

// entrySize and ENTRY_OVERHEAD come from hpack_primitives: RFC 7541 §4.1 and
// RFC 9204 §3.2.1 define them identically, and two copies of a constant both
// peers must agree on is exactly the kind of thing that drifts.


/**
 * createQpackTable(capacity)
 *
 * Entries are held newest-first, which matches how they are addressed: QPACK
 * numbers entries by ABSOLUTE index — a counter of every insertion ever made
 * on the connection — rather than by position. That indirection is what lets
 * a header block name an entry without knowing how many have been evicted
 * since, and it is why `insertCount` below is never reset.
 */
function createQpackTable(capacity) {
  var entries = [];      // newest first
  var size = 0;          // bytes, by the formula above
  var insertCount = 0;   // absolute, monotonic, never reset

  function evictTo(limit) {
    while (size > limit && entries.length > 0) {
      var e = entries.pop();
      size -= entrySize(e.name, e.value);
    }
  }

  return {
    /**
     * Insert, returning the new absolute index, or null if it did not fit.
     *
     * An entry larger than the whole table is not an error: §3.2.2 says to
     * empty the table and not insert it. Treating it as a failure would be
     * wrong, and treating it as a success would leave both sides disagreeing
     * about what the table holds.
     */
    insert: function (name, value) {
      var need = entrySize(name, value);
      if (need > capacity) { evictTo(0); return null; }
      evictTo(capacity - need);
      entries.unshift({ name: name, value: value });
      size += need;
      return ++insertCount;
    },

    /** Absolute index -> entry, or null once it has been evicted. */
    get: function (absoluteIndex) {
      var pos = insertCount - absoluteIndex;
      if (pos < 0 || pos >= entries.length) return null;
      return entries[pos];
    },

    /**
     * Find a name/value pair, or just the name.
     *
     * Returns { index, full }, where `full` distinguishes a complete match
     * from a name-only one — the difference between emitting one byte and
     * emitting a name reference plus a literal value.
     */
    find: function (name, value) {
      var nameHit = null;
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].name !== name) continue;
        var absolute = insertCount - i;
        if (entries[i].value === value) return { index: absolute, full: true };
        if (nameHit === null) nameHit = { index: absolute, full: false };
      }
      return nameHit;
    },

    // Whether an entry fits WITHOUT evicting anything.
    //
    // The encoder only ever inserts when this holds. Evicting is where QPACK
    // gets dangerous: RFC 9204 §2.1.1 forbids evicting an entry that a field
    // section still in flight refers to, and knowing that means tracking every
    // unacknowledged section. Never evicting sidesteps it entirely — once the
    // table is full, new fields simply go out as literals. 4096 bytes holds
    // every header that actually repeats.
    fits: function (name, value) {
      return size + entrySize(name, value) <= capacity;
    },

    setCapacity: function (n) { capacity = n; evictTo(capacity); },

    get insertCount() { return insertCount; },
    get size() { return size; },
    get capacity() { return capacity; },
    get length() { return entries.length; }
  };
}


// ============================================================
//  Encoder insertion history
// ============================================================
//
// Which fields this encoder has sent recently, so that a field is inserted
// into the dynamic table on its SECOND sighting rather than its first. The
// table is never evicted (see fits above), so whatever enters it stays for
// the connection's life — and inserting on first sight filled it with values
// that never come back: on a connection of 300 API responses, 74 of the 79
// entries were one response's etag or x-request-id, the table was full after
// 37 responses, and from then on nothing new could be learned. A field seen
// twice is one that repeats.
//
// Bounded the way the table is, by bytes (entrySize, RFC 9204 §3.2.1), and
// forgets oldest first: what repeats does so from one response to the next,
// well within it.
function createQpackHistory(byteLimit) {
  var seen = new Map();   // name\0value -> its size; insertion order is age
  var size = 0;
  return {
    /** Whether the field was seen before; records it either way. */
    seenBefore: function (name, value) {
      var key = name + '\0' + value;
      if (seen.has(key)) return true;
      var need = entrySize(name, value);
      if (need > byteLimit) return false;   // could never be inserted anyway
      seen.set(key, need);
      size += need;
      while (size > byteLimit) {
        var oldest = seen.keys().next().value;
        size -= seen.get(oldest);
        seen.delete(oldest);
      }
      return false;
    }
  };
}


// ============================================================
//  Encoder-stream instructions (RFC 9204 §4.3)
// ============================================================

/**
 * "Insert with Name Reference" (1Txxxxxx) or "Insert with Literal Name"
 * (01Nxxxxx), whichever the static table allows.
 *
 * T=1 means the name index refers to the STATIC table. Only static references
 * are used here: a dynamic name reference would create a dependency between
 * two insertions, and while that is legal it earns very little and adds a
 * second ordering constraint to reason about.
 */
function encodeInsert(name, value) {
  var staticIndex = STATIC_NAME[name];

  // encodePrefixedInt and encodeStringLiteral both return plain arrays, not
  // Buffers — they are shared with HPACK, where the caller accumulates into an
  // array and converts once at the end. Wrapping each one here rather than
  // assuming.
  if (staticIndex !== undefined) {
    var prefix = encodePrefixedInt(staticIndex, 6);
    prefix[0] |= 0xc0;                       // 1 1 xxxxxx : insert, static name
    return Buffer.concat([Buffer.from(prefix),
                          Buffer.from(encodeStringLiteral(value, 7))]);
  }

  // Insert with Literal Name: 01Nxxxxx, N=0 (this entry may be indexed).
  // The name uses a 5-bit prefix here, not the 7-bit one used for values —
  // the two are different fields and encoding them alike is a silent
  // corruption that only shows on long names.
  var nameBytes = encodeStringLiteral(name, 5);
  nameBytes[0] |= 0x40;
  return Buffer.concat([Buffer.from(nameBytes),
                        Buffer.from(encodeStringLiteral(value, 7))]);
}

/** "Set Dynamic Table Capacity" (001xxxxx). */
function encodeSetCapacity(capacity) {
  var b = encodePrefixedInt(capacity, 5);
  b[0] |= 0x20;
  return Buffer.from(b);
}


// ============================================================
//  Decoder-stream instructions (RFC 9204 §4.4)
// ============================================================

var DECODER_SECTION_ACK   = 0x80;   // 1xxxxxxx
var DECODER_STREAM_CANCEL = 0x40;   // 01xxxxxx
var DECODER_INSERT_COUNT  = 0x00;   // 00xxxxxx

/**
 * Read the peer's decoder stream and report what it acknowledged.
 *
 * Only "Insert Count Increment" carries what this encoder needs: how many of
 * our insertions the peer has processed. Section acknowledgements and stream
 * cancellations matter for eviction accounting in a fuller implementation;
 * here they are parsed and skipped, because entries are never evicted while
 * referenced — this encoder only references acknowledged entries, and the
 * table is small enough that eviction pressure comes from capacity alone.
 */
function parseDecoderInstructions(buf, offset) {
  var increments = 0;
  var i = offset || 0;

  // readPrefixedInt(buf, prefixBits, pos) — prefix width SECOND, position
  // THIRD, and it returns { value, next } rather than a byte length. Getting
  // that order wrong is not a crash: it reads a plausible integer from the
  // wrong bits and advances by the wrong amount, so the stream desynchronises
  // and every instruction after the first is misread.
  while (i < buf.length) {
    var b = buf[i];
    var r;

    if (b & DECODER_SECTION_ACK) {
      r = readPrefixedInt(buf, 7, i);
      if (!r) break;
      i = r.next;
    } else if (b & DECODER_STREAM_CANCEL) {
      r = readPrefixedInt(buf, 6, i);
      if (!r) break;
      i = r.next;
    } else {
      r = readPrefixedInt(buf, 6, i);
      if (!r) break;
      increments += r.value;
      i = r.next;
    }
  }

  return { increments: increments, consumed: i - (offset || 0) };
}


// ============================================================
//  Header block encoding (RFC 9204 §4.5)
// ============================================================

/**
 * Encode one header list.
 *
 * Returns { block, inserts } — the field section for the request stream, and
 * any insertions that must go out on the encoder stream. The caller sends the
 * insertions FIRST; they describe entries this block does not yet use, since
 * nothing is referenced before it is acknowledged.
 *
 * `options.knownReceivedCount` is the acknowledgement watermark: entries at or
 * below it are safe to reference, entries above it are not. It is the single
 * value that makes this encoder non-blocking.
 */
function encodeHeaderBlock(headerList, table, options) {
  options = options || {};
  // Base: the acknowledged insert count. Everything referenced is at or below
  // it, which is the whole non-blocking guarantee.
  var known = options.knownReceivedCount || 0;
  // MaxEntries for the Required Insert Count encoding comes from the DECODER's
  // advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY — the peer's — not from the
  // capacity this encoder chose to use (RFC 9204 §4.5.1.1).
  var maxEntries = Math.floor((options.peerMaxTableCapacity || 0) / ENTRY_OVERHEAD);
  var neverIndex = options.neverIndex || {};

  var out = [];
  var inserts = [];
  var queued = {};                 // name\0value already queued in this block
  var queuedSize = 0;              // bytes those will take
  var maxRef = 0;                  // highest absolute index referenced (1-based)

  for (var i = 0; i < headerList.length; i++) {
    var name = String(headerList[i][0]).toLowerCase();
    var value = String(headerList[i][1]);

    // ---- Static table, full match: one byte ----
    var staticFull = STATIC_FULL[name + '\0' + value];
    if (staticFull !== undefined) {
      var idx = encodePrefixedInt(staticFull, 6);
      idx[0] |= 0xc0;                        // 1 T=1 xxxxxx : indexed, static
      push(out, idx);
      continue;
    }

    // ---- Dynamic table, but only if acknowledged ----
    //
    // `hit.index <= known` and `rel >= 0` below are the same condition: rel
    // is (known - index). Both are kept because they say different things —
    // the first is the non-blocking policy, the second a bounds check on the
    // wire encoding.
    var neverIdx = neverIndex[name] === true || headerList[i][2] === true;
    if (!neverIdx && table.capacity > 0 && maxEntries > 0) {
      var hit = table.find(name, value);
      if (hit && hit.full && hit.index <= known) {
        // Indexed, dynamic: 10xxxxxx, relative to Base (§4.5.2). Absolute
        // indices are zero-based in the RFC and one-based in this table, so
        // relative = Base - 1 - (index - 1) = known - index.
        var rel = known - hit.index;
        if (rel >= 0) {
          var dyn = encodePrefixedInt(rel, 6);
          dyn[0] |= 0x80;
          push(out, dyn);
          if (hit.index > maxRef) maxRef = hit.index;
          continue;
        }
      }
    }

    var staticName = STATIC_NAME[name];

    if (neverIdx) {
      // N=1: an intermediary must not add this to a table either. Compressed
      // size is observable, so a secret in a table can be recovered one byte
      // at a time — the CRIME attack, which is what the N bit exists for.
      if (staticName !== undefined) {
        var nl = encodePrefixedInt(staticName, 4);
        nl[0] |= 0x70;                       // 01 N=1 T=1 xxxx : literal, static name
        push(out, nl);
      } else {
        // 001 N=1 H xxx. The H bit (0x08) is set by encodeStringLiteral when
        // it actually used Huffman; forcing it here — as 0x38 did — marked a
        // plain name as Huffman-coded, and the peer decoded garbage.
        var nn = encodeStringLiteral(name, 3);
        nn[0] |= 0x30;
        push(out, nn);
      }
      push(out, encodeStringLiteral(value, 7));
      continue;
    }

    if (staticName !== undefined) {
      var ln = encodePrefixedInt(staticName, 4);
      ln[0] |= 0x50;                         // 01 N=0 T=1 xxxx : literal, static name
      push(out, ln);
      push(out, encodeStringLiteral(value, 7));
    } else {
      var lit = encodeStringLiteral(name, 3);
      lit[0] |= 0x20;                        // 001 N=0 H xxx : literal, literal name
      push(out, lit);
      push(out, encodeStringLiteral(value, 7));
    }

    // Queue it so a LATER request can reference it — only if it is not in the
    // table already, not queued twice in one block, fits without evicting,
    // and (given a history) has been sent before: see createQpackHistory.
    var key = name + '\0' + value;
    if (table.capacity > 0 && maxEntries > 0 && !queued[key] &&
        !(table.find(name, value) || {}).full &&
        (!options.history || options.history.seenBefore(name, value))) {
      var need = entrySize(name, value);
      if (table.size + queuedSize + need <= table.capacity) {
        queued[key] = true;
        queuedSize += need;
        inserts.push({ name: name, value: value });
      }
    }
  }

  // Field Section Prefix (§4.5.1).
  //
  // Required Insert Count is the highest entry THIS section references, plus
  // one — not everything acknowledged so far. A section that references
  // nothing declares 0, and depends on nothing.
  //
  // Base stays at the acknowledged count, which is at or above it, so the
  // Delta Base is (Base - RIC) with the sign bit clear.
  var prefix = [];
  if (maxRef === 0) {
    push(prefix, encodePrefixedInt(0, 8));
    push(prefix, encodePrefixedInt(0, 7));
  } else {
    push(prefix, encodeRequiredInsertCount(maxRef, maxEntries));
    push(prefix, encodePrefixedInt(known - maxRef, 7));   // S=0
  }

  return {
    block: Buffer.from(prefix.concat(out)),
    inserts: inserts
  };
}

/**
 * Required Insert Count, encoded modulo 2 * MaxEntries (§4.5.1.1).
 *
 * The wrapping exists so the field stays small on long-lived connections
 * where the absolute count grows without bound. With capacity 0 there are no
 * dynamic references at all and the value is 0.
 */
function encodeRequiredInsertCount(ric, maxEntries) {
  // RFC 9204 §4.5.1.1: 0 stays 0; otherwise (RIC mod 2*MaxEntries) + 1.
  //
  // This sent the count raw for a while, to agree with quico's own decoder,
  // which read it raw. The two agreed with each other and with nothing else:
  // Chrome and ls-qpack decode the wrapped form, as the RFC requires.
  if (ric === 0 || maxEntries === 0) return encodePrefixedInt(0, 8);
  return encodePrefixedInt((ric % (2 * maxEntries)) + 1, 8);
}

/**
 * The inverse, for the decoder: the Required Insert Count a field section
 * actually declares (RFC 9204 §4.5.1.1).
 *
 * `totalInserts` is how many entries the decoder has received so far and
 * `maxEntries` is floor(the capacity WE advertised / 32). Throws on an
 * encoding no conforming encoder could have produced.
 */
function decodeRequiredInsertCount(encoded, maxEntries, totalInserts) {
  if (encoded === 0) return 0;
  var fullRange = 2 * maxEntries;
  if (maxEntries === 0 || encoded > fullRange) {
    throw new Error('QPACK: invalid Required Insert Count encoding ' + encoded);
  }
  var maxValue = totalInserts + maxEntries;
  var maxWrapped = Math.floor(maxValue / fullRange) * fullRange;
  var ric = maxWrapped + encoded - 1;
  if (ric > maxValue) {
    if (ric <= fullRange) throw new Error('QPACK: invalid Required Insert Count ' + ric);
    ric -= fullRange;
  }
  if (ric === 0) throw new Error('QPACK: Required Insert Count decoded to 0');
  return ric;
}

/** "Section Acknowledgment" (1xxxxxxx) for the decoder stream (§4.4.1). */
function encodeSectionAck(streamId) {
  var b = encodePrefixedInt(streamId, 7);
  b[0] |= 0x80;
  return Buffer.from(b);
}


/**
 * The Base this encoder uses, and what the decoder must agree it is.
 *
 * Kept equal to the acknowledged insert count, which is also the Required
 * Insert Count above. Everything referenced is at or below it by construction,
 * so no post-base indices are ever emitted and the Delta Base is always zero.
 */

/** Delta Base, sign bit clear: Base equals Required Insert Count. */
function encodeBase(delta) {
  var b = encodePrefixedInt(delta, 7);
  return b;                                   // S=0
}

function push(arr, bytes) {
  for (var i = 0; i < bytes.length; i++) arr.push(bytes[i]);
}


/**
 * "Insert Count Increment" (00xxxxxx) for the decoder stream.
 *
 * Sent after processing insertions from the peer's encoder stream. Without
 * it a conservative peer — one that only references acknowledged entries,
 * like this implementation — never advances past literals, and the dynamic
 * table on both sides fills up while compressing nothing. The two halves are
 * useless apart.
 */
/**
 * "Stream Cancellation" (01xxxxxx) for the decoder stream (RFC 9204 §4.4.2):
 * reading of a stream was abandoned, and any section on it will never be
 * acknowledged.
 */
function encodeStreamCancellation(streamId) {
  var b = encodePrefixedInt(streamId, 6);
  b[0] |= 0x40;
  return Buffer.from(b);
}

function encodeInsertCountIncrement(count) {
  var b = encodePrefixedInt(count, 6);
  b[0] &= 0x3f;                              // 00xxxxxx
  return Buffer.from(b);
}


export {
  createQpackHistory,
  encodeStreamCancellation,
  encodeInsertCountIncrement,
  decodeRequiredInsertCount,
  encodeSectionAck,
  createQpackTable,
  encodeHeaderBlock,
  encodeInsert,
  encodeSetCapacity,
  parseDecoderInstructions,
  entrySize,
  ENTRY_OVERHEAD
};
