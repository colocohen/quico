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
  concatUint8Arrays,
  writeVarInt,
  readVarInt
} from './utils.js';
import { SUPPORTED_VERSIONS, isSupportedVersion, longPacketType } from './quic_version.js';


// ============================================================
//  QUIC Datagram → Packet splitting (RFC 9000 §12.2)
// ============================================================

/**
 * Parse a single QUIC packet header (enough to get type + totalLength).
 *
 * shortCidLen: the length of the connection IDs this receiver issues. A short
 * header carries its Destination Connection ID without a length (RFC 9000
 * §17.3) — only the receiver, who chose it, knows where it ends. A server whose
 * IDs all have one length passes it, and short-header packets then come back
 * with `dcid` like long-header ones do. Without it their `dcid` is absent.
 */
function parse_quic_packet(array, offset0, shortCidLen) {
  if (!(array instanceof Uint8Array)) return null;
  if (offset0 === undefined) offset0 = 0;
  if (offset0 >= array.length) return null;

  var firstByte = array[offset0];
  var isLong = (firstByte & 0x80) !== 0;

  if (isLong) {
    if (offset0 + 6 > array.length) return null;

    var version = (
      (array[offset0 + 1] << 24) |
      (array[offset0 + 2] << 16) |
      (array[offset0 + 3] << 8) |
      array[offset0 + 4]
    ) >>> 0;

    var dcidLen = array[offset0 + 5];
    var offset = offset0 + 6;

    if (offset + dcidLen + 1 > array.length) return null;
    var dcid = array.slice(offset, offset + dcidLen);
    offset += dcidLen;

    var scidLen = array[offset++];
    if (offset + scidLen > array.length) return null;
    var scid = array.slice(offset, offset + scidLen);
    offset += scidLen;

    // Version Negotiation
    if (version === 0) {
      var supportedVersions = [];
      while (offset + 4 <= array.length) {
        supportedVersions.push(
          (array[offset] << 24) | (array[offset + 1] << 16) |
          (array[offset + 2] << 8) | array[offset + 3]
        );
        offset += 4;
      }
      return {
        form: 'long', type: 'version_negotiation',
        version: version, dcid: dcid, scid: scid,
        supportedVersions: supportedVersions,
        totalLength: offset - offset0
      };
    }

    // What the type bits mean is the version's (RFC 9369 §3.2). A version
    // this side does not speak has no known layout past the connection IDs:
    // what is known is enough to answer it with Version Negotiation.
    var packetType = longPacketType(version, (firstByte & 0x30) >> 4);
    if (!packetType) {
      return {
        form: 'long', type: 'unknown',
        version: version, dcid: dcid, scid: scid,
        totalLength: array.length - offset0
      };
    }

    if (packetType === 'retry') {
      return {
        form: 'long', type: 'retry',
        version: version, dcid: dcid, scid: scid,
        totalLength: array.length - offset0
      };
    }

    // Initial: read token
    var token = null;
    if (packetType === 'initial') {
      try {
        var tokenLen = readVarInt(array, offset);
        offset += tokenLen.byteLength;
        if (offset + tokenLen.value > array.length) return null;
        token = array.slice(offset, offset + tokenLen.value);
        offset += tokenLen.value;
      } catch (e) { return null; }
    }

    // Length field
    try {
      var lengthInfo = readVarInt(array, offset);
      offset += lengthInfo.byteLength;
      var totalLength = offset - offset0 + lengthInfo.value;
      if (offset0 + totalLength > array.length) return null;

      return {
        form: 'long', type: packetType,
        version: version, dcid: dcid, scid: scid, token: token,
        totalLength: totalLength
      };
    } catch (e) { return null; }

  } else {
    // Short Header. Its fixed bit ("QUIC bit", 0x40) is not checked: every
    // connection here advertises grease_quic_bit (RFC 9287), which lets the
    // peer send it as 0. Bytes that are not a packet — zeros padding a
    // datagram after its packets — fail decryption like any other garbage.
    var shortPkt = {
      form: 'short', type: '1rtt',
      totalLength: array.length - offset0
    };
    if (shortCidLen > 0) {
      if (offset0 + 1 + shortCidLen > array.length) return null;
      shortPkt.dcid = array.slice(offset0 + 1, offset0 + 1 + shortCidLen);
    }
    return shortPkt;
  }
}


/**
 * Split a UDP datagram into QUIC packets. shortCidLen: see parse_quic_packet.
 */
function parse_quic_datagram(array, shortCidLen) {
  var packets = [];
  var offset = 0;

  while (offset < array.length) {
    var pkt = parse_quic_packet(array, offset, shortCidLen);
    if (!pkt || !pkt.totalLength) break;

    var start = offset;
    var end = offset + pkt.totalLength;

    pkt.raw = (start === 0 && end === array.length)
      ? array
      : array.slice(start, end);

    if (packets.length > 0) {
      if (DEBUG) console.log('[quic] coalesced pkt #' + packets.length + ' type=' + pkt.type + ' offset=' + start + ' len=' + pkt.totalLength + ' firstByte=0x' + array[start].toString(16).padStart(2,'0'));
    }

    packets.push(pkt);
    offset = end;
  }

  return packets;
}


// ============================================================
//  Version Negotiation (RFC 9000 §6, §17.2.1)
// ============================================================

/**
 * Is this a version we can handle? (quic_version.js has them.)
 * Version 0 identifies a Version Negotiation packet, not a real version.
 */
function is_supported_version(version) {
  return isSupportedVersion(version);
}

/**
 * Build a Version Negotiation packet (RFC 9000 §17.2.1).
 *
 * A server MUST send one when it receives a long-header packet carrying a
 * version it does not support — it is how a client discovers what the server
 * speaks, and how any QUIC prober checks whether a server is alive without
 * completing a handshake. The interop runner's simulator does exactly that
 * before starting a test, so without this the server looks dead.
 *
 * The packet is unusual: no encryption, no packet number, no frames, and no
 * connection state. It is valid only as an immediate response.
 *
 * IMPORTANT: the connection IDs are swapped. The DCID we send is the SCID we
 * received, and vice versa — the client matches the reply against its own
 * Source CID, so getting this backwards makes the packet be ignored.
 *
 *   byte 0    1 (long header) + 7 unpredictable bits
 *   1..4      version 0x00000000
 *   5         DCID length, then DCID
 *   ...       SCID length, then SCID
 *   ...       list of supported versions, 4 bytes each
 *
 * @param {Uint8Array} recvDcid  DCID from the client's packet (becomes our SCID)
 * @param {Uint8Array} recvScid  SCID from the client's packet (becomes our DCID)
 * @param {number[]} [versions]  the versions offered (the server's, in its
 *                               preference); every supported one by default
 */
function build_version_negotiation(recvDcid, recvScid, offered) {
  var dcid = recvScid || new Uint8Array(0);
  var scid = recvDcid || new Uint8Array(0);

  // RFC 9000 §17.2.1: the low 7 bits are unused and SHOULD be random, so that
  // clients don't come to depend on a fixed value.
  var first = 0x80 | (Math.floor(Math.random() * 128) & 0x7f);

  var versions = (offered || SUPPORTED_VERSIONS).slice();

  // A reserved ("greased") version, per RFC 9000 §6.3. Its pattern is
  // 0x?a?a?a?a, and no endpoint will ever support it. Including one keeps
  // clients honest: any client that assumes it understands every version in
  // the list will break here rather than in the field.
  var grease = ((Math.floor(Math.random() * 16) << 28) |
                (0x0a << 24) |
                (Math.floor(Math.random() * 16) << 20) |
                (0x0a << 16) |
                (Math.floor(Math.random() * 16) << 12) |
                (0x0a << 8) |
                (Math.floor(Math.random() * 16) << 4) |
                0x0a) >>> 0;
  versions.push(grease);

  var out = new Uint8Array(1 + 4 + 1 + dcid.length + 1 + scid.length + versions.length * 4);
  var o = 0;

  out[o++] = first;
  out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;   // version 0

  out[o++] = dcid.length;
  out.set(dcid, o); o += dcid.length;

  out[o++] = scid.length;
  out.set(scid, o); o += scid.length;

  for (var i = 0; i < versions.length; i++) {
    var v = versions[i] >>> 0;
    out[o++] = (v >>> 24) & 0xff;
    out[o++] = (v >>> 16) & 0xff;
    out[o++] = (v >>> 8) & 0xff;
    out[o++] = v & 0xff;
  }

  return out;
}


// ============================================================
//  QUIC Frame encoding (RFC 9000 §12.4)
// ============================================================

// ---- Sizes and in-place writing, for the frames every packet carries ----
//
// A packet's frames were encoded one by one (each frame's pieces joined),
// then all joined: the stream data was copied twice before encryption — and
// sendFrames encoded whole packets once or twice more only to learn their
// size. The frames that carry data (STREAM, CRYPTO, DATAGRAM) and those in
// most packets (ACK, PADDING, PING) are now measured without encoding and
// written straight into one buffer; the rest, rare and small, as before.

function varIntSize(v) { return v < 0x40 ? 1 : v < 0x4000 ? 2 : v < 0x40000000 ? 4 : 8; }

function writeVarIntInto(buf, off, v) {
  if (v < 0x40) { buf[off] = v; return off + 1; }
  if (v < 0x4000) { buf[off] = 0x40 | (v >> 8); buf[off + 1] = v & 0xff; return off + 2; }
  if (v < 0x40000000) {
    buf[off] = 0x80 | (v >>> 24); buf[off + 1] = (v >>> 16) & 0xff; buf[off + 2] = (v >>> 8) & 0xff; buf[off + 3] = v & 0xff;
    return off + 4;
  }
  var w = writeVarInt(v);
  buf.set(w, off);
  return off + w.length;
}

function hotFrameSize(f) {
  var t = f.type;
  if (t === 'stream') {
    var n = (f.data && f.data.length) ? f.data.length : 0;
    return 1 + varIntSize(f.id) + ((f.offset != null && f.offset > 0) ? varIntSize(f.offset) : 0) + varIntSize(n) + n;
  }
  if (t === 'crypto') return 1 + varIntSize(f.offset) + varIntSize(f.data.length) + f.data.length;
  if (t === 'datagram') return 1 + varIntSize(f.data.byteLength) + f.data.byteLength;
  if (t === 'padding') return f.length;
  if (t === 'ping') return 1;
  if (t === 'ack') {
    var sz = 1 + varIntSize(f.largest) + varIntSize(f.delay) + varIntSize(f.ranges.length) + varIntSize(f.firstRange != null ? f.firstRange : 0);
    for (var j = 0; j < f.ranges.length; j++) sz += varIntSize(f.ranges[j].gap) + varIntSize(f.ranges[j].length);
    if (f.ecn !== null && f.ecn !== undefined) sz += varIntSize(f.ecn.ect0) + varIntSize(f.ecn.ect1) + varIntSize(f.ecn.ce);
    return sz;
  }
  return -1;
}

// What encode_quic_frames(frames) would be, in bytes — without encoding.
function quic_frames_size(frames) {
  var total = 0;
  for (var i = 0; i < frames.length; i++) {
    var sz = hotFrameSize(frames[i]);
    total += sz >= 0 ? sz : encode_quic_frames_each([frames[i]]).length;
  }
  return total;
}

function writeHotFrame(f, out, off) {
  var t = f.type;
  if (t === 'stream') {
    var data = f.data || null, n = data ? data.length : 0;
    var hasOffset = (f.offset != null && f.offset > 0);
    // LEN always present (see encode_quic_frames_each).
    out[off++] = 0x08 | 0x02 | (hasOffset ? 0x04 : 0) | (f.fin ? 0x01 : 0);
    off = writeVarIntInto(out, off, f.id);
    if (hasOffset) off = writeVarIntInto(out, off, f.offset);
    off = writeVarIntInto(out, off, n);
    if (n) { out.set(data, off); off += n; }
    return off;
  }
  if (t === 'crypto') {
    out[off++] = 0x06;
    off = writeVarIntInto(out, off, f.offset);
    off = writeVarIntInto(out, off, f.data.length);
    out.set(f.data, off);
    return off + f.data.length;
  }
  if (t === 'datagram') {
    out[off++] = 0x31;
    off = writeVarIntInto(out, off, f.data.byteLength);
    out.set(f.data, off);
    return off + f.data.byteLength;
  }
  if (t === 'padding') return off + f.length;            // zeros: the buffer is new
  if (t === 'ping') { out[off] = 0x01; return off + 1; }
  // ack
  var hasECN = f.ecn !== null && f.ecn !== undefined;
  out[off++] = hasECN ? 0x03 : 0x02;
  off = writeVarIntInto(out, off, f.largest);
  off = writeVarIntInto(out, off, f.delay);
  off = writeVarIntInto(out, off, f.ranges.length);
  off = writeVarIntInto(out, off, f.firstRange != null ? f.firstRange : 0);
  for (var j = 0; j < f.ranges.length; j++) {
    off = writeVarIntInto(out, off, f.ranges[j].gap);
    off = writeVarIntInto(out, off, f.ranges[j].length);
  }
  if (hasECN) {
    off = writeVarIntInto(out, off, f.ecn.ect0);
    off = writeVarIntInto(out, off, f.ecn.ect1);
    off = writeVarIntInto(out, off, f.ecn.ce);
  }
  return off;
}

// A packet's frames, encoded into one buffer: each byte of data copied once.
// `extra` zero bytes after them (PADDING), so a caller that pads need not
// copy the whole again.
function encode_quic_frames(frames, extra) {
  var sizes = new Array(frames.length), rare = null, total = 0;
  for (var i = 0; i < frames.length; i++) {
    var sz = hotFrameSize(frames[i]);
    if (sz < 0) {
      if (!rare) rare = {};
      rare[i] = encode_quic_frames_each([frames[i]]);
      sz = rare[i].length;
    }
    sizes[i] = sz;
    total += sz;
  }
  var out = new Uint8Array(total + (extra > 0 ? extra : 0));
  var off = 0;
  for (var k = 0; k < frames.length; k++) {
    if (rare && rare[k]) { out.set(rare[k], off); off += rare[k].length; }
    else off = writeHotFrame(frames[k], out, off);
  }
  return out;
}

// Each frame on its own, then joined — every frame type; what the rare ones
// still go through (and the reference the fast path is tested against).
function encode_quic_frames_each(frames) {
  var parts = [];

  for (var i = 0; i < frames.length; i++) {
    var frame = frames[i];

    if (frame.type === 'padding') {
      parts.push(new Uint8Array(frame.length));

    } else if (frame.type === 'ping') {
      parts.push(new Uint8Array([0x01]));

    } else if (frame.type === 'ack') {
      var hasECN = frame.ecn !== null && frame.ecn !== undefined;
      var typeByte = hasECN ? 0x03 : 0x02;
      var temp = [
        new Uint8Array([typeByte]),
        writeVarInt(frame.largest),
        writeVarInt(frame.delay),
        writeVarInt(frame.ranges.length),
        writeVarInt(frame.firstRange != null ? frame.firstRange : 0)
      ];
      for (var j = 0; j < frame.ranges.length; j++) {
        temp.push(writeVarInt(frame.ranges[j].gap));
        temp.push(writeVarInt(frame.ranges[j].length));
      }
      if (hasECN) {
        temp.push(writeVarInt(frame.ecn.ect0));
        temp.push(writeVarInt(frame.ecn.ect1));
        temp.push(writeVarInt(frame.ecn.ce));
      }
      parts.push(concatUint8Arrays(temp));

    } else if (frame.type === 'crypto') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x06]),
        writeVarInt(frame.offset),
        writeVarInt(frame.data.length),
        frame.data
      ]));

    } else if (frame.type === 'stream') {
      var typeByte = 0x08;
      var hasOffset = (frame.offset != null && frame.offset > 0);
      var hasFin = !!frame.fin;
      var dataLen = (frame.data && frame.data.length) ? frame.data.length : 0;

      // ALWAYS emit the LEN field. A STREAM frame without the LEN bit means
      // "data runs to the end of the packet"; if anything follows it in the
      // packet (another frame — e.g. a zero-length FIN-only batched with
      // others — or padding), the peer reads those trailing bytes as stream
      // data and the offset overshoots the declared final size
      // (FINAL_SIZE / PROTOCOL_VIOLATION 0xa). An explicit length is always
      // safe and self-delimiting.
      if (hasOffset) typeByte |= 0x04;
      typeByte |= 0x02; // LEN — always present
      if (hasFin) typeByte |= 0x01;

      parts.push(concatUint8Arrays([
        new Uint8Array([typeByte]),
        writeVarInt(frame.id),
        hasOffset ? writeVarInt(frame.offset) : new Uint8Array(0),
        writeVarInt(dataLen),
        frame.data || new Uint8Array(0)
      ]));

    } else if (frame.type === 'new_token') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x07]),
        writeVarInt(frame.token.length),
        frame.token
      ]));

    } else if (frame.type === 'max_data') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x10]),
        writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'max_stream_data') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x11]),
        writeVarInt(frame.id),
        writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'max_streams_bidi') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x12]),
        writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'max_streams_uni') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x13]),
        writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'connection_close') {
      var code = frame.application ? 0x1d : 0x1c;
      var errorCode = writeVarInt(frame.error || 0);
      var frameType = frame.application ? new Uint8Array(0) : writeVarInt(frame.frameType || 0);
      var reason = new TextEncoder().encode(frame.reason || '');
      parts.push(concatUint8Arrays([
        new Uint8Array([code]),
        errorCode,
        frameType,
        writeVarInt(reason.length),
        reason
      ]));

    } else if (frame.type === 'handshake_done') {
      parts.push(new Uint8Array([0x1e]));

    } else if (frame.type === 'immediate_ack') {
      // draft-ietf-quic-ack-frequency §5
      parts.push(new Uint8Array([0x1f]));

    } else if (frame.type === 'ack_frequency') {
      // draft-ietf-quic-ack-frequency §4: Sequence Number, Ack-Eliciting
      // Threshold, Requested Max Ack Delay (µs), Reordering Threshold.
      parts.push(concatUint8Arrays([
        writeVarInt(0xaf),
        writeVarInt(frame.seq),
        writeVarInt(frame.threshold),
        writeVarInt(frame.maxDelayUs),
        writeVarInt(frame.reorder)
      ]));

    } else if (frame.type === 'new_connection_id') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x18]),
        writeVarInt(frame.seq),
        writeVarInt(frame.retire),
        new Uint8Array([frame.connId.length]),
        frame.connId,
        frame.token
      ]));

    } else if (frame.type === 'retire_connection_id') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x19]),
        writeVarInt(frame.seq)
      ]));

    } else if (frame.type === 'path_challenge' || frame.type === 'path_response') {
      parts.push(concatUint8Arrays([
        new Uint8Array([frame.type === 'path_challenge' ? 0x1a : 0x1b]),
        frame.data
      ]));

    } else if (frame.type === 'reset_stream') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x04]),
        writeVarInt(frame.id),
        writeVarInt(frame.error),
        writeVarInt(frame.finalSize)
      ]));

    } else if (frame.type === 'reset_stream_at') {
      // RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset §4): a reset
      // that keeps the stream's first reliableSize bytes delivered.
      parts.push(concatUint8Arrays([
        new Uint8Array([0x24]),
        writeVarInt(frame.id),
        writeVarInt(frame.error),
        writeVarInt(frame.finalSize),
        writeVarInt(frame.reliableSize)
      ]));

    } else if (frame.type === 'stop_sending') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x05]),
        writeVarInt(frame.id),
        writeVarInt(frame.error)
      ]));

    } else if (frame.type === 'data_blocked') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x14]),
        writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'streams_blocked_bidi' || frame.type === 'streams_blocked_uni') {
      parts.push(concatUint8Arrays([
        new Uint8Array([frame.type === 'streams_blocked_bidi' ? 0x16 : 0x17]),
        writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'stream_data_blocked') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x15]),
        writeVarInt(frame.id),
        writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'datagram') {
      // The 0x31 form, with a Length: datagrams share packets with each other
      // and with stream data now (execute_quic_burst), so one is not always
      // the last frame, which the 0x30 form requires. (The parser accepts
      // both forms on receive.)
      parts.push(concatUint8Arrays([
        new Uint8Array([0x31]),
        writeVarInt(frame.data.byteLength),
        frame.data
      ]));
    }
  }

  return parts.length === 1 ? parts[0] : concatUint8Arrays(parts);
}


// ============================================================
//  QUIC Frame parsing (RFC 9000 §12.4)
// ============================================================

function parse_quic_frames(buf) {
  var offset = 0;
  var frames = [];

  function safeReadVarInt() {
    if (offset >= buf.length) return null;
    var res = readVarInt(buf, offset);
    if (!res) return null;
    offset += res.byteLength;
    return res;
  }

  // A frame that ends before its fields do — every `break` below but the
  // unknown type's — is reported as { type: 'malformed' }, last: the frames
  // before it stand, and the connection closes with FRAME_ENCODING_ERROR
  // (RFC 9000 §12.4, §19). Dropped silently, as it was, a truncated frame
  // was simply not there, and the packet acknowledged all the same.
  var whole = true;
  while (offset < buf.length) {
    whole = false;
    var type = buf[offset++];

    // Multi-byte frame type: a varint of two bytes or more (RFC 9000 §12.4
    // — a type is a varint like any other). Only 4- and 8-byte ones were
    // read as such; a 2-byte one (0x40..0x3fff: ACK_FREQUENCY is 0xaf) was
    // read as its first byte.
    if (type >= 0x40) {
      offset--;
      var t = safeReadVarInt();
      if (!t) break;
      type = t.value;
    }

    if (type === 0x00) {
      // PADDING — skip. Noted, so a packet of PADDING alone is told apart
      // from one with no frames (RFC 9000 §12.4).
      frames.padding = true;
    } else if (type === 0x01) {
      frames.push({ type: 'ping' });

    } else if ((type & 0xfe) === 0x02) {
      var hasECN = (type & 0x01) === 1;
      var largest = safeReadVarInt(); if (!largest) break;
      var delay = safeReadVarInt(); if (!delay) break;
      var rangeCount = safeReadVarInt(); if (!rangeCount) break;
      var firstRange = safeReadVarInt(); if (!firstRange) break;

      var ranges = [];
      for (var i = 0; i < rangeCount.value; i++) {
        var gap = safeReadVarInt(); if (!gap) break;
        var len = safeReadVarInt(); if (!len) break;
        ranges.push({ gap: gap.value, length: len.value });
      }
      if (ranges.length !== rangeCount.value) break;

      var ecn = null;
      if (hasECN) {
        var ect0 = safeReadVarInt(); if (!ect0) break;
        var ect1 = safeReadVarInt(); if (!ect1) break;
        var ce = safeReadVarInt(); if (!ce) break;
        ecn = { ect0: ect0.value, ect1: ect1.value, ce: ce.value };
      }

      frames.push({
        type: 'ack', largest: largest.value, delay: delay.value,
        firstRange: firstRange.value, ranges: ranges, ecn: ecn
      });

    } else if (type === 0x04) {
      var id = safeReadVarInt(); if (!id) break;
      var error = safeReadVarInt(); if (!error) break;
      var finalSize = safeReadVarInt(); if (!finalSize) break;
      frames.push({ type: 'reset_stream', id: id.value, error: error.value, finalSize: finalSize.value });

    } else if (type === 0x24) {
      var id = safeReadVarInt(); if (!id) break;
      var error = safeReadVarInt(); if (!error) break;
      var finalSize = safeReadVarInt(); if (!finalSize) break;
      var reliableSize = safeReadVarInt(); if (!reliableSize) break;
      frames.push({ type: 'reset_stream_at', id: id.value, error: error.value, finalSize: finalSize.value, reliableSize: reliableSize.value });

    } else if (type === 0x05) {
      var id = safeReadVarInt(); if (!id) break;
      var error = safeReadVarInt(); if (!error) break;
      frames.push({ type: 'stop_sending', id: id.value, error: error.value });

    } else if (type === 0x06) {
      var off = safeReadVarInt(); if (!off) break;
      var len = safeReadVarInt(); if (!len) break;
      if (offset + len.value > buf.length) break;
      var data = buf.slice(offset, offset + len.value); offset += len.value;
      frames.push({ type: 'crypto', offset: off.value, data: data });

    } else if (type === 0x07) {
      var len = safeReadVarInt(); if (!len) break;
      if (offset + len.value > buf.length) break;
      var token = buf.slice(offset, offset + len.value); offset += len.value;
      frames.push({ type: 'new_token', token: token });

    } else if (type >= 0x08 && type <= 0x0f) {
      var fin = !!(type & 0x01);
      var lenb = !!(type & 0x02);
      var offb = !!(type & 0x04);

      var stream_id = safeReadVarInt(); if (!stream_id) break;
      var offset_val = offb ? safeReadVarInt() : { value: 0 }; if (!offset_val) break;
      var length_val = lenb ? safeReadVarInt() : { value: buf.length - offset }; if (!length_val) break;
      if (offset + length_val.value > buf.length) break;

      var data = buf.slice(offset, offset + length_val.value); offset += length_val.value;
      frames.push({
        type: 'stream', id: stream_id.value,
        offset: offset_val.value, fin: fin, data: data
      });

    } else if (type === 0x10) {
      var max = safeReadVarInt(); if (!max) break;
      frames.push({ type: 'max_data', max: max.value });

    } else if (type === 0x11) {
      var id = safeReadVarInt(); if (!id) break;
      var max = safeReadVarInt(); if (!max) break;
      frames.push({ type: 'max_stream_data', id: id.value, max: max.value });

    } else if (type === 0x12 || type === 0x13) {
      var max = safeReadVarInt(); if (!max) break;
      frames.push({ type: type === 0x12 ? 'max_streams_bidi' : 'max_streams_uni', max: max.value });

    } else if (type === 0x14) {
      var limit = safeReadVarInt(); if (!limit) break;
      frames.push({ type: 'data_blocked', limit: limit.value });

    } else if (type === 0x15) {
      var id = safeReadVarInt(); if (!id) break;
      var limit = safeReadVarInt(); if (!limit) break;
      frames.push({ type: 'stream_data_blocked', id: id.value, limit: limit.value });

    } else if (type === 0x16 || type === 0x17) {
      var limit = safeReadVarInt(); if (!limit) break;
      frames.push({ type: type === 0x16 ? 'streams_blocked_bidi' : 'streams_blocked_uni', limit: limit.value });

    } else if (type === 0x18) {
      var seq = safeReadVarInt(); if (!seq) break;
      var retire = safeReadVarInt(); if (!retire) break;
      if (offset >= buf.length) break;
      var cidLen = buf[offset++];
      if (offset + cidLen + 16 > buf.length) break;
      var connId = buf.slice(offset, offset + cidLen); offset += cidLen;
      var token = buf.slice(offset, offset + 16); offset += 16;
      frames.push({ type: 'new_connection_id', seq: seq.value, retire: retire.value, connId: connId, token: token });

    } else if (type === 0x19) {
      var seq = safeReadVarInt(); if (!seq) break;
      frames.push({ type: 'retire_connection_id', seq: seq.value });

    } else if (type === 0x1a || type === 0x1b) {
      if (offset + 8 > buf.length) break;
      var data = buf.slice(offset, offset + 8); offset += 8;
      frames.push({ type: type === 0x1a ? 'path_challenge' : 'path_response', data: data });

    } else if (type === 0x1c || type === 0x1d) {
      var error = safeReadVarInt(); if (!error) break;
      var frameType = null;
      if (type === 0x1c) {
        var ft = safeReadVarInt(); if (!ft) break;
        frameType = ft.value;
      }
      var reasonLen = safeReadVarInt(); if (!reasonLen) break;
      if (offset + reasonLen.value > buf.length) break;
      var reason = new TextDecoder().decode(buf.slice(offset, offset + reasonLen.value));
      offset += reasonLen.value;
      frames.push({
        type: 'connection_close', application: type === 0x1d,
        error: error.value, frameType: frameType, reason: reason
      });

    } else if (type === 0x1e) {
      frames.push({ type: 'handshake_done' });

    } else if (type === 0x1f) {
      frames.push({ type: 'immediate_ack' });

    } else if (type === 0xaf) {
      var afSeq = safeReadVarInt(); if (!afSeq) break;
      var afThr = safeReadVarInt(); if (!afThr) break;
      var afDelay = safeReadVarInt(); if (!afDelay) break;
      var afReorder = safeReadVarInt(); if (!afReorder) break;
      frames.push({ type: 'ack_frequency', seq: afSeq.value, threshold: afThr.value, maxDelayUs: afDelay.value, reorder: afReorder.value });

    } else if (type === 0x30 || type === 0x31) {
      // RFC 9221 DATAGRAM frame. The 0x31 form carries an explicit Length
      // varint and the datagram data is exactly that many bytes; the 0x30 form
      // has no Length and the data runs to the end of the packet (so a 0x30
      // DATAGRAM must be the last frame). The optional field is a Length — not
      // a "context ID" (that draft-era concept was removed before RFC 9221).
      var data;
      if (type === 0x31) {
        var len = safeReadVarInt(); if (!len) break;
        var end = offset + len.value;
        if (end > buf.length) break; // truncated / invalid length
        data = buf.slice(offset, end); offset = end;
      } else {
        data = buf.slice(offset); offset = buf.length;
      }
      frames.push({ type: 'datagram', data: data });

    } else {
      // Unknown frame — stop: its length is not known, so nothing after it
      // can be read. FRAME_ENCODING_ERROR (§12.4), the connection's to send.
      frames.push({ type: 'unknown', frameType: type });
      return frames;
    }
    whole = true;
  }
  if (!whole) frames.push({ type: 'malformed', frameType: type });

  return frames;
}


// ============================================================
//  Transport Parameters (RFC 9000 §18)
// ============================================================

function build_transport_params(params) {
  var out = [];

  function addParam(id, value) {
    var idBytes = writeVarInt(id);
    var valueBytes;

    if (typeof value === 'number') {
      valueBytes = writeVarInt(value);
    } else if (value instanceof Uint8Array) {
      valueBytes = Array.from(value);
    } else if (value === true) {
      valueBytes = [];
    } else {
      throw new Error('Unsupported param value type for id ' + id);
    }

    var lengthBytes = writeVarInt(valueBytes.length);
    out.push.apply(out, Array.from(idBytes));
    out.push.apply(out, Array.from(lengthBytes));
    out.push.apply(out, valueBytes);
  }

  if (params.original_destination_connection_id)
    addParam(0x00, params.original_destination_connection_id);
  if (params.max_idle_timeout)
    addParam(0x01, params.max_idle_timeout);
  if (params.stateless_reset_token)
    addParam(0x02, params.stateless_reset_token);
  if (params.max_udp_payload_size)
    addParam(0x03, params.max_udp_payload_size);
  if (params.initial_max_data)
    addParam(0x04, params.initial_max_data);
  if (params.initial_max_stream_data_bidi_local)
    addParam(0x05, params.initial_max_stream_data_bidi_local);
  if (params.initial_max_stream_data_bidi_remote)
    addParam(0x06, params.initial_max_stream_data_bidi_remote);
  if (params.initial_max_stream_data_uni)
    addParam(0x07, params.initial_max_stream_data_uni);
  if (params.initial_max_streams_bidi)
    addParam(0x08, params.initial_max_streams_bidi);
  if (params.initial_max_streams_uni)
    addParam(0x09, params.initial_max_streams_uni);
  if (params.ack_delay_exponent !== undefined)
    addParam(0x0a, params.ack_delay_exponent);
  if (params.max_ack_delay !== undefined)
    addParam(0x0b, params.max_ack_delay);
  if (params.disable_active_migration)
    addParam(0x0c, true);
  if (params.active_connection_id_limit)
    addParam(0x0e, params.active_connection_id_limit);
  if (params.initial_source_connection_id)
    addParam(0x0f, params.initial_source_connection_id);
  if (params.retry_source_connection_id)
    addParam(0x10, params.retry_source_connection_id);
  if (params.max_datagram_frame_size)
    addParam(0x20, params.max_datagram_frame_size);
  // reset_stream_at (draft-ietf-quic-reliable-stream-reset §3): empty; this
  // side takes RESET_STREAM_AT.
  if (params.reset_stream_at)
    addParam(0x1d, true);
  // version_information (RFC 9368 §3): Chosen Version, then the Available
  // Versions, 32 bits each.
  if (params.version_information) {
    var vi = params.version_information;
    var list = [vi.chosen].concat(vi.available || []);
    var vb = new Uint8Array(list.length * 4);
    for (var i = 0; i < list.length; i++) {
      var v = list[i] >>> 0;
      vb[i * 4] = (v >>> 24) & 0xff; vb[i * 4 + 1] = (v >>> 16) & 0xff;
      vb[i * 4 + 2] = (v >>> 8) & 0xff; vb[i * 4 + 3] = v & 0xff;
    }
    addParam(0x11, vb);
  }
  // grease_quic_bit (RFC 9287): the peer may send the fixed bit as 0.
  if (params.grease_quic_bit)
    addParam(0x2ab2, true);
  // min_ack_delay (draft-ietf-quic-ack-frequency §3), µs: this side takes
  // ACK_FREQUENCY and IMMEDIATE_ACK.
  if (params.min_ack_delay !== undefined)
    addParam(0xff04de1b, params.min_ack_delay);

  return new Uint8Array(out);
}


// Transport parameters whose value is a byte string rather than a number
// (RFC 9000 §18.2). Their contents are per-connection random; only their
// length is a stable property of the sender.
var OPAQUE_PARAMS = {
  0x00: 1,   // original_destination_connection_id
  0x02: 1,   // stateless_reset_token
  0x0d: 1,   // preferred_address
  0x0f: 1,   // initial_source_connection_id
  0x10: 1    // retry_source_connection_id
};

// version_information (RFC 9368 §3) → { chosen, available: [...] }, or
// 'invalid' — shorter than one version, not a whole number of them, or a
// zero version among them (§4: closed with a TRANSPORT_PARAMETER_ERROR).
function parseVersionInformation(bytes) {
  if (bytes.length < 4 || bytes.length % 4 !== 0) return 'invalid';
  var list = [];
  for (var i = 0; i < bytes.length; i += 4) {
    var v = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    if (v === 0) return 'invalid';
    list.push(v);
  }
  return { chosen: list[0], available: list.slice(1) };
}

// preferred_address (RFC 9000 §18.2): IPv4 address and port, IPv6 address
// and port, a connection ID (1-20 bytes — "a server MUST NOT include a
// zero-length connection ID"), its stateless reset token. Anything else:
// null, malformed.
function parsePreferredAddress(b) {
  if (b.length < 4 + 2 + 16 + 2 + 1 + 16) return null;
  var cidLen = b[24];
  if (cidLen < 1 || cidLen > 20 || b.length !== 25 + cidLen + 16) return null;
  return {
    ipv4: b.slice(0, 4), ipv4Port: (b[4] << 8) | b[5],
    ipv6: b.slice(6, 22), ipv6Port: (b[22] << 8) | b[23],
    connectionId: b.slice(25, 25 + cidLen),
    statelessResetToken: b.slice(25 + cidLen)
  };
}

// The largest a stream count may be (RFC 9000 §4.6, §18.2): 2^60. Read
// exactly, not through a Number — 2^60 + 1 and 2^60 are one Number.
var MAX_STREAMS_LIMIT = 1n << 60n;
function streamCountTooLarge(bytes) {
  if (bytes.length !== 8 || (bytes[0] >> 6) !== 3) return false;
  var v = BigInt(bytes[0] & 0x3f);
  for (var i = 1; i < 8; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v > MAX_STREAMS_LIMIT;
}

function quietInt(bytes) { var r = readVarInt(bytes, 0); return r ? r.value : 0; }

function parse_transport_params(buf, start) {
  if (!(buf instanceof Uint8Array)) throw new Error('Expect Uint8Array');
  var offset = start || 0;
  var end = buf.length;
  var out = {};
  // The first reason the parameters are malformed, if they are (RFC 9000
  // §7.4: a TRANSPORT_PARAMETER_ERROR) — on a non-enumerable property, like
  // _ordered: the connection decides. Truncated, an identifier twice, an
  // integer whose varint does not fill the value exactly, a value out of
  // the range §18.2 gives it.
  var invalid = null;
  function bad(why) { if (!invalid) invalid = why; }
  var seen = new Set();
  // The parameters again in the order sent, on a non-enumerable property so
  // nothing that iterates the result is affected. Both order and unknown
  // identifiers are lost by the object form, and both are fingerprintable
  // properties of the peer's implementation.
  var ordered = [];

  // An integer parameter (§18): one varint that fills the value exactly.
  // Empty, short or with bytes left over: malformed (and read as 0).
  function viOf(id, bytes) {
    var r = readVarInt(bytes, 0);
    if (!r || r.byteLength !== bytes.length) { bad('parameter 0x' + id.toString(16) + ' is not one integer'); return 0; }
    return r.value;
  }
  function cidOf(id, bytes) {
    if (bytes.length > 20) bad('parameter 0x' + id.toString(16) + ': a connection ID longer than 20 bytes');
    return bytes;
  }

  while (offset < end) {
    var idVar = readVarInt(buf, offset);
    if (!idVar) { bad('truncated'); break; }
    offset += idVar.byteLength;

    var lenVar = readVarInt(buf, offset);
    if (!lenVar) { bad('truncated'); break; }
    offset += lenVar.byteLength;

    if (offset + lenVar.value > end) { bad('truncated'); break; }
    var valueBytes = buf.slice(offset, offset + lenVar.value);
    offset += lenVar.value;

    var id = idVar.value;
    // §7.4: "An endpoint SHOULD treat receipt of duplicate transport
    // parameters as a connection error" — unknown ones too.
    if (seen.has(id)) bad('parameter 0x' + id.toString(16) + ' twice');
    seen.add(id);

    var vi = function (bytes) { return viOf(id, bytes); };
    var cid = function (bytes) { return cidOf(id, bytes); };

    switch (id) {
      case 0x00: out.original_destination_connection_id = cid(valueBytes); break;
      case 0x01: out.max_idle_timeout = vi(valueBytes); break;
      case 0x02:
        if (valueBytes.length !== 16) bad('stateless_reset_token of ' + valueBytes.length + ' bytes');
        out.stateless_reset_token = valueBytes;
        break;
      case 0x03:
        // "Values below 1200 are invalid."
        out.max_udp_payload_size = vi(valueBytes);
        if (out.max_udp_payload_size < 1200) bad('max_udp_payload_size below 1200');
        break;
      case 0x04: out.initial_max_data = vi(valueBytes); break;
      case 0x05: out.initial_max_stream_data_bidi_local = vi(valueBytes); break;
      case 0x06: out.initial_max_stream_data_bidi_remote = vi(valueBytes); break;
      case 0x07: out.initial_max_stream_data_uni = vi(valueBytes); break;
      case 0x08:
      case 0x09:
        // "...cannot exceed 2^60, as it is not possible to encode stream
        // IDs larger than 2^62-1" (§18.2).
        var sname = id === 0x08 ? 'initial_max_streams_bidi' : 'initial_max_streams_uni';
        if (streamCountTooLarge(valueBytes)) bad(sname + ' above 2^60');
        out[sname] = vi(valueBytes);
        break;
      case 0x0a:
        // "Values above 20 are invalid."
        out.ack_delay_exponent = vi(valueBytes);
        if (out.ack_delay_exponent > 20) bad('ack_delay_exponent above 20');
        break;
      case 0x0b:
        // "Values of 2^14 or greater are invalid."
        out.max_ack_delay = vi(valueBytes);
        if (out.max_ack_delay >= 16384) bad('max_ack_delay of 2^14 or more');
        break;
      case 0x0c:
        // "This parameter is a zero-length value."
        if (valueBytes.length !== 0) bad('disable_active_migration with a value');
        out.disable_active_migration = true;
        break;
      case 0x0d:
        out.preferred_address = parsePreferredAddress(valueBytes);
        if (!out.preferred_address) bad('preferred_address malformed');
        break;
      case 0x0e:
        // "The value ... MUST be at least 2."
        out.active_connection_id_limit = vi(valueBytes);
        if (out.active_connection_id_limit < 2) bad('active_connection_id_limit below 2');
        break;
      case 0x0f: out.initial_source_connection_id = cid(valueBytes); break;
      case 0x10: out.retry_source_connection_id = cid(valueBytes); break;
      case 0x20: out.max_datagram_frame_size = vi(valueBytes); break;
      case 0x1d:
        // reset_stream_at: "a value ... MUST be treated as a connection
        // error of type TRANSPORT_PARAMETER_ERROR".
        if (valueBytes.length !== 0) bad('reset_stream_at with a value');
        out.reset_stream_at = true;
        break;
      case 0x11: out.version_information = parseVersionInformation(valueBytes); break;
      case 0xff04de1b: out.min_ack_delay = vi(valueBytes); break;
      case 0x2ab2:
        // RFC 9287 §3: a value is a TRANSPORT_PARAMETER_ERROR; noted, the
        // connection decides.
        out.grease_quic_bit = valueBytes.length === 0 ? true : 'invalid';
        break;
      default:
        if (!out.unknown) out.unknown = [];
        out.unknown.push({ id: id, bytes: valueBytes });
    }

    // Recorded for every parameter, known or not.
    //
    // OPAQUE parameters are recorded by LENGTH, never by content: connection
    // ids, stateless-reset tokens and preferred-address blobs are freshly
    // random on every connection, so hashing their contents produces a
    // fingerprint that never repeats. Their length, on the other hand, is a
    // property of the implementation and is exactly what should be captured.
    //
    // Chosen by identifier rather than by size, which was the first attempt
    // and was wrong: an 8-byte connection id is short enough to look like a
    // number, so a length test silently let it through and the fingerprint
    // changed on every connection. Which parameters are opaque is fixed by
    // RFC 9000 §18.2, so it can simply be listed.
    ordered.push({
      id: id,
      value: OPAQUE_PARAMS[id] ? ('L' + valueBytes.length)
           : id === 0x11 ? ('V' + Buffer.from(valueBytes).toString('hex'))
           : quietInt(valueBytes)
    });
  }

  Object.defineProperty(out, '_ordered', { value: ordered, enumerable: false });
  Object.defineProperty(out, '_invalid', { value: invalid, enumerable: false });
  return out;
}

// The parameters only a server sends (RFC 9000 §18.2): "A client MUST NOT
// include any server-only transport parameter ... A server MUST treat receipt
// of any of these transport parameters as a connection error of type
// TRANSPORT_PARAMETER_ERROR."
var SERVER_ONLY_PARAMS = [
  'original_destination_connection_id', 'preferred_address',
  'retry_source_connection_id', 'stateless_reset_token'
];

// Why the peer's parameters are a TRANSPORT_PARAMETER_ERROR, or null:
// malformed (above), or — fromClient — one only a server sends.
function transport_params_error(p, fromClient) {
  if (p._invalid) return p._invalid;
  if (fromClient) {
    for (var i = 0; i < SERVER_ONLY_PARAMS.length; i++) {
      if (p[SERVER_ONLY_PARAMS[i]] !== undefined) return SERVER_ONLY_PARAMS[i] + ' from a client';
    }
  }
  return null;
}


// ============================================================
//  Exports
// ============================================================

export {
  // Datagram/packet parsing
  parse_quic_datagram,
  parse_quic_packet,

  // Version negotiation
  SUPPORTED_VERSIONS,
  is_supported_version,
  build_version_negotiation,

  // Frame encode/decode
  encode_quic_frames,
  encode_quic_frames_each,
  quic_frames_size,
  parse_quic_frames,

  // Transport parameters
  build_transport_params,
  parse_transport_params,
  transport_params_error
};
