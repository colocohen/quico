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
  concatUint8Arrays,
  writeVarInt,
  readVarInt
} from './utils.js';


// ============================================================
//  QUIC Datagram → Packet splitting (RFC 9000 §12.2)
// ============================================================

/**
 * Parse a single QUIC packet header (enough to get type + totalLength).
 */
function parse_quic_packet(array, offset0) {
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

    var typeBits = (firstByte & 0x30) >> 4;
    var typeMap = ['initial', '0rtt', 'handshake', 'retry'];
    var packetType = typeMap[typeBits] || 'unknown';

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
    // Short Header — Fixed Bit (0x40) MUST be 1 (RFC 9000 §17.3)
    if ((firstByte & 0x40) === 0) return null; // padding or invalid
    return {
      form: 'short', type: '1rtt',
      totalLength: array.length - offset0
    };
  }
}


/**
 * Split a UDP datagram into QUIC packets.
 */
function parse_quic_datagram(array) {
  var packets = [];
  var offset = 0;

  while (offset < array.length) {
    var pkt = parse_quic_packet(array, offset);
    if (!pkt || !pkt.totalLength) break;

    var start = offset;
    var end = offset + pkt.totalLength;

    pkt.raw = (start === 0 && end === array.length)
      ? array
      : array.slice(start, end);

    if (packets.length > 0) {
      console.log('[quic] coalesced pkt #' + packets.length + ' type=' + pkt.type + ' offset=' + start + ' len=' + pkt.totalLength + ' firstByte=0x' + array[start].toString(16).padStart(2,'0'));
    }

    packets.push(pkt);
    offset = end;
  }

  return packets;
}


// ============================================================
//  QUIC Frame encoding (RFC 9000 §12.4)
// ============================================================

function encode_quic_frames(frames) {
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
      var hasLen = (frame.data && frame.data.length > 0);
      var hasFin = !!frame.fin;

      if (hasOffset) typeByte |= 0x04;
      if (hasLen) typeByte |= 0x02;
      if (hasFin) typeByte |= 0x01;

      parts.push(concatUint8Arrays([
        new Uint8Array([typeByte]),
        writeVarInt(frame.id),
        hasOffset ? writeVarInt(frame.offset) : new Uint8Array(0),
        hasLen ? writeVarInt(frame.data.length) : new Uint8Array(0),
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

    } else if (frame.type === 'stream_data_blocked') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x15]),
        writeVarInt(frame.id),
        writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'datagram') {
      if (frame.contextId != null) {
        parts.push(concatUint8Arrays([
          new Uint8Array([0x31]),
          writeVarInt(frame.contextId),
          frame.data
        ]));
      } else {
        parts.push(concatUint8Arrays([
          new Uint8Array([0x30]),
          frame.data
        ]));
      }
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

  while (offset < buf.length) {
    var type = buf[offset++];

    // Multi-byte frame type
    if (type >= 0x80) {
      offset--;
      var t = safeReadVarInt();
      if (!t) break;
      type = t.value;
    }

    if (type === 0x00) {
      // PADDING — skip
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

    } else if (type === 0x30 || type === 0x31) {
      var contextId = null;
      if (type === 0x31) {
        var cid = safeReadVarInt(); if (!cid) break;
        contextId = cid.value;
      }
      var data = buf.slice(offset); offset = buf.length;
      frames.push({ type: 'datagram', contextId: contextId, data: data });

    } else {
      // Unknown frame — stop
      frames.push({ type: 'unknown', frameType: type });
      break;
    }
  }

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

  return new Uint8Array(out);
}


function parse_transport_params(buf, start) {
  if (!(buf instanceof Uint8Array)) throw new Error('Expect Uint8Array');
  var offset = start || 0;
  var end = buf.length;
  var out = {};

  while (offset < end) {
    var idVar = readVarInt(buf, offset);
    if (!idVar) break;
    offset += idVar.byteLength;

    var lenVar = readVarInt(buf, offset);
    if (!lenVar) break;
    offset += lenVar.byteLength;

    if (offset + lenVar.value > end) break;
    var valueBytes = buf.slice(offset, offset + lenVar.value);
    offset += lenVar.value;

    var id = idVar.value;

    switch (id) {
      case 0x00: out.original_destination_connection_id = valueBytes; break;
      case 0x01: out.max_idle_timeout = readVarInt(valueBytes, 0).value; break;
      case 0x02: out.stateless_reset_token = valueBytes; break;
      case 0x03: out.max_udp_payload_size = readVarInt(valueBytes, 0).value; break;
      case 0x04: out.initial_max_data = readVarInt(valueBytes, 0).value; break;
      case 0x05: out.initial_max_stream_data_bidi_local = readVarInt(valueBytes, 0).value; break;
      case 0x06: out.initial_max_stream_data_bidi_remote = readVarInt(valueBytes, 0).value; break;
      case 0x07: out.initial_max_stream_data_uni = readVarInt(valueBytes, 0).value; break;
      case 0x08: out.initial_max_streams_bidi = readVarInt(valueBytes, 0).value; break;
      case 0x09: out.initial_max_streams_uni = readVarInt(valueBytes, 0).value; break;
      case 0x0a: out.ack_delay_exponent = readVarInt(valueBytes, 0).value; break;
      case 0x0b: out.max_ack_delay = readVarInt(valueBytes, 0).value; break;
      case 0x0c: out.disable_active_migration = true; break;
      case 0x0e: out.active_connection_id_limit = readVarInt(valueBytes, 0).value; break;
      case 0x0f: out.initial_source_connection_id = valueBytes; break;
      case 0x10: out.retry_source_connection_id = valueBytes; break;
      case 0x20: out.max_datagram_frame_size = readVarInt(valueBytes, 0).value; break;
      default:
        if (!out.unknown) out.unknown = [];
        out.unknown.push({ id: id, bytes: valueBytes });
    }
  }

  return out;
}


// ============================================================
//  Exports
// ============================================================

export {
  // Datagram/packet parsing
  parse_quic_datagram,
  parse_quic_packet,

  // Frame encode/decode
  encode_quic_frames,
  parse_quic_frames,

  // Transport parameters
  build_transport_params,
  parse_transport_params
};
