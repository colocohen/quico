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
//  HTTP/2 framing (RFC 9113 §4-§6).
//
//  Pure codec: bytes in, frame objects out, no connection state. The state
//  machine, flow control and HPACK live in h2.js, exactly as h1.js is a parser
//  and h1_server is the thing that owns a socket.
//
//  Every frame is a 9-byte header followed by a payload:
//
//    +-----------------------------------------------+
//    |                 Length (24)                   |
//    +---------------+---------------+---------------+
//    |   Type (8)    |   Flags (8)   |
//    +-+-------------+---------------+-------------------------------+
//    |R|                 Stream Identifier (31)                      |
//    +=+=============================================================+
//    |                   Frame Payload (0...)                      ...
//
//  Note the R bit: the stream id is 31 bits, not 32. Reading it as a uint32
//  makes every id with the high bit set enormous and negative-ish, and RFC
//  9113 §4.1 says a receiver MUST ignore that bit rather than reject the
//  frame — so it is masked off here, once, for every frame type.
// ============================================================

var FRAME_HEADER_SIZE = 9;

var TYPE = {
  DATA:          0x0,
  HEADERS:       0x1,
  PRIORITY:      0x2,
  RST_STREAM:    0x3,
  SETTINGS:      0x4,
  PUSH_PROMISE:  0x5,
  PING:          0x6,
  GOAWAY:        0x7,
  WINDOW_UPDATE: 0x8,
  CONTINUATION:  0x9,
  // RFC 9218 §7.1: a stream's priority after its request, client to server,
  // on stream 0 — the scheme that replaced PRIORITY (RFC 9113 §5.3.2).
  PRIORITY_UPDATE: 0x10
};

var TYPE_NAME = {};
for (var _t in TYPE) TYPE_NAME[TYPE[_t]] = _t;

var FLAG = {
  END_STREAM:  0x01,   // DATA, HEADERS
  ACK:         0x01,   // SETTINGS, PING — same bit, different meaning
  END_HEADERS: 0x04,   // HEADERS, PUSH_PROMISE, CONTINUATION
  PADDED:      0x08,   // DATA, HEADERS, PUSH_PROMISE
  PRIORITY:    0x20    // HEADERS
};

// RFC 9113 §7.
var ERROR = {
  NO_ERROR:            0x0,
  PROTOCOL_ERROR:      0x1,
  INTERNAL_ERROR:      0x2,
  FLOW_CONTROL_ERROR:  0x3,
  SETTINGS_TIMEOUT:    0x4,
  STREAM_CLOSED:       0x5,
  FRAME_SIZE_ERROR:    0x6,
  REFUSED_STREAM:      0x7,
  CANCEL:              0x8,
  COMPRESSION_ERROR:   0x9,
  CONNECT_ERROR:       0xa,
  ENHANCE_YOUR_CALM:   0xb,
  INADEQUATE_SECURITY: 0xc,
  HTTP_1_1_REQUIRED:   0xd
};

var ERROR_NAME = {};
for (var _e in ERROR) ERROR_NAME[ERROR[_e]] = _e;

// RFC 9113 §6.5.2.
var SETTINGS = {
  HEADER_TABLE_SIZE:      0x1,
  ENABLE_PUSH:            0x2,
  MAX_CONCURRENT_STREAMS: 0x3,
  INITIAL_WINDOW_SIZE:    0x4,
  MAX_FRAME_SIZE:         0x5,
  MAX_HEADER_LIST_SIZE:   0x6,
  // RFC 8441 §3. A server that sends this with the value 1 is telling clients
  // they may use extended CONNECT — a CONNECT request carrying a `:protocol`
  // pseudo-header — which is how WebSocket runs over HTTP/2. Without it, a
  // browser will not even try, and opens a separate HTTP/1.1 connection
  // instead.
  ENABLE_CONNECT_PROTOCOL: 0x8,
  // RFC 9218 §2.1: 1 — this endpoint ignores RFC 7540's priority tree (as
  // RFC 9113 lets it), and reads RFC 9218's signals instead.
  NO_RFC7540_PRIORITIES: 0x9
};

var SETTINGS_NAME = {};
for (var _s in SETTINGS) SETTINGS_NAME[SETTINGS[_s]] = _s;

// The connection preface a client sends before anything else (§3.4). It is
// deliberately something an HTTP/1.1 server cannot mistake for a request, so
// that speaking h2 to a server that does not know it fails immediately rather
// than being half-understood.
var PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'latin1');

var MAX_WINDOW = 2147483647;          // 2^31 - 1
var DEFAULT_MAX_FRAME_SIZE = 16384;   // §6.5.2, also the minimum allowed
var MAX_ALLOWED_FRAME_SIZE = 16777215;
var DEFAULT_WINDOW_SIZE = 65535;


/**
 * A protocol failure.
 *
 * `stream` distinguishes the two kinds RFC 9113 §5.4 defines and never mixes:
 * a CONNECTION error (stream === 0) ends everything with GOAWAY, a STREAM
 * error resets one stream with RST_STREAM and leaves the rest running.
 * Choosing wrongly in either direction is a real bug — tearing down a
 * connection over one malformed request is a denial of service against the
 * other streams on it, and continuing after a framing error means every
 * subsequent frame is read at the wrong offset.
 */
function h2Error(message, code, streamId) {
  var err = new Error(message);
  err.code = 'H2_' + (ERROR_NAME[code] || 'PROTOCOL_ERROR');
  err.h2Code = code === undefined ? ERROR.PROTOCOL_ERROR : code;
  err.streamId = streamId || 0;
  return err;
}


// ============================================================
//  Decoding
// ============================================================

/**
 * Read one frame from `buf` at `offset`.
 *
 * Returns null when the buffer does not yet hold a whole frame — a partial
 * frame is the normal state of affairs on a TCP stream, not an error.
 * Throws h2Error for anything malformed.
 */
function readFrame(buf, offset, maxFrameSize) {
  offset = offset || 0;
  maxFrameSize = maxFrameSize || DEFAULT_MAX_FRAME_SIZE;

  if (buf.length - offset < FRAME_HEADER_SIZE) return null;

  var length = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2];
  var type = buf[offset + 3];
  var flags = buf[offset + 4];
  // Mask the reserved bit (§4.1).
  var streamId = buf.readUInt32BE(offset + 5) & 0x7fffffff;

  if (length > maxFrameSize) {
    // §4.2. Checked before waiting for the payload: otherwise a peer could
    // announce a 16 MB frame and make us buffer it before we objected.
    throw h2Error('frame of ' + length + ' bytes exceeds SETTINGS_MAX_FRAME_SIZE ' +
                  maxFrameSize, ERROR.FRAME_SIZE_ERROR);
  }

  if (buf.length - offset < FRAME_HEADER_SIZE + length) return null;

  var payload = buf.subarray(offset + FRAME_HEADER_SIZE, offset + FRAME_HEADER_SIZE + length);
  var frame;
  try {
    frame = parsePayload(type, flags, streamId, payload);
  } catch (err) {
    // The frame is whole, so its extent is known: a caller that answers a
    // STREAM error with RST_STREAM skips exactly this frame and reads on.
    err.consumed = FRAME_HEADER_SIZE + length;
    throw err;
  }
  frame.length = length;
  frame.consumed = FRAME_HEADER_SIZE + length;
  return frame;
}


function parsePayload(type, flags, streamId, payload) {
  var frame = {
    type: type,
    typeName: TYPE_NAME[type] || ('UNKNOWN_0x' + type.toString(16)),
    flags: flags,
    streamId: streamId
  };

  switch (type) {

    case TYPE.DATA: {
      if (streamId === 0) {
        throw h2Error('DATA on stream 0', ERROR.PROTOCOL_ERROR);
      }
      var d = stripPadding(payload, flags);
      frame.data = d;
      frame.endStream = (flags & FLAG.END_STREAM) !== 0;
      return frame;
    }

    case TYPE.HEADERS: {
      if (streamId === 0) {
        throw h2Error('HEADERS on stream 0', ERROR.PROTOCOL_ERROR);
      }
      var p = stripPadding(payload, flags);
      var pos = 0;
      if (flags & FLAG.PRIORITY) {
        if (p.length < 5) {
          throw h2Error('HEADERS with PRIORITY is shorter than 5 bytes',
                        ERROR.FRAME_SIZE_ERROR);
        }
        var dep = p.readUInt32BE(0);
        frame.exclusive = (dep & 0x80000000) !== 0;
        frame.dependency = dep & 0x7fffffff;
        frame.weight = p[4] + 1;
        // §5.3.1: a stream cannot depend on itself. RFC 9113 deprecates
        // priority signalling but keeps this as a stream error.
        if (frame.dependency === streamId) {
          throw h2Error('stream depends on itself', ERROR.PROTOCOL_ERROR, streamId);
        }
        pos = 5;
      }
      frame.headerBlock = p.subarray(pos);
      frame.endStream = (flags & FLAG.END_STREAM) !== 0;
      frame.endHeaders = (flags & FLAG.END_HEADERS) !== 0;
      return frame;
    }

    case TYPE.PRIORITY: {
      if (streamId === 0) throw h2Error('PRIORITY on stream 0', ERROR.PROTOCOL_ERROR);
      // A stream error, not a connection error (§6.3) — the frame is
      // self-contained, so the connection is still readable.
      if (payload.length !== 5) {
        throw h2Error('PRIORITY payload must be 5 bytes', ERROR.FRAME_SIZE_ERROR, streamId);
      }
      var dep2 = payload.readUInt32BE(0);
      frame.exclusive = (dep2 & 0x80000000) !== 0;
      frame.dependency = dep2 & 0x7fffffff;
      frame.weight = payload[4] + 1;
      if (frame.dependency === streamId) {
        throw h2Error('stream depends on itself', ERROR.PROTOCOL_ERROR, streamId);
      }
      return frame;
    }

    case TYPE.RST_STREAM: {
      if (streamId === 0) throw h2Error('RST_STREAM on stream 0', ERROR.PROTOCOL_ERROR);
      if (payload.length !== 4) {
        throw h2Error('RST_STREAM payload must be 4 bytes', ERROR.FRAME_SIZE_ERROR);
      }
      frame.errorCode = payload.readUInt32BE(0);
      return frame;
    }

    case TYPE.SETTINGS: {
      if (streamId !== 0) throw h2Error('SETTINGS on a non-zero stream', ERROR.PROTOCOL_ERROR);
      frame.ack = (flags & FLAG.ACK) !== 0;
      if (frame.ack) {
        // §6.5: an ACK carries no settings. A payload here means the peer is
        // confused about which direction this frame is going.
        if (payload.length !== 0) {
          throw h2Error('SETTINGS ACK must have an empty payload', ERROR.FRAME_SIZE_ERROR);
        }
        frame.settings = {};
        return frame;
      }
      if (payload.length % 6 !== 0) {
        throw h2Error('SETTINGS payload is not a multiple of 6', ERROR.FRAME_SIZE_ERROR);
      }
      var settings = {};
      // The same parameters again as an ORDERED list, including the ones
      // dropped above. Both forms are needed and neither substitutes for the
      // other: the protocol wants a lookup by name, and fingerprinting wants
      // the sequence exactly as sent — which parameters appear, in which
      // order, and which are absent. Unknown identifiers are kept here for the
      // same reason: an unrecognised setting is still a fact about the peer.
      var settingsList = [];
      for (var i = 0; i + 6 <= payload.length; i += 6) {
        var id = payload.readUInt16BE(i);
        var value = payload.readUInt32BE(i + 2);
        validateSetting(id, value);
        settingsList.push({ id: id, value: value });
        // Unknown identifiers must be IGNORED (§6.5.2), not rejected: that is
        // the extension point the whole protocol relies on for future settings.
        if (SETTINGS_NAME[id]) settings[SETTINGS_NAME[id]] = value;
      }
      frame.settings = settings;
      frame.settingsList = settingsList;
      return frame;
    }

    case TYPE.PUSH_PROMISE: {
      if (streamId === 0) throw h2Error('PUSH_PROMISE on stream 0', ERROR.PROTOCOL_ERROR);
      var pp = stripPadding(payload, flags);
      if (pp.length < 4) {
        throw h2Error('PUSH_PROMISE is shorter than 4 bytes', ERROR.FRAME_SIZE_ERROR);
      }
      frame.promisedStreamId = pp.readUInt32BE(0) & 0x7fffffff;
      frame.headerBlock = pp.subarray(4);
      frame.endHeaders = (flags & FLAG.END_HEADERS) !== 0;
      return frame;
    }

    case TYPE.PING: {
      if (streamId !== 0) throw h2Error('PING on a non-zero stream', ERROR.PROTOCOL_ERROR);
      if (payload.length !== 8) {
        throw h2Error('PING payload must be 8 bytes', ERROR.FRAME_SIZE_ERROR);
      }
      frame.ack = (flags & FLAG.ACK) !== 0;
      frame.payload = Buffer.from(payload);
      return frame;
    }

    case TYPE.GOAWAY: {
      if (streamId !== 0) throw h2Error('GOAWAY on a non-zero stream', ERROR.PROTOCOL_ERROR);
      if (payload.length < 8) {
        throw h2Error('GOAWAY is shorter than 8 bytes', ERROR.FRAME_SIZE_ERROR);
      }
      frame.lastStreamId = payload.readUInt32BE(0) & 0x7fffffff;
      frame.errorCode = payload.readUInt32BE(4);
      frame.debugData = Buffer.from(payload.subarray(8));
      return frame;
    }

    case TYPE.WINDOW_UPDATE: {
      if (payload.length !== 4) {
        throw h2Error('WINDOW_UPDATE payload must be 4 bytes', ERROR.FRAME_SIZE_ERROR);
      }
      frame.increment = payload.readUInt32BE(0) & 0x7fffffff;
      if (frame.increment === 0) {
        // §6.9. On a stream it is a stream error; on the connection it ends
        // everything, because a zero increment can only be a sender that has
        // lost track of its own window.
        throw h2Error('WINDOW_UPDATE increment of 0', ERROR.PROTOCOL_ERROR, streamId);
      }
      return frame;
    }

    case TYPE.PRIORITY_UPDATE: {
      // RFC 9218 §7.1: on stream 0 only, and naming a stream.
      if (streamId !== 0) throw h2Error('PRIORITY_UPDATE on stream ' + streamId, ERROR.PROTOCOL_ERROR);
      if (payload.length < 4) throw h2Error('PRIORITY_UPDATE shorter than 4 bytes', ERROR.FRAME_SIZE_ERROR);
      frame.prioritizedStreamId = payload.readUInt32BE(0) & 0x7fffffff;
      if (frame.prioritizedStreamId === 0) throw h2Error('PRIORITY_UPDATE for stream 0', ERROR.PROTOCOL_ERROR);
      frame.priorityField = payload.subarray(4).toString('latin1');
      return frame;
    }

    case TYPE.CONTINUATION: {
      if (streamId === 0) throw h2Error('CONTINUATION on stream 0', ERROR.PROTOCOL_ERROR);
      frame.headerBlock = payload;
      frame.endHeaders = (flags & FLAG.END_HEADERS) !== 0;
      return frame;
    }

    default:
      // §4.1: a frame of unknown type MUST be ignored and discarded. Another
      // extension point — rejecting it would break every future frame type.
      frame.unknown = true;
      frame.payload = Buffer.from(payload);
      return frame;
  }
}


/**
 * Remove the padding a PADDED frame carries (§6.1).
 *
 * The length byte counts padding AFTER itself, so a value >= the remaining
 * length means the padding would consume the real payload and then some. §6.1
 * calls that a connection error, and it is the shape of an attempt to make two
 * implementations disagree about where the payload ends.
 */
function stripPadding(payload, flags) {
  if ((flags & FLAG.PADDED) === 0) return payload;
  if (payload.length < 1) {
    throw h2Error('PADDED frame with no padding length', ERROR.PROTOCOL_ERROR);
  }
  var padLength = payload[0];
  if (padLength >= payload.length) {
    throw h2Error('padding length ' + padLength + ' is not smaller than the payload',
                  ERROR.PROTOCOL_ERROR);
  }
  return payload.subarray(1, payload.length - padLength);
}


function validateSetting(id, value) {
  switch (id) {
    case SETTINGS.ENABLE_PUSH:
      if (value !== 0 && value !== 1) {
        throw h2Error('SETTINGS_ENABLE_PUSH must be 0 or 1', ERROR.PROTOCOL_ERROR);
      }
      break;
    case SETTINGS.ENABLE_CONNECT_PROTOCOL:
      // RFC 8441 §3: 0 or 1, and once advertised as 1 it may never go back to
      // 0 — a peer that has started using extended CONNECT cannot be told to
      // stop mid-connection. The one-way rule is enforced in h2.js, which is
      // where the previous value is known.
      if (value !== 0 && value !== 1) {
        throw h2Error('SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1', ERROR.PROTOCOL_ERROR);
      }
      break;
    case SETTINGS.NO_RFC7540_PRIORITIES:
      if (value !== 0 && value !== 1) {
        throw h2Error('SETTINGS_NO_RFC7540_PRIORITIES must be 0 or 1', ERROR.PROTOCOL_ERROR);
      }
      break;
    case SETTINGS.INITIAL_WINDOW_SIZE:
      if (value > MAX_WINDOW) {
        throw h2Error('SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1',
                      ERROR.FLOW_CONTROL_ERROR);
      }
      break;
    case SETTINGS.MAX_FRAME_SIZE:
      if (value < DEFAULT_MAX_FRAME_SIZE || value > MAX_ALLOWED_FRAME_SIZE) {
        throw h2Error('SETTINGS_MAX_FRAME_SIZE outside 16384..16777215',
                      ERROR.PROTOCOL_ERROR);
      }
      break;
  }
}


// ============================================================
//  Encoding
// ============================================================

function frameHeader(length, type, flags, streamId) {
  var h = Buffer.allocUnsafe(FRAME_HEADER_SIZE);
  h[0] = (length >>> 16) & 0xff;
  h[1] = (length >>> 8) & 0xff;
  h[2] = length & 0xff;
  h[3] = type;
  h[4] = flags;
  h.writeUInt32BE(streamId & 0x7fffffff, 5);
  return h;
}

function buildFrame(type, flags, streamId, payload) {
  payload = payload || Buffer.alloc(0);
  return Buffer.concat([frameHeader(payload.length, type, flags, streamId), payload]);
}

function buildData(streamId, data, endStream) {
  return buildFrame(TYPE.DATA, endStream ? FLAG.END_STREAM : 0, streamId, data);
}

function buildHeaders(streamId, headerBlock, options) {
  options = options || {};
  var flags = 0;
  if (options.endStream) flags |= FLAG.END_STREAM;
  if (options.endHeaders !== false) flags |= FLAG.END_HEADERS;
  return buildFrame(TYPE.HEADERS, flags, streamId, headerBlock);
}

function buildContinuation(streamId, headerBlock, endHeaders) {
  return buildFrame(TYPE.CONTINUATION, endHeaders ? FLAG.END_HEADERS : 0,
                    streamId, headerBlock);
}

function buildRstStream(streamId, errorCode) {
  var p = Buffer.allocUnsafe(4);
  p.writeUInt32BE(errorCode >>> 0, 0);
  return buildFrame(TYPE.RST_STREAM, 0, streamId, p);
}

function buildSettings(settings, ack) {
  if (ack) return buildFrame(TYPE.SETTINGS, FLAG.ACK, 0, Buffer.alloc(0));
  var names = Object.keys(settings || {});
  var p = Buffer.allocUnsafe(names.length * 6);
  var off = 0;
  for (var i = 0; i < names.length; i++) {
    var id = SETTINGS[names[i]];
    if (id === undefined) continue;
    p.writeUInt16BE(id, off);
    p.writeUInt32BE(settings[names[i]] >>> 0, off + 2);
    off += 6;
  }
  return buildFrame(TYPE.SETTINGS, 0, 0, p.subarray(0, off));
}

function buildPing(payload, ack) {
  var p = Buffer.alloc(8);
  if (payload) Buffer.from(payload).copy(p, 0, 0, Math.min(8, payload.length));
  return buildFrame(TYPE.PING, ack ? FLAG.ACK : 0, 0, p);
}

function buildGoaway(lastStreamId, errorCode, debugData) {
  var d = debugData ? Buffer.from(debugData) : Buffer.alloc(0);
  var p = Buffer.allocUnsafe(8 + d.length);
  p.writeUInt32BE(lastStreamId & 0x7fffffff, 0);
  p.writeUInt32BE(errorCode >>> 0, 4);
  d.copy(p, 8);
  return buildFrame(TYPE.GOAWAY, 0, 0, p);
}

// RFC 9218 §7.1: the stream, then its Priority Field Value.
function buildPriorityUpdate(streamId, field) {
  var f = Buffer.from(field || '', 'latin1');
  var p = Buffer.allocUnsafe(4 + f.length);
  p.writeUInt32BE(streamId & 0x7fffffff, 0);
  f.copy(p, 4);
  return buildFrame(TYPE.PRIORITY_UPDATE, 0, 0, p);
}

function buildWindowUpdate(streamId, increment) {
  var p = Buffer.allocUnsafe(4);
  p.writeUInt32BE(increment & 0x7fffffff, 0);
  return buildFrame(TYPE.WINDOW_UPDATE, 0, streamId, p);
}

/**
 * Split a header block into HEADERS + as many CONTINUATION frames as needed.
 *
 * A header block larger than MAX_FRAME_SIZE is ordinary — a request with a big
 * cookie reaches it easily — and the ONLY legal way to send it is to fragment.
 * The fragments must be contiguous on the connection with no other frame
 * between them (§6.10), which is why this returns them together rather than
 * letting a caller interleave.
 */
function buildHeaderFrames(streamId, headerBlock, options, maxFrameSize) {
  options = options || {};
  maxFrameSize = maxFrameSize || DEFAULT_MAX_FRAME_SIZE;

  if (headerBlock.length <= maxFrameSize) {
    return [buildHeaders(streamId, headerBlock, { endStream: options.endStream, endHeaders: true })];
  }

  var out = [];
  out.push(buildHeaders(streamId, headerBlock.subarray(0, maxFrameSize), {
    endStream: options.endStream,
    endHeaders: false
  }));
  var pos = maxFrameSize;
  while (pos < headerBlock.length) {
    var end = Math.min(pos + maxFrameSize, headerBlock.length);
    out.push(buildContinuation(streamId, headerBlock.subarray(pos, end),
                               end >= headerBlock.length));
    pos = end;
  }
  return out;
}


export {
  FRAME_HEADER_SIZE,
  TYPE, TYPE_NAME,
  FLAG,
  ERROR, ERROR_NAME,
  SETTINGS, SETTINGS_NAME,
  PREFACE,
  MAX_WINDOW,
  DEFAULT_MAX_FRAME_SIZE,
  MAX_ALLOWED_FRAME_SIZE,
  DEFAULT_WINDOW_SIZE,
  h2Error,
  readFrame,
  buildFrame,
  frameHeader,
  buildData,
  buildHeaders,
  buildContinuation,
  buildRstStream,
  buildSettings,
  buildPing,
  buildGoaway,
  buildWindowUpdate,
  buildPriorityUpdate,
  buildHeaderFrames
};
