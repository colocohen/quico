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

import { HpackEncoder, HpackDecoder } from './hpack.js';
import * as F from './h2_frames.js';
import {
  Emitter, addHeader, parseContentLength, isConnectionSpecific,
  isPseudoHeader, REQUEST_PSEUDO, RESPONSE_PSEUDO
} from './http_common.js';


// ============================================================
//  H2Connection — HTTP/2 over one byte stream (RFC 9113).
//
//  The same position in the stack as h3.js: it is handed ordered bytes and
//  turns them into request/response events, knowing nothing about sockets.
//  What it must do that h3.js does not is everything QUIC provides for free —
//  streams, their state machine, and flow control in both directions. In
//  HTTP/3 those are the transport's; here they are the protocol's own, which
//  is most of the reason this file is four times the size of h3.js's framing.
//
//  Events:
//    'headers'  (streamId, headers, endStream)
//    'data'     (streamId, chunk)
//    'end'      (streamId)
//    'rst'      (streamId, errorCode)
//    'settings' (settings)
//    'goaway'   (lastStreamId, errorCode, debug)
//    'ping'     (payload)
//    'send'     (buffer)          — bytes to put on the wire
//    'error'    (err)             — connection error; the connection is over
//    'drain'    (streamId)        — a stream's send window reopened
// ============================================================

var STATE = {
  IDLE:               'idle',
  RESERVED_LOCAL:     'reserved_local',
  RESERVED_REMOTE:    'reserved_remote',
  OPEN:               'open',
  HALF_CLOSED_LOCAL:  'half_closed_local',
  HALF_CLOSED_REMOTE: 'half_closed_remote',
  CLOSED:             'closed'
};

// Pseudo-header sets and the connection-specific field list live in
// http_common.js: RFC 9114 §4.2 names exactly the same fields for HTTP/3, so
// h3.js will want them too rather than a second copy that can drift.


function H2Connection(options) {
  if (!(this instanceof H2Connection)) return new H2Connection(options);
  options = options || {};

  var isServer = options.isServer !== false;

  var ev = Emitter();
  var on = ev.on, emit = ev.emit, off = ev.off;

  // ---- Settings ----
  var localSettings = {
    HEADER_TABLE_SIZE:      options.headerTableSize      != null ? options.headerTableSize : 4096,
    ENABLE_PUSH:            0,          // we never accept push; see below
    MAX_CONCURRENT_STREAMS: options.maxConcurrentStreams != null ? options.maxConcurrentStreams : 100,
    INITIAL_WINDOW_SIZE:    options.initialWindowSize    != null ? options.initialWindowSize : 65535,
    MAX_FRAME_SIZE:         options.maxFrameSize         != null ? options.maxFrameSize : 16384,
    MAX_HEADER_LIST_SIZE:   options.maxHeaderListSize    != null ? options.maxHeaderListSize : 128 * 1024
  };

  var remoteSettings = {
    HEADER_TABLE_SIZE:      4096,
    ENABLE_PUSH:            1,
    MAX_CONCURRENT_STREAMS: Infinity,
    INITIAL_WINDOW_SIZE:    F.DEFAULT_WINDOW_SIZE,
    MAX_FRAME_SIZE:         F.DEFAULT_MAX_FRAME_SIZE,
    MAX_HEADER_LIST_SIZE:   Infinity
  };

  var encoder = new HpackEncoder({ maxTableSize: remoteSettings.HEADER_TABLE_SIZE });
  var decoder = new HpackDecoder({
    maxTableSize: localSettings.HEADER_TABLE_SIZE,
    maxHeaderListSize: localSettings.MAX_HEADER_LIST_SIZE
  });

  // ---- Connection state ----
  var buf = Buffer.alloc(0);
  var prefaceReceived = !isServer;    // a server waits for it, a client sends it
  var streams = {};
  var lastRemoteStreamId = 0;
  var nextLocalStreamId = isServer ? 2 : 1;
  var goawaySent = false;
  var goawayReceived = false;
  var closed = false;
  var settingsAcked = false;

  // Connection-level flow control. Two independent windows per direction: one
  // for the connection, one per stream, and a DATA frame consumes from BOTH.
  //
  // Both start at 65535 and NOT at INITIAL_WINDOW_SIZE. RFC 9113 §6.9.2 is
  // explicit that SETTINGS_INITIAL_WINDOW_SIZE governs stream windows only and
  // does not change the connection window, which moves solely by WINDOW_UPDATE
  // on stream 0. Seeding it from the setting instead makes a server that
  // advertises a small per-stream window unable to receive anything at all —
  // the connection window runs out first and every request dies with a
  // connection-level FLOW_CONTROL_ERROR that looks like the peer's fault.
  var localWindow = F.DEFAULT_WINDOW_SIZE;     // what we may receive
  var remoteWindow = F.DEFAULT_WINDOW_SIZE;    // what we may send

  // A header block may be split across HEADERS + CONTINUATION, and §6.10
  // forbids ANY other frame in between — including one for a different stream.
  // Tracking it as connection state rather than per-stream is the point: an
  // interleaved frame is a connection error precisely because the HPACK
  // decoder is connection-wide and would be fed the fragments out of order.
  var continuationStream = 0;
  var continuationFragments = [];
  var continuationFrame = null;


  function connectionError(message, code) {
    if (closed) return;
    var err = message instanceof Error ? message
            : F.h2Error(message, code === undefined ? F.ERROR.PROTOCOL_ERROR : code);
    sendGoaway(err.h2Code || F.ERROR.PROTOCOL_ERROR, err.message);
    closed = true;
    emit('error', err);
  }

  // A peer that keeps sending on a stream we have reset gets a reset back each
  // time (RFC 9113 §5.1), but only so many: answering an endless stream of
  // frames with an endless stream of RST_STREAMs is a reflection amplifier
  // pointed at ourselves. Past the limit the connection goes.
  var MAX_RESETS_PER_STREAM = 8;

  function streamError(streamId, code, message) {
    var s = streams[streamId];

    // Do NOT bail out because the stream is already closed. That was the bug
    // h2spec §5.1.8/9/11/12 found: a DATA or HEADERS frame arriving after we
    // reset a stream MUST be answered with STREAM_CLOSED, and returning here
    // meant answering with nothing at all. The peer sat waiting for a reply
    // that never came — every one of those four tests failed as "Timeout"
    // rather than as a wrong error code, which is what silence looks like from
    // the other end.
    if (s) {
      s.resetCount = (s.resetCount || 0) + 1;
      if (s.resetCount > MAX_RESETS_PER_STREAM) {
        connectionError('too many resets on stream ' + streamId, F.ERROR.ENHANCE_YOUR_CALM);
        return;
      }
      s.state = STATE.CLOSED;
      s.closedBy = 'rst';
      s.pendingData = [];
      if (!s.closedAt) s.closedAt = Date.now();
    }

    write(F.buildRstStream(streamId, code));
    emit('rst', streamId, code);
  }

  /**
   * Has this stream id never been used, as opposed to used and finished?
   *
   * RFC 9113 §5.1 treats the two completely differently: a frame for an IDLE
   * stream is a connection error, while the same frame for a CLOSED one is
   * ordinary — the peer had it in flight when we closed the stream. Telling
   * them apart is possible because ids only ever increase: anything above the
   * highest we have seen was never opened, anything at or below it was.
   */
  function isIdleStreamId(id) {
    if (streams[id]) return streams[id].state === STATE.IDLE;
    var peerInitiated = isServer ? (id % 2 === 1) : (id % 2 === 0);
    if (peerInitiated) return id > lastRemoteStreamId;
    return id >= nextLocalStreamId;
  }

  function write(buffer) {
    if (buffer && buffer.length) emit('send', buffer);
  }


  // ============================================================
  //  Streams
  // ============================================================

  function getStream(id, create) {
    var s = streams[id];
    if (s) return s;
    if (!create) return null;
    s = {
      id: id,
      state: STATE.IDLE,
      // Per-stream windows, seeded from each side's INITIAL_WINDOW_SIZE.
      localWindow: localSettings.INITIAL_WINDOW_SIZE,
      remoteWindow: remoteSettings.INITIAL_WINDOW_SIZE,
      headersReceived: false,
      trailersReceived: false,
      endStreamReceived: false,
      endStreamSent: false,
      pendingData: [],     // queued while the send window is closed
      contentLength: null,
      bytesReceived: 0
    };
    streams[id] = s;
    return s;
  }

  /**
   * `how` records WHY the stream closed, because RFC 9113 §5.1 answers a later
   * frame differently depending on it:
   *
   *   'rst' — we (or the peer) reset it. A frame that was already in flight is
   *           expected, so the answer is another RST_STREAM: a stream error.
   *   'end' — END_STREAM was seen. Both sides agreed the stream was over, so a
   *           further frame means the peer's state machine has diverged from
   *           ours, and §5.1 makes that a CONNECTION error of type
   *           STREAM_CLOSED.
   *
   * The two look identical from the outside — the stream is closed either way
   * — which is why h2spec §5.1.12 was the last test standing: we answered a
   * post-END_STREAM HEADERS with a polite RST_STREAM where the spec requires
   * the connection to end.
   */
  function closeStream(id, how) {
    var s = streams[id];
    if (!s) return;
    s.state = STATE.CLOSED;
    if (how) s.closedBy = how;
    s.pendingData = [];
    // Kept briefly rather than deleted: frames for a just-closed stream are
    // ordinary (the peer had them in flight when we closed it) and must be
    // ignored, not treated as frames for an idle stream — which would be a
    // connection error. A count-bounded sweep keeps this from growing.
    s.closedAt = Date.now();
    reapClosedStreams();
  }

  function reapClosedStreams() {
    var ids = Object.keys(streams);
    if (ids.length < 1000) return;
    var cutoff = Date.now() - 30000;
    for (var i = 0; i < ids.length; i++) {
      var s = streams[ids[i]];
      if (s.state === STATE.CLOSED && s.closedAt && s.closedAt < cutoff) delete streams[ids[i]];
    }
  }

  function countActiveStreams() {
    var n = 0;
    for (var id in streams) {
      var st = streams[id].state;
      if (st === STATE.OPEN || st === STATE.HALF_CLOSED_LOCAL || st === STATE.HALF_CLOSED_REMOTE) n++;
    }
    return n;
  }


  // ============================================================
  //  Receiving
  // ============================================================

  function execute(chunk) {
    if (closed) return;
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);

    try {
      if (!prefaceReceived) {
        if (buf.length < F.PREFACE.length) return;
        if (!buf.subarray(0, F.PREFACE.length).equals(F.PREFACE)) {
          // Almost always an HTTP/1.1 client that reached an h2-only port. The
          // preface exists so this fails here instead of being parsed as a
          // request line.
          throw F.h2Error('invalid connection preface', F.ERROR.PROTOCOL_ERROR);
        }
        buf = buf.subarray(F.PREFACE.length);
        prefaceReceived = true;
      }

      var offset = 0;
      for (;;) {
        var frame = F.readFrame(buf, offset, localSettings.MAX_FRAME_SIZE);
        if (!frame) break;
        offset += frame.consumed;
        handleFrame(frame);
        if (closed) return;
      }
      buf = offset > 0 ? buf.subarray(offset) : buf;

    } catch (err) {
      if (err.streamId) streamError(err.streamId, err.h2Code, err.message);
      else connectionError(err);
    }
  }


  function handleFrame(frame) {
    // §6.10 again: while a header block is open, the ONLY frame that may
    // arrive is a CONTINUATION for the same stream.
    if (continuationStream !== 0) {
      if (frame.type !== F.TYPE.CONTINUATION || frame.streamId !== continuationStream) {
        throw F.h2Error('frame ' + frame.typeName + ' interleaved into a header block',
                        F.ERROR.PROTOCOL_ERROR);
      }
    }

    switch (frame.type) {
      case F.TYPE.SETTINGS:      return onSettings(frame);
      case F.TYPE.HEADERS:       return onHeaders(frame);
      case F.TYPE.CONTINUATION:  return onContinuation(frame);
      case F.TYPE.DATA:          return onData(frame);
      case F.TYPE.RST_STREAM:    return onRstStream(frame);
      case F.TYPE.WINDOW_UPDATE: return onWindowUpdate(frame);
      case F.TYPE.PING:          return onPing(frame);
      case F.TYPE.GOAWAY:        return onGoaway(frame);
      case F.TYPE.PRIORITY:      return;   // parsed and ignored; deprecated by RFC 9113
      case F.TYPE.PUSH_PROMISE:
        // We advertise ENABLE_PUSH 0, so receiving one is a protocol error
        // (§6.6). A server receiving PUSH_PROMISE is always an error.
        throw F.h2Error('PUSH_PROMISE received although push is disabled',
                        F.ERROR.PROTOCOL_ERROR);
      default:
        return;   // unknown type: ignore (§4.1)
    }
  }


  function onSettings(frame) {
    if (frame.ack) { settingsAcked = true; return; }

    for (var name in frame.settings) {
      var value = frame.settings[name];

      if (name === 'INITIAL_WINDOW_SIZE') {
        // §6.9.2: changing this retroactively adjusts the send window of every
        // OPEN stream by the difference. Not applying the delta is a slow,
        // baffling bug — streams stall or over-send long after the SETTINGS
        // frame that caused it.
        var delta = value - remoteSettings.INITIAL_WINDOW_SIZE;
        for (var id in streams) {
          var s = streams[id];
          if (s.state === STATE.CLOSED) continue;
          s.remoteWindow += delta;
          if (s.remoteWindow > F.MAX_WINDOW) {
            throw F.h2Error('INITIAL_WINDOW_SIZE change overflows a stream window',
                            F.ERROR.FLOW_CONTROL_ERROR);
          }
        }
      }

      remoteSettings[name] = value;

      if (name === 'HEADER_TABLE_SIZE') encoder.setMaxTableSize(value);
    }

    // The ACK must go out before anything that relies on the new settings.
    write(F.buildSettings(null, true));
    emit('settings', frame.settings);

    // Flush anything that was waiting on a window this SETTINGS may have opened.
    for (var sid in streams) flushStream(streams[sid]);
  }


  function onHeaders(frame) {
    var id = frame.streamId;

    if (isServer) {
      // §5.1.1: client-initiated streams are odd, and ids must strictly
      // increase. A reused or lower id would let a peer resurrect a closed
      // stream, which is how request state gets confused between them.
      if (id % 2 === 0) {
        throw F.h2Error('client-initiated stream with an even id', F.ERROR.PROTOCOL_ERROR);
      }
      if (id <= lastRemoteStreamId && !streams[id]) {
        throw F.h2Error('stream id ' + id + ' is not greater than the previous ' +
                        lastRemoteStreamId, F.ERROR.PROTOCOL_ERROR);
      }
    }

    // A closed stream that has already been reaped leaves no record. Without
    // one we cannot know whether it ended by RST_STREAM or by END_STREAM, and
    // the stricter reading is the safe one: a peer opening a stream id it has
    // already used is desynchronised whichever way it closed.
    if (!streams[id] && !isIdleStreamId(id)) {
      throw F.h2Error('HEADERS on a closed stream', F.ERROR.STREAM_CLOSED);
    }

    var s = getStream(id, true);

    if (s.state === STATE.CLOSED) {
      if (s.closedBy === 'rst') {
        // Reset by one of us; a frame already in flight is expected.
        streamError(id, F.ERROR.STREAM_CLOSED, 'HEADERS after RST_STREAM');
      } else {
        throw F.h2Error('HEADERS after END_STREAM', F.ERROR.STREAM_CLOSED);
      }
      return;
    }
    if (s.state === STATE.HALF_CLOSED_REMOTE) {
      streamError(id, F.ERROR.STREAM_CLOSED, 'HEADERS after END_STREAM');
      return;
    }

    if (s.state === STATE.IDLE) {
      if (isServer && countActiveStreams() >= localSettings.MAX_CONCURRENT_STREAMS) {
        // §5.1.2: refusing is a stream error, and REFUSED_STREAM specifically
        // tells the peer the request was never processed, so it is safe to
        // retry elsewhere.
        streamError(id, F.ERROR.REFUSED_STREAM, 'too many concurrent streams');
        return;
      }
      s.state = STATE.OPEN;
      if (isServer) lastRemoteStreamId = id;
    }

    startHeaderBlock(frame, id);
  }

  function onContinuation(frame) {
    if (continuationStream === 0) {
      throw F.h2Error('CONTINUATION with no open header block', F.ERROR.PROTOCOL_ERROR);
    }
    continuationFragments.push(frame.headerBlock);
    if (frame.endHeaders) finishHeaderBlock();
  }

  function startHeaderBlock(frame, id) {
    continuationStream = id;
    continuationFragments = [frame.headerBlock];
    continuationFrame = frame;
    if (frame.endHeaders) finishHeaderBlock();
  }

  function finishHeaderBlock() {
    var id = continuationStream;
    var frame = continuationFrame;
    var block = Buffer.concat(continuationFragments);

    continuationStream = 0;
    continuationFragments = [];
    continuationFrame = null;

    var list;
    try {
      list = decoder.decode(block);
    } catch (err) {
      // HPACK failures are ALWAYS connection errors: the table is shared, so a
      // block we could not decode leaves our table and the peer's permanently
      // out of step, and every later block on every stream would be wrong.
      throw F.h2Error(err.message, F.ERROR.COMPRESSION_ERROR);
    }

    var s = streams[id];
    if (!s || s.state === STATE.CLOSED) return;   // reset while the block arrived

    var headers;
    try {
      headers = validateHeaderList(list, s);
    } catch (err) {
      streamError(id, err.h2Code || F.ERROR.PROTOCOL_ERROR, err.message);
      return;
    }

    if (s.headersReceived) {
      // A second header block on the same stream is trailers, and trailers
      // must end the stream (§8.1).
      if (!frame.endStream) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, 'trailers without END_STREAM');
        return;
      }
      s.trailersReceived = true;
      emit('trailers', id, headers);
    } else {
      s.headersReceived = true;
      try {
        var n = parseContentLength(headers['content-length']);
        if (n !== null) s.contentLength = n;
      } catch (e) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, e.message);
        return;
      }
      emit('headers', id, headers, !!frame.endStream);
    }

    if (frame.endStream) receiveEndStream(s);
  }


  /**
   * §8.3 and §8.2.2. Malformed here means a STREAM error, not a connection
   * error: one bad request should not take down the other streams sharing the
   * connection.
   */
  function validateHeaderList(list, stream) {
    var headers = {};
    var seenRegular = false;
    var pseudo = isServer ? REQUEST_PSEUDO : RESPONSE_PSEUDO;

    for (var i = 0; i < list.length; i++) {
      var name = list[i][0];
      var value = list[i][1];

      if (isPseudoHeader(name)) {
        if (seenRegular) {
          throw F.h2Error('pseudo-header after a regular field', F.ERROR.PROTOCOL_ERROR);
        }
        if (!pseudo[name]) {
          throw F.h2Error('unknown or misdirected pseudo-header ' + name,
                          F.ERROR.PROTOCOL_ERROR);
        }
        if (name in headers) {
          throw F.h2Error('duplicate pseudo-header ' + name, F.ERROR.PROTOCOL_ERROR);
        }
        headers[name] = value;
        continue;
      }

      seenRegular = true;

      if (isConnectionSpecific(name)) {
        // Carrying these across is how a request that means one thing in
        // HTTP/2 becomes two requests after an HTTP/1.1 hop.
        throw F.h2Error('connection-specific field ' + name + ' is not permitted',
                        F.ERROR.PROTOCOL_ERROR);
      }
      if (name === 'te' && String(value).toLowerCase() !== 'trailers') {
        throw F.h2Error('te may only be "trailers"', F.ERROR.PROTOCOL_ERROR);
      }

      // Repeat-combining is RFC 9110 §5.3, shared with h1: set-cookie never
      // joins, cookie joins with "; " (which §8.2.3 relies on, since an h2
      // sender may split it deliberately to compress better).
      addHeader(headers, name, value);
    }

    if (isServer && !stream.headersReceived) {
      if (!headers[':method'] || !headers[':scheme'] || !headers[':path']) {
        throw F.h2Error('request is missing a mandatory pseudo-header', F.ERROR.PROTOCOL_ERROR);
      }
      if (headers[':path'] === '' && headers[':method'] !== 'CONNECT') {
        throw F.h2Error('empty :path', F.ERROR.PROTOCOL_ERROR);
      }
    }
    if (!isServer && !stream.headersReceived && !headers[':status']) {
      throw F.h2Error('response is missing :status', F.ERROR.PROTOCOL_ERROR);
    }

    return headers;
  }


  function onData(frame) {
    var id = frame.streamId;
    var s = streams[id];

    // Flow control is accounted for even on a stream we are about to reject:
    // the peer has spent the window, and if we do not give it back the
    // connection stalls (§6.9.1). This is the classic "works until it
    // doesn't" bug — small bodies pass, then everything freezes.
    var len = frame.length;
    localWindow -= len;
    if (localWindow < 0) {
      throw F.h2Error('connection flow-control window exceeded', F.ERROR.FLOW_CONTROL_ERROR);
    }
    maybeSendConnectionWindowUpdate(len);

    if (isIdleStreamId(id)) {
      throw F.h2Error('DATA on an idle stream', F.ERROR.PROTOCOL_ERROR);
    }
    if (!s || s.state === STATE.CLOSED || s.state === STATE.HALF_CLOSED_REMOTE) {
      // DATA after END_STREAM is a connection error for the same reason as
      // HEADERS; after a reset it is a stream error. §5.1 again.
      if (s && s.closedBy === 'rst') {
        streamError(id, F.ERROR.STREAM_CLOSED, 'DATA after RST_STREAM');
      } else {
        throw F.h2Error('DATA after END_STREAM', F.ERROR.STREAM_CLOSED);
      }
      return;
    }

    s.localWindow -= len;
    if (s.localWindow < 0) {
      streamError(id, F.ERROR.FLOW_CONTROL_ERROR, 'stream window exceeded');
      return;
    }

    s.bytesReceived += frame.data.length;
    if (s.contentLength !== null && s.bytesReceived > s.contentLength) {
      streamError(id, F.ERROR.PROTOCOL_ERROR, 'body longer than content-length');
      return;
    }

    if (frame.data.length) emit('data', id, frame.data);
    maybeSendStreamWindowUpdate(s, len);

    if (frame.endStream) {
      if (s.contentLength !== null && s.bytesReceived !== s.contentLength) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, 'body shorter than content-length');
        return;
      }
      receiveEndStream(s);
    }
  }

  function receiveEndStream(s) {
    s.endStreamReceived = true;
    if (s.state === STATE.OPEN) s.state = STATE.HALF_CLOSED_REMOTE;
    else if (s.state === STATE.HALF_CLOSED_LOCAL) closeStream(s.id, 'end');
    emit('end', s.id);
  }


  function onRstStream(frame) {
    if (isIdleStreamId(frame.streamId)) {
      throw F.h2Error('RST_STREAM on an idle stream', F.ERROR.PROTOCOL_ERROR);
    }
    closeStream(frame.streamId, 'rst');
    emit('rst', frame.streamId, frame.errorCode);
  }


  function onWindowUpdate(frame) {
    if (frame.streamId === 0) {
      remoteWindow += frame.increment;
      if (remoteWindow > F.MAX_WINDOW) {
        throw F.h2Error('connection send window overflow', F.ERROR.FLOW_CONTROL_ERROR);
      }
      for (var id in streams) flushStream(streams[id]);
      return;
    }

    if (isIdleStreamId(frame.streamId)) {
      // §5.1: nothing may be sent for a stream that was never opened. This is
      // the distinction the old code missed — it lumped "idle" together with
      // "closed" and ignored both, so h2spec §5.1.3 waited for a GOAWAY that
      // never came.
      throw F.h2Error('WINDOW_UPDATE on an idle stream', F.ERROR.PROTOCOL_ERROR);
    }

    var s = streams[frame.streamId];
    if (!s || s.state === STATE.CLOSED) {
      // Genuinely closed: the peer had this in flight when we closed the
      // stream, which is ordinary and must be ignored (§6.9).
      return;
    }
    s.remoteWindow += frame.increment;
    if (s.remoteWindow > F.MAX_WINDOW) {
      streamError(frame.streamId, F.ERROR.FLOW_CONTROL_ERROR, 'stream send window overflow');
      return;
    }
    flushStream(s);
  }


  function onPing(frame) {
    if (frame.ack) { emit('pong', frame.payload); return; }
    // §6.7: a PING must be answered immediately with the same payload. It is
    // also how a peer measures RTT, so delaying it is not neutral.
    write(F.buildPing(frame.payload, true));
    emit('ping', frame.payload);
  }


  function onGoaway(frame) {
    goawayReceived = true;
    emit('goaway', frame.lastStreamId, frame.errorCode, frame.debugData);
  }


  // ============================================================
  //  Flow control — receive side
  //
  //  When credit is returned decides whether flow control does anything at all.
  //
  //  autoWindowUpdate (the default) grants it as soon as a DATA frame is
  //  parsed. Simple, and correct for a consumer that keeps up — but it means
  //  the window never actually closes, so there is no back-pressure: a peer
  //  can push a body far faster than the application reads it and the excess
  //  piles up in our memory. That is fine for a proxy that forwards
  //  immediately and wrong for anything that buffers.
  //
  //  With autoWindowUpdate false, credit is returned only when the consumer
  //  calls consume(streamId, bytes). The window then reflects what has really
  //  been dealt with, and a slow application slows the peer down instead of
  //  filling the heap. h2_server uses this so that a paused Readable
  //  back-pressures the network, the same way h1_server lets TCP do it.
  //
  //  The threshold exists because a WINDOW_UPDATE per DATA frame doubles the
  //  frame count for no benefit; half the window is what every implementation
  //  uses.
  // ============================================================

  var autoWindowUpdate = options.autoWindowUpdate !== false;
  var creditNow = autoWindowUpdate;
  var pendingConnectionCredit = 0;

  function maybeSendConnectionWindowUpdate(consumed) {
    pendingConnectionCredit += consumed;
    if (!creditNow) return;
    // Keyed off the connection window's own size, for the same reason as
    // above: with a small INITIAL_WINDOW_SIZE this would otherwise emit a
    // WINDOW_UPDATE for stream 0 after every few bytes.
    var threshold = Math.max(1, Math.floor(F.DEFAULT_WINDOW_SIZE / 2));
    if (pendingConnectionCredit >= threshold) {
      write(F.buildWindowUpdate(0, pendingConnectionCredit));
      localWindow += pendingConnectionCredit;
      pendingConnectionCredit = 0;
    }
  }

  function maybeSendStreamWindowUpdate(s, consumed) {
    s.pendingCredit = (s.pendingCredit || 0) + consumed;
    if (!creditNow) return;
    var threshold = Math.max(1, Math.floor(localSettings.INITIAL_WINDOW_SIZE / 2));
    if (s.pendingCredit >= threshold && s.state !== STATE.CLOSED) {
      write(F.buildWindowUpdate(s.id, s.pendingCredit));
      s.localWindow += s.pendingCredit;
      s.pendingCredit = 0;
    }
  }


  // ============================================================
  //  Sending
  // ============================================================

  function sendPreface() {
    if (!isServer) write(F.PREFACE);
    write(F.buildSettings(localSettings, false));
  }

  function sendHeaders(streamId, headers, endStream) {
    var s = getStream(streamId, true);
    if (s.state === STATE.IDLE) s.state = STATE.OPEN;

    var block = encoder.encode(headers);
    var frames = F.buildHeaderFrames(streamId, block, { endStream: !!endStream },
                                     remoteSettings.MAX_FRAME_SIZE);
    // Concatenated into ONE write: §6.10 forbids any other frame between
    // HEADERS and its CONTINUATIONs, and emitting them separately invites a
    // caller (or a queue) to interleave.
    write(Buffer.concat(frames));

    if (endStream) sendEndStream(s);
  }

  /**
   * Queue body bytes. Returns false when the send window is closed, so a
   * caller can stop producing — the same contract as a Node stream's write().
   */
  function sendData(streamId, data, endStream) {
    var s = streams[streamId];
    if (!s || s.state === STATE.CLOSED) return false;
    if (data && data.length) s.pendingData.push(Buffer.from(data));
    if (endStream) s.pendingEnd = true;
    flushStream(s);
    return sendableBytes(s) > 0;
  }

  function sendableBytes(s) {
    return Math.max(0, Math.min(s.remoteWindow, remoteWindow));
  }

  /**
   * Write as much of a stream's queue as both windows allow, split to
   * MAX_FRAME_SIZE.
   *
   * Both windows: the connection's and the stream's. Checking only one is the
   * single most common HTTP/2 flow-control bug — it works in every test with a
   * single stream and deadlocks the moment there are several, because one
   * greedy stream drains the connection window and the others never learn why
   * they stalled.
   */
  function flushStream(s) {
    if (!s || s.state === STATE.CLOSED) return;
    var wasBlocked = s.pendingData.length > 0;

    while (s.pendingData.length > 0) {
      var budget = Math.min(sendableBytes(s), remoteSettings.MAX_FRAME_SIZE);
      if (budget <= 0) return;

      var chunk = s.pendingData[0];
      var take = Math.min(chunk.length, budget);
      var piece = chunk.subarray(0, take);

      if (take === chunk.length) s.pendingData.shift();
      else s.pendingData[0] = chunk.subarray(take);

      s.remoteWindow -= take;
      remoteWindow -= take;

      var last = s.pendingData.length === 0 && s.pendingEnd;
      write(F.buildData(s.id, piece, !!last));
      if (last) { s.pendingEnd = false; sendEndStream(s); }
    }

    if (s.pendingEnd && s.pendingData.length === 0) {
      s.pendingEnd = false;
      write(F.buildData(s.id, Buffer.alloc(0), true));
      sendEndStream(s);
    }

    if (wasBlocked && s.pendingData.length === 0) emit('drain', s.id);
  }

  function sendEndStream(s) {
    s.endStreamSent = true;
    if (s.state === STATE.OPEN) s.state = STATE.HALF_CLOSED_LOCAL;
    else if (s.state === STATE.HALF_CLOSED_REMOTE) closeStream(s.id, 'end');
  }

  function sendGoaway(errorCode, debug) {
    if (goawaySent) return;
    goawaySent = true;
    write(F.buildGoaway(lastRemoteStreamId, errorCode || F.ERROR.NO_ERROR, debug));
  }


  // ============================================================
  //  API
  // ============================================================

  this.on = on;
  // off() matters here in a way it does not for a parser: h2_server registers
  // a one-shot 'drain' listener per blocked write, and a long response on a
  // narrow window blocks thousands of times. Without a way to remove them the
  // listener array grows for the life of the connection.
  this.off = off;
  this.execute = execute;
  this.sendPreface = sendPreface;
  this.sendHeaders = sendHeaders;
  this.sendData = sendData;
  this.sendGoaway = sendGoaway;

  this.sendRstStream = function (streamId, errorCode) {
    streamError(streamId, errorCode === undefined ? F.ERROR.CANCEL : errorCode);
  };

  this.sendPing = function (payload) { write(F.buildPing(payload, false)); };

  this.sendTrailers = function (streamId, headers) {
    var s = streams[streamId];
    if (!s || s.state === STATE.CLOSED) return;
    var block = encoder.encode(headers);
    write(Buffer.concat(F.buildHeaderFrames(streamId, block, { endStream: true },
                                            remoteSettings.MAX_FRAME_SIZE)));
    sendEndStream(s);
  };

  /** Allocate the next stream id for a locally initiated stream. */
  this.nextStreamId = function () {
    var id = nextLocalStreamId;
    nextLocalStreamId += 2;
    return id;
  };

  /**
   * Tell the connection that `bytes` of a stream's body have been dealt with,
   * returning that much flow-control credit to the peer.
   *
   * Only meaningful with autoWindowUpdate: false; with the default the credit
   * has already been returned and this is a no-op.
   */
  this.consume = function (streamId, bytes) {
    if (autoWindowUpdate) return;
    var s = streams[streamId];
    creditNow = true;
    try {
      maybeSendConnectionWindowUpdate(0);
      if (s) {
        s.pendingCredit = (s.pendingCredit || 0);
        maybeSendStreamWindowUpdate(s, 0);
      }
    } finally { creditNow = false; }
  };

  this.getStreamState = function (id) {
    var s = streams[id];
    return s ? s.state : STATE.IDLE;
  };

  this.canSend = function (id) {
    var s = streams[id];
    return s ? sendableBytes(s) > 0 : false;
  };

  Object.defineProperty(this, 'localSettings',  { get: function () { return localSettings; } });
  Object.defineProperty(this, 'remoteSettings', { get: function () { return remoteSettings; } });
  Object.defineProperty(this, 'activeStreams',  { get: function () { return countActiveStreams(); } });
  Object.defineProperty(this, 'goawayReceived', { get: function () { return goawayReceived; } });
  Object.defineProperty(this, 'closed',         { get: function () { return closed; } });

  return this;
}


export { H2Connection, STATE };
