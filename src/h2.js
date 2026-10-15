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
  Emitter, parseContentLength, validateFieldSection, parsePriority, formatPriority
} from './http_common.js';
import { mergePriority } from './utils.js';


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
//    'stream_close' (streamId)    — a stream that was open is closed (both
//                                   ends, or reset); `activeStreams` counts the rest
//    'window_blocked' (streamId)  — a stream's DATA waits for the peer to
//                                   open a window (WINDOW_UPDATE)
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
  // The server's counters (server_stats.js), when its server keeps them.
  var stats = options.stats || null;

  var ev = Emitter();
  var on = ev.on, emit = ev.emit, off = ev.off;

  // ---- Settings ----
  var localSettings = {
    HEADER_TABLE_SIZE:      options.headerTableSize      != null ? options.headerTableSize : 4096,
    ENABLE_PUSH:            0,          // we never accept push; see below
    // Node's own HTTP/2 server advertises 2^32-1 here, i.e. no limit, and
    // browsers are tuned against that. Advertising 100 is defensible but it is
    // a much lower ceiling than anything a browser expects to meet, and a
    // client that is counting streams against it may decline to open one it
    // would otherwise have opened. Matching Node removes that variable; a
    // caller that wants a real limit can still set one.
    // 100 is what browsers, nghttp2 and most public servers settle on, and it
    // is what h2spec §5.1.2 exercises: a server advertising 2^32-1 is saying
    // there is no limit, and the conformance suite duly tries to open that
    // many streams. Node's own server does advertise 2^32-1, but Node is not
    // trying to be a public-facing server by default.
    //
    // Worth being deliberate about rather than inherited: this is the only
    // backstop against a peer opening unbounded streams, and each stream costs
    // memory that the flow-control window does not bound. A caller that wants
    // a different ceiling can now set one — that option used to be dropped
    // before it reached this layer.
    MAX_CONCURRENT_STREAMS: options.maxConcurrentStreams != null ? options.maxConcurrentStreams : 100,
    INITIAL_WINDOW_SIZE:    options.initialWindowSize    != null ? options.initialWindowSize : 65535,
    MAX_FRAME_SIZE:         options.maxFrameSize         != null ? options.maxFrameSize : 16384,
    MAX_HEADER_LIST_SIZE:   options.maxHeaderListSize    != null ? options.maxHeaderListSize : 128 * 1024,
    // RFC 8441. A server advertises it so clients may run WebSocket over this
    // connection; a client never does (it has nothing to offer a server), so
    // it is only included below when isServer.
    ENABLE_CONNECT_PROTOCOL: (isServer && options.enableConnectProtocol !== false) ? 1 : 0
  };
  // RFC 9218 §2.1: the server reads RFC 9218's signals, not RFC 7540's tree.
  // A server's only: a client's SETTINGS are left as they were (a client
  // profile may be matching a browser's exactly).
  if (isServer) localSettings.NO_RFC7540_PRIORITIES = 1;

  var remoteSettings = {
    HEADER_TABLE_SIZE:      4096,
    ENABLE_PUSH:            1,
    MAX_CONCURRENT_STREAMS: Infinity,
    INITIAL_WINDOW_SIZE:    F.DEFAULT_WINDOW_SIZE,
    MAX_FRAME_SIZE:         F.DEFAULT_MAX_FRAME_SIZE,
    MAX_HEADER_LIST_SIZE:   Infinity,
    ENABLE_CONNECT_PROTOCOL: 0
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
  var goawayLastStreamId = 0;   // the last-stream-id our GOAWAY carried
  // Streams counted against MAX_CONCURRENT_STREAMS, kept as a count: it was
  // recomputed by walking every stream record on every new HEADERS.
  var activeCount = 0;
  // Whether the transport below can take more right now (the socket's buffer
  // is not over its mark). DATA waits while it cannot; see flushStream.
  var isWriteBlocked = typeof options.isWriteBlocked === 'function' ? options.isWriteBlocked : function () { return false; };
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

  // What we widen the connection receive window to in our first flight; see
  // sendPreface. Configurable because a proxy fanning out thousands of
  // connections may not want 16MB of credit outstanding on each.
  var CONNECTION_WINDOW = options.connectionWindowSize != null
                        ? options.connectionWindowSize
                        : 16 * 1024 * 1024;

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
    // A protocol error says what was wrong; anything else is ours (an
    // exception from a listener, the application's request handler among
    // them) and is INTERNAL_ERROR, with no detail. Its message went out as the
    // GOAWAY's debug data — internal error text handed to the client — under
    // PROTOCOL_ERROR, which blamed the peer.
    if (err.h2Code) sendGoaway(err.h2Code, err.message);
    else sendGoaway(F.ERROR.INTERNAL_ERROR, 'internal error');
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
      // A stream the peer reset stays so: it is the peer's later frames that
      // this answers.
      if (s.closedBy !== 'rst_received') s.closedBy = 'rst_sent';
      markClosed(s);
    }

    write(F.buildRstStream(streamId, code));
    if (stats) stats.code(stats.streamResets.h2.sent, code);
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
   *   'rst_sent'     — we reset it. What the peer sent before our RST_STREAM
   *                    reached it is still arriving — a response's DATA up to
   *                    a whole stream window — and §5.1 says to ignore it:
   *                    "An endpoint MUST ignore frames that it receives on
   *                    closed streams after it has sent a RST_STREAM frame"
   *                    (counted in the connection's flow control all the
   *                    same, §6.9). Each was answered with another RST_STREAM,
   *                    and past MAX_RESETS_PER_STREAM the connection went
   *                    (ENHANCE_YOUR_CALM): a download the client cancelled
   *                    took the client's whole connection down with it once
   *                    more than 8 frames were in flight.
   *   'rst_received' — the peer reset it, so it knows the stream is gone: a
   *                    frame after that is answered STREAM_CLOSED, a stream
   *                    error (h2spec §5.1.9–11).
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
    if (how) s.closedBy = how;
    markClosed(s);
  }

  function markOpen(s) {
    s.state = STATE.OPEN;
    if (!s.active) { s.active = true; activeCount++; }
  }

  // Closed streams are kept briefly rather than deleted: frames for a
  // just-closed stream are ordinary (the peer had them in flight when we
  // closed it) and must be ignored, not treated as frames for an idle stream
  // — which would be a connection error. Kept in the order they closed, and
  // let go after 30 s or beyond the most recent MAX_RETAINED_CLOSED. The sweep
  // walked every record on every close once there were 1000 of them, and kept
  // everything closed in the last 30 s however many that was — a peer that
  // opened and reset streams as fast as it could grew the map without bound
  // and made each close slower than the last.
  var MAX_RETAINED_CLOSED = 4096;
  var closedOrder = [];
  function markClosed(s) {
    s.state = STATE.CLOSED;
    s.pendingData = [];
    waiting.delete(s);
    if (s.active) { s.active = false; activeCount--; emit('stream_close', s.id); }
    if (s.closedAt) return;
    s.closedAt = Date.now();
    closedOrder.push(s.id);
    var cutoff = s.closedAt - 30000;
    while (closedOrder.length > 0) {
      var old = streams[closedOrder[0]];
      if (old && old.state === STATE.CLOSED && closedOrder.length <= MAX_RETAINED_CLOSED && old.closedAt >= cutoff) break;
      if (old && old.state === STATE.CLOSED) delete streams[closedOrder[0]];
      closedOrder.shift();
    }
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

      // Every frame is handled once. A STREAM error — thrown by the parser
      // for a frame it refused, or by a handler — resets that stream and the
      // loop goes on from the next frame. It used to end the loop with the
      // buffer not advanced: every frame of the chunk already handled was
      // handled again on the next read (a HEADERS block decoded twice, the
      // HPACK table desynchronised), and the buffer only grew.
      var offset = 0;
      for (;;) {
        var frame;
        try {
          frame = F.readFrame(buf, offset, localSettings.MAX_FRAME_SIZE);
        } catch (err) {
          if (!err.streamId || !err.consumed) throw err;
          offset += err.consumed;
          streamError(err.streamId, err.h2Code, err.message);
          if (closed) return;
          continue;
        }
        if (!frame) break;
        offset += frame.consumed;
        try {
          handleFrame(frame);
        } catch (err) {
          if (!err.streamId) throw err;
          streamError(err.streamId, err.h2Code, err.message);
        }
        if (closed) return;
      }
      buf = offset > 0 ? buf.subarray(offset) : buf;

    } catch (err) {
      connectionError(err);
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
      case F.TYPE.PRIORITY_UPDATE: return onPriorityUpdate(frame);
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

      if (name === 'ENABLE_CONNECT_PROTOCOL' &&
          remoteSettings.ENABLE_CONNECT_PROTOCOL === 1 && value === 0) {
        // §3: "a sender MUST NOT send a value of 0 after previously sending a
        // value of 1". A stream may already be running extended CONNECT, and
        // withdrawing permission would leave it in a state neither side can
        // describe.
        throw F.h2Error('SETTINGS_ENABLE_CONNECT_PROTOCOL cannot be withdrawn',
                        F.ERROR.PROTOCOL_ERROR);
      }

      remoteSettings[name] = value;

      if (name === 'HEADER_TABLE_SIZE') encoder.setMaxTableSize(value);
    }

    // The ACK must go out before anything that relies on the new settings.
    write(F.buildSettings(null, true));
    // Both forms: the object for consumers that want a value by name, and the
    // ordered list for fingerprinting, which needs the sequence as sent.
    emit('settings', frame.settings, frame.settingsList || []);

    // Flush anything that was waiting on a window this SETTINGS may have opened.
    flushAll();
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

    var streamIsNew = !streams[id];
    var s = getStream(id, true);

    // Every header block is decoded, whatever becomes of its stream — refused,
    // reset, or after our GOAWAY. The HPACK table is shared by the connection
    // and the peer's encoder has already applied this block to its copy; a
    // block skipped here leaves the two tables apart, and every later block on
    // every stream decodes wrong (RFC 9113 §4.3). A refused stream had its
    // block skipped, and, when it lacked END_HEADERS, its CONTINUATION then
    // found no open block and took the connection down. startHeaderBlock on a
    // stream already closed decodes and drops (finishHeaderBlock).

    // A new stream, announced before its request is processed — the point at
    // which a rate limiter can refuse it: refused here, it costs the block's
    // decode and never becomes a request. Guarded: no listener, no cost.
    if (streamIsNew && isServer && ev.listenerCount('stream_open')) {
      emit('stream_open', id);
      if (s.state === STATE.CLOSED) {
        // Refused by the listener (sendRstStream), which has already sent the
        // RST; the id is used all the same.
        lastRemoteStreamId = Math.max(lastRemoteStreamId, id);
        startHeaderBlock(frame, id);
        return;
      }
    }

    if (s.state === STATE.CLOSED) {
      if (s.closedBy === 'rst_sent') {
        // Reset by us: in flight before our RST_STREAM — ignored, its block
        // decoded all the same (HPACK's table is the connection's).
        startHeaderBlock(frame, id);
      } else if (s.closedBy === 'rst_received') {
        streamError(id, F.ERROR.STREAM_CLOSED, 'HEADERS after RST_STREAM');
        startHeaderBlock(frame, id);
      } else {
        throw F.h2Error('HEADERS after END_STREAM', F.ERROR.STREAM_CLOSED);
      }
      return;
    }
    if (s.state === STATE.HALF_CLOSED_REMOTE) {
      streamError(id, F.ERROR.STREAM_CLOSED, 'HEADERS after END_STREAM');
      startHeaderBlock(frame, id);
      return;
    }

    if (s.state === STATE.IDLE) {
      // Refused streams use their id too: ids only increase (§5.1.1), and a
      // refusal left lastRemoteStreamId behind, so a lower unused id was
      // still accepted afterwards.
      if (isServer) lastRemoteStreamId = id;

      // After our GOAWAY, a stream above its last-stream-id is not processed
      // (§6.8). It was: goaway() — which a rate limiter calls to stop a peer —
      // did not stop new requests at all. REFUSED_STREAM tells the client it
      // may retry the request on a new connection.
      if (isServer && goawaySent && id > goawayLastStreamId) {
        streamError(id, F.ERROR.REFUSED_STREAM, 'received after GOAWAY');
        startHeaderBlock(frame, id);
        return;
      }
      if (isServer && activeCount >= localSettings.MAX_CONCURRENT_STREAMS) {
        // §5.1.2: refusing is a stream error, and REFUSED_STREAM specifically
        // tells the peer the request was never processed, so it is safe to
        // retry elsewhere.
        streamError(id, F.ERROR.REFUSED_STREAM, 'too many concurrent streams');
        startHeaderBlock(frame, id);
        return;
      }
      markOpen(s);
    }

    startHeaderBlock(frame, id);
  }

  // A header block (HEADERS + CONTINUATION) is bounded while it accumulates,
  // before any of it can be decoded: in bytes, and in frames. Nothing bounded
  // it — fragments were collected until END_HEADERS, however many and however
  // large, including empty ones (the CONTINUATION flood of 2024). The byte
  // bound leaves room for the decoded list's own limit (MAX_HEADER_LIST_SIZE)
  // even through HPACK's worst-case expansion; the frame bound is nghttp2's,
  // and so node's. Past either, the block cannot be decoded and the HPACK
  // state is lost with it: a connection error.
  var MAX_CONTINUATION_FRAMES = 8;
  var continuationBytes = 0;
  var continuationCount = 0;
  function headerBlockByteLimit() {
    return Math.max(64 * 1024, 4 * localSettings.MAX_HEADER_LIST_SIZE);
  }

  function onContinuation(frame) {
    if (continuationStream === 0) {
      throw F.h2Error('CONTINUATION with no open header block', F.ERROR.PROTOCOL_ERROR);
    }
    continuationBytes += frame.headerBlock.length;
    if (++continuationCount > MAX_CONTINUATION_FRAMES) {
      throw F.h2Error('header block split across too many CONTINUATION frames', F.ERROR.ENHANCE_YOUR_CALM);
    }
    if (continuationBytes > headerBlockByteLimit()) {
      throw F.h2Error('header block too large', F.ERROR.ENHANCE_YOUR_CALM);
    }
    continuationFragments.push(frame.headerBlock);
    if (frame.endHeaders) finishHeaderBlock();
  }

  // A header block left open — HEADERS without END_HEADERS — holds the whole
  // connection: until its CONTINUATIONs end it, no other frame may arrive
  // (§6.10). 'header_block_open' and 'header_block_closed' bracket that time,
  // for whoever bounds it (h2_server's headersTimeout); refused and reset
  // streams' blocks included, since they hold the connection just the same.
  var headerBlockOpen = false;

  function startHeaderBlock(frame, id) {
    continuationStream = id;
    continuationFragments = [frame.headerBlock];
    continuationFrame = frame;
    continuationBytes = frame.headerBlock.length;
    continuationCount = 0;
    if (frame.endHeaders) { finishHeaderBlock(); return; }
    headerBlockOpen = true;
    emit('header_block_open', id);
  }

  function finishHeaderBlock() {
    var id = continuationStream;
    var frame = continuationFrame;
    var block = Buffer.concat(continuationFragments);

    continuationStream = 0;
    continuationFragments = [];
    continuationFrame = null;
    if (headerBlockOpen) { headerBlockOpen = false; emit('header_block_closed', id); }

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
      // A body that content-length promised and the trailers ended short
      // (§8.1.1) — checked on DATA's END_STREAM, not here.
      if (isServer && s.contentLength !== null && s.bytesReceived !== s.contentLength) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, 'body shorter than content-length');
        return;
      }
      s.trailersReceived = true;
      emit('trailers', id, headers);
    } else if (!isServer && /^1\d\d$/.test(String(headers[':status']))) {
      // A 1xx response (103 Early Hints) is not the response (§8.1): the
      // final head follows on the same stream. Counted as the head, the
      // real one after it was taken for trailers — with a :status in it,
      // malformed — and the stream was reset: a response with Early Hints
      // never arrived. It may not end the stream.
      if (frame.endStream) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, 'informational response with END_STREAM');
        return;
      }
      emit('headers', id, headers, false, null);
      return;
    } else {
      s.headersReceived = true;
      try {
        var n = parseContentLength(headers['content-length']);
        if (n !== null) s.contentLength = n;
      } catch (e) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, e.message);
        return;
      }
      // A request that promises a body and ends with its headers (§8.1.1).
      // Requests only: a response to HEAD, or a 304, carries a length and no body.
      if (isServer && frame.endStream && s.contentLength) {
        streamError(id, F.ERROR.PROTOCOL_ERROR, 'content-length ' + s.contentLength + ' but no body');
        return;
      }
      if (isServer) applyRequestPriority(s, headers);
      // An extended CONNECT stream is a bidirectional byte channel, not a
      // request/response pair: END_STREAM on the request would close the
      // client's half before the protocol on top has said anything.
      emit('headers', id, headers, !!frame.endStream, s.extendedConnect || null);
    }

    if (frame.endStream) receiveEndStream(s);
  }


  /**
   * §8.3 and §8.2.2. Malformed here means a STREAM error, not a connection
   * error: one bad request should not take down the other streams sharing the
   * connection.
   */
  function validateHeaderList(list, stream) {
    // The rules are shared with HTTP/3 (validateFieldSection, http_common);
    // what is HTTP/2's is the answer — a stream error, PROTOCOL_ERROR — and
    // where the result goes.
    var r;
    try {
      r = validateFieldSection(list, {
        isServer: isServer,
        trailers: stream.headersReceived,
        connectProtocol: !!localSettings.ENABLE_CONNECT_PROTOCOL
      });
    } catch (err) {
      throw F.h2Error(err.message, F.ERROR.PROTOCOL_ERROR);
    }
    if (r.protocol) stream.extendedConnect = r.protocol;
    // Emitted only after validation passes: a malformed header list is not a
    // fingerprint, and reporting one would let a peer feed noise into whatever
    // is collecting these.
    if (r.pseudoOrder.length) emit('pseudo_order', r.pseudoOrder);
    return r.headers;
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
      if (s && s.closedBy === 'rst_sent') {
        // In flight before our RST_STREAM: ignored (counted above).
      } else if (s && s.closedBy === 'rst_received') {
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
    closeStream(frame.streamId, 'rst_received');
    if (stats) stats.code(stats.streamResets.h2.received, frame.errorCode);
    emit('rst', frame.streamId, frame.errorCode);

    // Separate from 'rst', which also fires for resets WE send. Only the
    // peer's resets are the Rapid Reset signal (CVE-2023-44487): open a
    // stream, reset it immediately, repeat. MAX_CONCURRENT_STREAMS never
    // catches it because no stream stays open — the rate of resets is the
    // only thing that shows it.
    if (ev.listenerCount('stream_reset')) {
      emit('stream_reset', frame.streamId, frame.errorCode);
    }
  }


  function onWindowUpdate(frame) {
    // Surfaced before any validation: the connection-level increment a peer
    // opens with is one of the strongest implementation tells there is —
    // Chrome sends 15663105, Firefox 12517377, and most libraries send none.
    emit('window_update', frame.streamId, frame.increment);

    if (frame.streamId === 0) {
      remoteWindow += frame.increment;
      if (remoteWindow > F.MAX_WINDOW) {
        throw F.h2Error('connection send window overflow', F.ERROR.FLOW_CONTROL_ERROR);
      }
      flushAll();
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
    if (stats) stats.code(stats.closes.h2.received, frame.errorCode);
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
    // WINDOW_UPDATE for stream 0 after every few bytes. Its own size is
    // CONNECTION_WINDOW (sendPreface widens it to that), not the 65535 it
    // starts at: keyed off that, it went every 32 KB of a 16 MB window — a
    // frame, a TLS record and a system call per 32 KB, 3000 of them in a
    // 96 MB download, 10% of the client's CPU.
    var threshold = Math.max(1, Math.floor(Math.max(F.DEFAULT_WINDOW_SIZE, CONNECTION_WINDOW) / 2));
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

    var toSend = {};
    for (var k in localSettings) {
      // A client has no use for ENABLE_CONNECT_PROTOCOL: it is a server
      // telling clients what they may ask for, and RFC 8441 §3 only defines
      // the server-to-client direction.
      if (k === 'ENABLE_CONNECT_PROTOCOL' && !isServer) continue;
      toSend[k] = localSettings[k];
    }
    write(F.buildSettings(toSend, false));

    // Widen the CONNECTION receive window immediately.
    //
    // It starts at 65535 and, unlike a stream window, SETTINGS cannot change
    // it — RFC 9113 §6.9.2 leaves WINDOW_UPDATE on stream 0 as the only way to
    // move it. A server that never sends one is telling every peer it can
    // accept 64KB across the whole connection before stopping to wait for
    // credit, no matter how many streams are open or how large the per-stream
    // windows are.
    //
    // Every real implementation widens it in its first flight, which is why
    // Chrome's HTTP/2 session table shows send windows in the megabytes for
    // other servers and exactly 65535 for one that does not. On a fast link
    // the difference is a round trip per 64KB — the connection spends most of
    // its time waiting for WINDOW_UPDATEs it could have been given up front.
    //
    // 16MB nearly matches what Chrome itself advertises (15728640) and is
    // comfortably under the 2^31-1 ceiling.
    var bump = CONNECTION_WINDOW - F.DEFAULT_WINDOW_SIZE;
    if (bump > 0) {
      localWindow += bump;
      write(F.buildWindowUpdate(0, bump));
    }
  }

  function sendHeaders(streamId, headers, endStream) {
    var s = getStream(streamId, true);
    if (s.state === STATE.IDLE) markOpen(s);

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
    // The caller's bytes as they are, not a copy — as net.Socket takes them:
    // what is handed to write() is not the caller's to change until it has
    // gone. A copy here, and another to put a frame header in front of each
    // piece, were most of what a large response cost.
    if (data && data.length) {
      s.pendingData.push(typeof data === 'string' ? Buffer.from(data)
        : Buffer.isBuffer(data) ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength));
    }
    if (endStream) s.pendingEnd = true;
    // Straight out while nothing else waits; behind the others, in their
    // order, when something does (see flushAll).
    if (waiting.size === 0 || (waiting.size === 1 && waiting.has(s))) flushStream(s);
    else { waiting.add(s); flushAll(); }
    // Done with this write once nothing of it is left queued; 'drain' follows
    // when what is queued has gone. It returned whether the window was still
    // open — so a write that used it up exactly, leaving nothing queued, was
    // told to wait for a 'drain' that nothing would ever emit.
    return s.pendingData.length === 0;
  }

  function sendableBytes(s) {
    return Math.max(0, Math.min(s.remoteWindow, remoteWindow));
  }

  /**
   * One DATA frame of a stream's queue — as much as both windows allow, up to
   * MAX_FRAME_SIZE — or its END_STREAM alone once the queue is empty. True if
   * a frame was written.
   *
   * Both windows: the connection's and the stream's. Checking only one is the
   * single most common HTTP/2 flow-control bug — it works in every test with a
   * single stream and deadlocks the moment there are several, because one
   * greedy stream drains the connection window and the others never learn why
   * they stalled.
   */
  function writeFrame(s) {
    if (s.state === STATE.CLOSED) return false;
    if (s.pendingData.length === 0) {
      if (!s.pendingEnd) return false;
      s.pendingEnd = false;
      write(F.buildData(s.id, Buffer.alloc(0), true));
      sendEndStream(s);
      return true;
    }
    // The windows say what the PEER will accept; the transport's buffer says
    // what is actually leaving. A peer that grants a large window and then
    // stops reading had every byte its windows allowed — up to 2 GB a stream
    // — queued in the socket (the "internal data buffering" attack of 2019).
    // DATA now waits in this queue, and flushAll() resumes when the socket
    // drains.
    if (isWriteBlocked()) return false;
    var budget = Math.min(sendableBytes(s), remoteSettings.MAX_FRAME_SIZE);
    if (budget <= 0) { emit('window_blocked', s.id); return false; }

    var chunk = s.pendingData[0];
    var take = Math.min(chunk.length, budget);
    var piece = chunk.subarray(0, take);

    if (take === chunk.length) s.pendingData.shift();
    else s.pendingData[0] = chunk.subarray(take);

    s.remoteWindow -= take;
    remoteWindow -= take;

    var last = s.pendingData.length === 0 && s.pendingEnd;
    // Header and payload as two writes, the payload never copied; the
    // server corks the socket, so they still leave together.
    write(F.frameHeader(take, F.TYPE.DATA, last ? F.FLAG.END_STREAM : 0, s.id));
    write(piece);
    if (last) { s.pendingEnd = false; sendEndStream(s); }
    if (s.pendingData.length === 0) { waiting.delete(s); emit('drain', s.id); }
    return true;
  }

  // As much of one stream's queue as can go now; what cannot waits (waiting).
  function flushStream(s) {
    if (!s) return;
    while (writeFrame(s)) {}
    if (s.state !== STATE.CLOSED && (s.pendingData.length > 0 || s.pendingEnd)) waiting.add(s);
    else waiting.delete(s);
  }

  // ---- Which stream's DATA goes next (RFC 9218) ────────────────────────
  //
  // The streams whose DATA waits — for a window, or for the socket to drain —
  // and the order they go in when there is room, by the rules HTTP/3's
  // sender uses (quic_connection's execute_quic_burst): urgency first, most
  // urgent first; within one, the non-incremental streams one at a time, by
  // stream number, then the incremental ones taking turns, a frame each,
  // the round starting after whoever went first last time. A stream with no
  // signal takes turns at urgency 3. They went by stream number, each until
  // blocked: after every drain the lowest-numbered stream took all the room.
  //
  // Only what waits is ordered: a write while nothing waits goes straight to
  // the socket, and what the socket holds (up to its mark, isWriteBlocked)
  // leaves in the order it was written.
  var waiting = new Set();
  var rrCursor = {};   // urgency → the stream that opened the last round

  function flushAll() {
    if (waiting.size === 0) return;
    var tiers = new Map();
    waiting.forEach(function (s) {
      if (s.state === STATE.CLOSED) { waiting.delete(s); return; }
      var pr = s.priority, u = pr && pr.urgency != null ? pr.urgency : 3;
      var t = tiers.get(u);
      if (!t) { t = { seq: [], inc: [] }; tiers.set(u, t); }
      (pr && pr.incremental === false ? t.seq : t.inc).push(s);
    });
    var byId = function (a, b) { return a.id - b.id; };
    var urgencies = Array.from(tiers.keys()).sort(function (a, b) { return a - b; });
    for (var ui = 0; ui < urgencies.length; ui++) {
      var u = urgencies[ui], t = tiers.get(u);
      t.seq.sort(byId);
      for (var i = 0; i < t.seq.length; i++) {
        flushStream(t.seq[i]);
        if (isWriteBlocked()) return;
      }
      var inc = t.inc.sort(byId);
      if (inc.length === 0) continue;
      var first = 0;
      if (rrCursor[u] !== undefined) {
        while (first < inc.length && inc[first].id <= rrCursor[u]) first++;
        if (first === inc.length) first = 0;
      }
      var opened = false, progress = true;
      while (progress) {
        progress = false;
        for (var k = 0; k < inc.length; k++) {
          var st = inc[(first + k) % inc.length];
          if (!writeFrame(st)) continue;
          progress = true;
          if (!opened) { rrCursor[u] = st.id; opened = true; }
        }
        if (isWriteBlocked()) break;
      }
      for (var j = 0; j < inc.length; j++) flushStream(inc[j]);   // waiting, as they now are
      if (isWriteBlocked()) return;
    }
  }

  // ---- RFC 9218's signals ----
  //
  // As in HTTP/3 (h3.js): a request's `priority` header and PRIORITY_UPDATE,
  // which replaces it, are the client's signals; what the application sets
  // (setStreamPriority, h2_server's res.setPriority) is the server's decision,
  // and a signal does not override it (mergePriority). An update for a
  // stream not yet opened is held until its request arrives — bounded,
  // oldest out.
  var PRIORITY_PENDING_MAX = 128;
  var prioPending = new Map();   // stream id → Priority Field Value

  function setStreamPriority(id, p, fromPeer) {
    var s = streams[id];
    if (!s || s.state === STATE.CLOSED) return false;
    s.priority = mergePriority(s.priority || {}, p, fromPeer);
    if (waiting.has(s)) flushAll();
    return true;
  }

  function applyRequestPriority(s, headers) {
    if (headers.priority != null) setStreamPriority(s.id, parsePriority(headers.priority), true);
    if (prioPending.has(s.id)) {
      setStreamPriority(s.id, parsePriority(prioPending.get(s.id)), true);
      prioPending.delete(s.id);
    }
  }

  function onPriorityUpdate(frame) {
    // §7.1: the server sends none; the stream must be one the client opens.
    if (!isServer) throw F.h2Error('PRIORITY_UPDATE from the server', F.ERROR.PROTOCOL_ERROR);
    var id = frame.prioritizedStreamId;
    if (id % 2 !== 1) throw F.h2Error('PRIORITY_UPDATE for stream ' + id + ', not a request stream', F.ERROR.PROTOCOL_ERROR);
    var s = streams[id];
    if (isIdleStreamId(id) || (s && !s.headersReceived)) {
      prioPending.delete(id);
      prioPending.set(id, frame.priorityField);
      if (prioPending.size > PRIORITY_PENDING_MAX) prioPending.delete(prioPending.keys().next().value);
      return;
    }
    setStreamPriority(id, parsePriority(frame.priorityField), true);   // a closed stream: nothing to do
  }

  function sendEndStream(s) {
    s.endStreamSent = true;
    if (s.state === STATE.OPEN) {
      s.state = STATE.HALF_CLOSED_LOCAL;
      // Our side is done and the peer's is not: a server that answered
      // before the request body was in (RFC 9113 §8.1). The layer above
      // decides whether to tell the client to stop (RST_STREAM NO_ERROR).
      emit('local_end', s.id);
    }
    else if (s.state === STATE.HALF_CLOSED_REMOTE) closeStream(s.id, 'end');
  }

  function sendGoaway(errorCode, debug) {
    if (goawaySent) return;
    goawaySent = true;
    goawayLastStreamId = lastRemoteStreamId;
    write(F.buildGoaway(lastRemoteStreamId, errorCode || F.ERROR.NO_ERROR, debug));
    if (stats) stats.code(stats.closes.h2.sent, errorCode || F.ERROR.NO_ERROR);
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
  /** The transport can take more again (its 'drain'): send what DATA waited. */
  this.flushAll = flushAll;
  /**
   * A stream's priority: { urgency (0..7, 0 first; default 3), incremental }
   * (RFC 9218). Set by the application, it is the decision; fromPeer marks
   * the peer's signal, which does not override it (see mergePriority).
   */
  this.setStreamPriority = setStreamPriority;
  /** The client's side: change a request's priority after it was sent (RFC 9218 §7.1). */
  this.sendPriorityUpdate = function (streamId, p) {
    if (isServer) return false;
    write(F.buildPriorityUpdate(Number(streamId), formatPriority(p)));
    return true;
  };
  this.sendGoaway = sendGoaway;

  /**
   * Tell the peer to stop opening streams.
   *
   * NOT a disconnect: RFC 9113 §6.8 leaves streams below lastStreamId running
   * to completion, and only forbids new ones. That is what makes it right for
   * a rate limiter — in-flight requests still get answered — and wrong if the
   * intent is to cut the peer off, which needs destroying the socket as well.
   */
  this.goaway = function (errorCode) {
    sendGoaway(errorCode === undefined ? F.ERROR.NO_ERROR : errorCode);
  };

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

  /** The `:protocol` value if this stream is an extended CONNECT, else null. */
  this.getStreamProtocol = function (id) {
    var s = streams[id];
    return (s && s.extendedConnect) || null;
  };

  /** Whether the PEER told us it accepts extended CONNECT. */
  this.peerAllowsConnectProtocol = function () {
    return remoteSettings.ENABLE_CONNECT_PROTOCOL === 1;
  };

  this.getStreamState = function (id) {
    var s = streams[id];
    return s ? s.state : STATE.IDLE;
  };

  this.canSend = function (id) {
    var s = streams[id];
    return s ? sendableBytes(s) > 0 : false;
  };

  /** Whether some stream's DATA waits for the peer's WINDOW_UPDATE. */
  this.windowBlocked = function () {
    var blocked = false;
    waiting.forEach(function (s) {
      if (s.state !== STATE.CLOSED && s.pendingData.length > 0 && sendableBytes(s) <= 0) blocked = true;
    });
    return blocked;
  };

  Object.defineProperty(this, 'localSettings',  { get: function () { return localSettings; } });
  Object.defineProperty(this, 'remoteSettings', { get: function () { return remoteSettings; } });
  Object.defineProperty(this, 'activeStreams',  { get: function () { return activeCount; } });
  Object.defineProperty(this, 'goawayReceived', { get: function () { return goawayReceived; } });
  Object.defineProperty(this, 'closed',         { get: function () { return closed; } });

  return this;
}


// DATA waits while a socket holds this much unsent (isWriteBlocked) — the
// server's and the client's sessions alike.
var SOCKET_HIGH_WATER = 256 * 1024;

export { H2Connection, STATE, SOCKET_HIGH_WATER };
