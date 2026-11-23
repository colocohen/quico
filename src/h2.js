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
import { random_bytes_sync } from 'cryptographic-primitives/random.js';
import {
  Emitter, parseContentLength, validateFieldSection, parsePriority, formatPriority, argType, sessionGone, checkInt
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
//    'headers'  (streamId, headers, endStream, extendedConnect, list)
//                                 — list: the fields as they came, in order
//                                   ([name, value, neverIndex?], duplicates
//                                   and pseudo-headers in it): node:http2's
//                                   rawHeaders and sensitiveHeaders
//    'trailers' (streamId, headers, list)
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
  // exactSettings: the preface announces only what the caller set (options
  // below, given explicitly, and options.settings), nothing of quico's own,
  // and the connection window is not widened unless connectionWindowSize is
  // given: nghttp2's first flight, which node:http2 sends (an empty SETTINGS
  // when nothing is set). What is not announced holds at the RFC's initial
  // value (no stream limit, no CONNECT protocol), except the header list
  // limit, which is enforced either way (RFC 9113 §6.5.2 makes it advisory).
  var exactSettings = options.exactSettings === true;
  // Entries one SETTINGS may carry (onSettings); nghttp2's default.
  var maxSettings = options.maxSettings != null ? options.maxSettings : 32;
  var givenSettings = {};
  function opt(name, key, dflt, rfc) {
    if (options[name] != null) { givenSettings[key] = true; return options[name]; }
    return exactSettings ? rfc : dflt;
  }
  var localSettings = {
    HEADER_TABLE_SIZE:      opt('headerTableSize', 'HEADER_TABLE_SIZE', 4096, 4096),
    // A client takes server push only when asked (enablePush; a server's
    // means nothing). exactSettings: the RFC's 1, unannounced, as nghttp2.
    ENABLE_PUSH:            options.enablePush != null ? (givenSettings.ENABLE_PUSH = true, options.enablePush ? 1 : 0) : exactSettings ? 1 : 0,
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
    MAX_CONCURRENT_STREAMS: opt('maxConcurrentStreams', 'MAX_CONCURRENT_STREAMS', 100, Infinity),
    INITIAL_WINDOW_SIZE:    opt('initialWindowSize', 'INITIAL_WINDOW_SIZE', 65535, 65535),
    MAX_FRAME_SIZE:         opt('maxFrameSize', 'MAX_FRAME_SIZE', 16384, 16384),
    MAX_HEADER_LIST_SIZE:   opt('maxHeaderListSize', 'MAX_HEADER_LIST_SIZE', 128 * 1024, 128 * 1024),
    // RFC 8441. A server advertises it so clients may run WebSocket over this
    // connection; a client never does (it has nothing to offer a server), so
    // it is only included below when isServer.
    ENABLE_CONNECT_PROTOCOL: (isServer && (exactSettings ? options.enableConnectProtocol === true : options.enableConnectProtocol !== false)) ? 1 : 0
  };
  // RFC 9218 §2.1: the server reads RFC 9218's signals, not RFC 7540's tree.
  // A server's only: a client's SETTINGS are left as they were (a client
  // profile may be matching a browser's exactly).
  if (isServer && !exactSettings) localSettings.NO_RFC7540_PRIORITIES = 1;
  if (exactSettings && localSettings.ENABLE_CONNECT_PROTOCOL) givenSettings.ENABLE_CONNECT_PROTOCOL = true;

  // What the preface announces is not yet in effect: until the peer
  // acknowledges our SETTINGS it may hold to the RFC's initial values
  // (RFC 9113 §6.5.3) — send a stream 65535 bytes, a header block indexed
  // against a 4096-byte table, a 16384-byte frame. They were in effect at
  // once: a server with initialWindowSize 1000 answered a client's upload,
  // sent before our SETTINGS reached it, with FLOW_CONTROL_ERROR, and its
  // request was lost. Now these three take effect at the ACK (onSettings,
  // applyLocalSettings), as nghttp2 applies them; a peer that has read our
  // SETTINGS acknowledges them before it sends anything that relies on them,
  // so nothing it may send is refused. MAX_CONCURRENT_STREAMS and
  // MAX_HEADER_LIST_SIZE are only ever stricter: they hold from the start.
  // node:http2's `settings` option, by the RFC's names (toWire): over the
  // options above. A setting by number is a custom one (customSettings).
  var localCustom = {};      // custom settings of ours, in effect (acknowledged)
  var announcedCustom = {};
  if (options.settings) {
    for (var sk in options.settings) {
      // A number that names an RFC setting is that setting (as node:http2's
      // customSettings take one), not a custom one.
      var named = /^[0-9]+$/.test(sk) ? F.SETTINGS_NAME[Number(sk)] : sk;
      if (named === undefined) announcedCustom[sk] = options.settings[sk];
      // NO_RFC7540_PRIORITIES is a server's (RFC 9218 §2.1); a client's is ignored.
      else if (named in localSettings || named === 'ENABLE_PUSH' || (named === 'NO_RFC7540_PRIORITIES' && isServer)) {
        localSettings[named] = options.settings[sk];
        givenSettings[named] = true;
      }
    }
  }
  var remoteCustom = {};     // the peer's settings this side has no name for, by number
  var announced = {};
  for (var ak in localSettings) if (!exactSettings || givenSettings[ak]) announced[ak] = localSettings[ak];
  Object.assign(announced, announcedCustom);
  localSettings.INITIAL_WINDOW_SIZE = F.DEFAULT_WINDOW_SIZE;
  localSettings.HEADER_TABLE_SIZE = 4096;
  localSettings.MAX_FRAME_SIZE = F.DEFAULT_MAX_FRAME_SIZE;

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
                        : exactSettings ? F.DEFAULT_WINDOW_SIZE : 16 * 1024 * 1024;

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

  // node:http2's maxSessionInvalidFrames (default 1000): frames from the
  // peer that this side had to refuse — every stream error a received frame
  // caused (nghttp2's on_invalid_frame_recv), and empty DATA without
  // END_STREAM (node's HandleDataFrame) — that may come before the
  // connection is given up (CVE-2019-9518, a flood of them costs this side
  // work per frame and the peer nothing). Counted as node does: the one that
  // finds the count already past the bound ends it.
  var maxInvalidFrames = options.maxSessionInvalidFrames != null ? options.maxSessionInvalidFrames : 1000;
  var invalidFrames = 0;
  function invalidFrame() {
    if (invalidFrames++ <= maxInvalidFrames) return false;
    // node: ERR_HTTP2_TOO_MANY_INVALID_FRAMES, the session destroyed, which
    // sends GOAWAY INTERNAL_ERROR; the frame itself is not answered.
    var err = new Error('Too many invalid HTTP/2 frames');
    err.code = 'ERR_HTTP2_TOO_MANY_INVALID_FRAMES';
    sendGoaway(F.ERROR.INTERNAL_ERROR);
    closed = true;
    emit('error', err);
    return true;
  }

  // `local`: a reset of this side's choosing (sendRstStream, a stream refused
  // after our GOAWAY) rather than a refused frame of the peer's; not counted.
  function streamError(streamId, code, message, local) {
    if (!local && invalidFrame()) return;
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

  // Frames sent and received, nghttp2's counts (node:http2's perf entry,
  // framesSent / framesReceived). Sent, read off the frame headers as the
  // bytes go: a frame's header is always written whole, its payload may
  // follow in other writes (DATA's, writeData) — `sendPayloadLeft` of it is
  // still to come. The client's preface is not a frame.
  var framesSent = 0, framesReceived = 0;
  var sendPayloadLeft = 0;

  function write(buffer) {
    if (!buffer || !buffer.length) return;
    if (buffer !== F.PREFACE) {
      var fi = 0;
      while (fi < buffer.length) {
        if (sendPayloadLeft > 0) {
          var skip = Math.min(sendPayloadLeft, buffer.length - fi);
          sendPayloadLeft -= skip; fi += skip;
          continue;
        }
        framesSent++;
        sendPayloadLeft = buffer.readUIntBE(fi, 3);
        fi += 9;
      }
    }
    emit('send', buffer);
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
      pendingTrailers: null,  // trailers waiting for the queued DATA to go first
      contentLength: null,
      bytesReceived: 0,
      // The MAX_HEADER_LIST_SIZE in effect when the stream was made: its
      // header lists are held to it, a later SETTINGS notwithstanding (as
      // nghttp2 under node:http2: a request sent before the client lowered
      // it still takes its response).
      headerListLimit: localSettings.MAX_HEADER_LIST_SIZE
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

  // node:http2's maxSessionMemory, as what this connection holds for its
  // open streams: a stream's own state (STREAM_MEMORY, an estimate of
  // nghttp2's and node's per-stream objects), the header lists it received
  // (RFC 7541's entry sizes — what the application keeps of a request), and
  // the DATA queued on it, not yet sent. Past the bound, a new stream of the
  // peer's is refused ENHANCE_YOUR_CALM (node's CanAddStream), so a peer that
  // opens streams and then stops reading their responses (or sends header
  // lists it never finishes using) cannot hold this side's memory without
  // bound. In bytes; none by default (the servers set node's 10 MB).
  var maxSessionMemory = options.maxSessionMemory != null ? options.maxSessionMemory : Infinity;
  var STREAM_MEMORY = 1024;
  var streamMemory = 0;   // STREAM_MEMORY and header lists, of the active streams
  var queuedBytes = 0;    // DATA queued, of every stream
  function sessionMemory() { return streamMemory + queuedBytes; }

  // ---- Requests past the peer's MAX_CONCURRENT_STREAMS ----
  // A client's request whose HEADERS would open more streams than the server
  // allows waits (its DATA and trailers behind it) until one of ours closes,
  // in id order — nghttp2's ob_syn queue, and so node:http2's: a request is
  // never refused for being one too many. They went at once, and the server
  // refused them (REFUSED_STREAM). Until the server's first SETTINGS its limit
  // is taken as peerMaxConcurrentStreams (100, nghttp2's and node's): a burst
  // of requests before it would otherwise be refused; that SETTINGS sets the
  // limit it announces, or none. Drained at the end of execute() and of the
  // calls that may close a stream (settle), never in the middle of one.
  var peerMaxConcurrentStreams = options.peerMaxConcurrentStreams != null ? options.peerMaxConcurrentStreams : 100;
  // node:http2's maxReservedRemoteStreams (nghttp2's
  // max_reserved_remote_streams, 200): pushes promised and not yet begun
  // (reserved (remote)) a client holds; past it, a PUSH_PROMISE's stream is
  // reset CANCEL (onPushPromise).
  var maxReservedRemoteStreams = options.maxReservedRemoteStreams != null ? options.maxReservedRemoteStreams : 200;
  var reservedRemoteCount = 0;
  var remoteSettingsReceived = false;
  var outgoingStreams = 0;   // open streams this side opened
  var synQueue = [];         // queued requests, in id order
  var settleNeeded = false;
  function outgoingLimit() {
    return remoteSettingsReceived ? remoteSettings.MAX_CONCURRENT_STREAMS : peerMaxConcurrentStreams;
  }
  function isLocalId(id) { return (id % 2 === 1) === !isServer; }
  function settle() {
    if (!settleNeeded || closed) return;
    settleNeeded = false;
    while (synQueue.length > 0 && (goawayReceived || outgoingStreams < outgoingLimit())) {
      var q = synQueue.shift();
      q.queued = false;
      var hs = q.queuedHeaders;
      q.queuedHeaders = null;
      sendRequestHeaders(q, hs.headers, hs.endStream);
      if (closed) return;
    }
  }

  function markOpen(s) {
    s.state = STATE.OPEN;
    if (!s.active) {
      s.active = true; activeCount++;
      s.memory = STREAM_MEMORY; streamMemory += STREAM_MEMORY;
      if (isLocalId(s.id)) { s.outgoing = true; outgoingStreams++; }
    }
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
    if (s.state === STATE.RESERVED_REMOTE) reservedRemoteCount--;
    s.state = STATE.CLOSED;
    for (var q = 0; q < s.pendingData.length; q++) queuedBytes -= s.pendingData[q].length;
    s.pendingData = [];
    s.pendingTrailers = null;
    waiting.delete(s);
    if (s.active) {
      s.active = false; activeCount--;
      streamMemory -= s.memory; s.memory = 0;
      if (s.outgoing) { s.outgoing = false; outgoingStreams--; if (synQueue.length) settleNeeded = true; }
      emit('stream_close', s.id);
    }
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

  // Bytes that arrive while a frame is being handled — the peer's answer to
  // what a listener of ours just sent, when the two ends are joined in
  // memory (a duplex pair, a test) and its 'send' reaches the other side at
  // once — are appended, and the loop already running reads them after the
  // frame in hand. A second loop started there read the same buffer from
  // its start: every frame not yet consumed was handled again (a HEADERS
  // block decoded twice, the HPACK table out of step with the peer's), and
  // a client's RST_STREAM was answered with one of ours.
  var executing = false;

  function execute(chunk) {
    if (closed) return;
    emit('received');   // activity, for a session's setTimeout()
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    if (executing) return;
    executing = true;

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
          framesReceived++;
          offset += err.consumed;
          streamError(err.streamId, err.h2Code, err.message);
          if (closed) return;
          continue;
        }
        if (!frame) break;
        framesReceived++;
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
    } finally {
      executing = false;
    }
    settle();
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
      case F.TYPE.PRIORITY:
        // Deprecated by RFC 9113 and not acted on — but surfaced, because which
        // PRIORITY frames a client opens with (Firefox's dependency tree, or
        // none at all, as Chrome) is a section of the HTTP/2 fingerprint.
        emit('priority', frame.streamId, frame.exclusive, frame.dependency, frame.weight);
        return;
      case F.TYPE.PRIORITY_UPDATE: return onPriorityUpdate(frame);
      case F.TYPE.ALTSVC:
        // RFC 7838 §4: a server's; on stream 0 it names its origin, on a
        // stream it has none (the stream's is meant). Anything else, and a
        // server's receiving one, is ignored.
        if (isServer || frame.unknown) return;
        if (frame.streamId === 0 ? frame.origin.length === 0 : frame.origin.length !== 0) return;
        emit('altsvc', frame.streamId, frame.origin, frame.altValue);
        return;
      case F.TYPE.ORIGIN:
        // RFC 8336 §2: a server's, on stream 0; otherwise ignored.
        if (isServer || frame.unknown || frame.streamId !== 0) return;
        emit('origin', frame.origins);
        return;
      case F.TYPE.PUSH_PROMISE:  return onPushPromise(frame);
      default:
        return;   // unknown type: ignore (§4.1)
    }
  }


  // The SETTINGS we sent and the peer has not acknowledged, oldest first:
  // the preface's, then each of sendSettings(). A setting of ours takes
  // effect when its ACK comes (RFC 9113 §6.5.3: the peer applies it on
  // receipt, before the ACK) — as nghttp2 applies them, so `localSettings`
  // is what the peer has agreed to.
  var pendingSettings = [];

  function applyLocalSettings(values) {
    for (var name in values) {
      var v = values[name];
      if (/^[0-9]+$/.test(name)) { localCustom[name] = v; continue; }
      if (name === 'INITIAL_WINDOW_SIZE') {
        // The peer moved the send window of every stream by the difference
        // (§6.9.2); our record of what it may send moves with it.
        var delta = v - localSettings.INITIAL_WINDOW_SIZE;
        for (var id in streams) if (streams[id].state !== STATE.CLOSED) streams[id].localWindow += delta;
      } else if (name === 'HEADER_TABLE_SIZE') {
        decoder.setMaxTableSize(v);
      } else if (name === 'MAX_HEADER_LIST_SIZE') {
        decoder.setMaxHeaderListSize(v);
      }
      localSettings[name] = v;
    }
  }

  function onSettings(frame) {
    if (frame.ack) {
      settingsAcked = true;
      var acked = pendingSettings.shift();
      if (acked) {
        if (acked.values) applyLocalSettings(acked.values);
        emit('settings_ack', acked);
      }
      return;
    }

    // node:http2's maxSettings (nghttp2's max_settings): more entries than
    // that in one SETTINGS ends the connection, before any is applied — a
    // peer's way to make this side spend work per entry.
    if (frame.length / 6 > maxSettings) {
      throw F.h2Error('SETTINGS: too many setting entries', F.ERROR.ENHANCE_YOUR_CALM);
    }

    remoteSettingsReceived = true;
    if (synQueue.length) settleNeeded = true;

    // The ones without a name here, by number: node:http2's customSettings.
    var list = frame.settingsList || [];
    for (var ci = 0; ci < list.length; ci++) {
      if (!F.SETTINGS_NAME[list[ci].id]) remoteCustom[list[ci].id] = list[ci].value;
    }

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

    // A server opens a stream only by promising it (§8.4): HEADERS on an
    // even stream it never promised is not one.
    if (!isServer && id % 2 === 0 && (!streams[id] || streams[id].state === STATE.IDLE)) {
      throw F.h2Error('HEADERS: stream in idle', F.ERROR.PROTOCOL_ERROR);
    }

    var streamIsNew = !streams[id];
    var s = getStream(id, true);

    if (s.state === STATE.RESERVED_REMOTE) {
      // A pushed response: reserved (remote) → half-closed (local) (§5.1).
      markOpen(s);
      s.state = STATE.HALF_CLOSED_LOCAL;
      s.endStreamSent = true;
      reservedRemoteCount--;
      startHeaderBlock(frame, id);
      return;
    }

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
        streamError(id, F.ERROR.REFUSED_STREAM, 'received after GOAWAY', true);
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
      if (sessionMemory() + STREAM_MEMORY > maxSessionMemory) {
        // After the stream limit, as nghttp2 refuses first and node then
        // (its callback). This side's choice, not the peer's fault: not an
        // invalid frame.
        streamError(id, F.ERROR.ENHANCE_YOUR_CALM, 'session memory exceeded', true);
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

    var decoded;
    // A PUSH_PROMISE's list is the promised stream's, made with it: the limit now.
    var own = frame.type === F.TYPE.PUSH_PROMISE ? null : streams[id];
    var limit = own ? own.headerListLimit : localSettings.MAX_HEADER_LIST_SIZE;
    try {
      decoded = decoder.decodeBounded(block, limit);
    } catch (err) {
      // HPACK failures are ALWAYS connection errors: the table is shared, so a
      // block we could not decode leaves our table and the peer's permanently
      // out of step, and every later block on every stream would be wrong.
      throw F.h2Error(err.message, F.ERROR.COMPRESSION_ERROR);
    }
    var list = decoded.list;
    // A list over our MAX_HEADER_LIST_SIZE: decoded whole (the tables are in
    // step), so only its stream is refused — ENHANCE_YOUR_CALM, as nghttp2
    // under node:http2 does; a reset of ours, not an invalid frame.
    var tooLarge = decoded.tooLarge && ('header list over ' + limit + ' bytes');

    if (frame.type === F.TYPE.PUSH_PROMISE) {
      if (tooLarge && !frame.ignore) {
        var rs = streams[frame.promisedStreamId];
        if (rs && rs.state === STATE.RESERVED_REMOTE) streamError(frame.promisedStreamId, F.ERROR.ENHANCE_YOUR_CALM, tooLarge, true);
        return;
      }
      finishPushPromise(frame, list);
      return;
    }

    var s = streams[id];
    if (!s || s.state === STATE.CLOSED) return;   // reset while the block arrived
    if (tooLarge) { streamError(id, F.ERROR.ENHANCE_YOUR_CALM, tooLarge, true); return; }
    if (s.active) {
      var held = 0;
      for (var hi = 0; hi < list.length; hi++) held += list[hi][0].length + list[hi][1].length + 32;
      s.memory += held; streamMemory += held;
    }

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
      emit('trailers', id, headers, list);
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
      emit('headers', id, headers, false, null, list);
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
      // A response defined to have no content — to a HEAD request, a 204, a
      // 304 — has none, whatever its content-length says (RFC 9113 §8.1.1:
      // there it gives the representation's size, RFC 9110 §8.6): its body is
      // 0 bytes long. Its END_STREAM on an empty DATA frame (as some servers
      // send it) was checked against the header and the stream reset with
      // PROTOCOL_ERROR; DATA with bytes in it still is.
      if (!isServer && (s.requestMethod === 'HEAD' || headers[':status'] === '204' || headers[':status'] === '304')) {
        s.contentLength = 0;
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
      emit('headers', id, headers, !!frame.endStream, s.extendedConnect || null, list);
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


  // ---- Server push (RFC 9113 §8.4) — a client's side ----
  // A PUSH_PROMISE is taken when this side's ENABLE_PUSH says so (quico's
  // client announces 0 unless asked; exactSettings leaves it 1, the RFC's,
  // as node:http2's client does). Checked as nghttp2 checks it (its messages):
  // on one of our streams, not idle, promising a new even stream. After our
  // GOAWAY it is ignored; on a stream of ours already closed, or past
  // maxReservedRemoteStreams, the promised stream is reset CANCEL. Its block
  // is decoded whatever becomes of it (the HPACK table is the connection's).
  function onPushPromise(frame) {
    if (isServer || !localSettings.ENABLE_PUSH) {
      throw F.h2Error('PUSH_PROMISE: push disabled', F.ERROR.PROTOCOL_ERROR);
    }
    var parentId = frame.streamId, pid = frame.promisedStreamId;
    if (!isLocalId(parentId)) {
      throw F.h2Error('PUSH_PROMISE: invalid stream_id', F.ERROR.PROTOCOL_ERROR);
    }
    if (goawaySent) { frame.ignore = true; startHeaderBlock(frame, parentId); return; }
    if (pid === 0 || pid % 2 !== 0 || pid <= lastRemoteStreamId) {
      throw F.h2Error('PUSH_PROMISE: invalid promised_stream_id', F.ERROR.PROTOCOL_ERROR);
    }
    if (isIdleStreamId(parentId)) {
      throw F.h2Error('PUSH_PROMISE: stream in idle', F.ERROR.PROTOCOL_ERROR);
    }
    lastRemoteStreamId = pid;
    var parent = streams[parentId];
    var ps = getStream(pid, true);
    if (!parent || parent.state === STATE.CLOSED || reservedRemoteCount >= maxReservedRemoteStreams) {
      streamError(pid, F.ERROR.CANCEL, 'push refused', true);
      frame.ignore = true;
      startHeaderBlock(frame, parentId);
      return;
    }
    if (parent.state === STATE.HALF_CLOSED_REMOTE) {
      throw F.h2Error('PUSH_PROMISE: stream closed', F.ERROR.STREAM_CLOSED);
    }
    ps.state = STATE.RESERVED_REMOTE;
    reservedRemoteCount++;
    startHeaderBlock(frame, parentId);
  }

  // The promised request: a request's fields (§8.4.1), its method safe and
  // cacheable (GET or HEAD, §8.4: RFC's "MUST", which nghttp2 does not
  // check), else the promised stream is reset PROTOCOL_ERROR.
  // 'push_promise' (parentId, promisedId, headers, list).
  function finishPushPromise(frame, list) {
    if (frame.ignore) return;
    var pid = frame.promisedStreamId;
    var ps = streams[pid];
    if (!ps || ps.state !== STATE.RESERVED_REMOTE) return;   // reset meanwhile
    var headers;
    try {
      headers = validateFieldSection(list, { isServer: true, trailers: false, connectProtocol: false }).headers;
      if (headers[':method'] !== 'GET' && headers[':method'] !== 'HEAD') throw new Error('pushed request ' + headers[':method'] + ' is not safe and cacheable');
    } catch (err) {
      streamError(pid, F.ERROR.PROTOCOL_ERROR, err.message);
      return;
    }
    ps.requestMethod = headers[':method'];
    emit('push_promise', frame.streamId, pid, headers, list);
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
    // §5.1: on a reserved stream only HEADERS, RST_STREAM and PRIORITY.
    if (s && (s.state === STATE.RESERVED_REMOTE || s.state === STATE.RESERVED_LOCAL)) {
      throw F.h2Error('DATA: stream in reserved', F.ERROR.PROTOCOL_ERROR);
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

    // The frame's credit is counted before the data goes up: a consumer that
    // reads it at once calls consume() from inside 'data', and the credit
    // counted after that waited for the next frame's consume(). With a
    // stream window of a frame or two there was no next frame — the peer's
    // window had run out — and the transfer stopped.
    maybeSendStreamWindowUpdate(s, len);
    if (len === 0 && !frame.endStream && invalidFrame()) return;
    if (frame.data.length) emit('data', id, frame.data);

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


  var peerGoawayLastStreamId = 0x7fffffff;   // the last-stream-id of the peer's last GOAWAY
  function onGoaway(frame) {
    // RFC 9113 §6.8: lastStreamId names a stream this side opened (or 0),
    // and a later GOAWAY "MUST NOT increase" it. Either is a protocol error,
    // as nghttp2 (and so node:http2) treats it; it was taken as given.
    var last = frame.lastStreamId;
    // One message for both, nghttp2's.
    if ((last > 0 && (last % 2 === 1) !== !isServer) || last > peerGoawayLastStreamId) {
      throw F.h2Error('GOAWAY: invalid last_stream_id', F.ERROR.PROTOCOL_ERROR);
    }
    peerGoawayLastStreamId = last;
    goawayReceived = true;
    if (synQueue.length) settleNeeded = true;
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

  // What the preface's ACK puts in effect: the three settings held at the
  // RFC's values until then (above) that it announces, and its custom ones.
  function prefaceAcked() {
    var v = {};
    ['INITIAL_WINDOW_SIZE', 'HEADER_TABLE_SIZE', 'MAX_FRAME_SIZE'].forEach(function (k) {
      if (announced[k] !== undefined) v[k] = announced[k];
    });
    return Object.assign(v, announcedCustom);
  }

  function sendPreface() {
    if (!isServer) write(F.PREFACE);

    var toSend = {};
    for (var k in announced) {
      // A client has no use for ENABLE_CONNECT_PROTOCOL: it is a server
      // telling clients what they may ask for, and RFC 8441 §3 only defines
      // the server-to-client direction.
      if (k === 'ENABLE_CONNECT_PROTOCOL' && !isServer) continue;
      toSend[k] = announced[k];
    }
    // Recorded before it is written: a peer joined in memory (a duplex pair, a
    // test) acknowledges it within the write, and that ACK found nothing to
    // apply — every ACK after it then applied the SETTINGS before its own.
    pendingSettings.push({
      values: prefaceAcked(),
      sentAt: Date.now(), initial: true
    });
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

  // `:method` of a header list — [[name, value], ...] or an object, as the
  // encoder takes it.
  function methodOf(headers) {
    if (!Array.isArray(headers)) return headers[':method'];
    for (var i = 0; i < headers.length; i++) if (headers[i][0] === ':method') return headers[i][1];
    return undefined;
  }

  // node:http2's maxSendHeaderBlockLength (nghttp2's
  // max_send_header_block_length, default 64 KB): a header block whose bound
  // (HpackEncoder.bound, plus the 5 bytes of a HEADERS' priority, as nghttp2
  // counts it) is over it is not sent. 'frame_error' (streamId, type, code
  // FRAME_SIZE_ERROR) says so; the HPACK table is not touched, so the
  // connection goes on. A request's stream, never opened on the wire, is
  // closed with REFUSED_STREAM ('rst', no RST_STREAM sent) — retryable, as
  // nghttp2 closes it; a response or trailers leave the stream as it was.
  var maxSendHeaderBlockLength = options.maxSendHeaderBlockLength != null ? options.maxSendHeaderBlockLength : 65536;

  // node:http2's paddingStrategy, as nghttp2 applies its select_padding
  // callback: 0 none (the default), 1 ALIGNED — the frame (header and
  // payload) a multiple of 8 bytes —, 2 MAX — as much as may go: 256 bytes
  // more than the content, within the frame's room (DATA: its windows and
  // MAX_FRAME_SIZE, the padding is flow-controlled; HEADERS: one frame of
  // 16384 at most — a block that needs CONTINUATION is not padded). Hides the
  // lengths of what is sent from someone reading TLS record sizes.
  var paddingStrategy = options.paddingStrategy === 'max' ? 2
    : options.paddingStrategy === 'aligned' ? 1
    : options.paddingStrategy === 2 ? 2
    : (options.paddingStrategy === 1 || options.paddingStrategy === 3) ? 1 : 0;
  // The payload's length, padded: `len` content, `room` the most the frame may carry.
  function paddedLength(len, room) {
    if (paddingStrategy === 0 || len >= room) return len;
    var most = Math.min(len + 256, room);
    if (paddingStrategy === 2) return most;
    var r = (len + 9) % 8;
    return r === 0 ? len : Math.min(most, len + (8 - r));
  }
  function headerPadTo(block) {
    return paddingStrategy === 0 ? 0 : paddedLength(block.length, Math.min(16384, block.length + 256));
  }
  function headerBlockTooLong(streamId, headers, extra) {
    if (encoder.bound(headers) + extra <= maxSendHeaderBlockLength) return false;
    emit('frame_error', streamId, F.TYPE.HEADERS, F.ERROR.FRAME_SIZE_ERROR);
    return true;
  }

  function sendHeaders(streamId, headers, endStream) {
    var s = getStream(streamId, true);
    if ((!isServer && s.state === STATE.IDLE) || s.state === STATE.RESERVED_LOCAL) {
      if (s.queued) return true;   // already waiting
      if (synQueue.length > 0 || outgoingStreams >= outgoingLimit()) {
        s.queued = true;
        s.queuedHeaders = { headers: headers, endStream: !!endStream };
        synQueue.push(s);
        settleNeeded = true;   // a GOAWAY may already be in
        settle();
        return true;
      }
      return sendRequestHeaders(s, headers, endStream);
    }
    return sendHeaderBlock(s, headers, endStream);
  }

  // A request's HEADERS, its turn come: refused when the server has sent
  // GOAWAY (RFC 9113 §6.8: no new streams on it) — 'frame_error' (HEADERS,
  // INTERNAL_ERROR: node's code for nghttp2's START_STREAM_NOT_ALLOWED), and
  // the stream closed REFUSED_STREAM, retryable elsewhere, as nghttp2 does;
  // otherwise sent, and whatever DATA waited behind it after it.
  function sendRequestHeaders(s, headers, endStream) {
    if (goawayReceived) {
      emit('frame_error', s.id, F.TYPE.HEADERS, F.ERROR.INTERNAL_ERROR);
      refuseRequest(s, F.ERROR.REFUSED_STREAM);
      return false;
    }
    var sent = sendHeaderBlock(s, headers, endStream);
    if (sent) flushStream(s);
    return sent;
  }

  // A request that never went on the wire, ended: 'rst' (id, code), no
  // RST_STREAM sent (there is no stream to reset).
  function refuseRequest(s, code) {
    s.closedBy = 'rst_sent';
    markClosed(s);
    emit('rst', s.id, code);
  }

  function sendHeaderBlock(s, headers, endStream) {
    var streamId = s.id;
    if (headerBlockTooLong(streamId, headers, 5)) {
      if (s.state === STATE.IDLE && !isServer) refuseRequest(s, F.ERROR.REFUSED_STREAM);
      return false;
    }
    if (s.state === STATE.IDLE) markOpen(s);
    else if (s.state === STATE.RESERVED_LOCAL) {
      // A pushed response: reserved (local) → half-closed (remote) (§5.1).
      markOpen(s);
      s.state = STATE.HALF_CLOSED_REMOTE;
    }
    // A request's method: what its response's length is read by (a HEAD's
    // has no content, finishHeaderBlock).
    if (!isServer && headers && s.requestMethod === undefined) s.requestMethod = methodOf(headers);

    var block = encoder.encode(headers);
    var frames = F.buildHeaderFrames(streamId, block, { endStream: !!endStream, padTo: headerPadTo(block) },
                                     remoteSettings.MAX_FRAME_SIZE);
    // Concatenated into ONE write: §6.10 forbids any other frame between
    // HEADERS and its CONTINUATIONs, and emitting them separately invites a
    // caller (or a queue) to interleave.
    write(Buffer.concat(frames));

    if (endStream) sendEndStream(s);
    return true;
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
      var piece = typeof data === 'string' ? Buffer.from(data)
        : Buffer.isBuffer(data) ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
      s.pendingData.push(piece);
      queuedBytes += piece.length;
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

  // What a stream has queued and not yet sent as DATA — past its window, or
  // behind the transport: a Duplex's writableLength over it.
  function streamQueued(streamId) {
    var s = streams[streamId];
    if (!s) return 0;
    var n = 0;
    for (var i = 0; i < s.pendingData.length; i++) n += s.pendingData[i].length;
    return n;
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
    // A pushed stream's DATA waits for its response's HEADERS.
    if (s.state === STATE.CLOSED || s.queued || s.state === STATE.RESERVED_LOCAL) return false;
    if (s.pendingData.length === 0) {
      if (s.pendingTrailers) { writeTrailers(s); return true; }
      if (!s.pendingEnd) return false;
      s.pendingEnd = false;
      writeData(s, Buffer.alloc(0), true, Math.max(0, Math.min(sendableBytes(s), remoteSettings.MAX_FRAME_SIZE)));
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
    queuedBytes -= take;

    var last = s.pendingData.length === 0 && s.pendingEnd;
    writeData(s, piece, last, budget);
    if (last) { s.pendingEnd = false; sendEndStream(s); }
    if (s.pendingData.length === 0) {
      if (s.pendingTrailers) writeTrailers(s);
      waiting.delete(s);
      emit('drain', s.id);
    }
    return true;
  }

  // The trailers that waited behind the stream's DATA: HEADERS with
  // END_STREAM, encoded now — HPACK's dynamic table is in the order the
  // blocks go out, not the order they were asked for.
  function writeTrailers(s) {
    var headers = s.pendingTrailers;
    s.pendingTrailers = null;
    if (headerBlockTooLong(s.id, headers, 5)) return;
    var block = encoder.encode(headers);
    write(Buffer.concat(F.buildHeaderFrames(s.id, block, { endStream: true, padTo: headerPadTo(block) }, remoteSettings.MAX_FRAME_SIZE)));
    sendEndStream(s);
  }

  // One DATA frame: `piece`, padded within `room` (paddedLength) — the
  // padding, flow-controlled, taken from the windows with the content.
  // Header and payload as separate writes, the payload never copied (the
  // server corks the socket, so they still leave together); a padded one as
  // nghttp2 writes it: header, Pad Length, content, padding.
  function writeData(s, piece, endStream, room) {
    var total = paddedLength(piece.length, room);
    s.remoteWindow -= total;
    remoteWindow -= total;
    var flags = endStream ? F.FLAG.END_STREAM : 0;
    if (total === piece.length) {
      write(F.frameHeader(total, F.TYPE.DATA, flags, s.id));
      write(piece);
      return;
    }
    var padLength = total - piece.length - 1;
    write(F.frameHeader(total, F.TYPE.DATA, flags | F.FLAG.PADDED, s.id));
    write(Buffer.from([padLength]));
    write(piece);
    if (padLength > 0) write(Buffer.alloc(padLength));
  }

  // As much of one stream's queue as can go now; what cannot waits (waiting).
  function flushStream(s) {
    if (!s) return;
    while (writeFrame(s)) {}
    if (s.state !== STATE.CLOSED && (s.pendingData.length > 0 || s.pendingEnd || s.pendingTrailers)) waiting.add(s);
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
  this.sendData = function (streamId, data, endStream) {
    var r = sendData(streamId, data, endStream);
    settle();
    return r;
  };
  this.streamQueued = streamQueued;
  /** The transport can take more again (its 'drain'): send what DATA waited. */
  this.flushAll = function () { flushAll(); settle(); };
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
  //
  // node:http2's goaway(code, lastStreamId, opaqueData): lastStreamId 0 (or
  // none) is the last stream the peer opened, a larger one is brought down to
  // it (nghttp2 does the same); opaqueData goes as the frame's debug data.
  // Unlike the GOAWAYs the connection sends on its own (sendGoaway, once), it
  // may be called again — RFC 9113 §6.8 allows a second GOAWAY, with a
  // last-stream-id no higher than the first's.
  this.goaway = function (errorCode, lastStreamId, debugData) {
    var code = errorCode === undefined ? F.ERROR.NO_ERROR : errorCode;
    var id = lastStreamId > 0 ? Math.min(lastStreamId, lastRemoteStreamId) : lastRemoteStreamId;
    if (goawaySent) id = Math.min(id, goawayLastStreamId);
    goawaySent = true;
    goawayLastStreamId = id;
    write(F.buildGoaway(id, code, debugData));
    if (stats) stats.code(stats.closes.h2.sent, code);
  };

  this.sendRstStream = function (streamId, errorCode) {
    var code = errorCode === undefined ? F.ERROR.CANCEL : errorCode;
    var q = streams[streamId];
    if (q && q.queued) {
      // Never sent: out of the queue, closed with the code (nghttp2 cancels
      // it in ob_syn), and no RST_STREAM.
      synQueue.splice(synQueue.indexOf(q), 1);
      q.queued = false; q.queuedHeaders = null;
      refuseRequest(q, code);
      return;
    }
    streamError(streamId, code, undefined, true);
    settle();
  };

  this.sendPing = function (payload) { write(F.buildPing(payload, false)); };
  /** RFC 7838 §4 (node:http2's altsvc()): a server's. */
  this.sendAltsvc = function (streamId, origin, value) { write(F.buildAltsvc(streamId, origin, value)); };
  /** RFC 8336 (node:http2's origin()): a server's. */
  this.sendOrigin = function (origins) { write(F.buildOrigin(origins)); };

  /**
   * SETTINGS during the connection (node:http2's session.settings()): the
   * values, by their RFC names, go now and take effect when acknowledged
   * ('settings_ack', with the entry). `extra` rides along to the ACK — the
   * caller's callback, say. Returns how many are now unacknowledged.
   */
  this.sendSettings = function (values, extra) {
    var entry = { values: values, sentAt: Date.now(), extra: extra };
    pendingSettings.push(entry);
    write(F.buildSettings(values, false));
    return pendingSettings.length;
  };

  /**
   * The connection's receive window (node:http2's setLocalWindowSize()):
   * larger, the difference is granted at once (WINDOW_UPDATE on stream 0);
   * smaller, credit is held back until consumption has paid for it — a
   * window, once granted, cannot be taken back.
   */
  this.setLocalWindowSize = function (size) {
    var delta = size - CONNECTION_WINDOW;
    CONNECTION_WINDOW = size;
    if (delta > 0) {
      // Credit still held back from a smaller window is what a larger one
      // gives first; only the rest is granted. Granted on top of it, 20 then
      // 100000 let the peer send 165515 (as nghttp2 does: it cancels the
      // reduction first).
      var owed = Math.min(delta, Math.max(0, -pendingConnectionCredit));
      pendingConnectionCredit += owed;
      var grant = delta - owed;
      if (grant > 0) {
        localWindow += grant;
        write(F.buildWindowUpdate(0, grant));
      }
    } else if (delta < 0) {
      pendingConnectionCredit += delta;
    }
  };

  /**
   * node:http2's stream.state, from this side's record: nghttp2's state
   * numbers, the default weight (RFC 9113 has no tree), which ends have
   * sent END_STREAM, the stream's receive window. null once it has closed.
   */
  var STATE_NUMBER = { idle: 1, open: 2, reserved_local: 3, reserved_remote: 4,
                       half_closed_local: 5, half_closed_remote: 6, closed: 7 };
  this.getStreamInfo = function (streamId) {
    var s = streams[streamId];
    if (!s || s.state === STATE.CLOSED) return null;
    return {
      state: STATE_NUMBER[s.state],
      weight: 16,
      sumDependencyWeight: 0,
      localClose: s.endStreamSent ? 1 : 0,
      remoteClose: s.endStreamReceived ? 1 : 0,
      localWindowSize: s.localWindow
    };
  };
  /** Whether a stream is open on the wire (not idle, not closed). */
  this.isStreamOpen = function (streamId) {
    var s = streams[streamId];
    return !!s && s.state !== STATE.CLOSED && s.state !== STATE.IDLE;
  };

  /** node:http2's session.state, from this side's records. */
  this.getState = function () {
    var queued = 0;
    for (var id in streams) if (streams[id].pendingData && streams[id].pendingData.length) queued += streams[id].pendingData.length;
    return {
      effectiveLocalWindowSize: CONNECTION_WINDOW,
      effectiveRecvDataLength: Math.max(0, pendingConnectionCredit),
      nextStreamID: nextLocalStreamId,
      // What the peer was granted and may still send (nghttp2's
      // local_window_size): a grant cannot be taken back, so a smaller
      // setLocalWindowSize() shows in effectiveLocalWindowSize, and here only
      // as the data the peer sends uses the grant up. (It was the smaller
      // size at once: 20 where node:http2 says 65535.)
      localWindowSize: localWindow,
      lastProcStreamID: lastRemoteStreamId,
      remoteWindowSize: remoteWindow,
      outboundQueueSize: queued,
      deflateDynamicTableSize: encoder.tableSize,
      inflateDynamicTableSize: decoder.tableSize
    };
  };

  // Trailers end the stream, so they go after its DATA: while DATA waits
  // for a window (or for the socket), they wait behind it. They were written
  // at once — END_STREAM ahead of the body's rest, which the peer then took
  // as DATA on a closed stream (STREAM_CLOSED): a large response or upload
  // with trailers (gRPC's) to a peer with HTTP/2's 64 KB window was cut.
  this.sendTrailers = function (streamId, headers) {
    var s = streams[streamId];
    if (!s || s.state === STATE.CLOSED) return;
    s.pendingTrailers = headers;
    s.pendingEnd = false;
    if (s.pendingData.length > 0 || s.queued) { waiting.add(s); return; }
    writeTrailers(s);
    settle();
  };

  /**
   * Server push (node:http2's stream.pushStream): PUSH_PROMISE on
   * `parentId` for the request `headers` (GET or HEAD); the promised stream
   * (even, reserved (local)) is the returned id, its response sent with
   * sendHeaders / sendData as any other — counted against the client's
   * MAX_CONCURRENT_STREAMS from its HEADERS on, queued past it as a
   * request is. Or a reason, a string: 'push_disabled' (the client's
   * ENABLE_PUSH 0; node's -528), 'stream_closed' (a parent this side cannot
   * send on, or itself pushed; -510), 'ids_exhausted' (-509). A block over
   * maxSendHeaderBlockLength, or the client's GOAWAY in: not sent —
   * 'frame_error' (parentId, PUSH_PROMISE, FRAME_SIZE_ERROR / INTERNAL_ERROR)
   * and the promised stream closed ('rst', INTERNAL_ERROR), as nghttp2 does.
   */
  this.pushPromise = function (parentId, headers) {
    if (!isServer) return 'stream_closed';
    if (remoteSettings.ENABLE_PUSH === 0) return 'push_disabled';
    var parent = streams[parentId];
    if (!parent || isLocalId(parentId) || parent.queued ||
        (parent.state !== STATE.OPEN && parent.state !== STATE.HALF_CLOSED_REMOTE)) return 'stream_closed';
    if (nextLocalStreamId > 0x7fffffff) return 'ids_exhausted';
    var pid = nextLocalStreamId;
    nextLocalStreamId += 2;
    var ps = getStream(pid, true);
    ps.state = STATE.RESERVED_LOCAL;
    ps.requestMethod = methodOf(headers);
    var code = goawayReceived ? F.ERROR.INTERNAL_ERROR
      : encoder.bound(headers) > maxSendHeaderBlockLength ? F.ERROR.FRAME_SIZE_ERROR : 0;
    if (code) {
      emit('frame_error', parentId, F.TYPE.PUSH_PROMISE, code);
      ps.closedBy = 'rst_sent';
      markClosed(ps);
      emit('rst', pid, F.ERROR.INTERNAL_ERROR);
      return pid;
    }
    var block = encoder.encode(headers);
    var padTo = paddingStrategy === 0 ? 0 : paddedLength(block.length + 4, Math.min(16384, block.length + 4 + 256));
    write(Buffer.concat(F.buildPushPromiseFrames(parentId, pid, block, { padTo: padTo }, remoteSettings.MAX_FRAME_SIZE)));
    return pid;
  };

  /** Allocate the next stream id for a locally initiated stream. */
  this.nextStreamId = function () {
    var id = nextLocalStreamId;
    nextLocalStreamId += 2;
    return id;
  };

  /**
   * setNextStreamId(id) (node:http2's setNextStreamID, nghttp2's
   * nghttp2_session_set_next_stream_id): the next locally initiated stream
   * takes `id`. Refused (false) for an id below the next one, of the other
   * side's parity, or past 2^31 - 1; the ids skipped are never used.
   */
  this.setNextStreamId = function (id) {
    if (!Number.isInteger(id) || id <= 0 || id > 0x7fffffff || id % 2 !== (isServer ? 0 : 1) ||
        id < nextLocalStreamId) return false;
    nextLocalStreamId = id;
    return true;
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
  Object.defineProperty(this, 'framesSent', { get: function () { return framesSent; } });
  Object.defineProperty(this, 'framesReceived', { get: function () { return framesReceived; } });
  // What the open streams hold (maxSessionMemory's measure), in bytes.
  Object.defineProperty(this, 'sessionMemory', { get: sessionMemory });
  Object.defineProperty(this, 'pendingSettingsAck', { get: function () { return pendingSettings.length; } });
  Object.defineProperty(this, 'localCustomSettings', { get: function () { return localCustom; } });
  Object.defineProperty(this, 'remoteCustomSettings', { get: function () { return remoteCustom; } });
  Object.defineProperty(this, 'goawayReceived', { get: function () { return goawayReceived; } });
  Object.defineProperty(this, 'closed',         { get: function () { return closed; } });

  return this;
}


// DATA waits while a socket holds this much unsent (isWriteBlocked) — the
// server's and the client's sessions alike.
var SOCKET_HIGH_WATER = 256 * 1024;

// ============================================================
//  node:http2's session operations, for both ends of an HTTP/2 connection.
//
//  settings() (and the 'localSettings' / 'remoteSettings' events,
//  localSettings, remoteSettings, pendingSettingsAck), ping() (and 'ping'),
//  setLocalWindowSize(), state, setTimeout() (and 'timeout'). The same on
//  the server's session (h2_server's handle) and the client's (connect()),
//  as in node:http2, where both are an Http2Session — so they are written
//  once, here, over the H2Connection (h2.js) that each of them has.
//
//  Argument checks, error codes and messages are node:http2's
//  (lib/internal/http2/core.js), so code written for it behaves the same.
// ============================================================


// node:http2's setting names and the RFC's.
var WIRE = {
  headerTableSize: 'HEADER_TABLE_SIZE',
  enablePush: 'ENABLE_PUSH',
  initialWindowSize: 'INITIAL_WINDOW_SIZE',
  maxFrameSize: 'MAX_FRAME_SIZE',
  maxConcurrentStreams: 'MAX_CONCURRENT_STREAMS',
  maxHeaderListSize: 'MAX_HEADER_LIST_SIZE',
  enableConnectProtocol: 'ENABLE_CONNECT_PROTOCOL'
};

var kMaxInt = 2 ** 32 - 1;
var RANGES = {
  headerTableSize: [0, kMaxInt],
  initialWindowSize: [0, 2 ** 31 - 1],
  maxFrameSize: [16384, 2 ** 24 - 1],
  maxConcurrentStreams: [0, kMaxInt],
  maxHeaderListSize: [0, kMaxInt],
  maxHeaderSize: [0, kMaxInt]
};

function nodeError(Ctor, code, message) {
  var e = new Ctor(message);
  e.code = code;
  return e;
}

function invalidSetting(Ctor, name, value) {
  return nodeError(Ctor, 'ERR_HTTP2_INVALID_SETTING_VALUE', 'Invalid value for setting "' + name + '": ' + value);
}

// node:http2's validateSettings().
function validateSettings(settings) {
  for (var name in RANGES) {
    var v = settings[name];
    if (v !== undefined && (typeof v !== 'number' || v < RANGES[name][0] || v > RANGES[name][1])) {
      throw invalidSetting(RangeError, name, v);
    }
  }
  if (settings.enablePush !== undefined && typeof settings.enablePush !== 'boolean') {
    throw invalidSetting(TypeError, 'enablePush', settings.enablePush);
  }
  if (settings.enableConnectProtocol !== undefined && typeof settings.enableConnectProtocol !== 'boolean') {
    throw invalidSetting(TypeError, 'enableConnectProtocol', settings.enableConnectProtocol);
  }
  // customSettings: { id: value }, at most 10 (node:http2's
  // MAX_ADDITIONAL_SETTINGS), ids 1..0xffff, values 1..2^32 - 1.
  var custom = settings.customSettings;
  if (custom !== undefined) {
    if (custom === null || typeof custom !== 'object') throw argType('customSettings', 'object', custom);
    var keys = Object.keys(custom);
    if (keys.length > MAX_CUSTOM_SETTINGS) {
      throw nodeError(Error, 'ERR_HTTP2_TOO_MANY_CUSTOM_SETTINGS', 'Number of custom settings exceeds MAX_ADDITIONAL_SETTINGS');
    }
    for (var i = 0; i < keys.length; i++) {
      var id = Number(keys[i]), val = custom[keys[i]];
      if (!Number.isInteger(id) || id <= 0 || id > 0xffff) throw invalidSetting(RangeError, 'customSettings:id', keys[i]);
      if (typeof val !== 'number' || !(val > 0) || val > kMaxInt) throw invalidSetting(RangeError, 'customSettings:value', val);
    }
  }
}

var MAX_CUSTOM_SETTINGS = 10;
var MAX_ALTSVC = 2 ** 14 - 2;   // node:http2's kMaxALTSVC

// node:http2's remoteCustomSettings option: the ids, at most 10.
function checkRemoteCustomSettings(list) {
  if (list === undefined) return;
  if (!Array.isArray(list)) throw argType('options.remoteCustomSettings', 'Array', list);
  if (list.length > MAX_CUSTOM_SETTINGS) {
    throw nodeError(Error, 'ERR_HTTP2_TOO_MANY_CUSTOM_SETTINGS', 'Number of custom settings exceeds MAX_ADDITIONAL_SETTINGS');
  }
}

// node:http2's getURLOrigin(): the origin of a URL string, 'null' when it has none.
function urlOrigin(s) {
  try { return new URL(s).origin; } catch (e) { return 'null'; }
}

// node:http2's names → the RFC's, as h2.js sends them.
function toWire(settings) {
  var out = {};
  if (settings.maxHeaderSize !== undefined) {
    if (settings.maxHeaderListSize !== undefined) {
      process.emitWarning('settings.maxHeaderSize overwrite settings.maxHeaderListSize');
    }
    settings = Object.assign({}, settings, { maxHeaderListSize: settings.maxHeaderSize });
  }
  for (var name in WIRE) {
    var v = settings[name];
    if (v === undefined) continue;
    out[WIRE[name]] = typeof v === 'boolean' ? (v ? 1 : 0) : v;
  }
  // A custom setting by its number (buildSettings sends it so) — one whose
  // number names an RFC setting is that setting, as node:http2 takes it: by
  // number it went out as that setting and was recorded as a custom one, so
  // the peer applied { 4: 100 } as INITIAL_WINDOW_SIZE and this side did not.
  if (settings.customSettings) {
    for (var id in settings.customSettings) {
      var rfc = F.SETTINGS_NAME[Number(id)];
      out[rfc !== undefined ? rfc : String(Number(id))] = settings.customSettings[id];
    }
  }
  return out;
}

// The RFC's → node:http2's: every setting, an unlimited one as 2^32 - 1 (as
// nghttp2 reports it).
function fromWire(wire, custom) {
  function n(v, dflt) { v = v === undefined ? dflt : v; return v === Infinity ? kMaxInt : v; }
  var max = n(wire.MAX_HEADER_LIST_SIZE, Infinity);
  var out = {
    headerTableSize: n(wire.HEADER_TABLE_SIZE, 4096),
    enablePush: n(wire.ENABLE_PUSH, 1) !== 0,
    initialWindowSize: n(wire.INITIAL_WINDOW_SIZE, 65535),
    maxFrameSize: n(wire.MAX_FRAME_SIZE, 16384),
    maxConcurrentStreams: n(wire.MAX_CONCURRENT_STREAMS, Infinity),
    maxHeaderListSize: max,
    maxHeaderSize: max,
    enableConnectProtocol: n(wire.ENABLE_CONNECT_PROTOCOL, 0) !== 0
  };
  // Only when there are some, as node:http2 gives them.
  if (custom && Object.keys(custom).length) {
    out.customSettings = {};
    for (var id in custom) out.customSettings[id] = custom[id];
  }
  return out;
}



/**
 * Gives `session` (an EventEmitter) node:http2's session operations.
 *
 * `hooks`:
 *   h2()          the H2Connection, or null while there is none (connecting)
 *   destroyed()   whether the session is over
 *   connecting()  whether it is not yet up (the client's, before 'connect')
 *   closed()      whether close() was called
 *   whenUp(fn)    run fn once it is up (the client's; the server's is)
 *   fail(err)     destroy the session with err
 *   options       maxOutstandingPings, maxOutstandingSettings (node:http2's, 10)
 *
 * Returns { attach(h2), end() }: attach() once the H2Connection exists, end()
 * when the session is over (what is outstanding is cancelled).
 */
function addSessionOps(session, hooks) {
  var options = hooks.options || {};
  var maxPings = options.maxOutstandingPings > 0 ? options.maxOutstandingPings : 10;
  var maxSettings = options.maxOutstandingSettings > 0 ? options.maxOutstandingSettings : 10;

  var pendingAck = 0;          // settings() not yet acknowledged
  var pings = [];              // { key, payload, at, cb }, in the order sent
  var timeout = null, timeoutMs = 0;
  var pendingWindow = null;    // setLocalWindowSize() while connecting
  var ended = false;
  var origins = null;          // the client's origin set (RFC 8336), once asked for
  var maxOrigins = options.maxOriginSetSize != null ? options.maxOriginSetSize : 128;

  // The connection's own origin first, as node:http2 starts the set.
  function originSet() {
    if (!origins) origins = new Set([urlOrigin(hooks.originBase())]);
    return origins;
  }

  function touch() { if (timeout) timeout.refresh(); }

  function attach(h2) {
    h2.on('settings_ack', function (entry) {
      if (ended) return;
      var cb = entry.extra && entry.extra.cb;
      if (entry.extra) pendingAck--;
      var now = session.localSettings;
      if (typeof cb === 'function') cb(null, now, Date.now() - entry.sentAt);
      session.emit('localSettings', now);
    });
    h2.on('settings', function () {
      if (ended) return;
      touch();
      session.emit('remoteSettings', session.remoteSettings);
    });
    // The client's: ALTSVC and ORIGIN from the server.
    h2.on('altsvc', function (streamId, origin, value) {
      if (ended) return;
      touch();
      session.emit('altsvc', value, origin, streamId);
    });
    h2.on('origin', function (origins) {
      if (ended) return;
      touch();
      if (!hooks.encrypted()) return;   // RFC 8336 §2.3: a TLS connection's only
      var set = originSet();
      for (var i = 0; i < origins.length; i++) {
        if (set.size >= maxOrigins) {
          hooks.fail(nodeError(Error, 'ERR_HTTP2_TOO_MANY_ORIGINS', 'Remote peer has sent more than ' + maxOrigins + ' origins'));
          return;
        }
        set.add(origins[i]);
      }
      session.emit('origin', origins);
    });
    h2.on('ping', function (payload) {
      if (ended) return;
      touch();
      session.emit('ping', Buffer.from(payload));
    });
    h2.on('pong', function (payload) {
      var key = Buffer.from(payload).toString('hex');
      for (var i = 0; i < pings.length; i++) {
        if (pings[i].key !== key) continue;
        var p = pings.splice(i, 1)[0];
        var d = process.hrtime.bigint() - p.at;
        p.cb(null, Number(d) / 1e6, Buffer.from(payload));
        return;
      }
    });
    h2.on('received', touch);
    h2.on('send', touch);
    if (pendingWindow !== null) { h2.setLocalWindowSize(pendingWindow); pendingWindow = null; }
  }

  function end() {
    if (ended) return;
    ended = true;
    if (timeout) { clearTimeout(timeout); timeout = null; }
    var ps = pings; pings = [];
    for (var i = 0; i < ps.length; i++) ps[i].cb(nodeError(Error, 'ERR_HTTP2_PING_CANCEL', 'HTTP2 ping cancelled'));
    // A settings() callback still waiting is not called: node:http2 calls it
    // only for an acknowledgement (its ERR_HTTP2_SETTINGS_CANCEL never comes
    // from a destroy), and code written for it expects no call.
  }

  Object.defineProperties(session, {
    pendingSettingsAck: { get: function () { return pendingAck > 0; }, configurable: true },
    localSettings: {
      get: function () { var h2 = hooks.h2(); return h2 && !hooks.destroyed() ? fromWire(h2.localSettings, h2.localCustomSettings) : {}; },
      configurable: true
    },
    // The peer's custom settings: only those whose ids remoteCustomSettings
    // lists, as node:http2 keeps them.
    remoteSettings: {
      get: function () {
        var h2 = hooks.h2();
        if (!h2 || hooks.destroyed()) return {};
        var custom = {}, theirs = h2.remoteCustomSettings, allowed = options.remoteCustomSettings || [];
        for (var i = 0; i < allowed.length; i++) if (theirs[allowed[i]] !== undefined) custom[allowed[i]] = theirs[allowed[i]];
        return fromWire(h2.remoteSettings, custom);
      },
      configurable: true
    },
    state: {
      get: function () { var h2 = hooks.h2(); return h2 && !hooks.destroyed() && !hooks.connecting() ? h2.getState() : {}; },
      configurable: true
    },
    timeout: { get: function () { return timeoutMs; }, configurable: true }
  });

  if (hooks.isServer) {
    // node:http2's altsvc(alt, originOrStream): ALTSVC (RFC 7838) for an
    // origin, or for the stream given by number.
    session.altsvc = function (alt, originOrStream) {
      if (hooks.destroyed()) throw sessionGone();
      var stream = 0, origin;
      if (typeof originOrStream === 'string') {
        origin = urlOrigin(originOrStream);
        if (origin === 'null') throw nodeError(TypeError, 'ERR_HTTP2_ALTSVC_INVALID_ORIGIN', 'HTTP/2 ALTSVC frames require a valid origin');
      } else if (typeof originOrStream === 'number') {
        if (originOrStream >>> 0 !== originOrStream || originOrStream === 0) {
          throw nodeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "originOrStream" is out of range. It must be > 0 && < 4294967296. Received ' + originOrStream);
        }
        stream = originOrStream;
      } else if (originOrStream !== undefined) {
        if (originOrStream !== null && typeof originOrStream === 'object') origin = originOrStream.origin;
        if (typeof origin !== 'string') throw argType('originOrStream', 'string, number, URL, or object', originOrStream);
        if (origin === 'null' || origin.length === 0) throw nodeError(TypeError, 'ERR_HTTP2_ALTSVC_INVALID_ORIGIN', 'HTTP/2 ALTSVC frames require a valid origin');
      } else {
        // Neither: node:http2 aborts the process here (an assertion in its
        // C++). An ALTSVC on stream 0 must name an origin (RFC 7838 §4).
        throw nodeError(TypeError, 'ERR_HTTP2_ALTSVC_INVALID_ORIGIN', 'HTTP/2 ALTSVC frames require a valid origin');
      }
      if (typeof alt !== 'string') throw argType('alt', 'string', alt);
      if (!/^[\x09\x20-\x5b\x5d-\x7e\x80-\xff]*$/.test(alt)) {
        throw nodeError(TypeError, 'ERR_INVALID_CHAR', 'Invalid character in alt');
      }
      if (alt.length + (origin !== undefined ? origin.length : 0) > MAX_ALTSVC) {
        throw nodeError(TypeError, 'ERR_HTTP2_ALTSVC_LENGTH', 'HTTP/2 ALTSVC frames are limited to 16382 bytes');
      }
      var h2 = hooks.h2();
      if (h2) { touch(); h2.sendAltsvc(stream, origin || '', alt); }
    };

    // node:http2's origin(...origins): ORIGIN (RFC 8336).
    session.origin = function () {
      if (hooks.destroyed()) throw sessionGone();
      if (arguments.length === 0) return;
      var list = [], len = 0;
      for (var i = 0; i < arguments.length; i++) {
        var o = arguments[i];
        if (typeof o === 'string') o = urlOrigin(o);
        else if (o !== null && typeof o === 'object') o = o.origin;
        if (typeof o !== 'string') throw argType('origin', 'string', o);
        if (o === 'null') throw nodeError(TypeError, 'ERR_HTTP2_INVALID_ORIGIN', 'HTTP/2 ORIGIN frames require a valid origin');
        list.push(o);
        len += o.length;
      }
      if (len > MAX_ALTSVC) throw nodeError(TypeError, 'ERR_HTTP2_ORIGIN_LENGTH', 'HTTP/2 ORIGIN frames are limited to 16382 bytes');
      var h2 = hooks.h2();
      if (h2) { touch(); h2.sendOrigin(list); }
    };
  } else {
    // node:http2's originSet: the origins this connection may serve — its own,
    // and those the server's ORIGIN frames added. undefined over cleartext.
    Object.defineProperty(session, 'originSet', {
      get: function () { return hooks.encrypted() && !hooks.destroyed() && !hooks.connecting() ? Array.from(originSet()) : undefined; },
      configurable: true
    });
  }

  // node:http2's settings(settings[, callback]): sent now (once connected),
  // in effect when acknowledged — then callback(null, localSettings,
  // duration) and 'localSettings'. Past maxOutstandingSettings unacknowledged,
  // the session is destroyed (ERR_HTTP2_MAX_PENDING_SETTINGS_ACK).
  session.settings = function (settings, callback) {
    if (hooks.destroyed()) throw sessionGone();
    if (settings === null || typeof settings !== 'object' || Array.isArray(settings)) throw argType('settings', 'object', settings);
    validateSettings(settings);
    if (callback !== undefined && callback !== null && typeof callback !== 'function') throw argType('callback', 'function', callback);
    pendingAck++;
    var wire = toWire(settings);
    var submit = function () {
      if (hooks.destroyed()) return;
      var h2 = hooks.h2();
      if (!h2) return;
      touch();
      var outstanding = h2.sendSettings(wire, { cb: callback });
      if (outstanding > maxSettings) {
        hooks.fail(nodeError(Error, 'ERR_HTTP2_MAX_PENDING_SETTINGS_ACK', 'Maximum number of pending settings acknowledgements'));
      }
    };
    if (hooks.connecting()) hooks.whenUp(submit);
    else submit();
  };

  // node:http2's ping([payload][, callback]): callback(null, duration in ms,
  // payload) when the PING is answered; false past maxOutstandingPings.
  session.ping = function (payload, callback) {
    if (hooks.destroyed()) throw sessionGone();
    if (typeof payload === 'function') { callback = payload; payload = undefined; }
    if (payload !== undefined && payload !== null) {
      if (!ArrayBuffer.isView(payload)) throw argType('payload', 'Buffer, TypedArray, or DataView', payload);
      if (payload.byteLength !== 8) throw nodeError(RangeError, 'ERR_HTTP2_PING_LENGTH', 'HTTP2 ping payload must be 8 bytes');
    }
    if (typeof callback !== 'function') throw argType('callback', 'function', callback);
    var bytes = payload ? Buffer.from(payload.buffer, payload.byteOffset, 8) : Buffer.from(random_bytes_sync(8));
    if (hooks.connecting() || hooks.closed()) {
      process.nextTick(callback, nodeError(Error, 'ERR_HTTP2_PING_CANCEL', 'HTTP2 ping cancelled'));
      return;
    }
    if (pings.length >= maxPings) return false;
    pings.push({ key: bytes.toString('hex'), payload: bytes, at: process.hrtime.bigint(), cb: callback });
    touch();
    hooks.h2().sendPing(bytes);
    return true;
  };

  // node:http2's setLocalWindowSize(windowSize): the connection's receive window.
  session.setLocalWindowSize = function (windowSize) {
    if (hooks.destroyed()) throw sessionGone();
    checkInt(windowSize, 'windowSize', 0, 2 ** 31 - 1);
    var h2 = hooks.h2();
    if (h2 && !hooks.connecting()) h2.setLocalWindowSize(windowSize);
    else pendingWindow = windowSize;
  };

  // node:http2's setTimeout(msecs[, callback]): 'timeout' after msecs without
  // a frame either way; 0 turns it off.
  session.setTimeout = function (msecs, callback) {
    if (hooks.destroyed()) return session;
    if (typeof msecs !== 'number') throw argType('msecs', 'number', msecs);
    if (msecs < 0 || !Number.isFinite(msecs)) {
      throw nodeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "msecs" is out of range. It must be a non-negative finite number. Received ' + msecs);
    }
    if (callback !== undefined && typeof callback !== 'function') throw argType('callback', 'function', callback);
    timeoutMs = msecs;
    if (timeout) { clearTimeout(timeout); timeout = null; }
    if (msecs === 0) {
      if (callback) session.removeListener('timeout', callback);
      return session;
    }
    timeout = setTimeout(function () {
      if (!hooks.destroyed()) session.emit('timeout');
    }, msecs);
    if (timeout.unref) timeout.unref();
    if (callback) session.once('timeout', callback);
    return session;
  };

  return { attach: attach, end: end };
}



// The stream codes of HTTP/2, for StreamBase (http_common.js).
var H2_STREAM_CODES = {
  none: F.ERROR.NO_ERROR, cancel: F.ERROR.CANCEL, internal: F.ERROR.INTERNAL_ERROR, max: 0xffffffff,
  wire: function (code) { return code; },
  name: function (code) { return 'NGHTTP2_' + (F.ERROR_NAME[code] || 'UNKNOWN_CODE'); }
};


export { H2Connection, STATE, SOCKET_HIGH_WATER, H2_STREAM_CODES, addSessionOps, toWire, fromWire, validateSettings, checkRemoteCustomSettings };
