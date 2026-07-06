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

import flat_ranges from 'flat-ranges';

import {
  DEBUG,
  Emitter,
  concatUint8Arrays,
  uint8Equal,
  ack_frame_to_ranges,
  ranges_to_ack_frame
} from './utils.js';

import {
  quic_derive_init_secrets,
  quic_derive_from_tls_secrets,
  quic_derive_key_update,
  encrypt_quic_packet,
  decrypt_quic_packet,
  extract_tls_messages_from_chunks
} from './crypto.js';

import {
  parse_quic_datagram,
  encode_quic_frames,
  parse_quic_frames
} from './transport.js';

import { TLSBridge } from './tls_bridge.js';


function QUICConnection(options) {
  if (!(this instanceof QUICConnection)) return new QUICConnection(options);
  options = options || {};

  var ev = Emitter();
  var tls = null;

  // ============================================================
  //  Context
  // ============================================================

  var context = {
    isServer: options.isServer !== false,
    state: 'idle',
    handshake_done: false,
    handshake_done_sent: false,

    // Connection close (RFC 9000 §10.2)
    close_frame: null,         // the CONNECTION_CLOSE frame to (re)send while closing
    last_close_echo: 0,        // timestamp throttle for closing-state CC echoes

    version: 1,
    original_dcid: null,
    my_cids: [],
    their_cids: [],

    // Keys
    initial_read: null,
    initial_write: null,
    handshake_read: null,
    handshake_write: null,
    app_read: null,
    app_write: null,
    app_prev_read: null,       // previous read keys (kept during transition)
    key_phase: false,          // our current send key_phase
    read_key_phase: false,     // expected key_phase on incoming packets
    app_read_secret: null,     // current read secret (for deriving next)
    app_write_secret: null,    // current write secret (for deriving next)
    cipher_hash: 'sha256',     // hash for key derivation
    cipher_suite: null,        // TLS cipher suite code (for key length)

    // Packet numbers — sending
    send_pn: { initial: 0, handshake: 0, app: 0 },

    // Packet numbers — receiving
    recv_pn_largest: { initial: -1, handshake: -1, app: -1 },
    recv_pn_ranges: { initial: [], handshake: [], app: [] },

    // CRYPTO
    crypto_chunks: { initial: {}, handshake: {} },   // RECEIVE-side reassembly
    crypto_offset: { initial: 0, handshake: 0 },
    crypto_send_offset: { initial: 0, handshake: 0, app: 0 },

    // CRYPTO send-side loss recovery (Initial/Handshake spaces).
    // The app stream path retransmits "for free" — stream bytes stay in
    // send_streams and the round-robin re-scans them. CRYPTO is otherwise
    // fire-and-forget (cryptoWrite discards the bytes after one send), and the
    // handshake spaces have no expireInFlight. So we mirror the stream model on
    // a tiny per-space structure (same flat-ranges semantics, no stream id, no
    // FIN): retain sent bytes, track which PN carried which byte-range, expire
    // by time, and re-send missing ranges. A CRYPTO frame is just a STREAM frame
    // of a single id-less, fin-less stream — so the bookkeeping is identical.
    crypto_sent: {
      initial:   { buf: [], in_flight: {}, acked: [], backoff: 0 },
      handshake: { buf: [], in_flight: {}, acked: [], backoff: 0 },
    },
    crypto_timer: null,

    // ACK
    pending_ack: { initial: [], handshake: [], app: [] },

    // Receiving streams
    recv_streams: {},

    // Sending streams
    send_streams: {},

    // In-flight tracking (Phase 1)
    sending_app_pn_in_flight: new Set(),
    sending_app_pn_history: [],   // [time_sent, encoded_len, delivered_at_send, delivered_time_at_send]
    delivered: 0,                 // cumulative app bytes acked — for BBR rate samples
    delivered_time: Date.now(),   // wall-clock of the last delivered update (BBR delivery clock)

    // ── Burst / congestion-control knobs ───────────────────────────────────
    // Three layers (+ a floor):
    //   max_*     HARD CEILING — the programmer sets these; the CC NEVER exceeds
    //             them, whatever the network measurements say. Safety net against
    //             a CC bug, a pathological link, or memory blow-up.
    //   min_*     FLOOR — the CC never shrinks below this. Also prevents the
    //             deadlock where a cap < one packet rounds down to 0.
    //   init_*    STARTING point of the current_* values at each new connection.
    //   current_* RUNTIME values the CC rewrites (≈ every RTT). Always clamped to
    //             [min_, max_]. The send loop reads min(current_, max_), so the
    //             moment Phase 4b starts writing current_* it takes effect with no
    //             further wiring.
    //
    // Naming: <when>_limit_<noun>. The qualifiers (when=max/min/init/current, and the
    // word `limit`) all sit up front; the noun (bytes_in_flight / packets_per_sec /
    // packet_payload) stays whole at the end. This keeps `current_limit_bytes_in_flight`
    // (the CC's CEILING) clearly distinct from the live `bytesInFlight` it gates against.
    //
    // What each algorithm owns:
    //   current_limit_*_in_flight   (cwnd)        ← Phase 4b  (BBR-lite: ≈ 2·BtlBw·min_rtt)
    //   current_limit_*_per_sec     (pacing rate) ← Phase 4b  (BBR-lite: ≈ BtlBw)
    //   current_limit_packet_payload (MTU)        ← DPLPMTUD  (separate, later)
    // Until those algorithms run, init_* = max_* so behavior is the static default.
    // When 4b lands, lower the in-flight init_* toward IW10 (~10 pkts / ~14 KB)
    // and let the algorithm climb from there.

    max_packets_per_burst: 20,          // fixed cap — not CC-controlled, no current_/init_

    // packet payload (MTU). current_ is the size actually used; max_ is the ceiling
    // DPLPMTUD must not probe past; init_/floor is QUIC's guaranteed 1200-byte minimum.
    max_limit_packet_payload:     1452,       // ceiling (IPv6-safe Ethernet: 1500 − 48 hdr)
    init_limit_packet_payload:    1200,       // QUIC guaranteed floor — where we start
    current_limit_packet_payload: 1200,       // = init_; DPLPMTUD raises toward max_

    // in-flight window (cwnd) — bytes is the primary signal; packets kept coherent.
    // init_/current_ start at IW10 (RFC 9002 initial window, ~10 pkts) and BBR-lite
    // climbs from there toward 2·BDP; max_ is the hard ceiling, min_ the floor.
    max_limit_packets_in_flight:     256,     // ceiling ≈ 300 KB at 1200 B/pkt
    min_limit_packets_in_flight:     2,       // floor (RFC 9002 min cwnd)
    init_limit_packets_in_flight:    10,      // IW10
    current_limit_packets_in_flight: 10,      // = init_; BBR rewrites at round-end
    max_limit_bytes_in_flight:       300000,  // ceiling ~300 KB — coherent with packets ↑
    min_limit_bytes_in_flight:       2400,    // floor ~2 packets
    init_limit_bytes_in_flight:      12000,   // IW10 (10 × 1200 B)
    current_limit_bytes_in_flight:   12000,   // = init_; BBR rewrites at round-end

    // pacing rate
    max_limit_packets_per_sec:       12000,   // ceiling ≈ 14 MB/s
    min_limit_packets_per_sec:       10,      // floor — avoid 0/deadlock
    init_limit_packets_per_sec:      12000,
    current_limit_packets_per_sec:   12000,   // = init_; BBR rewrites at round-end
    max_limit_bytes_per_sec:         14000000, // ceiling ~14 MB/s — coherent ↑
    min_limit_bytes_per_sec:         12000,   // floor ~96 kbps — avoid 0/deadlock
    init_limit_bytes_per_sec:        14000000,
    current_limit_bytes_per_sec:     14000000, // = init_; BBR rewrites at round-end

    burst_timer: null,
    pacing_tokens: 0,           // token-bucket pacer: accumulated send credit (bytes)
    pacing_last_refill: Date.now(),

    // Pending app packets
    pending_app_packets: [],

    // Flow control — connection level (RFC 9000 §4.1)
    bytes_sent: 0,                    // total STREAM bytes sent (raw stat, incl. retransmits)
    // max_data_sent: connection-level FC USAGE — the sum of per-stream
    // high-water marks (highest offset sent on each stream). RFC 9000 §4.1
    // counts usage by highest offset, NOT bytes on the wire: retransmissions
    // re-send offsets that were already inside the allowance, so they must not
    // advance this counter. bytes_sent above (which does include retransmits)
    // previously doubled as the FC counter — under loss that inflated usage
    // until sending stalled with budget the peer had actually granted.
    max_data_sent: 0,
    bytes_received: 0,                // total STREAM bytes *received off the wire* (incl. out-of-order)
    remote_max_data: 1048576,         // peer's limit on what we can send (default 1MB until parsed)

    // ── Flow control, receive side (RFC 9000 §4.1) — consumption-based
    // sliding window (the ngtcp2/quiche scheme; replaces the old unbounded
    // ×2 doubling, which never actually limited the peer and grew forever).
    //
    // Three numbers per level:
    //   window (W)  — fixed size, = the value in our transport params.
    //   consumed    — bytes DELIVERED IN-ORDER to the application (advances in
    //                 flushStream), NOT bytes received off the wire. Data can
    //                 arrive out of order and park in the buffer unconsumed —
    //                 exactly what the window must bound (memory).
    //   advertised  — the limit last sent to the peer (local_max_data below /
    //                 per-stream local_max_stream_data). Slides forward by
    //                 `advertised = consumed + W` once consumed passes half a
    //                 window since the last update (hysteresis).
    //
    // USAGE (what the peer is measured against) counts by HIGHEST OFFSET per
    // stream (fc_recv_usage = Σ max_recv_offset), not bytes-on-the-wire —
    // retransmissions must not advance it. Exceeding `advertised` on either
    // level is a protocol violation → CONNECTION_CLOSE FLOW_CONTROL_ERROR
    // (0x03). A peer stalled because we haven't consumed sends DATA_BLOCKED /
    // STREAM_DATA_BLOCKED, answered by re-sending the current advertised —
    // that pairing (see the frame handlers) is what makes a lost window
    // update recoverable.
    local_max_data: 1048576,          // ADVERTISED conn limit (starts = window, from transport params)
    local_max_data_window: 1048576,   // W — fixed; matches initial_max_data we advertise
    local_max_data_consumed: 0,       // in-order bytes delivered to the app (all streams)
    fc_recv_usage: 0,                 // Σ per-stream max_recv_offset — the peer's usage

    //
    // Flow control — stream level (RFC 9000 §4.1)
    local_initial_max_stream_data: 262144, // matches transport params; doubled on MAX_STREAM_DATA updates

    remote_max_streams_bidi: 100,
    remote_max_streams_uni: 3,

    // ── Per-stream send-side flow control (RFC 9000 §4.1) — the peer's limits
    // on what WE may send per stream. Seeded from the peer's transport params
    // (initial_max_stream_data_*, mapped by stream direction/initiator in
    // initialStreamSendLimit), then raised by MAX_STREAM_DATA frames. The RFC
    // default for an omitted param is 0 — a peer that doesn't grant, grants
    // nothing (in practice params always arrive during the handshake, before
    // any app data can flow).
    peer_initial_max_stream_data_bidi_local: 0,
    peer_initial_max_stream_data_bidi_remote: 0,
    peer_initial_max_stream_data_uni: 0,
    // MAX_STREAM_DATA values keyed by stream id (monotonic). Lives outside the
    // stream object so a frame that arrives BEFORE the stream is created is
    // still honored at creation time. Entries are dropped when the stream is
    // fully acked / stopped.
    remote_max_stream_data_by_sid: {},

    // FC-blocked signaling (DATA_BLOCKED / STREAM_DATA_BLOCKED, RFC 9000 §4.1).
    // Set by get_stream_chunks when a window clamp actually binds; consumed by
    // maybeSendBlockedFrames after each burst pass. This doubles as our loss
    // recovery for window updates: MAX_DATA / MAX_STREAM_DATA are sent once
    // and never retransmitted, so a lost update would stall the sender forever
    // — the repeated (rate-limited) BLOCKED frame prompts the peer to re-send
    // its current limit.
    fc_blocked_conn: false,          // conn-level budget bound this pass
    last_data_blocked_sent: 0,       // rate-limit timestamp (connection)
    last_stream_blocked_sent: {},    // sid → rate-limit timestamp (per stream)

    // RTT estimate (RFC 9002 §5), updated incrementally on every new sample.
    // null = no sample yet. Replaces the old raw rtt_history log: the EWMA below
    // keeps the needed history implicitly, so per-sample storage isn't needed.
    srtt: null,
    rttvar: null,
    min_rtt: null,
    latest_rtt: null,
    max_ack_delay: 25, // ms; seeded from the peer's transport params (max_ack_delay) once parsed
    peer_ack_delay_exponent: 3, // seeded from the peer's transport params; ACK Delay = field × 2^this µs

    // --- Raw network observations (collected for the future congestion
    // controller; NOT acted on here). Flat on context, like the RTT fields.
    // Counters are cumulative; rates/extents are derived later over a window. ---
    max_rtt: null,              // paired with min_rtt — the gap reveals bufferbloat
    latest_delivery_rate: null, // bytes/sec acked in the most recent ACK sample
    max_delivery_rate: null,    // peak delivery rate ≈ BtlBw (a CC bandwidth input)
    lost_count: 0,              // packets declared lost by expireInFlight (≈ loss)
    reorder_in_count: 0,        // app packets that arrived below the highest PN seen (network reordering, peer→us)

    // --- BBR-lite measurement (Phase 4b, step 1+2 — measure only, no control). ---
    // BBR models the path from two measured quantities and derives the BDP:
    //   BDP = BtlBw × RTprop.  BtlBw = windowed-MAX delivery rate (≈ bottleneck
    //   bandwidth); RTprop = windowed-MIN RTT (≈ propagation, queue-free). Both use
    //   windows so a stale peak/min decays: a forever-max would never drop when the
    //   link slows, a forever-min would never rise as the true RTT changes.
    bbr_round_count: 0,         // round-trip counter; one round ≈ one RTT elapsed
    bbr_round_start_pn: 0,      // round completes when an ACK's largest >= this
    bbr_round_start_delivered: 0, // context.delivered at round start (for per-round rate)
    bbr_round_start_time: Date.now(), // wall-clock at round start (for per-round rate)
    bbr_btlbw_samples: [],      // [{round, rate}] — per-ACK delivery-rate samples
    bbr_btlbw: null,            // windowed-max delivery rate over the last N rounds (≈ BtlBw)
    bbr_min_rtt: null,          // windowed-min RTT over ~10s (≈ RTprop)
    bbr_min_rtt_stamp: 0,       // when bbr_min_rtt was last (re)set
    bbr_bdp: null,              // derived BtlBw × min_rtt (bytes) — the in-flight target

    // BBR-lite state machine. Startup ramps exponentially (high gain) to discover
    // BtlBw; once it plateaus (no ≥25% growth for 3 rounds) the pipe is full, so
    // Drain removes the queue Startup built, then ProbeBW holds steady at the
    // bottleneck rate. Without Startup, writing cwnd from an under-saturated
    // measurement death-spirals to the floor (the link never gets filled).
    bbr_state: 'startup',       // 'startup' | 'drain' | 'probe_bw'
    bbr_full_bw: 0,             // highest BtlBw seen — Startup plateau detector
    bbr_full_bw_count: 0,       // consecutive rounds without ≥25% BtlBw growth
    bbr_cycle_idx: 0,           // ProbeBW pacing-gain cycle position (0..7)

    // Timers
    idle_timeout: options.idleTimeout || 30000,
    handshake_timeout: options.handshakeTimeout || 10000,
    last_activity: Date.now(),
    // Time of the most recent ACK received from the peer (set only in
    // processAckFrame). Drives the in-flight-expiry backoff: while the peer
    // isn't ACKing us, the retransmit timeout widens so we don't flood a dead
    // path. Distinct from last_activity (which also bumps on send/receive).
    last_ack_time: Date.now(),
    idle_timer: null,
    handshake_timer: null,

    // Keep-alive: when > 0, send a PING after this many ms of inactivity to
    // keep the connection from idling out (RFC 9000 §10.1.2). Should be < the
    // idle timeout. options.keepAlive: true → idle_timeout/2; a number → ms.
    keep_alive_interval: (function () {
      var k = options.keepAlive;
      if (k === true) return Math.max(1000, Math.floor((options.idleTimeout || 30000) / 2));
      if (typeof k === 'number' && k > 0) return k;
      return 0;
    })(),
    keep_alive_timer: null,

    SNICallback: options.SNICallback || null,
    hostname: options.hostname || null,

    // ALPN protocol(s) to advertise in the TLS handshake.
    // Defaults to ['h3'] (HTTP/3). Other QUIC-based protocols set their own,
    // e.g. 'doq' for DNS-over-QUIC (RFC 9250). Accepts a string or array.
    alpn: (function () {
      var a = options.alpn || ['h3'];
      return Array.isArray(a) ? a : [a];
    })(),
  };


  // ============================================================
  //  set_context
  // ============================================================

  function set_context(updates) {
    if (!updates || typeof updates !== 'object') return;
    var changed = {};

    if ('state' in updates && updates.state !== context.state) {
      context.state = updates.state;
      changed.state = true;
    }
    if ('handshake_done' in updates && updates.handshake_done !== context.handshake_done) {
      context.handshake_done = updates.handshake_done;
      changed.handshake_done = true;
    }
    if ('handshake_done_sent' in updates) {
      context.handshake_done_sent = updates.handshake_done_sent;
    }
    if ('original_dcid' in updates && updates.original_dcid !== null && context.original_dcid === null) {
      context.original_dcid = updates.original_dcid;
      changed.original_dcid = true;
    }
    if ('version' in updates && updates.version !== context.version) {
      context.version = updates.version;
    }
    if ('add_their_cid' in updates) {
      var cid = updates.add_their_cid;
      var found = false;
      for (var i = 0; i < context.their_cids.length; i++) {
        if (uint8Equal(cid, context.their_cids[i])) { found = true; break; }
      }
      if (!found) context.their_cids.push(cid);
    }
    if ('initial_read' in updates)   { context.initial_read = updates.initial_read; changed.initial_read = true; }
    if ('initial_write' in updates)  { context.initial_write = updates.initial_write; changed.initial_write = true; }
    if ('handshake_read' in updates) { context.handshake_read = updates.handshake_read; }
    if ('handshake_write' in updates){ context.handshake_write = updates.handshake_write; }
    if ('app_read' in updates)       { context.app_read = updates.app_read; }
    if ('app_write' in updates)      { context.app_write = updates.app_write; }
    if ('remote_max_data' in updates && updates.remote_max_data > context.remote_max_data) {
      context.remote_max_data = updates.remote_max_data; changed.remote_max_data = true;
    }
    if ('remote_max_streams_bidi' in updates) { context.remote_max_streams_bidi = updates.remote_max_streams_bidi; }
    if ('remote_max_streams_uni' in updates)  { context.remote_max_streams_uni = updates.remote_max_streams_uni; }
    if ('key_phase' in updates && updates.key_phase !== context.key_phase) {
      context.key_phase = updates.key_phase; changed.key_phase = true;
    }

    // ---- Reactive ----

    if (changed.initial_read || changed.initial_write) {
      if (context.state === 'idle') { context.state = 'handshaking'; changed.state = true; }
    }

    if (changed.handshake_done && context.handshake_done === true) {
      if (DEBUG) console.log('[quic] handshake done — flushing ' + context.pending_app_packets.length + ' pending');
      if (context.pending_app_packets.length > 0) {
        var pending = context.pending_app_packets;
        context.pending_app_packets = [];
        for (var i = 0; i < pending.length; i++) {
          processDecryptedPacket('app', pending[i].packet_number, pending[i].plaintext);
        }
      }
      startIdleTimer();
      startKeepAliveTimer();
    }

    if (changed.state && context.state === 'connected') {
      // 'connect' event is emitted explicitly by TLS handlers (not here)
      // Server emits on appSecrets, Client emits on secureConnect
    }

    if (changed.state && (context.state === 'draining' || context.state === 'closing')) {
      clearIdleTimer();
      // A draining/closing endpoint must stop retransmitting CRYPTO — the
      // ticker would otherwise keep resending the handshake flight at a peer
      // that already told us the connection is dead (seen live: three Initial
      // retransmits fired after a CONNECTION_CLOSE was processed).
      stopCryptoRetx();
      var _drainTimer = setTimeout(function () {
        if (context.state === 'draining' || context.state === 'closing') { context.state = 'closed'; ev.emit('close'); }
      }, Math.min(3000, context.idle_timeout / 3));
      if (_drainTimer.unref) _drainTimer.unref();
    }

    if (changed.state && context.state === 'closed') { clearIdleTimer(); ev.emit('close'); }
    if (changed.remote_max_data) { plan_quic_burst(); }
    if (changed.key_phase) {
      // We initiated key update — derive new write keys
      if (context.app_write_secret) {
        var next = quic_derive_key_update(context.app_write_secret, context.cipher_hash, context.cipher_suite);
        if (DEBUG) console.log('[quic] key update initiated — new write keys');
        context.app_write = { key: next.key, iv: next.iv, hp: context.app_write.hp };
        context.app_write_secret = next.secret;
      }
    }
  }


  // ============================================================
  //  Idle timeout
  // ============================================================

  function touchActivity() { context.last_activity = Date.now(); }

  function startIdleTimer() {
    clearIdleTimer();
    if (context.idle_timeout <= 0) return;
    context.idle_timer = setInterval(function () {
      if (Date.now() - context.last_activity >= context.idle_timeout) {
        if (DEBUG) console.log('[quic] idle timeout');
        close(0, 'idle timeout');
      }
    }, Math.max(1000, Math.floor(context.idle_timeout / 4)));
    if (context.idle_timer.unref) context.idle_timer.unref();
  }

  function startKeepAliveTimer() {
    if (context.keep_alive_interval <= 0) return;
    if (context.keep_alive_timer !== null) return; // idempotent
    context.keep_alive_timer = setInterval(function () {
      if (context.state !== 'connected') return;
      // Only ping when the connection has actually been idle for the interval.
      // Real traffic (sent or received) calls touchActivity(), which resets
      // last_activity and suppresses unnecessary keep-alive PINGs.
      if (Date.now() - context.last_activity >= context.keep_alive_interval) {
        if (DEBUG) console.log('[quic] keep-alive PING');
        sendFrames('app', [{ type: 'ping' }]);
      }
    }, context.keep_alive_interval);
    if (context.keep_alive_timer.unref) context.keep_alive_timer.unref();
  }

  function clearIdleTimer() {
    if (context.idle_timer !== null) { clearInterval(context.idle_timer); context.idle_timer = null; }
    // Keep-alive shares the connection's liveness lifecycle: stop it wherever
    // the idle timer is stopped (handshake (re)start, draining/closing, closed).
    if (context.keep_alive_timer !== null) { clearInterval(context.keep_alive_timer); context.keep_alive_timer = null; }
  }


  // ============================================================
  //  TLS Bridge
  // ============================================================

  function initTLS() {
    // Start handshake timeout — if TLS doesn't complete in time, close
    if (context.handshake_timeout > 0 && !context.handshake_timer) {
      context.handshake_timer = setTimeout(function () {
        if (context.state !== 'connected' && context.state !== 'closed' && context.state !== 'draining' && context.state !== 'closing') {
          if (DEBUG) console.log('[quic] handshake timeout (' + context.handshake_timeout + 'ms)');
          ev.emit('error', new Error('QUIC handshake timeout'));
          close(0x100, 'handshake timeout');  // 0x100 = CRYPTO_ERROR
        }
      }, context.handshake_timeout);
      if (context.handshake_timer.unref) context.handshake_timer.unref();
    }

    tls = new TLSBridge({
      isServer: context.isServer,
      SNICallback: context.SNICallback,
      originalDcid: context.original_dcid,
      localCid: context.my_cids.length > 0 ? context.my_cids[0] : new Uint8Array(0),
      hostname: context.hostname,
      alpn: context.alpn
    });

    tls.on('send', function (epoch, data) { cryptoWrite(epoch, data); });

    // Peer's QUIC transport parameters (parsed from the TLS 0x39 extension). These
    // replace hardcoded defaults: the peer's flow-control limit, ACK-delay scaling,
    // and max ACK delay. Arrives once, during the handshake, before app data flows.
    tls.on('peerTransportParams', function (p) {
      // ack_delay_exponent: clamp to RFC 9000 range [0,20] (guards Math.pow blowup).
      if (typeof p.ack_delay_exponent === 'number') {
        context.peer_ack_delay_exponent = Math.max(0, Math.min(20, p.ack_delay_exponent));
      }
      // max_ack_delay (ms): the peer's stated max delay before it sends an ACK.
      if (typeof p.max_ack_delay === 'number' && p.max_ack_delay >= 0) {
        context.max_ack_delay = Math.min(p.max_ack_delay, 16384); // RFC cap 2^14 ms
      }
      // initial_max_data: the AUTHORITATIVE initial flow-control limit. Set directly
      // (not via the monotonic MAX_DATA path, which only increases) so a peer that
      // grants less than our 1MB default is honored. MAX_DATA frames raise it later.
      if (typeof p.initial_max_data === 'number') {
        context.remote_max_data = p.initial_max_data;
      }
      // Per-stream send limits (RFC 9000 §18.2). The params are named from the
      // PEER's perspective; initialStreamSendLimit() maps them onto our stream
      // ids by direction/initiator when a send-stream is created.
      if (typeof p.initial_max_stream_data_bidi_local === 'number') {
        context.peer_initial_max_stream_data_bidi_local = p.initial_max_stream_data_bidi_local;
      }
      if (typeof p.initial_max_stream_data_bidi_remote === 'number') {
        context.peer_initial_max_stream_data_bidi_remote = p.initial_max_stream_data_bidi_remote;
      }
      if (typeof p.initial_max_stream_data_uni === 'number') {
        context.peer_initial_max_stream_data_uni = p.initial_max_stream_data_uni;
      }
      // Stream-count limits the peer grants us. Enforcement (blocking opens
      // past the cap) is future work, but seed the real values so the guessed
      // defaults (100/3) don't masquerade as negotiated ones.
      if (typeof p.initial_max_streams_bidi === 'number') {
        context.remote_max_streams_bidi = p.initial_max_streams_bidi;
      }
      if (typeof p.initial_max_streams_uni === 'number') {
        context.remote_max_streams_uni = p.initial_max_streams_uni;
      }
      // Defensive: raise the limit of any stream opened before the params
      // arrived (normally none — params land during the handshake).
      for (var rsid in context.send_streams) {
        var rst = context.send_streams[rsid];
        var seeded = initialStreamSendLimit(Number(rsid));
        if (seeded > rst.remote_max_stream_data) rst.remote_max_stream_data = seeded;
      }
      plan_quic_burst(); // budgets changed
      if (DEBUG) console.log('[quic] peer params: ack_delay_exp=' + context.peer_ack_delay_exponent +
        ' max_ack_delay=' + context.max_ack_delay + ' remote_max_data=' + context.remote_max_data +
        ' msd_bidi_local=' + context.peer_initial_max_stream_data_bidi_local +
        ' msd_bidi_remote=' + context.peer_initial_max_stream_data_bidi_remote +
        ' msd_uni=' + context.peer_initial_max_stream_data_uni);
    });

    tls.on('handshakeSecrets', function (secrets) {
      set_context({
        handshake_read: quic_derive_from_tls_secrets(secrets.remote, secrets.hash, secrets.cipher),
        handshake_write: quic_derive_from_tls_secrets(secrets.local, secrets.hash, secrets.cipher)
      });
    });

    tls.on('appSecrets', function (secrets) {
      // Handshake complete — clear timeout
      if (context.handshake_timer) {
        clearTimeout(context.handshake_timer);
        context.handshake_timer = null;
      }

      // Store secrets for future key updates (RFC 9001 §6)
      context.app_read_secret = secrets.remote;
      context.app_write_secret = secrets.local;
      context.cipher_hash = secrets.hash;
      context.cipher_suite = secrets.cipher;

      set_context({
        app_read: quic_derive_from_tls_secrets(secrets.remote, secrets.hash, secrets.cipher),
        app_write: quic_derive_from_tls_secrets(secrets.local, secrets.hash, secrets.cipher),
        state: 'connected',
        handshake_done: true
      });

      // NOTE: do NOT stop crypto recovery here. Reaching appSecrets means OUR
      // side finished, but the peer hasn't necessarily received our flight yet
      // (the server hits this the moment it sends Finished, before the client
      // confirms). The crypto ticker self-terminates once every CRYPTO byte is
      // acked (cryptoHasInFlight() === false); close() force-stops it otherwise.

      // Server: emit connect now (Finished already sent)
      // Client: wait for secureConnect (after client Finished is generated)
      if (context.isServer) {
        ev.emit('connect');
      }
    });

    tls.on('secureConnect', function () {
      // Client: Finished has been generated and queued. 
      // Flush handshake first, then emit connect so 1-RTT goes after Finished.
      if (!context.isServer) {
        plan_quic_burst(); // flush any pending handshake data (Finished)
        ev.emit('connect');
      }
    });

    // Note: QUIC handles key updates via key_phase bit, not TLS KeyUpdate message.
    // RFC 9001 §6: "endpoints MUST treat the receipt of a TLS KeyUpdate message
    // as a connection error of type 0x010a" — but we silently ignore it.
  }


  // ============================================================
  //  Incoming packets
  // ============================================================

  function feedDatagram(from_ip, from_port, data) {
    if (DEBUG) console.log('[quic] datagram from ' + from_ip + ':' + from_port + ' len=' + data.length);
    feedPackets(from_ip, from_port, parse_quic_datagram(data));
  }

  // Feed already-parsed packets. Used by the server, which parses each UDP
  // datagram once (to route it to a connection) and then hands the parsed
  // packets here directly, avoiding a redundant second parse.
  function feedPackets(from_ip, from_port, packets) {
    if (context.state === 'closed' || context.state === 'draining') return;
    if (context.state === 'closing') {
      // RFC 9000 §10.2.1: while closing, don't process packets normally; instead
      // re-send CONNECTION_CLOSE in response (rate-limited) so the peer learns
      // we've closed even if the first CC was lost.
      if (Date.now() - context.last_close_echo >= 200) sendConnectionClose();
      return;
    }
    touchActivity();
    for (var i = 0; i < packets.length; i++) {
      if (packets[i] !== null) {
        // Safety net: a single malformed packet must never crash the process or
        // tear down the connection. The parsers are bounds-checked, but this
        // also guards decrypt / frame-handler edge cases. Drop the bad packet
        // (logged under DEBUG) and keep processing the rest of the datagram.
        try {
          feedPacket(packets[i]);
        } catch (e) {
          if (DEBUG) console.log('[quic] dropped packet — processing error: ' + (e && e.message));
        }
      }
    }
  }

  function feedPacket(pkt) {
    if (context.state === 'draining' || context.state === 'closed') return;

    if (pkt.version && pkt.version !== context.version) set_context({ version: pkt.version });
    if (pkt.dcid && pkt.dcid.byteLength > 0) set_context({ original_dcid: pkt.dcid });
    if (pkt.scid && pkt.scid.byteLength > 0) set_context({ add_their_cid: pkt.scid });

    var space = pkt.type === 'initial' ? 'initial'
              : pkt.type === 'handshake' ? 'handshake'
              : pkt.type === '1rtt' ? 'app' : null;
    if (!space) return;

    if (space === 'initial' && !context.initial_read && context.original_dcid) {
      set_context({
        initial_read: quic_derive_init_secrets(context.original_dcid, context.version, 'read'),
        initial_write: quic_derive_init_secrets(context.original_dcid, context.version, 'write')
      });
    }

    var readKeys = space === 'initial' ? context.initial_read
                 : space === 'handshake' ? context.handshake_read : context.app_read;
    if (!readKeys) return;

    // Connection ID by which *we* are addressed. Its length is needed to locate
    // the packet number in short (1-RTT) headers, which carry no DCID-length
    // field — the receiver must already know its own CID length. For a server
    // this is the SCID it chose (which it adopts as original_dcid); for a client
    // it's its own SCID (my_cids[0]). Long headers carry the DCID length on the
    // wire, so decrypt ignores this value for Initial/Handshake packets.
    var recvCid = context.isServer
      ? context.original_dcid
      : (context.my_cids.length > 0 ? context.my_cids[0] : context.original_dcid);

    var decrypted = decrypt_quic_packet(
      pkt.raw, readKeys.key, readKeys.iv, readKeys.hp,
      recvCid, context.recv_pn_largest[space]
    );

    // Key Update: if app decrypt fails, try with derived next keys
    if ((!decrypted || !decrypted.plaintext) && space === 'app' && context.app_read_secret) {
      var next = quic_derive_key_update(context.app_read_secret, context.cipher_hash, context.cipher_suite);
      decrypted = decrypt_quic_packet(
        pkt.raw, next.key, next.iv, readKeys.hp, // HP doesn't change
        recvCid, context.recv_pn_largest[space]
      );

      if (decrypted && decrypted.plaintext && decrypted.plaintext.byteLength > 0) {
        // Key update confirmed — install new read keys
        if (DEBUG) console.log('[quic] key update detected — installing new read keys');
        context.app_prev_read = context.app_read;
        context.app_read = { key: next.key, iv: next.iv, hp: readKeys.hp };
        context.app_read_secret = next.secret;
        context.read_key_phase = !context.read_key_phase;
      }
    }

    // Also try prev keys for reordered packets from before key update
    if ((!decrypted || !decrypted.plaintext) && space === 'app' && context.app_prev_read) {
      decrypted = decrypt_quic_packet(
        pkt.raw, context.app_prev_read.key, context.app_prev_read.iv, context.app_prev_read.hp,
        recvCid, context.recv_pn_largest[space]
      );
    }

    if (!decrypted || !decrypted.plaintext || decrypted.plaintext.byteLength === 0) {
      if (DEBUG) console.log('[quic] decrypt failed: ' + space + ' raw_len=' + pkt.raw.byteLength + ' first20=' + Array.from(pkt.raw.slice(0, 20)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ') + ' recv_cid_len=' + (recvCid ? recvCid.byteLength : 'null') + ' has_keys=' + !!readKeys + ' largest_pn=' + context.recv_pn_largest[space]);
      return;
    }

    if (DEBUG) console.log('[quic] decrypted ' + space + ' pn=' + decrypted.packet_number + ' len=' + decrypted.plaintext.byteLength);

    var pn = decrypted.packet_number;
    var ranges = context.recv_pn_ranges[space];
    var isNew = true;
    for (var ri = 0; ri < ranges.length; ri += 2) {
      if (pn >= ranges[ri] && pn < ranges[ri + 1]) { isNew = false; break; }
    }
    if (isNew) {
      flat_ranges.add(ranges, [pn, pn + 1]);
      if (pn > context.recv_pn_largest[space]) {
        context.recv_pn_largest[space] = pn;
      } else if (space === 'app') {
        // New packet, but below the highest PN already seen → it arrived out of
        // order. Pure network reordering (the peer sends PNs strictly increasing).
        context.reorder_in_count++;
      }
    }

    if (DEBUG) console.log('[quic] pn=' + pn + ' isNew=' + isNew);
    if (!isNew) return;

    if (space === 'app' && !context.handshake_done) {
      context.pending_app_packets.push(decrypted);
      return;
    }

    processDecryptedPacket(space, pn, decrypted.plaintext);
  }


  // ============================================================
  //  Frame processing
  // ============================================================

  function processDecryptedPacket(space, packetNumber, plaintext) {
    var frames = parse_quic_frames(plaintext);
    if (DEBUG) console.log('[quic] frames: ' + space + ' pn=' + packetNumber + ' [' + frames.map(function(f){ return f.type; }).join(',') + ']');
    var ackEliciting = false;

    if (context.isServer && space === 'app' && !context.handshake_done_sent) {
      set_context({ handshake_done_sent: true });
      sendFrames('app', [{ type: 'handshake_done' }]);
    }

    for (var i = 0; i < frames.length; i++) {
      var frame = frames[i];

      if (frame.type === 'crypto') {
        ackEliciting = true;
        processCryptoFrame(space, frame.offset, frame.data);
      } else if (frame.type === 'stream') {
        ackEliciting = true;
        processStreamFrame(frame);
      } else if (frame.type === 'ack') {
        processAckFrame(space, frame);
      } else if (frame.type === 'ping') {
        ackEliciting = true;
      } else if (frame.type === 'handshake_done') {
        ackEliciting = true;
      } else if (frame.type === 'path_challenge') {
        ackEliciting = true;
        sendFrames(space, [{ type: 'path_response', data: frame.data }]);
      } else if (frame.type === 'new_connection_id') {
        ackEliciting = true;
      } else if (frame.type === 'connection_close') {
        if (DEBUG) console.log('[quic] CONNECTION_CLOSE error=0x' + (frame.error || 0).toString(16) + ' frame_type=0x' + (frame.frameType || 0).toString(16) + ' reason="' + (frame.reason || '') + '"');
        set_context({ state: 'draining' });
        return;
      } else if (frame.type === 'stop_sending') {
        // Peer says: stop sending on this stream
        ackEliciting = true;
        if (frame.id in context.send_streams) {
          if (DEBUG) console.log('[quic] STOP_SENDING stream=' + frame.id + ' error=' + frame.error);
          delete context.send_streams[frame.id];
          delete context.remote_max_stream_data_by_sid[frame.id];
          delete context.last_stream_blocked_sent[frame.id];
        }
      } else if (frame.type === 'reset_stream') {
        // Peer cancelled their stream
        ackEliciting = true;
        if (frame.id in context.recv_streams) {
          if (DEBUG) console.log('[quic] RESET_STREAM stream=' + frame.id + ' error=' + frame.error);
          delete context.recv_streams[frame.id];
        }
      } else if (frame.type === 'max_data') {
        ackEliciting = true;
        set_context({ remote_max_data: frame.max });
      } else if (frame.type === 'max_streams_bidi') {
        ackEliciting = true;
        set_context({ remote_max_streams_bidi: frame.max });
      } else if (frame.type === 'max_streams_uni') {
        ackEliciting = true;
        set_context({ remote_max_streams_uni: frame.max });
      } else if (frame.type === 'max_stream_data') {
        ackEliciting = true;
        // The peer raised our send allowance on one stream (previously the
        // value was dropped on the floor). Track it monotonically in the
        // sid-keyed map (so a frame arriving before the stream exists is
        // honored at creation) and on the live stream, then reschedule — this
        // may have just unblocked a sender stalled on the old limit.
        var msdPrev = context.remote_max_stream_data_by_sid[frame.id] || 0;
        if (frame.max > msdPrev) context.remote_max_stream_data_by_sid[frame.id] = frame.max;
        var msdStream = context.send_streams[frame.id];
        if (msdStream && frame.max > msdStream.remote_max_stream_data) {
          msdStream.remote_max_stream_data = frame.max;
          plan_quic_burst();
        }
      } else if (frame.type === 'data_blocked') {
        // The peer is stalled on our connection window. Our MAX_DATA may have
        // been lost (window updates are sent once, unrecovered) — re-send the
        // current limit. Harmless if it wasn't lost: the peer's limit is
        // monotonic, a duplicate is ignored.
        ackEliciting = true;
        sendFrames('app', [{ type: 'max_data', max: context.local_max_data }]);
      } else if (frame.type === 'stream_data_blocked') {
        // Same, per stream. If we never received data on this stream (all of
        // it lost), no recv_stream exists yet — answer with the initial limit
        // we advertised in our transport params.
        ackEliciting = true;
        var sdbStream = context.recv_streams[frame.id];
        var sdbLimit = sdbStream ? sdbStream.local_max_stream_data
                                 : context.local_initial_max_stream_data;
        sendFrames('app', [{ type: 'max_stream_data', id: Number(frame.id), max: sdbLimit }]);
      } else if (frame.type === 'datagram') {
        // DATAGRAM frames are ack-eliciting (RFC 9221 §5.2). Without this, a
        // peer sending only datagrams (a classic WebTransport flow) would get
        // no ACKs from us and read the silence as total loss.
        ackEliciting = true;
        ev.emit('datagram', frame.data);
      }
    }

    if (ackEliciting) {
      flat_ranges.add(context.pending_ack[space], [packetNumber, packetNumber + 1]);
      var ackFrame = ranges_to_ack_frame(context.pending_ack[space], null, 0);
      if (ackFrame) {
        sendFrames(space, [ackFrame]);
        if (space !== 'app') context.pending_ack[space] = [];
      }
    }
  }


  // ============================================================
  //  CRYPTO → TLS
  // ============================================================

  function processCryptoFrame(space, offset, data) {
    if (space !== 'initial' && space !== 'handshake') return;
    if (DEBUG) console.log('[quic] CRYPTO: space=' + space + ' offset=' + offset + ' len=' + data.length);

    var chunks = context.crypto_chunks[space];
    var fromOffset = context.crypto_offset[space];
    if (!(offset in chunks) || chunks[offset].byteLength < data.byteLength) chunks[offset] = data;

    var result = extract_tls_messages_from_chunks(chunks, fromOffset);
    if (DEBUG) console.log('[quic] TLS messages: ' + (result ? result.tls_messages.length : 'none'));
    if (!result) return;

    context.crypto_offset[space] = result.new_from_offset;
    if (!tls) { if (DEBUG) console.log('[quic] initializing TLS bridge'); initTLS(); }

    for (var i = 0; i < result.tls_messages.length; i++) {
      var msg = result.tls_messages[i];
      var msgType = msg[0];
      if (DEBUG) console.log('[quic] → TLS msg #' + i + ' type=0x' + msgType.toString(16) + ' len=' + msg.length);

      // Detect HelloRetryRequest (type 0x02 with special random)
      if (msgType === 0x02 && msg.length >= 38) {
        var hrrRandom = [0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C];
        var isHRR = true;
        for (var j = 0; j < 32; j++) { if (msg[6 + j] !== hrrRandom[j]) { isHRR = false; break; } }
        if (isHRR && DEBUG) console.log('[quic] ⚠️  HelloRetryRequest detected! LemonTLS needs HRR support.');
      }

      tls.feedMessage(msg);
    }
  }


  // ============================================================
  //  Stream receive
  // ============================================================

  function processStreamFrame(frame) {
    var sid = frame.id;
    if (!(sid in context.recv_streams)) {
      context.recv_streams[sid] = { chunks: {}, ranges: [], total_size: 0, flushed_to: 0,
        max_recv_offset: 0,   // highest offset seen — the peer's FC usage on this stream
        local_max_stream_data: context.local_initial_max_stream_data };
    }
    var stream = context.recv_streams[sid];

    // ── FC usage + enforcement (RFC 9000 §4.1) ──────────────────────────────
    // Usage advances only when the HIGHEST offset advances — a retransmission
    // re-delivers offsets already counted and must not be charged (the old
    // bytes_received counter charged every arriving byte, so under loss we
    // advertised new windows early). Exceeding what we advertised, on either
    // level, is the peer's protocol violation → FLOW_CONTROL_ERROR (0x03).
    var newHigh = frame.offset + frame.data.length;
    if (newHigh > stream.max_recv_offset) {
      if (newHigh > stream.local_max_stream_data) {
        if (DEBUG) console.log('[quic] FC violation: stream ' + sid + ' offset ' + newHigh + ' > advertised ' + stream.local_max_stream_data);
        close(0x03, 'stream flow control exceeded');
        return;
      }
      var fcDelta = newHigh - stream.max_recv_offset;
      if (context.fc_recv_usage + fcDelta > context.local_max_data) {
        if (DEBUG) console.log('[quic] FC violation: connection usage ' + (context.fc_recv_usage + fcDelta) + ' > advertised ' + context.local_max_data);
        close(0x03, 'connection flow control exceeded');
        return;
      }
      stream.max_recv_offset = newHigh;
      context.fc_recv_usage += fcDelta;
    }

    var alreadyHave = false;
    for (var ri = 0; ri < stream.ranges.length; ri += 2) {
      if (frame.offset >= stream.ranges[ri] && frame.offset + frame.data.length <= stream.ranges[ri + 1]) {
        alreadyHave = true; break;
      }
    }
    if (!alreadyHave) {
      flat_ranges.add(stream.ranges, [frame.offset, frame.offset + frame.data.length]);
      if (!(frame.offset in stream.chunks) || stream.chunks[frame.offset].byteLength < frame.data.byteLength) {
        stream.chunks[frame.offset] = frame.data;
      }
      // Raw stat only — FC usage is max_recv_offset above, not this.
      context.bytes_received += frame.data.byteLength;
    }
    if (frame.fin && stream.total_size === 0) stream.total_size = frame.offset + frame.data.length;
    flushStream(sid);
  }

  // (checkLocalFlowControl — the old unbounded ×2 doubling — was replaced by
  //  the consumption-based sliding window inside flushStream above.)

  function flushStream(sid) {
    var stream = context.recv_streams[sid];
    if (!stream) return;
    var parts = [];
    var offset = stream.flushed_to;
    // Walk the in-order prefix. Chunks are keyed by their start offset, but
    // retransmission re-slices byte ranges with boundaries that need not match
    // the original transmission's (the per-burst budget differs between
    // passes). So a chunk can START BEFORE the cursor and extend past it —
    // an exact-key walk (`offset in chunks`) stalls forever on such a chunk
    // even though every byte is present (observed live: ranges said
    // [0,262144] complete while flushed_to sat at 31846, mid-chunk of the
    // entry keyed 31747). When the exact key misses, scan for a covering
    // chunk and consume its tail; drop fully-stale chunks (entirely behind
    // the cursor — overlap leftovers) along the way.
    while (true) {
      var chunk = stream.chunks[offset];
      var chunkStart = offset;
      if (!chunk) {
        var keys = Object.keys(stream.chunks);
        for (var ki = 0; ki < keys.length; ki++) {
          var ks = Number(keys[ki]);
          var c = stream.chunks[ks];
          var kEnd = ks + c.byteLength;
          if (kEnd <= offset) { delete stream.chunks[ks]; continue; }  // stale overlap leftover
          if (ks < offset && kEnd > offset) { chunk = c; chunkStart = ks; break; }
        }
        if (!chunk) break;  // genuine gap — wait for more data
      }
      delete stream.chunks[chunkStart];
      var skip = offset - chunkStart;                    // 0 on the exact-key path
      parts.push(skip > 0 ? chunk.subarray(skip) : chunk);
      offset = chunkStart + chunk.byteLength;
    }
    if (parts.length === 0) return;
    var delivered = offset - stream.flushed_to;   // in-order bytes handed to the app now
    stream.flushed_to = offset;
    var data = parts.length === 1 ? parts[0] : concatUint8Arrays(parts);
    var fin = (stream.total_size > 0 && offset >= stream.total_size);
    ev.emit('stream', Number(sid), data, fin);
    if (fin) setTimeout(function () { delete context.recv_streams[sid]; }, 100);

    // ── Sliding window updates (consumption-based; see the context header) ──
    // Both levels use the same rule: once consumption has advanced at least
    // half a window past the last advertisement, advertise consumed + W.
    // Monotonic by construction; a duplicate/lower advert is ignored by the
    // peer, and re-sends on DATA_BLOCKED reuse these same fields.

    // Connection level: consumed = in-order bytes delivered across all streams.
    context.local_max_data_consumed += delivered;
    var W = context.local_max_data_window;
    if (context.local_max_data_consumed + W - context.local_max_data >= W / 2) {
      context.local_max_data = context.local_max_data_consumed + W;
      sendFrames('app', [{ type: 'max_data', max: context.local_max_data }]);
    }

    // Stream level: consumed = flushed_to. No update after FIN — the stream
    // is done, its final usage stays counted at the connection level.
    if (!fin) {
      var Ws = context.local_initial_max_stream_data;
      if (stream.flushed_to + Ws - stream.local_max_stream_data >= Ws / 2) {
        stream.local_max_stream_data = stream.flushed_to + Ws;
        sendFrames('app', [{ type: 'max_stream_data', id: Number(sid), max: stream.local_max_stream_data }]);
      }
    }
  }


  // Update the smoothed RTT estimate from a new sample (RFC 9002 §5.3).
  // latest_rtt = now − time_sent(largest_acked); ack_delay_ms is the peer's
  // reported ACK delay. min_rtt uses the raw sample; srtt/rttvar use the
  // ack_delay-adjusted sample. Recursive EWMA: each sample folds into
  // srtt/rttvar immediately, so no per-sample history is retained.
  function updateRtt(latest_rtt, ack_delay_ms) {
    context.latest_rtt = latest_rtt;

    // min_rtt tracks the raw minimum (before any ack_delay adjustment).
    context.min_rtt = (context.min_rtt === null)
      ? latest_rtt
      : Math.min(context.min_rtt, latest_rtt);

    // max_rtt tracks the raw maximum; max_rtt − min_rtt ≈ queueing/bufferbloat.
    context.max_rtt = (context.max_rtt === null)
      ? latest_rtt
      : Math.max(context.max_rtt, latest_rtt);

    // BBR RTprop: windowed-min RTT over ~10s. Unlike the forever-min above, it
    // expires so it can rise if the true path RTT changes. It is refreshed by a
    // lower sample, or replaced when the 10s window lapses (ProbeRTT later forces
    // a queue-free sample so this stays honest under a persistent standing queue).
    var BBR_MIN_RTT_WINDOW = 10000; // ms
    var now_rtt = Date.now();
    if (context.bbr_min_rtt === null ||
        latest_rtt <= context.bbr_min_rtt ||
        now_rtt - context.bbr_min_rtt_stamp > BBR_MIN_RTT_WINDOW) {
      context.bbr_min_rtt = latest_rtt;
      context.bbr_min_rtt_stamp = now_rtt;
    }

    // Subtract ACK delay, but cap it at max_ack_delay and never let it pull the
    // sample below min_rtt (RFC 9002 §5.3).
    var ack_delay = Math.min(ack_delay_ms, context.max_ack_delay);
    var adjusted = latest_rtt;
    if (latest_rtt >= context.min_rtt + ack_delay) adjusted = latest_rtt - ack_delay;

    if (context.srtt === null) {
      context.srtt = adjusted;
      context.rttvar = adjusted / 2;
    } else {
      context.rttvar = 0.75 * context.rttvar + 0.25 * Math.abs(context.srtt - adjusted);
      context.srtt = 0.875 * context.srtt + 0.125 * adjusted;
    }
    if (DEBUG) console.log('[quic] rtt: sample=' + latest_rtt + 'ms srtt=' + Math.round(context.srtt) + ' rttvar=' + Math.round(context.rttvar) + ' min=' + context.min_rtt);
  }


  // ============================================================
  //  ACK processing (Phase 1)
  // ============================================================

  // Total app stream bytes currently in flight (unacked). Used by BBR's Drain
  // state to know when the queue built during Startup has been emptied.
  function appBytesInFlight() {
    var total = 0;
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (!st.in_flight_ranges) continue;
      for (var pn in st.in_flight_ranges) {
        if (pn === '_burst') continue;
        total += st.in_flight_ranges[pn][1] - st.in_flight_ranges[pn][0];
      }
    }
    return total;
  }

  function processAckFrame(space, frame) {
    var ackedRanges = ack_frame_to_ranges(frame);
    if (!ackedRanges || ackedRanges.length === 0) return;

    // The peer acknowledged something → it's responsive in the return
    // direction. Resets the in-flight-expiry backoff (any space counts).
    // Capture the previous ACK time first — it's the interval for delivery_rate.
    var ackNow = Date.now();
    var prevAckTime = context.last_ack_time;
    context.last_ack_time = ackNow;

    // Initial/Handshake: an ACK confirms crypto byte-ranges. Move them in_flight
    // → acked and reset that space's resend backoff (the peer is responding).
    if (space === 'initial' || space === 'handshake') {
      var cs = context.crypto_sent[space];
      for (var cpn in cs.in_flight) {
        var p = Number(cpn), hit = false;
        for (var cri = 0; cri < ackedRanges.length; cri += 2) {
          if (p >= ackedRanges[cri] && p <= ackedRanges[cri + 1]) { hit = true; break; }
        }
        if (hit) { flat_ranges.add(cs.acked, cs.in_flight[cpn].range); delete cs.in_flight[cpn]; }
      }
      cs.backoff = 0;
      return;
    }

    if (space === 'app') {
      // RTT measurement
      if ('largest' in frame && 'delay' in frame) {
        var largest_pn = frame.largest;
        // Only measure from the largest *newly* acked, ack-eliciting packet
        // (RFC 9002 §5.1). sending_app_pn_in_flight holds data-carrying PNs —
        // the closest signal until sent_packets tracks ack_eliciting per packet
        // (so PING-only packets are not yet used as RTT samples).
        if (context.sending_app_pn_in_flight.has(largest_pn)) {
          var now = Date.now();
          // ACK Delay is microseconds scaled by 2^ack_delay_exponent; use the peer's
          // value (parsed from its transport params; defaults to 3 until then).
          var ack_delay_ms = Math.round((frame.delay * Math.pow(2, context.peer_ack_delay_exponent)) / 1000);
          var pn_index = largest_pn - (context.send_pn.app - context.sending_app_pn_history.length);
          if (pn_index >= 0 && pn_index < context.sending_app_pn_history.length) {
            var latest_rtt = now - context.sending_app_pn_history[pn_index][0];
            if (latest_rtt > 0) updateRtt(latest_rtt, ack_delay_ms);
          }
        }
      }

      // Mark in-flight as acked. Collect the acked PNs first, then mutate —
      // deleting from a Set while iterating it with for-of is fragile.
      var ackedPns = [];
      for (var pn of context.sending_app_pn_in_flight) {
        for (var ri = 0; ri < ackedRanges.length; ri += 2) {
          if (pn >= ackedRanges[ri] && pn <= ackedRanges[ri + 1]) { ackedPns.push(pn); break; }
        }
      }
      var newlyAckedBytes = 0;   // goodput bytes confirmed by this ACK (for delivery_rate)
      var oldestAckedPn = null;  // smallest newly-acked PN → longest delivery interval
      for (var ai = 0; ai < ackedPns.length; ai++) {
        var apn = ackedPns[ai];
        if (oldestAckedPn === null || apn < oldestAckedPn) oldestAckedPn = apn;
        context.sending_app_pn_in_flight.delete(apn);
        for (var sid in context.send_streams) {
          var st = context.send_streams[sid];
          if (st.in_flight_ranges && apn in st.in_flight_ranges) {
            newlyAckedBytes += st.in_flight_ranges[apn][1] - st.in_flight_ranges[apn][0];
            flat_ranges.add(st.acked_ranges, st.in_flight_ranges[apn]);
            delete st.in_flight_ranges[apn];
            if (st.total_size > 0 && st.acked_ranges.length === 2 &&
                st.acked_ranges[0] === 0 && st.acked_ranges[1] >= st.total_size) {
              delete context.send_streams[sid];
              delete context.remote_max_stream_data_by_sid[sid];
              delete context.last_stream_blocked_sent[sid];
            }
          }
        }
      }

      // Cumulative delivered advances by this ACK's goodput; the delivery clock
      // is the wall-time of this update.
      context.delivered += newlyAckedBytes;

      // latest_delivery_rate / max_delivery_rate: per-ACK observations (kept for
      // visibility). NOTE: these are NOT fed to the BtlBw filter — per-ACK samples
      // spike under ACK aggregation and the windowed-max locks onto the spike
      // (the 20→39 Mbps over-read). BtlBw is sampled once per round instead (below).
      if (oldestAckedPn !== null && context.sending_app_pn_history.length > 0) {
        var rs_idx = oldestAckedPn - (context.send_pn.app - context.sending_app_pn_history.length);
        if (rs_idx >= 0 && rs_idx < context.sending_app_pn_history.length) {
          var deliveredAtSend     = context.sending_app_pn_history[rs_idx][2];
          var deliveredTimeAtSend = context.sending_app_pn_history[rs_idx][3];
          var interval = ackNow - deliveredTimeAtSend;
          var deltaDelivered = context.delivered - deliveredAtSend;
          if (interval >= 1 && deltaDelivered > 0) {
            context.latest_delivery_rate = (deltaDelivered * 1000) / interval;
            if (context.max_delivery_rate === null ||
                context.latest_delivery_rate > context.max_delivery_rate) {
              context.max_delivery_rate = context.latest_delivery_rate;
            }
          }
        }
      }
      context.delivered_time = ackNow;

      // BBR round tracking: a round (~1 RTT) completes when this ACK acknowledges
      // a packet sent at/after the round boundary. We then recompute the windowed
      // BtlBw (max delivery rate over the last N rounds) and the derived BDP. This
      // is the per-RTT cadence at which Phase 4b step 3 will write current_limit_*.
      if ('largest' in frame && frame.largest >= context.bbr_round_start_pn) {
        // Per-round rate sample: total bytes delivered during the round over the
        // round's duration (≈ 1 RTT). Averaging across the whole round washes out
        // ACK-aggregation spikes that corrupt per-ACK samples.
        var roundDur = ackNow - context.bbr_round_start_time;
        var roundDelivered = context.delivered - context.bbr_round_start_delivered;
        if (roundDur >= 1 && roundDelivered > 0) {
          context.bbr_btlbw_samples.push({ round: context.bbr_round_count, rate: (roundDelivered * 1000) / roundDur });
        }

        context.bbr_round_count++;
        context.bbr_round_start_pn = context.send_pn.app; // next PN must be acked for the next round
        context.bbr_round_start_delivered = context.delivered;
        context.bbr_round_start_time = ackNow;

        var BBR_BTLBW_WINDOW = 10; // rounds
        var cutoff = context.bbr_round_count - BBR_BTLBW_WINDOW;
        var kept = [], maxRate = null;
        for (var bi = 0; bi < context.bbr_btlbw_samples.length; bi++) {
          var smp = context.bbr_btlbw_samples[bi];
          if (smp.round >= cutoff) {
            kept.push(smp);
            if (maxRate === null || smp.rate > maxRate) maxRate = smp.rate;
          }
        }
        context.bbr_btlbw_samples = kept;
        context.bbr_btlbw = maxRate;

        // Derived in-flight target. Uses bbr_min_rtt (RTprop, windowed) in seconds.
        if (context.bbr_btlbw !== null && context.bbr_min_rtt !== null) {
          // BDP = BtlBw × RTprop. On near-zero-RTT paths (localhost, LAN) RTprop
          // collapses toward 0, so BDP → 0 and cwnd would clamp to the min floor
          // (≈2 packets) — starving throughput on the fastest links. Floor RTprop at
          // a few ms for this calc: it only affects sub-floor RTTs (where the link is
          // fast and can absorb the extra window) and never binds on normal links.
          // (A tick-adaptive floor was tried and reverted — see the pacer note.)
          var BBR_RTPROP_FLOOR_MS = 5;
          var rttForBdp = Math.max(context.bbr_min_rtt, BBR_RTPROP_FLOOR_MS);
          context.bbr_bdp = context.bbr_btlbw * (rttForBdp / 1000);

          // ── State machine → (pacing_gain, cwnd_gain) ──────────────────────
          var STARTUP_GAIN = 2.89;            // ≈ 2/ln2 — exponential ramp
          var pacing_gain, cwnd_gain;
          if (context.bbr_state === 'startup') {
            pacing_gain = STARTUP_GAIN; cwnd_gain = STARTUP_GAIN;
            // Plateau detector: BtlBw must grow ≥25% per round to stay in Startup.
            if (context.bbr_btlbw >= context.bbr_full_bw * 1.25) {
              context.bbr_full_bw = context.bbr_btlbw;
              context.bbr_full_bw_count = 0;
            } else if (++context.bbr_full_bw_count >= 3) {
              context.bbr_state = 'drain';    // pipe is full
            }
          } else if (context.bbr_state === 'drain') {
            pacing_gain = 1 / STARTUP_GAIN; cwnd_gain = STARTUP_GAIN; // drain the queue
            if (appBytesInFlight() <= context.bbr_bdp) context.bbr_state = 'probe_bw';
          } else { // probe_bw — cruise at the bottleneck rate while gently probing.
            // pacing_gain cycles 1.25 (probe for more bw) → 0.75 (drain the queue
            // that 1.25 just built) → 1.0×6 (cruise). The 0.75 phase is what keeps
            // the standing queue near-empty: without it, cwnd=2·BDP lets ~1 BDP of
            // queue sit permanently (≈ the bufferbloat we measured). One phase per round.
            var PROBE_BW_CYCLE = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
            pacing_gain = PROBE_BW_CYCLE[context.bbr_cycle_idx];
            // cwnd_gain bounds the standing queue directly: in JS userland the pacer
            // isn't precise enough to hold in-flight at exactly BDP (kernel BBR uses
            // cwnd_gain 2), so a tighter ceiling is what actually limits bufferbloat.
            // 1.25 → at most ~0.25·BDP of queue, while leaving room for the 1.25 probe.
            cwnd_gain = 1.25;
            context.bbr_cycle_idx = (context.bbr_cycle_idx + 1) % PROBE_BW_CYCLE.length;
          }

          // ── Write the controls, clamped to [min,max] (the hard safety net). ──
          var clamp = function (v, lo, hi) { return Math.max(lo, Math.min(hi, v)); };

          var targetInflight = clamp(cwnd_gain * context.bbr_bdp,
            context.min_limit_bytes_in_flight, context.max_limit_bytes_in_flight);
          context.current_limit_bytes_in_flight = targetInflight;
          context.current_limit_packets_in_flight = clamp(
            Math.round(targetInflight / context.current_limit_packet_payload),
            context.min_limit_packets_in_flight, context.max_limit_packets_in_flight);

          var targetRate = clamp(pacing_gain * context.bbr_btlbw,
            context.min_limit_bytes_per_sec, context.max_limit_bytes_per_sec);
          context.current_limit_bytes_per_sec = targetRate;
          context.current_limit_packets_per_sec = clamp(
            Math.round(targetRate / context.current_limit_packet_payload),
            1, context.max_limit_packets_per_sec);
        }
        if (DEBUG && context.bbr_bdp !== null) {
          console.log('[bbr] round=' + context.bbr_round_count + ' ' + context.bbr_state +
            ' BtlBw=' + (context.bbr_btlbw * 8 / 1e6).toFixed(2) + 'Mbps' +
            ' RTprop=' + context.bbr_min_rtt + 'ms' +
            ' BDP=' + Math.round(context.bbr_bdp) + 'B' +
            ' → cwnd=' + Math.round(context.current_limit_bytes_in_flight) + 'B' +
            ' pace=' + (context.current_limit_bytes_per_sec * 8 / 1e6).toFixed(2) + 'Mbps');
        }
      }

      // ACK freed capacity — try to send more
      plan_quic_burst();
    }
  }


  // ============================================================
  //  Sending
  // ============================================================

  function cryptoWrite(epoch, data) {
    var space = epoch === 'initial' ? 'initial' : epoch === 'handshake' ? 'handshake' : 'app';
    var offset = context.crypto_send_offset[space];
    context.crypto_send_offset[space] += data.byteLength;
    // Retain the bytes so a lost CRYPTO frame can be re-sent (app/1-RTT crypto
    // never loses — it rides the app stream-recovery path and isn't tracked here).
    if (space === 'initial' || space === 'handshake') {
      context.crypto_sent[space].buf.push({ off: offset, data: data });
    }
    sendFrames(space, [{ type: 'crypto', offset: offset, data: data }]);
    if (space === 'initial' || space === 'handshake') scheduleCryptoRetx();
  }

  // Assemble the bytes for crypto byte-range [from,to) of `space` from retained
  // fragments (contiguous, appended in order by cryptoWrite).
  function cryptoSlice(space, from, to) {
    var out = new Uint8Array(to - from);
    var frags = context.crypto_sent[space].buf;
    for (var i = 0; i < frags.length; i++) {
      var fOff = frags[i].off, fEnd = fOff + frags[i].data.byteLength;
      var lo = Math.max(from, fOff), hi = Math.min(to, fEnd);
      if (lo < hi) out.set(frags[i].data.subarray(lo - fOff, hi - fOff), lo - from);
    }
    return out;
  }

  // Time-based loss recovery for the Initial/Handshake CRYPTO streams — the
  // analog of expireInFlight for the app path. No RTT sample exists during the
  // handshake, so the timeout starts at kInitialRtt (333ms) and backs off ×2 per
  // unacked round (reset by an ACK in processAckFrame).
  function cryptoTimeout(space) {
    var base = (context.srtt === null) ? 333 : context.srtt + Math.max(4 * context.rttvar, 1);
    var bo = Math.min(context.crypto_sent[space].backoff, 6); // cap ×64
    return base * Math.pow(2, bo);
  }

  // Re-send any crypto byte-range that is neither acked nor currently in-flight.
  // Mirrors get_stream_chunks: missing = invert(acked ∪ in_flight, 0, total).
  function resendMissingCrypto(space) {
    var cs = context.crypto_sent[space];
    var total = context.crypto_send_offset[space];
    if (total === 0) return false;

    var known = cs.acked.slice();
    for (var pn in cs.in_flight) flat_ranges.add(known, cs.in_flight[pn].range);
    var missing = flat_ranges.invert(known, 0, total);
    if (!missing || missing.length === 0) return false;

    var MAX = Math.max(256, context.current_limit_packet_payload - 64); // leave header room
    var sentAny = false;
    for (var i = 0; i < missing.length; i += 2) {
      var from = missing[i], to = missing[i + 1];
      while (from < to) {
        var end = Math.min(from + MAX, to);
        sendFrames(space, [{ type: 'crypto', offset: from, data: cryptoSlice(space, from, end) }]);
        sentAny = true;
        from = end;
      }
    }
    return sentAny;
  }

  // Expire in-flight crypto whose timeout elapsed (range returns to "missing").
  function expireCryptoInFlight() {
    var now = Date.now(), spaces = ['initial', 'handshake'], expired = false;
    for (var s = 0; s < spaces.length; s++) {
      var space = spaces[s], cs = context.crypto_sent[space], timeout = cryptoTimeout(space);
      for (var pn in cs.in_flight) {
        if (now - cs.in_flight[pn].time_sent >= timeout) { delete cs.in_flight[pn]; expired = true; }
      }
    }
    return expired;
  }

  function cryptoHasInFlight() {
    return Object.keys(context.crypto_sent.initial.in_flight).length > 0 ||
           Object.keys(context.crypto_sent.handshake.in_flight).length > 0;
  }

  // Self-terminating ticker: keeps firing while any CRYPTO byte is unacked
  // (the analog of plan_quic_burst's hasInFlight reschedule — needed because the
  // first flight can be lost with no ACK to trigger anything). It is driven by
  // acked-state, NOT local handshake_done: the server reaches handshake_done the
  // moment it sends Finished, but must keep resending until the client acks.
  function cryptoTick() {
    context.crypto_timer = null;
    if (expireCryptoInFlight()) {
      if (resendMissingCrypto('initial'))   context.crypto_sent.initial.backoff++;
      if (resendMissingCrypto('handshake')) context.crypto_sent.handshake.backoff++;
    }
    if (cryptoHasInFlight()) scheduleCryptoRetx();
  }

  function scheduleCryptoRetx() {
    if (context.crypto_timer !== null) return; // idempotent
    var iv = Math.min(cryptoTimeout('initial'), cryptoTimeout('handshake'));
    context.crypto_timer = setTimeout(cryptoTick, iv);
    if (context.crypto_timer.unref) context.crypto_timer.unref();
  }

  function stopCryptoRetx() {
    if (context.crypto_timer !== null) { clearTimeout(context.crypto_timer); context.crypto_timer = null; }
    context.crypto_sent.initial   = { buf: [], in_flight: {}, acked: [], backoff: 0 };
    context.crypto_sent.handshake = { buf: [], in_flight: {}, acked: [], backoff: 0 };
  }

  function sendFrames(space, frameList) {
    // RFC 9000 §10.2: a draining endpoint MUST NOT send packets at all; a
    // closing endpoint may only (re)send its CONNECTION_CLOSE. Belt-and-
    // suspenders with the timer cleanup — any stray timer (crypto retx, burst,
    // keep-alive) that fires after the state change dies here instead of
    // emitting packets at a dead connection.
    if (context.state === 'draining' || context.state === 'closed') return;
    if (context.state === 'closing' &&
        !(frameList.length === 1 && frameList[0].type === 'connection_close')) return;

    var writeKeys = space === 'initial' ? context.initial_write
                  : space === 'handshake' ? context.handshake_write : context.app_write;
    if (!writeKeys) { if (DEBUG) console.log('[quic] sendFrames(' + space + ') — no keys'); return; }

    // Read the next packet number but DON'T commit it yet — only advance
    // send_pn once the packet is successfully encrypted and emitted (below).
    // A failed encryption must not consume a PN: a gap would desync the
    // pn → sending_app_pn_history index math (and RTT). See LOSS_PTO_PLAN §5.
    var pn = context.send_pn[space];
    var packetType = space === 'initial' ? 'initial' : space === 'handshake' ? 'handshake' : '1rtt';

    var dcid, scid;
    if (packetType === '1rtt') {
      dcid = context.their_cids.length > 0 ? context.their_cids[0] : new Uint8Array(0);
      scid = new Uint8Array(0);
    } else if (context.isServer) {
      dcid = context.their_cids.length > 0 ? context.their_cids[0] : new Uint8Array(0);
      scid = context.original_dcid || new Uint8Array(0);
    } else {
      // Client: Initial uses original_dcid (for key derivation),
      // Handshake uses server's SCID (RFC 9000 §7.2)
      if (space === 'initial' || context.their_cids.length === 0) {
        dcid = context.original_dcid || new Uint8Array(0);
      } else {
        dcid = context.their_cids[0];
      }
      scid = context.my_cids.length > 0 ? context.my_cids[0] : new Uint8Array(0);
    }

    var encoded = encode_quic_frames(frameList);

    // RFC 9000 §14.1: Initial datagrams must be >= 1200 bytes
    if (space === 'initial') {
      var overhead = 1 + 4 + 1 + dcid.byteLength + 1 + scid.byteLength + 1 + 2 + 1 + 16;
      var minPayload = 1200 - overhead;
      if (encoded.length < minPayload) {
        encoded = concatUint8Arrays([encoded, new Uint8Array(minPayload - encoded.length)]);
      }
    }

    var encrypted = encrypt_quic_packet(
      packetType, encoded, writeKeys.key, writeKeys.iv, writeKeys.hp, pn, dcid, scid, null,
      space === 'app' ? context.key_phase : false
    );

    if (encrypted) {
      // Commit the packet number now that the packet is real and about to go
      // out on the wire — atomic with the bookkeeping below, so send_pn and
      // sending_app_pn_history always advance together (no phantom PN).
      context.send_pn[space] = pn + 1;
      var fnames = frameList.map(function(f){ return f.type + (f.type === 'ack' ? '(lg=' + f.largest + ')' : ''); }).join(',');
      if (DEBUG) console.log('[quic] → ' + packetType + ' pn=' + pn + ' frames=[' + fnames + '] len=' + encrypted.length);
      touchActivity();

      if (space === 'app') {
        context.sending_app_pn_history.push([Date.now(), encoded.length, context.delivered, context.delivered_time]);
        var has_data = false;
        for (var i = 0; i < frameList.length; i++) {
          if (frameList[i].type === 'stream' || frameList[i].type === 'crypto') { has_data = true; break; }
        }
        if (has_data) context.sending_app_pn_in_flight.add(pn);

        for (var i = 0; i < frameList.length; i++) {
          if (frameList[i].type === 'stream') {
            var sid = frameList[i].id;
            var dataLen = frameList[i].data ? frameList[i].data.byteLength : 0;

            // Track connection-level bytes sent
            context.bytes_sent += dataLen;

            if (sid in context.send_streams) {
              if (!context.send_streams[sid].in_flight_ranges) context.send_streams[sid].in_flight_ranges = {};
              var from = frameList[i].offset;
              var to = from + (frameList[i].data ? frameList[i].data.byteLength : 0);
              if (!context.send_streams[sid].in_flight_ranges[pn]) {
                context.send_streams[sid].in_flight_ranges[pn] = [from, to];
              } else {
                flat_ranges.add(context.send_streams[sid].in_flight_ranges[pn], [from, to]);
              }
            }
          }
        }
      }

      // Initial/Handshake: record which byte-range of the crypto stream this PN
      // carried, so a lost packet's range can be re-sent (see crypto_sent).
      if (space === 'initial' || space === 'handshake') {
        for (var ci = 0; ci < frameList.length; ci++) {
          if (frameList[ci].type === 'crypto') {
            var cFrom = frameList[ci].offset;
            var cTo = cFrom + (frameList[ci].data ? frameList[ci].data.byteLength : 0);
            if (cTo > cFrom) context.crypto_sent[space].in_flight[pn] = { range: [cFrom, cTo], time_sent: Date.now() };
          }
        }
      }

      ev.emit('packet', encrypted);
    }
  }


  // ============================================================
  //  Stream send + Burst scheduler (Phase 2)
  //  Adapted from old quic_socket.js, improved with set_context
  // ============================================================

  /**
   * Initial send-limit for a stream we write to, per the peer's transport
   * params. Which param applies depends on the stream's direction and who
   * initiated it — the params are named from the PEER's perspective
   * (RFC 9000 §18.2):
   *   uni stream we send on      → initial_max_stream_data_uni
   *   bidi stream WE initiated   → ..._bidi_remote  ("remote" from the peer's view)
   *   bidi stream THEY initiated → ..._bidi_local
   * A MAX_STREAM_DATA that arrived before the stream existed is honored via
   * remote_max_stream_data_by_sid (monotonic max wins).
   */
  function initialStreamSendLimit(sid) {
    var isUni = (sid & 0x2) === 0x2;                 // bit 1: uni vs bidi
    var clientInitiated = (sid & 0x1) === 0x0;       // bit 0: initiator
    var weInitiated = context.isServer ? !clientInitiated : clientInitiated;
    var base;
    if (isUni) base = context.peer_initial_max_stream_data_uni;
    else if (weInitiated) base = context.peer_initial_max_stream_data_bidi_remote;
    else base = context.peer_initial_max_stream_data_bidi_local;
    var pending = context.remote_max_stream_data_by_sid[sid] || 0;
    return Math.max(base, pending);
  }

  /**
   * Buffer data for a stream. Does NOT send immediately.
   * Calls plan_quic_burst() to schedule sending.
   */
  function set_sending_stream(streamId, options) {
    if (!(streamId in context.send_streams)) {
      context.send_streams[streamId] = {
        pending_data: null, pending_offset_start: 0,
        write_offset: 0, send_offset: 0, total_size: 0,
        fin_sent: false, acked_ranges: [], in_flight_ranges: {},
        // Send-side FC (RFC 9000 §4.1): the peer's absolute offset cap for
        // this stream, and our high-water mark (highest offset ever yielded).
        // New data = bytes extending max_sent_offset; only those consume the
        // connection-level budget. See get_stream_chunks.
        remote_max_stream_data: initialStreamSendLimit(streamId),
        max_sent_offset: 0,
        fc_blocked: false
      };
    }

    var stream = context.send_streams[streamId];

    if (typeof options === 'object' && 'add_chunk' in options) {
      if (options.add_chunk.data === null || options.add_chunk.data === undefined) {
        if (stream.total_size === 0) {
          stream.total_size = stream.write_offset;
          if (DEBUG) console.log('[quic] stream ' + streamId + ' FIN via null data, total_size=' + stream.total_size);
        }
      } else {
        var chunk = options.add_chunk.data;
        if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
        var start = stream.write_offset;
        stream.write_offset += chunk.byteLength;
        if (DEBUG) console.log('[quic] stream ' + streamId + ' add_chunk len=' + chunk.byteLength + ' write_offset=' + stream.write_offset + ' fin=' + !!options.add_chunk.fin);

        if (stream.pending_data === null) {
          stream.pending_data = chunk;
          stream.pending_offset_start = start;
        } else {
          var old = stream.pending_data, old_off = stream.pending_offset_start;
          var ns = Math.min(old_off, start);
          var ne = Math.max(old_off + old.length, start + chunk.length);
          var merged = new Uint8Array(ne - ns);
          merged.set(old, old_off - ns);
          merged.set(chunk, start - ns);
          stream.pending_data = merged;
          stream.pending_offset_start = ns;
        }
        if (options.add_chunk.fin) {
          stream.total_size = stream.write_offset;
          if (DEBUG) console.log('[quic] stream ' + streamId + ' FIN via add_chunk.fin, total_size=' + stream.total_size);
        }
      }
    }

    // Don't send directly — let burst scheduler handle it
    plan_quic_burst();
  }

  function sendStream(streamId, data, fin) {
    set_sending_stream(streamId, { add_chunk: { data: data, fin: fin } });
  }

  function sendDatagram(data) {
    if (context.state !== 'connected') return false;
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    // A DATAGRAM frame must fit within a single packet — datagrams are never
    // fragmented (RFC 9221 §3). Reject payloads that exceed our per-packet
    // budget instead of emitting an oversized packet. Overhead is the 1-byte
    // 0x30 DATAGRAM frame type.
    if (data.byteLength > context.current_limit_packet_payload - 1) {
      if (DEBUG) console.log('[quic] sendDatagram: payload too large (' + data.byteLength + ' > ' + (context.current_limit_packet_payload - 1) + ')');
      return false;
    }
    sendFrames('app', [{ type: 'datagram', data: data }]);
    return true;
  }

  // Largest datagram payload (in bytes) that can be sent right now in a single
  // packet, or 0 if datagrams can't be sent yet (connection not 'connected').
  // This is a local single-packet estimate; QUICO does not currently parse the
  // peer's max_datagram_frame_size transport parameter, so it does not reflect
  // a negotiated peer limit.
  function maxDatagramSize() {
    if (context.state !== 'connected') return 0;
    return Math.max(0, context.current_limit_packet_payload - 1);
  }


  /**
   * plan_quic_burst — calculates how many packets we can send,
   * calls execute_quic_burst, schedules next burst if needed.
   */
  // Expire packets that have been in flight longer than the RTT-derived timeout
  // — the round-robin sender's equivalent of loss detection. A timed-out range
  // is deleted from in_flight_ranges, so the next pass sees it as "missing" and
  // resends it under a new packet number. Time-based ONLY (reordering must not
  // trigger a resend). A global backoff keyed off last_ack_time widens the
  // timeout while the peer isn't ACKing, so a dead path isn't flooded.
  function expireInFlight() {
    var now = Date.now();
    var base = (context.srtt === null) ? 333 : context.srtt + Math.max(4 * context.rttvar, 1);

    // Global backoff: while no ACK has arrived, widen the timeout geometrically.
    // Resets the instant an ACK updates last_ack_time.
    var sinceAck = now - context.last_ack_time;
    var mult = 1;
    while (sinceAck > base * mult * 2 && mult < 1024) mult *= 2;
    var timeout = base * mult;

    // PN of history index 0 (the array is a contiguous suffix of recent PNs).
    var pnBase = context.send_pn.app - context.sending_app_pn_history.length;

    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (!st.in_flight_ranges) continue;
      for (var pn in st.in_flight_ranges) {
        if (pn === '_burst') continue;          // temporary within-burst sentinel
        var pnum = Number(pn);
        var idx = pnum - pnBase;
        var expired;
        if (idx < 0 || idx >= context.sending_app_pn_history.length) {
          expired = true;                        // no send-time on record → assume expired (fail-safe)
        } else {
          expired = (now - context.sending_app_pn_history[idx][0] >= timeout);
        }
        if (expired) {
          delete st.in_flight_ranges[pn];        // → becomes "missing" again, resent next pass
          // Count the loss once per packet: the Set holds each PN once, so the
          // first stream to expire it returns true; later same-PN deletes (a
          // multi-stream packet) return false and don't double-count.
          if (context.sending_app_pn_in_flight.delete(pnum)) context.lost_count++;
        }
      }
    }
  }


  // Consume the fc_blocked flags set by get_stream_chunks and, rate-limited,
  // tell the peer we're stalled on its window (RFC 9000 §4.1 SHOULD). Beyond
  // being polite, this is the loss-recovery path for window updates: the
  // receiver answers a BLOCKED frame by re-sending its current MAX_DATA /
  // MAX_STREAM_DATA, so a single lost update can no longer deadlock the
  // sender. Returns true if any flag was set this pass (used to keep the
  // scheduler ticking while blocked with nothing in flight).
  var FC_BLOCKED_RESEND_MS = 500;
  function maybeSendBlockedFrames() {
    var now = Date.now();
    var wasBlocked = false;
    if (context.fc_blocked_conn) {
      context.fc_blocked_conn = false;
      wasBlocked = true;
      if (now - context.last_data_blocked_sent >= FC_BLOCKED_RESEND_MS) {
        context.last_data_blocked_sent = now;
        sendFrames('app', [{ type: 'data_blocked', limit: context.remote_max_data }]);
      }
    }
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (!st.fc_blocked) continue;
      st.fc_blocked = false;
      wasBlocked = true;
      if (now - (context.last_stream_blocked_sent[sid] || 0) >= FC_BLOCKED_RESEND_MS) {
        context.last_stream_blocked_sent[sid] = now;
        sendFrames('app', [{ type: 'stream_data_blocked', id: Number(sid), limit: st.remote_max_stream_data }]);
      }
    }
    return wasBlocked;
  }


  function plan_quic_burst() {
    if (!context.app_write) return;
    if (context.state !== 'connected') return;

    // Cancel pending timer
    if (context.burst_timer !== null) {
      clearTimeout(context.burst_timer);
      clearImmediate(context.burst_timer);
      context.burst_timer = null;
    }

    // Time out anything that's been in flight too long, so it resurfaces as
    // "missing" below and gets resent. (Runs before inflight/hasData are read.)
    expireInFlight();

    var now = Date.now();
    var oneSecAgo = now - 1000;

    // Count bytes/packets sent in last second
    var bytesSentLastSec = 0;
    var packetsSentLastSec = 0;
    for (var i = 0; i < context.sending_app_pn_history.length; i++) {
      if (context.sending_app_pn_history[i][0] > oneSecAgo) {
        bytesSentLastSec += context.sending_app_pn_history[i][1];
        packetsSentLastSec++;
      }
    }

    // Prune old history (older than 2 seconds)
    var twoSecAgo = now - 2000;
    while (context.sending_app_pn_history.length > 0 && context.sending_app_pn_history[0][0] < twoSecAgo) {
      context.sending_app_pn_history.shift();
    }

    // Effective limits. For rate: min(current_, max_). For in-flight: clamp
    // current_ to [min_, max_] — the min_ floor is the min-cwnd that keeps the
    // connection alive (a cap below one packet would otherwise round to 0 and
    // deadlock); max_ is the absolute ceiling and wins any min_>max_ misconfig.
    var effBytesPerSec   = Math.min(context.current_limit_bytes_per_sec,     context.max_limit_bytes_per_sec);
    var effPacketsPerSec = Math.min(context.current_limit_packets_per_sec,   context.max_limit_packets_per_sec);
    var effPktsInFlight  = Math.min(context.max_limit_packets_in_flight, Math.max(context.min_limit_packets_in_flight, context.current_limit_packets_in_flight));
    var effBytesInFlight = Math.min(context.max_limit_bytes_in_flight,   Math.max(context.min_limit_bytes_in_flight,   context.current_limit_bytes_in_flight));

    // Rate limits
    var bytesRemaining = effBytesPerSec - bytesSentLastSec;
    var packetsRemaining = effPacketsPerSec - packetsSentLastSec;
    if (bytesRemaining < 0) bytesRemaining = 0;
    if (packetsRemaining < 0) packetsRemaining = 0;

    // In-flight limits (packets)
    var inflightCount = context.sending_app_pn_in_flight.size;
    var inflightRoom = effPktsInFlight - inflightCount;
    if (inflightRoom < 0) inflightRoom = 0;

    // In-flight limits (bytes). Sum the application bytes currently in flight
    // (the spans still tracked in each stream's in_flight_ranges), then turn the
    // remaining byte budget into a packet count. Divide by the packet payload
    // (not the 35-byte min used for the rate limit): this is a HARD ceiling, so
    // we under-estimate how many packets fit and never overshoot the cap.
    var bytesInFlight = 0;
    for (var sidB in context.send_streams) {
      var stB = context.send_streams[sidB];
      if (!stB.in_flight_ranges) continue;
      for (var pnB in stB.in_flight_ranges) {
        if (pnB === '_burst') continue;
        bytesInFlight += stB.in_flight_ranges[pnB][1] - stB.in_flight_ranges[pnB][0];
      }
    }
    var bytesInFlightRoom = effBytesInFlight - bytesInFlight;
    if (bytesInFlightRoom < 0) bytesInFlightRoom = 0;
    var inflightBytesPackets = Math.floor(bytesInFlightRoom / context.current_limit_packet_payload);

    // Calculate burst size
    var burstCount = Math.min(
      context.max_packets_per_burst,
      packetsRemaining,
      inflightRoom,
      inflightBytesPackets,                          // bytes-in-flight cap
      Math.floor(bytesRemaining / Math.max(1, 35))  // min packet ~35 bytes
    );
    if (burstCount < 0) burstCount = 0;

    // Token-bucket pacer. Credit accrues continuously at the pacing rate; a burst
    // can spend up to PACE_BURST_MS worth of accrued tokens. This paces the long-run
    // rate to current_limit_bytes_per_sec while tolerating setTimeout jitter (a late
    // tick just accrues more tokens to catch up), and the small cap bounds how much
    // can enter the bottleneck at once = the max standing queue. (A zero-burst gate
    // starved throughput on JS timers; an unpaced ACK-clock parked ~1 BDP of queue.)
    //
    // KNOWN CEILING (documented, deliberate): on coarse-timer platforms
    // (Windows setTimeout ≈ 15ms) the 5ms cap discards most of a late tick's
    // accrual, capping throughput near cap/tick (~6 Mbps observed). Widening
    // the cap/bursts to cover a measured tick was tried and REVERTED: bigger
    // bursts overflow the small default UDP socket buffers (esp. same-process
    // loopback on Windows) → silent local drops → the loss-recovery machinery
    // turns a lossless link into a crawling one. Raising this ceiling properly
    // needs socket buffer sizing (setRecvBufferSize/setSendBufferSize at the
    // dgram layer) validated on a measurable rig — CC-calibration work, not a
    // constant to guess at. Stability beats throughput until then.
    var PACE_BURST_MS = 5;
    var rateBps = context.current_limit_bytes_per_sec;
    var nowR = Date.now();
    context.pacing_tokens += (nowR - context.pacing_last_refill) / 1000 * rateBps;
    context.pacing_last_refill = nowR;
    var tokenCap = Math.max(2 * context.current_limit_packet_payload, rateBps * (PACE_BURST_MS / 1000));
    if (context.pacing_tokens > tokenCap) context.pacing_tokens = tokenCap;
    var tokenPackets = Math.floor(context.pacing_tokens / context.current_limit_packet_payload);
    if (burstCount > tokenPackets) burstCount = tokenPackets;

    // Check if there's anything to send
    var hasData = false;
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (!st.pending_data || st.pending_data.byteLength === 0) continue;
      var total = st.total_size > 0 ? st.total_size : st.write_offset;
      var known = st.acked_ranges.slice();
      if (st.in_flight_ranges) {
        for (var pn in st.in_flight_ranges) flat_ranges.add(known, st.in_flight_ranges[pn]);
      }
      var missing = flat_ranges.invert(known, 0, total);
      if (missing.length > 0) { hasData = true; break; }
      // Also check: all data sent but FIN not yet sent?
      if (st.total_size > 0 && !st.fin_sent && missing.length === 0) { hasData = true; break; }
    }
    // Also check pending ACK
    var hasPendingAck = context.pending_ack.app.length > 0;

    // Any unacked data still in flight? Keep the scheduler alive so
    // expireInFlight can time it out and resend even when nothing is
    // immediately sendable — otherwise a lost range would stall here forever.
    var hasInFlight = false;
    for (var sidF in context.send_streams) {
      var stF = context.send_streams[sidF];
      if (!stF.in_flight_ranges) continue;
      for (var pnF in stF.in_flight_ranges) {
        if (pnF !== '_burst') { hasInFlight = true; break; }
      }
      if (hasInFlight) break;
    }

    if (!hasData && !hasPendingAck && !hasInFlight) return;

    // Paced out: have data + cwnd room, but not enough tokens yet for a packet.
    var pacedOut = hasData && burstCount === 0 && tokenPackets < 1 &&
                   context.sending_app_pn_in_flight.size < effPktsInFlight;

    // Execute burst
    var sent = 0;
    if (burstCount > 0) {
      sent = execute_quic_burst(burstCount);   // returns packets ACTUALLY sent
      // Charge tokens for what went out — not for the burstCount ceiling.
      // Charging the ceiling overbilled short bursts (e.g. a 2-packet stream
      // tail billed as 64) and starved the pacer for a full tick afterwards.
      if (sent > 0) context.pacing_tokens -= sent * context.current_limit_packet_payload;
    }

    // FC-blocked signaling — consume flags set inside the burst just executed.
    var fcBlocked = maybeSendBlockedFrames();

    // Schedule next burst if needed
    if (hasData && (sent || pacedOut)) {
      // Wait roughly until one more packet's worth of tokens has accrued.
      var delayMs = (rateBps > 0) ? (context.current_limit_packet_payload * 1000 / rateBps) : 1;
      if (delayMs < 1) delayMs = 1;       // setTimeout floor
      if (delayMs > 100) delayMs = 100;   // don't stall on a pathologically low rate
      context.burst_timer = setTimeout(function () {
        context.burst_timer = null;
        plan_quic_burst();
      }, delayMs);
      if (context.burst_timer.unref) context.burst_timer.unref();
    } else if (burstCount === 0 && hasData) {
      // Blocked by cwnd / rate window (not pacing) — wait for capacity / ACKs.
      var waitMs = (packetsRemaining <= 0 || bytesRemaining < 35) ? 50 : 10;
      context.burst_timer = setTimeout(function () {
        context.burst_timer = null;
        plan_quic_burst();
      }, waitMs);
      if (context.burst_timer.unref) context.burst_timer.unref();
    } else if (hasInFlight) {
      // Nothing to send right now, but data is still in flight and unacked.
      // Keep a light timer ticking so expireInFlight (top of each pass) can
      // time it out and resend. Self-terminating once everything is acked.
      context.burst_timer = setTimeout(function () {
        context.burst_timer = null;
        plan_quic_burst();
      }, 20);
      if (context.burst_timer.unref) context.burst_timer.unref();
    } else if (fcBlocked && hasData) {
      // FC-blocked with nothing in flight: without this the scheduler would go
      // idle here and the (rate-limited) BLOCKED signal above would fire only
      // once — and a once-sent frame can be lost too. Keep ticking until the
      // peer's window update arrives and unblocks hasData → sent.
      context.burst_timer = setTimeout(function () {
        context.burst_timer = null;
        plan_quic_burst();
      }, 250);
      if (context.burst_timer.unref) context.burst_timer.unref();
    }
  }


  /**
   * execute_quic_burst — fill up to packet_count packets.
   * Round-robin across active streams.
   * Returns the number of packets actually sent (0 if none) — the pacer
   * charges tokens per REAL packet, not per the packetCount ceiling.
   */
  function execute_quic_burst(packetCount) {
    var MAX_PAYLOAD = context.current_limit_packet_payload;
    var OVERHEAD = 24; // STREAM frame header overhead estimate
    var sentCount = 0;

    function getActiveIds() {
      var ids = [];
      for (var sid in context.send_streams) {
        var st = context.send_streams[sid];
        if (!st.pending_data || st.pending_data.byteLength === 0) continue;
        var total = st.total_size > 0 ? st.total_size : st.write_offset;
        // Build known_sent = acked + in_flight
        var known = st.acked_ranges.slice();
        if (st.in_flight_ranges) {
          for (var pn in st.in_flight_ranges) flat_ranges.add(known, st.in_flight_ranges[pn]);
        }
        var missing = flat_ranges.invert(known, 0, total);
        if (missing.length > 0) ids.push(Number(sid));
      }
      return ids;
    }

    var activeIds = getActiveIds();
    var burstYielded = {}; // track ranges yielded per-stream within this burst

    for (var p = 0; p < packetCount; p++) {
      var frames = [];
      var used = 0;

      // (1) ACK in first packet if pending
      if (p === 0 && context.pending_ack.app.length > 0) {
        var ackFrame = ranges_to_ack_frame(context.pending_ack.app, null, 0);
        if (ackFrame) {
          var ackEncoded = encode_quic_frames([ackFrame]);
          if (ackEncoded.byteLength <= MAX_PAYLOAD) {
            frames.push(ackFrame);
            used += ackEncoded.byteLength;
            context.pending_ack.app = [];
          }
        }
      }

      // (2) Round-robin STREAM data across active streams
      if (activeIds.length > 0 && used < MAX_PAYLOAD) {
        var progress = true;
        while (used < MAX_PAYLOAD && progress) {
          progress = false;

          for (var i = 0; i < activeIds.length; i++) {
            if (used >= MAX_PAYLOAD) break;

            var sid = activeIds[i];
            var st = context.send_streams[sid];
            if (!st || !st.pending_data) continue;

            var budget = Math.max(0, MAX_PAYLOAD - used - OVERHEAD);
            if (budget <= 0) break;

            var chunks = get_stream_chunks(sid, budget);
            if (!chunks || chunks.length === 0) continue;

            for (var c = 0; c < chunks.length; c++) {
              var ch = chunks[c];
              var fin = (st.total_size > 0 && ch.offset + ch.data.byteLength >= st.total_size);
              frames.push({ type: 'stream', id: sid, offset: ch.offset, fin: fin, data: ch.data });
              used += ch.data.byteLength + OVERHEAD;
              progress = true;

              // Immediately track as yielded so next round-robin iteration won't resend
              if (!burstYielded[sid]) burstYielded[sid] = [];
              flat_ranges.add(burstYielded[sid], [ch.offset, ch.offset + ch.data.byteLength]);
              // Also add to in_flight with temp key so get_stream_chunks sees it
              if (!st.in_flight_ranges) st.in_flight_ranges = {};
              if (!st.in_flight_ranges['_burst']) st.in_flight_ranges['_burst'] = [];
              flat_ranges.add(st.in_flight_ranges['_burst'], [ch.offset, ch.offset + ch.data.byteLength]);
            }
          }
        }
      }

      // (3) FIN-only frames: if all data sent/in-flight but FIN not yet sent
      for (var sid in context.send_streams) {
        var st = context.send_streams[sid];
        if (!st || st.total_size <= 0 || st.fin_sent) continue;
        // Check if all bytes are covered (acked + in_flight)
        var known = st.acked_ranges.slice();
        if (st.in_flight_ranges) {
          for (var pn in st.in_flight_ranges) flat_ranges.add(known, st.in_flight_ranges[pn]);
        }
        var missing = flat_ranges.invert(known, 0, st.total_size);
        if (DEBUG) console.log('[quic] FIN-only check stream=' + sid + ' total_size=' + st.total_size + ' fin_sent=' + st.fin_sent + ' missing=' + missing.length + ' known=' + JSON.stringify(known));
        if (missing.length === 0) {
          if (DEBUG) console.log('[quic] → sending FIN-only for stream ' + sid);
          // All data sent — send FIN-only STREAM frame
          frames.push({ type: 'stream', id: Number(sid), offset: st.total_size, fin: true, data: new Uint8Array(0) });
          st.fin_sent = true;
        }
      }

      // Send packet if it has content beyond just ACK-only
      if (frames.length > 0) {
        sendFrames('app', frames);
        sentCount++;
        // Clean up temp _burst in_flight keys (real PN keys now recorded by sendFrames)
        for (var sid in burstYielded) {
          var st = context.send_streams[sid];
          if (st && st.in_flight_ranges && st.in_flight_ranges['_burst']) {
            delete st.in_flight_ranges['_burst'];
          }
        }
      } else {
        break; // nothing to fill further packets
      }

      // Refresh active list
      activeIds = getActiveIds();
      if (activeIds.length === 0) break;
    }

    return sentCount;
  }


  /**
   * get_stream_chunks — find what bytes are missing (not acked) and
   * extract up to maxBytes from pending_data.
   * Uses flat_ranges.invert(acked_ranges) — the heart of retransmit.
   * Adapted from old get_stream_chunks_to_send().
   *
   * Strategy: first forward from send_offset (new data),
   *           then fill gaps before send_offset (retransmit).
   * pending_data is NEVER deleted — only when stream is fully acked.
   */
  function get_stream_chunks(streamId, maxBytes) {
    var stream = context.send_streams[streamId];
    if (!stream || !stream.pending_data || stream.pending_data.byteLength === 0) return [];

    // ── Flow control, send side (RFC 9000 §4.1) — two levels, one rule ──────
    // Both limits cap the HIGHEST OFFSET we may send, so they bind only NEW
    // data (bytes extending max_sent_offset). Retransmissions re-send offsets
    // that were already inside the allowance when first sent — they consume no
    // budget and MUST NOT be blocked. (The previous connection-only check
    // gated ALL bytes on remote_max_data − bytes_sent: under loss at the edge
    // of an exhausted window, the lost range itself was FC-blocked from being
    // repaired — a deadlock the peer can't always resolve, since the data it
    // would raise the window for is exactly the data that never arrived.)
    //   streamLimit   — absolute offset cap for THIS stream (seeded from the
    //                   peer's initial_max_stream_data_*, raised by
    //                   MAX_STREAM_DATA). Monotonic, so it never binds on a
    //                   retransmit of previously-allowed offsets.
    //   connRemaining — connection-level budget for new bytes: the peer's
    //                   max_data minus the sum of all streams' high-water
    //                   marks (context.max_data_sent). Decremented locally as
    //                   this call yields new bytes; committed via
    //                   max_data_sent at yield time (charging a chunk that a
    //                   later encrypt-failure drops only wastes budget —
    //                   conservative — never overspends it).
    var streamLimit = stream.remote_max_stream_data;
    var connRemaining = context.remote_max_data - context.max_data_sent;

    var data = stream.pending_data;
    var baseOffset = stream.pending_offset_start;
    var totalSize = stream.total_size > 0 ? stream.total_size : stream.write_offset;

    // Build "known sent" = acked + in_flight (don't resend what's already in transit)
    var knownSent = stream.acked_ranges.slice(); // copy
    if (stream.in_flight_ranges) {
      for (var pn in stream.in_flight_ranges) {
        flat_ranges.add(knownSent, stream.in_flight_ranges[pn]);
      }
    }

    // What truly needs sending? = invert of knownSent over [0, totalSize)
    var missing = flat_ranges.invert(knownSent, 0, totalSize);
    if (!missing || missing.length === 0) return [];

    var sendOffset = stream.send_offset;
    var chunks = [];
    var used = 0;

    // Phase 1: forward from send_offset (new data, priority)
    for (var i = 0; i < missing.length; i += 2) {
      if (used >= maxBytes) break;
      var mFrom = missing[i];
      var mTo = missing[i + 1];

      // Only ranges at or after send_offset
      if (mTo <= sendOffset) continue;
      var from = Math.max(mFrom, sendOffset);
      var to = mTo;

      // Clamp to budget
      var len = Math.min(to - from, maxBytes - used);
      if (len <= 0) continue;

      // Clamp to buffer bounds
      var relStart = from - baseOffset;
      var relEnd = relStart + len;
      if (relStart < 0 || relStart >= data.byteLength) continue;
      if (relEnd > data.byteLength) { relEnd = data.byteLength; len = relEnd - relStart; }
      if (len <= 0) continue;

      // FC clamp 1: never extend past the peer's per-stream offset cap.
      if (from + len > streamLimit) {
        stream.fc_blocked = true;   // the cap bound — signal STREAM_DATA_BLOCKED
        if (from >= streamLimit) continue;
        len = streamLimit - from; relEnd = relStart + len;
      }

      // FC clamp 2: charge the connection budget for NEW bytes only (the part
      // of this chunk above the stream's high-water mark).
      var newStart = Math.max(from, stream.max_sent_offset);
      var newBytes = Math.max(0, (from + len) - newStart);
      if (newBytes > connRemaining) {
        context.fc_blocked_conn = true;  // the budget bound — signal DATA_BLOCKED
        len -= (newBytes - connRemaining);
        relEnd = relStart + len;
        newBytes = connRemaining;
      }
      if (len <= 0) continue;

      chunks.push({ offset: from, data: data.slice(relStart, relEnd) });
      used += len;

      // Commit FC usage at yield time (see header note).
      if (newBytes > 0) {
        stream.max_sent_offset = from + len;
        context.max_data_sent += newBytes;
        connRemaining -= newBytes;
      }

      // Advance send_offset
      if (from + len > stream.send_offset) {
        stream.send_offset = from + len;
      }
    }

    // Phase 2: fill gaps before send_offset (retransmit lost data)
    // First update knownSent with what Phase 1 just yielded
    if (chunks.length > 0) {
      for (var ci = 0; ci < chunks.length; ci++) {
        flat_ranges.add(knownSent, [chunks[ci].offset, chunks[ci].offset + chunks[ci].data.byteLength]);
      }
      missing = flat_ranges.invert(knownSent, 0, totalSize);
    }
    if (used < maxBytes) {
      for (var i = 0; i < missing.length; i += 2) {
        if (used >= maxBytes) break;
        var mFrom = missing[i];
        var mTo = missing[i + 1];

        // Only ranges before send_offset
        if (mFrom >= sendOffset) break;
        var to = Math.min(mTo, sendOffset);

        var len = Math.min(to - mFrom, maxBytes - used);
        if (len <= 0) continue;

        var relStart = mFrom - baseOffset;
        var relEnd = relStart + len;
        if (relStart < 0 || relStart >= data.byteLength) continue;
        if (relEnd > data.byteLength) { relEnd = data.byteLength; len = relEnd - relStart; }
        if (len <= 0) continue;

        // FC fail-safe: retransmits sit below the high-water mark, which was
        // itself capped when first sent, and limits are monotonic — so these
        // clamps should never bind here. Applied anyway so the invariant
        // "nothing ever leaves above streamLimit / beyond the conn budget"
        // holds unconditionally, whatever the scheduler does around us.
        if (mFrom >= streamLimit) continue;
        if (mFrom + len > streamLimit) { len = streamLimit - mFrom; relEnd = relStart + len; }
        var newStart2 = Math.max(mFrom, stream.max_sent_offset);
        var newBytes2 = Math.max(0, (mFrom + len) - newStart2);
        if (newBytes2 > connRemaining) {
          len -= (newBytes2 - connRemaining);
          relEnd = relStart + len;
          newBytes2 = connRemaining;
        }
        if (len <= 0) continue;

        chunks.push({ offset: mFrom, data: data.slice(relStart, relEnd) });
        used += len;

        if (newBytes2 > 0) {
          stream.max_sent_offset = mFrom + len;
          context.max_data_sent += newBytes2;
          connRemaining -= newBytes2;
        }
      }
    }

    // Trim front of pending_data if beginning is fully acked (optimization)
    if (stream.acked_ranges.length >= 2 && stream.acked_ranges[0] === 0 && stream.acked_ranges[1] > baseOffset) {
      var trimTo = stream.acked_ranges[1];
      var trimBytes = trimTo - baseOffset;
      if (trimBytes > 0 && trimBytes < data.byteLength) {
        stream.pending_data = data.slice(trimBytes);
        stream.pending_offset_start = trimTo;
      }
    }

    return chunks;
  }


  // ============================================================
  //  Close
  // ============================================================

  function sendConnectionClose() {
    if (!context.close_frame) return;
    sendFrames('app', [context.close_frame]);
    context.last_close_echo = Date.now();
  }

  function close(errorCode, reason) {
    if (context.state === 'closed' || context.state === 'draining' || context.state === 'closing') return;
    if (context.handshake_timer) { clearTimeout(context.handshake_timer); context.handshake_timer = null; }
    stopCryptoRetx();
    context.close_frame = {
      type: 'connection_close', application: false,
      error: errorCode || 0, frameType: 0, reason: reason || ''
    };
    sendConnectionClose();
    // RFC 9000 §10.2.1: the endpoint that *sends* CONNECTION_CLOSE enters the
    // closing state — it re-echoes the CC (rate-limited) in response to incoming
    // packets, rather than going silent. The peer, which *receives* the CC,
    // enters draining (handled where connection_close frames are processed).
    set_context({ state: 'closing' });
  }


  // ============================================================
  //  Client connect (Phase 7)
  // ============================================================

  function connect() {
    if (context.isServer) return; // server waits for feedPacket, doesn't connect

    // Generate random DCID (8 bytes)
    var dcid = new Uint8Array(8);
    for (var i = 0; i < 8; i++) dcid[i] = Math.floor(Math.random() * 256);

    // Generate random SCID (8 bytes)
    var scid = new Uint8Array(8);
    for (var i = 0; i < 8; i++) scid[i] = Math.floor(Math.random() * 256);

    context.original_dcid = dcid;
    context.my_cids.push(scid);

    // Client initial keys: SWAPPED from server
    // Client writes with "client in" keys (direction='read' in our function)
    // Client reads with "server in" keys (direction='write' in our function)
    set_context({
      initial_write: quic_derive_init_secrets(dcid, context.version, 'read'),
      initial_read: quic_derive_init_secrets(dcid, context.version, 'write')
    });

    // Initialize TLS (client mode)
    if (DEBUG) console.log('[quic] client connecting, dcid=' + Array.from(dcid).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(''));
    initTLS();

    // Trigger ClientHello by feeding empty message
    tls.feedMessage(new Uint8Array(0));
  }


  // ============================================================
  //  Public API
  // ============================================================

  var api = {
    context: context,
    on: function (name, fn) { ev.on(name, fn); },
    off: function (name, fn) { ev.off(name, fn); },
    feedDatagram: feedDatagram,
    feedPackets: feedPackets,
    sendStream: sendStream,
    sendDatagram: sendDatagram,
    maxDatagramSize: maxDatagramSize,
    close: close,
    connect: connect,
    set_context: set_context,
    get state() { return context.state; }
  };

  // Copy api onto `this`. Use descriptors (not `this[k] = api[k]`) so that
  // accessor properties like `get state()` are preserved as live getters
  // instead of being frozen to their construction-time value.
  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) {
      Object.defineProperty(this, k, Object.getOwnPropertyDescriptor(api, k));
    }
  }
  return this;
}

export { QUICConnection };