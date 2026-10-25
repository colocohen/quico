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
  ranges_to_ack_frame,
  mergePriority
} from './utils.js';

import {
  quic_derive_init_secrets,
  quic_derive_from_tls_secrets,
  quic_derive_key_update,
  encrypt_quic_packet,
  decrypt_quic_packet,
  open_retry_packet
} from './crypto.js';

import {
  parse_quic_datagram,
  encode_quic_frames,
  quic_frames_size,
  parse_quic_frames,
  transport_params_error
} from './transport.js';

import { TLSBridge, defaultTransportParams } from './tls_bridge.js';
import { QUIC_V1, QUIC_V2, SUPPORTED_VERSIONS, isSupportedVersion, isCompatible, parseVersionList, versionName } from './quic_version.js';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';

// Random bytes for every packet (the greased QUIC bit, RFC 9287; the skipped
// packet numbers) from a pool, refilled 4 KB at a time from the same secure
// source. randomBytes(1) per packet sent was ~5% of a bulk transfer's CPU —
// an allocation and a system-source call for one bit.
var RANDOM_POOL_SIZE = 4096;
var randomPool = null, randomPoolAt = RANDOM_POOL_SIZE;
function randomByte() {
  if (randomPoolAt >= RANDOM_POOL_SIZE) { randomPool = randomBytes(RANDOM_POOL_SIZE); randomPoolAt = 0; }
  return randomPool[randomPoolAt++];
}

// Congestion-control tracing on its own switch. QUICO_DEBUG enables per-packet
// logging, whose synchronous console.log volume is heavy enough to become the
// bottleneck it is trying to observe (a 2 MB transfer measured 33s with it on,
// 3s with it off). The [bbr] round line fires only once per RTT — cheap — so
// it gets a separate flag that leaves the per-packet spam off.
var DEBUG_BBR = DEBUG ||
  (typeof process !== 'undefined' && process.env && !!process.env.QUICO_DEBUG_BBR);

// Packet-number / ACK tracing on its own switch (QUICO_TRACE_ACK=1): one line
// per packet received (space, packet number) and per ACK frame sent (space,
// the ranges it acknowledges). Enough to see, next to the peer's own log,
// which acknowledgement it rejected — without QUICO_DEBUG's per-frame volume.
var TRACE_ACK = typeof process !== 'undefined' && process.env && !!process.env.QUICO_TRACE_ACK;


// The congestion window a connection starts with, in full-size packets:
// options.initialCongestionWindow, or 20. RFC 9002 §7.2 suggests 10 (12 KB),
// but TCP's window on the same path is larger by the time a response goes
// out: its handshake was a flight of acknowledged segments, and Linux grows
// cwnd on them — a 10-segment TCP window is ~20 when the server starts
// writing. QUIC's handshake ACKs grow ours too (processAckFrame), but they
// acknowledge only the few packets of a handshake; starting at 10 left a 60 KB
// page a round trip behind TCP. 20 packets is where TCP effectively is.
// Checked once by whoever takes the option (createServer, new WebTransport):
// a count in packets, so a value in bytes by mistake (24000) is refused
// rather than taken as a 28 MB burst.
var DEFAULT_INITIAL_CWND_PACKETS = 20;
var MAX_INITIAL_CWND_PACKETS = 100;
// startupCap (see startupCap() in the connection): 'stall' (the default),
// 'always' or 'off'. Checked where it is given — createServer, a client's
// options, a connectionOptions answer, setStartupCap.
var STARTUP_CAP_VALUES = ['stall', 'always', 'off'];
function startupCapOption(v) {
  if (v === undefined || v === null) return 'stall';
  if (STARTUP_CAP_VALUES.indexOf(v) === -1) throw new TypeError("startupCap must be 'stall', 'always' or 'off', got " + v);
  return v;
}

// ============================================================
//  Careful Resume (RFC 9959) — what a returning client's connection starts
//  from, and what it is checked against
// ============================================================
//
// A server that has measured the path to a client keeps the measurement in
// the client's session ticket (lemon-tls setTicketState: encrypted and
// authenticated with the server's ticket keys, so the client carries it but
// can neither read nor forge it). When the client comes back with that
// ticket, the connection may jump to half the capacity measured last time
// (RFC 9959 §4.3) — once the first flight has shown the path is still the
// same — instead of discovering it again round trip by round trip.
//
// Here: the state's format and the checks on it. The phases
// (Reconnaissance, Unvalidated, Validating, Safe Retreat) run in the
// connection, next to the congestion controller they steer (crStart and on).

// How long a measurement may be used (RFC 9959 §4.1, "Lifetime"): no fixed
// value in the RFC — minutes for paths that change, hours for stable ones.
// An hour: a client back within it is very likely on the same network; the
// ticket itself lives longer (sessionTimeout), and the measurement is
// dropped before it.
var LIFETIME_S = 3600;

// Not saved (§3.1: "may skip") when the capacity is under four initial
// windows: the jump, half of it, would hardly exceed what slow start reaches
// in its first round trips anyway.
var MIN_SAVED_IW = 4;

// The remote endpoint (§2.2), as far as a server can tell it: the client's
// network — its IPv4 /24 or IPv6 /48 — not its exact address, which a NAT
// or a privacy address changes between visits of the same device on the
// same network. A laptop moved from home to a café presents the same ticket
// from another network: its measurement does not apply there (§4.2.1,
// "the path is not known to be the same").
function endpointTag(address) {
  if (typeof address !== 'string' || address === '') return null;
  var a = address;
  if (a.indexOf('::ffff:') === 0 && a.indexOf('.') > 0) a = a.slice(7);   // IPv4-mapped
  var prefix;
  if (a.indexOf(':') < 0) {
    var o = a.split('.');
    if (o.length !== 4) return null;
    prefix = o[0] + '.' + o[1] + '.' + o[2];
  } else {
    prefix = expandV6(a).slice(0, 3).join(':');
    if (!prefix) return null;
  }
  // A short hash: the ticket is encrypted anyway; this keeps it small.
  return createHash('sha256').update(prefix).digest('hex').slice(0, 8);
}

function expandV6(a) {
  var pct = a.indexOf('%'); if (pct >= 0) a = a.slice(0, pct);
  var parts = a.split('::');
  var head = parts[0] ? parts[0].split(':') : [];
  var tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  var fill = [];
  for (var i = head.length + tail.length; i < 8; i++) fill.push('0');
  return head.concat(fill, tail).map(function (h) { return (parseInt(h, 16) || 0).toString(16); });
}

// What goes into the ticket: the bottleneck bandwidth (bytes/s) and the
// minimum RTT (ms) — the capacity in use, saved_cwnd = bw × rtt, measured
// from the delivery rate as RFC 9959 Appendix C has it for BBR (a window at
// the end of slow start overshoots; the rate delivered does not) — when, and
// from which network. Null when there is too little to be worth saving.
function savedState(bw, rtt, address, initialWindowBytes, now) {
  if (!(bw > 0) || !(rtt > 0)) return null;
  if (bw * rtt / 1000 < MIN_SAVED_IW * initialWindowBytes) return null;
  return { b: Math.round(bw), r: Math.round(rtt), t: Math.floor(now / 1000), e: endpointTag(address) };
}

// A ticket's state, checked before anything is based on it: well-formed,
// within its lifetime, from the same network, worth a jump. Returns
// { bw, rtt, cwnd } — saved_cwnd in bytes — or null.
function usableState(st, address, initialWindowBytes, now) {
  if (!st || typeof st !== 'object') return null;
  var bw = st.b, rtt = st.r, t = st.t;
  if (!(typeof bw === 'number' && bw > 0 && typeof rtt === 'number' && rtt > 0 && typeof t === 'number')) return null;
  var age = now / 1000 - t;
  if (age < -60 || age > LIFETIME_S) return null;
  if (st.e !== endpointTag(address)) return null;
  var cwnd = bw * rtt / 1000;
  if (cwnd < MIN_SAVED_IW * initialWindowBytes) return null;
  return { bw: bw, rtt: rtt, cwnd: cwnd };
}

// RFC 9959 §4.2.1: the path is taken to have changed if the RTT now is at
// most half the saved one, or more than ten times it.
function sameRtt(current, saved) {
  return current > saved / 2 && current <= saved * 10;
}

// The server's option: off unless true.
function carefulResumeOption(v) {
  if (v === undefined || v === null) return false;
  if (typeof v !== 'boolean') throw new TypeError('carefulResume must be a boolean, got ' + v);
  return v;
}


// ── A connection's options (setOptions) ─────────────────────────────────
//
// The ones a connection is made with, takes from a connectionOptions answer,
// and can be given while it runs (conn.setOptions): each checked here, by
// its name — the same name createServer and a client's options use.
function optError(Ctor, code, msg) { var e = new Ctor(msg); e.code = code; return e; }
function rangeOption(name, lo, hi, unit) {
  return function (v) {
    if (typeof v !== 'number' || !Number.isFinite(v)) throw optError(TypeError, 'ERR_INVALID_ARG_TYPE', name + ' must be a number' + (unit ? ' (' + unit + ')' : '') + ', got ' + v);
    if (v < lo || v > hi) throw optError(RangeError, 'ERR_OUT_OF_RANGE', name + ' must be between ' + lo + ' and ' + hi + (unit ? ' (' + unit + ')' : '') + ', got ' + v);
    return v;
  };
}
// Path MTU discovery is off by default on Windows: Node cannot set the
// Don't Fragment bit there, so a probe may cross fragmented and be taken
// for a fit.
var PMTU_DEFAULT = !(typeof process !== 'undefined' && process.platform === 'win32');
var CONNECTION_OPTIONS = {
  startupCap:              { dflt: 'stall', check: function (v) { return startupCapOption(v); } },
  initialCongestionWindow: { dflt: DEFAULT_INITIAL_CWND_PACKETS, check: function (v) { return initialCongestionWindow(v); } },
  carefulResume:           { dflt: false, check: function (v) { return carefulResumeOption(v); } },
  pmtuDiscovery:           { dflt: PMTU_DEFAULT, check: function (v) {
    if (typeof v !== 'boolean') throw optError(TypeError, 'ERR_INVALID_ARG_TYPE', 'pmtuDiscovery must be a boolean, got ' + v);
    return v; } },
  maxUdpPayloadSize:       { dflt: 1452, check: function (v) { return Math.floor(rangeOption('maxUdpPayloadSize', 1200, 65527, 'bytes')(v)); } },
  initialRtt:              { dflt: 333, check: rangeOption('initialRtt', 10, 10000, 'ms') },
  reorderWindow:           { dflt: 5, check: rangeOption('reorderWindow', 0, 1000, 'ms') }
};
// Checked whole — every key known, every value good — before any is used:
// { name: value } as given (undefined values skipped), normalized. Throws.
function checkConnectionOptions(o, where) {
  if (!o || typeof o !== 'object') throw optError(TypeError, 'ERR_INVALID_ARG_TYPE', (where || 'setOptions') + '() takes an object');
  var out = {};
  for (var k in o) {
    if (o[k] === undefined) continue;
    var spec = CONNECTION_OPTIONS[k];
    if (!spec) throw optError(TypeError, 'ERR_INVALID_ARG_VALUE', k + ' is not an option of a connection');
    out[k] = spec.check(o[k]);
  }
  return out;
}
// The defaults, with what `o` sets over them (unchecked keys ignored).
function connectionOptionDefaults() {
  var d = {};
  for (var k in CONNECTION_OPTIONS) d[k] = CONNECTION_OPTIONS[k].dflt;
  return d;
}

function initialCongestionWindow(value) {
  if (value === undefined || value === null) return DEFAULT_INITIAL_CWND_PACKETS;
  if (typeof value !== 'number' || !Number.isInteger(value))
    throw new TypeError('initialCongestionWindow must be an integer (packets), got ' + value);
  if (value < 2 || value > MAX_INITIAL_CWND_PACKETS)
    throw new RangeError('initialCongestionWindow must be 2..' + MAX_INITIAL_CWND_PACKETS + ' packets, got ' + value);
  return value;
}

function QUICConnection(options) {
  if (!(this instanceof QUICConnection)) return new QUICConnection(options);
  options = options || {};
  // The transport parameters we send — the defaults, and what the
  // application set (options.transportParams; see tls_bridge). Read for our
  // own windows and stream limits below, which have to match them.
  var localTp = defaultTransportParams(options.transportParams);
  // The server's counters (server_stats.js), when its server keeps them.
  var serverStats = options.stats || null;
  // options.idleTimeout, the connection's own option from before the
  // transport parameter could be set: what we advertise follows it — it
  // advertised 30 s whatever it was, and the two sides disagreed on when the
  // connection would end. transportParams.maxIdleTimeout wins where given.
  if (typeof options.idleTimeout === 'number' && options.idleTimeout >= 0 &&
      !(options.transportParams && options.transportParams.maxIdleTimeout != null)) {
    localTp.max_idle_timeout = Math.floor(options.idleTimeout);
  }
  var initCwndPackets = initialCongestionWindow(options.initialCongestionWindow);
  // The connection's options (CONNECTION_OPTIONS): what was given, checked,
  // over the defaults.
  var connOpts = (function () {
    var given = {};
    for (var k in CONNECTION_OPTIONS) if (options[k] !== undefined && options[k] !== null) given[k] = options[k];
    return Object.assign(connectionOptionDefaults(), checkConnectionOptions(given, 'QUICConnection'));
  })();

  var ev = Emitter();
  var tls = null;

  // ============================================================
  //  Context
  // ============================================================

  var context = {
    isServer: options.isServer !== false,
    state: 'idle',
    handshake_done: false,
    // The peer's Finished received and verified — the handshake complete
    // (RFC 9001 §4.1.1). A client has it with its 1-RTT keys (handshake_done);
    // a server only later, at secureConnect: it has its 1-RTT keys, and sends
    // with them (0.5-RTT), as soon as its own Finished is out. Until then a
    // server holds the client's 1-RTT packets unprocessed (§5.7: it "MUST NOT
    // process incoming 1-RTT protected packets before the TLS handshake is
    // complete"), issues no connection IDs and sends no HANDSHAKE_DONE.
    peer_finished: false,
    handshake_done_sent: false,

    // Connection close (RFC 9000 §10.2)
    close_frame: null,         // the CONNECTION_CLOSE frame to (re)send while closing
    peer_close: null,          // { error, application, reason } from the peer's CONNECTION_CLOSE
    last_close_echo: 0,        // timestamp throttle for closing-state CC echoes

    // QUIC version (quic_version.js). `version` is the one packets are sent
    // in — the negotiated version once it is known; `original_version` the
    // one the client's first Initial used. They differ after compatible
    // version negotiation (RFC 9368): the server reads the client's
    // version_information and answers in another version both speak.
    //   quic_versions    client: [first flight's version, then the others it
    //                    accepts]; server: what it accepts, in its preference
    //   version_locked   client: the negotiated version is known (the
    //                    server's ServerHello came in it)
    //   initial_read_original  the original version's Initial read keys,
    //                    kept after a switch: the peer's Initials in it may
    //                    still arrive (RFC 9369 §4)
    version: QUIC_V1,
    original_version: QUIC_V1,
    quic_versions: SUPPORTED_VERSIONS.slice(),
    version_locked: false,
    initial_read_original: null,
    initial_key_cid: null,         // the DCID the Initial keys are derived from
    // grease_quic_bit (RFC 9287): the peer accepts the fixed bit as 0, so
    // ours is sent unpredictable (only once its parameters are in).
    peer_grease_quic_bit: false,

    // Connection IDs (RFC 9000 §5.1).
    //
    // original_dcid — the DCID of the client's first Initial. Initial keys are
    //   derived from it (RFC 9001 §5.2) and the server echoes it as
    //   original_destination_connection_id. That is all it is for.
    // my_cids[0] — the ID this endpoint is addressed by: the SCID of its long
    //   headers, the DCID the peer puts on every packet once it has heard from
    //   us, and what locates the packet number in a short header. A server's
    //   comes from its router (options.localCid), which must know it to route
    //   by it; it is 8 random bytes, which is also what lets its use by the
    //   client validate the client's address (RFC 9000 §8.1). A client's is
    //   drawn in connect().
    // their_cids[0] — the peer's, as it gave it in its long headers.
    original_dcid: null,
    my_cids: options.isServer !== false
      ? [options.localCid || new Uint8Array(randomBytes(8))]
      : [],
    their_cids: [],
    // Connection IDs beyond the first (RFC 9000 §5.1.1, §19.15-16). A peer
    // moving to a new address (connection migration, §9) — a phone from
    // Wi-Fi to cellular — addresses us with another of ours, and we it with
    // another of its, so the two paths cannot be linked by an observer
    // (§9.5). None was issued and those received were ignored: a client had
    // nothing to move with, and could only start a new connection.
    //   local_cids  ours issued: [{ seq, cid, token, retired }]
    //   peer_cids   the peer's: [{ seq, cid, token, retired, inUse }]
    local_cids: [],
    local_cid_next_seq: 1,
    local_cids_issued: 0,
    peer_cids: [],
    // The peer's IDs we have retired whose RETIRE_CONNECTION_ID is not yet
    // acknowledged (seq), bounded (§5.1.2; retireOfPeer).
    peer_cids_retiring: new Set(),
    // The DCID of the packet whose frames are being processed (§19.16).
    rx_dcid: null,
    peer_retire_prior_to: 0,
    peer_active_cid_limit: 2,     // the peer's active_connection_id_limit (default 2, §18.2)

    // The server's stateless reset token (RFC 9000 §10.3), from its transport
    // parameters. A client that receives a datagram ending in it knows the
    // server has lost the connection, and stops at once instead of waiting
    // out the idle timeout. (A server's own token is options.statelessResetToken,
    // handed to TLS to send.)
    peer_reset_token: null,

    // Retry (RFC 9000 §8.1.2, §17.2.5).
    // Server: options.retry — { originalDcid, sourceCid } — when the router
    //   opened this connection from a valid Retry token. The client's first
    //   DCID and the SCID of our Retry, both echoed in the transport
    //   parameters (§7.3); the token proved the client's address.
    // Client: the Retry it accepted (at most one, §17.2.5.2) — its SCID,
    //   addressed until the server's first Initial names another, and the
    //   token every later Initial carries.
    retry_original_dcid: (options.retry && options.retry.originalDcid) || null,
    retry_scid: (options.retry && options.retry.sourceCid) || null,
    retry_token: null,

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
    recv_pn_floor: { initial: 0, handshake: 0, app: 0 },   // below it: treated as seen (see feedPacket)

    // CRYPTO
    // Received, per space (cryptoRx): the bytes in order not yet read as TLS
    // messages, and the pieces that came ahead of a gap.
    crypto_rx: { initial: null, handshake: null, app: null },
    crypto_seen_initial: false,             // an Initial CRYPTO frame has arrived
    peer_initial_scid: null,                // server: the SCID of the client's first Initial
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
    // The handshake's sending (hsFlush): a flush is due at the end of this
    // turn; a PING asked of it (the client's anti-deadlock probe, 'initial'
    // or 'handshake'); the loss timer of ACK-based detection; whether an ACK
    // of one of our Handshake packets has come (RFC 9002 §6.2.2.1).
    hs_flush_pending: false,
    // The flush's last datagram, held to the end of the turn for a 1-RTT
    // packet to ride in it (hsTailTake, finishHsTail).
    hs_tail: null,
    hs_probe: null,
    stats_spurious_early: 0,    // see getStats().spuriousLosses
    // 0-RTT (RFC 9001 §4.6). Client: the key to write early data with, from
    // its ClientHello until the 1-RTT keys or the server's refusal. Server:
    // the key to read it with, once TLS took it; 0-RTT packets that came
    // before it (or before the application is set up), held — a few; the
    // streams early data opened (isEarlyStream). early_status: null (none),
    // 'offered' (a client's, undecided), 'accepted', 'rejected'.
    zero_rtt_write: null,
    zero_rtt_read: null,
    zero_rtt_held: [],
    zero_rtt_processing: false,
    early_streams: new Set(),
    early_status: null,
    peer_reset_stream_at: false,  // the peer takes RESET_STREAM_AT (its transport parameter)
    idle_timed_out: false,        // the idle timeout ended it (closed silently, §10.1)
    reset_at_sent: {},            // stream → { reliable, frameAcked, dataAcked }: RESET_STREAM_AT out
    early_remembered: null,       // a client's: the server's parameters it remembered (0-RTT)
    early_peer_tp: null,          // …and the ones this handshake brought, to compare
    early_app_remembered: null,   // …and the application's (HTTP/3 SETTINGS), as kept
    // A client's: the last packet number its 0-RTT packets used (-1: none) —
    // they share the application space with the 1-RTT ones after them.
    zero_rtt_pn_last: -1,
    confirm_waiters: [],        // whenConfirmed's callbacks
    hs_ended: false,            // 'handshake_ended' emitted (handshakeEnded)
    // 1-RTT loss detection by ACK (appDetectLost) and the tail loss probe
    // (tlp*): the largest packet number acknowledged, and each one's timer
    // with the deadline it is due at (one timer each, moved, not re-made).
    app_largest_acked: -1,
    app_loss_timer: null, app_loss_at: 0,
    tlp_timer: null, tlp_at: 0, tlp_out: false,
    hs_peer_resent: 0,          // §6.2.3 speedups taken (hsPeerResent)
    crypto_loss_timer: null,
    hs_ack_received: false,

    // ACK
    //
    // pending_ack: what has been received, per space — the ranges every ACK
    // frame reports. Kept after an ACK is sent (RFC 9000 §13.2.4 has a
    // receiver repeat ranges until it knows the peer has them), so a lost ACK
    // is made good by the next one; bounded at 32 ranges where it is filled.
    pending_ack: { initial: [], handshake: [], app: [] },
    // ack_state: whether an ACK is owed, per space (see "ACK management").
    //   eliciting       ack-eliciting packets received since our last ACK
    //   immediate       one of them calls for an ACK without delay
    //   largest         largest ack-eliciting packet number received
    //   largest_time    when it arrived (performance.now ms) — for ACK Delay
    ack_state: {
      initial:   { eliciting: 0, immediate: false, largest: -1, largest_time: 0 },
      handshake: { eliciting: 0, immediate: false, largest: -1, largest_time: 0 },
      app:       { eliciting: 0, immediate: false, largest: -1, largest_time: 0 }
    },
    ack_timer: null,            // app space: the max_ack_delay deadline
    // ACK frequency (draft-ietf-quic-ack-frequency): what the peer asked of
    // our ACKs (ACK_FREQUENCY) — and what we asked of its.
    //   ack_freq      ours to follow: { seq, threshold, delay_ms, reorder }
    //   peer_min_ack_delay   µs, from the peer's min_ack_delay: it takes
    //                 ACK_FREQUENCY (null: it does not)
    //   af_sent       the last ACK_FREQUENCY we sent
    ack_freq: { seq: -1, threshold: 1, delay_ms: null, reorder: 1 },
    peer_min_ack_delay: null,
    af_sent: null,
    af_seq: 0,
    ack_decision_pending: false,

    // ── Network paths (RFC 9000 §8, §9) ────────────────────────────────────
    //
    // A path is the peer's address and port as this endpoint sees them, with
    // what is known about it. `path` is where every packet goes. A client
    // never moves it; a server moves it when the peer's packets start coming
    // from somewhere else — the usual cause is a NAT that changed the port it
    // maps the client to (RFC 9000 §9.3). Not following it, the connection
    // went on sending to a port nobody listened on until it idled out.
    //
    //   path            current — see newPath() for the fields
    //   prev_path       the last validated path before it, to return to if the
    //                   new one fails validation (§9.3.2)
    //   candidate_path  an address packets arrived from without (yet) moving
    //                   the connection there: its received bytes are counted,
    //                   so a PATH_RESPONSE to it has a budget
    //
    // Anti-amplification is per path. Until a path is validated, a server
    // "MUST NOT send more
    // than three times as many bytes as the number of bytes they have
    // received", counting "all of the payload bytes received in datagrams
    // that are uniquely attributed to a single connection", discarded ones
    // included. Without it the handshake flight — certificates and all, ~6 KB
    // — goes to whatever address an Initial claims to come from, and the
    // server is a reflector: a spoofed Initial buys the attacker several times
    // its size in traffic aimed at the victim.
    //
    // The first path is validated when a packet from it arrives addressed to
    // our own connection ID, or a Handshake packet from it is processed
    // (§8.1: either proves the peer received our Initial); a later one by
    // PATH_CHALLENGE / PATH_RESPONSE (§8.2). A client validates the server
    // implicitly and is never limited.
    //
    // A packet that does not fit the budget is not dropped but held, in
    // order, and released as the client's next datagrams raise the budget or
    // the path is validated: it is already encrypted and numbered, and some
    // frames (ACKs, control frames) are sent only once.
    // Validated from the start: a client's (it chose the server); a server's
    // whose client proved its address with a Retry token or a NEW_TOKEN one.
    path: newPath(options.remoteAddress || null, options.remotePort || null, options.isServer === false || !!options.retry || !!options.addressValidated),
    // Client: a token from a NEW_TOKEN frame of an earlier connection, for
    // this one's Initial packets (RFC 9000 §8.1.3) — unless a Retry gives one.
    initial_token: options.isServer === false && options.token ? new Uint8Array(options.token) : null,
    prev_path: null,
    candidate_path: null,

    // Packet-number spaces whose keys have been discarded (RFC 9001 §4.9).
    // Once set, the space is closed for good: nothing is sent in it, nothing
    // received in it is processed, and its keys are never derived again.
    discarded: { initial: false, handshake: false },

    // ── Control frames that must arrive (RFC 9000 §13.3) ──────────────────
    //
    // quico retransmitted two things: STREAM data (it stays in send_streams
    // and is re-scanned) and CRYPTO. Every other frame was sent once, and a
    // lost packet lost it for good. §13.3 says otherwise for most of them:
    // HANDSHAKE_DONE "MUST be retransmitted until it is acknowledged";
    // MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS are re-sent, with their
    // CURRENT value, when the packet carrying the latest one is lost;
    // RESET_STREAM and STOP_SENDING until acknowledged. Unmet, a single lost
    // packet could leave a browser blocked on MAX_STREAMS for good, or an
    // upload stalled on a window update that never came.
    //
    // control_queue holds what is due to go out, one entry per key: 'max_data',
    // 'msd:<id>', 'ms_bidi', 'ms_uni', 'hd', 'nt', 'af', 'rs:<id>', 'ss:<id>',
    // 'ncid:<seq>', 'rcid:<seq>', 'crypto:<offset>', 'db', 'sdb:<id>',
    // 'sb_bidi', 'sb_uni' (the BLOCKED signals), 'ping'. A key queued twice goes
    // once, and every frame is built at send time — so what is sent is always
    // the current limit, never a stale one. The frames ride in whatever 1-RTT
    // packet leaves next (takeControlFrames); what no packet takes by the end
    // of the turn goes in packets of the send planner's (flushControl).
    control_queue: {},
    control_flush_pending: false,
    // Set at the end of a turn (flushControl) while frames wait: from then on
    // they are reason enough for the planner to send a packet without data.
    control_due: false,
    control_in_flight: {},      // pn -> { entries: [{ key, stored, frame }], deadline }
    control_timer: null,

    // Streams whose SENDING part is over — completed or reset — with their
    // final size, and streams whose RECEIVING part is over. Bounded (see
    // rememberFinal): they answer "was this stream already finished?" for a
    // stream whose state object is long gone, which a late reset needs.
    send_final: new Map(),      // sid -> final size, or -1 once reset

    // Bytes on the network that nothing will resend: pn -> bytes. A reset
    // stream's data (RFC 9000 §13.3), a stream's that left with bytes still
    // out (releaseStreamInFlight), and DATAGRAM frames (RFC 9221: never
    // retransmitted). Their packets are still in flight all the same, and
    // RFC 9002 counts them until they are acknowledged or lost — DATAGRAM
    // frames too, which are congestion-controlled (RFC 9221 §5.4). Dropping them
    // with the stream did two kinds of harm. Their ACKs credited nothing, so
    // BBR read the bytes as undelivered — forty cancelled uploads and it had
    // measured the path at ~40 KB/s, and the next upload crawled at it. And a
    // lost one stayed in sending_app_pn_in_flight forever, since expiry only
    // found packets through their stream: the packet budget shrank for good.
    no_resend_in_flight: {},
    // Which streams each packet in flight carries: pn → [sid], in the order
    // the packets were sent (a Map keeps insertion order). An ACK, and the
    // expiry timer, visit the streams of the packets in question — not every
    // stream for every packet. With hundreds of streams open on a connection
    // those walks were most of its CPU (an ACK of ten packets on a connection
    // with a thousand streams: ten thousand lookups). An entry can outlive
    // what it points to — a stream reset meanwhile — and is skipped then; it
    // goes when its packet is acknowledged or expires.
    pn_sids: new Map(),
    // What crossed the wire, whole packets: for getStats() (WebTransport's,
    // as the browser reports it — bytes_sent counts STREAM bytes only).
    stats_packets_sent: 0,
    stats_bytes_sent: 0,
    stats_packets_received: 0,
    stats_bytes_received: 0,
    // The application's bytes in them, for WebTransport's getStats() (W3C
    // WebTransportConnectionStats): DATAGRAM payloads sent (new STREAM bytes
    // are max_data_sent), the payload of the packets acknowledged, and the
    // size of the packets declared lost.
    stats_datagram_bytes_sent: 0,
    stats_payload_acked: 0,
    stats_bytes_lost: 0,
    // Streams that hit the peer's flow-control limit since the last check —
    // for STREAM_DATA_BLOCKED (maybeSendBlockedFrames), instead of a walk of
    // every stream on every send pass.
    fc_blocked_sids: new Set(),
    // The 1-RTT packets on the network that the peer has to acknowledge —
    // stream data, DATAGRAM frames, control frames alike: pn → { bytes, t },
    // in the order they were sent. `bytes` is the packet as it went out
    // (header, frames, padding and AEAD tag), what RFC 9002 counts in flight
    // and what an ACK delivers (§7: "bytes_in_flight ... including QUIC
    // framing overhead"). A packet leaves it acknowledged (processAckFrame)
    // or given up on (forgetPacket: the expiry and control timers).
    //
    // Counted by the STREAM bytes they carried, as before, the window held
    // more than it said: a full packet's header and tag are 2-3 % of it, a
    // packet of control frames all of it, and the handshake — a padded
    // Initial, the certificate — grew it by its CRYPTO bytes only. The
    // window, the pacing rate and the bandwidth BBR measures are now one unit.
    pkt_in_flight: new Map(),
    // Their bytes, summed: the planner and BBR ask for it on every pass.
    app_bytes_in_flight: 0,
    send_scheduled: false,             // a send pass is due at the end of this tick — see scheduleSend
    // DATAGRAM frames (RFC 9221) waiting for room in a packet — sendDatagram.
    peer_max_datagram_frame_size: 0,   // its transport parameter; 0: it takes none (§3)
    datagram_queue: [],                // [{ data, t, prio }], oldest first
    datagram_queue_bytes: 0,
    datagrams_dropped: 0,              // left the queue unsent: too old, or crowded out
    // Stream priorities — setStreamPriority, and the scheduler's turns
    // (execute_quic_burst). sid → { urgency, incremental, group, order }.
    stream_priority: {},
    // The scheduler's rotation (execute_quic_burst): per urgency, the rank of
    // whoever opened the last packet; per group, its member that had the last
    // turn. Groups are the application's objects: held weakly, gone with them.
    rr_cursor: new Map(),              // 'u' + urgency → rank
    group_cursor: new WeakMap(),       // group → member rank
    group_rank: new WeakMap(),         // group → its place in a round (after every stream)
    group_rank_next: 1,
    dg_groups: [],                     // urgency + 1 → the group of datagrams sent with no group
    recv_final: new Map(),      // sid -> final size

    // Receiving streams
    recv_streams: {},

    // Sending streams
    send_streams: {},

    // In-flight tracking (Phase 1)
    sending_app_pn_in_flight: new Set(),
    sending_app_pn_history: [],   // [time_sent, encoded_len, delivered_at_send, delivered_time_at_send]
                                  // (encoded_len 0: a number skipped, no packet — skipPacketNumber)
    // 1-RTT packet numbers skipped on purpose, the most recent few, and how
    // many packets until the next skip — see skipPacketNumber.
    skipped_pns: [],
    pn_skip_countdown: nextSkipGap(),
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
    //   current_limit_packet_payload (MTU)        ← DPLPMTUD  (see "Path MTU discovery")
    // The pacing rate starts at its ceiling (init_ = max_); the in-flight
    // window starts at the initial window and the algorithm climbs from there.

    max_packets_per_burst: 20,          // fixed cap — not CC-controlled, no current_/init_

    // packet payload (MTU). current_ is the size actually used; max_ is the ceiling
    // DPLPMTUD must not probe past; init_/floor is QUIC's guaranteed 1200-byte minimum.
    max_limit_packet_payload:     connOpts.maxUdpPayloadSize,   // ceiling, maxUdpPayloadSize: 1452 (IPv6-safe Ethernet: 1500 − 48 hdr) —
                                              // a whole UDP datagram: what DPLPMTUD probes up to
    init_limit_packet_payload:    1200,       // QUIC guaranteed floor — where we start
    current_limit_packet_payload: 1200,       // = init_; DPLPMTUD raises it: the frames a packet
                                              // carries, the datagram it confirmed less its header
    pmtu: null,                               // DPLPMTUD's state (pmtuReset)
    peer_max_udp_payload: 65527,              // its max_udp_payload_size (RFC 9000 §18.2)

    // in-flight window (cwnd) — bytes is the primary signal; packets kept coherent.
    // init_/current_ start at the initial window (initialCongestionWindow, 20
    // packets by default; see above) and BBR-lite climbs from there toward
    // 2·BDP; max_ is the hard ceiling, min_ the floor.
    // The ceiling is the window a long fat path needs: the pacing ceiling
    // below (14 MB/s) × a 450 ms round trip is 6.3 MB. At 300 KB, it was the
    // limit on every path longer than ~20 ms at that rate — a 4 MB file over
    // 450 ms took 8.6 s instead of 5.8. What it costs is memory only where the
    // path needs it: the window is reached only when BBR measured that BDP.
    max_limit_packets_in_flight:     6990,    // ceiling ≈ 8 MB at 1200 B/pkt
    min_limit_packets_in_flight:     2,       // floor (RFC 9002 min cwnd)
    init_limit_packets_in_flight:    initCwndPackets,
    current_limit_packets_in_flight: initCwndPackets,  // = init_; BBR rewrites at round-end
    max_limit_bytes_in_flight:       8388000, // ceiling ~8 MB — coherent with packets ↑
    min_limit_bytes_in_flight:       2400,    // floor ~2 packets
    init_limit_bytes_in_flight:      initCwndPackets * 1200,
    current_limit_bytes_in_flight:   initCwndPackets * 1200,  // = init_; BBR rewrites at round-end

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
    pacing_pkt_tokens: 0,       // …and in packets (current_limit_packets_per_sec)
    pacing_last_refill: Date.now(),

    // The client's 1-RTT packets that arrived before its Finished (peer_finished)
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
    local_max_data: localTp.initial_max_data,          // ADVERTISED conn limit (starts = window, from transport params)
    local_max_data_window: localTp.initial_max_data,   // W — starts at initial_max_data; grows (autotuning, see slideConnWindow)
    local_max_data_at: 0,             // when the connection window was last slid (ms)
    local_max_data_consumed: 0,       // in-order bytes delivered to the app (all streams)
    fc_recv_usage: 0,                 // Σ per-stream max_recv_offset — the peer's usage

    //
    // Flow control — stream level (RFC 9000 §4.1): each stream's window
    // starts at the initial_max_stream_data_* we sent for its kind
    // (localStreamWindow) and grows as the connection window does.

    remote_max_streams_bidi: 100,
    remote_max_streams_uni: 3,

    // ── Our own stream limits, and raising them (RFC 9000 §4.6) ──────────
    //
    // initial_max_streams_* limits the CUMULATIVE number of streams the peer
    // may open — not how many may be open at once. An endpoint keeps the peer
    // supplied by sending MAX_STREAMS as streams close. quico never did: the
    // limit stayed at the 100 in its transport parameters for the life of the
    // connection, so the 101st request on one connection could not be opened
    // at all. Chrome sent STREAMS_BLOCKED, waited, heard nothing — there was
    // nothing left to send — and closed the connection as a "network
    // blackhole"; the requests caught in it failed with "Failed to fetch".
    // Any long-lived tab, or a page with enough resources, gets there.
    local_max_streams_bidi: localTp.initial_max_streams_bidi,
    local_max_streams_uni: localTp.initial_max_streams_uni,
    peer_streams_closed_bidi: 0,
    peer_streams_closed_uni: 0,

    // ── Stream ID bookkeeping (RFC 9000 §2.1, §3.2, §4.6) ─────────────────
    // Highest stream index (sid / 4) opened so far, per initiator and type.
    // Opening a stream opens every lower-numbered stream of its type, so an
    // ID at or below the mark that is not in recv_open was opened and has
    // since finished receiving — it is closed, however long ago that was.
    // recv_final only remembers the last FINAL_MEMORY streams; a check that
    // relied on it let a peer reopen a stream ID once it had been forgotten.
    peer_max_opened_bidi: -1,
    peer_max_opened_uni: -1,
    local_max_opened_bidi: -1,
    local_max_opened_uni: -1,
    // Streams whose receiving part is open: every peer-initiated stream up to
    // the mark (including ones opened implicitly that have seen no data yet)
    // and every bidirectional stream we opened, until its FIN is delivered or
    // it is reset. Bounded by the stream limits: at most the streams the peer
    // may have open at once, plus our own.
    recv_open: new Set(),
    stream_sides_done: {},          // sid -> { recv, send } for peer-initiated streams
    max_streams_flush_pending: false,

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

    // Expired-but-unacknowledged packets ("limbo"). When expireInFlight times a
    // packet out, its stream spans are parked here instead of being forgotten.
    // If the ACK then arrives late — which on a queued path it regularly does,
    // since the expiry timer races the ACK's arrival — the spans are credited
    // to `delivered` and marked acked, cancelling any not-yet-sent retransmit.
    //
    // Without this, a spuriously-expired packet's bytes vanish from delivery
    // accounting forever: the ACK finds nothing to credit, BtlBw (computed
    // from `delivered`) reads a collapsing rate, the pacer follows it down,
    // and the sender relaxes the queue until ACKs beat the timer again — a
    // relaxation oscillator, measured against quic-go through the interop
    // simulator as a 114/4-packets-per-second sawtooth and ~21× duplication.
    //   pn → { t: expiry wall-time, spans: [[sid, ranges, finLost], ...] }
    //   (ranges: the packet's flat range list of that stream)
    expired_unacked: {},
    limbo_n: 0,                     // entries in expired_unacked (kept, not counted)
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
    // Whether the sender ran out of data during the current round while it
    // still had congestion window to spare. A delivery rate measured over such
    // a round says how much the APPLICATION produced, not what the path can
    // carry — see the sample filter at round end.
    bbr_round_app_limited: false,
    bbr_full_bw: 0,             // highest BtlBw seen — Startup plateau detector
    bbr_full_bw_count: 0,       // consecutive rounds without ≥25% BtlBw growth
    // ACK aggregation (BBR's extra_acked): how far ACKs ran ahead of what
    // BtlBw explains, at most, over the last 10 rounds — room the window
    // keeps over its BDP-based cap so a burst of late ACKs (Wi-Fi delivers
    // them in batches) does not stall the sender. The interval under way,
    // and the per-round maxima.
    bbr_ea_start: 0, bbr_ea_delivered: 0, bbr_ea_round_max: 0, bbr_ea_rounds: [],
    bbr_extra_acked: 0,
    // The lowest RTT of the current round (ACK delay taken out) and how many
    // samples it is of: a queue building at the bottleneck shows here before
    // anything is dropped (Startup's delay exit, at round end).
    bbr_round_min_rtt: null,
    bbr_round_rtt_samples: 0,
    bbr_cycle_idx: 0,           // ProbeBW pacing-gain cycle position (0..7)

    // Careful Resume (RFC 9959; savedState, usableState above). Server only, off unless
    // options.carefulResume is true: measured on returning page loads it
    // gave almost nothing on clean paths and, with random loss (Safe
    // Retreat taking it for congestion), cost a lot (README). `cr` is a resumed connection's progress
    // through the phases — null when it has nothing to resume from;
    // cr_saved_* is what this connection last put in a ticket.
    careful_resume: options.isServer !== false && connOpts.carefulResume,
    // Startup's cap on the window (startupCap): 'stall', 'always' or 'off'.
    startup_cap: connOpts.startupCap,
    // The RTT assumed before there is a sample (RFC 9002's kInitialRtt):
    // the handshake's timers, a new path's.
    initial_rtt: connOpts.initialRtt,
    // The least time a packet is let arrive late, out of order, before a
    // later one's ACK gives it up (appLossThreshold).
    reorder_window: connOpts.reorderWindow,
    // Path MTU discovery on (pmtuProbeSize); off, packets stay where they are.
    pmtu_discovery: connOpts.pmtuDiscovery,
    cr: null,
    cr_saved_at: 0,
    cr_saved_bw: 0,
    cr_tickets: 0,

    // Timers
    // The idle timeout in force (RFC 9000 §10.1): ours until the peer's
    // parameters arrive, then the smaller of the two non-zero ones (0: none).
    idle_timeout: localTp.max_idle_timeout,
    peer_idle_timeout: null,          // the peer's max_idle_timeout, once known
    handshake_timeout: options.handshakeTimeout || (options.tlsOptions && options.tlsOptions.handshakeTimeout) || 10000,
    last_activity: Date.now(),
    // The idle timer's clock (RFC 9000 §10.1), separate from last_activity
    // (keep-alive), which also moves on our own sends. Restarted only by a
    // packet from the peer, or by our first ack-eliciting packet after one.
    last_peer_activity: Date.now(),
    ack_eliciting_sent_since_rx: false,
    // Time of the most recent ACK received from the peer (set only in
    // processAckFrame). Drives the in-flight-expiry backoff: while the peer
    // isn't ACKing us, the retransmit timeout widens so we don't flood a dead
    // path. Distinct from last_activity (which also bumps on send/receive).
    last_ack_time: Date.now(),
    // When the current stretch without an ACK began, for that backoff: the
    // first ack-eliciting packet sent after the last ACK (backoff_mark: the
    // last_ack_time it followed). Counted from the ACK alone, a connection
    // idle for a while started its next send already "backed off" by the
    // idle time — a packet lost then waited about as long again, or longer,
    // before it was resent.
    backoff_since: Date.now(),
    backoff_mark: 0,
    idle_timer: null,
    handshake_timer: null,

    // Keep-alive: when > 0, send a PING after this many ms of inactivity to
    // keep the connection from idling out (RFC 9000 §10.1.2). Should be < the
    // idle timeout. options.keepAlive: true → idle_timeout/2; a number → ms.
    keep_alive_interval: 0,           // set by applyIdleTimeout
    keep_alive_timer: null,

    SNICallback: options.SNICallback || null,
    hostname: options.hostname || null,
    // Client-side peer certificate verification. Defaults to true (node:tls
    // semantics); set false for self-signed certs, private CAs, or interop.
    rejectUnauthorized: options.rejectUnauthorized !== false,
    ca: options.ca || null,

    // Server: session tickets — the server's keys, shared by its connections,
    // and the application's ticketData (see tls_bridge).
    ticketKeys: options.ticketKeys || null,
    ticketData: typeof options.ticketData === 'function' ? options.ticketData : null,
    // Encrypted Client Hello (see tls_bridge): server — its keys; client —
    // the server's ECHConfigList.
    ech: options.ech || null,
    // Server: OCSP stapling, (certificate, issuer, callback) (see tls_bridge).
    ocspRequest: typeof options.ocspRequest === 'function' ? options.ocspRequest : null,
    // Server: its TLS options, read once by quic_server (tls_options.js).
    tlsOptions: options.tlsOptions || null,

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

    // Closing, draining and closed are the end: nothing brings a connection
    // back from them. A close() from inside TLS's processing — transport
    // parameters refused at EncryptedExtensions — was undone by the
    // Finished in the same flight ('connected' set right after), and the
    // connection went on as if it had never been closed.
    if ('state' in updates && updates.state !== context.state &&
        !((context.state === 'closing' || context.state === 'draining' || context.state === 'closed') &&
          updates.state !== 'closing' && updates.state !== 'draining' && updates.state !== 'closed')) {
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
    if ('peer_finished' in updates && updates.peer_finished !== context.peer_finished) {
      context.peer_finished = updates.peer_finished;
      changed.peer_finished = true;
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
    // The peer's current ID replaced (its old one retired, §5.1.2).
    if ('their_cid_replace' in updates && updates.their_cid_replace) {
      context.their_cids[0] = updates.their_cid_replace;
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
    // MAX_STREAMS only ever raises the limit (RFC 9000 §19.11: a lower value
    // is ignored). A raise may release streams held back by it.
    if ('remote_max_streams_bidi' in updates && updates.remote_max_streams_bidi > context.remote_max_streams_bidi) {
      context.remote_max_streams_bidi = updates.remote_max_streams_bidi; changed.remote_max_streams = true;
    }
    if ('remote_max_streams_uni' in updates && updates.remote_max_streams_uni > context.remote_max_streams_uni) {
      context.remote_max_streams_uni = updates.remote_max_streams_uni; changed.remote_max_streams = true;
    }
    if ('key_phase' in updates && updates.key_phase !== context.key_phase) {
      context.key_phase = updates.key_phase; changed.key_phase = true;
    }

    // ---- Reactive ----

    if (changed.initial_read || changed.initial_write) {
      if (context.state === 'idle') { context.state = 'handshaking'; changed.state = true; }
    }

    if (changed.handshake_done && context.handshake_done === true) {
      if (DEBUG) console.log('[quic] handshake done (1-RTT keys)');
      applyIdleTimeout();
      startIdleTimer();
      startKeepAliveTimer();
    }

    if (changed.peer_finished && context.peer_finished === true) {
      if (DEBUG) console.log('[quic] peer Finished verified — processing ' + context.pending_app_packets.length + ' held 1-RTT packets');
      if (context.pending_app_packets.length > 0) {
        var pending = context.pending_app_packets;
        context.pending_app_packets = [];
        for (var i = 0; i < pending.length; i++) {
          processDecryptedPacket('app', pending[i].packet_number, parse_quic_frames(pending[i].plaintext), context.path);
        }
      }
      issueConnectionIds();
    }

    if (changed.state && context.state === 'connected') {
      // 'connect' event is emitted explicitly by TLS handlers (not here)
      // Server emits on appSecrets, Client emits on secureConnect
    }

    // A handshake that will not complete has ended too (handshakeEnded).
    if (changed.state && (context.state === 'draining' || context.state === 'closing' || context.state === 'closed')) handshakeEnded(false);

    if (changed.state && (context.state === 'draining' || context.state === 'closing')) {
      // 'closing': the connection is over for the application now — the
      // peer's CONNECTION_CLOSE came (draining), or ours went (closing).
      // 'close' follows when the closing or draining period ends (RFC 9000
      // §10.2: up to three PTOs, here at most 3 s), which is packet
      // housekeeping, not news: a session above that waited for 'close'
      // learned the peer was gone seconds late. With the peer's code and
      // reason (context.peer_close) when it was the peer; null when we
      // closed. Once.
      if (!context.closing_emitted) {
        context.closing_emitted = true;
        ev.emit('closing', context.state === 'draining' ? (context.peer_close || null) : null);
      }
      failPermitWaiters();
      clearIdleTimer();
      // A draining/closing endpoint must stop retransmitting CRYPTO — the
      // ticker would otherwise keep resending the handshake flight at a peer
      // that already told us the connection is dead (seen live: three Initial
      // retransmits fired after a CONNECTION_CLOSE was processed).
      stopCryptoRetx();
      stopControlRetx();
      stopAckTimer();
      stopPathValidation(context.path);
      stopPathValidation(context.prev_path);
      var _drainTimer = setTimeout(function () {
        if (context.state === 'draining' || context.state === 'closing') { context.state = 'closed'; ev.emit('close'); releaseSentWaits(); failPermitWaiters(); }
      }, context.idle_timeout > 0 ? Math.min(3000, context.idle_timeout / 3) : 3000);
      if (_drainTimer.unref) _drainTimer.unref();
    }

    if (changed.state && context.state === 'closed') {
      if (context.handshake_timer) { clearTimeout(context.handshake_timer); context.handshake_timer = null; }
      clearIdleTimer(); ev.emit('close'); releaseSentWaits(); failPermitWaiters();
    }
    if (changed.remote_max_data) { plan_quic_burst(); }
    if (changed.remote_max_streams) { releasePermitWaiters(); plan_quic_burst(); }
    if (changed.key_phase) {
      // We initiated key update — derive new write keys
      if (context.app_write_secret) {
        var next = quic_derive_key_update(context.app_write_secret, context.cipher_hash, context.cipher_suite, context.version);
        if (DEBUG) console.log('[quic] key update initiated — new write keys');
        context.app_write = { key: next.key, iv: next.iv, hp: context.app_write.hp, aead: next.aead };
        context.app_write_secret = next.secret;
      }
    }
  }


  // ============================================================
  //  Idle timeout
  // ============================================================

  function touchActivity() { context.last_activity = Date.now(); }

  // RFC 9000 §10.1: the idle timer restarts when a packet is received from
  // the peer, and when we send the first ack-eliciting packet after that —
  // never on our sends alone. Counting every send (as last_activity does)
  // kept a connection alive forever while we streamed to a peer that was
  // gone: nothing came back, but every packet we sent reset the clock.
  function peerPacketReceived() {
    var now = Date.now();
    context.last_activity = now;
    context.last_peer_activity = now;
    context.ack_eliciting_sent_since_rx = false;
  }

  function ackElicitingSent() {
    if (context.ack_eliciting_sent_since_rx) return;
    context.ack_eliciting_sent_since_rx = true;
    context.last_peer_activity = Date.now();
  }

  // The idle timeout in force, and the keep-alive that follows from it.
  // RFC 9000 §10.1: "the effective value at an endpoint is computed as the
  // minimum of the two advertised values (or the sole advertised value, if
  // only one endpoint advertises a non-zero value)". QUICO advertised 30 s
  // whatever it was set to, and ignored the peer's: a client that announced
  // 10 s had its connection kept for 30 by us, and one that allowed 60 lost
  // it at 30 with nothing on the wire saying why. options.keepAlive: true
  // pings at half of it — of the effective one, or the PING comes after the
  // peer has already let the connection go.
  function applyIdleTimeout() {
    var ours = localTp.max_idle_timeout || 0, theirs = context.peer_idle_timeout || 0;
    context.idle_timeout = (ours > 0 && theirs > 0) ? Math.min(ours, theirs) : (ours || theirs);
    var k = options.keepAlive, interval = 0;
    if (k === true) interval = context.idle_timeout > 0 ? Math.max(100, Math.floor(context.idle_timeout / 2)) : 0;
    else if (typeof k === 'number' && k > 0) interval = k;
    if (interval !== context.keep_alive_interval) {
      context.keep_alive_interval = interval;
      if (context.keep_alive_timer !== null) { clearInterval(context.keep_alive_timer); context.keep_alive_timer = null; startKeepAliveTimer(); }
    }
    // Running already: restarted on the new value — and the keep-alive with
    // it, which clearIdleTimer stops along with the idle timer.
    if (context.idle_timer !== null) { startIdleTimer(); startKeepAliveTimer(); }
  }

  function startIdleTimer() {
    clearIdleTimer();
    if (context.idle_timeout <= 0) return;
    context.idle_timer = setInterval(function () {
      // §10.1: "at least three times the current Probe Timeout" — a timeout
      // shorter than the path's round trips would close a live connection.
      if (Date.now() - context.last_peer_activity >= Math.max(context.idle_timeout, 3 * ptoBase())) {
        if (DEBUG) console.log('[quic] idle timeout');
        // RFC 9000 §10.1: "the connection is silently closed and its state is
        // discarded" — no CONNECTION_CLOSE: a peer that has gone would never
        // read it, one that has not runs the same timer (the smaller of the
        // two timeouts is both sides'). It was sent, a packet to an address
        // that may by now be someone else's. Through draining (its timers
        // stopped), at once to closed: 'close'.
        context.idle_timed_out = true;
        set_context({ state: 'draining' });
        set_context({ state: 'closed' });
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
        // Through the control queue, as every ack-eliciting 1-RTT frame:
        // paced, and sent again if the packet carrying it is lost.
        queueControl('ping', { type: 'ping' });
      }
      // Looked at twice per interval: once per interval, a check that fell
      // just short of it put the PING a whole interval later — 2 s of silence
      // under a 1.5 s idle timeout, and the peer closed.
    }, Math.max(50, Math.floor(context.keep_alive_interval / 2)));
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

  // The handshake must finish within handshake_timeout — counted from the
  // connection's first packet, not from the first TLS byte. It was started
  // with TLS, so a server connection opened by an Initial carrying no
  // ClientHello (a PING, padding, a CRYPTO frame at a later offset) had no
  // clock at all and held its place for good: twenty such datagrams, from
  // any spoofed address, filled a server with maxConnections 20 and kept
  // every real client out (QUICtester's Initial-without-CRYPTO flood).
  // A connection whose handshake never began is dropped without a word —
  // there is no one to tell, the address being unproven.
  function startHandshakeTimer() {
    if (!(context.handshake_timeout > 0) || context.handshake_timer) return;
    context.handshake_timer = setTimeout(function () {
      context.handshake_timer = null;
      if (context.state === 'closed' || context.state === 'draining' || context.state === 'closing') return;
      // Complete: a client's with its Finished made, a server's with the
      // client's Finished verified (state 'connected' comes earlier there,
      // when the server's own Finished goes).
      if (context.isServer ? context.peer_finished : context.state === 'connected') return;
      if (DEBUG) console.log('[quic] handshake timeout (' + context.handshake_timeout + 'ms)');
      if (!tls) { set_context({ state: 'closed' }); return; }
      ev.emit('error', new Error('QUIC handshake timeout'));
      close(0x100, 'handshake timeout');  // 0x100 = CRYPTO_ERROR
    }, context.handshake_timeout);
    if (context.handshake_timer.unref) context.handshake_timer.unref();
  }

  // The handshake is over — complete (the client's Finished verified, at a
  // server), or not to be (the connection closing first): 'handshake_ended'
  // (confirmed), once. For the server's count of handshakes under way
  // (quic_server): one that failed stops counting at once, not when its
  // connection's drain ends.
  function handshakeEnded(confirmed) {
    if (context.hs_ended) return;
    context.hs_ended = true;
    ev.emit('handshake_ended', confirmed);
  }

  function stopHandshakeTimer() {
    if (context.handshake_timer) { clearTimeout(context.handshake_timer); context.handshake_timer = null; }
  }

  // ── connectionOptions: this connection's settings, asked per connection ──
  //
  // Server, options.connectionOptions(info, callback): asked once the
  // ClientHello is in — its server name known, and whether it resumed and
  // with what (savedState) — and before anything is answered: the
  // handshake waits for it as it waits for an asynchronous SNICallback,
  // whose turn it takes first. What it answers sets this connection's
  // initialCongestionWindow, transportParams (over the server's: they go
  // out in this very handshake) and carefulResume.
  //
  // It cannot hold a handshake hostage: unanswered after
  // CONNECTION_OPTIONS_TIMEOUT_MS, an error, a throw, or an answer that does
  // not check out — the server's settings, and a process warning saying why
  // (an answer silently ignored would be a configuration bug nobody sees).
  var CONNECTION_OPTIONS_TIMEOUT_MS = 1000;
  var connectionOptionsAsked = false;
  function askConnectionOptions(servername, done) {
    if (connectionOptionsAsked) { done(); return; }   // a second ClientHello (HelloRetryRequest)
    connectionOptionsAsked = true;
    var finished = false;
    var timer = setTimeout(function () {
      warnConnectionOptions('no answer within ' + CONNECTION_OPTIONS_TIMEOUT_MS + ' ms');
      finish(null);
    }, CONNECTION_OPTIONS_TIMEOUT_MS);
    if (timer.unref) timer.unref();
    function finish(opts) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (opts && context.state !== 'closed' && context.state !== 'draining') applyConnectionOptions(opts);
      done();
    }
    var ticket = tls.getTicketInfo();
    var prev = ticket && ticket.resumed && ticket.state
      ? usableState(ticket.state, peerPath().address, context.init_limit_bytes_in_flight, Date.now()) : null;
    var info = {
      remoteAddress: peerPath().address,
      remotePort: peerPath().port,
      servername: servername || null,
      resumed: !!(ticket && ticket.resumed),
      // What the last connection from this client's network measured, within
      // its lifetime: what Careful Resume would start from. Null otherwise.
      previous: prev ? { rtt: prev.rtt, bandwidth: Math.round(prev.bw * 8), age: Math.max(0, Math.round(Date.now() / 1000 - ticket.state.t)) } : null
    };
    try {
      options.connectionOptions(info, function (err, opts) {
        if (err) warnConnectionOptions('callback error: ' + (err && err.message || err));
        finish(err ? null : opts);
      });
    } catch (e) {
      warnConnectionOptions('threw: ' + (e && e.message || e));
      finish(null);
    }
  }
  function warnConnectionOptions(why) {
    if (typeof process !== 'undefined' && process.emitWarning) {
      process.emitWarning('connectionOptions: ' + why + ' — the server\'s settings are used for this connection', { code: 'QUICO_CONNECTION_OPTIONS' });
    }
  }
  // Checked whole before any of it is taken: half an answer applied is a
  // connection nobody configured.
  function applyConnectionOptions(opts) {
    if (!opts || typeof opts !== 'object') { warnConnectionOptions('the answer is not an object'); return; }
    var tp, rest = {};
    for (var k in opts) if (k !== 'transportParams') rest[k] = opts[k];
    try {
      if (opts.transportParams !== undefined) tp = defaultTransportParams(Object.assign({}, options.transportParams || {}, opts.transportParams));
      rest = checkConnectionOptions(rest, 'connectionOptions');
      checkOptionTiming(rest);
    } catch (e) {
      warnConnectionOptions(e.message);
      return;
    }
    if (tp && !tls.updateTransportParams(tp)) { warnConnectionOptions('transportParams came after the ServerHello'); tp = undefined; }
    applyOptions(rest);
    if (tp) {
      // Our own limits follow what we advertise: the connection window, the
      // stream counts, and each stream's window (localStreamWindow).
      localTp = tp;
      // 0-RTT only under the parameters this connection advertises (RFC 9000
      // §7.4.1: a server that accepts it must not lower what the client remembered).
      if (tls.setEarlyDataContext) tls.setEarlyDataContext(earlyDataContext());
      applyIdleTimeout();
      context.local_max_data = context.local_max_data_window = tp.initial_max_data;
      context.local_max_streams_bidi = tp.initial_max_streams_bidi;
      context.local_max_streams_uni = tp.initial_max_streams_uni;
    }
  }

  // ── conn.setOptions / getOptions ────────────────────────────────────────
  //
  // This connection's options (CONNECTION_OPTIONS), while it runs. All
  // checked before any is applied — the values, and whether it is still
  // the time for each: initialRtt only before the first RTT sample (it is
  // what is assumed without one), initialCongestionWindow only before the
  // first 1-RTT packet, carefulResume only before the handshake is
  // confirmed (when it starts). Past that the call throws rather than take
  // a value that would do nothing. The others apply from now on.
  function stateError(msg) { var e = new Error(msg); e.code = 'ERR_INVALID_STATE'; return e; }
  function checkOptionTiming(o) {
    if ('initialRtt' in o && context.srtt !== null) throw stateError('initialRtt applies only before the first RTT sample');
    if ('initialCongestionWindow' in o && context.send_pn.app > 0) throw stateError('initialCongestionWindow applies only before the first 1-RTT packet');
    if ('carefulResume' in o && handshakeConfirmed()) throw stateError('carefulResume applies only before the handshake is confirmed');
  }
  function setOptions(o) {
    if (o && typeof o === 'object') {
      for (var k in o) {
        if (k === 'transportParams') throw optError(TypeError, 'ERR_INVALID_ARG_VALUE', 'transportParams go out in the handshake: set them in connectionOptions, or on the server');
        if (k === 'validateAddress' || k === 'handshakeLoadThreshold' || k === 'maxHandshakesPerAddress')
          throw optError(TypeError, 'ERR_INVALID_ARG_VALUE', k + ' is an option of the server, not of a connection: server.setOptions()');
      }
    }
    var n = checkConnectionOptions(o, 'setOptions');
    checkOptionTiming(n);
    applyOptions(n);
  }
  function applyOptions(n) {
    if ('startupCap' in n) context.startup_cap = n.startupCap;
    if ('reorderWindow' in n) { context.reorder_window = n.reorderWindow; if (context.app_loss_at) appDetectLost(); }
    if ('initialRtt' in n) context.initial_rtt = n.initialRtt;
    if ('carefulResume' in n) context.careful_resume = context.isServer && n.carefulResume;
    if ('initialCongestionWindow' in n) {
      context.init_limit_packets_in_flight = context.current_limit_packets_in_flight = n.initialCongestionWindow;
      context.init_limit_bytes_in_flight = context.current_limit_bytes_in_flight = n.initialCongestionWindow * 1200;
    }
    if ('maxUdpPayloadSize' in n) setMaxUdpPayload(n.maxUdpPayloadSize);
    if ('pmtuDiscovery' in n) {
      var was = context.pmtu_discovery;
      context.pmtu_discovery = n.pmtuDiscovery;
      // On: the search starts (or goes on) — off, a probe out is let go and
      // the size found stays.
      if (n.pmtuDiscovery && !was && handshakeConfirmed()) { if (context.pmtu) { context.pmtu.nextAt = 0; context.pmtu.size = 0; context.pmtu.tries = 0; } scheduleSend(); }
      if (!n.pmtuDiscovery && context.pmtu) context.pmtu.probe = null;
    }
  }
  // The largest UDP payload sent. Lower than the packets now: they shrink
  // at once (a size under one already confirmed is confirmed too). Higher:
  // the search may go there.
  function setMaxUdpPayload(v) {
    context.max_limit_packet_payload = v;
    var now = context.current_limit_packet_payload + shortHeaderOverhead();
    var m = context.pmtu;
    if (now > v) pmtuApply(v);
    if (m) {
      if (m.lo > v) m.lo = v;
      if (m.size > v) { m.size = 0; m.tries = 0; }
      if (m.fail && m.fail > v) m.fail = 0;
      if (now < v && m.nextAt > Date.now() + 1000) m.nextAt = 0;   // done searching: again, toward the new ceiling
    }
  }
  function getOptions() {
    return {
      startupCap: context.startup_cap,
      initialCongestionWindow: context.init_limit_packets_in_flight,
      carefulResume: context.careful_resume,
      pmtuDiscovery: context.pmtu_discovery,
      maxUdpPayloadSize: context.max_limit_packet_payload,
      initialRtt: context.initial_rtt,
      reorderWindow: context.reorder_window
    };
  }

  // ============================================================
  //  QUIC versions (quic_version.js; RFC 9368, RFC 9369)
  // ============================================================

  // The version the connection starts in and what it accepts. Server: the
  // version of the client's first Initial (options.version, from
  // quic_server) and its own list. Client: the first of quicVersions, or
  // options.version.
  (function initVersions() {
    var list = parseVersionList(options.quicVersions, 'quicVersions') || SUPPORTED_VERSIONS.slice();
    context.quic_versions = list;
    // options.version: the server's, the client's first Initial; a client's,
    // the version to start in after a Version Negotiation (quic_socket).
    var v = (options.version >>> 0) || list[0];
    if (!isSupportedVersion(v)) throw new Error('QUIC version 0x' + (v >>> 0).toString(16) + ' is not supported');
    context.version = context.original_version = v;
  })();

  // What a version's tickets are issued and accepted under (RFC 9369 §5):
  // none for v1, as tickets have always been; the version's name otherwise.
  function versionTicketContext(v) {
    return v === QUIC_V1 ? '' : 'quic-' + versionName(v);
  }

  // From now on packets go in `v`, under its Initial keys — derived from the
  // same connection ID, with its salt (RFC 9369 §4). The original version's
  // read keys stay: the peer's Initials in it may still come.
  function switchVersion(v) {
    if (v === context.version) return;
    if (DEBUG) console.log('[quic] version ' + versionName(context.version) + ' → ' + versionName(v));
    var cid = context.initial_key_cid || context.original_dcid;
    context.initial_read_original = context.initial_read;
    context.version = v;
    if (cid && !context.discarded.initial) {
      var clientKeys = quic_derive_init_secrets(cid, v, 'read');
      var serverKeys = quic_derive_init_secrets(cid, v, 'write');
      set_context(context.isServer ? { initial_read: clientKeys, initial_write: serverKeys }
                                   : { initial_read: serverKeys, initial_write: clientKeys });
    }
    if (context.isServer && tls) tls.setTicketContext(versionTicketContext(v));
    ev.emit('version', v);
  }

  // The peer's version_information (RFC 9368 §4). Returns false once the
  // connection is closed over it.
  //
  // Server: the client's Chosen Version must be the version its Initial
  // came in; the version used is the first of ours the client lists that its
  // first flight can be read as (compatible negotiation, no round trip).
  // Client: the server's Chosen Version must be the one its packets came in
  // — a switch nobody asked for, or one the server denies, is a downgrade
  // attempt: VERSION_NEGOTIATION_ERROR (0x11).
  function negotiateVersion(vi) {
    if (vi === 'invalid') { close(0x08, 'malformed version_information'); return false; }
    if (context.isServer) {
      if (!vi) return true;   // a client that does not negotiate: its version stands
      if (vi.chosen !== context.original_version) {
        close(0x11, 'version_information names ' + versionName(vi.chosen) + ', the Initial was ' + versionName(context.original_version));
        return false;
      }
      for (var i = 0; i < context.quic_versions.length; i++) {
        var v = context.quic_versions[i];
        if ((vi.available.indexOf(v) >= 0 || v === vi.chosen) && isCompatible(context.original_version, v)) {
          switchVersion(v);
          break;
        }
      }
      return true;
    }
    context.version_locked = true;
    // After a Version Negotiation (options.versionNegotiation: the versions
    // it offered), the server must say what it supports, and that must lead
    // to the version this attempt is in — or the Version Negotiation was not
    // the server's (RFC 9368 §4).
    var afterVn = Array.isArray(options.versionNegotiation);
    if (!vi) {
      if (afterVn) { close(0x11, 'no version_information after Version Negotiation'); return false; }
      if (context.version !== context.original_version) { close(0x11, 'the server switched version without version_information'); return false; }
      return true;
    }
    if (vi.chosen !== context.version) {
      close(0x11, 'the server chose ' + versionName(vi.chosen) + ', its packets are ' + versionName(context.version));
      return false;
    }
    if (afterVn) {
      var theirs = vi.available.concat([vi.chosen]), pick = null;
      for (var j = 0; j < context.quic_versions.length && pick === null; j++) {
        if (theirs.indexOf(context.quic_versions[j]) >= 0) pick = context.quic_versions[j];
      }
      if (pick !== context.version) { close(0x11, 'Version Negotiation did not match the server\'s versions'); return false; }
    }
    return true;
  }

  // ── 0-RTT (RFC 9001 §4.6; RFC 9000 §7.4.1) ────────────────────────────
  //
  // Client: with a saved session whose ticket allows it and earlyData on,
  // the ClientHello offers early data and its key comes at once
  // ('earlySecret'): from then until the 1-RTT keys, application packets go
  // as 0-RTT — within what the server allowed last time (its remembered
  // transport parameters) — and 'early' tells the application it may write.
  // The server's verdict comes with its EncryptedExtensions: accepted, and
  // nothing changes; refused, and everything sent early is as if never sent
  // — streams and flow control start over (RFC 9001 §4.6.2: "MUST reset the
  // state of all streams") — and 'early_rejected' tells the application to
  // send it again, now in 1-RTT.
  //
  // Server: TLS takes it (lemon-tls: the ticket allowed it, fresh, first
  // use, same ALPN, suite and parameters); 0-RTT packets are then read with
  // its key and taken at once, not held for the client's Finished — their
  // streams marked (isEarlyStream) for the application to judge. Packets
  // that came before the key, or before the application was set up, wait.

  // What 0-RTT is accepted under: the parameters a client remembers, as
  // this server sends them (another set — a restart with other settings —
  // and a ticket from before brings no 0-RTT).
  function earlyDataContext() {
    var keys = ['active_connection_id_limit', 'initial_max_data', 'initial_max_stream_data_bidi_local',
      'initial_max_stream_data_bidi_remote', 'initial_max_stream_data_uni', 'initial_max_streams_bidi',
      'initial_max_streams_uni', 'max_datagram_frame_size', 'reset_stream_at'];
    var parts = [String(context.version)];
    for (var i = 0; i < keys.length; i++) parts.push(keys[i] + '=' + (localTp[keys[i]] != null ? localTp[keys[i]] : ''));
    // And the application protocol's own settings, where a client may have
    // remembered them (HTTP/3's SETTINGS, RFC 9114 §7.2.4.2): earlyDataAppContext.
    if (typeof options.earlyDataAppContext === 'string') parts.push(options.earlyDataAppContext);
    return parts.join(';');
  }

  // A client writing early data now.
  function zeroRttSending() {
    return !context.isServer && !!context.zero_rtt_write && !context.app_write &&
           (context.state === 'handshaking' || context.state === 'idle');
  }

  var ZERO_RTT_HELD_MAX = 32;
  function zeroRttHold(pkt, path) {
    if (context.zero_rtt_held.length < ZERO_RTT_HELD_MAX) context.zero_rtt_held.push({ pkt: pkt, path: path });
  }
  function zeroRttRelease() {
    if (!context.zero_rtt_read || !context.app_write) return;
    var held = context.zero_rtt_held;
    context.zero_rtt_held = [];
    for (var i = 0; i < held.length; i++) feedPacket(held[i].pkt, held[i].path);
  }

  // The server's parameters as the client remembered them: the limits early
  // data stays within until this handshake's arrive (and replace them).
  function applyRememberedParams(r) {
    if (!r) return;
    context.early_remembered = r;
    // The IDs the server keeps: what 0-RTT may issue before its real
    // parameters arrive (RFC 9000 §7.4.1 lists it with the others).
    if (typeof r.active_connection_id_limit === 'number' && r.active_connection_id_limit >= 2) context.peer_active_cid_limit = r.active_connection_id_limit;
    if (typeof r.initial_max_data === 'number') context.remote_max_data = r.initial_max_data;
    if (typeof r.initial_max_stream_data_bidi_local === 'number') context.peer_initial_max_stream_data_bidi_local = r.initial_max_stream_data_bidi_local;
    if (typeof r.initial_max_stream_data_bidi_remote === 'number') context.peer_initial_max_stream_data_bidi_remote = r.initial_max_stream_data_bidi_remote;
    if (typeof r.initial_max_stream_data_uni === 'number') context.peer_initial_max_stream_data_uni = r.initial_max_stream_data_uni;
    if (typeof r.initial_max_streams_bidi === 'number') context.remote_max_streams_bidi = r.initial_max_streams_bidi;
    if (typeof r.initial_max_streams_uni === 'number') context.remote_max_streams_uni = r.initial_max_streams_uni;
    if (typeof r.max_datagram_frame_size === 'number') context.peer_max_datagram_frame_size = r.max_datagram_frame_size;
    // reset_stream_at, remembered as 1 (the draft, §3: a server that
    // accepts 0-RTT "MUST NOT" take it back).
    if (r.reset_stream_at === 1) context.peer_reset_stream_at = true;
  }

  // Accepted 0-RTT: the server's parameters now may not be below what the
  // client remembered and sent within (RFC 9000 §7.4.1; RFC 9221 §3 for
  // max_datagram_frame_size) — streams opened, data sent early would exceed
  // them. A client did not check, and went on past limits the server had
  // lowered: a connection the server would close for a flow-control or
  // stream-limit error later, with nothing pointing at the cause. Now the
  // connection is closed at once (PROTOCOL_VIOLATION), naming the
  // parameter. Asked when both are known: the verdict and the parameters
  // come in the same EncryptedExtensions, in either order.
  var EARLY_PARAM_DEFAULTS = { active_connection_id_limit: 2 };
  function checkEarlyParams() {
    var r = context.early_remembered, p = context.early_peer_tp;
    if (context.isServer || !r || !p || context.early_status !== 'accepted') return true;
    for (var k in r) {
      if (typeof r[k] !== 'number') continue;
      var now = typeof p[k] === 'number' ? p[k] : p[k] === true ? 1 : (EARLY_PARAM_DEFAULTS[k] || 0);
      if (now < r[k]) { close(0x0a, '0-RTT accepted with ' + k + ' reduced (' + r[k] + ' remembered, ' + now + ' now)'); return false; }
    }
    return true;
  }

  // Refused: what was sent early never happened. The packets are forgotten
  // (their numbers stay used — the space goes on), the streams and the flow
  // control they used start over, and the limits are the server's real ones,
  // which its parameters have set by now.
  function forgetEarlyData() {
    context.zero_rtt_write = null;
    context.pkt_in_flight.clear();
    context.app_bytes_in_flight = 0;
    context.sending_app_pn_in_flight.clear();
    context.pn_sids.clear();
    context.expired_unacked = {};
    context.limbo_n = 0;
    context.no_resend_in_flight = {};
    context.control_in_flight = {};
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      releaseStreamInFlight(st);
      checkSentWait(st, true);
    }
    context.send_streams = {};
    context.stream_priority = {};
    context.send_final = new Map();
    context.recv_streams = {};
    context.recv_open = new Set();
    context.local_max_opened_bidi = -1;
    context.local_max_opened_uni = -1;
    context.bytes_sent = 0;
    context.max_data_sent = 0;
    context.tlp_at = 0;
    context.app_loss_at = 0;
  }

  // Stream data that came in 0-RTT (server): its stream is marked.
  function noteEarlyStream(sid) {
    if (context.zero_rtt_processing) context.early_streams.add(Number(sid));
  }

  function initTLS() {
    startHandshakeTimer();

    var sni = context.SNICallback;
    if (context.isServer && typeof options.connectionOptions === 'function') {
      sni = function (servername, cb) {
        askConnectionOptions(servername, function () {
          if (context.SNICallback) context.SNICallback(servername, cb);
          else cb(null, null);
        });
      };
    }

    tls = new TLSBridge({
      isServer: context.isServer,
      transportParams: localTp,
      SNICallback: sni,
      // After a Retry the server echoes the client's first DCID, not the one
      // the connection's Initial keys came from (§7.3).
      originalDcid: context.retry_original_dcid || context.original_dcid,
      retrySourceCid: context.isServer ? context.retry_scid : null,
      localCid: context.my_cids.length > 0 ? context.my_cids[0] : new Uint8Array(0),
      statelessResetToken: context.isServer ? (options.statelessResetToken || null) : null,
      hostname: context.hostname,
      alpn: context.alpn,
      rejectUnauthorized: context.rejectUnauthorized,
      // Client: its certificate, for a server that asks for one.
      key: context.isServer ? null : (options.key || null),
      cert: context.isServer ? null : (options.cert || null),
      passphrase: context.isServer ? undefined : options.passphrase,
      // Client: a session saved from an earlier connection ('session'), to
      // resume — tls.connect's `session`.
      session: context.isServer ? null : (options.session || null),
      // Client: ask for the server's stapled OCSP response ('OCSPResponse').
      requestOCSP: !context.isServer && options.requestOCSP === true,
      ca: context.ca,
      ticketKeys: context.ticketKeys,
      ticketData: context.ticketData,
      ech: context.ech,
      // Client: GREASE ECH when it has no config (lemon-tls's echGrease).
      echGrease: !context.isServer && options.echGrease === true,
      // Client: the key-exchange groups to offer (ecdhCurve); null, the default.
      groups: context.isServer ? null : (options.groups || null),
      // Client: the signature schemes to offer (sigalgs); null, the default.
      sigalgs: context.isServer ? null : (options.sigalgs || null),
      ocspRequest: context.ocspRequest,
      // Tickets are for one QUIC version (RFC 9369 §5): v2's are issued and
      // accepted under their own context; v1's under none, as before.
      ticketContext: versionTicketContext(context.version),
      // 0-RTT (RFC 9001 §4.6), off unless asked for. Server: tickets that
      // allow it, and taking it (anti-replay: earlyDataMaxAge,
      // earlyDataReplay; under these transport parameters). Client: offered
      // with a saved session whose ticket allows it.
      earlyData: context.isServer ? options.earlyData === true : (options.earlyData === true && !!options.session),
      earlyDataMaxAge: options.earlyDataMaxAge,
      earlyDataReplay: options.earlyDataReplay,
      earlyDataContext: context.isServer ? earlyDataContext() : '',
      greaseQuicBit: options.greaseQuicBit !== false,
      minAckDelay: MIN_ACK_DELAY_US,
      versionInformation: function () {
        // Client: the version of its first flight, then every version that
        // flight can be read as, in its preference (RFC 9368 §3). Server: the
        // one chosen, and the versions it accepts.
        if (context.isServer) return { chosen: context.version, available: context.quic_versions.slice() };
        var avail = [context.original_version];
        for (var i = 0; i < context.quic_versions.length; i++) {
          var v = context.quic_versions[i];
          if (avail.indexOf(v) < 0 && isCompatible(context.original_version, v)) avail.push(v);
        }
        return { chosen: context.original_version, available: avail };
      },
      tlsOptions: context.tlsOptions
    });

    tls.on('send', function (epoch, data) { cryptoWrite(epoch, data); });

    // NSS key log lines (Wireshark / SSLKEYLOGFILE). Surfaced on the
    // connection so an application can persist them without reaching into the
    // TLS layer. Without this a QUIC capture is undecryptable, which makes
    // every wire-level bug an order of magnitude harder to diagnose.
    tls.on('keylog', function (line) { ev.emit('keylog', line); });
    // Client: a session to resume with later — a Buffer, as node:tls's
    // 'session' event gives it, once per ticket the server sends. Saved and
    // passed back as `session`, the next connection to the server resumes:
    // no certificate exchange, and the server gets back what it put in the
    // ticket (its Careful Resume state, its ticketData).
    if (!context.isServer) tls.on('session', function (buf) { ev.emit('session', buf); });
    if (!context.isServer) tls.on('OCSPResponse', function (buf) { ev.emit('OCSPResponse', buf); });
    // A fatal TLS alert ends the connection: CONNECTION_CLOSE with the alert
    // as a CRYPTO_ERROR (0x100 + alert code, RFC 9001 §4.8) — the peer learns
    // why, and this side reports the close now rather than at a timeout.
    tls.on('alert', function (code) { close(0x100 + code, 'TLS alert ' + code); });
    // The reason for that alert. During the handshake it is the connection's
    // failure, reported like the handshake timeout: 'error', then 'close'.
    // The alert has already closed the connection, so nothing else to do.
    tls.on('error', function (err) {
      if (!context.handshake_done) ev.emit('error', err);
    });

    // Peer's QUIC transport parameters (parsed from the TLS 0x39 extension). These
    // replace hardcoded defaults: the peer's flow-control limit, ACK-delay scaling,
    // and max ACK delay. Arrives once, during the handshake, before app data flows.
    tls.on('peerTransportParams', function (p) {
      // Surfaced verbatim, in order, before anything is applied — an
      // observation about the peer rather than a setting.
      ev.emit('peer_transport_params', p._ordered || []);

      // Malformed, out of range, or — at a server — one only a server sends
      // (RFC 9000 §7.4, §18.2): TRANSPORT_PARAMETER_ERROR, before any of it
      // is used. The ranges are checked once, by the parser; what is below
      // can take them as valid.
      var tpErr = transport_params_error(p, context.isServer);
      if (tpErr) { close(0x08, tpErr); return; }

      // Version negotiation (RFC 9368 §4), before anything else: the server
      // decides here — the ServerHello and everything after go out in the
      // version decided — and the client checks what the server says.
      if (!negotiateVersion(p.version_information)) return;
      // grease_quic_bit (RFC 9287 §3): empty, or a TRANSPORT_PARAMETER_ERROR.
      if (p.grease_quic_bit === 'invalid') { close(0x08, 'grease_quic_bit with a value'); return; }
      context.peer_grease_quic_bit = p.grease_quic_bit === true;

      // ack_delay_exponent (at most 20, checked above).
      if (typeof p.ack_delay_exponent === 'number') {
        context.peer_ack_delay_exponent = p.ack_delay_exponent;
      }
      // §7.3: a client "MUST" check that the connection IDs in the server's
      // parameters are the ones on the wire — the DCID of its first Initial,
      // the SCID the server's Initial carried, and the SCID of the Retry if
      // there was one (and none if there was not). They are what binds the
      // handshake to the packets that carried it: without the check an
      // attacker who injected a Retry or rewrote a connection ID went unseen.
      if (!context.isServer) {
        var odcid = p.original_destination_connection_id;
        var iscid = p.initial_source_connection_id;
        var rscid = p.retry_source_connection_id;
        var cidsMatch =
          !!odcid && uint8Equal(odcid, context.original_dcid) &&
          !!iscid && uint8Equal(iscid, context.their_cids[0]) &&
          (context.retry_scid ? !!rscid && uint8Equal(rscid, context.retry_scid) : !rscid);
        if (!cidsMatch) {
          close(0x08, 'connection IDs in transport parameters do not match');
          return;
        }
      } else if (!p.initial_source_connection_id || context.peer_initial_scid === null ||
                 !uint8Equal(p.initial_source_connection_id, context.peer_initial_scid)) {
        // §7.3, the server's half: the client's initial_source_connection_id
        // MUST be the SCID of its Initial packets — what ties the handshake
        // to the packets that carried it, as the check above does for the
        // client. Missing or different: TRANSPORT_PARAMETER_ERROR.
        close(0x08, 'initial_source_connection_id does not match the client\'s packets');
        return;
      }
      // stateless_reset_token: only a server sends one (§18.2), 16 bytes
      // (both checked above).
      if (!context.isServer && p.stateless_reset_token) {
        context.peer_reset_token = new Uint8Array(p.stateless_reset_token);
      }
      // min_ack_delay (µs): the peer takes ACK_FREQUENCY. Above its own
      // max_ack_delay: TRANSPORT_PARAMETER_ERROR.
      if (typeof p.min_ack_delay === 'number') {
        var peerMax = typeof p.max_ack_delay === 'number' ? p.max_ack_delay : 25;
        if (p.min_ack_delay > peerMax * 1000) { close(0x08, 'min_ack_delay above max_ack_delay'); return; }
        context.peer_min_ack_delay = p.min_ack_delay;
      }
      // active_connection_id_limit (§18.2): how many of our IDs the peer
      // keeps at once — at least 2; absent, 2.
      if (typeof p.active_connection_id_limit === 'number') {
        context.peer_active_cid_limit = p.active_connection_id_limit;
      } else context.peer_active_cid_limit = 2;
      // reset_stream_at: the peer takes RESET_STREAM_AT.
      context.peer_reset_stream_at = p.reset_stream_at === true;
      if (!context.isServer && context.early_remembered) {
        context.early_peer_tp = p;
        if (!checkEarlyParams()) return;
      }
      // The peer's first connection ID: sequence number 0, and — a server's —
      // its stateless reset token (§5.1.1).
      if (context.peer_cids.length === 0 && context.their_cids.length > 0) {
        context.peer_cids.push({ seq: 0, cid: context.their_cids[0], token: context.peer_reset_token, retired: false, inUse: true });
      }
      // max_idle_timeout (ms; 0 or absent: none) — the idle timeout in force
      // is the smaller of the two (applyIdleTimeout).
      context.peer_idle_timeout = typeof p.max_idle_timeout === 'number' ? p.max_idle_timeout : 0;
      applyIdleTimeout();
      // max_ack_delay (ms): the peer's stated max delay before it sends an ACK.
      // Below 2^14 (checked above).
      if (typeof p.max_ack_delay === 'number') {
        context.max_ack_delay = p.max_ack_delay;
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
      // RFC 9221 §3: absent, the peer takes no DATAGRAM frames at all; given,
      // none larger than it (the whole frame: type, length, data).
      if (typeof p.max_datagram_frame_size === 'number') {
        context.peer_max_datagram_frame_size = p.max_datagram_frame_size;
      }
      // max_udp_payload_size (RFC 9000 §18.2): the largest datagram it takes —
      // a bound on what DPLPMTUD probes. "Values below 1200 are invalid."
      if (typeof p.max_udp_payload_size === 'number') {
        context.peer_max_udp_payload = p.max_udp_payload_size;
      }
      // Stream-count limits the peer grants us (localStreamPermitted holds
      // back a stream past them). Seeded directly, not through set_context:
      // they replace guessed defaults (100/3), which may be higher.
      if (typeof p.initial_max_streams_bidi === 'number') {
        context.remote_max_streams_bidi = p.initial_max_streams_bidi;
      }
      if (typeof p.initial_max_streams_uni === 'number') {
        context.remote_max_streams_uni = p.initial_max_streams_uni;
      }
      releasePermitWaiters();
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

    // 0-RTT's key (see "0-RTT" above). Client: to write with, as its
    // ClientHello goes — and the application told it may write ('early').
    // Server: to read with, once TLS took the early data.
    tls.on('earlySecret', function (s) {
      var keys = quic_derive_from_tls_secrets(s.secret, s.hash, s.cipher, context.version);
      if (context.isServer) {
        context.zero_rtt_read = keys;
        if (context.app_write) queueMicrotask(zeroRttRelease);
        return;
      }
      context.zero_rtt_write = keys;
      context.early_status = 'offered';
      applyRememberedParams(s.remembered);
      context.early_app_remembered = s.rememberedApp != null ? s.rememberedApp : null;
      ev.emit('early');
    });
    tls.on('earlyData', function (accepted) {
      context.early_status = accepted ? 'accepted' : 'rejected';
      if (context.isServer) {
        if (serverStats) serverStats.earlyData[accepted ? 'accepted' : 'rejected']++;
        if (!accepted) { context.zero_rtt_held = []; context.zero_rtt_read = null; }
        return;
      }
      if (accepted) { if (checkEarlyParams()) ev.emit('early_accepted'); return; }
      forgetEarlyData();
      ev.emit('early_rejected');
    });

    tls.on('handshakeSecrets', function (secrets) {
      // Client: the ServerHello came in the version that stays (RFC 9369
      // §4: a CRYPTO frame in a version settles it).
      context.version_locked = true;
      set_context({
        handshake_read: quic_derive_from_tls_secrets(secrets.remote, secrets.hash, secrets.cipher, context.version),
        handshake_write: quic_derive_from_tls_secrets(secrets.local, secrets.hash, secrets.cipher, context.version)
      });
    });

    tls.on('appSecrets', function (secrets) {
      // A client's handshake is complete here (its Finished is made). A
      // server's is not: it has sent its Finished, and the handshake is
      // complete only with the client's (secureConnect, below) — until then
      // the deadline stands. Cleared here, a client that sent a ClientHello
      // and nothing more held the server's connection, unvalidated, until the
      // idle timeout instead.
      if (!context.isServer) stopHandshakeTimer();

      // Store secrets for future key updates (RFC 9001 §6)
      context.app_read_secret = secrets.remote;
      context.app_write_secret = secrets.local;
      context.cipher_hash = secrets.hash;
      context.cipher_suite = secrets.cipher;

      set_context({
        app_read: quic_derive_from_tls_secrets(secrets.remote, secrets.hash, secrets.cipher, context.version),
        app_write: quic_derive_from_tls_secrets(secrets.local, secrets.hash, secrets.cipher, context.version),
        state: 'connected',
        handshake_done: true,
        // A client has verified the server's Finished by now; a server has
        // only sent its own (secureConnect sets it).
        peer_finished: !context.isServer
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
        // 0-RTT held for the application, set up now (the 'connect' above).
        if (context.zero_rtt_read) queueMicrotask(zeroRttRelease);
      }
    });

    tls.on('secureConnect', function () {
      // Server: lemon-tls emits this once it has verified the client's
      // Finished — the handshake is complete (RFC 9001 §4.1.1), which at the
      // server is also "confirmed" (§4.1.2). Obligations follow:
      //   §5.7: the client's 1-RTT packets, held until now, are processed
      //         (peer_finished), and connection IDs issued.
      //   §4.1.2: "The server MUST send a HANDSHAKE_DONE frame as soon as the
      //           handshake is complete" — and not before. It used to go
      //           with the reply to the client's first 1-RTT packet as well,
      //           whether or not its Finished had come: a client told so
      //           discards its Handshake keys and stops resending a Finished
      //           that was lost, and the server, never getting it, never
      //           validated the client's address — capped at three times what
      //           the client sent, the connection stalled for good.
      //   §4.9.2: "An endpoint MUST discard its Handshake keys when the TLS
      //           handshake is confirmed."
      // The client's Finished proves it has our whole Handshake flight, so
      // nothing in that space needs resending.
      if (context.isServer) {
        stopHandshakeTimer();
        // 0-RTT's key kept a while for packets still on their way (RFC 9001
        // §4.9.3: up to three times the PTO), then let go.
        if (context.zero_rtt_read) {
          var zt = setTimeout(function () { context.zero_rtt_read = null; context.zero_rtt_held = []; }, 3 * ptoBase());
          if (zt.unref) zt.unref();
        }
        // Before the client's held 1-RTT packets are processed (below): the
        // handshake's end is told before the requests it lets in, as
        // node:tls's 'secureConnection' comes before a socket's data.
        handshakeEnded(true);
        set_context({ peer_finished: true });
        if (!context.handshake_done_sent && context.app_write) {
          set_context({ handshake_done_sent: true });
          queueControl('hd');     // retransmitted until acknowledged (§13.3)
          // A token for the client's next connection (NEW_TOKEN, §8.1.3):
          // it will need no proof of address then.
          if (typeof options.newToken === 'function') {
            var nt = options.newToken(peerPath().address, context.version);
            if (nt && nt.byteLength > 0) queueControl('nt', { type: 'new_token', token: nt });
          }
        }
        discardSpace('handshake');
        crStart();
        return;
      }

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
    feedPackets(from_ip, from_port, parse_quic_datagram(data), data.length);
  }

  // Feed already-parsed packets. Used by the server, which parses each UDP
  // datagram once (to route it to a connection) and then hands the parsed
  // packets here directly, avoiding a redundant second parse.
  //
  // datagramBytes: the UDP payload size of the datagram they came in. It is
  // what the anti-amplification budget counts (RFC 9000 §8.1) — the whole
  // datagram, whether or not its packets turn out to be processable, so it
  // is charged before any of them is looked at.
  function feedPackets(from_ip, from_port, packets, datagramBytes) {
    if (context.state === 'closed' || context.state === 'draining') return;
    if (isStatelessReset(packets)) {
      // §10.3.1: "the endpoint MUST enter the draining period and not send
      // any further packets on this connection."
      if (DEBUG) console.log('[quic] stateless reset from the peer — draining');
      set_context({ state: 'draining' });
      return;
    }
    // A client sends to one server address and never moves; the path a
    // server's datagram belongs to is where it came from.
    var path = context.isServer ? pathFor(from_ip, from_port) : context.path;
    if (!path.validated && datagramBytes > 0) path.received += datagramBytes;
    if (datagramBytes > path.max_rx) path.max_rx = datagramBytes;
    context.stats_packets_received += packets.length;
    context.stats_bytes_received += datagramBytes || 0;
    try {
      receivePackets(packets, path);
    } finally {
      // The client spoke: more budget, or a validated path. Release what
      // waited for it, and restart the handshake retransmission timer that
      // stood still while nothing could be sent (RFC 9002 §6.2.2.1: "When
      // the server receives a datagram from the client, the amplification
      // limit is increased and the server resets the PTO timer").
      if (path.queue.length > 0) releaseAmpQueue(path);
    }
  }

  // A client's handling of a Retry (RFC 9000 §17.2.5.2): the server wants
  // proof of our address before it commits anything to the connection.
  function acceptRetry(pkt) {
    // "At most one Retry packet for each connection attempt", and none after
    // anything from the server has been processed.
    if (context.retry_scid !== null || context.recv_pn_largest.initial >= 0) return;
    // In the version of our first Initial, or ignored (RFC 9369 §4.1).
    if (pkt.version !== context.original_version) return;
    // A tag that checks, and a token: anything else is discarded.
    var retry = open_retry_packet(pkt.raw, context.original_dcid);
    if (!retry || retry.token.byteLength === 0) return;
    // A token that cannot ride in an Initial of 1200 bytes with everything
    // else is no token: kept, every later Initial outgrew the datagram and
    // the connection could never be made (quinn GHSA-wppq-2f6r-wfvm).
    if (retry.token.byteLength > 512) return;
    if (DEBUG) console.log('[quic] Retry accepted — resending the Initial with its token');

    context.retry_scid = retry.scid;
    context.retry_token = retry.token;
    // New DCID, so new Initial keys (RFC 9001 §5.2) — the client's pair,
    // as connect() derives it. Packet numbers carry on (§17.2.5.3).
    context.initial_key_cid = retry.scid;
    set_context({
      initial_write: quic_derive_init_secrets(retry.scid, context.version, 'read'),
      initial_read: quic_derive_init_secrets(retry.scid, context.version, 'write')
    });
    // The ClientHello again, the same bytes (§17.2.5.3), in new packets:
    // what was in flight went to a server that did not keep it.
    context.crypto_sent.initial.in_flight = {};
    hsFlush();
    scheduleCryptoRetx();
  }

  // A client's handling of Version Negotiation (RFC 9000 §6.2, RFC 9368
  // §2.1): the server speaks none of the version of our first flight (nor,
  // compatibly, the others offered). Only one that answers our Initial —
  // addressed to our SCID, from the DCID we chose, before anything else from
  // the server — and that does not list the version we used (a forgery
  // meant to downgrade, RFC 9368 §4): the attempt ends, without a word on
  // the wire, and 'version_negotiation' names the versions the server
  // offers; the caller (quic_socket) starts over in one of them.
  function acceptVersionNegotiation(pkt) {
    if (context.recv_pn_largest.initial >= 0 || context.state === 'closed') return;
    if (!pkt.dcid || !uint8Equal(pkt.dcid, context.my_cids[0])) return;
    if (!pkt.scid || !uint8Equal(pkt.scid, context.original_dcid)) return;
    var offered = (pkt.supportedVersions || []).map(function (v) { return v >>> 0; });
    if (offered.indexOf(context.original_version) >= 0) return;
    if (DEBUG) console.log('[quic] Version Negotiation: the server offers ' + offered.map(versionName).join(', '));
    ev.emit('version_negotiation', offered);
    set_context({ state: 'closed' });
  }

  // §10.3.1: a datagram whose last 16 bytes are the peer's stateless reset
  // token. Checked on every datagram, which §10.3.1 allows ("This comparison
  // can be performed for every inbound datagram") — before its packets are
  // tried rather than after they fail: a reset is random bytes and fails
  // anyway, and a genuine packet ends in an AEAD tag that matches the token
  // with probability 2^-128. In constant time, as §10.3.1 requires: the
  // comparison must not leak the token.
  function isStatelessReset(packets) {
    if (packets.length === 0) return false;
    var raw = packets[packets.length - 1].raw;
    // §10.3: shorter than 21 bytes is never a valid packet, reset included.
    if (!raw || raw.byteLength < 21) return false;
    var tail = raw.subarray(raw.byteLength - 16);
    // The token of the first ID (from the transport parameters) and of every
    // other ID the peer issued and has not had retired (§10.3.1).
    var hit = false;
    if (context.peer_reset_token !== null && timingSafeEqual(tail, context.peer_reset_token)) hit = true;
    for (var i = 0; i < context.peer_cids.length; i++) {
      var pc = context.peer_cids[i];
      if (!pc.retired && pc.token && pc.token.byteLength === 16 && timingSafeEqual(tail, pc.token)) hit = true;
    }
    return hit;
  }

  function receivePackets(packets, path) {
    if (context.state === 'closing') {
      // RFC 9000 §10.2.1: while closing, don't process packets normally; instead
      // re-send CONNECTION_CLOSE in response (rate-limited) so the peer learns
      // we've closed even if the first CC was lost.
      if (Date.now() - context.last_close_echo >= 200) sendConnectionClose();
      return;
    }
    peerPacketReceived();
    for (var i = 0; i < packets.length; i++) {
      if (packets[i] !== null) {
        // Safety net: a single malformed packet must never crash the process or
        // tear down the connection. The parsers are bounds-checked, but this
        // also guards decrypt / frame-handler edge cases. Drop the bad packet
        // (logged under DEBUG) and keep processing the rest of the datagram.
        try {
          feedPacket(packets[i], path);
        } catch (e) {
          // Our failure, not the peer's: counted where it can be seen
          // (countInternalError), so a test or a fuzzer finds it — dropped
          // here, it left no trace without DEBUG.
          countInternalError(e);
          if (DEBUG) console.log('[quic] dropped packet — processing error: ' + (e && e.message));
        }
      }
    }
  }

  function feedPacket(pkt, path) {
    if (context.state === 'draining' || context.state === 'closed') return;

    // From an address other than the current one. RFC 9000 §9: the peer
    // "MUST NOT initiate connection migration before the handshake is
    // confirmed"; if it does, the endpoint "MUST either drop the incoming
    // packets on that path without generating a Stateless Reset or proceed
    // with path validation" — dropped, as is anything but 1-RTT after it:
    // the handshake spaces belong to the path the handshake ran on.
    if (path !== context.path && (!handshakeConfirmed() || pkt.type !== '1rtt')) return;

    // A server learns original_dcid from the client's first Initial (a
    // client set its own in connect()); set_context keeps only the first.
    if (context.isServer && pkt.type === 'initial' && pkt.dcid && pkt.dcid.byteLength > 0) set_context({ original_dcid: pkt.dcid });

    if (pkt.type === 'retry') { if (!context.isServer) acceptRetry(pkt); return; }
    if (pkt.type === 'version_negotiation') { if (!context.isServer) acceptVersionNegotiation(pkt); return; }

    // 0-RTT (RFC 9001 §4.6): the client's early data, in the application
    // space, under its own key. Only a server takes it; before the key — or
    // before the application is set up to hear it — held (zeroRttHold).
    var isZeroRtt = pkt.type === '0rtt';
    if (isZeroRtt) {
      if (!context.isServer || context.early_status === 'rejected' || handshakeConfirmed()) return;
      if (!context.zero_rtt_read || !context.app_write) { zeroRttHold(pkt, path); return; }
    }

    var space = pkt.type === 'initial' ? 'initial'
              : pkt.type === 'handshake' ? 'handshake'
              : (pkt.type === '1rtt' || isZeroRtt) ? 'app' : null;
    if (!space) return;

    // A discarded space stays closed. This must come before the Initial key
    // derivation below: that derives the keys whenever they are missing, so a
    // late Initial packet would otherwise bring the discarded keys back.
    if (space !== 'app' && context.discarded[space]) return;

    if (space === 'initial' && !context.initial_read && context.original_dcid) {
      context.initial_key_cid = context.original_dcid;
      set_context({
        initial_read: quic_derive_init_secrets(context.original_dcid, context.version, 'read'),
        initial_write: quic_derive_init_secrets(context.original_dcid, context.version, 'write')
      });
    }

    // A long header packet in another version than the connection's: the
    // client learning the negotiated version from the server's first one
    // in it (RFC 9369 §4); an Initial in the original version, which either
    // side may still send around the switch; anything else is dropped —
    // Handshake packets are in the negotiated version only.
    var readKeys;
    if (isZeroRtt) {
      if (pkt.version !== context.version) return;
      readKeys = context.zero_rtt_read;
    } else if (space !== 'app' && pkt.version !== context.version) {
      if (!context.isServer && !context.version_locked && context.quic_versions.indexOf(pkt.version) >= 0 &&
          isCompatible(context.original_version, pkt.version) && context.version === context.original_version) {
        switchVersion(pkt.version);
        readKeys = space === 'initial' ? context.initial_read : context.handshake_read;
      } else if (space === 'initial' && pkt.version === context.original_version && context.initial_read_original) {
        readKeys = context.initial_read_original;
      } else {
        return;
      }
    } else {
      readKeys = space === 'initial' ? context.initial_read
               : space === 'handshake' ? context.handshake_read : context.app_read;
    }
    if (!readKeys) return;

    // Connection ID by which *we* are addressed. Its length is needed to locate
    // the packet number in short (1-RTT) headers, which carry no DCID-length
    // field — the receiver must already know its own CID length. Long headers
    // carry the DCID length on the wire, so decrypt ignores this value for
    // Initial/Handshake packets.
    var recvCid = context.my_cids[0];

    var decrypted = decrypt_quic_packet(
      pkt.raw, readKeys.key, readKeys.iv, readKeys.hp,
      recvCid, context.recv_pn_largest[space], readKeys.aead
    );

    // Key Update: if app decrypt fails, try with derived next keys
    if ((!decrypted || !decrypted.plaintext) && space === 'app' && !isZeroRtt && context.app_read_secret) {
      var next = quic_derive_key_update(context.app_read_secret, context.cipher_hash, context.cipher_suite, context.version);
      decrypted = decrypt_quic_packet(
        pkt.raw, next.key, next.iv, readKeys.hp, // HP doesn't change
        recvCid, context.recv_pn_largest[space], next.aead
      );

      if (decrypted && decrypted.plaintext && decrypted.plaintext.byteLength > 0) {
        // Key update confirmed — install new read keys
        if (DEBUG) console.log('[quic] key update detected — installing new read keys');
        context.app_prev_read = context.app_read;
        context.app_read = { key: next.key, iv: next.iv, hp: readKeys.hp, aead: next.aead };
        context.app_read_secret = next.secret;
        context.read_key_phase = !context.read_key_phase;

        // RFC 9001 §6.2: a key update is BIDIRECTIONAL. Having accepted the
        // peer's new phase for reading, we MUST move our send keys to the same
        // phase before acknowledging anything received under it. Updating only
        // the read side means our very next ACK — which covers the peer's
        // new-phase packets — goes out under the OLD keys, and a conforming
        // peer treats that as KEY_UPDATE_ERROR and kills the connection.
        // (Measured against quic-go: connection closed ~3s after its routine
        // post-handshake key update, exactly when our stale-phase ACK landed.)
        // set_context({key_phase}) drives the existing machinery: it derives
        // next-generation write keys from app_write_secret and flips the KP
        // bit used by the encrypt path, so every packet from here on — the
        // ACK included — is protected under the new phase.
        //
        // Only when the peer started it. When we did, our send keys moved
        // first and this is the peer's answer in the phase we are already
        // in: flipped again, it was a second update, the peer answered that
        // one too, and the two went on updating every round trip for as long
        // as packets flowed (a 4 MB transfer after one update ended in the
        // phase it began with, as often as not).
        if (context.key_phase !== context.read_key_phase) set_context({ key_phase: context.read_key_phase });
      }
    }

    // Also try prev keys for reordered packets from before key update
    if ((!decrypted || !decrypted.plaintext) && space === 'app' && !isZeroRtt && context.app_prev_read) {
      decrypted = decrypt_quic_packet(
        pkt.raw, context.app_prev_read.key, context.app_prev_read.iv, context.app_prev_read.hp,
        recvCid, context.recv_pn_largest[space], context.app_prev_read.aead
      );
    }

    if (!decrypted || !decrypted.plaintext || decrypted.plaintext.byteLength === 0) {
      if (DEBUG) console.log('[quic] decrypt failed: ' + space + ' raw_len=' + pkt.raw.byteLength + ' first20=' + Array.from(pkt.raw.slice(0, 20)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ') + ' recv_cid_len=' + (recvCid ? recvCid.byteLength : 'null') + ' has_keys=' + !!readKeys + ' largest_pn=' + context.recv_pn_largest[space]);
      return;
    }

    if (DEBUG) console.log('[quic] decrypted ' + space + ' pn=' + decrypted.packet_number + ' len=' + decrypted.plaintext.byteLength);

    // RFC 9000 §8.1: "A server might wish to validate the client address
    // before starting the cryptographic handshake. [...] the server MAY
    // consider the peer address validated if the client uses a connection ID
    // chosen by the server and the connection ID contains at least 64 bits of
    // entropy." Ours is 8 random bytes, and the only way to learn it is to
    // receive our Initial at the address it went to. It covers what the
    // Handshake-packet rule below does not: a client that has our Initial but
    // none of our Handshake packets yet has nothing to send in that space,
    // and its Initial ACK now releases the held flight instead of waiting for
    // our retransmission timer.
    //
    // Only during the handshake, which is what §8.1 is about. Afterwards the
    // ID is no proof of anything: every packet of the connection carries it,
    // and an attacker who copies one and sends it from its own address
    // (§9.3.3) has it too. A later path is validated by PATH_CHALLENGE alone.
    if (!context.peer_finished && !path.validated && pkt.dcid && uint8Equal(pkt.dcid, context.my_cids[0])) markValidated(path);

    // The peer's connection ID, from a packet that proved to be the peer's.
    // Taken before decryption, it was whatever a forged packet claimed: the
    // first one to arrive decided where every later packet went.
    // The peer's connection ID, from its first long-header packet only: it
    // does not change during the handshake (§7.2), and a list grown from
    // every packet's SCID was a list the peer could grow.
    if (pkt.scid && pkt.scid.byteLength > 0 && context.their_cids.length === 0) set_context({ add_their_cid: pkt.scid });
    // The SCID of the client's first Initial — zero-length included, which
    // Chrome uses — for the §7.3 check of its transport parameters.
    if (context.isServer && context.peer_initial_scid === null && pkt.type === 'initial') {
      context.peer_initial_scid = pkt.scid || new Uint8Array(0);
    }

    var pn = decrypted.packet_number;
    var ranges = context.recv_pn_ranges[space];
    var isNew = true;
    var isLargest = false;
    // Below the oldest range still remembered: treated as a duplicate (RFC
    // 9000 §13.2.3 allows exactly this).
    if (pn < (context.recv_pn_floor[space] || 0)) isNew = false;
    for (var ri = 0; isNew && ri < ranges.length; ri += 2) {
      if (pn >= ranges[ri] && pn < ranges[ri + 1]) { isNew = false; break; }
    }
    if (isNew) {
      flat_ranges.add(ranges, [pn, pn + 1]);
      // The packet numbers seen, for telling a duplicate, kept to the newest
      // RECV_PN_RANGES_MAX ranges. A peer numbering its packets with a gap
      // between each made one range per packet, for the connection's life —
      // memory without bound, and a linear scan of all of it on every packet.
      if (ranges.length > RECV_PN_RANGES_MAX * 2) {
        var cut = ranges.length - RECV_PN_RANGES_MAX * 2;
        context.recv_pn_floor[space] = ranges[cut];
        ranges.splice(0, cut);
      }
      if (pn > context.recv_pn_largest[space]) {
        context.recv_pn_largest[space] = pn;
        isLargest = true;
      } else if (space === 'app') {
        // New packet, but below the highest PN already seen → it arrived out of
        // order. Pure network reordering (the peer sends PNs strictly increasing).
        context.reorder_in_count++;
      }
    }

    if (DEBUG) console.log('[quic] pn=' + pn + ' isNew=' + isNew);
    if (TRACE_ACK) console.log('[quic-ack] ' + Date.now() % 100000 + ' in  ' + space + ' pn=' + pn + (isNew ? '' : ' (dup)') + (space === 'app' && !context.peer_finished ? ' (held)' : ''));
    if (!isNew) return;

    // Held until the client's Finished (peer_finished). Not acknowledged
    // meanwhile — what is acknowledged is what was processed — so one past
    // the bound is simply dropped: the peer sends its content again.
    // (0-RTT is not held: taking it before the handshake is its point.)
    if (space === 'app' && !context.peer_finished && !isZeroRtt) {
      if (context.pending_app_packets.length < PENDING_APP_MAX) context.pending_app_packets.push(decrypted);
      return;
    }

    var frames = parse_quic_frames(decrypted.plaintext);
    if (isZeroRtt) {
      // RFC 9000 §12.4: no ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN,
      // PATH_RESPONSE or RETIRE_CONNECTION_ID in a 0-RTT packet.
      for (var zf = 0; zf < frames.length; zf++) {
        var zt = frames[zf].type;
        if (zt === 'ack' || zt === 'crypto' || zt === 'handshake_done' || zt === 'new_token' || zt === 'path_response' || zt === 'retire_connection_id') {
          close(0x0a, zt + ' frame in a 0-RTT packet');
          return;
        }
      }
      context.zero_rtt_processing = true;
      try { processDecryptedPacket('app', pn, frames, path); }
      finally { context.zero_rtt_processing = false; }
      return;
    }

    // §9.3: "An endpoint only changes the address to which it sends packets
    // in response to the highest-numbered non-probing packet" — so a
    // reordered packet from an address the peer has since left does not
    // move the connection back there. Decided before the frames are
    // processed: the ACK and anything else they prompt go to the new path.
    if (path !== context.path && isLargest && !isProbingOnly(frames)) migrateTo(path, pkt.dcid);

    context.rx_dcid = pkt.dcid || null;
    try { processDecryptedPacket(space, pn, frames, path); }
    finally { context.rx_dcid = null; }

    // RFC 9001 §4.9.1: "a server MUST discard Initial keys when it first
    // successfully processes a Handshake packet." The client can only send
    // one after it has every Initial CRYPTO byte from us, so nothing in the
    // Initial space is needed any more — including the acknowledgment of our
    // last Initial packet, which the client, having discarded its own Initial
    // keys already, can no longer send.
    if (context.isServer && space === 'handshake') {
      discardSpace('initial');
      // §8.1: "Once an endpoint has successfully processed a Handshake packet
      // from the peer, it can consider the peer address to have been
      // validated." Only a peer that could read our Initial could build one.
      markValidated(path);
    }
  }


  // ============================================================
  //  Frame processing
  // ============================================================

  // path: where the packet came from — where a PATH_RESPONSE to it goes.
  var RECV_PN_RANGES_MAX = 256;
  // 1-RTT packets held before the client's Finished: a request or two and
  // their ACKs, a few more if the Finished was lost and is being resent.
  var PENDING_APP_MAX = 64;

  function processDecryptedPacket(space, packetNumber, frames, path) {
    if (DEBUG) console.log('[quic] frames: ' + space + ' pn=' + packetNumber + ' [' + frames.map(function(f){ return f.type; }).join(',') + ']');
    var ackEliciting = false;

    // RFC 9000 §12.4: "An endpoint MUST treat the receipt of a frame of
    // unknown type as a connection error of type FRAME_ENCODING_ERROR" — and
    // one cut short (§19, transport.js 'malformed'). A packet with no frame
    // at all is a PROTOCOL_VIOLATION ("...containing no frames").
    // Checked before any frame is used: the packet is taken whole or not.
    if (frames.length === 0 && frames.padding !== true) { close(0x0a, 'a ' + space + ' packet with no frames'); return; }
    var lastFrame = frames.length ? frames[frames.length - 1] : null;
    if (lastFrame && (lastFrame.type === 'unknown' || lastFrame.type === 'malformed')) {
      close(0x07, (lastFrame.type === 'unknown' ? 'unknown frame type 0x' : 'malformed frame of type 0x') + lastFrame.frameType.toString(16));
      return;
    }

    // RFC 9000 §12.4: Initial and Handshake packets carry PADDING, PING,
    // ACK, CRYPTO and CONNECTION_CLOSE (0x1c) only; anything else in them is
    // PROTOCOL_VIOLATION. Unchecked, a STREAM frame in an Initial packet was
    // taken as the client's own data — and Initial keys come from the
    // client's first DCID, readable by anyone who saw that packet: a request
    // injected into another client's connection before its handshake was
    // done (xquic CVE-2026-6328). A server receives no HANDSHAKE_DONE or
    // NEW_TOKEN (§19.20, §19.7).
    for (var fi = 0; fi < frames.length; fi++) {
      var ftype = frames[fi].type;
      if (space !== 'app' && ftype !== 'crypto' && ftype !== 'ack' && ftype !== 'ping' &&
          !(ftype === 'connection_close' && !frames[fi].application)) {
        close(0x0a, ftype + ' frame in a ' + space + ' packet');
        return;
      }
      if (context.isServer && (ftype === 'handshake_done' || ftype === 'new_token')) {
        close(0x0a, ftype + ' frame from a client');
        return;
      }
    }

    // Initial and Handshake: the ACK this packet is owed is known before its
    // frames are processed — and must be. Processing a CRYPTO frame can send
    // at once: the server's ServerHello leaves while the ClientHello is still
    // being read. Recorded only afterwards, the ACK of the ClientHello went
    // in an Initial packet of its own, after the server's whole flight —
    // when the client had already dropped its Initial keys (§4.9.1 of RFC
    // 9001, at its first Handshake packet) and discarded it unread. The
    // client then never had an RTT sample from it. Owed beforehand, it rides
    // in the ServerHello's packet (sendFrames adds an ACK that is owed); what
    // is still owed after the frames goes at once, as before (§13.2.1).
    var preAcked = false;
    if (space !== 'app') {
      for (var ef = 0; ef < frames.length && !preAcked; ef++) {
        if (frames[ef].type === 'crypto' || frames[ef].type === 'ping') preAcked = true;
      }
      if (preAcked) {
        flat_ranges.add(context.pending_ack[space], [packetNumber, packetNumber + 1]);
        var pst = context.ack_state[space];
        if (packetNumber > pst.largest) { pst.largest = packetNumber; pst.largest_time = performance.now(); }
        pst.eliciting++;
      }
    }

    // One PATH_RESPONSE per packet, to its last PATH_CHALLENGE: it answered
    // each, and a packet can hold a hundred — a hundred packets out for one
    // in, each padded to 1200 bytes. The peer needs an answer to its latest
    // (RFC 9000 §8.2.2); quicly keeps one slot the same way.
    var pathChallenge = null;

    for (var i = 0; i < frames.length; i++) {
      var frame = frames[i];

      if (frame.type === 'crypto') {
        ackEliciting = true;
        processCryptoFrame(space, frame.offset, frame.data);
      } else if (frame.type === 'stream') {
        ackEliciting = true;
        if (processStreamFrame(frame) === false) return;   // a connection error: already closing
      } else if (frame.type === 'ack') {
        processAckFrame(space, frame);
      } else if (frame.type === 'ping') {
        ackEliciting = true;
      } else if (frame.type === 'immediate_ack') {
        // An ACK without delay (draft-ietf-quic-ack-frequency §5).
        ackEliciting = true;
        context.ack_state.app.immediate = true;
      } else if (frame.type === 'ack_frequency') {
        ackEliciting = true;
        if (onAckFrequency(frame) === false) return;
      } else if (frame.type === 'new_token') {
        // A server's token for our next connection (RFC 9000 §19.7; a server
        // receiving one was refused above). Empty: FRAME_ENCODING_ERROR.
        ackEliciting = true;
        if (!frame.token || frame.token.byteLength === 0) { close(0x07, 'empty NEW_TOKEN'); return; }
        ev.emit('new_token', Buffer.from(frame.token));
      } else if (frame.type === 'handshake_done') {
        ackEliciting = true;
        // RFC 9001 §4.1.2: at the client the handshake is confirmed when
        // HANDSHAKE_DONE arrives, and §4.9.2: its Handshake keys MUST then
        // be discarded.
        if (!context.isServer) discardSpace('handshake');
      } else if (frame.type === 'path_challenge') {
        // §8.2.2: "A PATH_RESPONSE frame MUST be sent on the network path
        // where the PATH_CHALLENGE frame was received", without delay.
        ackEliciting = true;
        pathChallenge = frame.data;
      } else if (frame.type === 'path_response') {
        ackEliciting = true;
        onPathResponse(frame.data);
      } else if (frame.type === 'new_connection_id') {
        ackEliciting = true;
        if (onNewConnectionId(frame) === false) return;
      } else if (frame.type === 'retire_connection_id') {
        ackEliciting = true;
        if (onRetireConnectionId(frame) === false) return;
      } else if (frame.type === 'connection_close') {
        if (DEBUG) console.log('[quic] CONNECTION_CLOSE error=0x' + (frame.error || 0).toString(16) + ' frame_type=0x' + (frame.frameType || 0).toString(16) + ' reason="' + (frame.reason || '') + '"');
        // Kept for whoever reports the close: the peer's code and reason are
        // the only account of why a connection it ended went away.
        if (serverStats && !context.peer_close) serverStats.code(serverStats.closes[frame.application ? 'h3' : 'quic'].received, frame.error || 0);
        context.peer_close = { error: frame.error || 0, application: !!frame.application, reason: frame.reason || '' };
        set_context({ state: 'draining' });
        return;
      } else if (frame.type === 'stop_sending') {
        // The peer will not read what we send on this stream. RFC 9000 §3.5:
        // an endpoint that receives STOP_SENDING "MUST send a RESET_STREAM
        // frame if the stream is in the 'Ready' or 'Send' state" — it used to
        // be dropped here in silence, leaving the peer waiting on a stream we
        // had quietly abandoned. The error code is carried over, as §3.5
        // suggests. (The sending part becomes terminal when the RESET_STREAM
        // is acknowledged; see ackControl.)
        ackEliciting = true;
        if (DEBUG) console.log('[quic] STOP_SENDING stream=' + frame.id + ' error=' + frame.error);
        if (checkStreamId(frame.id, 'send') === false) return;
        // Nothing to stop on a sending part that is already over. Unchecked,
        // a STOP_SENDING for a long-closed stream reset it again and left a
        // half-done entry in stream_sides_done for good.
        if (!sendSideOpen(frame.id)) continue;
        var hadSend = resetStream(frame.id, frame.error);
        if (hadSend) ev.emit('stop_sending', Number(frame.id), frame.error);
      } else if (frame.type === 'reset_stream' || frame.type === 'reset_stream_at') {
        ackEliciting = true;
        // A reset for a stream whose receiving part is already over is a
        // repeat: ignored. It used to be ignored only while recv_final still
        // remembered the stream — after that it ran again, and each run
        // counted the stream closed once more and raised MAX_STREAMS for it.
        var rsState = checkStreamId(frame.id, 'recv');
        if (rsState === false) return;
        if (rsState === 'closed') continue;
        if (serverStats) serverStats.code(serverStats.streamResets.h3.received, frame.error);
        if (!onPeerReset(frame)) return;    // a connection error: already closing
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
        // Validated first: remote_max_stream_data_by_sid is keyed by the ID,
        // and unchecked IDs grew it without bound.
        if (checkStreamId(frame.id, 'send') === false) return;
        if (!sendSideOpen(frame.id)) continue;   // a late one, for a finished stream
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
      } else if (frame.type === 'streams_blocked_bidi' || frame.type === 'streams_blocked_uni') {
        // The peer has used every stream we granted. Ack-eliciting like any
        // frame but ACK/PADDING/CONNECTION_CLOSE (it used to fall through
        // unacknowledged); answered with our current limit, which also
        // recovers a lost MAX_STREAMS, as DATA_BLOCKED does for MAX_DATA.
        ackEliciting = true;
        queueControl(frame.type === 'streams_blocked_bidi' ? 'ms_bidi' : 'ms_uni');
      } else if (frame.type === 'data_blocked') {
        // The peer is stalled on our connection window. Our MAX_DATA may have
        // been lost (window updates are sent once, unrecovered) — re-send the
        // current limit. Harmless if it wasn't lost: the peer's limit is
        // monotonic, a duplicate is ignored.
        ackEliciting = true;
        queueControl('max_data');
      } else if (frame.type === 'stream_data_blocked') {
        // Same, per stream. If we never received data on this stream (all of
        // it lost), no recv_stream exists yet — answer with the initial limit
        // we advertised in our transport params.
        ackEliciting = true;
        var sdbState = checkStreamId(frame.id, 'recv');
        if (sdbState === false) return;
        if (sdbState === 'closed') continue;
        // (materializeControl answers with the initial limit when no
        // recv_stream exists yet.)
        queueControl('msd:' + Number(frame.id));
      } else if (frame.type === 'datagram') {
        // DATAGRAM frames are ack-eliciting (RFC 9221 §5.2). Without this, a
        // peer sending only datagrams (a classic WebTransport flow) would get
        // no ACKs from us and read the silence as total loss.
        ackEliciting = true;
        // §3: none when we offered none, none larger than we offered —
        // PROTOCOL_VIOLATION. (The frame's size: type, length, data.)
        if (!localTp.max_datagram_frame_size || frame.data.byteLength + 1 > localTp.max_datagram_frame_size) {
          close(0x0a, 'DATAGRAM frame larger than max_datagram_frame_size');
          return;
        }
        ev.emit('datagram', frame.data);
      }
    }

    if (pathChallenge) sendFrames(space, [{ type: 'path_response', data: pathChallenge }], path);

    if (ackEliciting) {
      if (!preAcked) flat_ranges.add(context.pending_ack[space], [packetNumber, packetNumber + 1]);

      // Cap the acknowledged ranges (RFC 9000 §13.2.4 explicitly allows
      // acking a subset). Under loss, packet-number gaps never close — a lost
      // PN is gone forever; its DATA returns under a new PN — so every loss
      // event mints one more range that would otherwise live here for the
      // rest of the connection. Unpruned, the ACK frame grows with the loss
      // count until it crosses the MTU and the ACK cannot be sent AT ALL, at
      // which point the peer (correctly) stalls and idle-times-out. Measured
      // against a quiche server through the interop simulator: 485 losses in
      // 7s of line-rate transfer inflated our ACK packets 325B→1017B second
      // by second, ACKs died at t≈8s, and quiche collected the connection.
      // Dropping the LOWEST ranges is safe: those packets were received and
      // have been acknowledged in every ACK frame sent since; anything the
      // peer still considers unacked it will retransmit as new data under a
      // fresh, high PN that the surviving ranges cover.
      var pa = context.pending_ack[space];
      var MAX_ACK_RANGES = 32;
      if (pa.length > MAX_ACK_RANGES * 2) pa.splice(0, pa.length - MAX_ACK_RANGES * 2);

      if (preAcked) { if (ackOwed(space)) scheduleHsFlush(); }   // unless already in a packet sent meanwhile
      else onAckElicitingReceived(space, packetNumber);
    }
  }


  // ============================================================
  //  ACK management (RFC 9000 §13.2)
  //
  //  When an ACK goes out is decided here, and only here.
  //
  //  Initial and Handshake: at once, synchronously, as before — §13.2.1
  //  "MUST acknowledge all ack-eliciting Initial and Handshake packets
  //  immediately".
  //
  //  1-RTT: delayed, which §13.2.1 allows up to the max_ack_delay we advertise.
  //  An ACK used to go out for every ack-eliciting packet, in a packet of its
  //  own: a 20 MB download had the client send 18,046 ACK-only packets for
  //  18,054 received, and the server process every one through a full pass
  //  of its send planner. Now an ACK is sent:
  //    - once two or more ack-eliciting packets are unacknowledged (§13.2.2
  //      "SHOULD send an ACK frame after receiving at least two"), decided at
  //      the end of the event-loop turn, so datagrams that arrived together
  //      get one ACK;
  //    - without delay for a packet out of order — below one already
  //      received, or past a gap — which is what lets the sender detect loss
  //      quickly (§13.2.1);
  //    - else when the ACK timer expires;
  //    - and, whenever a packet goes out anyway, inside it (piggybacked: see
  //      sendFrames), which settles whatever was owed.
  //
  //  ACK Delay (§19.3) carries how long the largest acknowledged packet
  //  waited, in units of 2^ack_delay_exponent µs, so the sender can take it
  //  out of its RTT sample — without it, every delayed ACK would read as
  //  path delay.
  // ============================================================

  var ACK_ELICITING_THRESHOLD = 2;   // §13.2.2 — or what ACK_FREQUENCY sets (ack_freq)
  // min_ack_delay we advertise (µs): the shortest delay our timers keep —
  // ~1 ms, ~16 ms on Windows.
  var MIN_ACK_DELAY_US = (typeof process !== 'undefined' && process.platform === 'win32') ? 16000 : 1000;
  // The deadline we keep, under the max_ack_delay we advertise: timers fire
  // late by up to their granularity — ~15.6 ms on Windows — and the peer's
  // loss timer counts on our ACK arriving within the advertised value.
  var LOCAL_ACK_DELAY_MS = Math.max(1, defaultTransportParams().max_ack_delay - 15);
  var LOCAL_ACK_DELAY_EXPONENT = defaultTransportParams().ack_delay_exponent;

  // Is every packet number in [from, to) received? (recv_pn_ranges: flat,
  // ascending; searched from the top, where the answer is.)
  function pnRangeReceived(space, from, to) {
    var r = context.recv_pn_ranges[space];
    for (var i = r.length - 2; i >= 0; i -= 2) {
      if (r[i] <= from) return r[i + 1] >= to;
      if (r[i + 1] < to) return false;
    }
    return false;
  }

  function onAckElicitingReceived(space, pn) {
    var st = context.ack_state[space];
    // §13.2.1: out of order — below an ack-eliciting packet already received,
    // or past one with packets missing in between.
    // With a Reordering Threshold from the peer (ACK_FREQUENCY): only past
    // it — a gap of that many below the new largest, or a packet that many
    // below the largest; 0: never (the other thresholds decide). 1, the
    // default, is §13.2.1's any gap, any packet below.
    var R = space === 'app' ? context.ack_freq.reorder : 1;
    var outOfOrder = R > 0 && st.largest >= 0 &&
      ((pn < st.largest && st.largest - pn >= R) ||
       (pn > st.largest + 1 && pn - st.largest - 1 >= R && !pnRangeReceived(space, st.largest + 1, pn)));
    if (pn > st.largest) { st.largest = pn; st.largest_time = performance.now(); }
    st.eliciting++;

    // Initial and Handshake: at once (§13.2.1) — in the flush at the end of
    // this turn, with whatever else the space sends (hsFlush).
    if (space !== 'app') { scheduleHsFlush(); return; }
    if (outOfOrder) st.immediate = true;
    if (!context.ack_decision_pending) {
      context.ack_decision_pending = true;
      setImmediate(ackDecision);
    }
  }

  // End of the turn in which 1-RTT packets arrived: send now, or wait.
  function ackDecision() {
    context.ack_decision_pending = false;
    var st = context.ack_state.app;
    if (st.eliciting === 0) return;               // settled by a piggyback meanwhile
    // "after receiving more than" the Ack-Eliciting Threshold (1: §13.2.2's
    // two), or when the delay is up — the peer's Requested Max Ack Delay
    // when it asked for one.
    if (st.immediate || st.eliciting > context.ack_freq.threshold) { sendAckNow('app'); return; }
    if (context.ack_timer === null) {
      context.ack_timer = setTimeout(function () {
        context.ack_timer = null;
        if (context.ack_state.app.eliciting > 0) sendAckNow('app');
      }, context.ack_freq.delay_ms !== null ? context.ack_freq.delay_ms : LOCAL_ACK_DELAY_MS);
      if (context.ack_timer.unref) context.ack_timer.unref();
    }
  }

  // ── ACK frequency (draft-ietf-quic-ack-frequency) ──
  //
  // A receiver ACKs every second packet (§13.2.2): a 20 MB download is ~9,000
  // ACK packets the receiver builds and sends and the sender decrypts and
  // processes, one by one, in JavaScript here. A sender with a window of
  // many packets has no use for most of them; it says so with ACK_FREQUENCY
  // — an ACK after every N, or after a delay — and this side follows what
  // the peer asks the same way.

  // The peer's request (§4). Applied only if newer than the last (Sequence
  // Number); a delay below the min_ack_delay we advertised, or past 2^14 ms,
  // is a PROTOCOL_VIOLATION.
  function onAckFrequency(frame) {
    var us = frame.maxDelayUs;
    if (us < MIN_ACK_DELAY_US || us >= 16384 * 1000) { close(0x0a, 'ACK_FREQUENCY Requested Max Ack Delay ' + us + ' µs'); return false; }
    if (frame.seq <= context.ack_freq.seq) return true;
    // Our timer keeps under what was asked, as LOCAL_ACK_DELAY_MS does under
    // what we advertise: it fires late by up to its granularity.
    var ms = us / 1000;
    context.ack_freq = {
      seq: frame.seq,
      threshold: frame.threshold,
      delay_ms: Math.max(1, Math.floor(ms > 16 ? ms - 15 : ms / 2)),
      reorder: frame.reorder
    };
    return true;
  }

  // Ours to the peer, after an ACK: an ACK every N packets while many are
  // in flight — N up to 10 and a quarter of what is in flight (within the
  // window), the Ack-Eliciting Threshold one below — and the delay a quarter
  // of the RTT, within the peer's min_ack_delay and its own max_ack_delay
  // (which PTO already counts, so no timer here waits longer than it did).
  // While little is in flight — a request and its answer, a ping — the
  // peer's defaults are asked for again: there is nothing to save, and a
  // delayed ACK there is only delay. Sent again only when either changes,
  // at most once a round trip (§8.1).
  function maybeSendAckFrequency() {
    if (context.peer_min_ack_delay === null || !context.handshake_done || context.srtt === null) return;
    var now = Date.now();
    var last = context.af_sent;
    if (last && now - last.at < context.srtt) return;
    var flightPkts = Math.floor(Math.min(context.current_limit_bytes_in_flight, context.app_bytes_in_flight) / 1200);
    var thr = Math.max(1, Math.min(9, Math.floor(flightPkts / 4) - 1));
    var maxUs = context.max_ack_delay * 1000;
    var delayUs = thr === 1 ? maxUs
                : Math.round(Math.max(context.peer_min_ack_delay, Math.min(maxUs, context.srtt * 1000 / 4)));
    if (!last && thr === 1) return;          // nothing to change from the defaults
    if (last && last.threshold === thr && Math.abs(last.delay - delayUs) <= last.delay / 4) return;
    var seq = context.af_seq++;
    context.af_sent = { threshold: thr, delay: delayUs, at: now };
    queueControl('af', { type: 'ack_frequency', seq: seq, threshold: thr, maxDelayUs: delayUs, reorder: 1 });
  }

  // An ACK frame for `space` as of now, or null when there is nothing to say.
  function buildAckFrame(space) {
    var delay = 0;
    // §13.2.5 / RFC 9002 §5.3: ACK Delay only means anything in 1-RTT; the
    // other spaces acknowledge at once.
    if (space === 'app' && context.ack_state.app.largest >= 0) {
      var us = (performance.now() - context.ack_state.app.largest_time) * 1000;
      delay = Math.max(0, Math.floor(us / Math.pow(2, LOCAL_ACK_DELAY_EXPONENT)));
    }
    return ranges_to_ack_frame(context.pending_ack[space], null, delay);
  }

  function ackOwed(space) { return context.ack_state[space].eliciting > 0; }

  function sendAckNow(space) {
    var f = buildAckFrame(space);
    if (f) sendFrames(space, [f]);     // sendFrames records it (ackSent)
  }

  // An ACK frame for `space` has gone out: nothing is owed any more.
  function ackSent(space) {
    var st = context.ack_state[space];
    st.eliciting = 0;
    st.immediate = false;
    if (space === 'app' && context.ack_timer !== null) {
      clearTimeout(context.ack_timer);
      context.ack_timer = null;
    }
  }

  function stopAckTimer() {
    if (context.ack_timer !== null) { clearTimeout(context.ack_timer); context.ack_timer = null; }
  }


  // ============================================================
  //  CRYPTO → TLS
  // ============================================================

  // CRYPTO data held ahead of what TLS has taken, per packet number space:
  // bytes, and separate pieces. Unbounded, one Initial packet's frames at
  // spread-out offsets held what the peer chose, and the next packet more —
  // memory without limit, before any handshake (s2n-quic CVE-2026-10740,
  // the CRYPTO floods of quiche CVE-2024-1765 and MerCuriuzz). A handshake
  // flight is a few KB; quiche allows 64 KB, as here. Past it:
  // CRYPTO_BUFFER_EXCEEDED (RFC 9000 §7.5).
  var CRYPTO_BUFFER_MAX = 64 * 1024;
  var CRYPTO_PIECES_MAX = 128;

  // 1-RTT CRYPTO data carries what TLS sends after the handshake. In QUIC
  // that is the server's NewSessionTicket and nothing else: no KeyUpdate
  // (RFC 9001 §6 — QUIC updates keys itself), no post-handshake client
  // authentication (§4.4), so nothing at all from a client. It was dropped
  // unread, on both sides — a client never saw a ticket, so it could never
  // resume, and the server's Careful Resume state (savedState),
  // which rides in the ticket, never came back to it.
  var NEW_SESSION_TICKET = 0x04;

  // Reassembly, per space. In order: `q`, the bytes received and not yet
  // read as TLS messages (pieces, `qlen` of them in all), up to `end`.
  // Ahead of a gap: `ahead`, pieces sorted by offset that never overlap
  // each other or what is in order (only bytes not held yet are kept), at
  // most CRYPTO_PIECES_MAX of them, none past CRYPTO_BUFFER_MAX beyond what
  // was read (RFC 9000 §7.5: CRYPTO_BUFFER_EXCEEDED). Each byte is copied
  // once, into the message it belongs to.
  //
  // The old reassembly kept pieces by their exact offset and joined only a
  // piece starting where the last one ended: data sent again in other
  // boundaries — a lost packet's CRYPTO re-planned into a larger one, as
  // our own flush does — never joined, and the handshake waited for bytes
  // the peer, holding an ACK for them, would not send again. And every
  // frame concatenated everything held so far, the partial message
  // included: a datagram of one-byte frames copied the buffer once per
  // frame — before the peer had proven anything.
  function cryptoRx(space) {
    return context.crypto_rx[space] || (context.crypto_rx[space] = { end: 0, q: [], qlen: 0, ahead: [] });
  }

  // The first n bytes in order (n <= qlen), removed and returned as one array.
  function cryptoTake(rx, n) {
    var out = (rx.q[0].byteLength >= n) ? null : new Uint8Array(n), at = 0, first = null;
    while (at < n) {
      var p = rx.q[0], need = n - at;
      if (p.byteLength <= need) {
        rx.q.shift();
        if (out) out.set(p, at); else first = p;
        at += p.byteLength;
      } else {
        if (out) out.set(p.subarray(0, need), at); else first = p.subarray(0, need);
        rx.q[0] = p.subarray(need);
        at += need;
      }
    }
    rx.qlen -= n;
    return out || first;
  }

  // Byte i of what is in order (i < qlen).
  function cryptoPeek(rx, i) {
    for (var k = 0; k < rx.q.length; k++) {
      if (i < rx.q[k].byteLength) return rx.q[k][i];
      i -= rx.q[k].byteLength;
    }
    return 0;
  }

  function processCryptoFrame(space, offset, data) {
    if (DEBUG) console.log('[quic] CRYPTO: space=' + space + ' offset=' + offset + ' len=' + data.length);
    if (space === 'initial') context.crypto_seen_initial = true;

    var rx = cryptoRx(space);
    var end = offset + data.byteLength;
    if (end <= rx.end) {              // all of it held already: a retransmission
      if (space !== 'app') hsPeerResent();
      return;
    }
    if (end > (rx.end - rx.qlen) + CRYPTO_BUFFER_MAX) { close(0x0d, 'CRYPTO data beyond the buffer limit'); return; }

    if (offset <= rx.end) {
      // In order (or overlapping the end of what is): the new bytes go on,
      // then whatever was waiting ahead of them that now joins.
      rx.q.push(data.subarray(rx.end - offset));
      rx.qlen += end - rx.end;
      rx.end = end;
      while (rx.ahead.length && rx.ahead[0].off <= rx.end) {
        var a = rx.ahead.shift(), aEnd = a.off + a.data.byteLength;
        if (aEnd > rx.end) {
          rx.q.push(a.data.subarray(rx.end - a.off));
          rx.qlen += aEnd - rx.end;
          rx.end = aEnd;
        }
      }
    } else {
      // Ahead of a gap: the bytes not held yet, between the pieces there.
      var pos = offset, i = 0, add = [];
      while (i < rx.ahead.length && rx.ahead[i].off + rx.ahead[i].data.byteLength <= pos) i++;
      var at = i;
      while (pos < end) {
        var nxt = i < rx.ahead.length ? rx.ahead[i] : null;
        if (nxt && nxt.off <= pos) { pos = Math.max(pos, nxt.off + nxt.data.byteLength); i++; continue; }
        var stop = nxt ? Math.min(end, nxt.off) : end;
        add.push({ off: pos, data: data.subarray(pos - offset, stop - offset) });
        pos = stop;
      }
      if (add.length) {
        if (rx.ahead.length + add.length > CRYPTO_PIECES_MAX) { close(0x0d, 'CRYPTO data in too many pieces'); return; }
        // Merged in order: what was at or after `at` and the new pieces.
        var merged = rx.ahead.slice(0, at), rest = rx.ahead.slice(at), x = 0, y = 0;
        while (x < rest.length || y < add.length) {
          if (y >= add.length || (x < rest.length && rest[x].off < add[y].off)) merged.push(rest[x++]);
          else merged.push(add[y++]);
        }
        rx.ahead = merged;
      }
      return;
    }

    // The TLS messages now whole (RFC 8446 §4: type, 3-byte length, body).
    var messages = [];
    while (rx.qlen >= 4) {
      var len = (cryptoPeek(rx, 1) << 16) | (cryptoPeek(rx, 2) << 8) | cryptoPeek(rx, 3);
      if (rx.qlen < 4 + len) break;
      messages.push(cryptoTake(rx, 4 + len));
    }
    if (DEBUG) console.log('[quic] TLS messages: ' + messages.length);
    if (messages.length === 0) return;
    if (!tls) { if (DEBUG) console.log('[quic] initializing TLS bridge'); initTLS(); }

    for (var mi = 0; mi < messages.length; mi++) {
      var msg = messages[mi];
      var msgType = msg[0];
      if (space === 'app' && (context.isServer || msgType !== NEW_SESSION_TICKET)) {
        // TLS's unexpected_message as a CRYPTO_ERROR (RFC 9001 §4.8); a
        // KeyUpdate is named as one (§6).
        close(0x100 + 10, 'TLS message ' + msgType + ' after the handshake');
        return;
      }
      // Closed by what an earlier message brought: the rest is not read.
      if (context.state === 'closing' || context.state === 'draining' || context.state === 'closed') return;
      if (DEBUG) console.log('[quic] → TLS msg #' + mi + ' type=0x' + msgType.toString(16) + ' len=' + msg.length);
      tls.feedMessage(msg);
    }
  }


  // ============================================================
  //  Control frames: queue, send, track, retransmit (RFC 9000 §13.3)
  // ============================================================

  var FINAL_MEMORY = 4096;     // streams remembered as finished, per direction
  function rememberFinal(map, sid, value) {
    map.delete(sid);
    map.set(sid, value);
    if (map.size > FINAL_MEMORY) map.delete(map.keys().next().value);   // oldest first
  }

  function queueControl(key, frame) {
    context.control_queue[key] = frame || null;
    if (!context.control_flush_pending) {
      context.control_flush_pending = true;
      // The fallback, at the end of this turn: by then the frames have
      // usually left inside another packet — the response the request that
      // raised a limit is answered with, the ACK of the packets that brought
      // it (takeControlFrames) — and there is nothing left to flush.
      setImmediate(flushControl);
    }
  }

  function hasQueuedControl() {
    for (var k in context.control_queue) return true;
    return false;
  }

  // The frame for a queue key, built now. null = no longer needed.
  function materializeControl(key, stored) {
    if (key === 'max_data') return { type: 'max_data', max: context.local_max_data };
    if (key === 'ms_bidi') return { type: 'max_streams_bidi', max: context.local_max_streams_bidi };
    if (key === 'ms_uni') return { type: 'max_streams_uni', max: context.local_max_streams_uni };
    if (key === 'hd') return { type: 'handshake_done' };
    if (key.indexOf('msd:') === 0) {
      var id = Number(key.substring(4));
      var rs = context.recv_streams[id];
      // §13.3: no more MAX_STREAM_DATA once the receiving part has its final size.
      if (context.recv_final.has(id) || (rs && rs.has_final)) return null;
      return { type: 'max_stream_data', id: id,
               max: rs ? rs.local_max_stream_data : localStreamWindow(id) };
    }
    if (key.indexOf('ss:') === 0) {
      // Only while the peer still has something to stop sending.
      return context.recv_final.has(stored.id) ? null : stored;
    }
    if (key.indexOf('ncid:') === 0) {
      // §13.3: "a NEW_CONNECTION_ID frame is sent until acknowledged" — not
      // one the peer has since retired.
      for (var i = 0; i < context.local_cids.length; i++) {
        if (context.local_cids[i].seq === stored.seq && !context.local_cids[i].retired) return stored;
      }
      return null;
    }
    // A BLOCKED signal (§19.12-19.14) only while it is still true: at the
    // limit it names. Raised meanwhile (the MAX_* it asked for came), it says
    // nothing any more — when it would first go, and when lost and resent.
    if (key === 'db') return stored.limit === context.remote_max_data ? stored : null;
    if (key === 'sb_bidi') return stored.limit === context.remote_max_streams_bidi ? stored : null;
    if (key === 'sb_uni') return stored.limit === context.remote_max_streams_uni ? stored : null;
    if (key.indexOf('sdb:') === 0) {
      var sst = context.send_streams[stored.id];
      return sst && sst.remote_max_stream_data === stored.limit ? stored : null;
    }
    if (key === 'af') {
      // ack-frequency §4: only the latest request is worth resending; an
      // older one lost while a newer is out has been superseded.
      return stored.seq === context.af_seq - 1 ? stored : null;
    }
    // 'rs:<id>': the same frame every time — its content MUST NOT change
    // (§13.3); 'rcid:', 'nt', 'crypto:' likewise, until acknowledged.
    return stored;
  }

  // Which queue entry each frame handed out by takeControlFrames came from:
  // sendFrames reads it to track the frames by the packet that carries them,
  // or to put them back if that packet never leaves.
  var controlOrigin = new WeakMap();

  // The queued control frames that fit in `room` bytes, built with the
  // values of this moment and taken off the queue. What does not fit stays
  // for the next packet. Every 1-RTT packet takes them first, after its ACK
  // (sendFrames, execute_quic_burst) — as other implementations build a
  // packet: ACK, control frames, then data filling the rest.
  function takeControlFrames(room) {
    var out = [], used = 0;
    for (var key in context.control_queue) {
      var stored = context.control_queue[key];
      var f = materializeControl(key, stored);
      if (!f) { delete context.control_queue[key]; continue; }
      var len = quic_frames_size([f]);
      if (used + len > room) continue;
      delete context.control_queue[key];
      controlOrigin.set(f, { key: key, stored: stored, frame: f });
      out.push(f);
      used += len;
    }
    return out;
  }

  // A packet with control frames in it is on its way (pn committed): they
  // are tracked by it until acknowledged (ackControl) or deemed lost
  // (controlTick).
  function controlFramesSent(pn, frameList) {
    var entries = null;
    for (var i = 0; i < frameList.length; i++) {
      var o = controlOrigin.get(frameList[i]);
      if (!o) continue;
      controlOrigin.delete(frameList[i]);
      (entries || (entries = [])).push(o);
    }
    if (!entries) return;
    var now = Date.now();
    context.control_in_flight[pn] = { entries: entries, deadline: now + retxTimeout() };
    scheduleControlTimer();
  }

  // A packet with control frames in it did not leave: they go back to the
  // queue — under their key, unless something newer took it meanwhile.
  function controlFramesUnsent(frameList) {
    for (var i = 0; i < frameList.length; i++) {
      var o = controlOrigin.get(frameList[i]);
      if (!o) continue;
      controlOrigin.delete(frameList[i]);
      if (!(o.key in context.control_queue)) context.control_queue[o.key] = o.stored;
    }
  }

  // What is still queued at the end of the turn, when no packet took it:
  // a pass of the send planner, which puts it in packets of their own —
  // paced and within the congestion window, as every ack-eliciting packet
  // (RFC 9002 §7), and as many as it takes (a client cancelling a whole page
  // queues a burst of resets). They used to leave here directly, outside both.
  function flushControl() {
    context.control_flush_pending = false;
    if (!context.app_write) return;
    if (context.state === 'draining' || context.state === 'closed' || context.state === 'closing') {
      context.control_queue = {};
      return;
    }
    if (!hasQueuedControl()) return;
    context.control_due = true;
    plan_quic_burst();
  }

  // The retransmission timeout, of stream data (expireInFlight) and control
  // frames alike: the PTO (RFC 9002 §6.2.1), doubled for each one that has
  // gone by without an ACK — since the last ACK, or since the first packet
  // sent after it when that came later (backoff_since).
  function retxTimeout() {
    var base = ptoBase();
    var since = Date.now() - Math.max(context.last_ack_time, context.backoff_since);
    var mult = 1;
    while (since > base * mult * 2 && mult < 1024) mult *= 2;
    return base * mult;
  }

  // Its own timer, not expireInFlight: that one runs from the burst planner,
  // which does not run at all when there is no stream data — exactly when a
  // lone RESET_STREAM, or a MAX_STREAMS for a blocked peer, needs resending.
  // Each packet's deadline is fixed when it is sent (controlFramesSent), with
  // the backoff in force then. Measured against the timeout of the moment
  // instead — which grows with the time since the last ACK — a packet resent
  // during an outage never caught up with it: the timer woke a timeout
  // later, by when the timeout had doubled, and the resend never went.
  function scheduleControlTimer() {
    if (context.control_timer !== null) return;
    var first = Infinity;
    for (var k in context.control_in_flight) first = Math.min(first, context.control_in_flight[k].deadline);
    if (first === Infinity) return;
    context.control_timer = setTimeout(controlTick, Math.max(5, Math.ceil(first - Date.now())));
    if (context.control_timer.unref) context.control_timer.unref();
  }

  function stopControlRetx() {
    if (context.control_timer !== null) { clearTimeout(context.control_timer); context.control_timer = null; }
    context.control_in_flight = {};
    context.control_queue = {};
  }

  // A packet carrying control frames deemed lost: each is queued again under
  // its key, and built afresh when it goes — MAX_* with their CURRENT value
  // (§13.3), what is no longer needed not at all (materializeControl). A key
  // queued again meanwhile keeps the newer entry.
  function controlTick() {
    context.control_timer = null;
    if (context.state !== 'connected') return;
    var now = Date.now(), lost = false;
    for (var pn in context.control_in_flight) {
      var entry = context.control_in_flight[pn];
      if (now < entry.deadline) continue;
      delete context.control_in_flight[pn];
      // Out of the bytes in flight — unless it carried stream data or
      // datagrams too: that packet is expireInFlight's to give up on, with
      // its data, on its own clock.
      if (!context.sending_app_pn_in_flight.has(Number(pn))) forgetPacket(Number(pn));
      lost = true;
      for (var i = 0; i < entry.entries.length; i++) {
        var e = entry.entries[i];
        if (!(e.key in context.control_queue)) queueControl(e.key, e.stored);
      }
    }
    if (lost) flushControl();
    scheduleControlTimer();
  }

  // A packet carrying control frames given up on before its deadline (its
  // datagram known lost, expireAppPacket): its frames queued again.
  function controlPacketLost(pn) {
    var entry = context.control_in_flight[pn];
    if (!entry) return;
    delete context.control_in_flight[pn];
    for (var i = 0; i < entry.entries.length; i++) {
      var e = entry.entries[i];
      if (!(e.key in context.control_queue)) queueControl(e.key, e.stored);
    }
  }

  // An ACK covered these control packets.
  function ackControl(ackedRanges) {
    for (var cpn in context.control_in_flight) {
      var p = Number(cpn), hit = false;
      for (var r = 0; r < ackedRanges.length; r += 2) {
        if (p >= ackedRanges[r] && p <= ackedRanges[r + 1]) { hit = true; break; }
      }
      if (!hit) continue;
      var entries = context.control_in_flight[cpn].entries;
      delete context.control_in_flight[cpn];
      for (var i = 0; i < entries.length; i++) {
        // RESET_STREAM acknowledged: the sending part is "Reset Recvd"
        // (RFC 9000 §3.1), terminal — the stream's credit can come back.
        var f = entries[i].frame;
        if (f.type === 'reset_stream') markStreamSideDone(f.id, 'send');
        else if (f.type === 'reset_stream_at') {
          // Its sending part is over once the reliable bytes are
          // acknowledged as well (resetAtProgress).
          var ras = context.reset_at_sent[f.id];
          if (ras && ras.reliable === f.reliableSize) {
            ras.frameAcked = true;
            if (ras.dataAcked) { delete context.reset_at_sent[f.id]; markStreamSideDone(f.id, 'send'); }
          }
        }
        else if (f.type === 'retire_connection_id') context.peer_cids_retiring.delete(f.seq);
      }
    }
  }


  // ============================================================
  //  Aborting streams: RESET_STREAM and STOP_SENDING (RFC 9000 §3.1-3.5)
  // ============================================================

  /**
   * Abandon the SENDING part of a stream: RESET_STREAM with `errorCode`.
   *
   * Nothing queued for the stream is sent after this, and nothing already
   * sent is retransmitted (§13.3). The final size is the highest offset ever
   * sent, which the peer must see exactly — its flow control has counted it.
   * Returns false when there is nothing to reset: a stream we cannot send on,
   * one already reset, or one whose data has all been delivered.
   */
  // An application error code, as RESET_STREAM and STOP_SENDING carry it: a
  // varint, up to 2^62 - 1 (RFC 9000 §20.2) — here up to 2^53 - 1, what a
  // Number holds exactly. It was cut to 32 bits (>>> 0), and WebTransport's
  // codes, mapped into HTTP/3's space above 2^46, came out as other numbers.
  function appErrorCode(code) {
    code = Number(code);
    return (code >= 0 && code <= Number.MAX_SAFE_INTEGER && Math.floor(code) === code) ? code : 0;
  }

  // reliableSize (optional): RESET_STREAM_AT (draft-ietf-quic-reliable-
  // stream-reset) — the stream's first reliableSize bytes are still
  // delivered, sent and resent as before; what lies past them is dropped and
  // never resent, and the peer's reading ends there with the code. Only when
  // the peer took it (its reset_stream_at transport parameter); otherwise,
  // and for 0, a RESET_STREAM. A stream given a smaller reliable size again,
  // or a plain RESET_STREAM after it, keeps its first code and final size
  // (the frames MUST NOT change them).
  function resetStream(streamId, errorCode, reliableSize) {
    streamId = Number(streamId);
    // A unidirectional stream the peer opened has no sending part here.
    if ((streamId & 2) !== 0 && streamIsPeerInitiated(streamId)) return false;
    if (context.send_final.has(streamId)) return false;   // already reset, or all data delivered
    noteLocalStream(streamId);

    var st = context.send_streams[streamId];
    var ra = st && st.reset_at;
    var keep = reliableSize > 0 && context.peer_reset_stream_at && st ? Math.min(Math.floor(reliableSize), st.write_offset) : 0;
    if (ra && keep >= ra.reliable) return true;            // MUST NOT grow; the same again is nothing new
    if (keep > 0) return resetStreamAt(streamId, st, ra ? ra.error : appErrorCode(errorCode), keep);

    // The final size: a RESET_STREAM_AT's before it; the FIN's, once a FIN
    // has gone (a reset after end(): §3.1 allows it until all is
    // acknowledged, and the size the FIN told MUST stay, §4.5); otherwise
    // what was sent.
    var finalSize = ra && ra.finalSize !== null ? ra.finalSize : (st ? (st.fin_went ? st.total_size : st.max_sent_offset) : 0);
    var code = ra ? ra.error : appErrorCode(errorCode);
    rememberFinal(context.send_final, streamId, -1);
    delete context.stream_priority[streamId];
    if (st) {
      releaseStreamInFlight(st);
      checkSentWait(st, true);
      delete context.send_streams[streamId];
      delete context.remote_max_stream_data_by_sid[streamId];
      delete context.last_stream_blocked_sent[streamId];
    }
    delete context.reset_at_sent[streamId];
    queueControl('rs:' + streamId, { type: 'reset_stream', id: streamId, error: code, finalSize: finalSize });
    if (serverStats && !ra) serverStats.code(serverStats.streamResets.h3.sent, code);
    if (DEBUG) console.log('[quic] RESET_STREAM out stream=' + streamId + ' error=' + code + ' finalSize=' + finalSize);
    return true;
  }

  // ── RESET_STREAM_AT, the sending side ───────────────────────────────────
  //
  // The stream ends at `reliable`: what was written past it is dropped —
  // the queue cut there, its bytes no longer missing, and those in flight
  // no longer resent when lost (moved to no_resend_in_flight, as a reset
  // stream's are) — and no FIN goes. What lies below goes on being sent and
  // resent as any stream's. The frame waits until all of it has been sent
  // once: its final size is then what was sent, inside the flow-control
  // limits by construction (the draft: the sender "MUST NOT" exceed them).
  // The stream leaves once its first `reliable` bytes are acknowledged; its
  // sending part is over ("Reset Recvd") when the frame is too.
  function resetStreamAt(streamId, st, code, reliable) {
    var first = !st.reset_at;
    st.reset_at = { error: code, reliable: reliable, finalSize: st.reset_at ? st.reset_at.finalSize : null,
                    finSize: st.reset_at ? st.reset_at.finSize : (st.fin_went ? st.total_size : null) };
    // The queue, cut at `reliable`.
    if (st.write_offset > reliable) {
      while (st.q.length > st.q_head && st.q_off[st.q.length - 1] >= reliable) {
        var gone = st.q.pop(); st.q_off.pop();
        st.queue_bytes -= gone.byteLength;
      }
      var last = st.q.length - 1;
      if (last >= st.q_head && st.q_off[last] + st.q[last].byteLength > reliable) {
        var keepLen = reliable - st.q_off[last];
        st.queue_bytes -= st.q[last].byteLength - keepLen;
        st.q[last] = st.q[last].subarray(0, keepLen);
      }
      st.tail_buf = null;
      st.write_offset = reliable;
    }
    flat_ranges.remove(st.missing_ranges, [reliable, Number.MAX_SAFE_INTEGER]);
    for (var pn in st.in_flight_ranges) {
      var past = flat_ranges.intersect(st.in_flight_ranges[pn], [reliable, Number.MAX_SAFE_INTEGER]);
      var n = flat_ranges.length(past);
      if (n === 0) continue;
      context.no_resend_in_flight[pn] = (context.no_resend_in_flight[pn] || 0) + n;
      flat_ranges.remove(st.in_flight_ranges[pn], [reliable, Number.MAX_SAFE_INTEGER]);
      if (st.in_flight_ranges[pn].length === 0) delete st.in_flight_ranges[pn];
    }
    // No FIN from now on — not again either: one that went stands, its
    // size is the final size (finSize).
    st.fin_set = false;
    checkSentWait(st, true);          // the writer is released: nothing more goes
    if (first && serverStats) serverStats.code(serverStats.streamResets.h3.sent, code);
    if (DEBUG) console.log('[quic] RESET_STREAM_AT stream=' + streamId + ' error=' + code + ' reliable=' + reliable);
    resetAtProgress(streamId, st);
    scheduleSend();
    return true;
  }

  // The frame, once the reliable part has been sent whole; the stream's end,
  // once that part is acknowledged. Called at the reset, as bytes are sent,
  // and as they are acknowledged.
  function resetAtProgress(streamId, st) {
    var ra = st.reset_at;
    if (!ra) return;
    if (ra.finalSize === null && st.max_sent_offset >= ra.reliable) {
      ra.finalSize = ra.finSize !== null ? ra.finSize : st.max_sent_offset;
    }
    if (ra.finalSize !== null) {
      var sent = context.reset_at_sent[streamId];
      if (!sent || sent.reliable !== ra.reliable) {
        context.reset_at_sent[streamId] = { reliable: ra.reliable, frameAcked: false };
        queueControl('rs:' + streamId, { type: 'reset_stream_at', id: streamId, error: ra.error, finalSize: ra.finalSize, reliableSize: ra.reliable });
      }
    }
    var acked = ra.reliable === 0 || (st.acked_ranges.length >= 2 && st.acked_ranges[0] === 0 && st.acked_ranges[1] >= ra.reliable);
    if (ra.finalSize !== null && acked) {
      releaseStreamInFlight(st);
      delete context.stream_priority[streamId];
      delete context.send_streams[streamId];
      delete context.remote_max_stream_data_by_sid[streamId];
      delete context.last_stream_blocked_sent[streamId];
      rememberFinal(context.send_final, streamId, -1);
      var rs = context.reset_at_sent[streamId];
      if (rs) { rs.dataAcked = true; if (rs.frameAcked) { delete context.reset_at_sent[streamId]; markStreamSideDone(streamId, 'send'); } }
    }
  }

  /**
   * Stop reading a stream: ask the peer, with STOP_SENDING, to stop sending
   * on it. What still arrives meanwhile is counted for flow control and then
   * dropped; the peer answers with RESET_STREAM (§3.5), which ends it.
   */
  function stopSending(streamId, errorCode) {
    streamId = Number(streamId);
    // A unidirectional stream WE opened has no receiving part here.
    if ((streamId & 2) !== 0 && !streamIsPeerInitiated(streamId)) return false;
    if (context.recv_final.has(streamId)) return false;   // the peer is done sending already
    var rs = context.recv_streams[streamId];
    // A stream open on the receiving side that has seen no data yet still
    // gets its state now: what arrives after this is not for the application,
    // and without the mark it would be delivered as if nothing had happened.
    if (!rs && context.recv_open.has(streamId)) rs = context.recv_streams[streamId] = newRecvStream(streamId);
    if (rs) {
      if (rs.stopped) return false;
      rs.stopped = true;
      rs.chunks = new Map();   // never to be read; the credit returns at the end
    }
    releaseStreamCredit(streamId);   // what was delivered will not be read either
    queueControl('ss:' + streamId, { type: 'stop_sending', id: streamId, error: appErrorCode(errorCode) });
    return true;
  }

  // ── Receive credit returned as the application reads ─────────────────
  //
  // By default a stream's bytes count as consumed when they are delivered
  // (flushStream): the window slides on, and the peer may send more, whether
  // or not anything above has read what it already sent. A request body that
  // the application had not started reading — a handler waiting on a lookup
  // before it reads — was taken in as fast as the client could send it, all
  // of it held in memory: tens of MB a second, without bound.
  //
  // A layer above can take that over, per stream, from the stream's first
  // byte: creditPolicy(sid) → true (h3 does it for request streams on the
  // server). The stream's delivered bytes are then held — not credited, at
  // the stream or the connection level — until creditStream(sid, n) says n
  // of them have been dealt with, or releaseStreamCredit(sid) says the rest
  // will not be waited for (the stream ended, was reset or abandoned, or
  // turned into something else); after that the stream is credited on
  // delivery again. The peer is then held to what the application can take,
  // as HTTP/2 is by its windows, and TCP by the socket's.
  var creditPolicy = null;
  var heldCredit = {};   // sid → bytes delivered and not yet credited

  function creditStream(streamId, n) {
    var sid = Number(streamId);
    var held = heldCredit[sid];
    if (held === undefined || !(n > 0)) return;
    if (n > held) n = held;
    heldCredit[sid] = held - n;
    grantStreamCredit(sid, n);
  }

  function releaseStreamCredit(streamId) {
    var sid = Number(streamId);
    var held = heldCredit[sid];
    if (held === undefined) return;
    delete heldCredit[sid];
    if (held > 0) grantStreamCredit(sid, held);
  }

  // n bytes of the stream consumed: the connection window, and the stream's.
  function grantStreamCredit(sid, n) {
    releaseConnCredit(n);
    var stream = context.recv_streams[sid];
    if (stream && !stream.fin_emitted && !stream.stopped) slideStreamWindow(sid, stream);
  }

  // ── Receive window autotuning ─────────────────────────────────────────
  //
  // A window caps what the peer sends to one window a round trip: 256 KB a
  // stream is 10 Mbit/s at 200 ms — a client downloaded 4 MB over a 20 Mbit/s,
  // 200 ms link in 7.8 s where Chromium took 3.1 s, and a server took an
  // upload no faster. A larger fixed window holds as much memory for every
  // stream, slow ones included. So, as Chromium and quiche do: a window that
  // the application consumed half of within two round trips of the last
  // update — the window, not the path, is what limits — doubles, up to 16 MB
  // a stream and 24 MB the connection (quiche's ceilings; a larger initial
  // window set in transportParams stays as it is). The connection's grows
  // with its streams, to 1.5× the largest, or one stream would fill it. It
  // grows with what the application consumes — credit-on-read (creditStream)
  // included — so a reader that falls behind never grows it.
  var MAX_STREAM_WINDOW = 16 * 1024 * 1024;
  var MAX_CONN_WINDOW = 24 * 1024 * 1024;

  // Whether a window slid at `lastAt` and sliding again now was limiting.
  function windowLimiting(lastAt, now) {
    return lastAt > 0 && context.srtt > 0 && now - lastAt < 2 * context.srtt;
  }

  // The stream-level rule of flushStream: once what has been consumed is half
  // a window past the last advertisement, advertise consumed + W.
  function slideStreamWindow(sid, stream) {
    var consumed = stream.flushed_to - (heldCredit[sid] || 0);
    var Ws = stream.window;
    if (consumed + Ws - stream.local_max_stream_data >= Ws / 2) {
      var now = Date.now();
      if (windowLimiting(stream.window_at, now) && Ws < MAX_STREAM_WINDOW) {
        stream.window = Ws = Math.min(Ws * 2, MAX_STREAM_WINDOW);
        var connMin = Math.min(Math.floor(Ws * 1.5), MAX_CONN_WINDOW);
        if (context.local_max_data_window < connMin) context.local_max_data_window = connMin;
      }
      stream.window_at = now;
      stream.local_max_stream_data = consumed + Ws;
      queueControl('msd:' + Number(sid));
    }
  }

  // The connection-level rule, for delivery and for released credit alike.
  function slideConnWindow() {
    var W = context.local_max_data_window;
    if (context.local_max_data_consumed + W - context.local_max_data >= W / 2) {
      var now = Date.now();
      if (windowLimiting(context.local_max_data_at, now) && W < MAX_CONN_WINDOW) {
        context.local_max_data_window = W = Math.min(W * 2, MAX_CONN_WINDOW);
      }
      context.local_max_data_at = now;
      context.local_max_data = context.local_max_data_consumed + W;
      queueControl('max_data');
    }
  }

  // Bytes of the connection window released by a stream that will never
  // deliver them (a reset one): counted as consumed, so the window keeps
  // sliding (RFC 9000 §4.5). Same rule as delivery.
  function releaseConnCredit(bytes) {
    if (bytes <= 0) return;
    context.local_max_data_consumed += bytes;
    slideConnWindow();
  }


  // ============================================================
  //  Stream credit: MAX_STREAMS
  // ============================================================

  function streamIsPeerInitiated(sid) {
    // Bit 0 of a stream ID is the initiator: 0 client, 1 server.
    return (sid & 1) === (context.isServer ? 0 : 1);
  }

  /**
   * One direction of a peer-initiated stream has finished — received in full
   * (or reset by the peer), or sent and acknowledged in full (or stopped by
   * the peer). When both have, the stream is closed and its credit returns.
   *
   * A unidirectional stream the peer opened has only a receive side.
   */
  function markStreamSideDone(sid, side) {
    sid = Number(sid);
    if (!streamIsPeerInitiated(sid)) return;
    var bidi = (sid & 2) === 0;
    var d = context.stream_sides_done[sid];
    if (!d) d = context.stream_sides_done[sid] = { recv: false, send: !bidi };
    if (d[side]) return;
    d[side] = true;
    if (!d.recv || !d.send) return;
    delete context.stream_sides_done[sid];
    delete context.remote_max_stream_data_by_sid[sid];

    if (bidi) context.peer_streams_closed_bidi++;
    else context.peer_streams_closed_uni++;

    // Sent from a fresh tick: a close is detected while processing an ACK or a
    // frame, and sending a packet from inside that loop is not safe.
    if (!context.max_streams_flush_pending) {
      context.max_streams_flush_pending = true;
      setImmediate(flushMaxStreams);
    }
  }

  /**
   * Give the peer its streams back. The target keeps the same number of
   * unopened streams available as at the start — closed + initial — and a
   * frame goes out only once half of that headroom has been used, so a single
   * MAX_STREAMS covers dozens of closes rather than one frame per request —
   * or once the peer has none left to open. Waiting for half alone, a small
   * limit could never be raised: with initial_max_streams_uni 4, three held
   * for good by HTTP/3, the peer has one stream open at a time and can never
   * close two — it waited for good.
   */
  function flushMaxStreams() {
    context.max_streams_flush_pending = false;
    if (context.state !== 'connected') return;
    var tp = localTp;
    // Queued, not sent directly: the control queue retransmits it with the
    // current limit if it is lost (RFC 9000 §13.3).
    var bidiTarget = context.peer_streams_closed_bidi + tp.initial_max_streams_bidi;
    if (shouldRaise(bidiTarget, context.local_max_streams_bidi, context.peer_max_opened_bidi, tp.initial_max_streams_bidi)) {
      context.local_max_streams_bidi = bidiTarget;
      queueControl('ms_bidi');
    }
    var uniTarget = context.peer_streams_closed_uni + tp.initial_max_streams_uni;
    if (shouldRaise(uniTarget, context.local_max_streams_uni, context.peer_max_opened_uni, tp.initial_max_streams_uni)) {
      context.local_max_streams_uni = uniTarget;
      queueControl('ms_uni');
    }
  }
  function shouldRaise(target, current, maxOpenedIndex, initial) {
    if (target <= current) return false;
    var leftToOpen = current - (maxOpenedIndex + 1);
    return target - current >= Math.ceil(initial / 2) || leftToOpen <= 0;
  }


  /**
   * The peer abandoned its sending part (RESET_STREAM). Returns false if the
   * frame broke the rules and the connection is being closed for it.
   *
   * Flow control first (RFC 9000 §4.5): the final size is what the peer has
   * charged to both windows, whether or not those bytes ever reach us — so
   * usage rises to it, and the part never delivered is released as consumed.
   * Skipping this shrank the connection window by every cancelled request's
   * undelivered bytes, for the life of the connection.
   *
   * Then the application: 'stream_reset'. It used to be told nothing — a
   * browser cancelling a request left the handler writing a response to
   * nobody, and a burst of cancellations (Rapid Reset) was invisible.
   */
  function onPeerReset(frame) {
    var sid = Number(frame.id);
    if (context.recv_final.has(sid)) return true;          // a repeat, or after FIN: done already
    var rs = context.recv_streams[sid];
    var at = frame.type === 'reset_stream_at';
    var name = at ? 'RESET_STREAM_AT' : 'RESET_STREAM';
    // RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset §4): a reliable
    // size past the final size is FRAME_ENCODING_ERROR; after an earlier
    // one, another code is STREAM_STATE_ERROR (the final size is checked as
    // a FIN's below: has_final). A larger reliable size than before is
    // ignored (reordering), a smaller one taken.
    if (at && frame.reliableSize > frame.finalSize) { close(0x07, 'RESET_STREAM_AT reliable size beyond its final size'); return false; }
    var prior = rs && rs.reset_at;
    if (prior && frame.error !== prior.error) { close(0x05, name + ' with another error code than its earlier RESET_STREAM_AT'); return false; }
    var high = rs ? rs.max_recv_offset : 0;

    // §4.5: a final size below what was already received, or different from
    // a FIN's, is FINAL_SIZE_ERROR (0x06).
    if (frame.finalSize < high || (rs && rs.has_final && frame.finalSize !== rs.total_size)) {
      close(0x06, 'final size mismatch in ' + name);
      return false;
    }
    var limit = rs ? rs.local_max_stream_data : localStreamWindow(sid);
    if (frame.finalSize > limit || context.fc_recv_usage + (frame.finalSize - high) > context.local_max_data) {
      close(0x03, name + ' final size beyond flow control');
      return false;
    }
    context.fc_recv_usage += frame.finalSize - high;

    // Its first reliableSize bytes still to be delivered: the stream stays
    // until they are (flushStream ends it there, resetAtDelivered); the
    // final size is known, usage is charged to it. What lies past them is
    // not delivered. Already delivered — or a stream we stopped reading —
    // it ends now, as for RESET_STREAM.
    var reliable = at ? frame.reliableSize : 0;
    if (prior) reliable = Math.min(reliable, prior.reliable);
    if (reliable > 0 && (rs || context.recv_open.has(sid)) && !(rs && rs.stopped) && (rs ? rs.flushed_to : 0) < reliable) {
      if (!rs) rs = context.recv_streams[sid] = newRecvStream(sid);
      rs.reset_at = { error: frame.error, reliable: reliable, finalSize: frame.finalSize };
      rs.has_final = true;
      rs.total_size = frame.finalSize;
      rs.max_recv_offset = frame.finalSize;
      if (DEBUG) console.log('[quic] RESET_STREAM_AT in stream=' + sid + ' error=' + frame.error + ' reliable=' + reliable + ' finalSize=' + frame.finalSize);
      flushStream(sid);
      return true;
    }
    endPeerReset(sid, rs, frame.error, frame.finalSize);
    return true;
  }

  // The receiving part ends with the peer's reset: the credit its final size
  // took comes back, and the application hears it ('stream_reset').
  function endPeerReset(sid, rs, error, finalSize) {
    releaseConnCredit(finalSize - (rs ? rs.flushed_to : 0));
    releaseStreamCredit(sid);
    recvSideClosed(sid, finalSize);
    if (rs) delete context.recv_streams[sid];
    markStreamSideDone(sid, 'recv');
    if (DEBUG) console.log('[quic] stream ' + sid + ' reset by the peer, error=' + error + ' finalSize=' + finalSize);
    ev.emit('stream_reset', sid, error, finalSize);
  }

  // ============================================================
  //  Stream receive
  // ============================================================

  // ── Stream ID validation (RFC 9000 §2.1, §4.6, §19.4-§19.13) ──────────
  //
  // Every frame that names a stream comes through here first. `use` is the
  // part of the stream the frame touches on OUR side: 'recv' for STREAM,
  // RESET_STREAM and STREAM_DATA_BLOCKED (the peer is sending), 'send' for
  // STOP_SENDING and MAX_STREAM_DATA (about what we send).
  //
  // Returns 'ok' when the frame may be processed, 'closed' when it is for a
  // stream whose receiving part is already over (a late retransmission —
  // §3.2 says to discard it), or false when it broke the rules and the
  // connection is being closed for it.
  //
  // Without this, nothing bounded how many streams a peer could open: no ID
  // was compared with the MAX_STREAMS we advertised, so a peer could open
  // streams without limit — a zero-length STREAM frame each, charging no
  // flow control at all — and every one became a request above.
  var STREAM_LIMIT_ERROR = 0x04, STREAM_STATE_ERROR = 0x05;

  function checkStreamId(sid, use) {
    sid = Number(sid);
    if (!Number.isSafeInteger(sid) || sid < 0) { close(STREAM_LIMIT_ERROR, 'stream ID out of range'); return false; }
    var uni = (sid % 4) >= 2;
    var index = Math.floor(sid / 4);
    var peer = streamIsPeerInitiated(sid);

    // A unidirectional stream has one part only: the opener's sending part
    // and the other side's receiving part. A frame for the part that does not
    // exist is STREAM_STATE_ERROR (§19.4, §19.5, §19.8, §19.10, §19.13).
    if (uni && peer && use === 'send') { close(STREAM_STATE_ERROR, 'send-side frame for a receive-only stream'); return false; }
    if (uni && !peer && use === 'recv') { close(STREAM_STATE_ERROR, 'data for a send-only stream'); return false; }

    if (!peer) {
      // §19.8 and others: a frame for a locally initiated stream that has not
      // been created yet is STREAM_STATE_ERROR.
      var localMax = uni ? context.local_max_opened_uni : context.local_max_opened_bidi;
      if (index > localMax) { close(STREAM_STATE_ERROR, 'frame for a stream we have not opened'); return false; }
      if (use === 'recv' && !context.recv_open.has(sid)) return 'closed';
      return 'ok';
    }

    // §4.6: a stream ID beyond the limit we advertised is STREAM_LIMIT_ERROR.
    var limit = uni ? context.local_max_streams_uni : context.local_max_streams_bidi;
    if (index >= limit) { close(STREAM_LIMIT_ERROR, 'stream ID beyond MAX_STREAMS'); return false; }

    // §3.2: opening a stream opens every lower-numbered stream of its type.
    // The gap is bounded by the limit just checked.
    var opened = uni ? context.peer_max_opened_uni : context.peer_max_opened_bidi;
    if (index > opened) {
      var low = sid % 4;
      for (var i = opened + 1; i <= index; i++) context.recv_open.add(i * 4 + low);
      if (uni) context.peer_max_opened_uni = index; else context.peer_max_opened_bidi = index;
    }
    if (use === 'recv' && !context.recv_open.has(sid)) return 'closed';
    return 'ok';
  }

  // The next stream of our own in a direction: the lowest number not yet
  // opened (RFC 9000 §2.1 — client bidi 0, 4…; server bidi 1, 5…; client uni
  // 2, 6…; server uni 3, 7…). It is opened, and taken, by the first sendStream
  // on it. Layers above guessed instead — h3 started WebTransport streams at a
  // fixed 15, webtransport.js at 4 and 14 — right only while nothing else had
  // opened a stream in between.
  function nextLocalStreamId(bidi) {
    var base = context.isServer ? 1 : 0;
    return bidi ? (context.local_max_opened_bidi + 1) * 4 + base
                : (context.local_max_opened_uni + 1) * 4 + base + 2;
  }

  // A stream we open: remembered so frames for it are accepted, and its
  // receiving part (bidirectional only) tracked as open.
  function noteLocalStream(sid) {
    sid = Number(sid);
    if (streamIsPeerInitiated(sid)) return;
    var uni = (sid % 4) >= 2;
    var index = Math.floor(sid / 4);
    if (uni) { if (index > context.local_max_opened_uni) context.local_max_opened_uni = index; return; }
    if (index > context.local_max_opened_bidi) {
      // Lower IDs are implicitly opened too (§3.2) — same rule as the peer's.
      for (var i = context.local_max_opened_bidi + 1; i <= index; i++) context.recv_open.add(i * 4 + (sid % 4));
      context.local_max_opened_bidi = index;
    }
  }

  // Whether our sending part of a (validated) stream is still open.
  function sendSideOpen(sid) {
    sid = Number(sid);
    if (sid in context.send_streams) return true;
    if (context.send_final.has(sid)) return false;
    // A stream we opened always has send state until its sending part ends.
    if (!streamIsPeerInitiated(sid)) return false;
    // The peer's bidirectional stream: one side done is recorded in
    // stream_sides_done; with neither done, its receiving part is open.
    var d = context.stream_sides_done[sid];
    if (d) return !d.send;
    return context.recv_open.has(sid);
  }

  // Whether a stream's sending part is open or still to come: the peer's
  // bidirectional stream with its sending part open, or a stream of ours
  // sending now or not yet opened. (A peer's unidirectional stream has none.)
  function sendSideAhead(sid) {
    if (sid in context.send_streams) return true;
    if (streamIsPeerInitiated(sid)) return (sid & 2) === 0 && sendSideOpen(sid);
    var index = Math.floor(sid / 4);
    return index > ((sid & 2) ? context.local_max_opened_uni : context.local_max_opened_bidi);
  }

  // ── Our side of the stream limits (RFC 9000 §4.6) ─────────────────────
  //
  // A stream we open counts against the MAX_STREAMS the peer granted us; one
  // past it may not be sent on until a MAX_STREAMS raises the limit —
  // sending anyway is the peer's STREAM_LIMIT_ERROR. This was not enforced
  // ("future work"): stream IDs are chosen above this layer (h3_client, the
  // agent's pooled connections), and a burst of requests on one connection
  // went straight past the limit. Now such a stream simply waits: its data is
  // queued, it is not scheduled, and STREAMS_BLOCKED tells the peer why.
  function localStreamPermitted(sid) {
    sid = Number(sid);
    if (streamIsPeerInitiated(sid)) return true;
    var uni = (sid % 4) >= 2;
    var limit = uni ? context.remote_max_streams_uni : context.remote_max_streams_bidi;
    if (Math.floor(sid / 4) < limit) return true;
    if (uni) context.streams_blocked_uni = true; else context.streams_blocked_bidi = true;
    return false;
  }

  // The receiving part of a stream is over: FIN delivered, or reset.
  function recvSideClosed(sid, finalSize) {
    sid = Number(sid);
    context.recv_open.delete(sid);
    rememberFinal(context.recv_final, sid, finalSize);
  }

  // Out-of-order reassembly limits, per stream. Every stored piece costs an
  // object and a Map entry beyond its bytes, and every gap a range; a peer
  // sending one-byte frames into a 256 KB window could store ~130,000 of
  // each — legal traffic, all inside flow control — and the old flush
  // scanned every stored chunk on every frame (quadratic). Gaps are capped
  // (quic-go caps them at 1000 too); pieces are compacted into one buffer
  // per contiguous run when they outnumber the gaps — and the bytes held:
  // compacting copies every byte held, so it waits for a piece per
  // COMPACT_BYTES_PER_PIECE of them. Triggered by the piece count alone, a
  // gap at the cursor with one-byte frames behind it had the whole run
  // copied again every 256 frames: quadratic in the window (a 1 MB one,
  // about 2 GB of copying). So each copy is paid for by the pieces that
  // made it necessary, and their overhead stays a fraction of their bytes.
  var MAX_RECV_GAPS = 1000;
  var COMPACT_MIN_PIECES = 256;
  var COMPACT_BYTES_PER_PIECE = 64;

  // First index r (even) in flat ranges with ranges[r + 1] > offset.
  function firstRangeEndingAfter(ranges, offset) {
    var lo = 0, hi = ranges.length >> 1;
    while (lo < hi) {
      var mid = (lo + hi) >> 1;
      if (ranges[mid * 2 + 1] > offset) hi = mid; else lo = mid + 1;
    }
    return lo * 2;
  }

  function compactRecvChunks(stream) {
    var keys = Array.from(stream.chunks.keys()).sort(function (a, b) { return a - b; });
    var out = new Map(), run = [], runStart = -1, runEnd = -1;
    function flushRun() {
      if (run.length) out.set(runStart, run.length === 1 ? run[0] : concatUint8Arrays(run));
      run = [];
    }
    for (var i = 0; i < keys.length; i++) {
      var c = stream.chunks.get(keys[i]);
      if (keys[i] !== runEnd) { flushRun(); runStart = keys[i]; }
      run.push(c);
      runEnd = keys[i] + c.byteLength;
    }
    flushRun();
    stream.chunks = out;
  }

  function newRecvStream(sid) {
    if (creditPolicy && sid !== undefined && !(sid in heldCredit) && creditPolicy(Number(sid))) heldCredit[Number(sid)] = 0;
    return { chunks: new Map(), ranges: [], total_size: 0, flushed_to: 0,
      held: 0,              // bytes in chunks (received ahead of flushed_to)
      has_final: false,     // total_size is known (a FIN arrived) — 0 is a valid final size
      fin_emitted: false,   // end-of-stream delivered to the app exactly once
      max_recv_offset: 0,   // highest offset seen — the peer's FC usage on this stream
      stopped: false,       // we sent STOP_SENDING: nothing more is delivered
      local_max_stream_data: localStreamWindow(sid),
      window: Math.max(localStreamWindow(sid), 1),   // grows (slideStreamWindow)
      window_at: 0 };       // when its window was last slid (ms)
  }

  // The receive window of a stream, by its kind — the initial_max_stream_data_*
  // we sent for it (RFC 9000 §18.2): _uni for the peer's unidirectional
  // streams, _bidi_remote for its bidirectional ones, _bidi_local for ours.
  // One size served all three, and it was not always the one we sent.
  function localStreamWindow(sid) {
    sid = Number(sid);
    if (sid & 2) return localTp.initial_max_stream_data_uni;
    return streamIsPeerInitiated(sid) ? localTp.initial_max_stream_data_bidi_remote : localTp.initial_max_stream_data_bidi_local;
  }

  function processStreamFrame(frame) {
    var sid = frame.id;
    // A stream whose receiving part is over — its FIN delivered, or reset by
    // the peer — takes nothing more (RFC 9000 §3.2: in "Data Read" or "Reset
    // Read" an endpoint discards further STREAM frames). Its state object is
    // gone, and without this check a late retransmission would create a
    // fresh one and hand the bytes to the application a second time.
    var idState = checkStreamId(sid, 'recv');
    if (idState === false) return false;
    if (idState === 'closed' || context.recv_final.has(Number(sid))) return true;
    noteEarlyStream(sid);
    if (!(sid in context.recv_streams)) context.recv_streams[sid] = newRecvStream(sid);
    var stream = context.recv_streams[sid];

    // ── Final size (RFC 9000 §4.5) ──────────────────────────────────────────
    // Data past a known final size, a second FIN with a different size, or a
    // FIN below data already received: FINAL_SIZE_ERROR (0x06).
    var frameEnd = frame.offset + frame.data.length;
    if (stream.has_final ? (frameEnd > stream.total_size || (frame.fin && frameEnd !== stream.total_size))
                         : (frame.fin && frameEnd < stream.max_recv_offset)) {
      close(0x06, 'final size violation in STREAM frame');
      return false;
    }

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
        return false;
      }
      var fcDelta = newHigh - stream.max_recv_offset;
      if (context.fc_recv_usage + fcDelta > context.local_max_data) {
        if (DEBUG) console.log('[quic] FC violation: connection usage ' + (context.fc_recv_usage + fcDelta) + ' > advertised ' + context.local_max_data);
        close(0x03, 'connection flow control exceeded');
        return false;
      }
      stream.max_recv_offset = newHigh;
      context.fc_recv_usage += fcDelta;
    }
    if (frame.fin && !stream.has_final) { stream.has_final = true; stream.total_size = frameEnd; }

    // We sent STOP_SENDING on this stream: the bytes above were charged to
    // flow control, as they must be; nobody is reading them. The peer's
    // RESET_STREAM normally releases the credit and ends the stream — but a
    // peer whose data and FIN were all sent (and acknowledged) before our
    // STOP_SENDING arrived has nothing left to reset, and sends none (§3.5
    // only requires it in "Ready" or "Send"). So the ranges are still
    // tracked, and once every byte up to the final size is in, the stream
    // ends here. It used to stay open for good: a MAX_STREAMS slot and its
    // connection credit lost each time.
    if (stream.stopped) {
      if (frame.data.length > 0) {
        flat_ranges.add(stream.ranges, [frame.offset, frameEnd]);
        if ((stream.ranges.length >> 1) > MAX_RECV_GAPS) {
          close(0x01, 'too many gaps in received stream data');
          return false;
        }
      }
      if (stream.has_final && (stream.total_size === 0 ||
          (stream.ranges.length >= 2 && stream.ranges[0] === 0 && stream.ranges[1] >= stream.total_size))) {
        releaseConnCredit(stream.total_size - stream.flushed_to);
        recvSideClosed(sid, stream.total_size);
        delete context.recv_streams[sid];
        markStreamSideDone(sid, 'recv');
      }
      return true;
    }

    // Store only the bytes not held yet, so stored pieces never overlap and
    // tile `ranges` exactly: the flush then walks them by exact key, with no
    // scan for a piece that straddles the cursor. Bytes already delivered
    // are inside ranges too, so a late retransmission stores nothing.
    var ranges = stream.ranges;
    if (frame.data.length > 0) {
      var pos = frame.offset;
      var r = firstRangeEndingAfter(ranges, pos);
      var stored = 0;
      while (pos < frameEnd) {
        var gapEnd = frameEnd;
        if (r < ranges.length && ranges[r] <= pos) { pos = Math.min(frameEnd, ranges[r + 1]); r += 2; continue; }
        if (r < ranges.length) gapEnd = Math.min(frameEnd, ranges[r]);
        // A piece much smaller than its frame is copied, so a mostly
        // duplicate frame does not keep its whole buffer alive for one byte.
        var piece = frame.data.subarray(pos - frame.offset, gapEnd - frame.offset);
        stream.chunks.set(pos, piece.length * 2 < frame.data.length ? piece.slice() : piece);
        stored += gapEnd - pos;
        pos = gapEnd;
      }
      if (stored > 0) {
        stream.held += stored;
        flat_ranges.add(ranges, [frame.offset, frameEnd]);
        // Raw stat only — FC usage is max_recv_offset above, not this.
        context.bytes_received += stored;
        if ((ranges.length >> 1) > MAX_RECV_GAPS) {
          close(0x01, 'too many gaps in received stream data');
          return false;
        }
        if (stream.chunks.size > Math.max(COMPACT_MIN_PIECES, 4 * (ranges.length >> 1), stream.held / COMPACT_BYTES_PER_PIECE)) compactRecvChunks(stream);
      }
    }
    flushStream(sid);
    return true;
  }

  // (checkLocalFlowControl — the old unbounded ×2 doubling — was replaced by
  //  the consumption-based sliding window inside flushStream above.)

  function flushStream(sid) {
    var stream = context.recv_streams[sid];
    if (!stream) return;
    var parts = [];
    var offset = stream.flushed_to;
    // Walk the in-order prefix. processStreamFrame stores only bytes not held
    // yet, so the pieces never overlap and each one starts exactly where the
    // previous one ends: an exact-key walk, O(1) per piece. (Retransmissions
    // re-slice byte ranges with boundaries that need not match the original
    // transmission's — that is handled at insertion, by trimming.) The old
    // walk, on a missed key, scanned every stored chunk — on every frame
    // while a gap sat at the cursor: quadratic in the chunks a peer stored.
    // RESET_STREAM_AT: delivered up to its reliable size, no further.
    var upTo = stream.reset_at ? stream.reset_at.reliable : Infinity;
    while (offset < upTo) {
      var chunk = stream.chunks.get(offset);
      if (chunk === undefined) break;   // a gap — wait for more data
      stream.chunks.delete(offset);
      if (offset + chunk.byteLength > upTo) { stream.held -= offset + chunk.byteLength - upTo; chunk = chunk.subarray(0, upTo - offset); }
      parts.push(chunk);
      offset += chunk.byteLength;
    }
    var resetNow = !!stream.reset_at && offset >= upTo;
    if (parts.length === 0 && resetNow) { endResetAt(sid, stream); return; }
    if (parts.length === 0) {
      // No bytes to deliver — but the stream may just have COMPLETED. A peer
      // whose final write ends exactly on a packet boundary closes the stream
      // with a zero-length FIN-only frame (quic-go does this for any body
      // that is a multiple of its write-buffer size — a 64 KiB file, say).
      // That frame stores total_size above and lands here with an empty chunk
      // map; returning without emitting means the FIN evaporates: no more
      // frames will ever arrive to re-trigger this flush (retransmits of the
      // empty frame take this same path), the H3 layer never sees http_end,
      // and the request above it waits forever. Emit the end-of-stream event
      // with an empty payload instead — every consumer (h3, hq-interop,
      // tls_bridge) already guards zero-length data.
      if (stream.has_final && offset >= stream.total_size && !stream.fin_emitted) {
        stream.fin_emitted = true;
        ev.emit('stream', Number(sid), new Uint8Array(0), true);
        setTimeout(function () { delete context.recv_streams[sid]; }, 100);
        // Remembered as finished, exactly as the data-carrying end below is.
        // Without it, once the state above is deleted a late retransmission
        // for this stream finds nothing (processStreamFrame checks recv_final
        // only), creates a fresh stream, and charges its bytes to connection
        // flow control a second time — usage that is never consumed, so on a
        // long-lived lossy connection it adds up to a FLOW_CONTROL_ERROR the
        // peer never committed.
        recvSideClosed(sid, stream.total_size);
        markStreamSideDone(sid, 'recv');
      }
      return;
    }
    var delivered = offset - stream.flushed_to;   // in-order bytes handed to the app now
    stream.held -= delivered;
    stream.flushed_to = offset;
    // Held for the application (see creditStream): counted before the
    // delivery, which may already credit some of it.
    if (heldCredit[sid] !== undefined) { heldCredit[sid] += delivered; delivered = 0; }
    var data = parts.length === 1 ? parts[0] : concatUint8Arrays(parts);
    var fin = !stream.reset_at && (stream.has_final && offset >= stream.total_size);
    if (fin) stream.fin_emitted = true;   // a late FIN-only retransmit must not fire a second end
    ev.emit('stream', Number(sid), data, fin);
    if (fin) {
      setTimeout(function () { delete context.recv_streams[sid]; }, 100);
      recvSideClosed(sid, stream.total_size);
      markStreamSideDone(sid, 'recv');
    }

    // ── Sliding window updates (consumption-based; see the context header) ──
    // Both levels use the same rule: once consumption has advanced at least
    // half a window past the last advertisement, advertise consumed + W.
    // Monotonic by construction; a duplicate/lower advert is ignored by the
    // peer, and re-sends on DATA_BLOCKED reuse these same fields.

    // Connection level: consumed = in-order bytes delivered across all streams.
    context.local_max_data_consumed += delivered;
    slideConnWindow();

    // Stream level: consumed = flushed_to. No update after FIN — the stream
    // is done, its final usage stays counted at the connection level.
    if (resetNow) { endResetAt(sid, stream); return; }
    if (!fin && !stream.stopped) slideStreamWindow(sid, stream);
  }

  // A RESET_STREAM_AT's reliable part delivered: the reset now, after it.
  function endResetAt(sid, stream) {
    stream.chunks = new Map();
    endPeerReset(sid, stream, stream.reset_at.error, stream.reset_at.finalSize);
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

    // The round's lowest, for Startup's delay exit — with the peer's ACK
    // delay out of it: an ACK held back (ours asks for that, ACK_FREQUENCY)
    // is not a queue.
    if (context.bbr_round_min_rtt === null || adjusted < context.bbr_round_min_rtt) context.bbr_round_min_rtt = adjusted;
    context.bbr_round_rtt_samples++;
    if (DEBUG) console.log('[quic] rtt: sample=' + latest_rtt + 'ms srtt=' + Math.round(context.srtt) + ' rttvar=' + Math.round(context.rttvar) + ' min=' + context.min_rtt);
  }


  // ============================================================
  //  ACK processing (Phase 1)
  // ============================================================

  // Total app stream bytes currently in flight (unacked). Used by BBR's Drain
  // state to know when the queue built during Startup has been emptied.
  function appBytesInFlight() {
    return context.app_bytes_in_flight;
  }

  // ── Skipped packet numbers (RFC 9000 §21.4) ─────────────────────────────
  // A peer can acknowledge packets it has not received yet — "optimistic
  // ACK" — and the congestion controller, reading a fast clean path, opens
  // the window until the sender floods it. An ACK for a number that was never
  // sent is the one thing it cannot fake around: so, now and then, one 1-RTT
  // number is skipped, and an ACK that covers it closes the connection
  // (PROTOCOL_VIOLATION, processAckFrame). A peer that only acknowledges what
  // arrived never names it. The gap costs it nothing but one ACK range; this
  // stack infers no loss from gaps (expireInFlight is time-based).
  //
  // The skip keeps sending_app_pn_history contiguous — the pn → index math
  // depends on it — with a placeholder of length 0 that no packet carries.
  // Every 256–1023 packets, at random from the system's secure source: a
  // predictable skip is one an optimistic peer can step around.
  function nextSkipGap() {
    return 256 + (((randomByte() << 8) | randomByte()) % 768);
  }

  function skipPacketNumber() {
    var pn = context.send_pn.app;
    context.sending_app_pn_history.push([Date.now(), 0, context.delivered, context.delivered_time]);
    context.send_pn.app = pn + 1;
    context.skipped_pns.push(pn);
    if (context.skipped_pns.length > 8) context.skipped_pns.shift();
    context.pn_skip_countdown = nextSkipGap();
  }

  function acksSkippedNumber(ackedRanges) {
    for (var k = 0; k < context.skipped_pns.length; k++) {
      var spn = context.skipped_pns[k];
      for (var r = 0; r < ackedRanges.length; r += 2) {
        if (spn >= ackedRanges[r] && spn <= ackedRanges[r + 1]) return true;
      }
    }
    return false;
  }


  var BBR_STARTUP_GAIN = 2.89;   // ≈ 2/ln2 — Startup's exponential ramp

  // Careful Resume's jump is out, or being retreated from (RFC 9959 §4.3-4.5):
  // it builds a queue on purpose and has its own response — Startup's delay
  // exit stays out of it.
  function crJumpOut() {
    var cr = context.cr;
    return !!(cr && (cr.phase === 'unvalidated' || cr.phase === 'validating' || cr.phase === 'safe_retreat'));
  }

  // Startup's window growth: by every byte an ACK newly delivers (BBR's
  // BBRSetCwnd before the pipe is known full — TCP's slow start), from the
  // handshake's packets as from the application's, by their size on the wire.
  //
  // Bounded, as BBR v3 bounds it (draft-ietf-ccwg-bbr, BBRSetCwnd): no more
  // than STARTUP_CWND_GAIN × BDP + extra_acked (startupCap). The window
  // still doubles each round while the path keeps up — the BDP measured
  // doubles with it — but once the bottleneck is full and BtlBw stops
  // growing, so does the window: at most a BDP more than the pipe holds,
  // where it went on doubling for the rounds the plateau detector takes to
  // see it (2.89 × BDP and climbing), into a router's queue and past it. Not
  // a loss response: the cap is made of what was delivered, and a loss does
  // not lower it.
  //
  // When it applies is the application's choice (startupCap): 'stall', by
  // default — from the first round in which BtlBw did not grow by a quarter,
  // the rounds the overshoot happens in, and not while the window is still
  // climbing: measured a round late, a BDP can hold a window under what the
  // path already carries, and on a long path with loss that cost a page a
  // round trip (Chromium, 250 ms, 3 %: 1.94 s → 2.16 s with the cap always
  // on, 1.97 s with it from the stall; queue drops at a bottleneck about
  // half of none, a twentieth with it always on). 'always': the whole of
  // Startup — fewest drops, for bulk transfers. 'off': no cap.
  var STARTUP_CWND_GAIN = 2;
  function startupCap() {
    if (context.startup_cap === 'off' || context.bbr_bdp === null || crJumpOut()) return Infinity;
    if (context.startup_cap === 'stall' && context.bbr_full_bw_count < 1) return Infinity;
    return Math.max(context.init_limit_bytes_in_flight, STARTUP_CWND_GAIN * context.bbr_bdp + context.bbr_extra_acked);
  }

  // BBR's extra_acked: bytes acknowledged beyond what BtlBw explains since
  // the interval began (it begins again whenever the ACKs fall behind), at
  // most the window — a round's maximum kept for 10 rounds.
  function bbrExtraAcked(acked, now) {
    if (!(acked > 0) || context.bbr_btlbw === null) return;
    var expected = context.bbr_btlbw * (now - context.bbr_ea_start) / 1000;
    if (context.bbr_ea_delivered <= expected) {
      context.bbr_ea_start = now; context.bbr_ea_delivered = 0; expected = 0;
    }
    context.bbr_ea_delivered += acked;
    var extra = Math.min(context.bbr_ea_delivered - expected, context.current_limit_bytes_in_flight);
    if (extra > context.bbr_ea_round_max) context.bbr_ea_round_max = extra;
  }

  function growStartupWindow(newlyAckedBytes) {
    if (context.bbr_state !== 'startup' || !(newlyAckedBytes > 0)) return;
    var cap = startupCap(), cur = context.current_limit_bytes_in_flight;
    if (cur >= cap) return;
    context.current_limit_bytes_in_flight = Math.min(context.max_limit_bytes_in_flight, cap,
      cur + newlyAckedBytes);
    context.current_limit_packets_in_flight = Math.min(context.max_limit_packets_in_flight,
      Math.max(context.min_limit_packets_in_flight,
        Math.round(context.current_limit_bytes_in_flight / context.current_limit_packet_payload)));
  }

  // ── Careful Resume (RFC 9959) ──────────────────────────────────────────
  //
  // A returning client's ticket may carry what this server measured on its
  // last connection (savedState, at the top of this file). The connection then runs RFC 9959's
  // phases, as Appendix C fits them to BBR:
  //
  //   reconnaissance  the initial window, as any connection — until the
  //                   first flight is acknowledged without loss and the RTT
  //                   is the saved one's (§4.2.1); otherwise it is over.
  //   confirmed       waiting for the sender to need more than the window
  //                   (§4.2.1: the jump "may be deferred until" then).
  //   unvalidated     the window jumps to half the saved capacity, paced
  //                   over one round trip (§4.3); ends after a round trip,
  //                   when the window is filled, or when the first packet
  //                   sent so is acknowledged.
  //   validating      what was sent unvalidated is acknowledged (§4.4);
  //                   slow start goes on from there.
  //   safe_retreat    a loss while unvalidated or validating (§4.5): the
  //                   saved state is deleted, the window halved to what was
  //                   actually delivered (PipeSize / 2) and held until the
  //                   last unvalidated packet is acknowledged; BBR leaves
  //                   Startup, its delivery rates of the period discarded
  //                   (Appendix C.3).
  //   done            normal congestion control from here on.

  function crStart() {
    if (!context.careful_resume || !context.isServer || !tls) return;
    var info = tls.getTicketInfo();
    if (!info || !info.resumed || !info.state) return;
    var saved = usableState(info.state, peerPath().address, context.init_limit_bytes_in_flight, Date.now());
    if (!saved) return;
    // The measurement goes on to the next visit: the ticket this handshake
    // ended with was issued before the resumption was known, without it, and
    // a connection that measures nothing new would otherwise leave the client
    // a ticket with nothing in it. Carried as it is — its time still that of
    // the measurement, so its lifetime runs from then. This connection's own
    // estimate replaces it only by being higher (in Startup it starts from
    // nothing and climbs) or, after Startup, different by a quarter.
    if (tls.setTicketState(info.state) && tls.sendTicket()) context.cr_tickets++;
    context.cr_saved_bw = saved.bw;
    context.cr_saved_at = 1;
    context.cr = { phase: 'reconnaissance', saved: saved, lost_at: context.lost_count,
                   recon_end_pn: null, first_pn: null, last_pn: null, pipe: 0, t: 0,
                   prev_rate: 0, flag_until: -1 };
  }

  function setCwnd(bytes) {
    context.current_limit_bytes_in_flight = Math.max(context.min_limit_bytes_in_flight,
      Math.min(context.max_limit_bytes_in_flight, bytes));
    context.current_limit_packets_in_flight = Math.min(context.max_limit_packets_in_flight,
      Math.max(context.min_limit_packets_in_flight,
        Math.round(context.current_limit_bytes_in_flight / context.current_limit_packet_payload)));
  }
  function setPacingRate(bps) {
    context.current_limit_bytes_per_sec = Math.max(context.min_limit_bytes_per_sec,
      Math.min(context.max_limit_bytes_per_sec, bps));
    context.current_limit_packets_per_sec = Math.max(1, Math.min(context.max_limit_packets_per_sec,
      Math.round(context.current_limit_bytes_per_sec / context.current_limit_packet_payload)));
  }
  function crRtt() { return context.srtt || context.bbr_min_rtt || context.cr.saved.rtt; }
  // Is anything at or below `pn` still in flight?
  function inFlightUpTo(pn) {
    for (var e of context.pkt_in_flight) return e[0] <= pn;
    return false;
  }

  // The sender has data and no window left: the moment to jump (§4.3).
  function crMaybeJump() {
    var cr = context.cr;
    if (!cr || cr.phase !== 'confirmed') return false;
    if (context.bbr_state !== 'startup') { cr.phase = 'done'; return false; }   // C: Startup only
    var jump = Math.min(context.max_limit_bytes_in_flight, cr.saved.cwnd / 2); // "no more than half"
    if (jump <= context.current_limit_bytes_in_flight) { cr.phase = 'done'; return false; }
    cr.pipe = context.app_bytes_in_flight;          // PipeSize = flight_size (§4.3)
    cr.first_pn = context.send_pn.app;
    cr.t = Date.now();
    cr.prev_rate = context.current_limit_bytes_per_sec;
    cr.flag_until = context.bbr_round_count + 2;    // C.1: two rounds carefully-resuming
    setCwnd(jump);
    // Paced over the current RTT (§4.3: ITT = RTT × MPS / jump_cwnd) — the
    // probing rate, half the saved bandwidth when the RTT is the saved one;
    // or Startup's own rate if that is higher (C.1).
    var probing = jump / (crRtt() / 1000);
    var nominal = (context.bbr_btlbw || 0) * BBR_STARTUP_GAIN;
    setPacingRate(Math.max(probing, nominal));
    cr.phase = 'unvalidated';
    if (DEBUG_BBR) console.log('[cr] jump: cwnd=' + Math.round(jump) + 'B pace=' + (context.current_limit_bytes_per_sec * 8 / 1e6).toFixed(2) + 'Mbps pipe=' + cr.pipe);
    return true;
  }

  // Unvalidated ends (§4.3): the window filled, the first packet sent in it
  // acknowledged, or a round trip gone by.
  function crEndUnvalidated() {
    var cr = context.cr;
    cr.last_pn = context.send_pn.app - 1;
    var flight = context.app_bytes_in_flight;
    if (flight < context.init_limit_bytes_in_flight || flight <= cr.pipe) {
      // Rate-limited: it did not use the jump. Back to what was delivered.
      setCwnd(Math.max(cr.pipe, context.init_limit_bytes_in_flight));
      setPacingRate(cr.prev_rate);
      cr.phase = 'done';
    } else {
      setCwnd(flight);
      cr.phase = 'validating';
    }
    if (DEBUG_BBR) console.log('[cr] unvalidated → ' + cr.phase + ' flight=' + flight + ' pipe=' + cr.pipe);
  }

  function crCheckUnvalidated() {
    var cr = context.cr;
    if (!cr || cr.phase !== 'unvalidated') return;
    if (context.app_bytes_in_flight + context.current_limit_packet_payload > context.current_limit_bytes_in_flight ||
        Date.now() - cr.t > crRtt()) crEndUnvalidated();
  }

  // After an app-space ACK: acked[i] is a packet number, sizes[i] its size.
  function crOnAck(acked, sizes) {
    var cr = context.cr;
    if (!cr || cr.phase === 'done') return;
    if (cr.phase === 'reconnaissance') {
      if (cr.recon_end_pn === null) cr.recon_end_pn = context.send_pn.app - 1;   // the first flight
      if (context.lost_count > cr.lost_at) { cr.phase = 'done'; return; }
      if (inFlightUpTo(cr.recon_end_pn)) return;
      var rtt = context.bbr_min_rtt;
      cr.phase = (rtt && sameRtt(rtt, cr.saved.rtt)) ? 'confirmed' : 'done';
      if (DEBUG_BBR) console.log('[cr] reconnaissance → ' + cr.phase + ' rtt=' + rtt + ' saved=' + cr.saved.rtt);
      return;
    }
    // PipeSize: what of the unvalidated period is acknowledged (§4.4).
    var hitFirst = false, hitLast = false;
    for (var i = 0; i < acked.length; i++) {
      if (cr.first_pn !== null && acked[i] >= cr.first_pn) { cr.pipe += sizes[i]; hitFirst = true; }
      if (cr.last_pn !== null && acked[i] >= cr.last_pn) hitLast = true;
    }
    if (cr.phase === 'unvalidated') {
      if (hitFirst) crEndUnvalidated();
      else crCheckUnvalidated();
    }
    if (cr.phase === 'validating' && !inFlightUpTo(cr.last_pn)) {
      cr.phase = 'done';
      if (DEBUG_BBR) console.log('[cr] validated, pipe=' + cr.pipe);
    } else if (cr.phase === 'safe_retreat' && hitLast) {
      // Out of Safe Retreat: BBR goes on in ProbeBW — the pipe is known to
      // be full (Appendix C.3) — from what was actually delivered, halved:
      // §4.5, "ssthresh MUST be no larger than PipeSize × Beta" (Beta 0.5),
      // as a rate. An upper bound: the rates BBR measured before the jump are
      // the first flight's, smaller, and keeping only those (tried) left a
      // 9 Mbps link at 0.4 Mbps. The price is the RFC's: a loss while the
      // jump is out is taken for congestion, and ProbeBW climbs back from
      // half — a random 2 % loss made a resumed download ~20 % slower than
      // an unresumed one, which does not react to loss at all.
      var base = Math.max(context.min_limit_bytes_per_sec, (cr.pipe / 2) / (crRtt() / 1000));
      context.bbr_btlbw_samples = [{ round: context.bbr_round_count, rate: base }];
      context.bbr_btlbw = base;
      context.bbr_state = 'probe_bw';
      context.bbr_cycle_idx = 0;
      cr.phase = 'done';
      if (DEBUG_BBR) console.log('[cr] safe retreat over, bw=' + Math.round(context.bbr_btlbw) + 'B/s');
    }
  }

  // A packet given up on: in Reconnaissance, simply the end of it; while the
  // jump is out, Safe Retreat (§4.5).
  function crOnLoss() {
    var cr = context.cr;
    if (!cr || cr.phase === 'done' || cr.phase === 'safe_retreat') return;
    if (cr.phase === 'reconnaissance' || cr.phase === 'confirmed') { cr.phase = 'done'; return; }
    if (cr.phase === 'unvalidated') cr.last_pn = context.send_pn.app - 1;
    var half = Math.max(context.min_limit_bytes_in_flight, cr.pipe / 2);
    setCwnd(half);
    setPacingRate(half / (crRtt() / 1000));
    context.bbr_state = 'drain';            // C.3: out of Startup; nothing grows
    cr.phase = 'safe_retreat';
    // "the saved CC parameters are deleted" — the ticket the client keeps
    // next is one without them.
    if (tls) { tls.setTicketState(null); tls.sendTicket(); }
    context.cr_saved_at = 0; context.cr_saved_bw = 0;
    if (DEBUG_BBR) console.log('[cr] loss → safe retreat, cwnd=' + Math.round(half));
  }

  // The observing side (§3.1), at each round's end: what this connection
  // measured goes into the client's ticket. The estimate is a delivery rate —
  // never more than the path carried, so a saved one is never more than its
  // capacity — and in Startup it climbs round by round: saved once, at the
  // first round worth it, it stayed there (2 Mbps of a 9 Mbps link, and the
  // next visit jumped to a fraction of what it could). So in Startup it is
  // saved again at every round it grew by a quarter — a handful of tickets,
  // the last one taken at about the bottleneck rate, whether or not Startup
  // ever ends (a download often finishes just as it finds the rate). After
  // Startup: again when it moves by a quarter either way, at most every few
  // seconds. Never while a resume is still being validated.
  var CR_SAVE_MIN_INTERVAL_MS = 5000;
  var CR_MAX_TICKETS = 16;
  function crRoundEnd() {
    if (context.cr && context.cr.flag_until >= 0 && context.bbr_round_count >= context.cr.flag_until) context.cr.flag_until = -1;
    if (!context.careful_resume || !context.isServer || !tls) return;
    var cr = context.cr;
    if (cr && (cr.phase === 'unvalidated' || cr.phase === 'validating' || cr.phase === 'safe_retreat')) return;
    if (context.bbr_btlbw === null || context.bbr_min_rtt === null) return;
    if (context.cr_tickets >= CR_MAX_TICKETS) return;
    var now = Date.now();
    if (context.cr_saved_at) {
      var ratio = context.bbr_btlbw / context.cr_saved_bw;
      if (context.bbr_state === 'startup') { if (ratio < 1.25) return; }
      else if (now - context.cr_saved_at < CR_SAVE_MIN_INTERVAL_MS || (ratio < 1.25 && ratio > 0.8)) return;
    }
    var st = savedState(context.bbr_btlbw, context.bbr_min_rtt, peerPath().address, context.init_limit_bytes_in_flight, now);
    if (!st) return;
    if (tls.setTicketState(st) && tls.sendTicket()) {
      context.cr_saved_at = now; context.cr_saved_bw = context.bbr_btlbw; context.cr_tickets++;
      if (DEBUG_BBR) console.log('[cr] saved bw=' + st.b + 'B/s rtt=' + st.r + 'ms');
    }
  }

  // A 1-RTT packet carrying stream data or datagrams declared lost: counted
  // (getStats' packetsLost, and bytesLost by its size on the wire), and
  // Careful Resume told.
  function countLostPacket(pnum) {
    context.lost_count++;
    var h = context.sending_app_pn_history[pnum - (context.send_pn.app - context.sending_app_pn_history.length)];
    if (h) context.stats_bytes_lost += h[1];
    crOnLoss();
  }

  // A packet given up on — expired, or its control frames deemed lost: out
  // of the bytes in flight. Returns its size (0: not in flight any more).
  function forgetPacket(pn) {
    var pk = context.pkt_in_flight.get(pn);
    if (!pk) return 0;
    context.pkt_in_flight.delete(pn);
    context.app_bytes_in_flight -= pk.bytes;
    return pk.bytes;
  }

  // How many of the values in `r` (flat [from, to) pairs) `a` already
  // covers — flat_ranges.length(flat_ranges.intersect(a, r)), found by binary
  // search in `a` for each pair of `r` instead of a walk of both. Both are
  // the library's sorted, merged lists; `r` not so (never seen) is answered
  // the original way.
  function coveredLength(a, r) {
    var na = a.length, total = 0, prevTo = -Infinity;
    if (na === 0 || r.length === 0) return 0;
    for (var i = 0; i < r.length; i += 2) {
      var f = r[i], t = r[i + 1];
      if (f < prevTo) return flat_ranges.length(flat_ranges.intersect(a, r));
      prevTo = t;
      if (f >= t) continue;
      // first pair of a whose `to` > f
      var lo = 0, hi = na >> 1;
      while (lo < hi) {
        var mid = (lo + hi) >> 1;
        if (a[(mid << 1) + 1] <= f) lo = mid + 1; else hi = mid;
      }
      for (var k = lo << 1; k < na && a[k] < t; k += 2) {
        var from = a[k] > f ? a[k] : f;
        var to = a[k + 1] < t ? a[k + 1] : t;
        if (to > from) total += to - from;
      }
    }
    return total;
  }

  // Would flat_ranges.remove(list, r) change `list`? Only if a pair of `r`
  // overlaps one of it (half-open; flat_ranges.overlaps, a binary search).
  function overlapsAny(list, r) {
    if (list.length === 0) return false;
    for (var i = 0; i < r.length; i += 2) {
      if (flat_ranges.overlaps(list, r[i], r[i + 1])) return true;
    }
    return false;
  }

  // How many packet numbers a flat [from, to, from, to, ...] list of
  // inclusive ranges covers.
  function rangesSpan(r) {
    var n = 0;
    for (var i = 0; i < r.length; i += 2) n += r[i + 1] - r[i] + 1;
    return n;
  }

  // Entries in the limbo table (kept as it changes — counting them meant
  // walking it).
  function limboCount() {
    return context.limbo_n > 0 ? context.limbo_n : 0;
  }

  function processAckFrame(space, frame) {
    // RFC 9000 §13.1: "An endpoint SHOULD treat receipt of an acknowledgment
    // for a packet it did not send as a connection error of type
    // PROTOCOL_VIOLATION". Nothing numbered at or past send_pn has been sent.
    // Taken as genuine, such an ACK would credit data that never left —
    // stream bytes marked delivered, RTT and delivery-rate samples made up —
    // and a peer (or an attacker who can inject into a space whose keys are
    // public, like Initial) could steer the congestion controller with it.
    if (frame.largest >= context.send_pn[space]) {
      close(0x0a, 'ACK of an unsent packet');
      return;
    }

    var ackedRanges = ack_frame_to_ranges(frame);
    if (!ackedRanges || ackedRanges.length === 0) return;

    // RFC 9001 §4.1.2: "a client MAY consider the handshake to be confirmed
    // when it receives an acknowledgment for a 1-RTT packet." Taken, so that
    // a lost HANDSHAKE_DONE (sent once) cannot leave the client holding its
    // Handshake keys — and resending its Finished, which the server, having
    // discarded its own Handshake keys, will never acknowledge.
    // A 1-RTT packet: an acknowledgment of 0-RTT ones only (the same space,
    // and the server's first flight may carry it) says nothing about the
    // handshake — taken as confirmation, the client dropped its Handshake
    // keys before its Finished went out, and the server never completed.
    if (space === 'app' && !context.isServer && frame.largest > context.zero_rtt_pn_last) discardSpace('handshake');

    // The peer acknowledged something → it's responsive in the return
    // direction. Resets the in-flight-expiry backoff (any space counts).
    // Capture the previous ACK time first — it's the interval for delivery_rate.
    var ackNow = Date.now();
    var prevAckTime = context.last_ack_time;
    context.last_ack_time = ackNow;

    // Initial/Handshake: an ACK confirms crypto byte-ranges. Move them in_flight
    // → acked and reset that space's resend backoff (the peer is responding).
    // The packets they acknowledge grow the window as 1-RTT packets do
    // (growStartupWindow; RFC 9002 §7.3.1: in slow start, every acknowledged
    // byte), by their size on the wire — the padded Initial included.
    if (space === 'initial' || space === 'handshake') {
      var cs = context.crypto_sent[space], hsAckedBytes = 0;
      // An RTT sample, as from a 1-RTT ACK (RFC 9002 §4.1: "round-trip time
      // (RTT) measurement are unified across packet number spaces"): the
      // largest acknowledged, newly — its entry is still here — and
      // ack-eliciting, which every CRYPTO packet is. Packet numbers are never
      // reused, so a retransmission is not mistaken for its original. No ACK
      // Delay taken off: §5.3 lets an endpoint ignore it for Initial packets,
      // and these spaces acknowledge at once (we send 0) — what remains is
      // the peer's processing, an overestimate, the safe side for a timer.
      // There was none: the handshake ran on kInitialRtt (333 ms) and its
      // doublings, the first 1-RTT packets too.
      var lgIn = cs.in_flight[frame.largest];
      if (lgIn && lgIn.time_sent > 0) {
        var hsRtt = ackNow - lgIn.time_sent;
        if (hsRtt > 0) updateRtt(hsRtt, 0);
      }
      if (space === 'handshake') context.hs_ack_received = true;
      for (var cpn in cs.in_flight) {
        var p = Number(cpn), hit = false;
        for (var cri = 0; cri < ackedRanges.length; cri += 2) {
          if (p >= ackedRanges[cri] && p <= ackedRanges[cri + 1]) { hit = true; break; }
        }
        if (hit) {
          flat_ranges.add(cs.acked, cs.in_flight[cpn].range);
          hsAckedBytes += cs.in_flight[cpn].bytes || 0;
          delete cs.in_flight[cpn];
        }
      }
      cs.backoff = 0;
      growStartupWindow(hsAckedBytes);
      if (cs.largest_acked == null || frame.largest > cs.largest_acked) cs.largest_acked = frame.largest;
      // Packets this ACK shows lost go again now, in the flush (hsDetectLost);
      // with nothing left in flight, a client still keeps its timer (§6.2.2.1).
      if (hsDetectLost()) scheduleHsFlush();
      // The retransmission timer again, from this ACK (RFC 9002 §6.2.1: "The
      // PTO timer MUST be set ... when an ack-eliciting packet is ...
      // acknowledged"; A.7 sets it on every ACK). Left as armed, it ran on
      // what it was set with — kInitialRtt, 333 ms — although the ACK had
      // just given an RTT and reset the backoff: a packet sent with one
      // acknowledged and one lost after it (the second half of a ClientHello
      // too large for one datagram — a post-quantum one) went again at
      // 333 ms, not at the 3 RTT or so the sample allowed.
      if (context.crypto_timer !== null) { clearTimeout(context.crypto_timer); context.crypto_timer = null; }
      if (cryptoHasInFlight() || hsProbeNeeded()) scheduleCryptoRetx();
      return;
    }

    if (space === 'app') {
      if (acksSkippedNumber(ackedRanges)) {
        close(0x0a, 'ACK of a packet number never sent (optimistic ACK)');
        return;
      }
      if (frame.largest > context.app_largest_acked) context.app_largest_acked = frame.largest;
      ackControl(ackedRanges);
      // RTT measurement
      if ('largest' in frame && 'delay' in frame) {
        var largest_pn = frame.largest;
        // Only measure from the largest *newly* acked, ack-eliciting packet
        // (RFC 9002 §5.1): pkt_in_flight holds every ack-eliciting packet
        // until it is acknowledged — data, and control frames alone (a
        // HANDSHAKE_DONE, NEW_CONNECTION_IDs, a PING). Only data-carrying ones
        // (sending_app_pn_in_flight) were sampled: a first flight of control
        // frames alone, acknowledged, left the connection with no RTT at all —
        // Careful Resume's reconnaissance then ended without one and never
        // jumped.
        //
        // Expired-but-limboed packets ALSO qualify. QUIC packet numbers are
        // never reused, so a late ACK is unambiguous (no TCP retransmission
        // ambiguity), and limbo membership proves the packet carried data.
        // Excluding them creates a self-sealing failure: an expiry timer that
        // is too short kills packets before their ACKs arrive → the ACKs are
        // then barred from producing RTT samples → srtt/rttvar keep reflecting
        // the pre-queue path → the timer never widens → every packet keeps
        // expiring. The queue-inflated samples these late ACKs carry are
        // exactly the evidence the timer needs in order to grow past the real
        // arrival time; one such sample spikes rttvar and ends the spiral.
        if (context.pkt_in_flight.has(largest_pn) || context.sending_app_pn_in_flight.has(largest_pn) ||
            (largest_pn in context.expired_unacked)) {
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
      // Walked from whichever side is smaller: the packets in flight, or the
      // packet numbers this ACK covers. Every in-flight packet was tested
      // against every range on every ACK — at a high RTT the window holds
      // thousands, and a page's worth of ACKs cost that many times over.
      // Ascending either way (the set is in send order), as before.
      if (rangesSpan(ackedRanges) < context.sending_app_pn_in_flight.size) {
        for (var ri = 0; ri < ackedRanges.length; ri += 2) {
          for (var rpn0 = ackedRanges[ri]; rpn0 <= ackedRanges[ri + 1]; rpn0++) {
            if (context.sending_app_pn_in_flight.has(rpn0)) ackedPns.push(rpn0);
          }
        }
      } else {
        // Both in ascending order (ack_frame_to_ranges sorts and merges the
        // ranges; the set is in packet-number order): one pointer into the
        // ranges, and the walk ends past the largest acknowledged — what is
        // in flight above it cannot be in this ACK. Each packet was tested
        // against every range, and the walk went on to the newest packet.
        var rp1 = 0, rTop1 = ackedRanges[ackedRanges.length - 1];
        for (var pn of context.sending_app_pn_in_flight) {
          if (pn > rTop1) break;
          while (ackedRanges[rp1 + 1] < pn) rp1 += 2;
          if (pn >= ackedRanges[rp1]) ackedPns.push(pn);
        }
      }
      // A packet's ranges of a stream, acknowledged. Returns the bytes newly
      // acknowledged — not those already recorded, so that both the original
      // transmission and a retransmission of the same range ending up ACKed
      // (routine once late ACKs for expired packets are honoured) count once.
      function creditRanges(st, ranges) {
        // The bytes of `ranges` not acknowledged before — what
        // length(intersect(acked, ranges)) gave, without walking all of
        // acked_ranges and building the intersection for every packet. After
        // a loss acked_ranges holds hundreds of pieces until the hole is
        // filled, and this ran once per acknowledged packet (coveredLength).
        var fresh = flat_ranges.length(ranges) - coveredLength(st.acked_ranges, ranges);
        flat_ranges.add(st.acked_ranges, ranges);
        // Out of missing, whatever it was: an ACK is proof — a late one too,
        // for bytes already given up on and not yet resent (add_have would
        // leave those missing: it defers to what not_have says).
        // remove() walks and rebuilds the whole list; it is called only when
        // it would change something — when the ranges touch a missing one.
        if (overlapsAny(st.missing_ranges, ranges)) flat_ranges.remove(st.missing_ranges, ranges);
        if (st.acked_ranges[0] === 0) sendQueueRelease(st, st.acked_ranges[1]);
        return fresh > 0 ? fresh : 0;
      }

      function retireStreamIfComplete(sid, st) {
        if (st.reset_at) { resetAtProgress(sid, st); return; }
        // Every byte AND the FIN acknowledged (RFC 9000 §3.1, "Data Recvd").
        // On the bytes alone, a stream whose FIN went in a packet of its own
        // was retired whether that packet arrived or not.
        if (st.fin_set && st.fin_acked && (st.total_size === 0 || (st.acked_ranges.length === 2 &&
            st.acked_ranges[0] === 0 && st.acked_ranges[1] >= st.total_size))) {
          checkSentWait(st, true);
          releaseStreamInFlight(st);   // a retransmission still out, of bytes now acked
          delete context.stream_priority[sid];
          delete context.send_streams[sid];
          delete context.remote_max_stream_data_by_sid[sid];
          delete context.last_stream_blocked_sent[sid];
          rememberFinal(context.send_final, Number(sid), st.total_size);
          markStreamSideDone(sid, 'send');
          // "Data Recvd": its waiters told (whenStreamCommitted).
          if (st.committed_waits) { var cws = st.committed_waits; st.committed_waits = null; for (var cwi = 0; cwi < cws.length; cwi++) queueMicrotask(cws[cwi]); }
        }
      }

      // The packets this ACK delivers, by their size on the wire: out of the
      // bytes in flight, into `delivered`. pkt_in_flight is in packet-number
      // order, and what is still in flight below the largest acknowledged is
      // only what was lost or reordered: the walk stops past it, so an ACK
      // costs the packets it acknowledges, not the window.
      var ackedPacketBytes = 0;
      var largestAckedPn = -1;
      for (var lri = 0; lri < ackedRanges.length; lri += 2) if (ackedRanges[lri + 1] > largestAckedPn) largestAckedPn = ackedRanges[lri + 1];
      var ackedPkts = [];
      var rp2 = 0;   // pointer into the ranges, as for ackedPns above
      for (var pke of context.pkt_in_flight) {
        var ppn = pke[0];
        if (ppn > largestAckedPn) break;
        while (ackedRanges[rp2 + 1] < ppn) rp2 += 2;
        if (ppn >= ackedRanges[rp2]) ackedPkts.push(ppn);
      }
      var ackedSizes = [];
      for (var api = 0; api < ackedPkts.length; api++) {
        var apk = context.pkt_in_flight.get(ackedPkts[api]);
        if (apk && apk.payload) context.stats_payload_acked += apk.payload;
        var asz = forgetPacket(ackedPkts[api]);
        ackedSizes.push(asz);
        ackedPacketBytes += asz;
      }
      pmtuOnAck(ackedRanges, ackedPkts, ackedSizes);

      var oldestAckedPn = null;  // smallest newly-acked PN → longest delivery interval
      for (var ai = 0; ai < ackedPns.length; ai++) {
        var apn = ackedPns[ai];
        if (oldestAckedPn === null || apn < oldestAckedPn) oldestAckedPn = apn;
        context.sending_app_pn_in_flight.delete(apn);
        // The streams this packet carried (pn_sids), not every stream.
        var apnSids = context.pn_sids.get(apn);
        if (apnSids) context.pn_sids.delete(apn);
        for (var asi = 0; apnSids && asi < apnSids.length; asi++) {
          var sid = apnSids[asi];
          var st = context.send_streams[sid];
          if (st && st.in_flight_ranges && apn in st.in_flight_ranges) {
            var ackedRangesOfPn = st.in_flight_ranges[apn];
            delete st.in_flight_ranges[apn];
            creditRanges(st, ackedRangesOfPn);
            if (st.fin_pns && st.fin_pns[apn]) { delete st.fin_pns[apn]; st.fin_acked = true; }
            retireStreamIfComplete(sid, st);
          }
        }
        // Bytes of a stream reset since they were sent: nothing to resend now.
        if (apn in context.no_resend_in_flight) delete context.no_resend_in_flight[apn];
      }

      // Late ACKs for packets the expiry timer already gave up on. The data
      // DID arrive — the timer was simply wrong — so: credit the goodput
      // (repairing the BtlBw signal), mark the spans acked (cancelling any
      // retransmit that hasn't left yet), and take back the loss we counted.
      // The limbo table holds up to ~10 s of expired packets: walking all of
      // it for each ACK (for-in, a string key made per entry) was the larger
      // part of an ACK's cost on a lossy, distant path. The covered numbers
      // are looked up instead when they are fewer — ascending, as for-in
      // visits integer keys.
      var lateHits = [];
      if (rangesSpan(ackedRanges) < limboCount()) {
        for (var lr = 0; lr < ackedRanges.length; lr += 2) {
          for (var lq = ackedRanges[lr]; lq <= ackedRanges[lr + 1]; lq++) {
            if (lq in context.expired_unacked) lateHits.push(String(lq));
          }
        }
      } else {
        // Ascending (integer keys), so: one pointer into the ranges, and
        // done past the largest acknowledged.
        var rp3 = 0, rTop3 = ackedRanges[ackedRanges.length - 1];
        for (var lpn0 in context.expired_unacked) {
          var lnum = Number(lpn0);
          if (lnum > rTop3) break;
          while (ackedRanges[rp3 + 1] < lnum) rp3 += 2;
          if (lnum >= ackedRanges[rp3]) lateHits.push(lpn0);
        }
      }
      for (var lhi = 0; lhi < lateHits.length; lhi++) {
        var lpn = lateHits[lhi];
        var rec = context.expired_unacked[lpn];
        if (!rec) continue;
        for (var si2 = 0; si2 < rec.spans.length; si2++) {
          var sidL = rec.spans[si2][0];
          var stL = context.send_streams[sidL];
          if (!stL) continue;   // stream already fully acked via a retransmit
          creditRanges(stL, rec.spans[si2][1]);
          if (rec.spans[si2][2]) stL.fin_acked = true;
          retireStreamIfComplete(sidL, stL);
        }
        // Delivered after all: the packet's bytes, kept when it expired.
        ackedPacketBytes += rec.bytes || 0;
        if (rec.early) context.stats_spurious_early++;
        delete context.expired_unacked[lpn];
        context.limbo_n--;
        if (context.lost_count > 0) context.lost_count--;   // it wasn't a loss after all
      }

      if (allSentWaiters.length > 0 && allDelivered()) fireAllSent();

      // What this ACK shows lost (the time threshold), and the tail probe
      // moved on: an ACK came, a probe may go again.
      appDetectLost();
      context.tlp_out = false;
      tlpRearm();

      // Cumulative delivered advances by the packets this ACK delivered; the
      // delivery clock is the wall-time of this update.
      context.delivered += ackedPacketBytes;
      bbrExtraAcked(ackedPacketBytes, ackNow);

      // Startup grows the window by what each ACK delivers — BBR's BBRSetCwnd
      // before the pipe is known to be full (cwnd += delivered), which is TCP's
      // slow start — not only at a round's end. Grown only there, the window
      // stayed at its initial ~12 KB until the whole first flight had been
      // acknowledged, the second flight left at that size too, and a 37 KB
      // page took three flights where TCP takes two: a round trip more on
      // every page. The round-end update below still sets the BDP-based
      // target, and in Startup never lowers what this raised.
      growStartupWindow(ackedPacketBytes);
      crOnAck(ackedPkts, ackedSizes);

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
        // An app-limited sample is kept only if it RAISES the estimate
        // (BBR delivery-rate sampling: such a sample can show the path is at
        // least that fast, never that it is slower).
        //
        // Without this, the first round of every connection — which carries
        // only a small HTML response and some ACK-only packets — measured a
        // near-zero bandwidth, and the rest of this block turned it into a
        // BDP of a few bytes: the window fell from IW10 to its 2-packet floor
        // and pacing to ~0.1 Mbps, just as the page's subresources were
        // requested. Measured in Chrome: 1.5 MB of subresources took 1.6-2.4 s
        // on the first page of a connection, against ~0.1 s over HTTP/2.
        var roundAppLimited = context.bbr_round_app_limited;
        context.bbr_round_app_limited = false;
        // Careful Resume's Safe Retreat: the window and the rate stay where
        // it put them, and what is delivered meanwhile is not a measurement
        // of the path (RFC 9959 Appendix C.3).
        var crRetreat = !!(context.cr && context.cr.phase === 'safe_retreat');
        if (!crRetreat && roundDur >= 1 && roundDelivered > 0) {
          var roundRate = (roundDelivered * 1000) / roundDur;
          if (!roundAppLimited || (context.bbr_btlbw !== null && roundRate > context.bbr_btlbw)) {
            context.bbr_btlbw_samples.push({ round: context.bbr_round_count, rate: roundRate });
          }
        }

        // The round's lowest RTT, and of how many samples, for the delay exit
        // below; the next round starts its own.
        var roundMinRtt = context.bbr_round_min_rtt, roundRttSamples = context.bbr_round_rtt_samples;
        context.bbr_round_min_rtt = null;
        context.bbr_round_rtt_samples = 0;

        context.bbr_round_count++;
        context.bbr_ea_rounds.push(context.bbr_ea_round_max);
        if (context.bbr_ea_rounds.length > 10) context.bbr_ea_rounds.shift();
        context.bbr_ea_round_max = 0;
        context.bbr_extra_acked = Math.max.apply(null, context.bbr_ea_rounds);
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
        if (!crRetreat && context.bbr_btlbw !== null && context.bbr_min_rtt !== null) {
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
          var STARTUP_GAIN = BBR_STARTUP_GAIN;
          var pacing_gain, cwnd_gain;
          if (context.bbr_state === 'startup') {
            pacing_gain = STARTUP_GAIN; cwnd_gain = context.startup_cap === 'off' ? STARTUP_GAIN : STARTUP_CWND_GAIN;
            // Delay exit: the round's lowest RTT above the path's by more than
            // an eighth of it (4-16 ms, HyStart++'s bounds, RFC 9406) — a queue
            // has formed at the bottleneck: the pipe is full. It shows a round
            // or more before the plateau detector below can tell, which only
            // sees BtlBw stop growing, three rounds in a row, while the window
            // goes on doubling into the queue. Not a loss signal: a packet
            // lost at random makes no RTT longer. Only rounds that tried to
            // fill the pipe, with a few samples; not while Careful Resume's
            // jump is out (it builds a queue on purpose, and has its own
            // retreat).
            var qThresh = Math.max(4, Math.min(16, context.bbr_min_rtt / 8));
            if (!roundAppLimited && !crJumpOut() && roundRttSamples >= 4 && roundMinRtt !== null &&
                roundMinRtt > context.bbr_min_rtt + qThresh) {
              if (DEBUG_BBR) console.log('[bbr] startup exit on delay: round min RTT ' + Math.round(roundMinRtt) + 'ms, RTprop ' + context.bbr_min_rtt + 'ms');
              context.bbr_state = 'drain';
              pacing_gain = 1 / STARTUP_GAIN;   // Drain's rate at once (below)
            }
            // Plateau detector: BtlBw must grow ≥25% per round to stay in Startup.
            else if (context.bbr_btlbw >= context.bbr_full_bw * 1.25) {
              context.bbr_full_bw = context.bbr_btlbw;
              context.bbr_full_bw_count = 0;
            } else if (!roundAppLimited && ++context.bbr_full_bw_count >= 3) {
              // Only rounds that actually tried to fill the pipe count. An
              // app-limited round didn't grow because there was nothing to
              // send; counting it left Startup on an idle connection with a
              // bandwidth estimate of almost nothing.
              context.bbr_state = 'drain';    // pipe is full
              // Drain's rate from now, not from the next round end: another
              // round at Startup's 2.89× only added to the queue being left.
              // (BBR sets the pacing rate after the state update, on the same ACK.)
              pacing_gain = 1 / STARTUP_GAIN;
            }
          } else if (context.bbr_state === 'drain') {
            pacing_gain = 1 / STARTUP_GAIN; cwnd_gain = STARTUP_GAIN; // drain the queue
            if (appBytesInFlight() <= context.bbr_bdp) {
              context.bbr_state = 'probe_bw';
              // Take ProbeBW's gains NOW, not at the next round end. The queue
              // is drained, so the drain rate has no purpose left — and if the
              // connection then goes quiet between page loads, the next round
              // end is the next load's first round: that load ran its opening
              // ~0.7 s at 1/2.89 of the bottleneck rate. Measured: the second
              // page of a connection slower than the first.
              pacing_gain = 1.0; cwnd_gain = 1.25;
            }
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

          // Startup only ever RAISES the window and the pacing rate — BBR's
          // rule (set the rate only "if filled_pipe or rate > current"), and
          // never below the initial window. Before the pipe is known to be
          // full, a lower estimate means too little has been measured yet, not
          // that the path is slower.
          if (context.bbr_state === 'startup') {
            // …within startupCap, which may now be lower than what ACKs grew
            // the window to (the BDP of this round is the measured one).
            targetInflight = Math.max(context.init_limit_bytes_in_flight,
              Math.min(Math.max(targetInflight, context.current_limit_bytes_in_flight), startupCap()));
            context.current_limit_bytes_in_flight = targetInflight;
            context.current_limit_packets_in_flight = clamp(
              Math.round(targetInflight / context.current_limit_packet_payload),
              context.min_limit_packets_in_flight, context.max_limit_packets_in_flight);
            targetRate = Math.max(targetRate, context.current_limit_bytes_per_sec);
          }
          context.current_limit_bytes_per_sec = targetRate;
          context.current_limit_packets_per_sec = clamp(
            Math.round(targetRate / context.current_limit_packet_payload),
            1, context.max_limit_packets_per_sec);
        }
        crRoundEnd();
        if (DEBUG_BBR && context.bbr_bdp !== null) {
          console.log('[bbr] round=' + context.bbr_round_count + ' ' + context.bbr_state +
            ' BtlBw=' + (context.bbr_btlbw * 8 / 1e6).toFixed(2) + 'Mbps' +
            ' RTprop=' + context.bbr_min_rtt + 'ms' +
            ' BDP=' + Math.round(context.bbr_bdp) + 'B' +
            ' → cwnd=' + Math.round(context.current_limit_bytes_in_flight) + 'B' +
            ' pace=' + (context.current_limit_bytes_per_sec * 8 / 1e6).toFixed(2) + 'Mbps');
        }
      }

      // How often the peer need ACK, now the window is what it is — first,
      // so that the request rides in the packets the burst below sends.
      maybeSendAckFrequency();
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

    // 1-RTT CRYPTO — after the handshake, which is where the server's
    // NewSessionTicket travels — goes through the control-frame queue, which
    // re-sends it until acknowledged (RFC 9000 §13.3: CRYPTO data is
    // retransmitted until acknowledged). A comment here used to say it
    // "rides the app stream-recovery path"; it did not — it is not a stream,
    // nothing tracked it, and a ticket lost with its packet was lost for good.
    // Keyed by offset: each piece is its own entry, re-sent unchanged — and
    // no piece larger than a packet takes, or none would ever take it.
    if (space === 'app') {
      var cmax = cryptoFramePayloadMax();
      for (var cat = 0; cat < data.byteLength; cat += cmax) {
        queueControl('crypto:' + (offset + cat),
          { type: 'crypto', offset: offset + cat, data: data.subarray(cat, Math.min(cat + cmax, data.byteLength)) });
      }
      return;
    }

    // Initial / Handshake: the bytes are kept (crypto_sent) and sent by the
    // flush at the end of this turn — with the rest of the flight, in as few
    // datagrams as it fits (hsFlush). Each TLS message went in a packet of
    // its own, each packet in a datagram of its own: a server's flight was
    // seven datagrams, every one of which had to arrive.
    context.crypto_sent[space].buf.push({ off: offset, data: data });
    scheduleHsFlush();
  }

  // The most CRYPTO data one packet carries: the packet payload less room for
  // the rest of it — a long header at its largest (two 20-byte connection
  // IDs, a 2-byte length, a 4-byte packet number), the 16-byte AEAD tag, and
  // the CRYPTO frame's own type, offset and length.
  function cryptoFramePayloadMax() {
    return Math.max(256, context.current_limit_packet_payload - 80);
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
  //
  // With a sample, RFC 9002's PTO (srtt + 4·rttvar), but not under
  // HS_PTO_MIN. An ACK of a handshake packet waits for what the packet
  // carried to be processed — a certificate chain to verify, a signature to
  // make — and on a short path that is longer than the round trip: the
  // client's quick Initial ACK gives the server a 1 ms RTT, and its flight
  // went again before the client had read it. (Chromium floors this timer
  // at 10 ms; the processing here is JavaScript.)
  var HS_PTO_MIN = 25;
  function cryptoTimeout(space) {
    var base = (context.srtt === null) ? context.initial_rtt : Math.max(context.srtt + Math.max(4 * context.rttvar, 1), HS_PTO_MIN);
    var bo = Math.min(context.crypto_sent[space].backoff, 6); // cap ×64
    return base * Math.pow(2, bo);
  }

  // ============================================================
  //  The handshake's sending: one flush, coalesced datagrams
  //  (RFC 9000 §12.2)
  //
  //  Initial and Handshake packets are not sent as they are made. What the
  //  two spaces have to send — CRYPTO data neither acknowledged nor in
  //  flight (new, or given up on), an ACK they owe, a probe — is sent by one
  //  flush at the end of the turn that produced it: packed into packets as
  //  full as the datagram allows, and the packets, Initial first, into as
  //  few datagrams as they fit. A server's whole flight — ServerHello,
  //  EncryptedExtensions, Certificate, CertificateVerify, Finished, and the
  //  ACK of the ClientHello — is one datagram with a small chain, where it
  //  was seven; a client's answer — the Initial ACK, the Handshake ACK and
  //  its Finished — one, where it was up to eight. Each of those datagrams
  //  had to arrive for the handshake to go on.
  //
  //  Sizes are worked out before anything is encrypted (quic_frames_size,
  //  hsPacketSize), so that the last packet of a datagram that carries an
  //  Initial can be padded to bring the datagram to 1200 bytes (§14.1) — in
  //  the datagram, not in an Initial packet padded with zeros ahead of the
  //  Handshake packets that could have filled it.
  // ============================================================

  function scheduleHsFlush() {
    if (context.hs_flush_pending) return;
    context.hs_flush_pending = true;
    queueMicrotask(function () { if (context.hs_flush_pending) hsFlush(); });
  }

  function hsVarIntSize(v) { return v < 0x40 ? 1 : v < 0x4000 ? 2 : v < 0x40000000 ? 4 : 8; }

  // The size on the wire of a long-header packet of `space`, numbered `pn`,
  // with `payloadLen` bytes of frames — as encrypt_quic_packet builds it.
  function hsPacketSize(space, pn, payloadLen) {
    var pnLen = pn <= 0xff ? 1 : pn <= 0xffff ? 2 : pn <= 0xffffff ? 3 : 4;
    var payload = Math.max(payloadLen, 4);   // encrypt_quic_packet's floor, for the header-protection sample
    var dcid = destinationCid(space, context.path), scid = context.my_cids[0];
    var h = 1 + 4 + 1 + dcid.byteLength + 1 + scid.byteLength;
    if (space === 'initial') {
      var tok = context.isServer ? null : (context.retry_token || context.initial_token);
      var tl = tok ? tok.byteLength : 0;
      h += hsVarIntSize(tl) + tl;
    }
    var len = pnLen + payload + 16;
    return h + hsVarIntSize(len) + len;
  }

  // The first CRYPTO range of `space` neither acknowledged, in flight, nor
  // already in a packet of this flush (`planned`): [from, to), or null.
  function hsMissing(space, planned) {
    var cs = context.crypto_sent[space];
    var total = context.crypto_send_offset[space];
    if (total === 0) return null;
    var known = cs.acked.slice();
    for (var pn in cs.in_flight) flat_ranges.add(known, cs.in_flight[pn].range);
    if (planned.length) flat_ranges.add(known, planned);
    var missing = flat_ranges.invert(known, 0, total);
    return (missing && missing.length) ? [missing[0], missing[1]] : null;
  }

  // Send what Initial and Handshake have to send. Returns the ack-eliciting
  // packets sent, by space (the crypto ticker backs off on them).
  // Whether a datagram of these planned packets must be padded to 1200
  // bytes (§14.1): it carries an Initial — a client's, always; a server's,
  // when it is ack-eliciting.
  function hsNeedsPad(plan) {
    for (var i = 0; i < plan.length; i++) {
      if (plan[i].space === 'initial' && (!context.isServer || isAckEliciting(plan[i].frames))) return true;
    }
    return false;
  }

  // Encrypt the planned packets and send them as one datagram, with `extra`
  // (an encrypted 1-RTT packet, { bytes, space, pn }) last if there is one;
  // the last planned packet padded to bring the datagram to 1200 bytes when
  // it must be. Returns the ack-eliciting packets sent, by space.
  function sealHsDatagram(plan, planBytes, path, extra) {
    var sent = { initial: 0, handshake: 0 };
    var extraBytes = extra ? extra.bytes.byteLength : 0;
    var pad = hsNeedsPad(plan) && planBytes + extraBytes < 1200 ? 1200 - planBytes - extraBytes : 0;
    // Padding may lengthen the last packet's Length field (a byte, past 63):
    // taken out of the padding, so the datagram is 1200, not 1201.
    if (pad > 0) {
      var lp = plan[plan.length - 1];
      var lpSize = hsPacketSize(lp.space, lp.pn, lp.payload);
      var grown = hsPacketSize(lp.space, lp.pn, lp.payload + pad) - lpSize - pad;
      // …unless that leaves it short of 1200 (the field grows exactly at
      // the edge): then 1201.
      if (grown > 0 && planBytes - lpSize + hsPacketSize(lp.space, lp.pn, lp.payload + pad - grown) + extraBytes >= 1200) pad -= grown;
    }
    var out = [];
    for (var j = 0; j < plan.length; j++) {
      if (!sendFrames(plan[j].space, plan[j].frames, path, { collect: out, pad: j === plan.length - 1 ? pad : 0 })) break;
      if (isAckEliciting(plan[j].frames)) sent[plan[j].space]++;
    }
    // A short header has no length: the 1-RTT packet goes last (§12.2).
    // The handshake packets know it rode with them: their datagram's loss,
    // when it is found, is its loss too (hsPeerResent, hsDetectLost).
    if (extra) {
      for (var r = 0; r < out.length; r++) {
        var inf = context.crypto_sent[out[r].space].in_flight[out[r].pn];
        if (inf) inf.rider = extra.pn;
      }
      out.push(extra);
    }
    if (out.length) {
      var bytes = out.length === 1 ? out[0].bytes : concatUint8Arrays(out.map(function (o) { return o.bytes; }));
      emitDatagram(bytes, out, path);
    }
    return sent;
  }

  // ── The handshake's last datagram, and the first 1-RTT packet ──────────
  //
  // The flush's last datagram is not sent at once when 1-RTT keys exist: it
  // waits for the end of the turn, and the first 1-RTT packet made in that
  // turn rides in it if it fits — the client's Finished and its request
  // (with its control streams), the server's Finished and its SETTINGS. One
  // datagram that must arrive, where there were two or three; and room the
  // padding of an Initial took is used by data. Only one: a 1-RTT packet
  // has no length, so it is the last in its datagram.
  function hsTailTake(pkt, path) {
    var t = context.hs_tail;
    if (!t || t.extra || path !== t.path) return false;
    var size = t.planBytes + pkt.bytes.byteLength;
    if (size > t.cap) return false;
    // Before the address is validated, not where the datagram alone would
    // have fitted the anti-amplification budget and the two together do not
    // (the flight would wait a round trip for the server's SETTINGS).
    if (!path.validated) {
      var before = t.pad ? Math.max(1200, t.planBytes) : t.planBytes;
      var after = t.pad ? Math.max(1200, size) : size;
      if (after > before && after > ampBudget(path)) return false;
    }
    t.extra = pkt;
    return true;
  }

  function finishHsTail() {
    var t = context.hs_tail;
    if (!t) return;
    context.hs_tail = null;
    sealHsDatagram(t.plan, t.planBytes, t.path, t.extra);
    if (cryptoHasInFlight() || hsProbeNeeded()) scheduleCryptoRetx();
  }

  function hsFlush() {
    context.hs_flush_pending = false;
    // A datagram held from an earlier flush leaves first, in order.
    if (context.hs_tail) finishHsTail();
    var sent = { initial: 0, handshake: 0 };
    if (context.state === 'draining' || context.state === 'closed' || context.state === 'closing') return sent;
    var path = context.path;
    var cap = Math.max(1200, context.current_limit_packet_payload);
    var plan = [], planBytes = 0;
    var nextPn = { initial: context.send_pn.initial, handshake: context.send_pn.handshake };
    var planned = { initial: [], handshake: [] };
    var ackPlanned = { initial: false, handshake: false };

    // The packets planned so far, as one datagram. The last of the flush,
    // when 1-RTT keys exist, is held for the end of the turn (hsTailTake);
    // what it sends is counted now, for the crypto ticker.
    function closeDatagram(last) {
      if (plan.length === 0) return;
      if (last && (context.app_write || zeroRttSending())) {
        context.hs_tail = { plan: plan, planBytes: planBytes, path: path, cap: cap, pad: hsNeedsPad(plan), extra: null };
        for (var k = 0; k < plan.length; k++) if (isAckEliciting(plan[k].frames)) sent[plan[k].space]++;
        queueMicrotask(finishHsTail);
      } else {
        var s2 = sealHsDatagram(plan, planBytes, path, null);
        sent.initial += s2.initial; sent.handshake += s2.handshake;
      }
      plan = []; planBytes = 0;
      nextPn.initial = context.send_pn.initial;
      nextPn.handshake = context.send_pn.handshake;
    }

    var spaces = ['initial', 'handshake'];
    for (var si = 0; si < spaces.length; si++) {
      var s = spaces[si];
      for (var guard = 0; guard < 256; guard++) {
        if (context.discarded[s] || !(s === 'initial' ? context.initial_write : context.handshake_write)) break;
        var ack = (!ackPlanned[s] && ackOwed(s)) ? buildAckFrame(s) : null;
        var miss = hsMissing(s, planned[s]);
        var probe = context.hs_probe === s;
        if (!ack && !miss && !probe) break;

        // Room for frames in what is left of the datagram — the header
        // counted with a 2-byte Length, which any packet with data has.
        var pn = nextPn[s];
        var room = cap - planBytes - (hsPacketSize(s, pn, 64) - 64);
        var frames = [];
        if (ack) frames.push(ack);
        var used = quic_frames_size(frames);
        if (miss) {
          var hdr = 1 + hsVarIntSize(miss[0]) + 2;
          var take = Math.min(miss[1] - miss[0], room - used - hdr);
          // Too little left for data worth a packet: the next datagram.
          if (take < Math.min(64, miss[1] - miss[0]) && plan.length) { closeDatagram(); continue; }
          if (take > 0) {
            frames.push({ type: 'crypto', offset: miss[0], data: cryptoSlice(s, miss[0], miss[0] + take) });
            flat_ranges.add(planned[s], [miss[0], miss[0] + take]);
          }
        }
        if (probe && !isAckEliciting(frames)) frames.push({ type: 'ping' });
        if (probe) context.hs_probe = null;
        if (frames.length === 0) break;
        var size = hsPacketSize(s, pn, quic_frames_size(frames));
        if (planBytes + size > cap && plan.length) {
          // It does not fit after all: undo, and start the next datagram.
          if (miss && frames[frames.length - 1].type === 'crypto') flat_ranges.remove(planned[s], [miss[0], miss[0] + frames[frames.length - 1].data.byteLength]);
          closeDatagram();
          continue;
        }
        if (ack) ackPlanned[s] = true;
        plan.push({ space: s, frames: frames, pn: pn, payload: quic_frames_size(frames) });
        planBytes += size;
        nextPn[s]++;
      }
    }
    closeDatagram(true);
    if (cryptoHasInFlight() || hsProbeNeeded()) scheduleCryptoRetx();
    return sent;
  }

  // RFC 9002 §6.1 for the handshake spaces: a packet is lost once one sent
  // after it is acknowledged and either three later ones are (kPacketThreshold)
  // or 9/8 of an RTT has passed since it was sent (kTimeThreshold) — not
  // only when the retransmission timer, three RTTs on the first sample, runs
  // out. Its range is then missing, and the flush sends it again; a late
  // ACK for it still counts (the range is acknowledged either way). The
  // application space keeps its own recovery (expireInFlight).
  function hsDetectLost() {
    var now = Date.now(), lost = false, nextAt = Infinity, riders = [];
    var thr = context.srtt === null ? null : Math.max(9 / 8 * Math.max(context.srtt, context.latest_rtt || 0), 1);
    var spaces = ['initial', 'handshake'];
    for (var si = 0; si < spaces.length; si++) {
      var cs = context.crypto_sent[spaces[si]];
      var la = cs.largest_acked;
      if (la == null) continue;
      for (var k in cs.in_flight) {
        var p = Number(k);
        if (p >= la) continue;
        var e = cs.in_flight[k];
        if (la - p >= 3 || (thr !== null && now - e.time_sent >= thr)) {
          if (e.rider !== undefined) riders.push(e.rider);
          delete cs.in_flight[k]; lost = true;
        }
        else if (thr !== null) nextAt = Math.min(nextAt, e.time_sent + thr);
      }
    }
    if (context.crypto_loss_timer !== null) { clearTimeout(context.crypto_loss_timer); context.crypto_loss_timer = null; }
    if (nextAt < Infinity) {
      context.crypto_loss_timer = setTimeout(function () {
        context.crypto_loss_timer = null;
        if (hsDetectLost()) hsFlush();
      }, Math.max(1, Math.ceil(nextAt - now)));
      if (context.crypto_loss_timer.unref) context.crypto_loss_timer.unref();
    }
    hsRidersLost(riders);
    return lost;
  }

  // RFC 9002 §6.2.3: the peer sent again handshake data we already had —
  // it has not heard from us: what we sent in answer, still unacknowledged,
  // was lost. A server whose flight is lost sees the client's ClientHello
  // again; a client whose Finished is lost sees the server's flight again.
  // That answer goes again now, with the ACK this packet is owed, not when
  // our timer — three RTTs on the first sample — runs out. "For a limited
  // number of times per connection" (§6.2.3): twice. A late ACK for what
  // was sent before still counts (the ranges are acknowledged either way);
  // the anti-amplification limit holds as for any packet.
  var HS_PEER_RESENT_MAX = 2;
  function hsPeerResent() {
    if (context.hs_peer_resent >= HS_PEER_RESENT_MAX) return;
    var lost = false, riders = [], spaces = ['initial', 'handshake'];
    for (var si = 0; si < spaces.length; si++) {
      var cs = context.crypto_sent[spaces[si]];
      for (var k in cs.in_flight) {
        if (cs.in_flight[k].rider !== undefined) riders.push(cs.in_flight[k].rider);
        delete cs.in_flight[k]; lost = true;
      }
    }
    if (!lost) return;
    context.hs_peer_resent++;
    if (DEBUG) console.log('[quic] the peer resent handshake data: ours, unacknowledged, goes again now');
    scheduleHsFlush();
    hsRidersLost(riders);
  }

  // 1-RTT packets that rode in handshake datagrams found lost: lost with
  // them — the client's request with its Finished, the server's SETTINGS
  // with its flight — and sent again now, in the flush's datagram, not a
  // retransmission timeout later.
  function hsRidersLost(riders) {
    if (riders.length === 0) return;
    for (var i = 0; i < riders.length; i++) expireAppPacket(riders[i]);
    if (hasQueuedControl()) context.control_due = true;
    scheduleSend();
  }

  // RFC 9002 §6.2.2.1: a client keeps its timer while the handshake is not
  // confirmed and none of its Handshake packets has been acknowledged —
  // even with nothing in flight: the server may be blocked by the
  // anti-amplification limit until it hears from us, with no timer of its
  // own meanwhile.
  function hsProbeNeeded() {
    return !context.isServer && !context.hs_ack_received && !handshakeConfirmed() &&
           context.state !== 'closing' && context.state !== 'draining' && context.state !== 'closed' &&
           !cryptoHasInFlight() && (context.initial_write || context.handshake_write) ? true : false;
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
    // RFC 9002 §6.2.2.1: while the anti-amplification limit blocks sending,
    // "the server's PTO timer MUST NOT be armed until datagrams have been
    // received from the client" — a retransmission would only join the queue.
    // feedPackets re-arms it (releaseAmpQueue) when the client next speaks.
    if (ampBlocked()) return;
    if (expireCryptoInFlight()) {
      var resent = hsFlush();
      if (resent.initial)   context.crypto_sent.initial.backoff++;
      if (resent.handshake) context.crypto_sent.handshake.backoff++;
    } else if (hsProbeNeeded()) {
      // RFC 9002 §6.2.2.1: the server may be waiting, blocked by the
      // anti-amplification limit, for any datagram from us — and it has no
      // timer while it waits. A PING it must acknowledge: Handshake, once we
      // have its keys, or else Initial (padded, as every client Initial).
      var ps = (context.handshake_write && !context.discarded.handshake) ? 'handshake' : 'initial';
      context.hs_probe = ps;
      hsFlush();
      context.crypto_sent[ps].backoff++;
    }
    if (cryptoHasInFlight() || hsProbeNeeded()) scheduleCryptoRetx();
  }

  // When the oldest CRYPTO packet in flight times out (expireCryptoInFlight's
  // test), or, with none, a timeout from now (a client's probe). It was a
  // timeout from whenever the timer was armed — often before the flight left:
  // the server arms it on the ClientHello and sends at the end of the turn,
  // after the certificate is signed. Then the tick found nothing old enough,
  // and waited a whole timeout more: a lost flight went again after two of
  // them (seen on a loaded machine: 665 ms instead of 333).
  function cryptoDue() {
    var now = Date.now(), due = Infinity, spaces = ['initial', 'handshake'];
    for (var s = 0; s < spaces.length; s++) {
      var cs = context.crypto_sent[spaces[s]], timeout = cryptoTimeout(spaces[s]);
      for (var pn in cs.in_flight) due = Math.min(due, cs.in_flight[pn].time_sent + timeout - now);
    }
    return due === Infinity ? Math.min(cryptoTimeout('initial'), cryptoTimeout('handshake')) : Math.max(1, due);
  }
  function scheduleCryptoRetx() {
    if (context.crypto_timer !== null) return; // idempotent
    var iv = cryptoDue();
    context.crypto_timer = setTimeout(cryptoTick, iv);
    if (context.crypto_timer.unref) context.crypto_timer.unref();
  }

  /**
   * Discard the keys of a packet-number space and everything that depended on
   * them. RFC 9001 §4.9; RFC 9000 §17.2.2.1 ("Any data in CRYPTO frames is
   * discarded -- and no longer retransmitted"); RFC 9002 §6.4 (packets sent
   * with those keys can no longer be acknowledged; their recovery state is
   * dropped).
   *
   * quico did none of this. It kept each space's CRYPTO data in flight until
   * acknowledged — and the last server Initial packet never is, because the
   * client discards its Initial keys as soon as it sends a Handshake packet.
   * So the crypto ticker resent it for the life of the connection, backing off
   * but never stopping: 13 Initial packets in one Chrome page load, each
   * dropped by Chrome as undecryptable ("DROPPED_UNDECRYPTABLE_PACKET
   * ENCRYPTION_INITIAL" in its net-log), plus a timer, per connection.
   */
  function discardSpace(space) {
    if (context.discarded[space]) return;
    context.discarded[space] = true;

    // No keys: sendFrames refuses to build a packet in this space from here
    // on, and the receive path above drops anything that arrives in it.
    if (space === 'initial') { context.initial_read_original = null; set_context({ initial_read: null, initial_write: null }); }
    else set_context({ handshake_read: null, handshake_write: null });

    // No recovery state and nothing left to acknowledge in this space.
    context.crypto_sent[space] = { buf: [], in_flight: {}, acked: [], backoff: 0 };
    context.pending_ack[space] = [];
    context.ack_state[space].eliciting = 0;
    context.ack_state[space].immediate = false;

    // The crypto ticker only ever serves Initial and Handshake. With nothing
    // left in flight in either, it has no more work.
    if (!cryptoHasInFlight() && context.crypto_timer !== null) {
      clearTimeout(context.crypto_timer);
      context.crypto_timer = null;
    }
    if (DEBUG) console.log('[quic] discarded ' + space + ' keys');
    if (space === 'handshake') {
      pmtuStartSoon();
      var cw = context.confirm_waiters;
      context.confirm_waiters = [];
      for (var ci = 0; ci < cw.length; ci++) cw[ci]();
    }
  }

  // cb() once the handshake is confirmed (RFC 9001 §4.1.2) — at once if it
  // is. A client that sent early data has its answer before then, and the
  // server's session ticket comes about when it is confirmed: a connection
  // closed on the answer would leave without the ticket for next time.
  function whenConfirmed(cb) {
    if (handshakeConfirmed()) { cb(); return; }
    if (context.state === 'closed' || context.state === 'draining') return;
    context.confirm_waiters.push(cb);
  }

  // The handshake confirmed (Handshake keys go then): the path MTU search
  // may start — a round trip later. The first responses go first: a probe
  // is 1.4 KB of padding, and the page's first packets should not queue
  // behind it on a slow link. Then a pass of its own (plan_quic_burst runs
  // for a probe due), not an incidental one: a client that only downloads
  // may have no other.
  function pmtuStartSoon() {
    if (!context.pmtu) pmtuReset();
    var wait = Math.max(1, Math.ceil(context.srtt || 0));
    context.pmtu.nextAt = Math.max(context.pmtu.nextAt, Date.now() + wait);
    var t = setTimeout(plan_quic_burst, wait + 1);
    if (t.unref) t.unref();
  }

  function stopCryptoRetx() {
    if (context.crypto_timer !== null) { clearTimeout(context.crypto_timer); context.crypto_timer = null; }
    if (context.crypto_loss_timer !== null) { clearTimeout(context.crypto_loss_timer); context.crypto_loss_timer = null; }
    context.crypto_sent.initial   = { buf: [], in_flight: {}, acked: [], backoff: 0 };
    context.crypto_sent.handshake = { buf: [], in_flight: {}, acked: [], backoff: 0 };
  }

  // ============================================================
  //  Network paths: anti-amplification, validation, migration
  //  (RFC 9000 §8, §9)
  // ============================================================

  // A path: the peer's address and port, and what is known about it.
  //
  //   validated   the peer is known to receive here. Until then received and
  //               sent bound what may go to it (three times, §8.1), and what
  //               does not fit waits in queue.
  //   challenge   an outstanding PATH_CHALLENGE (§8.2):
  //               { data, padded, started, tries, timer }, or null.
  //   new_ip      moved to with an IP address different from the last
  //               validated path's: its congestion and RTT state are reset
  //               once it is validated (§9.4). A change of port alone is not
  //               — "commonly the result of NAT rebinding" — and keeps them.
  function newPath(address, port, validated) {
    return {
      address: address,
      port: port,
      validated: !!validated,
      received: 0,
      sent: 0,
      queue: [],               // [{ bytes, space, pn }] held for lack of budget
      queue_bytes: 0,
      challenge: null,
      new_ip: false,
      max_rx: 0                // the largest datagram received on it: DPLPMTUD's first guess
    };
  }

  // The path a datagram from this address belongs to. A new address gets a
  // candidate path, counted but not yet used: whether the connection moves
  // there is decided per packet, once it is decrypted (see feedPacket).
  function pathFor(address, port) {
    var p = context.path;
    // A server built without the peer's address learns it from the first
    // datagram — the one that created the connection.
    if (p.address === null) { p.address = address; p.port = port; return p; }
    if (p.address === address && p.port === port) return p;
    p = context.prev_path;
    if (p && p.address === address && p.port === port) return p;
    p = context.candidate_path;
    if (p && p.address === address && p.port === port) return p;
    // One candidate at a time: an address that sends only probes and never
    // gets used is forgotten as soon as another appears.
    context.candidate_path = newPath(address, port, false);
    return context.candidate_path;
  }

  // Held packets, at most. Before validation the server has one handshake
  // flight to send (~6 KB) and a few 1-RTT packets; a queue this size is
  // never reached by a real client, and bounds what a forged address can
  // make us hold. A packet over it is dropped — the retransmission paths
  // send its contents again once the budget allows.
  var AMP_QUEUE_MAX = 32 * 1024;

  function ampBudget(path) {
    return 3 * path.received - path.sent;
  }

  // Blocked: something is waiting for budget on the current path. Nothing
  // new should be produced meanwhile — it could only queue behind it.
  function ampBlocked() {
    return !context.path.validated && context.path.queue.length > 0;
  }

  // Every datagram leaves through here: one packet (sendFrames), or several
  // coalesced into one (RFC 9000 §12.2 — hsFlush). `parts`: the packets in
  // it, [{ space, pn }], whose send times are moved to when it actually
  // leaves if it waits for anti-amplification budget. The budget counts
  // datagrams, as §8.1 does.
  function emitDatagram(bytes, parts, path) {
    context.stats_packets_sent += parts.length;
    context.stats_bytes_sent += bytes.byteLength;
    if (path.validated) { ev.emit('packet', bytes, path.address, path.port); return; }
    if (path.queue.length === 0 && bytes.byteLength <= ampBudget(path)) {
      path.sent += bytes.byteLength;
      ev.emit('packet', bytes, path.address, path.port);
      return;
    }
    if (path.queue_bytes + bytes.byteLength > AMP_QUEUE_MAX) {
      if (DEBUG) console.log('[quic] anti-amplification queue full — dropping a datagram of ' + parts.length + ' packet(s)');
      return;
    }
    path.queue.push({ bytes: bytes, parts: parts });
    path.queue_bytes += bytes.byteLength;
    if (serverStats) serverStats.amplificationBlocked++;
    if (DEBUG) console.log('[quic] anti-amplification: holding ' + bytes.byteLength + 'B (budget ' + ampBudget(path) + 'B)');
  }
  function emitPacket(bytes, space, pn, path) { emitDatagram(bytes, [{ space: space, pn: pn }], path); }

  // Send what the budget now allows, in order. A packet's send time is when
  // it actually leaves: a handshake packet held for a round trip must not be
  // declared lost for the time it spent here.
  function releaseAmpQueue(path) {
    var now = Date.now();
    while (path.queue.length > 0) {
      var held = path.queue[0];
      if (!path.validated) {
        if (held.bytes.byteLength > ampBudget(path)) break;
        path.sent += held.bytes.byteLength;
      }
      path.queue.shift();
      path.queue_bytes -= held.bytes.byteLength;
      for (var hp = 0; hp < held.parts.length; hp++) {
        var part = held.parts[hp];
        if (part.space === 'initial' || part.space === 'handshake') {
          var inf = context.crypto_sent[part.space].in_flight[part.pn];
          if (inf) inf.time_sent = now;
        } else {
          var idx = part.pn - (context.send_pn.app - context.sending_app_pn_history.length);
          if (idx >= 0 && idx < context.sending_app_pn_history.length) context.sending_app_pn_history[idx][0] = now;
          var heldPk = context.pkt_in_flight.get(part.pn);
          if (heldPk) heldPk.t = now;
        }
      }
      ev.emit('packet', held.bytes, path.address, path.port);
    }
    // Retransmission timers stood still while the current path was blocked;
    // set them going again.
    if (path !== context.path) return;
    if (cryptoHasInFlight()) scheduleCryptoRetx();
    if (path.queue.length === 0) plan_quic_burst();
  }

  // The peer's address as far as anything above the transport is concerned:
  // the current path once validated, until then the last one that was.
  function peerPath() {
    if (context.path.validated) return context.path;
    var prev = context.prev_path;
    return (prev && prev.validated) ? prev : context.path;
  }

  function markValidated(path) {
    if (path.validated) return;
    path.validated = true;
    if (path === context.path) ev.emit('path_validated', path.address, path.port);
    if (DEBUG) console.log('[quic] path ' + path.address + ':' + path.port + ' validated (received ' + path.received + 'B, sent ' + path.sent + 'B before)');
    if (path.queue.length > 0) releaseAmpQueue(path);
  }

  // ============================================================
  //  Path MTU discovery — DPLPMTUD (RFC 8899; RFC 9000 §14.3)
  //
  //  Packets start at what every QUIC path carries (current_limit_packet_
  //  payload, 1200 bytes of frames). Most paths carry more — ~1450 on
  //  Ethernet — and every byte more in a packet is a packet less: an
  //  encryption, a system call, the per-packet bookkeeping, which is where a
  //  JavaScript sender spends its time. So once the handshake is confirmed,
  //  the sender probes: a PING padded to a size, sent in the paced flow of
  //  the connection, and acknowledged — by its own packet number — only if
  //  that size crossed the path. Acknowledged, packets grow to it.
  //
  //  Sizes are whole UDP datagrams. The first probe is at the largest
  //  datagram the peer has sent us on this path (a path that carries it one
  //  way usually carries it the other: the limit is most often the peer's
  //  own link, a PPPoE or a VPN), then at the ceiling — max_limit_packet_
  //  payload, and the peer's max_udp_payload_size — and, past a failure, a
  //  binary search between the largest that crossed and the smallest that did
  //  not, down to PMTU_GRANULARITY. A size fails after PMTU_MAX_PROBES probes
  //  of it go unacknowledged, each within the retransmission timeout. Done,
  //  the search starts again PMTU_RAISE_MS later, the path may have grown.
  //
  //  A probe carries no stream data: one lost — and a probe too large is lost
  //  by design — holds nothing back and needs nothing resent, and it is not a
  //  loss to congestion control (§14.4: it "SHOULD NOT trigger a congestion
  //  control reaction"); nothing here counts it as one.
  //
  //  Black holes (RFC 8899 §4.3): the path's MTU can shrink mid-connection —
  //  a route change, a tunnel. Packets above the floor lost in a row, with
  //  none of them acknowledged since (PMTU_SUSPECT of them), are a suspicion,
  //  not a verdict: congestion loses packets in runs too. A probe of the
  //  current size settles it — acknowledged, it was congestion; lost
  //  PMTU_MAX_PROBES times, the size is gone: back to the floor, and the
  //  search again PMTU_RAISE_MS later.
  // ============================================================

  var PMTU_MAX_PROBES = 3;
  var PMTU_GRANULARITY = 16;
  var PMTU_RAISE_MS = 600000;
  var PMTU_SUSPECT = 3;

  function pmtuReset() {
    context.pmtu = {
      lo: 0,              // the largest datagram known to cross (0: the floor's)
      fail: 0,            // the smallest known not to (0: none)
      hintUsed: false,    // the peer's largest datagram tried first, once
      probe: null,        // the probe out: { pn, size, deadline }
      lastProbe: null,    // the last one given up on — honoured if acknowledged late
      size: 0,            // the size being tried, and how many times it was
      tries: 0,
      confirming: false,  // a black-hole suspicion being settled (above)
      nextAt: 0,          // no search before this (0: as soon as it may)
      bigLostPn: -1,      // above the floor: the last one lost
      bigLost: 0,         //   how many lost since one was acknowledged
      bigAckedPn: -1      //   the last one acknowledged
    };
  }

  // A 1-RTT packet's header and AEAD tag: what a datagram carries besides
  // its frames — at its largest (a 4-byte packet number), with the
  // connection ID the packet goes with (zero-length, as Chrome's, included).
  function shortHeaderOverhead() {
    return 1 + destinationCid('1rtt', context.path).byteLength + 4 + 16;
  }
  // The datagram every packet up to the floor's frames fits in.
  function pmtuFloor() { return context.init_limit_packet_payload + shortHeaderOverhead(); }
  function pmtuCeiling() { return Math.min(context.max_limit_packet_payload, context.peer_max_udp_payload); }

  // Packets carry the frames a `size` datagram has room for — never fewer
  // than the floor's.
  function pmtuApply(size) {
    context.current_limit_packet_payload = Math.max(context.init_limit_packet_payload, size - shortHeaderOverhead());
    if (DEBUG) console.log('[quic] PMTU ' + size + ' — packets of ' + context.current_limit_packet_payload + ' bytes of frames');
  }

  // The next size to probe, or 0 when the search is done.
  function pmtuNextSize() {
    var m = context.pmtu, lo = Math.max(m.lo, pmtuFloor()), ceil = pmtuCeiling();
    var fail = m.fail || (ceil + 1);
    if (!m.hintUsed) {
      m.hintUsed = true;
      var h = context.path ? context.path.max_rx : 0;
      if (h >= lo + PMTU_GRANULARITY && h < fail) return Math.min(h, ceil);
    }
    if (fail > ceil) return lo + PMTU_GRANULARITY <= ceil ? ceil : 0;
    if (fail - lo <= PMTU_GRANULARITY) return 0;
    return Math.floor((lo + fail) / 2);
  }

  // Whether a probe is due now — pmtuProbeSize's conditions, before the
  // room for it and without its effects: the planner runs for it.
  function pmtuWantsProbe() {
    if (!context.pmtu_discovery || !handshakeConfirmed() || context.srtt === null || !context.path.validated) return false;
    var m = context.pmtu, now = Date.now();
    if (!m) return true;
    if (m.probe) return now >= m.probe.deadline;
    return now >= m.nextAt;
  }

  // From the send planner, before its burst: the size of a probe due now,
  // or 0. It takes a packet of the burst's (`room`: what the window and the
  // pacer allow now), and goes out after the burst's data (pmtuSendProbe):
  // a probe is the path's business, and the first packets of a response
  // should not wait behind 1.4 KB of padding.
  function pmtuProbeSize(room) {
    if (!context.pmtu_discovery) return 0;
    if (!context.pmtu) pmtuReset();
    var m = context.pmtu, now = Date.now();
    // One out at a time; given up on after the retransmission timeout.
    if (m.probe) {
      if (now < m.probe.deadline) return 0;
      pmtuProbeLost();
    }
    if (room < 1 || !handshakeConfirmed() || context.srtt === null || !context.path.validated) return 0;
    if (now < m.nextAt) return 0;

    var size;
    if (m.confirming) size = Math.max(m.lo, pmtuFloor());
    else {
      if (m.size === 0 || m.tries >= PMTU_MAX_PROBES) {
        size = pmtuNextSize();
        if (size === 0) { m.nextAt = now + PMTU_RAISE_MS; m.fail = 0; m.size = 0; return 0; }   // done, for now
        m.size = size; m.tries = 0;
      }
      size = m.size;
    }
    if (context.app_bytes_in_flight + size > context.current_limit_bytes_in_flight) return 0;
    return size;
  }

  // Send the probe pmtuProbeSize sized. Returns whether it went.
  function pmtuSendProbe(size) {
    var m = context.pmtu, now = Date.now();
    // PING, padded so that the datagram is `size` (at most: the packet
    // number may take fewer than 4 bytes) — and nothing else rides in it:
    // too large for the ACK and control frames sendFrames adds, which
    // keep to the current packet size.
    var pad = size - shortHeaderOverhead() - 1;
    if (pad < 0) return 0;
    var pn = context.send_pn.app;
    if (!sendFrames('app', [{ type: 'ping' }, { type: 'padding', length: pad }])) return false;
    pn = context.send_pn.app - 1;
    m.probe = { pn: pn, size: size, deadline: now + retxTimeout() };
    if (!m.confirming) m.tries++;
    if (DEBUG) console.log('[quic] PMTU probe pn=' + pn + ' size=' + size + (m.confirming ? ' (confirming)' : ' try ' + m.tries));
    return true;
  }

  // The probe out went unacknowledged within the timeout.
  function pmtuProbeLost() {
    var m = context.pmtu, p = m.probe;
    m.probe = null;
    m.lastProbe = p;
    if (m.confirming) {
      if (++m.tries < PMTU_MAX_PROBES) return;
      // The size packets use crosses no more: a black hole. Back to the floor.
      if (DEBUG) console.log('[quic] PMTU black hole at ' + p.size + ' — back to the floor');
      m.confirming = false;
      m.lo = 0; m.fail = p.size; m.size = 0; m.tries = 0;
      m.bigLost = 0;
      context.current_limit_packet_payload = context.init_limit_packet_payload;
      m.nextAt = Date.now() + PMTU_RAISE_MS;
      return;
    }
    if (m.tries >= PMTU_MAX_PROBES) {
      if (DEBUG) console.log('[quic] PMTU ' + p.size + ' does not cross');
      m.fail = m.fail ? Math.min(m.fail, p.size) : p.size;
    }
  }

  // An ACK: a probe acknowledged — on time, or late — confirms its size;
  // packets above the floor acknowledged clear a suspicion's count.
  // acked/sizes: the packets this ACK delivered, and their sizes.
  function pmtuOnAck(ackedRanges, acked, sizes) {
    var m = context.pmtu;
    if (!m) return;
    var floor = pmtuFloor();
    for (var i = 0; i < acked.length; i++) {
      if (sizes[i] > floor && acked[i] > m.bigAckedPn) { m.bigAckedPn = acked[i]; m.bigLost = 0; }
    }
    var hit = function (pn) {
      for (var r = 0; r < ackedRanges.length; r += 2) if (pn >= ackedRanges[r] && pn <= ackedRanges[r + 1]) return true;
      return false;
    };
    var p = (m.probe && hit(m.probe.pn)) ? m.probe : (m.lastProbe && hit(m.lastProbe.pn)) ? m.lastProbe : null;
    if (!p) return;
    if (p === m.probe) m.probe = null; else m.lastProbe = null;
    if (m.confirming) {
      // It crosses: the losses were congestion's.
      m.confirming = false; m.tries = 0; m.bigLost = 0;
      return;
    }
    if (p.size > m.lo) { m.lo = p.size; pmtuApply(p.size); }
    if (m.fail && m.fail <= p.size) m.fail = 0;   // late: an earlier verdict wrong
    if (p.size === m.size) { m.size = 0; m.tries = 0; }
  }

  // A packet given up on (expireInFlight) of `bytes`: above the floor, one
  // more toward a black-hole suspicion — if none above it has been
  // acknowledged since it was sent.
  function pmtuOnLost(pn, bytes) {
    var m = context.pmtu;
    if (!m || m.lo === 0 || m.confirming) return;
    if ((m.probe && pn === m.probe.pn) || bytes <= pmtuFloor() || pn < m.bigAckedPn || pn <= m.bigLostPn) return;
    m.bigLostPn = pn;
    if (++m.bigLost >= PMTU_SUSPECT) {
      if (DEBUG) console.log('[quic] PMTU ' + m.lo + ' suspected: ' + m.bigLost + ' lost in a row — confirming');
      m.confirming = true; m.tries = 0; m.nextAt = 0;
    }
  }

  // RFC 9002 §6.2.1: PTO = smoothed_rtt + max(4·rttvar, granularity) +
  // max_ack_delay, before any backoff; kInitialRtt (333ms) with no sample yet.
  function ptoBase() {
    return (context.srtt === null)
      ? context.initial_rtt
      : context.srtt + Math.max(4 * context.rttvar, 1) + context.max_ack_delay;
  }

  // §8.2.4: "three times the larger of the current PTO or the PTO for the
  // new path (using kInitialRtt)" — the new path may be much slower, and a
  // single lost PATH_CHALLENGE or PATH_RESPONSE must not fail it.
  function pathValidationTimeout() {
    return 3 * Math.max(ptoBase(), 3 * context.initial_rtt + context.max_ack_delay);
  }

  function startPathValidation(path) {
    if (path.challenge) return;   // already underway
    path.challenge = { data: new Uint8Array(randomBytes(8)), padded: false, started: Date.now(), tries: 0, timer: null };
    sendPathChallenge(path);
  }

  // Sent again every PTO, doubling, until answered or abandoned — no more
  // often than a lost packet would be (§9.4).
  function sendPathChallenge(path) {
    var ch = path.challenge;
    ch.tries++;
    // sendFrames expands it to 1200 bytes when the path's budget allows.
    if (path.validated || ampBudget(path) >= 1200) ch.padded = true;
    sendFrames('app', [{ type: 'path_challenge', data: ch.data }], path);
    ch.timer = setTimeout(function () { onPathChallengeTimer(path); }, ptoBase() * Math.pow(2, ch.tries - 1));
    if (ch.timer.unref) ch.timer.unref();
  }

  function onPathChallengeTimer(path) {
    var ch = path.challenge;
    if (!ch) return;
    ch.timer = null;
    if (context.state !== 'connected') return;
    if (Date.now() - ch.started >= pathValidationTimeout()) pathValidationFailed(path);
    else sendPathChallenge(path);
  }

  function stopPathValidation(path) {
    if (!path || !path.challenge) return;
    if (path.challenge.timer !== null) clearTimeout(path.challenge.timer);
    path.challenge = null;
  }

  // §8.2.3: "A PATH_RESPONSE frame received on any network path validates
  // the path on which the PATH_CHALLENGE was sent."
  function onPathResponse(data) {
    var candidates = [context.path, context.prev_path];
    for (var i = 0; i < candidates.length; i++) {
      var p = candidates[i];
      if (p && p.challenge && uint8Equal(p.challenge.data, data)) { pathValidationSucceeded(p); return; }
    }
  }

  function pathValidationSucceeded(path) {
    var padded = path.challenge.padded;
    stopPathValidation(path);
    markValidated(path);
    if (path.new_ip && path === context.path) resetPathEstimates();
    path.new_ip = false;
    // §8.2.3: a response to a datagram that was not expanded validates the
    // address but not the path MTU, and "the endpoint MUST initiate another
    // path validation with an expanded datagram". Validated now, the path
    // has no budget left to stop the expansion.
    if (!padded) startPathValidation(path);
  }

  function pathValidationFailed(path) {
    stopPathValidation(path);
    if (DEBUG) console.log('[quic] path ' + path.address + ':' + path.port + ' failed validation');

    // The path left behind (§9.3.3): gone, which after a NAT rebinding is
    // what it is expected to be. Nothing to return to any more.
    if (path === context.prev_path) { context.prev_path = null; return; }
    if (path !== context.path) return;

    // A path already validated, failing only the expanded re-check (§8.2.3).
    // Every packet quico sends fits in 1200 bytes, so a path that has carried
    // them is carrying what this connection needs; it goes on.
    if (path.validated) return;

    // §9.3.2: "an endpoint MUST revert to using the last validated peer
    // address when validation of a new peer address fails" — the migration
    // may have been a spoofed packet. "If an endpoint has no state about the
    // last validated peer address, it MUST close the connection silently by
    // discarding all connection state."
    if (context.prev_path) {
      var back = context.prev_path;
      context.prev_path = null;
      setPath(back);
      return;
    }
    if (DEBUG) console.log('[quic] no validated path left — closing silently');
    set_context({ state: 'draining' });
  }

  function setPath(path) {
    context.path = path;
    if (context.candidate_path === path) context.candidate_path = null;
    if (DEBUG) console.log('[quic] now sending to ' + path.address + ':' + path.port + (path.validated ? '' : ' (unvalidated)'));
    ev.emit('path', path.address, path.port);
  }

  // ── Connection IDs: issuing ours, keeping the peer's (RFC 9000 §5.1) ──

  // At most this many of ours active at once, whatever the peer allows; and
  // at most this many issued over the connection: a peer that retires each
  // as it comes gets replacements up to here, not without end.
  var LOCAL_CID_ACTIVE_MAX = 4;
  var LOCAL_CID_ISSUE_MAX = 32;

  // Up to the peer's limit, once the handshake is done. A server's IDs come
  // from its router (options.issueConnectionId), which must know them to
  // route by them, with their stateless reset tokens; a client's are its
  // own, any packet on its socket being for it. Zero-length IDs have no
  // others (§5.1.1).
  function issueConnectionIds() {
    if (!context.peer_finished || context.my_cids.length === 0 || context.my_cids[0].byteLength === 0) return;
    if (context.local_cids.length === 0) context.local_cids.push({ seq: 0, cid: context.my_cids[0], token: null, retired: false });
    var want = Math.min(context.peer_active_cid_limit, LOCAL_CID_ACTIVE_MAX);
    var active = context.local_cids.filter(function (c) { return !c.retired; }).length;
    while (active < want && context.local_cids_issued < LOCAL_CID_ISSUE_MAX) {
      var made = context.isServer
        ? (typeof options.issueConnectionId === 'function' ? options.issueConnectionId() : null)
        : { cid: new Uint8Array(randomBytes(context.my_cids[0].byteLength)), token: new Uint8Array(randomBytes(16)) };
      if (!made) return;
      var seq = context.local_cid_next_seq++;
      context.local_cids.push({ seq: seq, cid: made.cid, token: made.token, retired: false });
      context.local_cids_issued++;
      active++;
      queueControl('ncid:' + seq, { type: 'new_connection_id', seq: seq, retire: 0, connId: made.cid, token: made.token });
    }
  }

  // §19.16: the peer is done with one of ours. Its route goes (server), and
  // another is issued in its place.
  function onRetireConnectionId(frame) {
    if (frame.seq >= context.local_cid_next_seq) { close(0x0a, 'RETIRE_CONNECTION_ID for an ID never issued'); return false; }
    for (var i = 0; i < context.local_cids.length; i++) {
      var c = context.local_cids[i];
      if (c.seq !== frame.seq || c.retired) continue;
      // §19.16: not the ID the frame came addressed to.
      if (context.rx_dcid && uint8Equal(c.cid, context.rx_dcid)) { close(0x0a, 'RETIRE_CONNECTION_ID for the connection ID of its own packet'); return false; }
      c.retired = true;
      // Still addressed by this one for long headers and the short-header
      // length: my_cids[0] stays — same length, and only a peer that has
      // left the handshake behind retires IDs.
      // Its route stays for a while (3 PTO, as quic-go keeps one): packets
      // the peer sent with it before retiring it may still be on their way —
      // overtaken by the RETIRE_CONNECTION_ID, or behind it in a reordering
      // path. Removed at once, they went nowhere.
      if (context.isServer && typeof options.retireConnectionId === 'function') {
        var goneCid = c.cid;
        var rt = setTimeout(function () { options.retireConnectionId(goneCid); }, Math.ceil(3 * ptoBase()));
        if (rt.unref) rt.unref();
      }
      break;
    }
    context.local_cids = context.local_cids.filter(function (c) { return !c.retired; });
    issueConnectionIds();
    return true;
  }

  // One of the peer's IDs retired by us: a RETIRE_CONNECTION_ID, tracked
  // until acknowledged (ackControl). §5.1.2: a peer that makes us retire IDs
  // faster than it acknowledges the frames (Retire Prior To raised in every
  // NEW_CONNECTION_ID) would have them pile up without end. "An endpoint
  // SHOULD allow for sending and tracking a number of RETIRE_CONNECTION_ID
  // frames of at least twice the value of its active_connection_id_limit";
  // past that, CONNECTION_ID_LIMIT_ERROR, which §5.1.2 allows.
  function retireOfPeer(seq) {
    context.peer_cids_retiring.add(seq);
    if (context.peer_cids_retiring.size > 2 * Math.max(2, localTp.active_connection_id_limit || 2)) {
      close(0x09, 'too many connection IDs to retire at once'); return false;
    }
    queueControl('rcid:' + seq, { type: 'retire_connection_id', seq: seq });
    return true;
  }

  // §19.15: another of the peer's IDs. Checked as §19.15 says, kept, and
  // the ones it says to retire (Retire Prior To) are retired — the one in
  // use too, moving to another — each with a RETIRE_CONNECTION_ID.
  function onNewConnectionId(frame) {
    if (context.their_cids.length > 0 && context.their_cids[0].byteLength === 0) {
      close(0x0a, 'NEW_CONNECTION_ID from a peer using zero-length connection IDs'); return false;
    }
    if (frame.retire > frame.seq) { close(0x07, 'Retire Prior To above the sequence number'); return false; }
    if (!frame.connId || frame.connId.byteLength < 1 || frame.connId.byteLength > 20) { close(0x07, 'connection ID length'); return false; }
    if (context.peer_cids.length === 0 && context.their_cids.length > 0) {
      context.peer_cids.push({ seq: 0, cid: context.their_cids[0], token: context.peer_reset_token, retired: false, inUse: true });
    }
    var known = null;
    for (var i = 0; i < context.peer_cids.length; i++) {
      var pc = context.peer_cids[i];
      if (pc.seq === frame.seq) known = pc;
      else if (uint8Equal(pc.cid, frame.connId)) { close(0x0a, 'one connection ID under two sequence numbers'); return false; }
    }
    if (known) {
      if (!uint8Equal(known.cid, frame.connId)) { close(0x0a, 'another connection ID under a known sequence number'); return false; }
    } else if (frame.seq < context.peer_retire_prior_to) {
      // Already retired by an earlier Retire Prior To: retired at once.
      if (!retireOfPeer(frame.seq)) return false;
    } else {
      context.peer_cids.push({ seq: frame.seq, cid: frame.connId, token: frame.token, retired: false, inUse: false });
    }
    if (frame.retire > context.peer_retire_prior_to) {
      context.peer_retire_prior_to = frame.retire;
      var current = context.their_cids[0];
      for (var j = 0; j < context.peer_cids.length; j++) {
        var r = context.peer_cids[j];
        if (r.retired || r.seq >= frame.retire) continue;
        r.retired = true;
        if (!retireOfPeer(r.seq)) return false;
        if (current && uint8Equal(r.cid, current)) current = null;
        clearPathDcid(r.cid);
      }
      if (!current) {
        var next = nextPeerCid(null);
        if (next) set_context({ their_cid_replace: next });
      }
    }
    // Retired ones are not kept: their RETIRE_CONNECTION_ID carries them
    // from here (peer_cids_retiring). Kept, a peer raising Retire Prior To
    // with every frame grew the list, and this scan, for the connection's life.
    context.peer_cids = context.peer_cids.filter(function (c) { return !c.retired; });
    var active = context.peer_cids.length;
    if (active > Math.max(2, (localTp.active_connection_id_limit || 2))) {
      close(0x09, 'more connection IDs than active_connection_id_limit'); return false;
    }
    return true;
  }

  // A peer ID not yet used, marked in use; null when there is none.
  function nextPeerCid(notThis) {
    for (var i = 0; i < context.peer_cids.length; i++) {
      var pc = context.peer_cids[i];
      if (pc.retired || pc.inUse) continue;
      if (notThis && uint8Equal(pc.cid, notThis)) continue;
      pc.inUse = true;
      return pc.cid;
    }
    return null;
  }

  // A path that used a retired ID goes back to the connection's current one.
  function clearPathDcid(cid) {
    var paths = [context.path, context.prev_path, context.candidate_path];
    for (var i = 0; i < paths.length; i++) if (paths[i] && paths[i].dcid && uint8Equal(paths[i].dcid, cid)) paths[i].dcid = null;
  }

  // §9.3: the peer's newest non-probing packet came from another address.
  // "If the recipient permits the migration, it MUST send subsequent packets
  // to the new peer address and MUST initiate path validation."
  function migrateTo(path, dcidUsed) {
    var old = context.path;
    // §9.5: a peer that moved deliberately addresses us by another of our
    // IDs; we answer on the new path with another of its, so nothing on the
    // wire links the two paths. One that kept the ID — NAT rebinding, which
    // it did not choose — keeps ours (§9.5: "MAY continue to use the current
    // connection ID with the new remote address").
    if (!path.dcid && dcidUsed && context.my_cids.length > 0 && !uint8Equal(dcidUsed, context.my_cids[0])) {
      var fresh = nextPeerCid(old.dcid || context.their_cids[0]);
      if (fresh) path.dcid = fresh;
    }
    var lastValid = old.validated ? old : context.prev_path;

    if (path === context.prev_path) context.prev_path = null;
    if (old.validated) context.prev_path = old;
    // An unvalidated path left behind is abandoned (§9.3: "After changing the
    // address to which it sends non-probing packets, an endpoint can abandon
    // any path validation for other addresses"), what it held with it.
    else stopPathValidation(old);

    if (!path.validated) path.new_ip = !lastValid || lastValid.address !== path.address;
    setPath(path);

    // §9.3.2 / §8.2: a path not seen validated is challenged. One returned
    // to — the connection moving back after a spurious migration — needs no
    // new proof (§9.3 "MAY skip validation of a peer address if that address
    // has been seen recently").
    if (!path.validated) startPathValidation(path);

    // §9.3.3: "In response to an apparent migration, endpoints MUST validate
    // the previously active path using a PATH_CHALLENGE frame." A copy of a
    // genuine packet forwarded by an off-path attacker looks exactly like a
    // NAT rebinding; the challenge makes the real peer answer on the old path,
    // and its next packet there moves the connection back.
    if (context.prev_path === old) startPathValidation(old);
  }

  // §9.4: "On confirming a peer's ownership of its new address, an endpoint
  // MUST immediately reset the congestion controller and round-trip time
  // estimator for the new path to initial values" — the capacity and delay
  // measured to another address say nothing about this one.
  function resetPathEstimates() {
    var now = Date.now();
    if (DEBUG) console.log('[quic] new peer address — congestion and RTT state reset');
    // A new path is not the one the saved state was measured on (RFC 9959
    // §4.2.1); starting again from the initial window, as below, is safer
    // than any of Careful Resume's phases.
    if (context.cr) context.cr.phase = 'done';
    context.current_limit_packets_in_flight = context.init_limit_packets_in_flight;
    context.current_limit_bytes_in_flight = context.init_limit_bytes_in_flight;
    context.current_limit_packets_per_sec = context.init_limit_packets_per_sec;
    context.current_limit_bytes_per_sec = context.init_limit_bytes_per_sec;
    context.current_limit_packet_payload = context.init_limit_packet_payload;
    context.srtt = null;
    context.rttvar = null;
    context.min_rtt = null;
    context.latest_rtt = null;
    context.max_rtt = null;
    context.latest_delivery_rate = null;
    context.max_delivery_rate = null;
    context.bbr_round_count = 0;
    context.bbr_round_start_pn = context.send_pn.app;
    context.bbr_round_start_delivered = context.delivered;
    context.bbr_round_start_time = now;
    context.bbr_btlbw_samples = [];
    context.bbr_btlbw = null;
    context.bbr_min_rtt = null;
    context.bbr_min_rtt_stamp = 0;
    context.bbr_bdp = null;
    context.bbr_state = 'startup';
    context.bbr_round_app_limited = false;
    context.bbr_full_bw = 0;
    context.bbr_full_bw_count = 0;
    context.bbr_ea_start = 0; context.bbr_ea_delivered = 0; context.bbr_ea_round_max = 0;
    context.bbr_ea_rounds = []; context.bbr_extra_acked = 0;
    context.bbr_cycle_idx = 0;
    context.bbr_round_min_rtt = null;
    context.bbr_round_rtt_samples = 0;
    pmtuReset();   // a new path: its MTU found again, from the floor (above)
  }

  // §9.1: PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID and PADDING are
  // probing frames. A packet of nothing else does not move the connection.
  function isProbingOnly(frames) {
    for (var i = 0; i < frames.length; i++) {
      var t = frames[i].type;
      if (t !== 'path_challenge' && t !== 'path_response' && t !== 'new_connection_id' && t !== 'padding') return false;
    }
    return true;
  }

  function hasPathFrame(frameList) {
    for (var i = 0; i < frameList.length; i++) {
      if (frameList[i].type === 'path_challenge' || frameList[i].type === 'path_response') return true;
    }
    return false;
  }

  // RFC 9000 §13.2.1 / RFC 9002 §2: every frame other than ACK, PADDING and
  // CONNECTION_CLOSE elicits an acknowledgment.
  function isAckEliciting(frameList) {
    for (var i = 0; i < frameList.length; i++) {
      var t = frameList[i].type;
      if (t !== 'ack' && t !== 'padding' && t !== 'connection_close') return true;
    }
    return false;
  }

  // path: where the packet goes — the current path unless given.
  // Returns true once the packet is on its way; false when nothing was sent
  // (a closing or draining connection, no keys yet, encryption failed). A
  // caller that marked its frames' bytes as sent takes them back on false.
  // The peer's ID a packet is addressed by: on a path, the one it uses
  // there; else the peer's; a client that has not heard from the server yet,
  // the SCID of its Retry if one came, or still original_dcid (RFC 9000
  // §7.2, §17.2.5.3).
  function destinationCid(packetType, path) {
    return (packetType === '1rtt' && path && path.dcid) ? path.dcid
         : context.their_cids.length > 0 ? context.their_cids[0]
         : context.isServer ? new Uint8Array(0)
         : context.retry_scid || context.original_dcid || new Uint8Array(0);
  }

  // opts (hsFlush only): { collect: [], pad } — the packet is built, recorded
  // and appended to `collect` instead of sent; `pad` bytes of PADDING added to
  // it (the datagram's, which the flush decides), and no padding of its own.
  function sendFrames(space, frameList, path, opts) {
    path = path || context.path;
    // A handshake flight waiting for the end of this turn goes first: a
    // 1-RTT packet ahead of it would reach the peer before the keys to read
    // it (the server's SETTINGS before its Finished).
    if (space === 'app' && context.hs_flush_pending) hsFlush();
    var collect = opts && opts.collect ? opts.collect : null;
    // A held handshake datagram leaves before any other Initial or Handshake
    // packet (a 1-RTT one may ride in it: below, at the send).
    if (context.hs_tail && !collect && space !== 'app') finishHsTail();
    // RFC 9000 §10.2: a draining endpoint MUST NOT send packets at all; a
    // closing endpoint may only (re)send its CONNECTION_CLOSE. Belt-and-
    // suspenders with the timer cleanup — any stray timer (crypto retx, burst,
    // keep-alive) that fires after the state change dies here instead of
    // emitting packets at a dead connection.
    if (context.state === 'draining' || context.state === 'closed') return false;
    if (context.state === 'closing' &&
        !(frameList.length === 1 && frameList[0].type === 'connection_close')) return false;

    var writeKeys = space === 'initial' ? context.initial_write
                  : space === 'handshake' ? context.handshake_write : context.app_write;
    // A client before its 1-RTT keys: early data, in 0-RTT packets.
    var zeroRtt = space === 'app' && !writeKeys && zeroRttSending();
    if (zeroRtt) writeKeys = context.zero_rtt_write;
    if (!writeKeys) {
      if (DEBUG) console.log('[quic] sendFrames(' + space + ') — no keys');
      controlFramesUnsent(frameList);
      return false;
    }

    // Read the next packet number but DON'T commit it yet — only advance
    // send_pn once the packet is successfully encrypted and emitted (below).
    // A failed encryption must not consume a PN: a gap would desync the
    // pn → sending_app_pn_history index math (and RTT). See LOSS_PTO_PLAN §5.
    if (space === 'app' && --context.pn_skip_countdown <= 0) skipPacketNumber();
    var pn = context.send_pn[space];
    var packetType = space === 'initial' ? 'initial' : space === 'handshake' ? 'handshake' : zeroRtt ? '0rtt' : '1rtt';

    // DCID: the peer's ID. A client that has not heard from the server yet
    // addresses it by the SCID of its Retry, if one came, or else still by
    // original_dcid (RFC 9000 §7.2, §17.2.5.3).
    // SCID (long headers only): our own.
    var dcid = destinationCid(packetType, path);
    var scid = packetType === '1rtt' ? new Uint8Array(0) : context.my_cids[0];

    // An ACK owed in this space rides along — any packet we send settles it
    // (see "ACK management"). Only where it fits: callers size their frames
    // to the packet, and a packet that would no longer fit goes without it.
    var carriesAck = false;
    for (var fa = 0; fa < frameList.length; fa++) {
      if (frameList[fa].type === 'ack') { carriesAck = true; break; }
    }
    if (!carriesAck && !zeroRtt && context.state !== 'closing' && ackOwed(space)) {
      var ackF = buildAckFrame(space);
      if (ackF) {
        var withAck = [ackF].concat(frameList);
        if (quic_frames_size(withAck) <= context.current_limit_packet_payload) {
          frameList = withAck;
          carriesAck = true;
        }
      }
    }

    // Control frames waiting in the queue ride along too, after the ACK, in
    // the room the packet has left (see takeControlFrames) — not in a packet
    // that probes a path (padded, and maybe to another address) nor in one
    // of a closing connection.
    if (space === 'app' && !zeroRtt && context.state !== 'closing' && path === context.path &&
        hasQueuedControl() && !hasPathFrame(frameList)) {
      var ctlRoom = context.current_limit_packet_payload - quic_frames_size(frameList);
      var ctl = ctlRoom > 0 ? takeControlFrames(ctlRoom) : [];
      if (ctl.length) {
        var at = carriesAck && frameList[0].type === 'ack' ? 1 : 0;
        frameList = frameList.slice(0, at).concat(ctl, frameList.slice(at));
      }
    }

    // Encoded once, the padding it needs included (below): sized first —
    // quic_frames_size, nothing copied — then written into one buffer.
    var frameBytes = quic_frames_size(frameList), padTo = frameBytes;

    // RFC 9000 §14.1: a client pads every datagram carrying an Initial
    // packet to 1200 bytes; a server "MUST expand the payload of all UDP
    // datagrams carrying ack-eliciting Initial packets". An ACK-only Initial
    // from a server needs none — and padding it spent 1.2 KB of the
    // anti-amplification budget on nothing: two such ACKs are a third of
    // what a Chrome ClientHello buys the whole handshake flight.
    // A packet the flush coalesces is padded as its datagram needs (opts.pad).
    if (collect) {
      padTo = frameBytes + (opts.pad > 0 ? opts.pad : 0);
    } else if (space === 'initial' && (!context.isServer || isAckEliciting(frameList))) {
      var overhead = 1 + 4 + 1 + dcid.byteLength + 1 + scid.byteLength + 1 + 2 + 1 + 16;
      var minPayload = 1200 - overhead;
      if (padTo < minPayload) padTo = minPayload;
    }

    // §8.2.1 / §8.2.2: a datagram carrying PATH_CHALLENGE or PATH_RESPONSE
    // is expanded to 1200 bytes — which is what proves the path carries
    // datagrams that size — but "MUST NOT" be where that would exceed the
    // path's anti-amplification limit. The packet-number length is not known
    // here: counted at its shortest for the full size (overshooting a
    // minimum is fine), at its longest when the budget is the ceiling.
    if (!collect && space === 'app' && hasPathFrame(frameList)) {
      var target = path.validated ? 1200 : Math.min(1200, ampBudget(path));
      var shortOverhead = 1 + dcid.byteLength + (target === 1200 ? 1 : 4) + 16;
      if (padTo < target - shortOverhead) padTo = target - shortOverhead;
    }
    var encoded = encode_quic_frames(frameList, padTo - frameBytes);

    // A client's Initial packets carry the Retry token, once it has one
    // (§17.2.5.3: "copied to all subsequent Initial packets").
    var token = (space === 'initial' && !context.isServer) ? (context.retry_token || context.initial_token) : null;

    // The fixed bit, greased (RFC 9287): unpredictable once the peer said
    // it takes either — never in an Initial, which may reach a server that
    // has not said so yet.
    var greaseBit = context.peer_grease_quic_bit && space !== 'initial' && (randomByte() & 1) === 1;
    var encrypted = encrypt_quic_packet(
      packetType, encoded, writeKeys.key, writeKeys.iv, writeKeys.hp, pn, dcid, scid, token,
      space === 'app' ? context.key_phase : false, writeKeys.aead, context.version, greaseBit
    );

    if (encrypted) {
      // Commit the packet number now that the packet is real and about to go
      // out on the wire — atomic with the bookkeeping below, so send_pn and
      // sending_app_pn_history always advance together (no phantom PN).
      context.send_pn[space] = pn + 1;
      if (zeroRtt) context.zero_rtt_pn_last = pn;
      if (DEBUG) {
        var fnames = frameList.map(function(f){ return f.type + (f.type === 'ack' ? '(lg=' + f.largest + ')' : ''); }).join(',');
        console.log('[quic] → ' + packetType + ' pn=' + pn + ' frames=[' + fnames + '] len=' + encrypted.length);
      }
      if (TRACE_ACK) {
        for (var ti = 0; ti < frameList.length; ti++) {
          var tf = frameList[ti];
          if (tf.type !== 'ack') continue;
          // The packet numbers it acknowledges, as the peer will read them.
          var acked = [], hi = tf.largest, lo = hi - tf.firstRange;
          acked.push(lo === hi ? String(hi) : lo + '-' + hi);
          for (var tr = 0; tr < (tf.ranges || []).length; tr++) {
            hi = lo - tf.ranges[tr].gap - 2;
            lo = hi - tf.ranges[tr].length;
            acked.push(lo === hi ? String(hi) : lo + '-' + hi);
          }
          console.log('[quic-ack] ' + Date.now() % 100000 + ' out ' + space + ' pn=' + pn + ' ACK ' + acked.join(',') + (frameList.length > 1 ? ' +' + (frameList.length - 1) + ' frames' : ''));
        }
      }
      touchActivity();
      if (isAckEliciting(frameList)) ackElicitingSent();
      if (carriesAck) ackSent(space);

      if (space === 'app') {
        context.sending_app_pn_history.push([Date.now(), encrypted.length, context.delivered, context.delivered_time]);
        // In flight, by its size on the wire, until acknowledged or given up
        // on (pkt_in_flight) — whatever it carries, if the peer must ACK it.
        if (isAckEliciting(frameList)) {
          if (context.backoff_mark !== context.last_ack_time) {
            context.backoff_mark = context.last_ack_time;
            context.backoff_since = Date.now();
          }
          context.pkt_in_flight.set(pn, { bytes: encrypted.length, t: Date.now() });
          if (context.tlp_at === 0 || context.tlp_timer === null) tlpRearm(); else context.tlp_at = Date.now() + tlpDelay();
          context.app_bytes_in_flight += encrypted.length;
        }
        // In flight = carrying STREAM data, which expireInFlight finds and
        // retires through its stream. 1-RTT CRYPTO is the control queue's to
        // track (see cryptoWrite); counted here too, a lost one was never
        // found by anything and held a slot of the packet budget forever.
        // DATAGRAM frames are in flight too, with nothing to resend
        // (no_resend_in_flight, see sendDatagram).
        var has_data = false, datagramBytes = 0, payloadBytes = 0;
        for (var i = 0; i < frameList.length; i++) {
          if (frameList[i].type === 'stream') { has_data = true; payloadBytes += frameList[i].data ? frameList[i].data.byteLength : 0; }
          else if (frameList[i].type === 'datagram') datagramBytes += frameList[i].data.byteLength;
        }
        context.stats_datagram_bytes_sent += datagramBytes;
        var inFlightPk = context.pkt_in_flight.get(pn);
        if (inFlightPk) inFlightPk.payload = payloadBytes + datagramBytes;   // getStats' bytesAcknowledged
        if (has_data || datagramBytes > 0) context.sending_app_pn_in_flight.add(pn);
        if (datagramBytes > 0) {
          context.no_resend_in_flight[pn] = (context.no_resend_in_flight[pn] || 0) + datagramBytes;
        }

        for (var i = 0; i < frameList.length; i++) {
          if (frameList[i].type === 'stream') {
            var sid = frameList[i].id;
            var dataLen = frameList[i].data ? frameList[i].data.byteLength : 0;

            // Track connection-level bytes sent
            context.bytes_sent += dataLen;

            if (sid in context.send_streams) {
              if (!context.send_streams[sid].in_flight_ranges) context.send_streams[sid].in_flight_ranges = {};
              // The packets that carry this stream's FIN: its delivery is
              // tracked like the bytes' (see fin_acked).
              if (frameList[i].fin) {
                (context.send_streams[sid].fin_pns || (context.send_streams[sid].fin_pns = {}))[pn] = true;
                // The peer may know the final size from now on: a reset
                // after it must carry the same (RFC 9000 §4.5).
                context.send_streams[sid].fin_went = true;
              }
              var from = frameList[i].offset;
              var to = from + (frameList[i].data ? frameList[i].data.byteLength : 0);
              // One packet can carry two pieces of one stream — new data and a
              // resent gap — so a packet's entry is a range list, not a span.
              if (!context.send_streams[sid].in_flight_ranges[pn]) {
                context.send_streams[sid].in_flight_ranges[pn] = [from, to];
                var pnList = context.pn_sids.get(pn);
                if (pnList) pnList.push(sid); else context.pn_sids.set(pn, [sid]);
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
            // bytes: the packet's size, which its ACK grows the window by.
            if (cTo > cFrom) context.crypto_sent[space].in_flight[pn] = { range: [cFrom, cTo], time_sent: Date.now(), bytes: encrypted.length };
          }
        }
      }

      if (space === 'app') controlFramesSent(pn, frameList);
      if (collect) collect.push({ bytes: encrypted, space: space, pn: pn });
      else if (space === 'app' && context.hs_tail && hsTailTake({ bytes: encrypted, space: space, pn: pn }, path)) { /* in the handshake's datagram */ }
      else {
        if (context.hs_tail) finishHsTail();   // the handshake's datagram first, in order
        emitPacket(encrypted, space, pn, path);
      }

      // RFC 9001 §4.9.1: "a client MUST discard Initial keys when it first
      // sends a Handshake packet." After the packet is on its way, not before:
      // it is the discard's trigger, not its casualty.
      if (!context.isServer && space === 'handshake') discardSpace('initial');
      return true;
    }
    controlFramesUnsent(frameList);
    return false;
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

  // ============================================================
  //  The send queue
  // ============================================================
  //
  // What the application wrote on a stream and the peer has not acknowledged
  // yet, held as the application's own buffers, in order: st.q the pieces,
  // st.q_off the stream offset each one starts at, st.q_head the first one
  // still live, st.queue_bytes their total.
  //
  // Nothing is copied on the way in. The stream used to keep one contiguous
  // buffer and copy every write into it: a 30 MB res.end() was copied into a
  // buffer twice its size, which held ~120 MB for a 30 MB response — and
  // every concurrent download of the same file held its own copies.
  // Writes up to SEND_COALESCE_MAX are the exception: they are copied into a
  // tail buffer of the stream's own, so a thousand small writes make one
  // piece rather than a thousand (an H3 frame header is such a write).
  //
  // On the way out a packet takes a view of one piece, or — where it straddles
  // two — a copy of its own bytes only (sendQueueRead). A piece leaves as soon
  // as the peer has acknowledged all of it (sendQueueRelease, called from
  // the ACK path), not the next time something is sent.
  //
  // As with net.Socket, a buffer handed to write() must not be modified until
  // it has been acknowledged: a large one is referenced, not copied.
  var SEND_COALESCE_MAX = 4096;   // writes up to this size are copied into the tail
  var SEND_TAIL_SIZE = 16384;     // the largest a tail buffer grows to
  // A stream's first tail is small and each next one twice the last, up to
  // SEND_TAIL_SIZE: most streams write a few small pieces in all — a
  // request's HEADERS, an HTTP/3 frame header, a short response — and each
  // took a zero-filled 16 KB buffer for them: 16 KB of garbage per request,
  // a tenth of a small-request client's CPU in collection.
  var SEND_TAIL_FIRST = 512;

  function sendQueuePush(st, chunk) {
    var n = chunk.byteLength;
    if (n === 0) return;
    var at = st.write_offset;
    st.write_offset += n;
    st.queue_bytes += n;
    flat_ranges.add(st.missing_ranges, [at, at + n]);   // written, not yet sent: missing
    var last = st.q.length - 1;
    if (n <= SEND_COALESCE_MAX) {
      // Into the open tail if it has room; the tail is always the last piece,
      // grown in place (bytes already handed out as views never change).
      var t = st.tail_buf;
      if (t && last >= st.q_head && st.q[last].buffer === t.buffer && st.q[last].byteLength + n <= t.byteLength) {
        var used = st.q[last].byteLength;
        t.set(chunk, used);
        st.q[last] = t.subarray(0, used + n);
        return;
      }
      var cap = st.tail_next || SEND_TAIL_FIRST;
      st.tail_next = Math.min(SEND_TAIL_SIZE, cap * 2);
      t = st.tail_buf = new Uint8Array(Math.max(cap, n));
      t.set(chunk, 0);
      st.q.push(t.subarray(0, n));
      st.q_off.push(at);
      return;
    }
    st.tail_buf = null;           // what follows starts a tail of its own
    st.q.push(chunk);
    st.q_off.push(at);
  }

  // len bytes of the stream from offset `from`, which the caller has kept
  // inside [sendQueueStart(st), st.write_offset).
  function sendQueueRead(st, from, len) {
    var lo = st.q_head, hi = st.q.length - 1;
    while (lo < hi) {                       // last piece starting at or before `from`
      var mid = (lo + hi + 1) >> 1;
      if (st.q_off[mid] <= from) lo = mid; else hi = mid - 1;
    }
    var piece = st.q[lo], rel = from - st.q_off[lo];
    if (rel + len <= piece.byteLength) return piece.subarray(rel, rel + len);
    var out = new Uint8Array(len), o = 0;
    while (o < len) {
      piece = st.q[lo++];
      var take = Math.min(piece.byteLength - rel, len - o);
      out.set(piece.subarray(rel, rel + take), o);
      o += take; rel = 0;
    }
    return out;
  }

  // The first offset still held: everything below it has been acknowledged.
  function sendQueueStart(st) {
    return st.q_head < st.q.length ? st.q_off[st.q_head] : st.write_offset;
  }

  // The peer has acknowledged every byte below ackedTo: let go of the pieces
  // that lie wholly beneath it. A piece acknowledged in part stays whole.
  function sendQueueRelease(st, ackedTo) {
    var h = st.q_head;
    while (h < st.q.length && st.q_off[h] + st.q[h].byteLength <= ackedTo) {
      st.queue_bytes -= st.q[h].byteLength;
      if (st.tail_buf && st.q[h].buffer === st.tail_buf.buffer) st.tail_buf = null;
      st.q[h] = null;
      h++;
    }
    if (h === st.q.length) { st.q.length = 0; st.q_off.length = 0; h = 0; }
    else if (h > 64 && h * 2 >= st.q.length) { st.q.splice(0, h); st.q_off.splice(0, h); h = 0; }
    st.q_head = h;
  }

  // Backpressure. The writer above (a ServerResponse, a WebTransport stream)
  // hands a write over and asks to be told when the stream has caught up:
  // when what it wrote and the stream has not yet sent once falls to `bytes`.
  // That is the writer's callback — net.Socket's, which Node calls once the
  // kernel has the data — and Node's Writable turns it into write() returning
  // false and 'drain'. Called at once if the stream is already there, or gone.
  // Bytes sent but not yet acknowledged do not count: the congestion window
  // bounds them, as the kernel's buffer bounds a TCP socket's. Without this
  // every write was acknowledged at once: piping a file into a response read
  // all of it into memory, whatever the client's pace.
  //
  // While the connection is closing or draining nothing more will be sent,
  // and the writer is held: released once the connection is closed, after
  // 'close' — by then the layers above have ended the stream, so a pipe has
  // stopped. Released at the start of the closing period instead, a pipe ran
  // on for its ~3 s and pushed its whole source into a connection that would
  // never send it.
  // A stream of ours past the peer's MAX_STREAMS waits (localStreamPermitted);
  // cb(null) once it may be opened — at once if it may now — or cb(err) if the
  // connection closes first. For WebTransport's waitUntilAvailable: the
  // stream exists, its bytes queue, and this says when it is really open.
  var permitWaiters = [];
  function whenStreamPermitted(streamId, cb) {
    var sid = Number(streamId);
    if (context.state === 'closing' || context.state === 'draining' || context.state === 'closed') { cb(new Error('the connection is closing')); return; }
    if (localStreamPermitted(sid)) { cb(null); return; }
    permitWaiters.push({ sid: sid, cb: cb });
  }
  function releasePermitWaiters() {
    if (permitWaiters.length === 0) return;
    var still = [], ready = [];
    for (var i = 0; i < permitWaiters.length; i++) (localStreamPermitted(permitWaiters[i].sid) ? ready : still).push(permitWaiters[i]);
    permitWaiters = still;
    for (var j = 0; j < ready.length; j++) ready[j].cb(null);
  }
  function failPermitWaiters() {
    var w = permitWaiters; permitWaiters = [];
    for (var i = 0; i < w.length; i++) w[i].cb(new Error('the connection is closing'));
  }

  function streamSendWindow(streamId) {
    var st = context.send_streams[Number(streamId)];
    if (!st) return 0;
    var queued = 0;
    for (var k in context.send_streams) {
      var o = context.send_streams[k];
      if (o.write_offset > o.max_sent_offset) queued += o.write_offset - o.max_sent_offset;
    }
    var streamRoom = st.remote_max_stream_data - st.write_offset;
    var connRoom = context.remote_max_data - context.max_data_sent - queued;
    return Math.max(0, Math.min(streamRoom, connRoom));
  }

  // The connection's figures, as WebTransport's getStats() reports them
  // (W3C WebTransportConnectionStats), and what QUICO's congestion control
  // knows besides. Times in ms; estimatedSendRate in bits per second (BBR's
  // bottleneck-bandwidth estimate; null until measured).
  // An exception of ours, caught: in the connection (internal_errors, the
  // last one's stack) and the server's counters. The packet being processed
  // is dropped (above), or HTTP/3 closes with H3_INTERNAL_ERROR (h3.js).
  // Reading e.stack formats the whole trace — a few hundred microseconds,
  // paid for every bad packet: a peer (or a scanner) sending many of them
  // cost the thread more in traces than in packets. The message always; the
  // stack, and a log line, once a minute per connection — the bug it points
  // at is the same one.
  function countInternalError(e) {
    context.internal_errors = (context.internal_errors || 0) + 1;
    var now = Date.now();
    if (now - (context.internal_error_logged_at || 0) >= 60000) {
      context.internal_error_logged_at = now;
      context.last_internal_error = (e && e.stack) || String(e);
      console.warn('[quic] packet dropped on an internal error (' + context.internal_errors + ' on this connection so far): ' + context.last_internal_error);
    } else {
      context.last_internal_error = (e && e.message) || String(e);
    }
    if (serverStats) serverStats.internalErrors++;
  }

  function getStats() {
    return {
      bytesSent: context.stats_bytes_sent,
      packetsSent: context.stats_packets_sent,
      packetsLost: context.lost_count,
      bytesLost: context.stats_bytes_lost,
      // The application's bytes: new STREAM data and DATAGRAM payloads sent
      // (no retransmissions, no framing), and the payload acknowledged.
      payloadBytesSent: context.max_data_sent + context.stats_datagram_bytes_sent,
      payloadBytesAcknowledged: context.stats_payload_acked,
      bytesReceived: context.stats_bytes_received,
      packetsReceived: context.stats_packets_received,
      smoothedRtt: context.srtt,
      rttVariation: context.rttvar,
      minRtt: context.min_rtt,
      estimatedSendRate: context.bbr_btlbw ? Math.round(context.bbr_btlbw * 8) : null,
      congestionWindow: context.current_limit_bytes_in_flight,
      bytesInFlight: context.app_bytes_in_flight,
      // Sending as fast as congestion control lets it: the window (less a
      // packet's room) is full.
      atSendCapacity: context.app_bytes_in_flight + context.current_limit_packet_payload >= context.current_limit_bytes_in_flight,
      datagramsExpired: context.datagrams_dropped,
      // Packets given up on before the retransmission timeout — a later
      // one's ACK past the time threshold — that were acknowledged after
      // all: the threshold too short for this path's reordering (raise
      // reorderWindow if it climbs).
      spuriousLosses: context.stats_spurious_early,
      // Careful Resume's phase on a resumed connection (RFC 9959), or null.
      carefulResume: context.cr ? context.cr.phase : null
    };
  }

  // The sending part of a stream in "Data Recvd" (RFC 9000 §3.1) — every
  // byte and the FIN acknowledged: cb() then, once — at once if it is
  // already. A stream reset first (RESET_STREAM, RESET_STREAM_AT), or a
  // connection that ends first: never. What a sender with a deadline on
  // delivery waits for (MOQT's SUBGROUP_DELIVERY_TIMEOUT): the end of a
  // write only says the bytes were handed over.
  function whenStreamCommitted(streamId, cb) {
    streamId = Number(streamId);
    var st = context.send_streams[streamId];
    if (st) { (st.committed_waits || (st.committed_waits = [])).push(cb); return; }
    var fin = context.send_final.get(streamId);
    if (fin !== undefined && fin >= 0) queueMicrotask(cb);   // committed already; -1: reset
  }

  function whenStreamSent(streamId, bytes, cb) {
    var st = context.send_streams[streamId];
    if (context.state === 'closed') { cb(); return; }
    if (st && (context.state === 'closing' || context.state === 'draining')) { parkSentWait(st, bytes, cb); return; }
    if (!st || st.write_offset - st.max_sent_offset <= bytes) { cb(); return; }
    parkSentWait(st, bytes, cb);
  }
  function parkSentWait(st, bytes, cb) {
    if (st.sent_wait) { var prev = st.sent_wait.cb; st.sent_wait = null; prev(); }   // one writer per stream
    st.sent_wait = { bytes: bytes, cb: cb };
  }
  function releaseSentWaits() {
    for (var sid in context.send_streams) checkSentWait(context.send_streams[sid], true);
    fireAllSent();
  }

  // Everything written on every stream acknowledged — bytes and FINs. For a
  // graceful close (HTTP/3 GOAWAY): CONNECTION_CLOSE stops all sending, so
  // closing when the last response is merely *written* lost whatever of it
  // was still in flight.
  function allDelivered() {
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (st.queue_bytes > 0) return false;                  // bytes not yet acknowledged
      if (st.fin_set && !st.fin_acked) return false;         // a FIN not yet acknowledged
    }
    return true;
  }
  var allSentWaiters = [];
  function whenAllSent(cb) {
    if (context.state === 'closed' || allDelivered()) { queueMicrotask(cb); return; }
    allSentWaiters.push(cb);
  }
  function fireAllSent() {
    if (allSentWaiters.length === 0) return;
    var ws = allSentWaiters; allSentWaiters = [];
    for (var i = 0; i < ws.length; i++) queueMicrotask(ws[i]);
  }
  // Called where max_sent_offset advances, and wherever a stream ends. The
  // callback runs after the burst in progress, never inside it: it writes.
  function checkSentWait(st, gone) {
    var w = st.sent_wait;
    if (!w || (!gone && st.write_offset - st.max_sent_offset > w.bytes)) return;
    st.sent_wait = null;
    queueMicrotask(w.cb);
  }

  // Anything on this stream for the sender to look at: bytes held (sent or
  // not — what is missing is the caller's to work out), or a FIN still to go.
  function hasBufferedData(st) {
    return st.queue_bytes > 0 || (st.fin_set && !st.fin_sent);
  }

  // ── What of a stream is still to send ───────────────────────────────────
  // flat-ranges' three states, of what the peer has of the stream's bytes:
  //   have     acked_ranges     acknowledged — it has them, for good
  //   not_have missing_ranges   written and not on the network: never sent,
  //                             or given up on — it surely lacks them
  //   unknown  (the rest)       in flight: in_flight_ranges, by packet
  // have and not_have never overlap. missing_ranges is what the sender sends
  // from, and it changes at five points, and nowhere else:
  //   the application writes bytes (sendQueuePush)  → added
  //   get_stream_chunks yields bytes                → removed
  //   an ACK credits bytes (creditRanges)           → removed (a late ACK can
  //                                                   name bytes that expired)
  //   expireInFlight gives a packet up              → its bytes added, except
  //                                                   any acknowledged meanwhile
  //                                                   (add_not_have)
  //   a packet that never left (execute_quic_burst) → its bytes added
  // Adding a packet's bytes back is exact because each byte is in flight in
  // one packet at most: bytes are yielded only while missing, and missing
  // again only once the packet that carried them has expired.
  //
  // (It used to be kept the other way round — sent_ranges, acked ∪ in
  // flight — with what is missing computed as its complement on each pass,
  // and "acked ⊆ sent" kept by hand at each of those points.)
  function nothingMissing(st) {
    return st.missing_ranges.length === 0;
  }

  // A stream leaves send_streams (reset, or every byte acknowledged) with
  // packets of its own still on the network: they stay counted until they
  // are acknowledged or expire, as no_resend_in_flight — RFC 9002 counts bytes
  // in flight until then, and a packet expiry could not find through its
  // stream would hold a slot of the packet budget forever.
  function releaseStreamInFlight(st) {
    for (var pn in st.in_flight_ranges) {
      context.no_resend_in_flight[pn] = (context.no_resend_in_flight[pn] || 0) + flat_ranges.length(st.in_flight_ranges[pn]);
    }
    st.in_flight_ranges = {};   // the bytes moved, the count did not change
  }

  /**
   * Buffer data for a stream. Does NOT send: asks for a send pass at the
   * end of the tick (scheduleSend).
   */
  function set_sending_stream(streamId, options) {
    // Reset: nothing more is sent on it, whoever still writes (RFC 9000 §3.1).
    noteLocalStream(streamId);
    if (context.send_final.get(Number(streamId)) === -1) return;
    // A connection that is closing will send nothing more: what is written now
    // is dropped, not queued — a writer that ignores the end would otherwise
    // fill memory with data that can never leave.
    if (context.state === 'closing' || context.state === 'draining' || context.state === 'closed') return;
    if (!(streamId in context.send_streams)) {
      context.send_streams[streamId] = {
        q: [], q_off: [], q_head: 0, queue_bytes: 0, tail_buf: null,   // the send queue (below)
        write_offset: 0, send_offset: 0, total_size: 0,
        // The FIN is written: total_size is the stream's final size — which
        // may be 0 (a stream ended with no data). total_size alone could not
        // tell that end from "not ended": such a FIN never went, and the
        // stream stayed for the connection's life.
        fin_set: false,
        fin_sent: false, acked_ranges: [], in_flight_ranges: {},
        missing_ranges: [],   // what the peer surely lacks — see "What of a stream is still to send"
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
    if (stream.reset_at) return;   // RESET_STREAM_AT: nothing more is written

    if (typeof options === 'object' && 'add_chunk' in options) {
      if (options.add_chunk.data === null || options.add_chunk.data === undefined) {
        if (!stream.fin_set) {
          stream.fin_set = true;
          stream.total_size = stream.write_offset;
          if (DEBUG) console.log('[quic] stream ' + streamId + ' FIN via null data, total_size=' + stream.total_size);
        }
      } else {
        // One buffer, or several written as one (a frame header and its
        // payload: queued together, scheduled once, so the header never
        // leaves in a packet of its own).
        var parts = Array.isArray(options.add_chunk.data) ? options.add_chunk.data : [options.add_chunk.data];
        for (var pi = 0; pi < parts.length; pi++) {
          var chunk = parts[pi];
          if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
          sendQueuePush(stream, chunk);
        }
        if (DEBUG) console.log('[quic] stream ' + streamId + ' add_chunk write_offset=' + stream.write_offset + ' fin=' + !!options.add_chunk.fin);
        if (options.add_chunk.fin) {
          stream.fin_set = true;
          stream.total_size = stream.write_offset;
          if (DEBUG) console.log('[quic] stream ' + streamId + ' FIN via add_chunk.fin, total_size=' + stream.total_size);
        }
      }
    }

    scheduleSend();
  }

  // ── Writes go out once per tick ─────────────────────────────────────────
  // A write does not send: it asks for one send pass at the end of the
  // current tick, and every write until then rides in it. Sent at once, each
  // write left in a packet of its own — a response written as headers, ten
  // small writes and an end went out as 14 datagrams of ~40 bytes each, every
  // one a header, an encryption and a system call, each billed by the pacer
  // as a full packet. Gathered, they fill packets.
  //
  // Only writes wait. A pass for any other reason (an ACK, a timer, flow
  // control opening) still runs at once, and takes whatever is waiting with
  // it — plan_quic_burst clears the request, so the tick's pass then has
  // nothing to do. close() sends what is waiting before CONNECTION_CLOSE, as
  // it went out before when writes were sent at once.
  function scheduleSend() {
    if (context.send_scheduled) return;
    context.send_scheduled = true;
    queueMicrotask(sendScheduled);
  }

  function sendScheduled() {
    if (!context.send_scheduled) return;   // a pass ran meanwhile and took it
    plan_quic_burst();
  }

  function sendStream(streamId, data, fin) {
    set_sending_stream(streamId, { add_chunk: { data: data, fin: fin } });
  }

  // ── DATAGRAM frames (RFC 9221) ─────────────────────────────────────────
  // Never retransmitted — a lost one is gone, and nobody is told — but sent
  // under the congestion controller like everything else (§5.4): the packets
  // that carry them count against the window, are acknowledged, and their
  // loss slows the sender. They were sent the moment they were written, each
  // in a packet of its own, past the window and the pacer: a burst overran
  // the path and was lost there, and crowded out the streams beside it.
  //
  // So they wait here for room, and execute_quic_burst takes them into
  // packets ahead of stream data — late, a datagram is worth nothing, so it
  // is not left behind a stream that can wait. While the path cannot keep up
  // the queue would only grow, each datagram later than the last; it is
  // bounded instead, and what goes is the oldest — the one least worth
  // sending. Bounded by bytes and by age: one that has waited datagramMaxAge
  // (250 ms unless set) is dropped rather than sent.
  var DATAGRAM_QUEUE_BYTES = 1024 * 1024;   // a cap on memory; the age is the working bound
  var datagramMaxAge = 250;   // ms; setDatagramMaxAge (WebTransport's outgoingMaxAge)
  var DATAGRAM_FRAME_OVERHEAD = 3;   // type (0x31) and a length of up to 2 bytes

  // Queued: true — it will be sent if room comes in time. false: it cannot
  // be — not connected, the peer takes no datagrams, or larger than it takes
  // or than a packet holds (a datagram is never split, §3).
  // prio (optional): { urgency, group, order } — the datagram then waits its
  // turn among streams like one of them (execute_quic_burst's tiers), as a
  // WebTransport datagram writable with a sendOrder does. Without it,
  // datagrams go ahead of all stream data.
  // owner (optional): whose datagram it is — a WebTransport session —
  // { maxAge (ms; null: the connection's, setDatagramMaxAge), expired (the
  // count of its datagrams dropped unsent, kept here) }. Sessions on one
  // connection share its queue; each has its own age limit and its own count.
  function sendDatagram(data, prio, owner) {
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    if (data.byteLength > maxDatagramSize() || maxDatagramSize() === 0) return false;
    context.datagram_queue.push({ data: data, t: Date.now(), prio: prio || null, owner: owner || null });
    context.datagram_queue_bytes += data.byteLength;
    while (context.datagram_queue_bytes > DATAGRAM_QUEUE_BYTES) dropOldestDatagram();
    scheduleSend();
    return true;
  }

  function dropOldestDatagram() {
    dropDatagram(context.datagram_queue.shift());
  }
  function dropDatagram(d) {
    context.datagram_queue_bytes -= d.data.byteLength;
    context.datagrams_dropped++;
    if (d.owner) d.owner.expired = (d.owner.expired || 0) + 1;
  }
  function datagramTooOld(d, now) {
    var age = d.owner && d.owner.maxAge != null ? d.owner.maxAge : datagramMaxAge;
    return now - d.t > age;
  }

  // The datagrams without a priority that fit in `room` bytes of a packet,
  // oldest first, as frames; those too old to send are dropped on the way.
  function takeDatagrams(room) {
    return takeMatching(room, function (d) { return !d.prio; });
  }

  // Those of one scheduler member: one group at one order — or, without a
  // group, one urgency at one order.
  function takePrioritizedDatagrams(m, room) {
    return takeMatching(room, function (d) {
      var p = d.prio;
      if (!p || (p.order || 0) !== m.order) return false;
      if (m.dg) return p.group === m.dg;
      return !p.group && (p.urgency != null ? p.urgency : 3) === m.urgency;
    });
  }

  function takeMatching(room, match) {
    var q = context.datagram_queue, out = [], now = Date.now();
    while (q.length > 0 && datagramTooOld(q[0], now)) dropOldestDatagram();
    for (var i = 0; i < q.length; ) {
      var d = q[i];
      // A session's own limit may be shorter than the head's: checked as met.
      if (datagramTooOld(d, now)) { q.splice(i, 1); dropDatagram(d); continue; }
      if (!match(d)) { i++; continue; }
      // Larger than any packet takes now — queued when packets were larger
      // (DPLPMTUD found a black hole since): it would hold the queue for
      // good. A datagram may be dropped (RFC 9221 §5), and this one is.
      if (d.data.byteLength + DATAGRAM_FRAME_OVERHEAD > context.current_limit_packet_payload) { q.splice(i, 1); dropDatagram(d); continue; }
      if (d.data.byteLength + DATAGRAM_FRAME_OVERHEAD > room) break;   // in order: no overtaking
      q.splice(i, 1);
      context.datagram_queue_bytes -= d.data.byteLength;
      out.push({ type: 'datagram', data: d.data });
      room -= d.data.byteLength + DATAGRAM_FRAME_OVERHEAD;
    }
    return out;
  }

  // Largest datagram payload that can be sent: what fits in a packet, and in
  // the peer's max_datagram_frame_size. 0: none can be — not connected, or
  // the peer did not say it takes them.
  function maxDatagramSize() {
    if (context.state !== 'connected' || !context.peer_max_datagram_frame_size) return 0;
    return Math.max(0, Math.min(context.peer_max_datagram_frame_size, context.current_limit_packet_payload) - DATAGRAM_FRAME_OVERHEAD);
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
  // The stream data packet `pnum` carried (`sids`), given up on: missing
  // again, to be resent; parked for a late ACK (expired_unacked).
  function expireStreamsOf(pnum, sids, now) {
    for (var esi = 0; esi < sids.length; esi++) {
      var sid = sids[esi];
      var st = context.send_streams[sid];
      var pn = pnum;
      if (!st || !(pn in st.in_flight_ranges)) continue;   // acked, reset or retired since
      // Park the ranges before forgetting them, so a late ACK can still be
      // honoured (see expired_unacked above). Keyed per-PN; a packet that
      // carried several streams accumulates one entry per stream.
      var limbo = context.expired_unacked[pnum];
      if (!limbo) { limbo = context.expired_unacked[pnum] = { t: now, spans: [] }; context.limbo_n++; }
      var finLost = !!(st.fin_pns && st.fin_pns[pnum]);
      var lostRanges = st.in_flight_ranges[pn];
      limbo.spans.push([sid, lostRanges, finLost]);

      // → missing again, resent next pass — except what an ACK for an
      // earlier copy has acknowledged since: add_not_have leaves what is
      // in have (acked_ranges) where it is.
      delete st.in_flight_ranges[pn];
      flat_ranges.add_not_have(st.acked_ranges, st.missing_ranges, lostRanges);
      // The FIN went with it: send it again. Bytes come back as "missing"
      // and are resent with the FIN when they reach the end; a FIN that
      // went alone has nothing to come back with — fin_sent held it
      // "sent" for good, and the peer never saw the stream end.
      if (finLost) { delete st.fin_pns[pnum]; if (!st.fin_acked) st.fin_sent = false; }
      // Count the loss once per packet: the Set holds each PN once, so the
      // first stream to expire it returns true; later same-PN deletes (a
      // multi-stream packet) return false and don't double-count.
      if (context.sending_app_pn_in_flight.delete(pnum)) countLostPacket(pnum);
    }
  }

  // One packet given up on now, as expireInFlight gives one up on its
  // timeout: its stream data, its place in flight, its bytes (kept for a
  // late ACK). For a 1-RTT packet that rode in a handshake datagram known
  // lost (hsPeerResent): the datagram's loss is its loss.
  function expireAppPacket(pnum) {
    var now = Date.now();
    var sids = context.pn_sids.get(pnum);
    if (sids) { context.pn_sids.delete(pnum); expireStreamsOf(pnum, sids, now); }
    // Given up on before the timeout: a late ACK for it says the threshold
    // was too short (getStats().spuriousLosses; reorderWindow).
    if (context.expired_unacked[pnum]) context.expired_unacked[pnum].early = true;
    if (pnum in context.no_resend_in_flight) {
      delete context.no_resend_in_flight[pnum];
      if (context.sending_app_pn_in_flight.delete(pnum)) countLostPacket(pnum);
    }
    if (context.pkt_in_flight.has(pnum)) {
      var pBytes = forgetPacket(pnum);
      if (context.expired_unacked[pnum]) context.expired_unacked[pnum].bytes = pBytes;
      if (pBytes > 0) pmtuOnLost(pnum, pBytes);
    }
    // Control frames it carried: lost too, queued again.
    controlPacketLost(pnum);
  }

  // ── 1-RTT loss by ACK: the time threshold (RFC 9002 §6.1.2) ────────────
  //
  // expireInFlight gives a packet up after the retransmission timeout —
  // srtt + 4·rttvar + max_ack_delay, three RTTs on a new connection, where
  // rttvar is half the first sample. A packet in the middle of a response
  // whose later packets are acknowledged is known missing well before that:
  // here it is given up on once a later one is acknowledged and
  // max(9/8·RTT, RTT + APP_REORDER_FLOOR) has passed since it was sent
  // (RTT: the larger of srtt and the latest sample). The time threshold
  // only — RFC 9002's packet threshold (three later packets acknowledged)
  // is left out: a packet that arrives out of order is not resent for it,
  // only for being later than the threshold. The floor keeps that so on a
  // short path, where an eighth of the RTT is a millisecond or two — less
  // than Wi-Fi's own retransmissions reorder by. Then exactly the timeout's
  // path (expireAppPacket): resent, parked for a late ACK, counted lost; no
  // congestion response but what a loss already brings (Careful Resume's,
  // RFC 9959).
  // The floor: reorderWindow (5 ms by default).
  function appLossThreshold() {
    if (context.srtt === null) return null;
    var r = Math.max(context.srtt, context.latest_rtt || 0);
    return Math.max(9 / 8 * r, r + context.reorder_window);
  }

  function appDetectLost() {
    var la = context.app_largest_acked, thr = appLossThreshold();
    if (la < 0 || thr === null || context.state !== 'connected') return false;
    var now = Date.now(), lost = [], nextAt = 0;
    // In packet-number order, which is the order they were sent: the first
    // one still inside the threshold ends the walk.
    for (var pe of context.pkt_in_flight) {
      if (pe[0] >= la) break;
      if (now - pe[1].t >= thr) lost.push(pe[0]);
      else { nextAt = pe[1].t + thr; break; }
    }
    for (var i = 0; i < lost.length; i++) expireAppPacket(lost[i]);
    context.app_loss_at = nextAt;
    if (nextAt) armAppLossTimer();
    if (lost.length) {
      if (DEBUG) console.log('[quic] lost by ACK (time threshold ' + Math.round(thr) + 'ms): ' + lost.join(','));
      if (hasQueuedControl()) context.control_due = true;
      scheduleSend();
    }
    return lost.length > 0;
  }

  function armAppLossTimer() {
    if (context.app_loss_timer !== null) return;   // it looks at app_loss_at when it fires
    context.app_loss_timer = setTimeout(function appLossTick() {
      context.app_loss_timer = null;
      if (!context.app_loss_at || context.state !== 'connected') return;
      if (Date.now() < context.app_loss_at) { armAppLossTimer(); return; }
      appDetectLost();
    }, Math.max(1, Math.ceil(context.app_loss_at - Date.now())));
    if (context.app_loss_timer.unref) context.app_loss_timer.unref();
  }

  // ── Tail loss probe (RFC 8985 §7) ──────────────────────────────────────
  //
  // The last packet of a response — or a request in one packet — has no
  // later one to be acknowledged after it: appDetectLost cannot tell it is
  // lost, and the timeout comes three RTTs after it was sent on a new
  // connection. When nothing has been acknowledged for 2·srtt +
  // max_ack_delay (the peer may hold its ACK that long), a copy of the last
  // packet's data goes, as a new packet. Nothing is given up on: the
  // original stays in flight and is acknowledged if it arrives, and what
  // either copy brings counts. One probe, then none until an ACK comes;
  // outside the congestion window, as RFC 8985 allows a probe. Not when the
  // timeout would come first anyway (once rttvar has settled it is near an
  // RTT, and the probe gains nothing).
  function tlpDelay() {
    if (context.srtt === null) return null;
    return 2 * context.srtt + context.max_ack_delay;
  }

  // An ack-eliciting packet sent, or an ACK in: the probe is due a delay
  // from now, while anything is in flight.
  function tlpRearm() {
    var d = tlpDelay();
    // Not before the handshake is confirmed (RFC 9002 §6.2.1: no PTO for
    // the application space until then): a 1-RTT packet the peer cannot read
    // yet is the handshake's recovery's (hsPeerResent, hsRidersLost).
    if (d === null || context.tlp_out || context.pkt_in_flight.size === 0 || d >= retxTimeout() || !handshakeConfirmed()) { context.tlp_at = 0; return; }
    context.tlp_at = Date.now() + d;
    if (context.tlp_timer !== null) return;   // it looks at tlp_at when it fires
    context.tlp_timer = setTimeout(tlpTick, Math.ceil(d));
    if (context.tlp_timer.unref) context.tlp_timer.unref();
  }

  function tlpTick() {
    context.tlp_timer = null;
    if (!context.tlp_at || context.state !== 'connected') return;
    var now = Date.now();
    if (now < context.tlp_at) {
      context.tlp_timer = setTimeout(tlpTick, Math.ceil(context.tlp_at - now));
      if (context.tlp_timer.unref) context.tlp_timer.unref();
      return;
    }
    context.tlp_at = 0;
    if (context.tlp_out || context.pkt_in_flight.size === 0 || tlpDelay() >= retxTimeout() || !handshakeConfirmed()) return;
    tlpSend();
  }

  // The probe: a copy of what the last packet with stream data carried that
  // is still unacknowledged — or a PING when the tail carried none.
  function tlpSend() {
    var last = null;
    for (var pe of context.pn_sids) last = pe;   // insertion order: the latest last
    var frames = [], room = context.current_limit_packet_payload - 8;
    if (last) {
      var pn = last[0], sids = last[1];
      for (var i = 0; i < sids.length && room > 0; i++) {
        var sid = sids[i], st = context.send_streams[sid];
        if (!st || !st.in_flight_ranges || !(pn in st.in_flight_ranges)) continue;
        var r = st.in_flight_ranges[pn], start = sendQueueStart(st);
        for (var k = 0; k + 1 < r.length && room > 0; k += 2) {
          var from = Math.max(r[k], start), to = Math.min(r[k + 1], st.write_offset);
          var finHere = !!(st.fin_pns && st.fin_pns[pn]) && r[k + 1] >= st.total_size;
          if (to < from || (to === from && !finHere)) continue;
          var len = Math.min(to - from, Math.max(0, room - 24));
          var data = len > 0 ? sendQueueRead(st, from, len) : new Uint8Array(0);
          frames.push({ type: 'stream', id: Number(sid), offset: from, fin: finHere && from + len >= st.total_size, data: data });
          room -= len + 24;
        }
      }
    }
    if (frames.length === 0) frames.push({ type: 'ping' });
    context.tlp_out = true;
    if (DEBUG) console.log('[quic] tail loss probe: ' + (frames[0].type === 'ping' ? 'PING' : frames.length + ' stream frame(s) of pn ' + last[0]));
    sendFrames('app', frames);
  }

  function expireInFlight() {
    var now = Date.now();
    // RFC 9002 §6.2.1: PTO = srtt + max(4·rttvar, granularity) + max_ack_delay.
    //
    // The max_ack_delay term is NOT optional. The peer is allowed to sit on an
    // ACK for up to that long (quic-go uses its full 25ms), so on a stable
    // 30ms-RTT path the ACK legitimately arrives up to ~55ms after the send —
    // while srtt + 4·rttvar alone converges to ~31ms as rttvar shrinks. Every
    // packet then "expires" moments before its ACK lands: the ACK finds the PN
    // already forgotten, the delivered counter never advances, BtlBw (computed
    // from delivered) collapses, the pacer follows it down, and the data is
    // resent anyway. Measured against quic-go through the interop simulator:
    // each byte crossed the wire ~21×, goodput 54 KB/s on a 10 Mbps link.
    // With the term restored the same path runs at line rate. (ptoBase)
    //
    // Global backoff: while no ACK has arrived, widen the timeout geometrically.
    // Resets the instant an ACK updates last_ack_time. (retxTimeout)
    var timeout = retxTimeout();

    // PN of history index 0 (the array is a contiguous suffix of recent PNs).
    var pnBase = context.send_pn.app - context.sending_app_pn_history.length;

    // Packets are visited oldest first — pn_sids is in the order they were
    // sent — and the first one still within the timeout ends the walk:
    // everything after it was sent later. A pass costs the expired packets
    // and their streams, not every stream (it walked each stream's packets).
    for (var pe of context.pn_sids) {
      var pnum = pe[0];
      var idx = pnum - pnBase;
      var expired;
      if (idx < 0 || idx >= context.sending_app_pn_history.length) {
        expired = true;                        // no send-time on record → assume expired (fail-safe)
      } else {
        expired = (now - context.sending_app_pn_history[idx][0] >= timeout);
      }
      if (!expired) break;
      context.pn_sids.delete(pnum);
      expireStreamsOf(pnum, pe[1], now);
    }

    // Packets of reset streams: expired like any other — out of the packet
    // count, counted as a loss — but nothing to resend (RFC 9000 §13.3).
    for (var rpn in context.no_resend_in_flight) {
      var rnum = Number(rpn);
      var ridx = rnum - pnBase;
      var rexpired = (ridx < 0 || ridx >= context.sending_app_pn_history.length) ||
                     (now - context.sending_app_pn_history[ridx][0] >= timeout);
      if (!rexpired) continue;
      delete context.no_resend_in_flight[rpn];
      if (context.sending_app_pn_in_flight.delete(rnum)) countLostPacket(rnum);
    }

    // And every packet past the same timeout leaves the bytes in flight —
    // the walks above find packets through what they carried; this one,
    // whatever they carried. A data packet's size goes with its limbo entry,
    // delivered if its ACK comes late after all.
    for (var pke of context.pkt_in_flight) {
      if (now - pke[1].t < timeout) break;
      var pBytes = forgetPacket(pke[0]);
      if (context.expired_unacked[pke[0]]) context.expired_unacked[pke[0]].bytes = pBytes;
      if (pBytes > 0) pmtuOnLost(pke[0], pBytes);
    }

    // Bound the limbo table: entries older than ~8 timeouts (min 10s) will
    // never see their ACK — the peer retires ACK ranges long before that.
    // At most once a second: it walks the whole table, and this runs on
    // every send burst. An entry kept a second longer only means a late ACK
    // for it is still honoured.
    if (now - (context.limbo_pruned_at || 0) >= 1000) {
      context.limbo_pruned_at = now;
      var limboCutoff = now - Math.max(10000, timeout * 8);
      for (var lpn in context.expired_unacked) {
        if (context.expired_unacked[lpn].t < limboCutoff) { delete context.expired_unacked[lpn]; context.limbo_n--; }
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
  // A stream held back by the peer's stream limit: STREAMS_BLOCKED, once
  // per limit value (§4.6 SHOULD). Called whether or not anything else is
  // sendable — a held stream is exactly when nothing is. Not a reason to keep
  // the scheduler ticking: the MAX_STREAMS that releases the stream restarts
  // it (set_context), and the peer retransmits that until acknowledged.
  function maybeSendStreamsBlocked() {
    if (context.streams_blocked_bidi) {
      context.streams_blocked_bidi = false;
      if (context.streams_blocked_sent_bidi !== context.remote_max_streams_bidi) {
        context.streams_blocked_sent_bidi = context.remote_max_streams_bidi;
        queueControl('sb_bidi', { type: 'streams_blocked_bidi', limit: context.remote_max_streams_bidi });
      }
    }
    if (context.streams_blocked_uni) {
      context.streams_blocked_uni = false;
      if (context.streams_blocked_sent_uni !== context.remote_max_streams_uni) {
        context.streams_blocked_sent_uni = context.remote_max_streams_uni;
        queueControl('sb_uni', { type: 'streams_blocked_uni', limit: context.remote_max_streams_uni });
      }
    }
  }

  var FC_BLOCKED_RESEND_MS = 500;
  function maybeSendBlockedFrames() {
    var now = Date.now();
    var wasBlocked = false;
    if (context.fc_blocked_conn) {
      context.fc_blocked_conn = false;
      wasBlocked = true;
      if (now - context.last_data_blocked_sent >= FC_BLOCKED_RESEND_MS) {
        context.last_data_blocked_sent = now;
        queueControl('db', { type: 'data_blocked', limit: context.remote_max_data });
      }
    }
    for (var sid of context.fc_blocked_sids) {
      var st = context.send_streams[sid];
      context.fc_blocked_sids.delete(sid);
      if (!st || !st.fc_blocked) continue;
      st.fc_blocked = false;
      wasBlocked = true;
      if (now - (context.last_stream_blocked_sent[sid] || 0) >= FC_BLOCKED_RESEND_MS) {
        context.last_stream_blocked_sent[sid] = now;
        queueControl('sdb:' + sid, { type: 'stream_data_blocked', id: Number(sid), limit: st.remote_max_stream_data });
      }
    }
    return wasBlocked;
  }


  function plan_quic_burst() {
    context.send_scheduled = false;   // this pass takes what writes left waiting
    if (!zeroRttSending()) {
      if (!context.app_write) return;
      if (context.state !== 'connected') return;
    }
    // Held for the anti-amplification budget: new packets would queue behind
    // it. releaseAmpQueue calls back here once the queue has drained.
    if (ampBlocked()) return;

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

    // Prune the send history (older than 2 seconds) — in one splice, not a
    // shift() per entry; it is in send order, so the walk stops at the first
    // entry still young enough.
    var hist = context.sending_app_pn_history;
    var twoSecAgo = now - 2000;
    var drop = 0;
    while (drop < hist.length && hist[drop][0] < twoSecAgo) drop++;
    if (drop > 0) hist.splice(0, drop);

    // Effective limits. For rate: min(current_, max_). For in-flight: clamp
    // current_ to [min_, max_] — the min_ floor is the min-cwnd that keeps the
    // connection alive (a cap below one packet would otherwise round to 0 and
    // deadlock); max_ is the absolute ceiling and wins any min_>max_ misconfig.
    var effBytesPerSec   = Math.min(context.current_limit_bytes_per_sec,     context.max_limit_bytes_per_sec);
    var effPacketsPerSec = Math.min(context.current_limit_packets_per_sec,   context.max_limit_packets_per_sec);
    // Packets in flight: only the hard ceiling. The congestion window is in
    // bytes (RFC 9002 §7) — the byte cap below is what the CC sets. The
    // packet-count window it used to be paired with is derived as bytes ÷ a
    // full packet, so every small packet — an ACK-only one, the H3 SETTINGS,
    // QPACK stream types, HANDSHAKE_DONE, a session ticket — took a full
    // packet's slot: the first response flight stopped at 10 packets with
    // 8.3 of its 12 KB window unused, and a page that fits the initial window
    // took a second round trip.
    var effPktsInFlight  = context.max_limit_packets_in_flight;
    var effBytesInFlight = Math.min(context.max_limit_bytes_in_flight,   Math.max(context.min_limit_bytes_in_flight,   context.current_limit_bytes_in_flight));

    // The rate — in bytes and in packets per second — is the pacer's below,
    // and only the pacer's. A second limit stood beside it: what had left in
    // the last second, against the rate. The two agree while the rate climbs;
    // when it falls at once — Startup's 2.89× to Drain's 1/2.89× — the second
    // still held the second of Startup's sending against the new rate: ~1 MB
    // sent, 0.8 MB/s allowed, and nothing at all left for the 0.7-0.8 s it
    // took that second to roll past, the losses of Startup's last round
    // unrepaired meanwhile (measured: a 4 MB download at 2.9 s instead of
    // 2.1, one connection in two). A token bucket follows the rate it has.

    // In-flight limits (packets)
    var inflightCount = context.sending_app_pn_in_flight.size;
    var inflightRoom = effPktsInFlight - inflightCount;
    if (inflightRoom < 0) inflightRoom = 0;

    // In-flight limits (bytes). The application bytes currently in flight,
    // turned into a packet count of the remaining byte budget. Divide by the
    // packet payload (not the 35-byte min used for the rate limit): this is a
    // HARD ceiling, so we under-estimate how many packets fit and never
    // overshoot the cap.
    var bytesInFlightRoom = effBytesInFlight - context.app_bytes_in_flight;
    if (bytesInFlightRoom < 0) bytesInFlightRoom = 0;
    var inflightBytesPackets = Math.floor(bytesInFlightRoom / context.current_limit_packet_payload);

    // Calculate burst size
    var burstCount = Math.min(
      context.max_packets_per_burst,
      inflightRoom,
      inflightBytesPackets                           // bytes-in-flight cap
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
    //
    // Two buckets, one per limit of the rate: bytes (current_limit_bytes_per_sec)
    // and packets (current_limit_packets_per_sec — what bounds many small
    // packets, each an encryption and a system call, where bytes alone would
    // let them through). Same accrual, same 5 ms cap; a packet takes from both.
    var PACE_BURST_MS = 5;
    var rateBps = effBytesPerSec;
    var ratePps = effPacketsPerSec;
    var nowR = Date.now();
    var elapsedS = (nowR - context.pacing_last_refill) / 1000;
    context.pacing_last_refill = nowR;
    context.pacing_tokens += elapsedS * rateBps;
    var tokenCap = Math.max(2 * context.current_limit_packet_payload, rateBps * (PACE_BURST_MS / 1000));
    if (context.pacing_tokens > tokenCap) context.pacing_tokens = tokenCap;
    context.pacing_pkt_tokens += elapsedS * ratePps;
    var pktTokenCap = Math.max(2, ratePps * (PACE_BURST_MS / 1000));
    if (context.pacing_pkt_tokens > pktTokenCap) context.pacing_pkt_tokens = pktTokenCap;
    var tokenPackets = Math.min(Math.floor(context.pacing_tokens / context.current_limit_packet_payload),
                                Math.floor(context.pacing_pkt_tokens));
    if (burstCount > tokenPackets) burstCount = tokenPackets;

    // Check if there's anything to send
    var hasData = false;
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (!hasBufferedData(st)) continue;
      if (!localStreamPermitted(sid)) continue;   // waits for MAX_STREAMS
      // Bytes still to send — or none, and the FIN still to go. (Asked
      // without building the list of what is missing: this runs for every
      // stream on every pass.)
      if (!nothingMissing(st) || (st.fin_set && !st.fin_sent)) { hasData = true; break; }
    }
    if (context.datagram_queue.length > 0) hasData = true;
    // Careful Resume: data waiting and no window left is the moment to jump
    // to the saved capacity; the pass is planned again under the new limits.
    if (hasData && inflightBytesPackets === 0 && crMaybeJump()) { scheduleSend(); return; }
    // Also check pending ACK
    // ACKs are sent by the ACK manager on their own schedule; the planner
    // only lets them ride in packets it sends anyway. (pending_ack keeps its
    // ranges after an ACK now, so it no longer says whether one is owed.)
    var hasPendingAck = false;

    // Any unacked data still in flight? Keep the scheduler alive so
    // expireInFlight can time it out and resend even when nothing is
    // immediately sendable — otherwise a lost range would stall here forever.
    var hasInFlight = context.pn_sids.size > 0;   // packets of streams on the network
    // Packets with nothing to resend (datagrams, reset streams) expire too —
    // out of the packet budget, counted as lost — and need the timer for it.
    if (!hasInFlight) for (var pnN in context.no_resend_in_flight) { hasInFlight = true; break; }
    // And a packet with neither (a PING, control frames alone): the sweep in
    // expireInFlight forgets it once past the timeout, if it was lost — but
    // only on a pass, and with nothing else in flight none came: its bytes
    // stayed counted in flight until the next send, whenever that was.
    if (!hasInFlight && context.pkt_in_flight.size > 0) hasInFlight = true;

    // App-limited: nothing left to send and window to spare. This round's
    // delivery rate will reflect what was offered, not what the path can do.
    if (!hasData && appBytesInFlight() < context.current_limit_bytes_in_flight) {
      context.bbr_round_app_limited = true;
    }

    maybeSendStreamsBlocked();
    // Control frames waiting (window updates, MAX_STREAMS, HANDSHAKE_DONE, a
    // BLOCKED signal…) are something to send as much as stream data is: they
    // leave in the packets of this pass (execute_quic_burst takes them first),
    // in a packet of their own when there is no data — paced and within the
    // congestion window like any ack-eliciting packet (RFC 9002 §7). Not
    // data for the app-limited mark above: offering a window update is not
    // offering the path anything to measure.
    // Only from the end of the turn on (control_due): before it, a packet
    // with data may yet take them — the client's request, written as soon as
    // its handshake is (and this pass, run at secureConnect, came first).
    if (!hasQueuedControl()) context.control_due = false;
    var wantSend = hasData || context.control_due;
    // A path MTU probe due is a reason of its own: a client that only
    // downloads has no data of its own, and nothing in flight once its
    // request is acknowledged — its search waited for an incidental pass.
    if (!wantSend && !hasPendingAck && !hasInFlight && !pmtuWantsProbe()) return;

    // Paced out: have data + cwnd room, but not enough tokens yet for a packet.
    var pacedOut = wantSend && burstCount === 0 && tokenPackets < 1 &&
                   context.sending_app_pn_in_flight.size < effPktsInFlight;

    // A path MTU probe due takes a packet of the burst (DPLPMTUD) — sent
    // after the burst's data, below.
    var probeSize = burstCount > 0 ? pmtuProbeSize(burstCount) : 0;
    if (probeSize) {
      burstCount--;
      context.pacing_tokens -= context.current_limit_packet_payload;
      context.pacing_pkt_tokens -= 1;
    }

    // Execute burst
    var sent = 0;
    // Only with something a packet could carry: data (or a FIN, or a
    // datagram — hasData), or control frames queued. Otherwise the burst
    // built its tiers, walked every stream and sent nothing — two passes in
    // three while small requests came and went (a pass runs for every ACK
    // and every write), the ACK it would have carried being the ACK
    // manager's to send.
    if (burstCount > 0 && (wantSend || hasQueuedControl())) {
      sent = execute_quic_burst(burstCount);   // returns packets ACTUALLY sent
      // Charge tokens for what went out — not for the burstCount ceiling.
      // Charging the ceiling overbilled short bursts (e.g. a 2-packet stream
      // tail billed as 64) and starved the pacer for a full tick afterwards.
      if (sent > 0) {
        context.pacing_tokens -= sent * context.current_limit_packet_payload;
        context.pacing_pkt_tokens -= sent;
      }
    }
    if (probeSize) pmtuSendProbe(probeSize);

    crCheckUnvalidated();

    // FC-blocked signaling — consume flags set inside the burst just executed.
    var fcBlocked = maybeSendBlockedFrames();

    // Schedule next burst if needed
    if (wantSend && (sent || pacedOut)) {
      // Wait roughly until one more packet's worth of tokens has accrued.
      // (both buckets: the slower of the two refills is the one waited for).
      var delayMs = Math.max(rateBps > 0 ? context.current_limit_packet_payload * 1000 / rateBps : 1,
                             ratePps > 0 ? 1000 / ratePps : 1);
      if (delayMs < 1) delayMs = 1;       // setTimeout floor
      if (delayMs > 100) delayMs = 100;   // don't stall on a pathologically low rate
      context.burst_timer = setTimeout(function () {
        context.burst_timer = null;
        plan_quic_burst();
      }, delayMs);
      if (context.burst_timer.unref) context.burst_timer.unref();
    } else if (burstCount === 0 && wantSend) {
      // Blocked by the congestion window (not pacing) — wait for ACKs.
      var waitMs = 10;
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

    // ── Who fills the room left in a packet ────────────────────────────
    //
    // The streams with something to send, in tiers (buildTiers): a packet
    // takes from the first tier with data, and only if that runs dry does the
    // next tier fill the rest of the same packet. Within a tier, the turns go
    // round as they always have — each takes what it has, up to the room
    // left, and the loop goes round again while anything was added (progress)
    // — but the round starts after whoever opened the previous packet
    // (rr_cursor). It started at the lowest stream number every packet, so
    // one stream with plenty to send filled every packet and the others
    // waited for it to finish: three 6 MB downloads ran one after another.
    //
    // The tiers, from setStreamPriority (RFC 9218's urgency and incremental,
    // WebTransport's sendGroup and sendOrder, via the layers above):
    //   urgency, most urgent first (-1: HTTP/3's own control streams);
    //   within one: the non-incremental streams one at a time, by stream
    //   number — each its own tier — then the incremental ones, sharing turns;
    //   a group (setStreamPriority's `group`, any object) takes ONE turn in
    //   its round, and passes it among its members: the highest `order` with
    //   something to send first, equal orders taking turns. A stream with no
    //   priority set shares turns at urgency 3 — as every stream did before.
    // Datagrams sent with a priority (sendDatagram's prio) take part as a
    // member of their group, or as an incremental member at their urgency.
    function rankOf(group) {
      var r = context.group_rank.get(group);
      if (r === undefined) { r = 4e15 + (context.group_rank_next++); context.group_rank.set(group, r); }
      return r;
    }
    function datagramGroup(u) {
      return context.dg_groups[u + 1] || (context.dg_groups[u + 1] = {});
    }

    // The streams with every byte sent and the FIN still to go, as this burst
    // began — the only ones step (3) below looks at, for each packet; it
    // walked every stream. A stream that still has bytes to send takes its
    // FIN with the last of them (memberTurn); one whose last gap is repaired
    // in this burst after its FIN was lost sends it in the next.
    var finCandidates = [];
    function buildTiers() {
      var buckets = new Map();   // urgency → { seq: [sid], slots: [], groups: Map }
      function bucket(u) {
        var b = buckets.get(u);
        if (!b) { b = { seq: [], slots: [], groups: new Map() }; buckets.set(u, b); }
        return b;
      }
      function joinGroup(b, group, order, member) {
        var g = b.groups.get(group);
        if (!g) { g = { rank: rankOf(group), key: group, levels: new Map() }; b.groups.set(group, g); b.slots.push(g); }
        var lv = g.levels.get(order);
        if (!lv) { lv = []; g.levels.set(order, lv); }
        lv.push(member);
      }
      finCandidates = [];
      for (var sid in context.send_streams) {
        var st = context.send_streams[sid];
        if (!hasBufferedData(st)) continue;
        if (!localStreamPermitted(sid)) continue;   // waits for MAX_STREAMS
        if (nothingMissing(st)) {
          if (st.fin_set && !st.fin_sent) finCandidates.push(sid);
          continue;
        }
        var id = Number(sid), pr = context.stream_priority[sid];
        var b = bucket(pr && pr.urgency != null ? pr.urgency : 3);
        if (pr && pr.group) joinGroup(b, pr.group, pr.order || 0, id);
        else if (pr && pr.incremental === false) b.seq.push(id);
        else b.slots.push({ rank: id, key: id, levels: null });
      }
      // Datagrams with a priority: one member per (group, order) — in their
      // group, or, without one, in a group of their urgency's own.
      var seenDg = new Set();
      for (var q = 0; q < context.datagram_queue.length; q++) {
        var dp = context.datagram_queue[q].prio;
        if (!dp) continue;
        var du = dp.urgency != null ? dp.urgency : 3, bk = bucket(du);
        var gkey = dp.group || datagramGroup(du), dord = dp.order || 0;
        var tag = rankOf(gkey) + ':' + dord;
        if (seenDg.has(tag)) continue;
        seenDg.add(tag);
        joinGroup(bk, gkey, dord, { dg: dp.group || null, urgency: du, order: dord });
      }

      var tiers = [], urgencies = Array.from(buckets.keys()).sort(function (a, b) { return a - b; });
      for (var ui = 0; ui < urgencies.length; ui++) {
        var bu = buckets.get(urgencies[ui]);
        bu.seq.sort(function (a, b) { return a - b; });
        for (var si = 0; si < bu.seq.length; si++) tiers.push({ key: null, slots: [{ rank: bu.seq[si], key: bu.seq[si], levels: null }] });
        if (bu.slots.length) {
          bu.slots.sort(function (a, b) { return a.rank - b.rank; });
          for (var gi = 0; gi < bu.slots.length; gi++) {
            var sl = bu.slots[gi];
            if (sl.levels) {   // a group: its levels, highest order first
              var orders = Array.from(sl.levels.keys()).sort(function (a, b) { return b - a; });
              sl.levels = orders.map(function (o) { return sl.levels.get(o).sort(memberRank); });
            }
          }
          tiers.push({ key: 'u' + urgencies[ui], slots: bu.slots });
        }
      }
      return tiers;
    }
    function memberRank(a, b) { return (typeof a === 'number' ? a : -1) - (typeof b === 'number' ? b : -1); }

    // Where a round starts: just after the one that opened the previous packet.
    function startAfter(list, last, rankFn) {
      if (list.length < 2) return 0;
      if (last === undefined) return 0;
      for (var i = 0; i < list.length; i++) if (rankFn(list[i]) > last) return i;
      return 0;
    }
    function slotRank(sl) { return sl.rank; }
    function memRank(m) { return typeof m === 'number' ? m : -1; }

    // One turn of a member: a stream's chunks, or its group's datagrams.
    // The tiers are built once per burst — nothing is written or acknowledged
    // while it runs — and a stream with nothing more it may send now (all
    // sent, or held by flow control) sits out the rest of it (spent).
    var spent = new Set();
    function memberTurn(m, budget) {
      if (typeof m !== 'number') {
        var dgs = takePrioritizedDatagrams(m, budget + OVERHEAD);
        if (!dgs.length) return null;
        var bytes = 0;
        for (var d = 0; d < dgs.length; d++) bytes += dgs[d].data.byteLength + DATAGRAM_FRAME_OVERHEAD;
        return { frames: dgs, bytes: bytes };
      }
      if (spent.has(m)) return null;
      var st = context.send_streams[m];
      if (!st || !hasBufferedData(st)) { spent.add(m); return null; }
      var chunks = get_stream_chunks(m, budget);
      if (!chunks || chunks.length === 0) { spent.add(m); return null; }
      var out = [], n = 0;
      for (var c = 0; c < chunks.length; c++) {
        var ch = chunks[c];
        var fin = (st.fin_set && ch.offset + ch.data.byteLength >= st.total_size);
        if (fin) st.fin_sent = true;   // no FIN-only frame needed besides
        out.push({ type: 'stream', id: m, offset: ch.offset, fin: fin, data: ch.data });
        n += ch.data.byteLength + OVERHEAD;
      }
      return { frames: out, bytes: n };
    }

    // One turn of a slot: a stream's, or a group's — passed to its highest
    // order with something to send, round among equals.
    function slotTurn(sl, budget) {
      if (!sl.levels) return memberTurn(sl.key, budget);
      for (var l = 0; l < sl.levels.length; l++) {
        var lv = sl.levels[l];
        var start = startAfter(lv, context.group_cursor.get(sl.key), memRank);
        for (var k = 0; k < lv.length; k++) {
          var m = lv[(start + k) % lv.length];
          var got = memberTurn(m, budget);
          if (got) { context.group_cursor.set(sl.key, memRank(m)); return got; }
        }
      }
      return null;
    }

    // A packet that did not leave (sendFrames returned false): its bytes were
    // marked sent when get_stream_chunks yielded them, and no packet number
    // holds them, so no expiry would ever bring them back — they go back to
    // missing here, and its FIN to unsent. Exact: they were missing when
    // yielded, so none of them is acknowledged or in flight elsewhere.
    function unsend(frames) {
      for (var u = 0; u < frames.length; u++) {
        var f = frames[u];
        if (f.type !== 'stream') continue;
        var stU = context.send_streams[f.id];
        if (!stU) continue;
        if (f.data.byteLength > 0) flat_ranges.add(stU.missing_ranges, [f.offset, f.offset + f.data.byteLength]);
        if (f.fin) stU.fin_sent = false;
      }
    }

    var tiers = buildTiers();

    for (var p = 0; p < packetCount; p++) {
      var frames = [];
      var used = 0;

      // (1) An ACK that is owed rides in the first packet, budgeted here
      // because the stream data below fills the packet to the brim. Only with
      // data: an ACK-only packet is the ACK manager's to decide (see below).
      if (p === 0 && ackOwed('app')) {
        var ackFrame = buildAckFrame('app');
        if (ackFrame) {
          var ackSize = quic_frames_size([ackFrame]);
          if (ackSize <= MAX_PAYLOAD) {
            frames.push(ackFrame);
            used += ackSize;
          }
        }
      }

      // (1a) Control frames waiting in the queue (window updates, MAX_STREAMS,
      // HANDSHAKE_DONE, new connection IDs...), ahead of the data that fills
      // the rest: small, and the peer may be waiting on them.
      if (hasQueuedControl()) {
        var ctl = takeControlFrames(MAX_PAYLOAD - used);
        if (ctl.length) {
          for (var ci = 0; ci < ctl.length; ci++) frames.push(ctl[ci]);
          used += quic_frames_size(ctl);
        }
      }

      // (1b) Datagrams, ahead of stream data: late, one is worth nothing
      // (see sendDatagram). Length-prefixed, so stream frames can follow.
      if (context.datagram_queue.length > 0) {
        var dgs = takeDatagrams(MAX_PAYLOAD - used);
        for (var di = 0; di < dgs.length; di++) {
          frames.push(dgs[di]);
          used += dgs[di].data.byteLength + DATAGRAM_FRAME_OVERHEAD;
        }
      }

      // (2) The room left: tier by tier (see buildTiers), the turns going
      // round within each, from just after whoever opened the last packet.
      for (var ti = 0; ti < tiers.length && used < MAX_PAYLOAD; ti++) {
        var slots = tiers[ti].slots;
        var first = tiers[ti].key === null ? 0 : startAfter(slots, context.rr_cursor.get(tiers[ti].key), slotRank);
        var opened = false;
        var progress = true;
        while (used < MAX_PAYLOAD && progress) {
          progress = false;
          for (var k = 0; k < slots.length; k++) {
            if (used >= MAX_PAYLOAD) break;
            var budget = Math.max(0, MAX_PAYLOAD - used - OVERHEAD);
            if (budget <= 0) break;
            var sl = slots[(first + k) % slots.length];
            var got = slotTurn(sl, budget);
            if (!got) continue;
            for (var f = 0; f < got.frames.length; f++) frames.push(got.frames[f]);
            used += got.bytes;
            progress = true;
            if (!opened && tiers[ti].key !== null) { context.rr_cursor.set(tiers[ti].key, sl.rank); opened = true; }
          }
        }
      }

      // (3) FIN-only frames: if all data sent/in-flight but FIN not yet sent
      for (var fci = 0; fci < finCandidates.length; fci++) {
        var sid = finCandidates[fci];
        var st = context.send_streams[sid];
        if (!st || !st.fin_set || st.fin_sent) continue;
        // Every byte acknowledged or in flight?
        if (nothingMissing(st)) {
          if (DEBUG) console.log('[quic] → sending FIN-only for stream ' + sid);
          // All data sent — send FIN-only STREAM frame
          frames.push({ type: 'stream', id: Number(sid), offset: st.total_size, fin: true, data: new Uint8Array(0) });
          st.fin_sent = true;
        }
      }

      // Send the packet if it carries something besides an ACK. An ACK alone
      // is not ours to send: the ACK manager decides when one goes out.
      if (frames.length > 0 && !(frames.length === 1 && frames[0].type === 'ack')) {
        if (!sendFrames('app', frames)) { unsend(frames); break; }   // nor will the next
        sentCount++;
      } else {
        break; // nothing to fill further packets
      }
    }

    return sentCount;
  }


  /**
   * get_stream_chunks — find what bytes are missing (neither acked nor in
   * flight: missing_ranges) and extract up to maxBytes from the send queue.
   * What it yields leaves missing_ranges at once, so a second call
   * for the same packet or burst does not yield it again; a packet that then
   * fails to leave hands it back (execute_quic_burst's unsend).
   *
   * Strategy: first forward from send_offset (new data),
   *           then fill gaps before send_offset (retransmit).
   * Bytes come from the send queue; what has been acknowledged from offset 0
   * is released there by the ACK path (sendQueueRelease).
   */
  function get_stream_chunks(streamId, maxBytes) {
    var stream = context.send_streams[streamId];
    if (!stream || stream.queue_bytes === 0) return [];
    if (!localStreamPermitted(streamId)) return [];

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

    var qLo = sendQueueStart(stream), qHi = stream.write_offset;   // the bytes still held

    // A copy to walk: what is yielded below leaves missing_ranges as it goes.
    if (stream.missing_ranges.length === 0) return [];
    var missing = stream.missing_ranges.slice();

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

      // Clamp to the bytes still held
      if (from < qLo || from >= qHi) continue;
      if (from + len > qHi) len = qHi - from;
      if (len <= 0) continue;

      // FC clamp 1: never extend past the peer's per-stream offset cap.
      if (from + len > streamLimit) {
        stream.fc_blocked = true;   // the cap bound — signal STREAM_DATA_BLOCKED
        context.fc_blocked_sids.add(streamId);
        if (from >= streamLimit) continue;
        len = streamLimit - from;
      }

      // FC clamp 2: charge the connection budget for NEW bytes only (the part
      // of this chunk above the stream's high-water mark).
      var newStart = Math.max(from, stream.max_sent_offset);
      var newBytes = Math.max(0, (from + len) - newStart);
      if (newBytes > connRemaining) {
        context.fc_blocked_conn = true;  // the budget bound — signal DATA_BLOCKED
        len -= (newBytes - connRemaining);
        newBytes = connRemaining;
      }
      if (len <= 0) continue;

      chunks.push({ offset: from, data: sendQueueRead(stream, from, len) });
      flat_ranges.remove(stream.missing_ranges, [from, from + len]);
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

    // Phase 2: fill gaps before send_offset (retransmit lost data), with
    // what Phase 1 just yielded no longer among them.
    if (chunks.length > 0) missing = stream.missing_ranges.slice();
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

        if (mFrom < qLo || mFrom >= qHi) continue;
        if (mFrom + len > qHi) len = qHi - mFrom;
        if (len <= 0) continue;

        // FC fail-safe: retransmits sit below the high-water mark, which was
        // itself capped when first sent, and limits are monotonic — so these
        // clamps should never bind here. Applied anyway so the invariant
        // "nothing ever leaves above streamLimit / beyond the conn budget"
        // holds unconditionally, whatever the scheduler does around us.
        if (mFrom >= streamLimit) continue;
        if (mFrom + len > streamLimit) len = streamLimit - mFrom;
        var newStart2 = Math.max(mFrom, stream.max_sent_offset);
        var newBytes2 = Math.max(0, (mFrom + len) - newStart2);
        if (newBytes2 > connRemaining) {
          len -= (newBytes2 - connRemaining);
          newBytes2 = connRemaining;
        }
        if (len <= 0) continue;

        chunks.push({ offset: mFrom, data: sendQueueRead(stream, mFrom, len) });
        flat_ranges.remove(stream.missing_ranges, [mFrom, mFrom + len]);
        used += len;

        if (newBytes2 > 0) {
          stream.max_sent_offset = mFrom + len;
          context.max_data_sent += newBytes2;
          connRemaining -= newBytes2;
        }
      }
    }

    checkSentWait(stream, false);   // max_sent_offset may have advanced
    // RESET_STREAM_AT: its reliable part now sent whole — the frame may go.
    if (stream.reset_at && stream.reset_at.finalSize === null && stream.max_sent_offset >= stream.reset_at.reliable) resetAtProgress(streamId, stream);
    return chunks;
  }


  // ============================================================
  //  Close
  // ============================================================

  // RFC 9000 §10.2.3: the frame goes "in a packet with the highest level of
  // packet protection" the peer can read. After the handshake is confirmed
  // that is 1-RTT alone. Before, the peer may not have the 1-RTT (or even
  // the Handshake) keys yet, and a close sent only there was lost on it — a
  // handshake that failed on our side (a TLS alert, the handshake timeout)
  // left the peer retransmitting into silence. So it goes in every space we
  // still have keys for, lowest first.
  //
  // In Initial and Handshake packets an application close (0x1d) "MUST" be
  // replaced by a transport one with APPLICATION_ERROR (0x0c) and no reason:
  // those packets are not yet authenticated to the peer, and the reason is
  // the application's to reveal only to a peer it knows.
  function sendConnectionClose() {
    if (!context.close_frame) return;
    var cf = context.close_frame;
    if (!handshakeConfirmed()) {
      var early = cf.application
        ? { type: 'connection_close', application: false, error: 0x0c, frameType: 0, reason: '' }
        : cf;
      if (context.initial_write && !context.discarded.initial) sendFrames('initial', [early]);
      if (context.handshake_write && !context.discarded.handshake) sendFrames('handshake', [early]);
    }
    if (context.app_write) sendFrames('app', [cf]);
    context.last_close_echo = Date.now();
  }

  // RFC 9001 §4.1.2: a server's handshake is confirmed when it completes; a
  // client's when HANDSHAKE_DONE (or an ACK of a 1-RTT packet) arrives —
  // which is when it discards its Handshake keys.
  function handshakeConfirmed() {
    return context.isServer ? context.peer_finished : context.discarded.handshake;
  }

  /**
   * Close the connection.
   *
   * `application` selects which CONNECTION_CLOSE frame is sent:
   *   false (default) — 0x1c, the TRANSPORT error space (RFC 9000 §20.1)
   *   true            — 0x1d, the APPLICATION error space (RFC 9000 §20.2)
   *
   * The distinction is not cosmetic: the two spaces are disjoint registries.
   * HTTP/3 and QPACK error codes (RFC 9114 §8.1, RFC 9204 §6 — H3_FRAME_ERROR
   * 0x0106, QPACK_DECOMPRESSION_FAILED 0x0200, ...) live in the application
   * space, and RFC 9114 §8.1 requires them to be sent in a 0x1d frame. Sending
   * one in a 0x1c frame tells the peer something entirely different: 0x0106 is
   * not a defined transport code, and 0x0200 lands nowhere at all. The peer
   * logs a transport violation it did not commit and has no way to learn what
   * actually went wrong.
   *
   * The transport builder has always handled both (transport.js picks 0x1c/0x1d
   * off `frame.application`); only this entry point was hardcoded.
   */
  function close(errorCode, reason, application) {
    if (context.state === 'closed' || context.state === 'draining' || context.state === 'closing') return;
    if (context.handshake_timer) { clearTimeout(context.handshake_timer); context.handshake_timer = null; }
    stopCryptoRetx();
    if (context.send_scheduled) plan_quic_burst();   // what was written before close() goes first
    context.close_frame = {
      type: 'connection_close', application: !!application,
      error: errorCode || 0, frameType: 0, reason: reason || ''
    };
    if (serverStats) serverStats.code(serverStats.closes[application ? 'h3' : 'quic'].sent, errorCode || 0);
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

    // DCID and SCID, 8 bytes each, from the system's secure random source.
    // §7.2: the first DCID "MUST" be "an unpredictable value" — it keys the
    // Initial packets, and Math.random() is predictable from its own output.
    // Our own ID is what the server addresses us by; a guessable one makes
    // our packets easier to find and forge.
    var dcid = new Uint8Array(randomBytes(8));
    var scid = new Uint8Array(randomBytes(8));

    context.original_dcid = dcid;
    context.initial_key_cid = dcid;
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

  // A server connection exists because a packet came; its handshake is on
  // the clock from now (see startHandshakeTimer).
  if (context.isServer) startHandshakeTimer();

  var api = {
    context: context,
    /** Whether the peer has begun a handshake: an Initial CRYPTO frame came. */
    get handshakeStarted() { return !!context.crypto_seen_initial; },
    /** Forget the connection without a word — for one that never began. */
    discard: function () { if (context.state !== 'closed') set_context({ state: 'closed' }); },
    on: function (name, fn) { ev.on(name, fn); },
    off: function (name, fn) { ev.off(name, fn); },
    feedDatagram: feedDatagram,
    feedPackets: feedPackets,
    sendStream: sendStream,
    nextLocalStreamId: nextLocalStreamId,
    // A stream's priority (see execute_quic_burst's tiers): { urgency (-1..7,
    // most urgent first; default 3), incremental (false: whole, one at a
    // time; default true), group (any object: its streams share one turn),
    // order (within the group, higher first) }. Merged into what is set.
    //
    // Two sources: the local application's decision, and the peer's signal
    // (fromPeer — RFC 9218's header and PRIORITY_UPDATE, read by the layer
    // above); see mergePriority. Returns false for a stream with no sending
    // part to come — an entry made for one would never be dropped (they go
    // when the stream retires).
    setStreamPriority: function (streamId, p, fromPeer) {
      var sid = Number(streamId);
      if (!sendSideAhead(sid)) return false;
      mergePriority(context.stream_priority[sid] || (context.stream_priority[sid] = {}), p, fromPeer);
      scheduleSend();
      return true;
    },
    // What is set for a stream: { urgency, incremental, group, order } as
    // set (fields not set are absent), or null.
    getStreamPriority: function (streamId) {
      var cur = context.stream_priority[Number(streamId)];
      if (!cur) return null;
      var out = {};
      if (cur.urgency != null) out.urgency = cur.urgency;
      if (cur.incremental != null) out.incremental = cur.incremental;
      if ('group' in cur) out.group = cur.group;
      if (cur.order != null) out.order = cur.order;
      return out;
    },
    // How long a datagram may wait for room before it is dropped, in ms;
    // null or Infinity: no limit (the byte bound still applies).
    // Whether a stream of our own could be opened now, within the peer's
    // MAX_STREAMS (one opened past it waits for more credit).
    // Whether the receiving part of a stream is open: opened (by the peer,
    // or implicitly by a higher-numbered one, RFC 9000 §3.2) and neither
    // finished nor reset.
    isReceiving: function (streamId) { return context.recv_open.has(Number(streamId)); },
    canOpenStream: function (bidi) {
      var sid = nextLocalStreamId(!!bidi);
      return Math.floor(sid / 4) < (bidi ? context.remote_max_streams_bidi : context.remote_max_streams_uni);
    },
    setDatagramMaxAge: function (ms) { datagramMaxAge = (ms == null || !(ms >= 0)) ? Infinity : ms; },
    whenStreamSent: whenStreamSent,
    whenStreamCommitted: whenStreamCommitted,
    whenStreamPermitted: whenStreamPermitted,
    getStats: getStats,
    countInternalError: countInternalError,
    // 0-RTT: null (none), 'offered' (a client's, undecided), 'accepted',
    // 'rejected'; and whether a stream's data came in 0-RTT (server).
    get earlyDataStatus() { return context.early_status; },
    // The peer takes RESET_STREAM_AT (resetStream's reliableSize).
    get resetStreamAtSupported() { return context.peer_reset_stream_at === true; },
    isEarlyStream: function (sid) { return context.early_streams.has(Number(sid)); },
    // The application protocol's settings, kept with the session (client):
    // set — the peer's, as they arrive — for the tickets saved after; read —
    // what the session this 0-RTT uses was saved with (null: none).
    rememberApplicationSettings: function (v) { if (!context.isServer && tls && tls.setRememberedApp) tls.setRememberedApp(v); },
    get rememberedApplicationSettings() { return context.early_status ? context.early_app_remembered : null; },
    whenConfirmed: whenConfirmed,
    setOptions: setOptions,
    getOptions: getOptions,
    whenAllSent: whenAllSent,
    sendDatagram: sendDatagram,
    resetStream: resetStream,
    stopSending: stopSending,
    // Receive credit returned as the application reads (see creditStream).
    setCreditPolicy: function (fn) { creditPolicy = typeof fn === 'function' ? fn : null; },
    creditStream: creditStream,
    releaseStreamCredit: releaseStreamCredit,
    maxDatagramSize: maxDatagramSize,
    close: close,
    connect: connect,
    set_context: set_context,

    /**
     * TLS fingerprints of this connection's handshake — getJA4, getJA5,
     * getJA4S, as a TLSSocket has them — { hash, raw }, or null.
     *
     * Over TCP these live on the TLSSocket; over QUIC there is no socket to
     * hang them on, because the TLS handshake happens inside the connection
     * itself. The values are computed either way — only the way out was
     * missing. The bridge tags them with the QUIC transport, so the same
     * client produces a different (and correct) fingerprint here than it would
     * over TCP.
     */
    getJA4: function (opts) { return (tls && tls.getJA4) ? tls.getJA4(opts) : null; },
    /** The peer's certificate chain, leaf first, as DER — or null. */
    getPeerCertificateChain: function () { return (tls && tls.getPeerCertificateChain) ? tls.getPeerCertificateChain() : null; },
    // TLS keying material (RFC 8446 §7.5), as node:tls's: WebTransport's
    // exportKeyingMaterial builds on it. null before the handshake has it.
    exportKeyingMaterial: function (length, label, context) { return (tls && tls.exportKeyingMaterial) ? tls.exportKeyingMaterial(length, label, context) : null; },
    // How many new bytes stream `streamId` could send now under flow control
    // (RFC 9000 §4.1): its own window, and the connection's less what every
    // stream has written and not yet sent. WebTransport's atomicWrite asks.
    streamSendWindow: streamSendWindow,
    // The client's certificate, node:tls-shaped, and whether it was verified
    // (requestCert): what req.socket answers over HTTP/3.
    getPeerCertificate: function () { return (tls && tls.getPeerCertificate) ? tls.getPeerCertificate() : {}; },
    isAuthorized: function () { return !!(tls && tls.isAuthorized && tls.isAuthorized()); },
    authorizationError: function () { return (tls && tls.authorizationError) ? tls.authorizationError() : null; },
    getJA5: function (opts) { return (tls && tls.getJA5) ? tls.getJA5(opts) : null; },
    getJA4S: function (opts) { return (tls && tls.getJA4S) ? tls.getJA4S(opts) : null; },
    getNegotiationResult: function () { return (tls && tls.getNegotiationResult) ? tls.getNegotiationResult() : null; },

    /** The certificate this connection presents, TLSSocket.getCertificate()'s
     *  shape; {} when none. */
    getCertificate: function () { return (tls && tls.getCertificate) ? tls.getCertificate() : {}; },

    /** The SNI the client sent, or false — TLSSocket.servername. */
    get servername() { return (tls && tls.getServername) ? tls.getServername() : false; },

    /** Encrypted Client Hello on this connection — TLSSocket's echStatus.
     *  Server: null (not offered) | 'accepted' | 'rejected'. Client: null
     *  (none) | 'grease' | 'accepted' | 'rejected'. */
    get echStatus() { return (tls && tls.getEchStatus) ? tls.getEchStatus() : null; },

    /**
     * This connection's session ticket, as TLSSocket.getTicketInfo() gives it
     * over TCP: { data, resumed, offered }. `data` is the server's ticketData —
     * what the ticket this connection resumed with carried, or, on a full
     * handshake, what was made for the ticket issued to it (from the end of
     * the handshake on). See lemon-tls TLSSession.getTicketInfo.
     */
    getTicketInfo: function () {
      return (tls && tls.getTicketInfo) ? tls.getTicketInfo() : null;
    },

    // The rest of what a TLSSocket answers about its session, same names and
    // same values, so code written against TCP reads a QUIC connection too.
    isSessionReused: function () { return !!(tls && tls.isResumed && tls.isResumed()); },
    getProtocol: function () { return (tls && tls.getProtocol) ? tls.getProtocol() : null; },
    getCipher: function () { return (tls && tls.getCipherInfo) ? tls.getCipherInfo() : null; },

    /**
     * The negotiated ALPN protocol, or false — the same name and the same
     * values as TLSSocket.alpnProtocol over TCP, so code that routes on it
     * works on either transport.
     *
     * A server offering more than one protocol has to know which the client
     * chose before deciding what the connection is. Without this the only
     * safe assumption was the one h3_server made: every connection is HTTP/3.
     */
    /** The QUIC version packets go in: 1 (v1) or 0x6b3343cf (v2) — after
     *  compatible version negotiation, the negotiated one. */
    get version() { return context.version; },
    get alpnProtocol() { return (tls && tls.getALPN) ? (tls.getALPN() || false) : false; },

    get state() { return context.state; },

    /** Where the peer is — net.Socket's names: the address it has PROVEN
     *  it receives at. A server's follows the client when its address
     *  changes (RFC 9000 §9.3), once the new one is validated; see the
     *  'path_validated' event.
     *
     *  It followed the path the moment a packet arrived from a new address,
     *  before validation — and a packet from an address its sender does not
     *  hold can be forged by anyone on the path, rewriting the source of a
     *  genuine one: every request after it, and every rate limit and access
     *  rule keyed on the address, saw the forged one (nginx's
     *  CVE-2026-40460, the same mistake). Packets still go to the new path
     *  meanwhile, within the anti-amplification limit — that is the
     *  transport's business — but nothing above it is told of an address
     *  until it is proven. */
    get remoteAddress() { return peerPath().address; },
    get remotePort() { return peerPath().port; }
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

export { QUICConnection, initialCongestionWindow, startupCapOption, checkConnectionOptions, connectionOptionDefaults, CONNECTION_OPTIONS };
// Careful Resume's saved state, for its unit test.
export { endpointTag, savedState, usableState, sameRtt, carefulResumeOption, LIFETIME_S };