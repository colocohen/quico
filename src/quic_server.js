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

import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { DEBUG, Emitter } from './utils.js';
import {
  parse_quic_datagram,
  build_version_negotiation
} from './transport.js';
import { build_retry_packet } from './crypto.js';
import { QUICConnection, checkConnectionOptions, connectionOptionDefaults, CONNECTION_OPTIONS } from './quic_connection.js';
import { createSecureContext, defaultTransportParams } from './tls_bridge.js';
import { serverTlsOptions } from './tls_options.js';
import lemonTls from 'lemon-tls';
import { QUIC_V1, QUIC_V2, parseVersionList } from './quic_version.js';


// ============================================================
//  createQuicServer(options)
//
//  Transport-only QUIC server. Owns the UDP socket(s), demultiplexes
//  incoming datagrams to per-peer QUICConnection objects, and emits a
//  'connection' event carrying the raw QUICConnection. It knows nothing
//  about HTTP/3 — application protocols (HTTP/3, DNS-over-QUIC, ...) are
//  layered on top by listening for 'connection' and then using the
//  connection's own stream/datagram API.
//
//  This is the connection-management harness that used to live inside
//  h3_server.js. h3_server now builds on it (wrapping each connection in
//  an H3Connection); other consumers (e.g. a DoQ server) can use it
//  directly.
//
//  Events:
//    'connection' (quic, peer)  — new QUICConnection created for a peer.
//                                  peer = { address, port }, kept current
//                                  if the client's address changes (as are
//                                  quic.remoteAddress / remotePort). Handlers
//                                  attach quic.on('connect'|'stream'|
//                                  'datagram'|'close') as needed.
//    'error'      (err)         — UDP socket / send error.
//
//  Options:
//    alpn            — ALPN protocol(s) to advertise (default 'h3').
//                      DoQ servers pass 'doq'.
//    SNICallback     — TLS SNI callback returning a SecureContext.
//    key/cert/ca     — convenience: build a default SecureContext when no
//                      SNICallback is given.
//    maxConnections  — capacity cap (default 10000).
//    socket/socket6  — externally-owned, already-bound UDP sockets
//                      (shared-port mode, RFC 9443). When provided, the
//                      caller feeds datagrams via handlePacket(msg, rinfo).
// ============================================================

function createQuicServer(options) {
  options = options || {};
  // The transport parameters every connection sends, where the application
  // set them (tls_bridge) — checked once, now, rather than per connection.
  var transportParams = options.transportParams || null;
  defaultTransportParams(transportParams);
  // What each new connection is made with (quic_connection's
  // CONNECTION_OPTIONS: initialCongestionWindow, carefulResume, startupCap,
  // pmtuDiscovery, maxUdpPayloadSize, initialRtt, reorderWindow) — the
  // defaults, what createServer set, and setOptions since. A connection
  // keeps what it was made with; connectionOptions and conn.setOptions
  // change one connection's.
  // 0-RTT (RFC 9001 §4.6), off unless asked for: tickets that allow it and
  // taking it, for connections made from then on. earlyDataMaxAge: how far
  // a ticket's stated age may be from what this server's clock says;
  // earlyDataReplay(id, ttl, cb): whether a ticket carries early data for the
  // first time (default: remembered in this process). See quic_connection.
  function earlyMaxAge(v) {
    if (v === undefined || v === null) return 10000;
    if (typeof v !== 'number' || !(v > 0) || v > 600000) { var e = new RangeError('earlyDataMaxAge must be between 1 and 600000 (ms), got ' + v); e.code = 'ERR_OUT_OF_RANGE'; throw e; }
    return v;
  }
  if (options.earlyData != null && typeof options.earlyData !== 'boolean') { var ee = new TypeError('earlyData must be a boolean, got ' + options.earlyData); ee.code = 'ERR_INVALID_ARG_TYPE'; throw ee; }
  if (options.earlyDataReplay != null && typeof options.earlyDataReplay !== 'function') { var er = new TypeError('earlyDataReplay must be a function (id, ttl, callback)'); er.code = 'ERR_INVALID_ARG_TYPE'; throw er; }
  var earlyData = options.earlyData === true;
  var earlyDataMaxAge = earlyMaxAge(options.earlyDataMaxAge);
  var earlyDataReplay = options.earlyDataReplay || null;

  var connDefaults = (function () {
    var given = {};
    for (var k in CONNECTION_OPTIONS) if (options[k] !== undefined && options[k] !== null) given[k] = options[k];
    return Object.assign(connectionOptionDefaults(), checkConnectionOptions(given, 'createServer'));
  })();
  // Each connection's own settings, asked once its ClientHello is in
  // (quic_connection: connectionOptions).
  if (options.connectionOptions != null && typeof options.connectionOptions !== 'function')
    throw new TypeError('connectionOptions must be a function (info, callback)');
  var connectionOptions = options.connectionOptions || null;
  // The QUIC versions accepted, in preference (quic_version.js): v1 first —
  // a client that offers v2 too (version_information) stays in v1 unless
  // the application puts v2 first; one that starts in v2 is served in it.
  var quicVersions = parseVersionList(options.quicVersions, 'quicVersions') || [QUIC_V1, QUIC_V2];

  var ev = Emitter();
  var udp4 = null;
  var udp6 = null;
  var port = null;

  // ALPN to advertise on every accepted connection. Default ['h3'].
  var alpn = options.alpn || ['h3'];

  // ── External socket mode (shared UDP port) ──
  // When socket/socket6 are provided, the UDP layer is owned externally.
  // The caller demuxes packets and feeds them via handlePacket(msg, rinfo).
  // See RFC 9443 for the shared-port multiplexing scheme.
  var externalSocket4 = options.socket  || null;
  var externalSocket6 = options.socket6 || null;

  if (externalSocket4) {
    try { externalSocket4.address(); }
    catch (e) { throw new Error('options.socket must be bound before createQuicServer()'); }
  }
  if (externalSocket6) {
    try { externalSocket6.address(); }
    catch (e) { throw new Error('options.socket6 must be bound before createQuicServer()'); }
  }

  var isExternal = !!(externalSocket4 || externalSocket6);

  // grease_quic_bit (RFC 9287): invite clients to send the fixed bit
  // unpredictable, so the bit stays free to change. On by default, but not
  // with external sockets: a port shared with other protocols (STUN, TURN,
  // DTLS — RFC 9443) tells QUIC apart by that very bit (§3.1). An external
  // socket that carries QUIC alone: greaseQuicBit: true.
  if (options.greaseQuicBit != null && typeof options.greaseQuicBit !== 'boolean') {
    throw new TypeError('greaseQuicBit must be a boolean');
  }
  var greaseQuicBit = options.greaseQuicBit != null ? options.greaseQuicBit : !isExternal;

  // Session tickets: ONE key for every connection of this server, so a
  // ticket issued on one connection opens on the next. Left to lemon-tls, each
  // connection drew its own and no client ever resumed. Random when not given:
  // tickets then last until this server restarts; pass ticketKeys (48 bytes)
  // kept across restarts to have them outlive it.
  var ticketKeys = options.ticketKeys || crypto.randomBytes(48);
  var ticketData = typeof options.ticketData === 'function' ? options.ticketData : null;
  // Encrypted Client Hello keys (lemon-tls): read per connection, so a new
  // set (setEchKeys) applies from the next one.
  var ech = options.ech || null;
  // OCSP stapling: (certificate, issuer, callback), asked per connection.
  var ocspRequest = typeof options.ocspRequest === 'function' ? options.ocspRequest : null;
  // node:tls's options — client certificates, ciphers, curves, signature
  // schemes, the ticket lifetime, the handshake timeout — read once, for QUIC
  // (TLS 1.3 only: tls_options.js).
  var tlsOptions = serverTlsOptions(options, true);
  // The server's counters (server_stats.js): createServer's; none on a
  // QUIC server made alone.
  var stats = options.stats || null;

  // Stateless reset (RFC 9000 §10.3). A client whose server has lost its
  // connection — a restart, a crash, a connection already gone — goes on
  // sending to it and hears nothing, until its idle timeout: 30 seconds of a
  // tab that looks alive and loads nothing. A Stateless Reset tells it at
  // once, and the browser opens a new connection instead.
  //
  // The token that makes a reset believable is HMAC(secret, connection ID),
  // cut to 16 bytes (§10.3.2): one secret for every connection, so a reset
  // can be made for a connection this server no longer has — which is when
  // it is needed. A random secret (the default) covers connections lost
  // while this server runs; one kept across restarts (resetTokenSecret —
  // node:quic's name for it) covers those lost in a restart as well.
  // Whoever holds it can end any connection of this server; kept like the
  // ticket keys.
  var resetTokenSecret = checkResetTokenSecret(options.resetTokenSecret) || crypto.randomBytes(32);

  function checkResetTokenSecret(secret) {
    if (secret === undefined || secret === null) return null;
    if (!(secret instanceof Uint8Array) || secret.byteLength < 16) {
      throw new TypeError('resetTokenSecret must be a Buffer or Uint8Array of at least 16 bytes');
    }
    return secret;
  }

  // Address validation with Retry (RFC 9000 §8.1.2). While it is on, a new
  // client's first Initial gets no connection — no state, no key exchange,
  // no signature — only a small Retry packet with a token. A client that is
  // really at its address comes back with it, a round trip later, and only
  // then is a connection made; one that is not (a spoofed flood) never does.
  //
  // Off unless asked for, and never switched by quico itself: whether the
  // round trip is worth paying is the application's call — always, never, or
  // when it sees load — through validateAddress (node:quic's name) and
  // setValidateAddress() while running.
  //
  // The token is the client's first DCID and the connection ID the Retry
  // gave it, with the time, sealed (AES-256-GCM) to the client's IP address
  // under a key of this server's own. It lives seconds, so a key drawn at
  // start is enough: a restart costs only the Retries in flight.
  //
  // tokenSecret (node:quic's name, at least 16 bytes) gives the key instead:
  // servers that pass the same one open each other's tokens. That is what
  // several servers sharing a port need (one per thread, SO_REUSEPORT): a
  // client back with a NEW_TOKEN from another port is hashed to another of
  // them, and without the key its token does not open — no harm, only the
  // shortcut lost. The AES key is derived from it (SHA-256), so a 16-byte
  // secret serves as well as a 32-byte one.
  var validateAddress = options.validateAddress === true;
  var tokenSecret = checkTokenSecret(options.tokenSecret) || crypto.randomBytes(32);
  var retryTokenKey = tokenKeyOf(tokenSecret);

  function checkTokenSecret(secret) {
    if (secret === undefined || secret === null) return null;
    if (!(secret instanceof Uint8Array) || secret.byteLength < 16) {
      throw new TypeError('tokenSecret must be a Buffer or Uint8Array of at least 16 bytes');
    }
    return secret;
  }
  function tokenKeyOf(secret) {
    return crypto.createHash('sha256').update('quico address-validation token key').update(secret).digest();
  }
  var RETRY_TOKEN_LIFETIME = 10000;   // ms
  // Tokens of two kinds, sealed alike (RFC 9000 §8.1.3): a Retry's, good for
  // seconds and one connection attempt; and a NEW_TOKEN's, given to a client
  // after its handshake for its next connection — from the same address, in
  // the same QUIC version — whose first flight then needs no proof of
  // address: no Retry, and no limit of three times what it sent (§8.1), so
  // a certificate chain larger than that goes out in one round trip. A day,
  // as quic-go's; a restart (a new key) only costs a client its shortcut.
  var TOKEN_RETRY = 1, TOKEN_NEW = 2;
  var NEW_TOKEN_LIFETIME = 24 * 3600 * 1000;   // ms

  // Bound to the client's IP address and the QUIC version of its Initial
  // (the AAD): the Initial that comes back with it must be in that version
  // (RFC 9369 §4.1 — a client MUST NOT switch versions there).
  function tokenAad(ip, version) {
    return Buffer.concat([Buffer.from(ip), Buffer.from([(version >>> 24) & 0xff, (version >>> 16) & 0xff, (version >>> 8) & 0xff, version & 0xff])]);
  }

  function sealRetryToken(originalDcid, sourceCid, ip, version) {
    var plain = Buffer.alloc(8 + 1 + originalDcid.length + sourceCid.length);
    plain[0] = TOKEN_RETRY;
    plain.writeUIntBE(Date.now(), 2, 6);
    plain[8] = originalDcid.length;
    Buffer.from(originalDcid).copy(plain, 9);
    Buffer.from(sourceCid).copy(plain, 9 + originalDcid.length);
    return seal(plain, ip, version);
  }

  // A NEW_TOKEN's token: the kind and the time, sealed to the address and
  // the version.
  function sealNewToken(ip, version) {
    var plain = Buffer.alloc(8);
    plain[0] = TOKEN_NEW;
    plain.writeUIntBE(Date.now(), 2, 6);
    return seal(plain, ip, version);
  }

  function seal(plain, ip, version) {
    var nonce = crypto.randomBytes(12);
    var cipher = crypto.createCipheriv('aes-256-gcm', retryTokenKey, nonce);
    cipher.setAAD(tokenAad(ip, version));
    var sealed = Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
    return new Uint8Array(sealed);
  }

  // A token this server sealed, for this address and version:
  //   { kind: 'retry', originalDcid, sourceCid } — a Retry's, for the ID the
  //     packet is addressed to, and still fresh;
  //   { kind: 'new' } — a NEW_TOKEN's, still within its lifetime.
  // null for a token that is not ours (it does not open), or an expired
  // NEW_TOKEN one — treated as no token at all (§8.1.3: the client is then
  // as one without a validated address); false for a Retry token of ours
  // that fails the rest — §8.1.2: the packet is discarded, and the client,
  // which accepts only one Retry, times out.
  function openToken(token, ip, dcid, version) {
    if (token.byteLength < 12 + 8 + 16) return null;
    var t = Buffer.from(token.buffer, token.byteOffset, token.byteLength);
    var plain;
    try {
      var decipher = crypto.createDecipheriv('aes-256-gcm', retryTokenKey, t.subarray(0, 12));
      decipher.setAAD(tokenAad(ip, version));
      decipher.setAuthTag(t.subarray(t.length - 16));
      plain = Buffer.concat([decipher.update(t.subarray(12, t.length - 16)), decipher.final()]);
    } catch (e) {
      return null;
    }
    var age = Date.now() - plain.readUIntBE(2, 6);
    if (plain[0] === TOKEN_NEW && plain.length === 8) {
      return (age >= 0 && age <= NEW_TOKEN_LIFETIME) ? { kind: 'new' } : null;
    }
    if (plain[0] !== TOKEN_RETRY) return null;
    if (age < 0 || age > RETRY_TOKEN_LIFETIME) return false;
    var odcidLen = plain[8];
    if (plain.length !== 9 + odcidLen + SERVER_CID_LEN) return false;
    var sourceCid = new Uint8Array(plain.subarray(9 + odcidLen));
    if (cidKey(sourceCid) !== cidKey(dcid)) return false;
    return { kind: 'retry', originalDcid: new Uint8Array(plain.subarray(9, 9 + odcidLen)), sourceCid: sourceCid };
  }

  // The Retry: from a connection ID the client is to use next — the one its
  // connection will have — carrying the token.
  function sendRetry(pkt, toIp, toPort) {
    var sourceCid = newLocalCid();
    var token = sealRetryToken(pkt.dcid, sourceCid, toIp, pkt.version);
    if (DEBUG) console.log('[qserver] Retry to ' + toIp + ':' + toPort);
    // In the version of the client's Initial (RFC 9369 §4.1).
    sendUdp(toIp, toPort, build_retry_packet(pkt.scid, sourceCid, token, pkt.dcid, pkt.version));
  }

  function resetToken(cid) {
    return new Uint8Array(crypto.createHmac('sha256', resetTokenSecret).update(cid).digest().subarray(0, 16));
  }

  // Build SNICallback
  var sniCallback = options.SNICallback || null;

  if (!sniCallback && options.key && options.cert) {
    var defaultCtx = createSecureContext({ key: options.key, cert: options.cert, ca: options.ca, passphrase: tlsOptions.passphrase });
    // Its chain compressed now, in the background, for the first client's
    // handshake (see tcp_listener; the cache is shared, so one server's two
    // stacks compress it once).
    if (!(tlsOptions.certificateCompression && tlsOptions.certificateCompression.length === 0))
      lemonTls.precompressCertificate(defaultCtx, tlsOptions.certificateCompression || undefined);
    sniCallback = function (servername, cb) { cb(null, defaultCtx); };
  }

  // ---- Connection tracking ----
  //
  // A connection is found by the connection ID a datagram is addressed to
  // (RFC 9000 §5.2), never by where it came from: a phone behind a NAT that
  // changes its port keeps sending to the same ID, and two clients behind one
  // address never share a connection.
  //
  // Each connection is addressed by an ID this server chose: SERVER_CID_LEN
  // random bytes. One length for all of them is what makes routing possible
  // at all — a short header carries its DCID without a length, and only by
  // knowing it can the router read it. The client's own choice, the DCID of
  // its first Initial, also leads to the connection: until our first Initial
  // reaches it, a client has no other (§7.2), and a retransmitted Initial
  // must find the connection its first one made.
  //
  //   connections  our ID (hex) → { quic, peer, cids, addressKey }
  //   cidMap       every ID that leads to a connection (hex) → our ID (hex)
  //   addressMap   "ip:port" → our ID — not for routing: for hasConnection(),
  //                which a demultiplexer sharing the port asks by address.
  var SERVER_CID_LEN = 8;
  var connections = {};
  var cidMap = {};
  var addressMap = {};
  var connectionCount = 0;
  var maxConnections = options.maxConnections || 10000;

  // ── Handshakes under way ────────────────────────────────────────────────
  //
  // A connection counts from when it is made until the client's Finished is
  // verified (or it goes). What load is, and what to do about it — Retry
  // for every new client (setValidateAddress), refusing work, scaling out —
  // is the application's call: it is told (getPendingHandshakes, and
  // 'handshakeLoad' at handshakeLoadThreshold, again when the count is back
  // under half of it). The cap per address is not a judgement of load:
  // past maxHandshakesPerAddress, an Initial from that address makes no
  // connection — the one place an address with many spoofed or real
  // attempts could otherwise fill maxConnections. High enough for many
  // clients behind one address (a carrier NAT), each handshake lasting a
  // round trip or two. All three can be changed while running.
  var pendingHandshakes = 0;
  var pendingByAddress = new Map();   // IP → handshakes under way from it
  var handshakeLoadHigh = false;
  var handshakeLoadThreshold = handshakeCount(options.handshakeLoadThreshold, 500, 'handshakeLoadThreshold');
  var maxHandshakesPerAddress = handshakeCount(options.maxHandshakesPerAddress, 64, 'maxHandshakesPerAddress');

  function handshakeCount(v, dflt, name) {
    if (v === undefined || v === null) return dflt;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
      var e = new RangeError(name + ' must be a whole number ≥ 0 (0: off), got ' + v); e.code = 'ERR_OUT_OF_RANGE'; throw e;
    }
    return v;
  }
  // An IPv4 client on a dual-stack socket is one address either way.
  function addressOf(ip) {
    return ip && ip.indexOf('::ffff:') === 0 && ip.indexOf('.') !== -1 ? ip.substring(7) : ip;
  }
  function handshakeStarted(entry, ip) {
    entry.pendingIp = addressOf(ip);
    pendingHandshakes++;
    pendingByAddress.set(entry.pendingIp, (pendingByAddress.get(entry.pendingIp) || 0) + 1);
    checkHandshakeLoad();
  }
  // Done, or gone — once.
  function handshakeEnded(entry) {
    if (entry.pendingIp === undefined) return;
    var n = (pendingByAddress.get(entry.pendingIp) || 1) - 1;
    if (n > 0) pendingByAddress.set(entry.pendingIp, n); else pendingByAddress.delete(entry.pendingIp);
    entry.pendingIp = undefined;
    pendingHandshakes--;
    checkHandshakeLoad();
  }
  function checkHandshakeLoad() {
    var t = handshakeLoadThreshold;
    if (!handshakeLoadHigh && t > 0 && pendingHandshakes >= t) {
      handshakeLoadHigh = true;
      ev.emit('handshakeLoad', { pending: pendingHandshakes, high: true });
    } else if (handshakeLoadHigh && (t === 0 || pendingHandshakes < t / 2)) {
      handshakeLoadHigh = false;
      ev.emit('handshakeLoad', { pending: pendingHandshakes, high: false });
    }
  }
  var sweepTimer = null;

  function cidKey(cid) {
    return Buffer.from(cid.buffer, cid.byteOffset, cid.byteLength).toString('hex');
  }


  // ============================================================
  //  UDP → connection routing
  // ============================================================

  function onUdpMessage(msg, rinfo) {
    // Closed (or closing, its last datagrams leaving): nothing more is taken.
    if (shutDown) return;
    var data = new Uint8Array(msg);
    var fromIp = rinfo.address;
    var fromPort = rinfo.port;
    if (DEBUG) console.log('[qserver] UDP from ' + fromIp + ':' + fromPort + ' len=' + data.length);

    var packets = parse_quic_datagram(data, SERVER_CID_LEN);
    if (packets.length === 0) return;

    // ── Version Negotiation (RFC 9000 §6) ──
    // Must happen before any connection is created. A long-header packet
    // carrying a version we don't speak gets a Version Negotiation packet in
    // reply — that is how a client discovers what we support, and how a prober
    // checks we are alive without completing a handshake.
    //
    // Getting this wrong is silent and confusing: without it, the router
    // below happily creates a connection for the unknown-version Initial, maps
    // the address to it, and every subsequent probe is routed into a
    // connection that cannot do anything with it. The peer sees no reply at
    // all and concludes the server is down.
    var firstPkt = packets[0];
    if (firstPkt.form === 'long' &&
        firstPkt.type !== 'version_negotiation' &&
        quicVersions.indexOf(firstPkt.version) < 0) {

      // Anti-amplification (RFC 9000 §14.1): only answer datagrams that are
      // at least 1200 bytes, so we can't be used to reflect traffic at a
      // spoofed source. A genuine Initial is always padded to that size.
      if (data.length < 1200) {
        if (DEBUG) console.log('[qserver] unsupported version 0x' +
          firstPkt.version.toString(16) + ' in a short datagram (' +
          data.length + 'B) — dropping without VN');
        return;
      }

      var vn = build_version_negotiation(firstPkt.dcid, firstPkt.scid, quicVersions);
      if (DEBUG) console.log('[qserver] version 0x' +
        firstPkt.version.toString(16) + ' unsupported — sending Version Negotiation');
      sendUdp(fromIp, fromPort, vn);
      return;
    }

    // RFC 9000 §14.1: "A server MUST discard an Initial packet that is
    // carried in a UDP datagram with a payload that is smaller than the
    // smallest allowed maximum datagram size of 1200 bytes." A real client
    // pads every datagram carrying an Initial to that size. One that does not
    // costs an attacker little and would buy a connection's state, a key
    // exchange and a signature — and, with the address unvalidated, three
    // times its own size in replies. Checked before any connection exists.
    for (var pi = 0; pi < packets.length; pi++) {
      if (packets[pi].type === 'initial' && data.length < 1200) {
        if (DEBUG) console.log('[qserver] Initial in a ' + data.length + 'B datagram — dropped (min 1200)');
        return;
      }
    }

    // The whole datagram goes where its first packet is addressed, parsed
    // once, here: the connection gets the packets, not the bytes. §12.2:
    // "Senders MUST NOT coalesce QUIC packets with different connection IDs
    // into a single UDP datagram. Receivers SHOULD ignore any subsequent
    // packets with a different Destination Connection ID than the first."
    var dcidKey = cidKey(firstPkt.dcid);
    var entry = (dcidKey in cidMap) ? connections[cidMap[dcidKey]] : null;

    if (!entry) {
      // Only an Initial may start a connection. Anything else addressed to
      // an ID we do not know — a packet for a connection already gone, or
      // one that never was — is not given a connection of its own. A 1-RTT
      // one is answered with a Stateless Reset; the rest are dropped.
      if (firstPkt.form === 'short') { sendStatelessReset(firstPkt.dcid, data.length, fromIp, fromPort); return; }
      if (firstPkt.type !== 'initial') return;
      // §7.2: the DCID of a client's first Initial "MUST be at least 8 bytes
      // in length". Shorter ones would also be easy to guess and collide.
      if (firstPkt.dcid.byteLength < 8) return;
      if (connectionCount >= maxConnections) return;

      var retry = null, knownAddress = false;
      if (firstPkt.token && firstPkt.token.byteLength > 0) {
        var tok = openToken(firstPkt.token, fromIp, firstPkt.dcid, firstPkt.version);
        if (tok === false) return;
        if (tok && tok.kind === 'retry') retry = tok;
        else if (tok && tok.kind === 'new') knownAddress = true;
      }
      if (!retry && !knownAddress && validateAddress) { sendRetry(firstPkt, fromIp, fromPort); return; }
      // Past the cap for its address: no connection (see "Handshakes under
      // way"). After the Retry: a spoofed address never comes back with a
      // token, and this count is of addresses that did.
      if (maxHandshakesPerAddress > 0 && (pendingByAddress.get(addressOf(fromIp)) || 0) >= maxHandshakesPerAddress) return;

      entry = createConnection(firstPkt.dcid, fromIp, fromPort, retry, firstPkt.version, knownAddress);
      if (!entry) return;
    }

    for (var ci = 1; ci < packets.length; ci++) {
      if (cidKey(packets[ci].dcid) !== dcidKey) { packets.length = ci; break; }
    }

    // The datagram's size goes with it: the connection charges it to the
    // anti-amplification budget (RFC 9000 §8.1).
    var isNew = !entry.started;
    entry.quic.feedPackets(fromIp, fromPort, packets, data.length);

    // A connection is kept only if its first datagram began a handshake (an
    // Initial CRYPTO frame that decrypted). One that did not — a PING, junk
    // under a random DCID, from an address nobody has proven — cost a
    // connection's state and a place under maxConnections; enough of them,
    // spoofed, kept every real client out (QUICtester found 10 of 19 servers
    // doing this). It goes at once, unanswered.
    if (isNew) {
      if (!entry.quic.handshakeStarted) { entry.quic.discard(); dropConnection(entry.connId); return; }
      entry.started = true;
    }
  }


  /**
   * Who this connection is, for an SNICallback that wants to know — the QUIC
   * counterpart of connectionInfo() in tcp_listener, with the same fields.
   *
   * A client dialling a bare IP address sends no SNI (RFC 6066 §3 forbids an
   * IP literal there), so the callback's only way to choose a certificate is
   * this third argument. Without it, a browser that loaded https://<ip> over
   * TCP, saw Alt-Svc and moved to QUIC, had its handshake refused and reported
   * ERR_QUIC_PROTOCOL_ERROR — HTTP/3 simply did not work by IP.
   *
   * localAddress is null, and that is not an omission. A UDP socket bound to
   * a wildcard address cannot tell which of the host's addresses a datagram
   * was sent to — Node exposes no IP_PKTINFO — so the honest answer is
   * "unknown", and the family the client used is what is reported instead.
   */
  function connectionInfo(fromIp, fromPort) {
    var remote = fromIp;
    var family = remote && remote.indexOf(':') !== -1 ? 'IPv6' : 'IPv4';
    // An IPv4 peer arriving on a dual-stack IPv6 socket.
    if (remote && remote.indexOf('::ffff:') === 0 && /^\d+\.\d+\.\d+\.\d+$/.test(remote.substring(7))) {
      remote = remote.substring(7);
      family = 'IPv4';
    }
    return {
      transport: 'quic',
      localAddress: null,
      localPort: port || null,
      family: family,
      remoteAddress: remote,
      remotePort: fromPort
    };
  }

  // retry: { originalDcid, sourceCid } when the client came back with a valid
  // Retry token — its address is proven, and the connection keeps the ID the
  // Retry gave it.
  // knownAddress: the client came with a NEW_TOKEN token of ours — its
  // address is proven, as by a Retry, but the connection keeps its IDs.
  function createConnection(originalDcid, fromIp, fromPort, retry, version, knownAddress) {
    // Bound per connection, with its details as a third argument — after cb,
    // so a (servername, cb) callback keeps working and never reads it. Only a
    // callback the application supplied gets it; the built-in one for a fixed
    // key/cert has no use for it.
    var connSni = options.SNICallback
      ? (function (info) {
          return function (servername, cb) { return options.SNICallback(servername, cb, info); };
        })(connectionInfo(fromIp, fromPort))
      : sniCallback;

    // Our ID for the connection: the one our Retry gave the client, or a new
    // one. (After a Retry the client addresses nothing else, so its first
    // DCID leads nowhere and is not mapped.)
    var localCid = retry ? retry.sourceCid : newLocalCid();
    var connId = cidKey(localCid);
    if (connId in cidMap) return null;   // a Retry ID taken meanwhile — 2^-64

    // The peer's address goes in with it: the connection keeps it — and the
    // address it moves to, if the client's NAT changes it (RFC 9000 §9.3) —
    // as quic.remoteAddress / remotePort, where anything that keys on the
    // peer (a rate limiter, a log line, an IP screen) reads it. Over TCP that
    // comes free from the socket; QUIC has no socket per connection.
    var quic = new QUICConnection({
      SNICallback: connSni, alpn: alpn, ticketKeys: ticketKeys, ticketData: ticketData, ech: ech, ocspRequest: ocspRequest, tlsOptions: tlsOptions,
      // The CAs a client certificate is checked against (requestCert).
      ca: tlsOptions.requestCert ? (options.ca || null) : null,
      localCid: localCid, statelessResetToken: resetToken(localCid), retry: retry,
      remoteAddress: fromIp, remotePort: fromPort, transportParams: transportParams,
      initialCongestionWindow: connDefaults.initialCongestionWindow,
      carefulResume: connDefaults.carefulResume,
      startupCap: connDefaults.startupCap,
      pmtuDiscovery: connDefaults.pmtuDiscovery,
      maxUdpPayloadSize: connDefaults.maxUdpPayloadSize,
      initialRtt: connDefaults.initialRtt,
      reorderWindow: connDefaults.reorderWindow,
      earlyData: earlyData, earlyDataMaxAge: earlyDataMaxAge, earlyDataReplay: earlyDataReplay,
      // The application protocol's part of the early-data context (h3_server: its SETTINGS).
      earlyDataAppContext: typeof options.earlyDataAppContext === 'string' ? options.earlyDataAppContext : undefined,
      connectionOptions: connectionOptions,
      // The version of the client's first Initial, and the ones accepted.
      version: version, quicVersions: quicVersions,
      addressValidated: !!knownAddress,
      // A token for the client's next connection (NEW_TOKEN, RFC 9000
      // §8.1.3), for the address it is at then, in the connection's version.
      newToken: function (ip, v) { return new Uint8Array(sealNewToken(ip, v)); },
      // More connection IDs for the connection (NEW_CONNECTION_ID, for
      // migration, RFC 9000 §9.5): each routed here from when it is made,
      // with its stateless reset token, until the client retires it.
      issueConnectionId: function () {
        var cid = newLocalCid();
        var k = cidKey(cid);
        if (k in cidMap) return null;
        cidMap[k] = connId;
        entry.cids.push(k);
        return { cid: cid, token: resetToken(cid) };
      },
      retireConnectionId: function (cid) {
        var k = cidKey(cid);
        if (cidMap[k] === connId) delete cidMap[k];
        var i = entry.cids.indexOf(k);
        if (i >= 0) entry.cids.splice(i, 1);
      },
      greaseQuicBit: greaseQuicBit,
      stats: stats
    });

    var addressKey = fromIp + ':' + fromPort;
    var entry = {
      quic: quic,
      peer: { address: fromIp, port: fromPort },
      cids: retry ? [connId] : [connId, cidKey(originalDcid)],
      addressKey: addressKey,
      connId: connId,
      started: false     // its first datagram began a handshake (see onUdpMessage)
    };
    connections[connId] = entry;
    connectionCount++;
    handshakeStarted(entry, fromIp);
    quic.on('handshake_ended', function (confirmed) {
      handshakeEnded(entry);
      if (!stats) return;
      stats.handshake('quic', confirmed, confirmed && quic.isSessionReused && quic.isSessionReused());
      if (confirmed) stats.protocol(quic.alpnProtocol);
    });
    if (stats) {
      stats.connections.quic++;
      // How it ended: the CONNECTION_CLOSE either way is counted by the
      // connection as it goes or comes; one that ended with neither, here.
      quic.on('close', function () {
        if (!quic.context.peer_close && !quic.context.close_frame) stats.closes.quic.silent++;
      });
    }
    for (var i = 0; i < entry.cids.length; i++) cidMap[entry.cids[i]] = connId;
    addressMap[addressKey] = connId;

    // Each packet goes where the connection says — its current path, or the
    // address a PATH_CHALLENGE or PATH_RESPONSE is for.
    quic.on('packet', function (data, address, port) {
      sendUdp(address, port, data);
    });

    // The connection now sends to another address. Routing is by connection
    // ID and needs nothing; what follows the address is hasConnection(), and
    // the peer object the 'connection' event handed out.
    //
    // The peer object is NOT moved with it: it is what the application keys
    // on — rate limits, access rules, logs — and an address is given to it
    // only once the client has proven it receives there (path_validated).
    // A packet with a rewritten source address moved it at once.
    quic.on('path', function (address, port) {
      if (addressMap[entry.addressKey] === connId) delete addressMap[entry.addressKey];
      entry.addressKey = address + ':' + port;
      addressMap[entry.addressKey] = connId;
      entry.peer.address = quic.remoteAddress;
      entry.peer.port = quic.remotePort;
    });
    quic.on('path_validated', function () {
      entry.peer.address = quic.remoteAddress;
      entry.peer.port = quic.remotePort;
    });

    // Drop our bookkeeping when the connection closes.
    quic.on('close', function () { dropConnection(connId); });

    // Hand the raw connection to the application layer (H3, DoQ, ...).
    ev.emit('connection', quic, entry.peer);
    return entry;
  }

  // A connection ID of ours: 64 random bits — unguessable, which a
  // connection relies on to take its use by the client as proof of the
  // client's address (§8.1) — and not in use already, which the check makes
  // certain rather than merely likely.
  function newLocalCid() {
    var cid;
    do { cid = new Uint8Array(crypto.randomBytes(SERVER_CID_LEN)); } while (cidKey(cid) in cidMap);
    return cid;
  }

  // The one place a connection leaves the maps: every ID that led to it, and
  // its address unless a newer connection has taken that over.
  function dropConnection(connId) {
    var entry = connections[connId];
    if (!entry) return;
    for (var i = 0; i < entry.cids.length; i++) {
      if (cidMap[entry.cids[i]] === connId) delete cidMap[entry.cids[i]];
    }
    if (addressMap[entry.addressKey] === connId) delete addressMap[entry.addressKey];
    delete connections[connId];
    connectionCount--;
    handshakeEnded(entry);
  }


  // ── setOptions / getOptions ────────────────────────────────────────────
  //
  // One call for every option that can change while the server runs, by
  // the names createServer takes: the server's own (validateAddress,
  // handshakeLoadThreshold, maxHandshakesPerAddress — from the next client
  // on, the threshold at once) and what new connections are made with
  // (CONNECTION_OPTIONS — connections already open keep theirs). Checked
  // whole before anything changes: one bad value, and nothing does. A name
  // that cannot change this way says what can.
  var SERVER_RUNTIME = ['validateAddress', 'handshakeLoadThreshold', 'maxHandshakesPerAddress', 'earlyData', 'earlyDataMaxAge'];
  var ELSEWHERE = {
    key: 'setSecureContext()', cert: 'setSecureContext()', ca: 'setSecureContext()', pfx: 'setSecureContext()',
    passphrase: 'setSecureContext()', SNICallback: 'setSecureContext()',
    ticketKeys: 'setTicketKeys()', ech: 'setEchKeys()', resetTokenSecret: 'setResetTokenSecret()', tokenSecret: 'setTokenSecret()',
    transportParams: 'connectionOptions, per connection'
  };
  function optErr(Ctor, code, msg) { var e = new Ctor(msg); e.code = code; return e; }
  function setOptions(o) {
    if (!o || typeof o !== 'object') throw optErr(TypeError, 'ERR_INVALID_ARG_TYPE', 'setOptions() takes an object');
    var conn = {}, srv = {};
    for (var k in o) {
      if (o[k] === undefined) continue;
      if (k in CONNECTION_OPTIONS) conn[k] = o[k];
      else if (SERVER_RUNTIME.indexOf(k) !== -1) srv[k] = o[k];
      else if (k in ELSEWHERE) throw optErr(TypeError, 'ERR_INVALID_ARG_VALUE', k + ' cannot be changed with setOptions(): use ' + ELSEWHERE[k]);
      else throw optErr(TypeError, 'ERR_INVALID_ARG_VALUE', k + ' cannot be changed while the server runs');
    }
    conn = checkConnectionOptions(conn, 'setOptions');
    if ('validateAddress' in srv && typeof srv.validateAddress !== 'boolean') throw optErr(TypeError, 'ERR_INVALID_ARG_TYPE', 'validateAddress must be a boolean, got ' + srv.validateAddress);
    if ('handshakeLoadThreshold' in srv) srv.handshakeLoadThreshold = handshakeCount(srv.handshakeLoadThreshold, 500, 'handshakeLoadThreshold');
    if ('maxHandshakesPerAddress' in srv) srv.maxHandshakesPerAddress = handshakeCount(srv.maxHandshakesPerAddress, 64, 'maxHandshakesPerAddress');
    if ('earlyData' in srv && typeof srv.earlyData !== 'boolean') throw optErr(TypeError, 'ERR_INVALID_ARG_TYPE', 'earlyData must be a boolean, got ' + srv.earlyData);
    if ('earlyDataMaxAge' in srv) srv.earlyDataMaxAge = earlyMaxAge(srv.earlyDataMaxAge);
    // All good: applied.
    Object.assign(connDefaults, conn);
    if ('validateAddress' in srv) validateAddress = srv.validateAddress;
    if ('earlyData' in srv) earlyData = srv.earlyData;
    if ('earlyDataMaxAge' in srv) earlyDataMaxAge = srv.earlyDataMaxAge;
    if ('maxHandshakesPerAddress' in srv) maxHandshakesPerAddress = srv.maxHandshakesPerAddress;
    if ('handshakeLoadThreshold' in srv) { handshakeLoadThreshold = srv.handshakeLoadThreshold; checkHandshakeLoad(); }
  }
  function getOptions() {
    return Object.assign({
      validateAddress: validateAddress,
      earlyData: earlyData,
      earlyDataMaxAge: earlyDataMaxAge,
      handshakeLoadThreshold: handshakeLoadThreshold,
      maxHandshakesPerAddress: maxHandshakesPerAddress
    }, connDefaults);
  }

  // ============================================================
  //  Stateless Reset (RFC 9000 §10.3)
  // ============================================================

  // At most this many a second, all addresses together (§10.3.3 suggests a
  // limit). Answering every packet for an unknown ID without one would let
  // anyone who sends junk make this server answer each of them; a real
  // client needs one reset, and gets more than enough within this.
  var RESET_RATE = 100;
  var resetBudget = RESET_RATE;
  var resetBudgetTime = Date.now();

  function sendStatelessReset(dcid, receivedBytes, toIp, toPort) {
    // §10.3.3: every reset smaller than the packet that prompted it — two
    // endpoints that both reset what they cannot place would otherwise
    // answer each other forever — and at least 21 bytes, the smallest a
    // short-header packet can be (§10.3). Up to 43 bytes, one byte shorter,
    // as §10.3 advises; above that, a varying size, so the length alone does
    // not mark it.
    if (!dcid || receivedBytes <= 21) return;

    var now = Date.now();
    resetBudget = Math.min(RESET_RATE, resetBudget + (now - resetBudgetTime) * RESET_RATE / 1000);
    resetBudgetTime = now;
    if (resetBudget < 1) return;
    resetBudget -= 1;

    var random = crypto.randomBytes(receivedBytes);
    var size = receivedBytes <= 43 ? receivedBytes - 1 : Math.min(receivedBytes - 1, 43 + random[0] % 58);
    var reset = new Uint8Array(size);
    reset.set(random.subarray(1, 1 + size - 16));
    // Fixed bits 01: to anyone but the client, a short-header packet (§10.3).
    reset[0] = 0x40 | (reset[0] & 0x3f);
    reset.set(resetToken(dcid), size - 16);
    if (DEBUG) console.log('[qserver] stateless reset (' + size + 'B) to ' + toIp + ':' + toPort);
    sendUdp(toIp, toPort, reset);
  }


  // ============================================================
  //  UDP send
  // ============================================================

  function sendUdp(toIp, toPort, data) {
    var isV6 = toIp.indexOf(':') >= 0;
    // Prefer external socket (shared mode) over internally-bound socket
    var socket = isV6
      ? (externalSocket6 || udp6)
      : (externalSocket4 || udp4);
    if (!socket) return;
    sendsPending++;
    socket.send(data, toPort, toIp, function (err) {
      sendsPending--;
      if (err && !closing) ev.emit('error', err);
      if (closing && sendsPending === 0) closing();
    });
  }
  // Datagrams handed to a socket and not yet sent. dgram.send() leaves on a
  // later turn (it resolves the address first), and a socket closed before
  // then drops what it was given: the CONNECTION_CLOSE close() sends every
  // connection never left, and each client found out only by its idle
  // timeout. close() waits for them — not long (SEND_DRAIN_MAX).
  var sendsPending = 0;
  var shutDown = false;
  var closing = null;
  var SEND_DRAIN_MAX = 200;


  // ============================================================
  //  listen / close
  // ============================================================

  function listen(listenPort, host, callback) {
    shutDown = false;
    if (typeof host === 'function') { callback = host; host = null; }
    // `|| 443` turned port 0 into 443 — and port 0 is not "no port": it is how
    // a caller asks the OS for a free one (server.js has the same fix).
    port = (listenPort === undefined || listenPort === null) ? 443 : listenPort;
    host = host || '::';

    if (isExternal) {
      // External sockets already bound — wire up incoming messages.
      // Starting the sweep timer is safe here (idempotent check below).
      // Externally-owned sockets are already bound, so enlarge them here.
      // The owner may not have done it, and the cost of asking twice is nil.
      // NOT listening on them. The owner of an external socket is the one
      // reading it — typically a demultiplexer that also carries STUN, DTLS
      // and SRTP on the same port — and it feeds QUIC packets in through
      // handlePacket(). This used to attach a 'message' listener as well, so
      // every datagram on the socket reached QUIC twice: each QUIC packet was
      // decrypted a second time and dropped as a duplicate, and every non-QUIC
      // packet — media included, on the hottest path there is — went through
      // the QUIC parser before being discarded.
      if (externalSocket4) {
        try { externalSocket4.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
        try { externalSocket4.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}
      }
      if (externalSocket6) {
        try { externalSocket6.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
        try { externalSocket6.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}
      }
      startSweepTimer();
      if (typeof callback === 'function') setImmediate(callback);
      return;
    }

    // Grow the kernel socket buffers once the socket is bound.
    //
    // Node's defaults are small. A full send buffer drops the datagram
    // locally and silently — indistinguishable from network loss, so loss
    // recovery engages and throughput collapses. See LOSS_PTO_PLAN 7.4: this
    // is what defeated the third pacer-calibration attempt.
    //
    // try/catch because some platforms cap the value and throw; not being
    // able to enlarge the buffer must not stop the server from listening.
    function growBuffers(sock) {
      try { sock.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
      try { sock.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}
    }

    // Both sockets are attempted, and listening succeeds if EITHER binds.
    //
    // The callback used to hang off udp6.bind alone. On a host without IPv6 —
    // a container, a CI runner, plenty of cloud instances — that bind fails
    // with EAFNOSUPPORT and the callback is never called: listen() returns, the
    // v4 socket is up and working, and the caller waits forever for a
    // 'listening' that cannot arrive. Nothing logs, because the error goes to
    // the 'error' event that a caller waiting on the callback has not reached
    // yet.
    //
    // A failure on one family is also not fatal on its own. Only if BOTH fail
    // is there nothing to listen on, and that is reported as an error.
    var pending = 2;
    var bound = 0;
    var lastErr = null;

    function settle(err) {
      if (err) lastErr = err;
      else bound++;
      if (--pending > 0) return;
      if (bound === 0) {
        ev.emit('error', lastErr || new Error('failed to bind UDP on port ' + port));
        return;
      }
      if (typeof callback === 'function') callback();
    }

    udp4 = dgram.createSocket('udp4');
    udp4.on('message', onUdpMessage);
    udp4.once('error', function (err) {
      // A bind failure arrives before we are listening; anything later is a
      // runtime socket error and belongs to the consumer.
      udp4 = null;
      settle(err);
      ev.emit('error', err);
    });
    var host4 = host.indexOf('.') !== -1 ? host : '0.0.0.0';
    udp4.bind(port, host4, function () { growBuffers(udp4); settle(null); });

    udp6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
    udp6.on('message', onUdpMessage);
    udp6.once('error', function (err) {
      udp6 = null;
      // No IPv6 on this host is ordinary, not an error the application needs
      // to see — the v4 socket is serving. Only a total failure is emitted,
      // from settle() above.
      settle(err);
    });
    var host6 = host.indexOf(':') !== -1 ? host : '::';
    udp6.bind(port, host6, function () { growBuffers(udp6); settle(null); });

    startSweepTimer();
  }

  // Periodic sweep for dead connections (safety net). Runs independently
  // of socket ownership so external-mode agents get the same cleanup.
  function startSweepTimer() {
    if (sweepTimer) return;  // idempotent
    sweepTimer = setInterval(function () {
      for (var id in connections) {
        if (connections[id].quic.state === 'closed') dropConnection(id);
      }
    }, 30000);
    if (sweepTimer.unref) sweepTimer.unref();
  }

  function close(callback) {
    shutDown = true;
    // Stop sweep
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }

    // Close all connections
    for (var id in connections) {
      // Transport NO_ERROR (0x1c, code 0) — deliberately NOT an HTTP/3 code.
      // This server is application-agnostic: `alpn` is an option, and a DoQ or
      // custom-protocol server built on it has no business emitting
      // H3_NO_ERROR. An application layer that wants its own code closes the
      // connection itself (h3_client / agent / webtransport all do).
      try { connections[id].quic.close(0, 'server closing'); } catch (e) { }
    }
    connections = {};
    cidMap = {};
    addressMap = {};
    connectionCount = 0;

    // The sockets close once what was sent — the CONNECTION_CLOSEs just
    // above — has left (see sendsPending).
    if (sendsPending > 0 && (udp4 || udp6)) {
      var drained = false;
      var finish = function () {
        if (drained) return;
        drained = true;
        clearTimeout(drainTimer);
        closing = null;
        closeSockets(callback);
      };
      closing = finish;
      var drainTimer = setTimeout(finish, SEND_DRAIN_MAX);
      return;
    }
    closeSockets(callback);
  }

  function closeSockets(callback) {
    var closed = 0;
    var total = (udp4 ? 1 : 0) + (udp6 ? 1 : 0);
    if (total === 0) { if (callback) callback(); return; }

    function onClose() {
      closed++;
      if (closed >= total && typeof callback === 'function') callback();
    }

    if (udp4) { udp4.close(onClose); udp4 = null; }
    if (udp6) { udp6.close(onClose); udp6 = null; }
  }


  // ============================================================
  //  External packet API (for shared UDP port scenarios)
  // ============================================================

  // Query whether a datagram belongs to an active QUIC connection.
  //
  // hasConnection(rinfo) — by the address it came from. Used by the demuxer
  // to disambiguate byte 0 in range 64-79 between QUIC short header and TURN
  // ChannelData (RFC 9443). Fresh connections must be classified by byte 0
  // range (80-127 or 192+ = QUIC).
  //
  // hasConnection(rinfo, msg) — by the connection ID the datagram is
  // addressed to, from wherever it came: the answer to "is this one mine"
  // when several servers share the port (one per thread, SO_REUSEPORT) and a
  // datagram can reach one that does not hold its connection — a client
  // whose address changed is hashed to another socket. Asked before
  // handlePacket: given a short-header packet for an ID it does not know,
  // handlePacket answers with a Stateless Reset, and that would end a
  // connection another server holds. The address does not count here: an ID
  // that leads nowhere is not ours, whatever address sent it.
  function hasConnection(rinfo, msg) {
    if (msg === undefined || msg === null) {
      var key = rinfo.address + ':' + rinfo.port;
      return (key in addressMap) && (addressMap[key] in connections);
    }
    var dcid = datagramDcid(msg);
    if (!dcid) return false;
    var k = cidKey(dcid);
    return (k in cidMap) && (cidMap[k] in connections);
  }

  // The Destination Connection ID of a datagram's first packet, without
  // parsing the rest (RFC 9000 §17.2, §17.3; RFC 8999 for any version): a
  // long header carries its length, a short header ours (SERVER_CID_LEN).
  // null for one too short to hold it.
  function datagramDcid(msg) {
    if (!(msg instanceof Uint8Array) || msg.length < 1) return null;
    if (msg[0] & 0x80) {
      if (msg.length < 6) return null;
      var len = msg[5];
      if (msg.length < 6 + len) return null;
      return msg.subarray(6, 6 + len);
    }
    if (msg.length < 1 + SERVER_CID_LEN) return null;
    return msg.subarray(1, 1 + SERVER_CID_LEN);
  }


  // ============================================================
  //  Server API
  // ============================================================

  return {
    listen: listen,
    close: close,
    on: function (name, fn) { ev.on(name, fn); },

    /** Feed an incoming UDP packet when running in external-socket mode.
     *  rinfo must be in Node's dgram format: { address, port, family, size }. */
    handlePacket: onUdpMessage,

    /** hasConnection(rinfo): the address matches an active QUIC connection.
     *  hasConnection(rinfo, msg): the datagram is addressed to one (by its
     *  connection ID). Used by demuxers for routing decisions on shared UDP
     *  ports — the second when several servers share it (see above). */
    hasConnection: hasConnection,

    /** The session ticket keys — tls.Server's names. A new key applies to
     *  connections made from now on. */
    getTicketKeys: function () { return ticketKeys; },
    setTicketKeys: function (keys) { ticketKeys = keys; },

    /** The Encrypted Client Hello keys; a new set applies to connections
     *  made from now on. */
    getEchKeys: function () { return ech; },
    setEchKeys: function (keys) { ech = keys || null; },

    /** The stateless reset secret. A new one applies to connections made
     *  from now on; a reset for one made before cannot be recognised. */
    /** Address validation with Retry (see validateAddress above): on or off,
     *  from the next new client on. */
    getValidateAddress: function () { return validateAddress; },
    setValidateAddress: function (on) { validateAddress = on === true; },

    /** Handshakes under way (see "Handshakes under way" above), and the
     *  two limits on them — changed while running, they apply at once: the
     *  threshold to the count as it stands, the cap to the next Initial. */
    getPendingHandshakes: function () { return pendingHandshakes; },

    /** The options that can change while the server runs, by createServer's
     *  names (see setOptions). */
    getOptions: getOptions,
    setOptions: setOptions,

    getResetTokenSecret: function () { return resetTokenSecret; },
    setResetTokenSecret: function (secret) { resetTokenSecret = checkResetTokenSecret(secret) || resetTokenSecret; },

    /** The address-validation token secret (Retry, NEW_TOKEN — see
     *  tokenSecret above). A new one applies from now on; tokens sealed
     *  under the one before no longer open: a client back with a NEW_TOKEN
     *  loses its shortcut, and one mid-Retry its attempt (it accepts no
     *  second Retry). */
    getTokenSecret: function () { return tokenSecret; },
    setTokenSecret: function (secret) {
      var s = checkTokenSecret(secret);
      if (s) { tokenSecret = s; retryTokenKey = tokenKeyOf(s); }
    }
  };
}


export { createQuicServer };
