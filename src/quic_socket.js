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
import { QUICConnection } from './quic_connection.js';
import lemonTls from 'lemon-tls';
import { SUPPORTED_VERSIONS, parseVersionList, versionName } from './quic_version.js';


/**
 * Create a UDP socket bound to an ephemeral port and wire it to a client-side
 * QUICConnection. Shared by the HTTP/3 client (h3_client.js) and the
 * WebTransport client (webtransport.js), which had near-identical setup code:
 * pick udp4/udp6, create the socket, forward datagrams into the connection,
 * bind, create the client QUICConnection, forward outgoing packets to the
 * socket, and start the handshake.
 *
 * opts:
 *   remoteIp, remotePort   — where to send packets
 *   hostname               — SNI / :authority for the QUIC/TLS handshake
 *   alpn                   — ALPN protocol(s) to offer. String or array.
 *                            Defaults to ['h3']. Non-HTTP/3 consumers pass
 *                            their own (e.g. ['hq-interop'] for HTTP/0.9,
 *                            ['doq'] for DNS-over-QUIC).
 *   rejectUnauthorized      — verify the server certificate (default true)
 *   ca                      — CA certificate(s) for verification
 *   idleTimeout, keepAlive  — as QUICConnection's (the idle timeout in force
 *                            is the smaller of the two sides', RFC 9000 §10.1)
 *   key, cert, passphrase   — a client certificate, sent if the server asks
 *                            for one (requestCert), as with tls.connect
 *   quicVersions            — QUIC versions, the first one's first flight
 *                            and the rest offered (default ['v1', 'v2'])
 *   token                   — a token from an earlier connection's
 *                            'new_token' event (NEW_TOKEN), used once
 *   session                 — a session saved from an earlier connection's
 *                            'session' event, to resume (tls.connect's name)
 *   onSocket(quic, socket)  — called as soon as the QUICConnection exists,
 *                            BEFORE the handshake starts. Use this to attach
 *                            listeners that must observe the handshake, such
 *                            as 'keylog'. onConnect is too late for those.
 *   onConnect(quic, socket) — called once the QUIC handshake completes
 *   onClose()              — called when the connection closes (the socket is
 *                            already closed by the time this runs)
 *   onError(err)           — socket errors and outgoing-packet send errors
 *
 * Returns the UDP socket synchronously. The QUICConnection is created after the
 * socket binds, so it is delivered via onConnect rather than returned here.
 */
function createQuicClientSocket(opts) {
  // ecdhCurve (tls.connect's): the key-exchange groups to offer, in order —
  // 'X25519MLKEM768:X25519' for the post-quantum hybrid first. Unset or
  // 'auto': X25519, P-256, P-384. A name not implemented (or the hybrid in a
  // Node without ML-KEM) throws here, as tls.connect's does.
  var groups = lemonTls.parseEcdhCurve(opts.ecdhCurve);
  // sigalgs (tls.connect's): the signature schemes to offer, in order; unset,
  // lemon-tls's list. A name it does not know throws here.
  var sigalgs = lemonTls.parseSigalgs(opts.sigalgs);
  var isIPv6 = opts.remoteIp.indexOf(':') >= 0;
  var udpSocket = dgram.createSocket(isIPv6 ? 'udp6' : 'udp4');
  var quic = null;

  udpSocket.on('message', function (msg, rinfo) {
    if (quic) quic.feedDatagram(rinfo.address, rinfo.port, new Uint8Array(msg));
  });

  udpSocket.on('error', function (err) {
    if (opts.onError) opts.onError(err);
  });

  udpSocket.bind(0, function () {
    // Grow the kernel socket buffers before any traffic flows.
    //
    // Node's defaults are small (and notably small on Windows). When the send
    // buffer overflows, the datagram is dropped locally with no error — it
    // looks exactly like network loss, so the loss-recovery machinery kicks in
    // and the connection crawls. This was the failure that killed the third
    // pacer-calibration attempt (see LOSS_PTO_PLAN 7.4): larger bursts spilled
    // over the buffer and turned a lossless link into a slow one.
    //
    // Wrapped in try/catch because the call can throw on platforms that cap
    // the size; failing to enlarge the buffer is not a reason to fail the
    // connection.
    try { udpSocket.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
    try { udpSocket.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}

    // One attempt; after a Version Negotiation, a second in a version the
    // server offered (RFC 9000 §6.2) — once.
    start(null, null);
  });

  function start(version, vnOffered) {
    var q = quic = new QUICConnection({
      isServer: false,
      hostname: opts.hostname,
      // Without this the client always offered 'h3' regardless of what the
      // caller wanted, because TLSBridge falls back to ['h3'] when alpn is
      // undefined. Normalize a bare string into an array here so callers can
      // pass either form.
      alpn: (function () {
        var a = opts.alpn || ['h3'];
        return Array.isArray(a) ? a : [a];
      })(),
      // Defaults to true. Pass false for self-signed certificates, or supply
      // `ca` for a private CA.
      rejectUnauthorized: opts.rejectUnauthorized !== false,
      // A client certificate, for a server that asks (tls.connect's names).
      key: opts.key || null, cert: opts.cert || null, passphrase: opts.passphrase,
      ca: opts.ca || null,
      session: opts.session || null,
      requestOCSP: opts.requestOCSP === true,
      // Encrypted Client Hello: the server's ECHConfigList, or GREASE ECH.
      ech: opts.ech || null,
      echGrease: opts.echGrease === true,
      // The groups to offer (ecdhCurve, above); null: the default.
      groups: groups,
      sigalgs: sigalgs,
      // A NEW_TOKEN token from an earlier connection to the server (RFC 9000
      // §8.1.3), for the Initial packets.
      token: opts.token || null,
      // quic.remoteAddress / remotePort, as on a net.Socket.
      remoteAddress: opts.remoteIp,
      remotePort: opts.remotePort,
      // Our transport parameters, where the caller set them (tls_bridge).
      transportParams: opts.transportParams || null,
      // The connection's own options: idleTimeout (ms; or
      // transportParams.maxIdleTimeout) and keepAlive (true: PING at half the
      // idle timeout in force; a number: every that many ms).
      idleTimeout: opts.idleTimeout,
      keepAlive: opts.keepAlive,
      // The congestion window it starts with, where the caller set it.
      initialCongestionWindow: opts.initialCongestionWindow,
      // The connection's options (quic_connection's CONNECTION_OPTIONS).
      startupCap: opts.startupCap,
      pmtuDiscovery: opts.pmtuDiscovery,
      maxUdpPayloadSize: opts.maxUdpPayloadSize,
      initialRtt: opts.initialRtt,
      reorderWindow: opts.reorderWindow,
      // 0-RTT with `session` when its ticket allows it (RFC 9001 §4.6).
      earlyData: opts.earlyData === true,
      // The QUIC versions: the first flight's, then the others accepted
      // (offered through version_information, RFC 9368). ['v1', 'v2'].
      quicVersions: opts.quicVersions,
      version: version || undefined,
      versionNegotiation: vnOffered || undefined
    });

    // Hand the connection to the caller BEFORE connect() runs.
    //
    // onConnect fires after the handshake, which is too late for anything that
    // has to observe the handshake itself. Key logging is the concrete case:
    // lemon-tls skips building NSS lines while nothing is listening, and the
    // handshake secrets are emitted during connect() — so a listener attached
    // in onConnect receives nothing at all, and the client half of a capture
    // is undecryptable. onSocket gives callers a hook at the only moment that
    // works.
    if (opts.onSocket) opts.onSocket(q, udpSocket);

    q.on('packet', function (data) {
      udpSocket.send(data, opts.remotePort, opts.remoteIp, function (err) {
        if (err && opts.onError) opts.onError(err);
      });
    });

    // A connection that never connects is a failure the caller must hear
    // about, once: the TLS reason when there is one (a refused certificate,
    // with node:tls's code), the handshake timeout, or — when the peer simply
    // closed — its CONNECTION_CLOSE. Before this a refused certificate closed
    // the connection in silence, and an HTTP/3 request or a WebTransport
    // `ready` waited on it forever.
    var connected = false, failed = false;
    function fail(err) {
      if (connected || failed) return;
      failed = true;
      if (opts.onError) opts.onError(err);
    }

    q.on('error', function (err) { if (q === quic) fail(err); });

    q.on('connect', function () {
      connected = true;
      if (opts.onConnect) opts.onConnect(q, udpSocket);
    });

    // 0-RTT: the connection may carry application data now, before the
    // handshake — onEarly(quic, socket). Refused by the server, what went is
    // forgotten and 'early_rejected' says so (send it again after onConnect).
    q.on('early', function () { if (opts.onEarly) opts.onEarly(q, udpSocket); });

    // The server speaks none of the versions offered in this attempt: a new
    // one, in the first of ours it offers. A Version Negotiation that
    // answers the second attempt is not followed (§6.2: once).
    q.on('version_negotiation', function (offered) {
      if (vnOffered) return;
      var prefs = opts.quicVersions ? parseVersionList(opts.quicVersions, 'quicVersions') : SUPPORTED_VERSIONS;
      var pick = null;
      for (var i = 0; i < prefs.length && pick === null; i++) if (offered.indexOf(prefs[i]) >= 0) pick = prefs[i];
      if (pick === null) {
        var err = new Error('the server supports none of our QUIC versions (it offers ' + offered.map(versionName).join(', ') + ')');
        err.code = 'ERR_QUIC_VERSION_NEGOTIATION';
        fail(err);
        return;
      }
      start(pick, offered);
    });

    function closedError() {
      var pc = quic.context && quic.context.peer_close;
      var lc = !pc && quic.context && quic.context.close_frame;
      var err = new Error('QUIC connection closed before the handshake completed' +
        (pc ? ' (peer error 0x' + pc.error.toString(16) + (pc.reason ? ': ' + pc.reason : '') + ')' :
         lc ? ' (error 0x' + lc.error.toString(16) + (lc.reason ? ': ' + lc.reason : '') + ')' : ''));
      err.code = 'ERR_QUIC_HANDSHAKE_FAILED';
      return err;
    }

    // A handshake that will not complete is reported when that is known —
    // the peer's CONNECTION_CLOSE, or ours — not when the connection's drain
    // (RFC 9000 §10.2, up to 3 s) ends and 'close' comes: a server that
    // refused the ClientHello was heard 3 s late, and an HTTP/3 request
    // waited that long to fail. On the next turn: a TLS alert of ours closes
    // the connection first and gives its reason ('error') right after.
    q.on('handshake_ended', function (confirmed) {
      if (confirmed || q !== quic) return;
      setImmediate(function () { if (q === quic && !connected) fail(closedError()); });
    });

    q.on('close', function () {
      if (q !== quic) return;            // an attempt given up for another
      try { udpSocket.close(); } catch (e) {}
      if (!connected) fail(closedError());
      if (opts.onClose) opts.onClose();
    });

    q.connect();
  }

  return udpSocket;
}


export { createQuicClientSocket };
