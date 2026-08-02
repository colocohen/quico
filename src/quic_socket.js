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

    quic = new QUICConnection({
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
      ca: opts.ca || null
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
    if (opts.onSocket) opts.onSocket(quic, udpSocket);

    quic.on('packet', function (data) {
      udpSocket.send(data, opts.remotePort, opts.remoteIp, function (err) {
        if (err && opts.onError) opts.onError(err);
      });
    });

    quic.on('connect', function () {
      if (opts.onConnect) opts.onConnect(quic, udpSocket);
    });

    quic.on('close', function () {
      try { udpSocket.close(); } catch (e) {}
      if (opts.onClose) opts.onClose();
    });

    quic.connect();
  });

  return udpSocket;
}


export { createQuicClientSocket };
