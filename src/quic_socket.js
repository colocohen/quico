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
    quic = new QUICConnection({ isServer: false, hostname: opts.hostname });

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
