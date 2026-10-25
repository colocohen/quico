/*
 * quico: a full HTTP stack in JavaScript
 * Copyright 2025 colocohen
 * Licensed under the Apache License, Version 2.0
 *     https://github.com/colocohen/quico
 */

// ============================================================
//  quico no longer imports node:http, node:https, node:http2 or node:tls.
//
//  Every protocol layer is here: HTTP/1.1 (h1.js), HTTP/2 (h2.js + hpack.js),
//  HTTP/3 (h3.js + QUIC), and WebSocket. TLS comes from lemon-tls, also pure
//  JavaScript. What remains from Node is the transport it alone can provide —
//  node:net for TCP and node:dgram for UDP — plus node:crypto for primitives.
//
//  The point is not purity for its own sake. One stack, one set of semantics:
//  the same IncomingMessage and ServerResponse reach the application whether a
//  request arrived over QUIC, over TCP with h2, or over TCP with HTTP/1.1, so
//  a framework written against node:http runs over all three without knowing.
// ============================================================

import { createServer } from './src/server.js';
import { request, get } from './src/client.js';
import { Agent, globalAgent } from './src/agent.js';
import { IncomingMessage, ServerResponse, ClientRequest } from './src/streams.js';
import { createSecureContext } from './src/tls_bridge.js';
import lemonTls from 'lemon-tls';

// Encrypted Client Hello keys (RFC 9849) — LemonTLS's; for createServer's `ech`.
const generateEchKey = lemonTls.generateEchKey;
import { WebTransport, WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
         WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream } from './src/webtransport.js';
import { WebSocket } from './src/ws_client.js';
import { connectUdp } from './src/connect_udp_client.js';
import { WebSocketServer, upgradeWebSocket } from './src/ws_server.js';
import { ja4h } from './src/ja4h.js';
import { h2Fingerprint, h3Fingerprint, observeH2 } from './src/h2_fingerprint.js';
import { profileRequest } from './src/client_profile.js';

// Transport layers, for building something other than HTTP on top.
import { createQuicServer } from './src/quic_server.js';
import { createQuicClientSocket } from './src/quic_socket.js';
import { createTcpListener } from './src/tcp_listener.js';

// Protocol layers, for consumers that own their own sockets.
import { createServer as createH1Server } from './src/h1_server.js';
import { createServer as createH2Server } from './src/h2_server.js';
import { createServer as createH3Server } from './src/h3_server.js';
import { request as h1Request } from './src/h1_client.js';
import { request as h2Request } from './src/h2_client.js';
import { request as h3Request } from './src/h3_client.js';

const api = {
  createServer, request, get, Agent, globalAgent,
  IncomingMessage, ServerResponse, ClientRequest,
  connectUdp, createSecureContext, generateEchKey, WebTransport, WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
  WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream, WebSocket, WebSocketServer, upgradeWebSocket,
  ja4h, h2Fingerprint, h3Fingerprint, observeH2, profileRequest,
  createQuicServer, createQuicClientSocket, createTcpListener,
  createH1Server, createH2Server, createH3Server,
  h1Request, h2Request, h3Request
};

export {
  createServer, request, get, Agent, globalAgent,
  IncomingMessage, ServerResponse, ClientRequest,
  connectUdp, createSecureContext, generateEchKey, WebTransport, WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
  WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream, WebSocket, WebSocketServer, upgradeWebSocket,
  ja4h, h2Fingerprint, h3Fingerprint, observeH2, profileRequest,
  createQuicServer, createQuicClientSocket, createTcpListener,
  createH1Server, createH2Server, createH3Server,
  h1Request, h2Request, h3Request
};
export default api;
