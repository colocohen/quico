/*
 * quico — TypeScript declarations
 * A full HTTP stack in JavaScript: QUIC, HTTP/3, HTTP/2, HTTP/1.1, QPACK,
 * WebTransport, WebSocket and CONNECT-UDP, for Node.js.
 *
 * The API mirrors node:https (server, request, Agent) and the browser's
 * WebTransport and WebSocket. See README.md for every option and event.
 */

/// <reference types="node" />

import { IncomingMessage as NodeIncomingMessage, ServerResponse as NodeServerResponse, ClientRequest as NodeClientRequest } from 'node:http';
import { Duplex, Readable, Writable } from 'node:stream';
import { EventEmitter } from 'node:events';
import { Socket as DgramSocket, RemoteInfo } from 'node:dgram';
import { Socket as NetSocket } from 'node:net';

// ============================================================
//  Shared
// ============================================================

type PemInput = string | Buffer | Array<string | Buffer | { pem: string | Buffer; passphrase?: string }>;

/** RFC 9218 priority: urgency 0 (first) – 7, default 3. */
interface Priority {
  urgency?: number;
  incremental?: boolean;
}

/** QUIC's windows and stream limits, by RFC 9000's names in camelCase. */
interface TransportParams {
  initialMaxData?: number;
  initialMaxStreamDataBidiLocal?: number;
  initialMaxStreamDataBidiRemote?: number;
  initialMaxStreamDataUni?: number;
  initialMaxStreamsBidi?: number;
  initialMaxStreamsUni?: number;
  maxIdleTimeout?: number;
  disableActiveMigration?: boolean;
}

type StartupCap = 'stall' | 'always' | 'off';
type QuicVersion = 'v1' | 'v2' | number;

/** QUIC connection options, as the server, a request, WebTransport and connectUdp take them. */
interface QuicConnectionOptions {
  initialCongestionWindow?: number;
  startupCap?: StartupCap;
  pmtuDiscovery?: boolean;
  maxUdpPayloadSize?: number;
  initialRtt?: number;
  reorderWindow?: number;
}

/** A fingerprint: its hash, the raw string it was taken from, and its parts. */
interface Fingerprint {
  hash: string;
  raw: string;
  [part: string]: any;
}

// ============================================================
//  Server
// ============================================================

type RequestHandler = (req: QuicoIncomingMessage, res: QuicoServerResponse) => void;

interface EchKey {
  config: Uint8Array | Buffer;
  privateKey: Uint8Array | Buffer;
  /** false: kept to decrypt, not sent as retry_configs (rotation). */
  retry?: boolean;
}

interface ConnectionOptionsInfo {
  remoteAddress: string;
  remotePort: number;
  servername: string | null;
  resumed: boolean;
  previous: { rtt: number; bandwidth: number; age: number } | null;
}

interface ConnectionOptionsAnswer extends QuicConnectionOptions {
  transportParams?: TransportParams;
  carefulResume?: boolean;
}

interface ConnectUdpServerOptions {
  template?: string;
  allowPrivate?: boolean;
  maxTunnelsPerConnection?: number;
  idleTimeout?: number;
  lookup?: (host: string, options: { all: true }, cb: (err: Error | null, addresses: Array<{ address: string; family: number }>) => void) => void;
  proxyName?: string;
}

interface ServerOptions extends QuicConnectionOptions {
  key?: PemInput;
  cert?: PemInput;
  ca?: PemInput;
  passphrase?: string;
  SNICallback?: (servername: string, cb: (err: Error | null, ctx?: any) => void, info?: { transport: 'tcp' | 'quic' }) => void;
  http3?: boolean;
  http2?: boolean;
  http1?: boolean;
  ALPNProtocols?: string[];
  maxConnections?: number;
  ticketKeys?: Buffer;
  ech?: { keys: EchKey[] };
  earlyData?: boolean;
  earlyDataMaxAge?: number;
  earlyDataReplay?: (id: string, ttl: number, cb: (err: Error | null, isNew?: boolean) => void) => void;
  earlyDataFilter?: (req: QuicoIncomingMessage, cb: (err: Error | null, allow?: boolean) => void) => void;
  sessionTimeout?: number;
  requestCert?: boolean;
  rejectUnauthorized?: boolean;
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  maxVersion?: 'TLSv1.2' | 'TLSv1.3';
  certificateCompression?: Array<'brotli' | 'zstd' | 'zlib'> | boolean;
  honorCipherOrder?: boolean;
  ciphers?: string;
  ecdhCurve?: string;
  sigalgs?: string;
  handshakeTimeout?: number;
  validateAddress?: boolean;
  handshakeLoadThreshold?: number;
  maxHandshakesPerAddress?: number;
  resetTokenSecret?: Buffer;
  tokenSecret?: Buffer;
  socket?: DgramSocket;
  socket6?: DgramSocket;
  greaseQuicBit?: boolean;
  port?: number;
  altSvc?: string | false;
  connectUdp?: ConnectUdpServerOptions;
  shouldUpgradeCallback?: (req: QuicoIncomingMessage) => boolean;
  headersTimeout?: number;
  requestTimeout?: number;
  keepAliveTimeout?: number;
  streamResetBurst?: number;
  streamResetRate?: number;
  maxRequestsPerSocket?: number;
  maxHeaderSize?: number;
  maxHeaderCount?: number;
  noDelay?: boolean;
  keepAlive?: boolean;
  keepAliveInitialDelay?: number;
  transportParams?: TransportParams;
  carefulResume?: boolean;
  quicVersions?: QuicVersion[];
  connectionOptions?: (info: ConnectionOptionsInfo, callback: (err: Error | null, options?: ConnectionOptionsAnswer) => void) => void;
  maxWebTransportSessions?: number;
  // HTTP/2 settings
  maxConcurrentStreams?: number;
  headerTableSize?: number;
  initialWindowSize?: number;
  maxFrameSize?: number;
  maxHeaderListSize?: number;
  connectionWindowSize?: number;
  enableConnectProtocol?: boolean;
  maxSessionMemory?: number;
}

/** The handle of an HTTP/2 or HTTP/3 connection ('connection', 'stream_open', 'stream_reset'). */
interface ConnectionHandle {
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly destroyed?: boolean;
  /** HTTP/3: 'h3'-side handle; HTTP/2: the session. */
  readonly httpVersion?: string;
  fingerprint(): Fingerprint | null;
  sendRstStream(streamId: number, code: 'refused' | 'cancelled' | number): void;
  goaway(code?: 'overloaded' | number): void;
  destroy(code?: 'overloaded' | number): void;
  /** QUIC only: this connection's options (see README "One connection's"). */
  setOptions?(options: QuicConnectionOptions & { carefulResume?: boolean }): this;
  getOptions?(): QuicConnectionOptions & { carefulResume?: boolean };
}

interface ServerStats {
  connections: { quic: number; tcp: number };
  handshakes: { quic: { completed: number; failed: number }; tcp: { completed: number; failed: number }; resumed: number };
  protocols: { h3: number; h2: number; 'http/1.1': number; other: number };
  earlyData: { accepted: number; rejected: number; tooEarly: number };
  closes: {
    quic: { sent: Record<string, number>; received: Record<string, number>; silent: number };
    h3: { sent: Record<string, number>; received: Record<string, number> };
    h2: { sent: Record<string, number>; received: Record<string, number> };
    http1: { sent: Record<string, number> };
  };
  streamResets: {
    h3: { sent: Record<string, number>; received: Record<string, number> };
    h2: { sent: Record<string, number>; received: Record<string, number> };
  };
  amplificationBlocked: number;
  internalErrors: number;
  since: number;
  uptime: number;
}

interface ConnectUdpTunnelStats {
  target: { host: string; port: number };
  address: string | null;
  port: number | null;
  httpVersion: string;
  state: 'pending' | 'open' | 'closed';
  transport: 'datagram' | 'capsule';
  openedAt: number | null;
  closedAt: number | null;
  durationMs: number | null;
  packetsFromClient: number;
  bytesFromClient: number;
  packetsToClient: number;
  bytesToClient: number;
  droppedFromClient: number;
  droppedToClient: number;
}

/** A CONNECT-UDP request, server side ('connectUdp'). */
interface ConnectUdpTunnel extends EventEmitter {
  readonly req: QuicoIncomingMessage;
  readonly target: { host: string; port: number };
  readonly state: 'pending' | 'open' | 'closed';
  readonly closeReason: 'client' | 'local' | 'idle' | 'aborted' | 'socket' | 'rejected' | null;
  readonly error: Error | null;
  readonly stats: ConnectUdpTunnelStats;
  accept(options?: {
    target?: { host: string; port: number };
    socket?: DgramSocket;
    relay?: boolean;
    headers?: Record<string, string | string[]>;
    allowPrivate?: boolean;
  }): void;
  reject(status: number, headers?: Record<string, string | string[]>): void;
  send(buf: Buffer | Uint8Array): boolean;
  close(): void;
  on(event: 'open', listener: () => void): this;
  on(event: 'message', listener: (msg: Buffer) => void): this;
  on(event: 'close', listener: (stats: ConnectUdpTunnelStats) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

interface QuicoServer extends EventEmitter {
  listen(port?: number, callback?: () => void): this;
  listen(port: number, host: string, callback?: () => void): this;
  /** As node:http's: requests in flight finish (HTTP/2, HTTP/3: GOAWAY), idle connections close now; then 'close'. */
  close(callback?: (err?: Error) => void): this;
  /** Connections with no request in flight, all versions. */
  closeIdleConnections(): void;
  /** Every connection, in flight or not (not HTTP/1.1 sockets handed to 'upgrade'). */
  closeAllConnections(): void;
  getConnections(callback: (err: Error | null, count: number) => void): this;
  readonly listening: boolean;
  headersTimeout: number;
  requestTimeout: number;
  /** HTTP/1.1. */
  keepAliveTimeout: number;
  /** HTTP/1.1. */
  maxHeadersCount: number;
  maxRequestsPerSocket: number;
  ref(): this;
  unref(): this;
  [Symbol.asyncDispose](): Promise<void>;
  /** node:tls's: the default certificate, from the next handshake on — all three versions. Throws on a bad one (the old stays). */
  setSecureContext(options: { key?: PemInput | PemInput[]; cert?: PemInput | PemInput[]; ca?: PemInput; passphrase?: string } | ReturnType<typeof createSecureContext>): void;
  /** node:tls's: a certificate for a name (SNI; '*.example.com' covers one label). */
  addContext(hostname: string, context: { key?: PemInput | PemInput[]; cert?: PemInput | PemInput[]; ca?: PemInput; passphrase?: string } | ReturnType<typeof createSecureContext>): void;
  address(): { address: string; family: string; port: number } | null;
  handleConnection(socket: NetSocket): void;
  setTimeout(msecs?: number, callback?: (socket: NetSocket) => void): this;
  timeout: number;
  /** External socket mode: feed a UDP datagram. */
  handlePacket(msg: Buffer, rinfo: RemoteInfo): void;
  /** External socket mode: whether a datagram belongs to a connection of this server. */
  hasConnection(rinfo: RemoteInfo, msg?: Buffer): boolean;
  addProtocol(name: string, handler: (socket: Duplex, protocol: string) => void, options?: { sniff?: (firstBytes: Buffer) => boolean | null }): this;
  getTicketKeys(): Buffer;
  setTicketKeys(keys: Buffer): void;
  getEchKeys(): { keys: EchKey[] } | null;
  setEchKeys(ech: { keys: EchKey[] }): void;
  getValidateAddress(): boolean;
  setValidateAddress(on: boolean): void;
  getResetTokenSecret(): Buffer;
  setResetTokenSecret(secret: Buffer): void;
  getTokenSecret(): Buffer;
  setTokenSecret(secret: Buffer): void;
  setOptions(options: Partial<ServerOptions>): this;
  getOptions(): ServerOptions;
  getPendingHandshakes(): number;
  getStats(): ServerStats;
  getConnectUdpStats(): { active: number; accepted: number; rejected: number; closed: number; [counter: string]: number };

  on(event: 'request', listener: RequestHandler): this;
  on(event: 'upgrade', listener: (req: QuicoIncomingMessage, socket: Duplex, head: Buffer) => void): this;
  on(event: 'connectUdp', listener: (req: QuicoIncomingMessage, tunnel: ConnectUdpTunnel) => void): this;
  on(event: 'timeout', listener: (socket: NetSocket) => void): this;
  on(event: 'connection', listener: (conn: NetSocket | ConnectionHandle) => void): this;
  on(event: 'secureConnection', listener: (conn: NetSocket | ConnectionHandle) => void): this;
  on(event: 'stream_open', listener: (conn: ConnectionHandle, streamId: number) => void): this;
  on(event: 'stream_reset', listener: (conn: ConnectionHandle, streamId: number, code: number) => void): this;
  on(event: 'handshakeLoad', listener: (info: { pending: number; high: boolean }) => void): this;
  on(event: 'OCSPRequest', listener: (certificate: Buffer, issuer: Buffer | null, callback: (err: Error | null, response: Buffer | null) => void) => void): this;
  on(event: 'tlsClientError', listener: (err: Error, socket: NetSocket | ConnectionHandle) => void): this;
  on(event: 'clientError', listener: (err: Error, socket: NetSocket) => void): this;
  on(event: 'sessionError', listener: (err: Error, session: ConnectionHandle) => void): this;
  on(event: 'listening', listener: () => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

// ============================================================
//  Request, response
// ============================================================

/** A request on the server, or a response on the client (node:http's). */
interface QuicoIncomingMessage extends NodeIncomingMessage {
  /** '3.0', '2.0' or '1.1'. */
  httpVersion: string;
  /** Server: true if it came in 0-RTT. Client: 'accepted', 'rejected' or null. */
  earlyData: boolean | 'accepted' | 'rejected' | null;
  /** HTTP/2 request's fingerprint. */
  h2Fingerprint?(): Fingerprint;
  /** HTTP/3 request's fingerprint. */
  h3Fingerprint?(): Fingerprint;

  // ---- WebTransport (server, after res.writeHead(200) on a session) ----
  /** The protocols the client offered (WT-Available-Protocols), in its order. */
  webTransportProtocols?: string[];
  /** The client's CLOSE_WEBTRANSPORT_SESSION, when it sent one. */
  closeInfo?: WebTransportCloseInfo;
  on(event: 'stream', listener: (stream: WebTransportNodeStream & Duplex) => void): this;
  on(event: 'unidirectionalStream', listener: (stream: WebTransportNodeStream & Readable) => void): this;
  on(event: 'datagram', listener: (data: Buffer) => void): this;
  on(event: 'draining', listener: () => void): this;
  on(event: 'aborted', listener: () => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

interface QuicoServerResponse extends NodeServerResponse {
  writeEarlyHints(hints: Record<string, string | string[]>, callback?: () => void): void;
  /** HTTP/2 and HTTP/3: the response's priority (RFC 9218). */
  setPriority(priority: Priority): void;

  // ---- WebTransport (after res.writeHead(200) on a session) ----
  /** true when queued, false when it cannot be sent at all. */
  sendDatagram?(data: Buffer | Uint8Array | string, options?: WebTransportSendOptions): boolean;
  maxDatagramSize?(): number;
  readonly datagrams?: WebTransportDatagramDuplexStream | null;
  getStats?(): Promise<WebTransportConnectionStats | null>;
  exportKeyingMaterial?(label: BufferSource, context: BufferSource, outputLength: number): Promise<Uint8Array>;
  /** null, without waitUntilAvailable, past the client's MAX_STREAMS. */
  createBidirectionalStream?(options?: WebTransportSendStreamOptions | null, callback?: (err: Error | null, stream?: WebTransportNodeStream & Duplex) => void): (WebTransportNodeStream & Duplex) | null;
  createUnidirectionalStream?(options?: WebTransportSendStreamOptions | null, callback?: (err: Error | null, stream?: WebTransportNodeStream & Writable) => void): (WebTransportNodeStream & Writable) | null;
  canOpenStream?(options?: { bidirectional?: boolean }): boolean;
  createSendGroup?(): WebTransportSendGroup;
  /** Before writeHead(200): the protocol chosen among req.webTransportProtocols. */
  setWebTransportProtocol?(name: string): void;
  closeSession?(code?: number, reason?: string): void;
  drainSession?(): void;
}

interface RequestOptions extends QuicConnectionOptions {
  protocol?: string;
  hostname?: string;
  host?: string;
  port?: number;
  path?: string;
  method?: string;
  headers?: Record<string, string | string[] | number>;
  priority?: Priority;
  ech?: Buffer | Uint8Array | string;
  echGrease?: boolean;
  ecdhCurve?: string;
  sigalgs?: string;
  rejectUnauthorized?: boolean;
  ca?: PemInput;
  key?: PemInput;
  cert?: PemInput;
  passphrase?: string;
  servername?: string;
  earlyData?: boolean;
  session?: Buffer;
  requestOCSP?: boolean;
  quicVersions?: QuicVersion[];
  agent?: Agent | false;
  http2?: boolean;
  http1?: boolean;
  h3Timeout?: number;
  timeout?: number;
}

interface QuicoClientRequest extends NodeClientRequest {
  /** The transport actually used: 'h3', 'h2' or 'https'. */
  protocol: string;
  setPriority(priority: Priority): void;
  on(event: 'response', listener: (res: QuicoIncomingMessage) => void): this;
  on(event: 'session', listener: (session: Buffer) => void): this;
  on(event: 'OCSPResponse', listener: (response: Buffer) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

// ============================================================
//  Agent
// ============================================================

interface AgentOptions {
  http2?: boolean;
  http1?: boolean;
  h3Timeout?: number;
  keepAlive?: boolean;
  keepAliveMsecs?: number;
  maxSockets?: number;
  maxFreeSockets?: number;
  timeout?: number;
  maxCachedSessions?: number;
  ecdhCurve?: string;
}

declare class Agent extends EventEmitter {
  constructor(options?: AgentOptions);
  getName(options?: RequestOptions): string;
  destroy(): void;
}

// ============================================================
//  WebTransport — the browser's API (W3C), and a Node-style one
// ============================================================

type WebTransportReliabilityMode = 'pending' | 'reliable-only' | 'supports-unreliable';
type WebTransportCongestionControl = 'default' | 'throughput' | 'low-latency';
type WebTransportErrorSource = 'stream' | 'session';

interface WebTransportHash {
  algorithm: string;
  value: BufferSource;
}

interface WebTransportCloseInfo {
  closeCode?: number;
  reason?: string;
}

interface WebTransportSendOptions {
  sendGroup?: WebTransportSendGroup | null;
  sendOrder?: number;
}

interface WebTransportSendStreamOptions extends WebTransportSendOptions {
  waitUntilAvailable?: boolean;
}

interface WebTransportDatagramStats {
  droppedIncoming: number;
  expiredIncoming: number;
  expiredOutgoing: number;
  lostOutgoing: number | null;
}

interface WebTransportConnectionStats {
  timestamp: number;
  /** The application's bytes: new stream data and datagram payloads (no framing, no retransmissions). */
  bytesSent: number | null;
  bytesSentOverhead: number | null;
  bytesAcknowledged: number | null;
  packetsSent: number | null;
  bytesLost: number | null;
  packetsLost: number | null;
  bytesReceived: number | null;
  packetsReceived: number | null;
  smoothedRtt: number | null;
  rttVariation: number | null;
  minRtt: number | null;
  /** Bits per second; null until measured. */
  estimatedSendRate: number | null;
  atSendCapacity: boolean | null;
  /** QUICO's: the congestion window, and the bytes in flight. */
  congestionWindow: number | null;
  bytesInFlight: number | null;
  datagrams: WebTransportDatagramStats;
}

interface WebTransportSendStreamStats {
  bytesWritten: number;
  bytesSent: number;
  bytesAcknowledged: number;
}

interface WebTransportReceiveStreamStats {
  bytesReceived: number;
  bytesRead: number;
}

interface WebTransportOptions extends QuicConnectionOptions {
  // ---- The browser's ----
  allowPooling?: boolean;
  requireUnreliable?: boolean;
  /** The browser's HeadersInit: a Headers, [name, value] pairs, or an object. */
  headers?: HeadersInit | Record<string, string | string[]>;
  serverCertificateHashes?: WebTransportHash[];
  congestionControl?: WebTransportCongestionControl;
  anticipatedConcurrentIncomingUnidirectionalStreams?: number | null;
  anticipatedConcurrentIncomingBidirectionalStreams?: number | null;
  protocols?: string[];
  datagramsReadableType?: 'bytes';
  // ---- Node's (as https.request / QUICO's WebSocket) ----
  /** Sent as Origin on the CONNECT (a browser sends its page's). */
  origin?: string;
  /** Verify the server's certificate (default true). */
  rejectUnauthorized?: boolean;
  ca?: PemInput;
  key?: PemInput;
  cert?: PemInput;
  passphrase?: string;
  /** A TLS session from an earlier 'session' event, to resume with. */
  session?: Buffer;
  transportParams?: TransportParams;
  quicVersions?: QuicVersion[];
  ech?: Buffer | Uint8Array | string;
  echGrease?: boolean;
  ecdhCurve?: string;
  sigalgs?: string;
}

/** The browser's WebTransportError: a DOMException named 'WebTransportError'. */
declare class WebTransportError extends DOMException {
  constructor(message?: string, options?: { source?: WebTransportErrorSource; streamErrorCode?: number | null });
  constructor(init: { message?: string; source?: WebTransportErrorSource; streamErrorCode?: number | null });
  readonly source: WebTransportErrorSource;
  readonly streamErrorCode: number | null;
  /** QUICO's Node code, where it gives one (e.g. 'ERR_WEBTRANSPORT_SESSION_LOST'), in place of DOMException's number. */
  readonly code: any;
  /** The QUIC close that lost the session, when the peer closed the connection. */
  readonly quicError?: { code: number; application: boolean; reason: string };
}

declare class WebTransportSendGroup {
  private constructor();
  getStats(): Promise<WebTransportSendStreamStats>;
}

declare class WebTransportWriter extends WritableStreamDefaultWriter<BufferSource> {
  private constructor();
  /** Sent only if all of it fits the flow-control window; otherwise rejects with an AbortError. */
  atomicWrite(chunk: BufferSource): Promise<void>;
  /** What was written so far reaches the peer even if the stream is aborted later (RESET_STREAM_AT). */
  commit(): void;
}

declare class WebTransportSendStream extends WritableStream<BufferSource> {
  private constructor();
  sendGroup: WebTransportSendGroup | null;
  sendOrder: number;
  getWriter(): WebTransportWriter;
  getStats(): Promise<WebTransportSendStreamStats>;
}

/** A byte stream: getReader({ mode: 'byob' }) works. */
declare class WebTransportReceiveStream extends ReadableStream<Uint8Array> {
  private constructor();
  getStats(): Promise<WebTransportReceiveStreamStats>;
}

/** What a stream also is in QUICO: a Node stream with these. */
interface WebTransportNodeStream {
  readonly id: number;
  readonly sessionId: number;
  readonly sendState: 'open' | 'finished' | 'committed' | 'reset' | 'stopped' | null;
  readonly recvState: 'open' | 'finished' | 'reset' | 'stopped' | null;
  readonly pending: boolean;
  readonly reliableResetSupported: boolean;
  readonly streamErrorCode: number | null;
  sendOrder: number;
  sendGroup: WebTransportSendGroup | null;
  resetStream(code?: number, options?: { reliableSize?: number }): boolean;
  stopSending(code?: number): void;
  getStats(): Promise<Partial<WebTransportSendStreamStats & WebTransportReceiveStreamStats>>;
  on(event: 'peerReset' | 'peerStopSending', listener: (code: number | null) => void): this;
  on(event: 'committed' | 'ready', listener: () => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

/**
 * The browser's WebTransportBidirectionalStream. In QUICO it is a Node
 * Duplex with the browser's .readable and .writable; instanceof recognises it.
 */
declare class WebTransportBidirectionalStream {
  private constructor();
  readonly readable: WebTransportReceiveStream;
  readonly writable: WebTransportSendStream;
}
type WebTransportBidirectionalNodeStream = WebTransportBidirectionalStream & WebTransportNodeStream & Duplex;

/** createUnidirectionalStream(): the browser's send stream, and Node's Writable on it. */
type WebTransportUnidirectionalNodeStream = WebTransportSendStream & {
  write(chunk: any, cb?: (err?: Error | null) => void): boolean;
  write(chunk: any, encoding: BufferEncoding, cb?: (err?: Error | null) => void): boolean;
  end(chunk?: any, cb?: () => void): void;
  destroy(err?: Error): void;
  resetStream(code?: number, options?: { reliableSize?: number }): boolean;
  readonly id: number;
  readonly sessionId: number;
  readonly sendState: 'open' | 'finished' | 'committed' | 'reset' | 'stopped';
  readonly pending: boolean;
  readonly writableLength: number;
  readonly writableNeedDrain: boolean;
  on(event: string | symbol, listener: (...args: any[]) => void): any;
  once(event: string | symbol, listener: (...args: any[]) => void): any;
};

declare class WebTransportDatagramsWritable extends WritableStream<BufferSource> {
  private constructor();
  sendGroup: WebTransportSendGroup | null;
  sendOrder: number;
}

declare class WebTransportDatagramDuplexStream {
  private constructor();
  createWritable(options?: WebTransportSendOptions): WebTransportDatagramsWritable;
  readonly readable: ReadableStream<Uint8Array>;
  readonly maxDatagramSize: number;
  /** ms; null (or 0 set) is none. */
  incomingMaxAge: number | null;
  outgoingMaxAge: number | null;
  incomingMaxBufferedDatagrams: number;
  outgoingMaxBufferedDatagrams: number;
  /** @deprecated The spec's earlier names: use createWritable() and …MaxBufferedDatagrams. */
  readonly writable: WebTransportDatagramsWritable;
  /** @deprecated Use incomingMaxBufferedDatagrams. */
  incomingHighWaterMark: number;
  /** @deprecated Use outgoingMaxBufferedDatagrams. */
  outgoingHighWaterMark: number;
}

declare class WebTransport extends EventEmitter {
  constructor(url: string | URL, options?: WebTransportOptions);

  // ---- The browser's ----
  readonly ready: Promise<void>;
  readonly closed: Promise<WebTransportCloseInfo>;
  readonly draining: Promise<void>;
  readonly reliability: WebTransportReliabilityMode;
  readonly congestionControl: WebTransportCongestionControl;
  readonly protocol: string;
  /** The server's answer to the CONNECT (immutable); null until ready. */
  readonly responseHeaders: Headers | null;
  anticipatedConcurrentIncomingUnidirectionalStreams: number | null;
  anticipatedConcurrentIncomingBidirectionalStreams: number | null;
  readonly datagrams: WebTransportDatagramDuplexStream;
  readonly incomingBidirectionalStreams: ReadableStream<WebTransportBidirectionalNodeStream>;
  readonly incomingUnidirectionalStreams: ReadableStream<WebTransportReceiveStream>;
  /** false: HTTP/3 only. */
  static readonly supportsReliableOnly: boolean;

  close(closeInfo?: WebTransportCloseInfo): void;
  getStats(): Promise<WebTransportConnectionStats>;
  exportKeyingMaterial(label: BufferSource, context: BufferSource, outputLength: number): Promise<Uint8Array>;
  createBidirectionalStream(options?: WebTransportSendStreamOptions): Promise<WebTransportBidirectionalNodeStream>;
  createUnidirectionalStream(options?: WebTransportSendStreamOptions): Promise<WebTransportUnidirectionalNodeStream>;
  createSendGroup(): WebTransportSendGroup;

  // ---- QUICO's, for Node code ----
  /** 'connecting', 'connected', 'closed' or 'failed'. */
  readonly state: 'connecting' | 'connected' | 'closed' | 'failed';
  readonly url: string;
  /** The server's CLOSE_WEBTRANSPORT_SESSION, or ours. */
  readonly closeInfo?: WebTransportCloseInfo;
  canOpenStream(options?: { bidirectional?: boolean }): boolean;
  /** true when queued, false when it cannot be sent at all. */
  sendDatagram(data: Buffer | Uint8Array | string, options?: WebTransportSendOptions): boolean;
  maxDatagramSize(): number;

  on(event: 'ready' | 'draining' | 'close', listener: () => void): this;
  on(event: 'stream', listener: (stream: WebTransportBidirectionalNodeStream) => void): this;
  on(event: 'unidirectionalStream', listener: (stream: WebTransportNodeStream & Readable) => void): this;
  on(event: 'datagram', listener: (data: Buffer) => void): this;
  on(event: 'session', listener: (session: Buffer) => void): this;
  on(event: 'error', listener: (err: WebTransportError) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

// ============================================================
//  WebSocket
// ============================================================

interface WebSocketClientOptions {
  origin?: string;
  headers?: Record<string, string | string[]>;
  ca?: PemInput;
  rejectUnauthorized?: boolean;
  maxPayload?: number;
  agent?: Agent;
  session?: Buffer;
}

/**
 * The ws package's listeners, beside the browser's addEventListener: they get
 * Node-style arguments ('message': (data, isBinary); 'close': (code, reason)).
 */
interface WebSocketNodeEvents<T> {
  on(event: 'message', listener: (this: T, data: Buffer, isBinary: boolean) => void): T;
  on(event: 'close', listener: (this: T, code: number, reason: Buffer) => void): T;
  on(event: 'ping' | 'pong', listener: (this: T, data: Buffer) => void): T;
  on(event: 'open', listener: (this: T) => void): T;
  on(event: 'error', listener: (this: T, err: Error) => void): T;
  on(event: 'session', listener: (this: T, session: Buffer) => void): T;
  on(event: string, listener: (this: T, ...args: any[]) => void): T;
  once(event: string, listener: (this: T, ...args: any[]) => void): T;
  addListener(event: string, listener: (this: T, ...args: any[]) => void): T;
  off(event: string, listener: (...args: any[]) => void): T;
  removeListener(event: string, listener: (...args: any[]) => void): T;
  removeAllListeners(event?: string): T;
  listenerCount(event: string): number;
  eventNames(): string[];
}

/** What a WebSocket has, client or server side: the browser's interface, ping() and onpong. */
interface WebSocketBase extends EventTarget {
  readonly CONNECTING: 0;
  readonly OPEN: 1;
  readonly CLOSING: 2;
  readonly CLOSED: 3;
  readonly url: string;
  readonly readyState: 0 | 1 | 2 | 3;
  readonly bufferedAmount: number;
  readonly protocol: string;
  readonly extensions: string;
  /** 'blob' (the browser's default) or 'arraybuffer'; 'nodebuffer' too. */
  binaryType: 'blob' | 'arraybuffer' | 'nodebuffer';
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  /** Not in the browser: the answer to ping(). */
  onpong: ((event: Event) => void) | null;
  /** options (the ws package's): binary forces a frame's type. */
  send(data: string | ArrayBufferLike | ArrayBufferView | Blob, options?: { binary?: boolean }): void;
  /** Not in the browser: a keepalive for a long-lived connection. */
  ping(data?: string | Buffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
}

/** The browser's WebSocket (WHATWG), with a third argument for Node's options. */
declare class WebSocket extends EventTarget implements WebSocketBase {
  /** protocols may also be an options bag, { protocols } (as WPT has it). */
  constructor(url: string | URL, protocols?: string | string[] | { protocols?: string | string[] }, options?: WebSocketClientOptions);
  static readonly CONNECTING: 0;
  static readonly OPEN: 1;
  static readonly CLOSING: 2;
  static readonly CLOSED: 3;
  readonly CONNECTING: 0;
  readonly OPEN: 1;
  readonly CLOSING: 2;
  readonly CLOSED: 3;
  readonly url: string;
  readonly readyState: 0 | 1 | 2 | 3;
  readonly bufferedAmount: number;
  readonly protocol: string;
  readonly extensions: string;
  binaryType: 'blob' | 'arraybuffer' | 'nodebuffer';
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onpong: ((event: Event) => void) | null;
  send(data: string | ArrayBufferLike | ArrayBufferView | Blob, options?: { binary?: boolean }): void;
  ping(data?: string | Buffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
}
interface WebSocket extends WebSocketNodeEvents<WebSocket> {}

interface WebSocketStreamOptions extends WebSocketClientOptions {
  protocols?: string[];
  signal?: AbortSignal;
}
interface WebSocketOpenInfo {
  /** One chunk per message: a string for text, a Uint8Array for binary. */
  readable: ReadableStream<string | Uint8Array>;
  /** An ArrayBuffer or a view goes as binary, anything else as text. */
  writable: WritableStream<string | BufferSource>;
  protocol: string;
  extensions: string;
}
interface WebSocketCloseInfo {
  closeCode?: number;
  reason?: string;
}

/**
 * EXPERIMENTAL — the browser's streams WebSocket (WICG explainer; Chrome has
 * it, not yet a standard). Backpressure both ways: an unread message pauses
 * the socket; write() resolves once the frame is sent.
 */
declare class WebSocketStream {
  constructor(url: string | URL, options?: WebSocketStreamOptions);
  readonly url: string;
  readonly opened: Promise<WebSocketOpenInfo>;
  readonly closed: Promise<{ closeCode: number; reason: string }>;
  close(closeInfo?: WebSocketCloseInfo): void;
}

/** The error of a WebSocketStream: a DOMException named 'WebSocketError'. */
declare class WebSocketError extends DOMException {
  constructor(message?: string, init?: WebSocketCloseInfo);
  readonly closeCode: number | null;
  readonly reason: string;
}

/** A connection a WebSocketServer accepted (or upgradeWebSocket made). */
interface ServerWebSocket extends WebSocketBase, WebSocketNodeEvents<ServerWebSocket> {}

interface UpgradeWebSocketOptions {
  origin?: string | string[] | ((origin: string, req: QuicoIncomingMessage) => boolean);
  verifyClient?: (req: QuicoIncomingMessage) => boolean | { code: number; message?: string; headers?: Record<string, string> };
  protocol?: string | ((offered: string[], req: QuicoIncomingMessage) => string | false | null | undefined);
  protocols?: string[];
  headers?: Record<string, string | string[]>;
  maxPayload?: number;
}

interface WebSocketServerOptions extends UpgradeWebSocketOptions {
  server?: QuicoServer;
  noServer?: boolean;
  path?: string;
  pingInterval?: number;
}

declare class WebSocketServer extends EventTarget {
  constructor(options: WebSocketServerOptions);
  readonly clients: Set<ServerWebSocket>;
  onconnection: ((event: Event & { socket?: ServerWebSocket; request?: QuicoIncomingMessage }) => void) | null;
  handleUpgrade(req: QuicoIncomingMessage, socket: Duplex, head: Buffer, cb: (ws: ServerWebSocket, req: QuicoIncomingMessage) => void): void;
  startAutoPing(intervalMs: number): void;
  stopAutoPing(): void;
  close(code?: number, reason?: string): void;
  on(event: 'connection', listener: (ws: ServerWebSocket, req: QuicoIncomingMessage) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
  once(event: string, listener: (...args: any[]) => void): this;
  off(event: string, listener: (...args: any[]) => void): this;
}

/** The socket, or null after answering the client itself (403, 401, …). */
declare function upgradeWebSocket(req: QuicoIncomingMessage, socket: Duplex, head: Buffer, options?: UpgradeWebSocketOptions): ServerWebSocket | null;

// ============================================================
//  CONNECT-UDP client
// ============================================================

interface ConnectUdpOptions extends QuicConnectionOptions {
  protocol?: 'auto' | 'h3' | 'h2' | 'http/1.1';
  h3Timeout?: number;
  fallback?: boolean;
  shareConnection?: boolean;
  headers?: Record<string, string | string[]>;
  ech?: Buffer | Uint8Array | string;
  echGrease?: boolean;
  ecdhCurve?: string;
  sigalgs?: string;
  template?: string;
  rejectUnauthorized?: boolean;
  ca?: PemInput;
  key?: PemInput;
  cert?: PemInput;
  passphrase?: string;
  servername?: string;
  quicVersions?: QuicVersion[];
  agent?: Agent | false;
  session?: Buffer;
}

interface UdpProxySocketStats {
  protocol: string | null;
  transport: 'datagram' | 'capsule' | null;
  target: { host: string; port: number };
  openedAt: number | null;
  closedAt: number | null;
  durationMs: number | null;
  packetsSent: number;
  bytesSent: number;
  packetsReceived: number;
  bytesReceived: number;
  dropped: number;
}

/** A UDP socket through a proxy, behaving as a connected dgram.Socket. */
interface UdpProxySocket extends EventEmitter {
  send(msg: string | Buffer | Uint8Array | ReadonlyArray<string | Buffer | Uint8Array>, callback?: (err: Error | null, bytes?: number) => void): void;
  send(msg: Buffer | Uint8Array, offset: number, length: number, callback?: (err: Error | null, bytes?: number) => void): void;
  close(callback?: () => void): void;
  remoteAddress(): { address: string; family: string; port: number };
  address(): { address: string; family: string; port: number };
  readonly maxPayloadSize: number;
  readonly protocol: 'h3' | 'h2' | 'http/1.1' | null;
  readonly statusCode: number | null;
  readonly responseHeaders: Record<string, string | string[]> | null;
  readonly closeReason: 'local' | 'proxy' | 'error' | null;
  readonly stats: UdpProxySocketStats;
  on(event: 'connect' | 'close', listener: () => void): this;
  on(event: 'message', listener: (msg: Buffer, rinfo: RemoteInfo) => void): this;
  on(event: 'error', listener: (err: Error & { code?: string; statusCode?: number; proxyStatus?: string }) => void): this;
  on(event: 'session', listener: (session: Buffer) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

declare function connectUdp(
  proxy: string | URL | { hostname: string; port?: number; template?: string },
  target: { host: string; port: number },
  options?: ConnectUdpOptions,
  callback?: () => void
): UdpProxySocket;
declare function connectUdp(
  proxy: string | URL | { hostname: string; port?: number; template?: string },
  target: { host: string; port: number },
  callback?: () => void
): UdpProxySocket;

// ============================================================
//  Fingerprinting
// ============================================================

declare function ja4h(req: NodeIncomingMessage): Fingerprint & { a: string; b: string; c: string; d: string };
declare function h2Fingerprint(observed: any): Fingerprint;
declare function h3Fingerprint(observed: any): Fingerprint;
declare function observeH2(...args: any[]): any;
declare function profileRequest(req: NodeIncomingMessage): {
  claimed: any;
  protocol: string;
  fingerprints: { ja4: string | null; ja4s: string | null; h2: string | null; h2raw: string | null; h3: string | null; h3raw: string | null };
  signals: any[];
  suspicion: number;
};

// ============================================================
//  TLS
// ============================================================

declare function createSecureContext(options: { key?: PemInput; cert?: PemInput; ca?: PemInput; passphrase?: string; [option: string]: any }): any;
declare function generateEchKey(options: { publicName: string; [option: string]: any }): {
  config: Uint8Array;
  privateKey: Uint8Array;
  configListBase64: string;
  [field: string]: any;
};

// ============================================================
//  Transport and protocol layers (see README "Protocol layers", "Low-level QUIC API")
// ============================================================

/** A QUIC connection (low-level API). */
interface QUICConnection extends EventEmitter {
  readonly state: 'idle' | 'handshaking' | 'connected' | 'closing' | 'draining' | 'closed';
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly earlyDataStatus: null | 'offered' | 'accepted' | 'rejected';
  readonly resetStreamAtSupported: boolean;
  readonly alpnProtocol: string | null;
  readonly servername: string | null;
  sendStream(id: number, data: Uint8Array | Buffer, fin?: boolean): void;
  whenStreamCommitted(id: number, cb: () => void): void;
  resetStream(id: number, code: number, reliableSize?: number): boolean;
  stopSending(id: number, code: number): void;
  sendDatagram(data: Uint8Array | Buffer, prio?: { urgency?: number; group?: object; order?: number } | null): boolean;
  setStreamPriority(id: number, priority: Priority & { group?: object; order?: number }, fromPeer?: boolean): boolean;
  getStreamPriority(id: number): (Priority & { group?: object; order?: number }) | null;
  canOpenStream(bidi: boolean): boolean;
  isReceiving(id: number): boolean;
  isEarlyStream(id: number): boolean;
  maxDatagramSize(): number;
  whenConfirmed(cb: () => void): void;
  close(errorCode?: number, reason?: string, application?: boolean): void;
  getCertificate(): any;
  getTicketInfo(): any;
  isSessionReused(): boolean;
  exportKeyingMaterial(length: number, label: string, context?: Uint8Array | null): Buffer | null;
  getStats(): Record<string, number | boolean | string | null>;
  on(event: 'stream', listener: (id: number, data: Uint8Array, fin: boolean) => void): this;
  on(event: 'stream_reset', listener: (id: number, code: number, finalSize: number) => void): this;
  on(event: 'stop_sending', listener: (id: number, code: number) => void): this;
  on(event: 'datagram', listener: (data: Uint8Array) => void): this;
  on(event: 'path', listener: (address: string, port: number) => void): this;
  /** The moment the connection is over for the application ('close' follows after the draining period). */
  on(event: 'closing', listener: (peerClose: { error: number; application: boolean; reason: string } | null) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

interface QuicServer extends EventEmitter {
  listen(port?: number, host?: string, callback?: () => void): this;
  close(callback?: () => void): void;
  handlePacket(msg: Buffer, rinfo: RemoteInfo): void;
  hasConnection(rinfo: RemoteInfo, msg?: Buffer): boolean;
  getPendingHandshakes(): number;
  setOptions(options: Record<string, any>): this;
  getOptions(): Record<string, any>;
  on(event: 'connection', listener: (quic: QUICConnection, peer: { address: string; port: number }) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
  [method: string]: any;
}

declare function createQuicServer(options: ServerOptions & { alpn?: string[]; [option: string]: any }): QuicServer;
declare function createQuicClientSocket(options: {
  remoteIp: string;
  remotePort: number;
  hostname?: string;
  alpn?: string | string[];
  ecdhCurve?: string;
  idleTimeout?: number;
  keepAlive?: boolean | number;
  onConnect?: (quic: QUICConnection, socket: DgramSocket) => void;
  onSocket?: (quic: QUICConnection, socket: DgramSocket) => void;
  onError?: (err: Error) => void;
  onClose?: () => void;
  [option: string]: any;
}): DgramSocket;
declare function createTcpListener(options: Record<string, any>): {
  register(alpn: string, handler: (socket: Duplex, protocol: string) => void, options?: { sniff?: (firstBytes: Buffer) => boolean | null }): void;
  listen(port: number, host?: string, callback?: () => void): void;
  [method: string]: any;
};

declare function createH1Server(options: ServerOptions, handler?: RequestHandler): any;
declare function createH2Server(options: ServerOptions, handler?: RequestHandler): any;
declare function createH3Server(options: ServerOptions, handler?: RequestHandler): any;
declare function h1Request(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
declare function h2Request(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
declare function h3Request(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;

// ============================================================
//  Main module
// ============================================================

declare function createServer(handler?: RequestHandler): QuicoServer;
declare function createServer(options: ServerOptions, handler?: RequestHandler): QuicoServer;

declare function request(url: string | URL, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
declare function request(url: string | URL, options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
declare function request(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;

declare function get(url: string | URL, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
declare function get(url: string | URL, options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
declare function get(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;

declare const globalAgent: Agent;

/** node:http's classes, as QUICO's request and response are made. */
declare const IncomingMessage: typeof NodeIncomingMessage;
declare const ServerResponse: typeof NodeServerResponse;
declare const ClientRequest: typeof NodeClientRequest;

declare const quico: {
  createServer: typeof createServer;
  request: typeof request;
  get: typeof get;
  Agent: typeof Agent;
  globalAgent: Agent;
  IncomingMessage: typeof NodeIncomingMessage;
  ServerResponse: typeof NodeServerResponse;
  ClientRequest: typeof NodeClientRequest;
  connectUdp: typeof connectUdp;
  createSecureContext: typeof createSecureContext;
  generateEchKey: typeof generateEchKey;
  WebTransport: typeof WebTransport;
  WebTransportError: typeof WebTransportError;
  WebTransportBidirectionalStream: typeof WebTransportBidirectionalStream;
  WebTransportReceiveStream: typeof WebTransportReceiveStream;
  WebTransportSendStream: typeof WebTransportSendStream;
  WebTransportWriter: typeof WebTransportWriter;
  WebTransportSendGroup: typeof WebTransportSendGroup;
  WebTransportDatagramsWritable: typeof WebTransportDatagramsWritable;
  WebTransportDatagramDuplexStream: typeof WebTransportDatagramDuplexStream;
  WebSocket: typeof WebSocket;
  WebSocketStream: typeof WebSocketStream;
  WebSocketError: typeof WebSocketError;
  WebSocketServer: typeof WebSocketServer;
  upgradeWebSocket: typeof upgradeWebSocket;
  ja4h: typeof ja4h;
  h2Fingerprint: typeof h2Fingerprint;
  h3Fingerprint: typeof h3Fingerprint;
  observeH2: typeof observeH2;
  profileRequest: typeof profileRequest;
  createQuicServer: typeof createQuicServer;
  createQuicClientSocket: typeof createQuicClientSocket;
  createTcpListener: typeof createTcpListener;
  createH1Server: typeof createH1Server;
  createH2Server: typeof createH2Server;
  createH3Server: typeof createH3Server;
  h1Request: typeof h1Request;
  h2Request: typeof h2Request;
  h3Request: typeof h3Request;
};

export default quico;
export {
  createServer, request, get, Agent, globalAgent,
  IncomingMessage, ServerResponse, ClientRequest,
  connectUdp, createSecureContext, generateEchKey,
  WebTransport, WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
  WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream,
  WebSocket, WebSocketStream, WebSocketError, WebSocketServer, upgradeWebSocket,
  ja4h, h2Fingerprint, h3Fingerprint, observeH2, profileRequest,
  createQuicServer, createQuicClientSocket, createTcpListener,
  createH1Server, createH2Server, createH3Server,
  h1Request, h2Request, h3Request
};
export type {
  ServerOptions, RequestOptions, RequestHandler, AgentOptions, Priority, TransportParams, StartupCap,
  QuicConnectionOptions, ConnectionOptionsInfo, ConnectionHandle, ServerStats, EchKey, Fingerprint,
  QuicoServer, QuicoIncomingMessage, QuicoServerResponse, QuicoClientRequest,
  ConnectUdpServerOptions, ConnectUdpTunnel, ConnectUdpTunnelStats, ConnectUdpOptions, UdpProxySocket, UdpProxySocketStats,
  WebTransportOptions, WebTransportHash, WebTransportCloseInfo, WebTransportSendOptions, WebTransportSendStreamOptions,
  WebTransportConnectionStats, WebTransportDatagramStats, WebTransportSendStreamStats, WebTransportReceiveStreamStats,
  WebTransportReliabilityMode, WebTransportCongestionControl, WebTransportErrorSource,
  WebTransportNodeStream, WebTransportBidirectionalNodeStream, WebTransportUnidirectionalNodeStream,
  WebSocketClientOptions, WebSocketStreamOptions, WebSocketOpenInfo, WebSocketCloseInfo, WebSocketServerOptions, UpgradeWebSocketOptions, ServerWebSocket,
  QUICConnection, QuicServer
};
