/*
 * quico — TypeScript declarations
 * Pure JavaScript QUIC, HTTP/3, QPACK & WebTransport for Node.js
 */

/// <reference types="node" />

import { IncomingMessage, ServerResponse } from 'node:http';
import { Duplex, Readable, Writable } from 'node:stream';
import { EventEmitter } from 'node:events';

// ============================================================
//  Server
// ============================================================

type RequestHandler = (req: QuicoIncomingMessage, res: QuicoServerResponse) => void;

interface ServerOptions {
  key?: string | Buffer;
  cert?: string | Buffer;
  ca?: string | Buffer;
  SNICallback?: (servername: string, cb: (err: Error | null, ctx: any) => void) => void;
  maxConnections?: number;
}

interface QuicoServer extends EventEmitter {
  listen(port: number, callback?: () => void): this;
  listen(port: number, host: string, callback?: () => void): this;
  close(callback?: () => void): void;
  on(event: 'request', listener: RequestHandler): this;
  on(event: 'listening', listener: () => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

interface QuicoIncomingMessage extends IncomingMessage {
  /** QUIC stream ID */
  streamId?: number;

  // WebTransport events (available after res.writeHead(200) on WT sessions)
  on(event: 'stream', listener: (stream: Duplex) => void): this;
  on(event: 'unidirectionalStream', listener: (stream: Readable) => void): this;
  on(event: 'datagram', listener: (data: Buffer) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

interface QuicoServerResponse extends ServerResponse {
  // WebTransport methods (available after res.writeHead(200) on WT sessions)
  sendDatagram?(data: Buffer | Uint8Array | string): void;
  createBidirectionalStream?(): Duplex;
  createUnidirectionalStream?(): Writable;
}


// ============================================================
//  Client
// ============================================================

interface RequestOptions {
  hostname?: string;
  host?: string;
  port?: number;
  path?: string;
  method?: string;
  headers?: Record<string, string | string[]>;
  agent?: QuicoAgent;
  rejectUnauthorized?: boolean;
  timeout?: number;
}

interface QuicoClientRequest extends Writable {
  on(event: 'response', listener: (res: QuicoIncomingMessage) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'timeout', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
  end(data?: string | Buffer): this;
  abort(): void;
  setTimeout(ms: number, callback?: () => void): this;
}


// ============================================================
//  Agent
// ============================================================

interface QuicoAgent {
  destroy(): void;
}


// ============================================================
//  WebTransport
// ============================================================

interface WebTransportOptions {
  /** Skip certificate verification (default: true for self-signed) */
  rejectUnauthorized?: boolean;
}

declare class WebTransport extends EventEmitter {
  constructor(url: string, options?: WebTransportOptions);

  /** Resolves when the WebTransport session is established */
  readonly ready: Promise<void>;
  /** Current state: 'connecting' | 'connected' | 'closed' */
  readonly state: string;
  /** The URL of the WebTransport session */
  readonly url: string;

  /** WHATWG-style datagram interface */
  readonly datagrams: {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
  };

  /** Create a bidirectional stream (Node.js Duplex + WHATWG .readable/.writable) */
  createBidirectionalStream(): Promise<Duplex & {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
  }>;

  /** Create a unidirectional stream for writing */
  createUnidirectionalStream(): Promise<Writable>;

  /** Send an unreliable datagram */
  sendDatagram(data: Buffer | Uint8Array): void;

  /** Close the WebTransport session */
  close(info?: { closeCode?: number; reason?: string }): void;

  on(event: 'datagram', listener: (data: Buffer) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}


// ============================================================
//  Main module
// ============================================================

declare const quico: {
  createServer(options: ServerOptions, handler?: RequestHandler): QuicoServer;

  request(url: string | URL, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
  request(url: string | URL, options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
  request(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;

  get(url: string | URL, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
  get(url: string | URL, options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;
  get(options: RequestOptions, callback?: (res: QuicoIncomingMessage) => void): QuicoClientRequest;

  globalAgent: QuicoAgent;
};

export default quico;
export { WebTransport };
export { QuicoServer, QuicoIncomingMessage, QuicoServerResponse, QuicoClientRequest, QuicoAgent };
export { ServerOptions, RequestOptions, RequestHandler, WebTransportOptions };
