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

import { createServer } from './src/server.js';
import { request, get } from './src/client.js';
import { Agent, globalAgent } from './src/agent.js';
import { IncomingMessage, ServerResponse, ClientRequest } from './src/streams.js';
import { createSecureContext } from './src/tls_bridge.js';
import { WebTransport } from './src/webtransport.js';

export {
  createServer,
  request,
  get,
  Agent,
  globalAgent,
  IncomingMessage,
  ServerResponse,
  ClientRequest,
  createSecureContext,
  WebTransport
};

export default {
  createServer,
  request,
  get,
  Agent,
  globalAgent,
  IncomingMessage,
  ServerResponse,
  ClientRequest,
  createSecureContext,
  WebTransport
};
