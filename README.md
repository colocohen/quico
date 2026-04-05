<p align="center">
  <img src="https://github.com/colocohen/quico/raw/main/quico.svg" width="450" alt="QUICO"/>
</p>

<h1 align="center">QUICO</h1>
<p align="center">
  <em>Pure JavaScript implementation of QUIC, HTTP/3, QPACK &amp; WebTransport for Node.js</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/quico">
    <img src="https://img.shields.io/npm/v/quico?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/quico?color=brightgreen" alt="license">
</p>

---

> **⚠️ Project status: Active development.**
> APIs may change before v1.0. Use at your own risk and please report issues!

---


## Table of Contents
1. [What is QUIC / HTTP/3?](#-what-is-quic--http3)
2. [Why QUICO?](#-why-quico)
3. [Quick Start](#-quick-start)
4. [Features](#-features)
5. [Node.js API Compatibility](#-nodejs-api-compatibility)
6. [WebTransport](#-webtransport)
7. [Testing](#-testing)
8. [Project Structure](#-project-structure)
9. [Roadmap](#-roadmap)
10. [Sponsors](#-sponsors)
11. [Contact](#-contact)
12. [License](#-license)


## ⚡ What is QUIC / HTTP/3?

**QUIC** is the future of Internet transport protocols. Created at Google and standardized by the IETF, QUIC powers **HTTP/3** and is already deployed at scale by the world’s largest platforms. It was specifically designed to overcome the limitations of TCP and deliver a faster, smoother, and more resilient web.

Key advantages of QUIC include:

- **Eliminating bottlenecks**: With TCP, data must arrive strictly in order. If a single packet is lost or delayed, all subsequent packets are blocked until it arrives — a phenomenon called **head-of-line blocking**. QUIC removes this bottleneck by running over UDP, so each package arrives on its own and avoids dependence on delayed pieces of data.

- **UDP efficiency**: By running over UDP, QUIC bypasses decades of kernel-level constraints, enabling lightning-fast performance even on constrained devices such as smartphones, IoT hardware, or edge gateways.

- **Security by default**: TLS 1.3 is built directly into the protocol. Every connection is encrypted — no exceptions, no downgrade paths.

- **Seamless mobility**: Connections remain stable as devices move across networks (e.g., Wi-Fi → 4G/5G) or switch IP addresses, without breaking the session.

- **Lower latency**: QUIC merges the transport and TLS handshake into fewer round-trips, significantly reducing connection setup time.

- **Smarter congestion control**: Advanced congestion control algorithms (such as BBR) continuously measure bandwidth, round-trip time, and loss in real time. They dynamically adjust to real-world network conditions.


QUIC combines **UDP speed, TCP reliability, mandatory TLS security, and adaptive multiplexing** into one powerful transport layer.

**HTTP/3** (h3 in short) is the layer on top of QUIC. This is the evolution of the web’s application layer. Instead of riding over TCP, HTTP/3 maps HTTP requests and responses directly onto QUIC streams.
HTTP/3 is also himself dramatically reduces overhead and improves efficiency - thats bring faster page loads and real-time applications that scale across the modern web.



## 🧠 Why QUICO?

Node.js is the backbone of countless modern web applications, but it currently lacks a native QUIC implementation. Supporting QUIC inside Node.js requires **deep access to TLS internals** that Node's existing TLS APIs don't expose. Beyond that, QUIC demands a **highly complex architecture** — intricate state machines, packet schedulers, and congestion control mechanisms.

**QUICO** brings this missing capability directly into the **Node.js ecosystem**. It is a from-scratch JavaScript implementation of QUIC, HTTP/3 and WebTransport, built without relying on OpenSSL or native code. At its core, it uses [LemonTLS](https://github.com/colocohen/lemon-tls) — a pure JavaScript TLS 1.3 library built by the same author — to provide the cryptographic layer that QUIC requires. Together, QUICO and LemonTLS form a complete, fully auditable JavaScript networking stack from UDP to HTTP/3.

**What this means for you:**

- **`npm install` and go** — no build tools, no platform-specific binaries, no gyp
- **Works everywhere Node.js runs** — Linux, macOS, Windows, ARM, Docker, edge
- **Debuggable top to bottom** — every packet, every frame, every byte is JavaScript you can step through


## 📦 Quick Start

```bash
npm install quico
```

### Server

```js
import quico from 'quico';
import fs from 'node:fs';

const server = quico.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt')
}, (req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('Hello from HTTP/3!');
});

server.listen(4433, () => {
  console.log('HTTP/3 server on https://localhost:4433');
});
```

### Client

```js
import quico from 'quico';

quico.request('https://www.google.com/', (res) => {
  console.log('Status:', res.statusCode);       // 200
  console.log('Protocol:', res.httpVersion);     // "3.0"
  res.on('data', (chunk) => process.stdout.write(chunk));
});
```

> 📂 For more examples, see [`examples/`](./examples)


## ✨ Features

### HTTP/3 Server & Client
- Full request/response cycle over QUIC
- QPACK header compression with static and dynamic tables
- Standard Node.js API: `req.headers`, `res.writeHead()`, `res.end()`
- Multiple requests per connection (stream multiplexing)
- Automatic `Alt-Svc` header for HTTP/3 protocol discovery
- H3 → H2 → H1 fallback when QUIC isn't available
- Tested against Google, Cloudflare, Facebook, Microsoft and nginx QUIC servers

### WebTransport
- Client and server implementation
- Bidirectional and unidirectional streams (Node.js Duplex + WHATWG Streams API)
- Unreliable datagrams (RFC 9297)
- Natural API: `req.on('stream')`, `res.sendDatagram()`, `res.writeHead(200)` to accept

### QUIC Transport
- Full TLS 1.3 handshake via LemonTLS (no OpenSSL)
- Initial, Handshake, and 1-RTT packet handling
- Connection ID management
- ACK processing and flow control
- Key updates (key phase bit rotation)
- HelloRetryRequest support (P-256, P-384, X25519)
- AES-128-GCM and AES-256-GCM cipher suites
- Handshake timeout


## 🔗 Node.js API Compatibility

One of the core design goals of QUICO is to provide a **familiar API**. If you already know `node:https`, working with QUICO should feel natural — `createServer`, `request`, `req`, `res` all work the same way.

This means existing frameworks work out of the box:

```js
import express from 'express';
import quico from 'quico';

const app = express();
app.get('/', (req, res) => res.json({ protocol: req.httpVersion }));

quico.createServer({ key: KEY, cert: CERT }, app).listen(4433);
// → { "protocol": "3.0" }
```

For multi-domain setups, QUICO supports `SNICallback` just like `node:https`:

```js
import quico from 'quico';
import tls from 'lemon-tls';

const server = quico.createServer({
  SNICallback: function (servername, cb) {
    cb(null, tls.createSecureContext({
      key: fs.readFileSync('certs/' + servername + '.key'),
      cert: fs.readFileSync('certs/' + servername + '.crt')
    }));
  }
}, (req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end('Hello World from HTTP/3 on Node.js!');
});

server.listen(4433, () => {
  console.log('🚀 QUIC server running on https://localhost:4433');
});
```


## 🚀 WebTransport

### Server

```js
import quico from 'quico';

quico.createServer({ key: KEY, cert: CERT }, (req, res) => {
  if (req.headers[':protocol'] === 'webtransport') {
    // Accept the WebTransport session
    res.writeHead(200);

    // Bidirectional streams from the client
    req.on('stream', (stream) => {
      stream.on('data', (chunk) => {
        stream.write(chunk); // echo back
      });
      stream.on('end', () => stream.end());
    });

    // Unreliable datagrams
    req.on('datagram', (data) => {
      res.sendDatagram(data); // echo back
    });

    // Server can also create streams
    const push = res.createBidirectionalStream();
    push.write('server says hello');
    push.end();
  } else {
    // Regular HTTP/3 request
    res.end('Hello HTTP/3!');
  }
}).listen(4433);
```

### Client (Node.js)

```js
import { WebTransport } from 'quico';

const wt = new WebTransport('https://localhost:4433/echo');
await wt.ready;

// Bidirectional stream
const stream = await wt.createBidirectionalStream();
stream.write('hello');
stream.on('data', (chunk) => console.log('echo:', chunk.toString()));
stream.end();

// Unidirectional stream
const uni = await wt.createUnidirectionalStream();
uni.write('fire and forget');
uni.end();

// Datagrams (unreliable)
wt.sendDatagram(Buffer.from('ping'));
wt.on('datagram', (data) => console.log('pong:', data.toString()));

wt.close();
```

### Client (Browser)

```js
const wt = new WebTransport('https://yourserver.com:4433/live');
await wt.ready;

// Send via WHATWG Streams API
const writer = wt.datagrams.writable.getWriter();
await writer.write(new TextEncoder().encode('Hello QUIC'));

// Receive
const reader = wt.datagrams.readable.getReader();
const { value } = await reader.read();
console.log('Received:', new TextDecoder().decode(value));
```


## 🧪 Testing

QUIC requires TLS 1.3. Self-signed RSA certificates usually fail with QUIC clients and browsers. For local development, [mkcert](https://github.com/FiloSottile/mkcert) is the easiest option — it generates locally-trusted ECDSA certificates automatically.

This project supports ALPN `"h3"` only (not draft variants like `h3-29`). You must explicitly force h3 when testing with Chrome.

**Chrome:**
```bash
chrome --enable-quic --quic-version=h3 --ignore-certificate-errors --origin-to-force-quic-on=localhost:4433
```

**curl:**
```bash
curl --http3 https://localhost:4433 --insecure
```

**Integration tests:**
```bash
node examples/test_integration.js          # HTTP/3 client + server — 19 tests
node examples/test_wt_server.js            # WebTransport server echo (QUICO ↔ QUICO)
node examples/test_webtransport.js URL     # WebTransport client against any server
```


## 📁 Project Structure

```
quico/
├── index.js               — Public API exports
└── src/
    ├── server.js            — Unified server (drop-in for node:https)
    ├── client.js            — Unified client with H3 → H2 → H1 fallback
    ├── agent.js             — Connection pooling and Alt-Svc protocol cache
    ├── streams.js           — IncomingMessage, ServerResponse, ClientRequest
    ├── h3.js                — HTTP/3 framing, QPACK, WebTransport detection
    ├── h3_server.js         — HTTP/3 + WebTransport server
    ├── h3_client.js         — HTTP/3 client (DNS, UDP, QUIC, H3 pipeline)
    ├── quic_connection.js   — QUIC state machine, burst scheduler, flow control
    ├── transport.js         — Packet parsing, frame encoding/decoding
    ├── crypto.js            — AEAD encryption, header protection, key derivation
    ├── tls_bridge.js        — LemonTLS integration, transport parameters
    └── webtransport.js      — WebTransport client + stream classes
```


## 🛣 Roadmap

### ✅ Done
- QUIC v1 transport (RFC 9000) — Initial, Handshake, 1-RTT
- TLS 1.3 via LemonTLS — X25519, P-256, P-384, AES-128/256-GCM
- HTTP/3 server and client (RFC 9114)
- QPACK header compression with static and dynamic tables (RFC 9204)
- WebTransport client and server — bidi/uni streams + datagrams (RFC 9297)
- Node.js `https`-style API compatibility — `createServer`, `request`, `get`
- Express / Fastify / Koa middleware support
- Connection reuse and multiplexing
- HelloRetryRequest — client and server
- Key updates (key phase rotation)
- Interop with Google, Cloudflare, Facebook, Microsoft, nginx
- Handshake timeout

### 🔄 In Progress
- Loss detection and PTO timers (RFC 9002)
- Congestion control (BBR / CUBIC)
- 0-RTT and session resumption
- Debug log cleanup (`QUICO_DEBUG` environment flag)

### ⏳ Planned
- Connection migration (PATH_CHALLENGE / PATH_RESPONSE)
- ChaCha20-Poly1305 cipher suite (0x1303)
- GOAWAY and graceful shutdown
- Stream priority (RFC 9218)
- TypeScript type definitions
- Performance benchmarks
- Fuzz testing

_Community contributions are welcome! Please ⭐ star the repo to follow progress._


## 🙏 Sponsors

QUICO is an evenings-and-weekends project.  
Support development via **GitHub Sponsors** or simply share the project.



## 💬 Contact

For feedback, ideas, or contributions,  
contact directly at:  
📧 **support@quicojs.dev**

For security-related issues, please see [SECURITY.md](./SECURITY.md).



## 📜 License

**Apache License 2.0**

```
Copyright © 2025 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```