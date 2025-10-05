<p align="center">
  <img src="https://github.com/colocohen/quico/raw/main/quico.svg" width="450" alt="QUICO"/>
</p>

<h1 align="center">QUICO</h1>
<p align="center">
  <em>🚀 JavaScript implementation of QUIC, HTTP/3, QPACK & WebTransport for Node.js</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/quico">
    <img src="https://img.shields.io/npm/v/quico?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/quico?color=brightgreen" alt="license">
</p>


> **⚠️ Project status: _Active development_.**  
> APIs may change without notice until we reach v1.0.  
> Use at your own risk and please report issues!



## Table of Contents
1. [What is QUIC/HTTP3?](#-what-is-quichttp3)
2. [Why is QUICO important?](#-why-is-quico-important)
3. [Features](#-features)
4. [Installation](#-installation)
5. [Node.js API Compatibility](#-nodejs-api-compatibility)
6. [Testing](#-testing)
7. [Project Structure](#-project-structure)
8. [Roadmap](#-roadmap)
9. [Sponsors](#-sponsors)
10. [Contact](#-contact)
11. [License](#-license)



## ⚡ What is QUIC/HTTP3?

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



## Why is QUICO important?

Node.js is the backbone of countless modern web applications, but it currently lacks a native QUIC implementation. Supporting QUIC inside Node.js requires **deep access to TLS internals** that Node’s existing TLS APIs don’t expose. Beyond that, QUIC demands a **highly complex architecture**, including intricate state machines, packet schedulers, and congestion control mechanisms.  

**QUICO** brings this missing capability directly into the **Node.js ecosystem**. It is a from-scratch JavaScript implementation of **QUIC, HTTP/3 and WebTransport**, built without relying on OpenSSL or native code. At its core, it uses [LemonTLS](https://github.com/colocohen/lemon-tls) a pure JavaScript TLS 1.3 library, to provide the cryptographic expose that QUIC requires.  



## ✨ Features

- **Pure JavaScript QUIC**  
  Full transport layer written from scratch in JS — including Initial & 1-RTT packet handling, connection ID management, acknowledgments, and flow control. No native bindings required.  

- **HTTP/3**  
  Support for control streams, request/response handling, and GOAWAY frames — the foundation of modern web transport.  

- **WebTransport**  
  Unidirectional and bidirectional streams plus datagrams (RFC 9298), tested with Chrome Canary for real-world compatibility.  

- **QPACK Compression**  
  Full encoder/decoder implementation with support for static, dynamic, and custom Huffman tables to reduce header overhead.  

> ⚠️ **Note**: Currently implemented as **server-side only**. Client support is planned in the roadmap.



## 📦 Installation

```bash
npm install quico
```



## 🔗 Node.js API Compatibility

One of the core design goals of QUICO is to provide a **familiar and intuitive API**.  
If you already know how to use Node’s built-in `http` or `https` modules, working with QUICO should feel natural.

QUICO exposes an API modeled after Node’s server interfaces:
- **`createServer`** works just like in `http` / `https`, accepting request and response objects.
- **`req` and `res` objects** follow the same semantics you already know: `req.headers`, `res.writeHead()`, `res.end()`, etc.


```js
import fs from 'node:fs';
import quico from 'quico';
import tls from 'lemon-tls';

const server = quico.createServer({
  SNICallback: function (servername, cb) {
    cb(null, tls.createSecureContext({
      key: fs.readFileSync('YOUR_KEY_FILE_PATH'),
      cert: fs.readFileSync('YOUR_CERT_FILE_PATH')
    }));
  }
}, function (req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8'
  });
  res.end('Hello World from HTTP/3 on Node.js!');
});

server.listen(4433, function () {
  console.log('🚀 QUIC server running on https://localhost:4433');
});
```

> 📂 For more examples, see [`examples/`](./examples)


## 🧪 Testing

QUIC requires TLS 1.3 with an ECDSA certificate.
RSA self-signed certificates usually fail with QUIC/HTTP3.
For local development the easiest option is [mkcert](https://github.com/FiloSottile/mkcert),
which generates locally trusted ECDSA certificates automatically.

This project supports ALPN `"h3"` only
(final version, not draft variants like `h3-29` or `h3-32`).
You must explicitly force h3 when testing.

> ✅ Launch Chrome with:
> `--enable-quic --quic-version=h3 --ignore-certificate-errors --origin-to-force-quic-on=localhost:4433`
>
> ✅ Or test with Curl:
> `curl --http3 -vvv --trace-time --trace-ascii - https://localhost:4433 --insecure`



## 📁 Project Structure

Quico follows a layered design:

- `quic_socket.js` – Core QUIC transport layer
- `h3_socket.js` – h3 built on top of QUIC
- `h3_server.js` – HTTP/3 and WebTransport Server implementation
- `examples/` – Practical usage examples and demos

➡️ For a full technical breakdown, see [ARCHITECTURE.md](./ARCHITECTURE.md).



## 🛣 Roadmap

The following roadmap reflects the current and planned status of the QUICO project.  
✅ = Completed 🔄 = In progress ⏳ = Planned ❌ = Not planned

### ✅ Completed
| Status | Item |
|:------:|------|
| ✅ | QUIC: Initial / Handshake / 1-RTT |
| ✅ | TLS 1.3 handshake & key schedule |
| ✅ | HTTP/3: control streams & basic requests |
| ✅ | QPACK: static & dynamic table |

### 🔄 In Progress
| Status | Item | Notes |
|:------:|------|-------|
| 🔄 | QPACK: Huffman encoding/decoding | Custom table support partially working |
| 🔄 | WebTransport: unidirectional & bidirectional streams | Stream interface WIP |
| 🔄 | HTTP/3: GOAWAY & request cancellation | Partial control flow support |
| 🔄 | Integration with Node.js `https`-style API | Goal: seamless compatibility |
| 🔄 | Project modularization & internal refactoring | To improve maintainability |

### ⏳ Planned
| Status | Item | Notes |
|:------:|------|-------|
| ⏳ | QUIC: 0-RTT support | Will follow key update & early data support |
| ⏳ | WebTransport: datagram support | Based on RFC 9298 |
| ⏳ | QUIC: proper connection teardown | CLOSE frame, idle timeout |
| ⏳ | QUIC: keep-alive & PING frames | For long-lived connections |
| ⏳ | QUIC: flow control & congestion (BBR / CUBIC) | Needs metrics and simulation |
| ⏳ | QUIC: session resumption & connection migration | For mobile/roaming support |
| ⏳ | End-to-end test suite against Chromium | Automate using testh3 and Puppeteer |
| ⏳ | Benchmarks, performance analysis & tuning | Resource usage, latency, throughput |
| ⏳ | Fuzz testing and protocol robustness checks | To improve security and reliability |
| ⏳ | Developer documentation & API reference | For better onboarding |
| ⏳ | TypeScript typings | Type safety for IDE support |

_Note: QUICO is a work-in-progress project aiming to provide a full JavaScript implementation of QUIC + HTTP/3. Community contributions are welcome!_

_Please ⭐ star the repo to follow progress!_



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