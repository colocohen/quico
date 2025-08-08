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

---

> **⚠️ Project status: _Active development_.**  
> APIs may change without notice until we reach v1.0.  
> Use at your own risk and please report issues!

## ✨ Features
- **Pure JS QUIC**: Initial & 1-RTT packets, connection ID management, ACK & flow-control.
- **TLS 1.3 handshake** in JavaScript (no OpenSSL binding).
- **HTTP/3** control stream, request/response, server push, GOAWAY.
- **WebTransport** streams & datagrams (RFC 9298) — tested with Chrome Canary.
- **QPACK** encoder/decoder with custom Huffman table support.
- Fully self-contained—no native addons, no external OpenSSL.

## 📦 Installation

```bash
npm install quico
```

## 🏃 Quick start

### Step 1: Generate a self-signed certificate

To test QUICO locally, you’ll need a TLS certificate.  
Generate one using OpenSSL:

```bash
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/localhost.key -out certs/localhost.crt -days 365
```

### Step 2: Create a basic HTTP/3 server

```js
const fs = require('fs');
const quico = require('quico');

const server = quico.createServer({
  SNICallback: function (servername, cb) {
    cb(null, {
      key: fs.readFileSync('certs/localhost.key'),
      cert: fs.readFileSync('certs/localhost.crt')
    });
  }
}, function (req, res) {
  const data = new TextEncoder().encode('Hello World from HTTP/3 on Node.js!');
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': data.byteLength
  });
  res.end(data);
});

server.listen(4433, function () {
  console.log('🚀 QUIC server running on https://localhost:4433');
});
```

> ✅ You must launch Chrome with `--enable-quic` and `--origin-to-force-quic-on=localhost:4433`  
> 📂 For more examples, see [`examples/`](./examples)

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