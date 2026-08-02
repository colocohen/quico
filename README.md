<p align="center">
  <img src="https://github.com/colocohen/quico/raw/main/quico.svg" width="450" alt="QUICO"/>
</p>

<h1 align="center">QUICO</h1>
<p align="center">
  <em>Pure JavaScript implementation of QUIC, HTTP/3, QPACK &amp; WebTransport for Node.js</em>
</p>

<p align="center">
  <strong>The entire HTTP/3 stack — QUIC, TLS 1.3, QPACK, congestion control — in JavaScript you can read.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/quico">
    <img src="https://img.shields.io/npm/v/quico?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow" alt="status">
  <img src="https://img.shields.io/badge/interop-6%2F6%20implementations-brightgreen" alt="interop">
  <img src="https://img.shields.io/github/license/colocohen/quico?color=brightgreen" alt="license">
</p>

---

> **⚠️ Project status: Beta — active development.**
> The core transport is verified against six independent QUIC implementations
> (see [Interoperability](#-interoperability)), but APIs may still change before
> v1.0. Please report issues!

---

## Table of Contents

1. [What is QUIC / HTTP/3?](#-what-is-quic--http3)
2. [Why QUICO?](#-why-quico)
3. [Requirements & Installation](#-requirements--installation)
4. [Quick Start](#-quick-start)
5. [Features](#-features)
6. [Design Choices](#-design-choices)
   - [The send model: range reconciliation](#the-send-model-range-reconciliation-not-retransmission)
   - [Congestion control](#congestion-control-bbr-style-not-loss-based)
   - [Stream scheduling](#stream-scheduling-byte-level-round-robin)
   - [Loss detection](#loss-detection-timers-and-how-we-treat-late-acks)
   - [Flow control](#flow-control-consumption-based-windows)
7. [Interoperability](#-interoperability)
8. [API Reference](#-api-reference)
   - [`createServer()`](#quicocreateserveroptions-requestlistener)
   - [`request()` / `get()`](#quicorequesturl-options-callback)
   - [`IncomingMessage`](#incomingmessage) · [`ServerResponse`](#serverresponse) · [`ClientRequest`](#clientrequest)
   - [`Agent`](#agent) · [`createSecureContext()`](#quicocreatesecurecontextoptions)
   - [Framework compatibility](#framework-compatibility)
   - [WebTransport](#webtransport)
   - [Low-level QUIC API](#low-level-quic-api)
9. [Configuration & Tuning](#-configuration--tuning)
10. [Debugging](#-debugging)
11. [Testing](#-testing)
12. [Project Structure](#-project-structure)
13. [Known Limitations](#-known-limitations)
14. [Roadmap](#-roadmap)
15. [Contributing](#-contributing)
16. [Sponsors](#-sponsors)
17. [Contact](#-contact)
18. [License](#-license)

---

## ⚡ What is QUIC / HTTP/3?

**QUIC is the future of Internet transport protocols.** Created at Google,
standardized by the IETF as [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), QUIC
powers **HTTP/3** and is already deployed at scale by the world's largest platforms.
It was specifically designed to overcome the limitations of TCP and deliver a faster,
smoother, and more resilient web.

Key advantages of QUIC include:

- **Eliminating bottlenecks** — With TCP, data must arrive strictly in order. If a
  single packet is lost or delayed, *all* subsequent packets are blocked until it
  arrives — a phenomenon called **head-of-line blocking**. QUIC removes this
  bottleneck by running over UDP and multiplexing independent streams: each stream
  makes progress on its own, and a loss on one never stalls the others.

- **UDP efficiency** — By running over UDP, QUIC bypasses decades of kernel-level TCP
  constraints, enabling fast connection handling even on constrained devices such as
  smartphones, IoT hardware, or edge gateways.

- **Security by default** — TLS 1.3 is built directly into the protocol. Every
  connection is encrypted — no exceptions, no downgrade paths. Even the packet
  headers are cryptographically protected.

- **Seamless mobility** — Connections are identified by connection IDs rather than
  IP/port 4-tuples, so a session can survive a device moving across networks
  (Wi-Fi → 4G/5G) or changing addresses.

- **Lower latency** — QUIC merges the transport and TLS handshakes into a single
  exchange, significantly reducing connection setup time.

- **Smarter congestion control** — Modern algorithms such as BBR continuously measure
  bandwidth and round-trip time instead of only reacting to loss, adapting to
  real-world network conditions in real time.

QUIC combines **UDP speed, TCP reliability, mandatory TLS security, and adaptive
multiplexing** into one transport layer.

**HTTP/3** ([RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)) is the layer on top:
the evolution of the web's application protocol. Instead of riding over TCP, HTTP/3
maps requests and responses directly onto QUIC streams, with
[QPACK](https://www.rfc-editor.org/rfc/rfc9204) header compression designed to avoid
reintroducing head-of-line blocking. The result: faster page loads and real-time
applications that scale across the modern web.

---

## 🧠 Why QUICO?

Node.js is the backbone of countless modern web applications — yet it has **no native
QUIC implementation**. The browser you're reading this in speaks HTTP/3. The CDN that
served this page speaks HTTP/3. Your Node server? Stuck on TCP.

Why? Supporting QUIC inside Node.js requires **deep access to TLS internals** that
Node's existing TLS APIs simply don't expose. TLS-over-TCP hands you an encrypted
*byte stream*; QUIC needs something entirely different — the raw **handshake secrets**
at each encryption level, so it can derive its own packet-protection keys and encrypt
each packet individually. `node:tls` was never built to hand those out. Beyond the
crypto, QUIC demands a genuinely complex architecture: interlocking state machines
across three packet-number spaces, a packet scheduler with pacing, loss detection
timers, and congestion control.

**QUICO brings this missing capability directly into the Node.js ecosystem.** It is a
from-scratch JavaScript implementation of QUIC, HTTP/3 and WebTransport, built without
OpenSSL and without a single line of native code. The cryptographic layer is
[LemonTLS](https://github.com/colocohen/lemon-tls) — a pure JavaScript TLS 1.3 library
built by the same author specifically to expose what QUIC needs. Together, QUICO and
LemonTLS form a complete, fully auditable JavaScript networking stack from the UDP
socket all the way up to HTTP/3.

No build tools. No platform-specific binaries. No node-gyp. It runs anywhere Node runs
— Linux, macOS, Windows, ARM, Docker, edge — and when something breaks at 3 AM, the
stack trace ends in code you can open, not in a `.node` binary.

---

## 📋 Requirements & Installation

| Requirement | Notes |
|---|---|
| **Node.js 18+** | ESM only (`import`). Tested on 18, 20 and 22. |
| **No compiler** | Pure JavaScript — no native addons. |

```bash
npm install quico
```

QUICO is an **ES module**. Use `import`, and make sure your `package.json` has
`"type": "module"` (or use the `.mjs` extension).

---

## 📦 Quick Start

### Server

```js
import quico from 'quico';
import fs from 'node:fs';

const server = quico.createServer({
  key:  fs.readFileSync('server.key'),
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
  console.log('Status:',   res.statusCode);   // 200
  console.log('Protocol:', res.httpVersion);  // "3.0"
  res.on('data', (chunk) => process.stdout.write(chunk));
}).end();
```

> ⚠️ Don't forget `.end()` — like `node:https`, the request isn't sent until you call it.

> 📂 More examples in [`examples/`](./examples)

---


## ✨ Features

### HTTP/3 Server & Client
- Full request/response cycle over QUIC (RFC 9114)
- QPACK header compression, static and dynamic tables (RFC 9204)
- Node.js-compatible API: `req.headers`, `res.writeHead()`, `res.end()`
- Stream multiplexing — many concurrent requests on one connection
- Connection pooling and coalescing: concurrent requests to the same origin share
  a single QUIC connection
- Automatic `Alt-Svc` advertisement for HTTP/3 discovery
- Automatic H3 → H2 → H1.1 fallback when QUIC is unavailable

### QUIC Transport
- QUIC v1 (RFC 9000) — Initial, Handshake and 1-RTT packet spaces
- TLS 1.3 handshake via LemonTLS, no OpenSSL (RFC 9001)
- Version Negotiation (RFC 9000 §6)
- HelloRetryRequest — X25519, P-256, P-384
- AES-128-GCM and AES-256-GCM
- Key Update — bidirectional key phase rotation (RFC 9001 §6)
- Connection ID management and packet coalescing
- Stream and connection-level flow control with sliding windows
- Loss detection with PTO and exponential backoff (RFC 9002)
- BBR-style congestion control with pacing
- Unreliable datagrams (RFC 9221)
- Stateless reset, idle timeout, keep-alive
- TLS keylog export for Wireshark decryption

### WebTransport
- Client and server (RFC 9297 + draft-ietf-webtrans-http3)
- Bidirectional and unidirectional streams (Node.js Duplex API)
- Unreliable datagrams
- Natural API: `req.on('stream')`, `res.sendDatagram()`, `res.writeHead(200)` to accept

---

## 🧬 Design Choices

Two QUIC implementations can both be fully conformant and still behave completely
differently on the wire. RFC 9000 defines *what* must happen; it deliberately leaves
*how* to the implementer. This section documents where QUICO made a choice — the
places where another implementation would reasonably do something else.

### The send model: range reconciliation, not retransmission

This is the foundational choice, and the one that most distinguishes QUICO from other
implementations.

**How it's normally done.** RFC 9002 describes tracking each packet you send along
with the frames it contained. When loss detection fires, you look up that packet,
recover its frames, and put them back in a retransmission queue. The sender is
*procedural*: an event happens (loss), and you perform a corrective action
(re-enqueue). Almost every QUIC stack works this way.

**What QUICO does instead.** There is no `sent_packets` table, no stored frame copies,
and no retransmission queue — those concepts don't exist in the codebase. Each stream
keeps only three things:

```js
{
  pending_data:     Uint8Array,     // the bytes the application wrote
  acked_ranges:     [from, to, …],  // byte ranges the peer has confirmed
  in_flight_ranges: { 47: [from, to], 48: [from, to] }   // packet number → bytes it carries
}
```

Every send opportunity asks one question, and it's a set operation:

```js
missing = invert(acked_ranges ∪ in_flight_ranges, 0, total_size)
```

Whatever's missing goes out. That's the whole algorithm. The sender doesn't remember
what it *did* — it recomputes what the peer *still needs*, from scratch, every time.
It's a declarative model: continuously reconcile "what the peer has" against "what the
peer should have", and emit the difference.

**Loss detection, therefore, is one line:**

```js
delete st.in_flight_ranges[pn];   // → those bytes are "missing" again
```

Deleting the mapping is the entire recovery action. Nothing is queued, scheduled, or
flagged. The bytes simply reappear in the next `missing` computation and get sent
along with everything else.

**The consequence: a packet is a disposable container, not an identity.** The data
that was in lost packet #47 doesn't come back *as* packet #47's contents. It comes
back as *bytes that need sending*, and the next burst may:

- **re-slice them differently** — the chunk boundaries depend on that burst's byte
  budget, so a lost 1200-byte range might go out as 400 bytes appended to one packet
  and 800 in the next;
- **coalesce them with new data** from the same stream, in a single STREAM frame;
- **pack them alongside other streams'** data in the same packet, via the round-robin
  scheduler below.

Packet numbers and stream byte-offsets are fully decoupled: PNs are transient
bookkeeping for the loss timer, while the byte range is the only durable identity of
data. This is possible because QUIC frames carry explicit offsets — the receiver
reassembles by offset and genuinely does not care how the bytes were packetized.

**Why this design:**

- **State can't drift.** A retransmission queue is mutable state maintained
  incrementally, and every incremental structure can desynchronize from reality —
  entries duplicated, entries dropped, a range acked while a stale copy still sits in
  the queue. Range arithmetic derives the truth fresh each pass, so a byte range can
  neither be forgotten nor sent twice by bookkeeping error.
- **Recovery is free.** No priority juggling between "retransmit queue" and "new data
  queue"; repairs and new data are the same thing, drawn from one computation and
  paced by the same congestion controller.
- **Late information is harmless.** An ACK arriving after the loss timer already fired
  isn't a contradiction to reconcile — it just adds a range to `acked_ranges`, and the
  next pass naturally stops sending those bytes.

**What it costs.** Computing `invert(acked ∪ in_flight)` per stream per send
opportunity is O(number of ranges) work, where a queue pop would be O(1). With
coalesced flat range arrays this stays cheap in practice, but it is real CPU that a
queue-based sender doesn't spend — a deliberate trade of cycles for correctness.

**The receive side is symmetric.** Incoming data goes into `chunks` keyed by offset
plus a `ranges` array, and delivery walks the contiguous prefix. Same range algebra,
mirrored — which is exactly why the receiver must tolerate chunks whose boundaries
don't line up with anything it saw before: on the sending side, they never had to.

### Congestion control: BBR-style, not loss-based

**The choice:** most QUIC stacks ship a loss-based controller — quic-go uses Reno with
HyStart++, others default to CUBIC. QUICO implements a **model-based controller in the
BBRv1 family** instead.

The difference is philosophical. Loss-based algorithms grow the window until packets
drop, which means they *require* queue overflow to find the limit — and they misread
random wireless loss as congestion. BBR builds an explicit model of the path and
steers by it:

```
BDP = BtlBw × RTprop
```

- **BtlBw** (bottleneck bandwidth) — a **windowed maximum** of per-round delivery rate
  over the last 10 rounds. Sampling happens once per round-trip, not per ACK: under
  ACK aggregation, per-ACK samples spike and a windowed-max latches onto the spike.
- **RTprop** (round-trip propagation) — a **windowed minimum** of RTT over 10 seconds,
  so queue-induced inflation decays out of the model.

Three states drive the two output knobs:

| State | Pacing gain | Purpose |
|---|---|---|
| `startup` | 2.89 (≈ 2/ln 2) | Exponential ramp to discover BtlBw. Exits after 3 rounds without ≥25% growth — the pipe is full. |
| `drain` | 1/2.89 | One phase to drain the queue startup necessarily built. |
| `probe_bw` | `[1.25, 0.75, 1, 1, 1, 1, 1, 1]` | Steady state: probe for more bandwidth, then yield to drain what the probe queued. |

The **pacing rate** (`gain × BtlBw`) spreads packets smoothly rather than dumping
window-sized bursts into the bottleneck; the **congestion window** (`cwnd_gain × BDP`)
is the in-flight backstop. Both are clamped to floors and ceilings so a single bad
measurement can never wedge the connection.

Watch it live, one line per round-trip:

```bash
QUICO_DEBUG_BBR=1 node yourserver.js
```
```
[bbr] round=5  startup  BtlBw=8.96Mbps  RTprop=16ms BDP=17920B → cwnd=51789B pace=25.89Mbps
[bbr] round=9  drain    BtlBw=10.98Mbps RTprop=16ms BDP=21952B → cwnd=63441B pace=3.80Mbps
[bbr] round=15 probe_bw BtlBw=10.98Mbps RTprop=16ms BDP=21952B → cwnd=27440B pace=10.98Mbps
```

That trace is a real run through a 10 Mbps bottleneck with a 25-packet queue: startup
finds the link in ~7 rounds, drain empties the queue, probe_bw settles within 5% of
line rate.

**Honest scope:** this is BBR-*style*, not a certified BBRv2. ProbeRTT — the periodic
cwnd collapse that re-measures RTprop on a permanently saturated path — is not
implemented, and there is no explicit loss response. The windowed filters bound the
damage of stale measurements in the meantime.

### Stream scheduling: byte-level round-robin

**The choice:** when several streams have data ready and one packet is going out, who
gets the space? Implementations differ sharply — many drain streams in priority or
creation order, filling each one before moving on.

QUICO interleaves at the **byte level, inside a single packet**
([`execute_quic_burst`](./src/quic_connection.js)). The scheduler cycles through all
active streams, taking a chunk from each until the packet is full, then cycles again —
so a 1350-byte packet routinely carries STREAM frames from three different streams:

```
┌─────────────────────────────── one QUIC packet ───────────────────────────────┐
│ ACK │ STREAM(id=0, 450B) │ STREAM(id=4, 450B) │ STREAM(id=8, 400B) │
└───────────────────────────────────────────────────────────────────────────────┘
```

The loop repeats while any stream still yields data and space remains (`progress`
flag), so a stream that runs dry doesn't hold a slot — the remaining bandwidth
redistributes to the others within the same packet.

**Why it matters:** three parallel downloads progress at genuinely equal rates instead
of finishing sequentially, and no stream can be starved by a large one ahead of it.
The cost is fragmentation — more STREAM frame headers per packet (~24 bytes each) than
a drain-one-stream-at-a-time scheduler. QUICO accepts that trade for fairness.
Priority signalling (RFC 9218) would let applications override the equal split; it's
on the roadmap.

**The subtle part** falls straight out of the reconciliation model: the sender decides
what to send by asking which bytes aren't acked or in flight — but chunks selected
*earlier in the same burst* have no packet number yet, so they're in neither set, and
the next iteration would select them again. QUICO parks them under a temporary
`_burst` key in the in-flight map, which real packet-number keys replace the moment
the packet is encrypted and sent. The set arithmetic stays honest even mid-burst.

### Within a stream: new data leads, gaps follow

Given the `missing` set, in what order do you drain it? QUICO walks it in two passes:
forward from the send cursor first (new data), then backfilling the gaps below it
(bytes whose packets were lost).

New data leads because it keeps the pipe full and the ACK clock running — the receiver
buffers out-of-order bytes anyway, and the gap gets repaired within the same burst
rather than a round-trip later. Both passes read from the same `missing` computation,
so there's no ordering conflict to arbitrate: it's one set, drained in two sweeps.

**Flow control interacts here in a non-obvious way.** Send-side limits cap the
*highest offset* we may send, so they bind only **new** bytes. A repair re-sends
offsets that were already inside the allowance when first sent — it consumes no budget
and must never be blocked. Getting this wrong deadlocks the connection: at the edge of
an exhausted window, the missing range itself becomes unsendable, and the peer can't
rescue you, because the data it would open the window for is exactly the data that
never arrived.

### Loss detection: timers, and how we treat late ACKs

Because recovery itself is just the reconciliation pass, loss "detection" here means
only one thing: deciding when to stop counting a packet's bytes as in flight. Two
decisions worth calling out:

- **Late ACKs are honoured, not discarded.** When the timer expires a packet, its
  stream ranges are parked in a *limbo* table rather than forgotten. If the ACK then
  arrives late — routine on a queued path — the bytes are credited to the delivery
  rate model, the pending retransmission is cancelled, and the loss counter is
  corrected. QUIC never reuses packet numbers, so unlike TCP there's no
  retransmission ambiguity: a late ACK is *unambiguous evidence* the data arrived, and
  discarding it distorts BtlBw exactly when the model needs accuracy most.
- **RTT samples are taken from those packets too** — same reasoning, plus a subtle
  failure mode it prevents: a too-short timer expires packets before their ACKs land,
  and if those ACKs are then barred from producing RTT samples, the timer never learns
  that it's too short. The loop is self-sealing. Accepting the sample breaks it.

The PTO itself is `srtt + max(4·rttvar, 1ms) + max_ack_delay`. That last term is not
optional: peers may legitimately sit on an ACK for their full advertised delay (25 ms
is common), and a timer without it expires packets moments before their ACKs arrive.

**ACK ranges are capped at 32** (RFC 9000 §13.2.4 permits acking a subset). Under
loss, packet-number gaps never close — a lost PN is gone forever, its data returns
under a new PN — so an uncapped ACK frame grows with the cumulative loss count until
it no longer fits in a packet. We measured exactly that against a line-rate sender:
ACK packets inflating 325 B → 1017 B second by second, until they crossed the MTU and
stopped being sendable at all.

### Flow control: consumption-based windows

**The choice:** when do you tell the peer it may send more? The naive trigger is
"bytes arrived"; QUICO slides its receive windows based on **application
consumption** — a `MAX_STREAM_DATA` / `MAX_DATA` update goes out once the app has
actually *read* a threshold of data, not merely when packets landed.

The difference shows up under backpressure: a slow consumer causes the window to stop
advancing, which slows the sender, instead of letting unbounded data accumulate in the
receive buffer. Node stream semantics (`write()` return values, `highWaterMark`)
propagate through H3 into these windows, so ordinary `.pipe()` backpressure reaches
all the way to the peer's congestion controller.

### Reading the source

Files map one-to-one onto protocol layers (see
[Project Structure](#-project-structure)), state lives in plain objects you can
`console.log`, and the dense parts carry comments explaining *why*, not just what.
Start at [`src/quic_connection.js`](./src/quic_connection.js) and follow a packet in
from `feedDatagram()` or out from `sendStream()`.

---

## 🔬 Interoperability

Everything above is a claim; this section is the receipt.

QUICO is tested with the [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner),
the standard cross-implementation test harness. Every test runs both directions
(QUICO as server *and* as client) through a network simulator with configurable
delay, bandwidth limits and packet loss.

| Peer implementation | Language | `handshake` | `transfer` | `http3` |
|---|---|:---:|:---:|:---:|
| [quic-go](https://github.com/quic-go/quic-go) | Go | ✅ | ✅ | ✅ |
| [ngtcp2](https://github.com/ngtcp2/ngtcp2) | C | ✅ | ✅ | ✅ |
| [quiche](https://github.com/cloudflare/quiche) (Cloudflare) | Rust | ✅ | ✅ | ✅ |
| [picoquic](https://github.com/private-octopus/picoquic) | C | ✅ | ✅ | ✅ |
| [aioquic](https://github.com/aiortc/aioquic) | Python | ✅ | ✅ | ✅ |
| [neqo](https://github.com/mozilla/neqo) (Firefox) | Rust | ✅ | ✅ | ✅ |

- **handshake** — TLS 1.3 handshake over QUIC completes
- **transfer** — 10 MB across multiple concurrent streams, through a 10 Mbps
  bottleneck with a shallow queue (i.e. with real packet loss)
- **http3** — three concurrent HTTP/3 requests, which must share **one** QUIC
  connection

Additionally verified against production servers: **Google**, **Cloudflare**,
**Facebook**, **Microsoft**, **LiteSpeed** and **nginx** — including a 12.7 MB
download from `cloudflaremirrors.com` byte-for-byte.

---

## 📚 API Reference

QUICO mirrors the `node:https` API wherever possible. If a method or property is not
documented here, it likely behaves exactly as its `node:https` counterpart.

This chapter covers the HTTP/3 API first, then framework compatibility, WebTransport,
and finally the low-level QUIC primitives for non-HTTP protocols.

### `quico.createServer([options][, requestListener])`

Creates an HTTP/3 server. Returns a server object with `listen()`, `close()` and
`on()`.

**Options**

| Option | Type | Default | Description |
|---|---|---|---|
| `key` | `Buffer \| string` | — | Private key in PEM format. Required unless `SNICallback` is used. |
| `cert` | `Buffer \| string` | — | Certificate chain in PEM format. |
| `ca` | `Buffer \| string \| Array` | `null` | Additional trusted CAs. |
| `SNICallback` | `Function` | `null` | `(servername, cb) => cb(null, secureContext)` for multi-domain setups. |
| `http2` | `boolean` | `true` | Also listen for HTTP/2 over TCP (fallback for non-QUIC clients). |
| `http1` | `boolean` | `true` | Also listen for HTTP/1.1 over TCP. |
| `maxConnections` | `number` | `10000` | Maximum concurrent QUIC connections. |
| `socket` | `dgram.Socket` | `null` | Use an externally-bound IPv4 UDP socket instead of creating one. Must already be bound. |
| `socket6` | `dgram.Socket` | `null` | Same, for IPv6. |

Setting `http2: false` and `http1: false` makes the server **HTTP/3 only** — no TCP
listener is opened.

**Methods**

- `server.listen(port[, host][, callback])` — start listening. Binds UDP (and TCP
  unless both fallbacks are disabled).
- `server.close([callback])` — stop listening and close all connections.

**Events**

- `'request'` — `(req, res)` — same as the `requestListener` argument
- `'listening'`
- `'error'` — `(err)`

```js
const server = quico.createServer({ key, cert, http2: false, http1: false });

server.on('request', (req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ url: req.url, version: req.httpVersion }));
});

server.listen(4433, '0.0.0.0');
```

---

### `quico.request(url|options[, options], callback)`

Issues an HTTP/3 request. Returns a [`ClientRequest`](#clientrequest). Accepts a URL
string, an options object, or both (options override the URL).

**Options**

| Option | Type | Default | Description |
|---|---|---|---|
| `hostname` / `host` | `string` | `'localhost'` | Target host. |
| `port` | `number` | `443` | Target port. |
| `path` | `string` | `'/'` | Request path including query string. |
| `method` | `string` | `'GET'` | HTTP method. |
| `headers` | `object` | `{}` | Request headers. |
| `rejectUnauthorized` | `boolean` | `true` | Verify the server certificate. Set `false` for self-signed certs. |
| `ca` | `Buffer \| string \| Array` | `null` | Trust these CAs in addition to the defaults. |
| `agent` | `Agent \| false` | `globalAgent` | Connection pool to use. `false` disables pooling. |
| `http2` | `boolean` | `true` | Allow HTTP/2 fallback. |
| `http1` | `boolean` | `true` | Allow HTTP/1.1 fallback. |
| `h3Timeout` | `number` | `3000` | Milliseconds to wait for QUIC before falling back. |

```js
const req = quico.request({
  hostname: 'localhost',
  port: 4433,
  path: '/api/items',
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  rejectUnauthorized: false     // self-signed cert in development
}, (res) => {
  let body = '';
  res.on('data', (c) => body += c);
  res.on('end', () => console.log(res.statusCode, body));
});

req.on('error', console.error);
req.write(JSON.stringify({ name: 'test' }));
req.end();
```

### `quico.get(url|options[, options], callback)`

Same as `request()` with `method: 'GET'`, and `end()` is called automatically.

---

### `IncomingMessage`

A Node.js `Readable` stream. On the server it is the request; on the client, the
response.

| Property | Description |
|---|---|
| `httpVersion` | `'3.0'`, `'2.0'` or `'1.1'` depending on the transport actually used |
| `headers` | Lower-cased header object |
| `method` | Request method (server side) |
| `url` | Request path (server side) |
| `statusCode` | Response status (client side) |
| `socket` / `connection` | Compatibility shim for frameworks |

Standard `Readable` behaviour applies: `'data'`, `'end'`, `'error'`, `pipe()`,
`for await (const chunk of req)`, and `setTimeout(ms, cb)`.

---

### `ServerResponse`

A Node.js `Writable` stream.

- `res.writeHead(statusCode[, statusMessage][, headers])`
- `res.setHeader(name, value)` / `getHeader` / `getHeaders` / `getHeaderNames` /
  `hasHeader` / `removeHeader`
- `res.flushHeaders()`
- `res.write(chunk)` / `res.end([chunk])`
- `res.statusCode`, `res.headersSent`

For WebTransport sessions, `ServerResponse` additionally exposes
`sendDatagram()`, `createBidirectionalStream()` and `createUnidirectionalStream()` —
see [WebTransport](#-webtransport).

---

### `ClientRequest`

A Node.js `Writable` stream.

- `req.write(chunk)` / `req.end([chunk])`
- `req.abort()` / `req.destroy()`
- `req.protocol` — which transport was actually used: `'h3'`, `'h2'` or `'https'`
- Events: `'response'`, `'error'`

---

### `Agent`

Connection pool and protocol cache, analogous to `https.Agent`.

```js
import { Agent } from 'quico';

const agent = new Agent({
  http2: true,        // allow H2 in the fallback chain
  http1: true,        // allow H1.1 in the fallback chain
  h3Timeout: 3000,    // ms before falling back from H3
  maxSockets: 256,
  timeout: 30000
});

quico.request({ hostname: 'example.com', agent }, handler).end();
```

The agent caches which protocol works per host (including `Alt-Svc` advertisements
with their `ma=` lifetime), pools live QUIC connections for multiplexing, and
coalesces concurrent requests to the same origin onto a single connection.

`quico.globalAgent` is the default instance used when no `agent` option is given.
Call `agent.destroy()` to close all pooled connections.

---

### `quico.createSecureContext(options)`

Creates a TLS context for use with `SNICallback`. Accepts `key`, `cert` and `ca`.
Re-exported from LemonTLS.

---

### Framework compatibility

A core design goal is a **familiar API**. If you know `node:https`, QUICO should feel
natural — which means existing frameworks work unmodified:

```js
import express from 'express';
import quico from 'quico';

const app = express();
app.get('/', (req, res) => res.json({ protocol: req.httpVersion }));

quico.createServer({ key: KEY, cert: CERT }, app).listen(4433);
// → { "protocol": "3.0" }
```

Express, Fastify and Koa are all supported this way.

Multi-domain setups use `SNICallback`, exactly as in `node:https`:

```js
import quico from 'quico';
import tls from 'lemon-tls';
import fs from 'node:fs';

const server = quico.createServer({
  SNICallback: (servername, cb) => {
    cb(null, tls.createSecureContext({
      key:  fs.readFileSync(`certs/${servername}.key`),
      cert: fs.readFileSync(`certs/${servername}.crt`)
    }));
  }
}, (req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end('Hello World from HTTP/3 on Node.js!');
});

server.listen(4433);
```

---

### WebTransport

#### Server

```js
import quico from 'quico';

quico.createServer({ key: KEY, cert: CERT }, (req, res) => {
  if (req.headers[':protocol'] === 'webtransport') {
    res.writeHead(200);                    // accept the session

    req.on('stream', (stream) => {         // client-initiated streams
      stream.on('data', (chunk) => stream.write(chunk));  // echo
      stream.on('end', () => stream.end());
    });

    req.on('datagram', (data) => res.sendDatagram(data));

    const push = res.createBidirectionalStream();  // server-initiated
    push.write('server says hello');
    push.end();
  } else {
    res.end('Hello HTTP/3!');
  }
}).listen(4433);
```

#### Client (Node.js)

```js
import { WebTransport } from 'quico';

const wt = new WebTransport('https://localhost:4433/echo');
await wt.ready;

const stream = await wt.createBidirectionalStream();
stream.write('hello');
stream.on('data', (chunk) => console.log('echo:', chunk.toString()));
stream.end();

const uni = await wt.createUnidirectionalStream();
uni.write('fire and forget');
uni.end();

wt.sendDatagram(Buffer.from('ping'));
wt.on('datagram', (data) => console.log('pong:', data.toString()));

wt.close();
```

#### Client (Browser)

A QUICO server works with the **native browser WebTransport API** — no client library
needed:

```js
const wt = new WebTransport('https://yourserver.com:4433/live');
await wt.ready;

const writer = wt.datagrams.writable.getWriter();
await writer.write(new TextEncoder().encode('Hello QUIC'));

const reader = wt.datagrams.readable.getReader();
const { value } = await reader.read();
console.log('Received:', new TextDecoder().decode(value));
```

---

### Low-level QUIC API

For non-HTTP protocols over QUIC, or full control of the connection.

#### `createQuicServer(options)`

| Option | Type | Default | Description |
|---|---|---|---|
| `key`, `cert`, `ca` | | — | TLS credentials |
| `SNICallback` | `Function` | `null` | Per-hostname contexts |
| `alpn` | `string[]` | `['h3']` | ALPN protocols to accept |
| `maxConnections` | `number` | `10000` | Connection cap |
| `socket` / `socket6` | `dgram.Socket` | `null` | External, already-bound UDP sockets |

Returns `{ listen, close, on, handlePacket, hasConnection }`. The `'connection'`
event fires with `(quicConnection, peer)`.

```js
import { createQuicServer } from 'quico';

const qs = createQuicServer({ key, cert, alpn: ['my-protocol'] });

qs.on('connection', (quic, peer) => {
  console.log('connection from', peer.address, peer.port);

  quic.on('stream', (streamId, data, fin) => {
    if (fin) quic.sendStream(streamId, Buffer.from('bye'), true);
  });

  quic.on('datagram', (data) => quic.sendDatagram(data));
});

qs.listen(4433);
```

`handlePacket(msg, rinfo)` and `hasConnection(rinfo)` support **external socket
mode**, where QUICO shares a UDP port with another protocol (STUN/TURN, for example)
and you route datagrams yourself.

#### `QUICConnection`

| Member | Description |
|---|---|
| `quic.state` | `'idle'`, `'handshaking'`, `'connected'`, `'closing'`, `'draining'`, `'closed'` |
| `quic.sendStream(id, data, fin)` | Write to a stream |
| `quic.sendDatagram(data)` | Send an unreliable datagram |
| `quic.maxDatagramSize()` | Largest datagram payload that fits the current path |
| `quic.close(errorCode, reason)` | Send CONNECTION_CLOSE |
| `quic.on(event, fn)` / `off` | Event subscription |

**Events:** `'connect'`, `'stream'` (`id, data, fin`), `'datagram'`, `'close'`,
`'error'`, `'keylog'`.

**Connection options** (when constructing directly): `idleTimeout` (default `30000`),
`handshakeTimeout` (default `10000`), `keepAlive` (`true` → half the idle timeout, or
a number of ms), `alpn`, `hostname`, `rejectUnauthorized`, `ca`.

---



---

## ⚙️ Configuration & Tuning

### Transport parameters

These are the values QUICO advertises to peers. They are currently compiled-in
defaults; making them configurable is on the roadmap.

| Parameter | Default | Meaning |
|---|---|---|
| `initial_max_data` | 1 MB | Connection-level receive window |
| `initial_max_stream_data_bidi_local/remote` | 256 KB | Per-stream receive window |
| `initial_max_stream_data_uni` | 128 KB | Per-unidirectional-stream window |
| `initial_max_streams_bidi` | 100 | Concurrent bidirectional streams |
| `initial_max_streams_uni` | 3 | Concurrent unidirectional streams |
| `max_idle_timeout` | 30 s | Idle before the connection is dropped |
| `max_ack_delay` | 25 ms | Maximum ACK delay we advertise |
| `max_datagram_frame_size` | 65527 | Datagram support (RFC 9221) |
| `active_connection_id_limit` | 4 | Connection IDs we will track |

Receive windows slide automatically as the application consumes data, so large
downloads are not limited by the initial values.

### Per-connection timers

```js
// via the low-level API
new QUICConnection({
  idleTimeout: 60000,      // default 30000
  handshakeTimeout: 10000, // default 10000
  keepAlive: true          // PING at idleTimeout/2; or a number of ms
});
```

---

## 🐛 Debugging

### Environment variables

| Variable | Effect |
|---|---|
| `QUICO_DEBUG=1` | Full per-packet trace: every datagram, packet, frame, stream write, and TLS transition. **Very verbose** — it can become the bottleneck it observes, so don't use it for throughput measurements. |
| `QUICO_DEBUG_BBR=1` | One line per round-trip with congestion-control state: `BtlBw`, `RTprop`, `BDP`, `cwnd`, pacing rate. Cheap enough to leave on. |

```bash
QUICO_DEBUG_BBR=1 node server.js
# [bbr] round=12 probe_bw BtlBw=9.84Mbps RTprop=16ms BDP=19671B → cwnd=24589B pace=9.84Mbps
```

### Decrypting traffic in Wireshark

QUICO emits TLS secrets in NSS keylog format, so you can read your own encrypted
QUIC traffic:

```js
import fs from 'node:fs';

const out = fs.createWriteStream('/tmp/keys.log', { flags: 'a' });
quic.on('keylog', (line) => out.write(line));   // low-level QUICConnection
```

Then in Wireshark, set *Preferences → Protocols → TLS → (Pre)-Master-Secret log
filename* to that file — or from the command line:

```bash
tshark -r capture.pcap -o tls.keylog_file:/tmp/keys.log -Y quic
```

---

## 🧪 Testing

QUIC requires TLS 1.3. Self-signed RSA certificates are often rejected by QUIC clients
and browsers; [mkcert](https://github.com/FiloSottile/mkcert) is the easiest way to get
locally-trusted ECDSA certificates.

QUICO supports ALPN `"h3"` only — not draft variants such as `h3-29`. Chrome must be
told explicitly to use QUIC against a local server:

**Chrome**
```bash
chrome --enable-quic --quic-version=h3 --ignore-certificate-errors \
       --origin-to-force-quic-on=localhost:4433
```

**curl** (needs an HTTP/3-enabled build)
```bash
curl --http3 https://localhost:4433 --insecure
```

**Test suites**
```bash
node examples/test_integration.js       # HTTP/3 client + server — 19 tests
node examples/test_wt_server.js         # WebTransport echo (QUICO ↔ QUICO)
node examples/test_webtransport.js URL  # WebTransport client against any server
```

**Interop runner** — see [`interop/`](./interop) for the Docker endpoint used with the
[QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner).

---

## 📁 Project Structure

```
quico/
├── index.js               — Public API exports
├── interop/               — QUIC Interop Runner endpoint (Dockerfile + shim)
├── examples/              — Runnable examples and test suites
└── src/
    ├── server.js            — Unified server (drop-in for node:https)
    ├── client.js            — Unified client with H3 → H2 → H1 fallback
    ├── agent.js             — Connection pooling, coalescing, Alt-Svc cache
    ├── streams.js           — IncomingMessage, ServerResponse, ClientRequest
    ├── h3.js                — HTTP/3 framing, QPACK, WebTransport detection
    ├── h3_server.js         — HTTP/3 + WebTransport server
    ├── h3_client.js         — HTTP/3 client (DNS, UDP, QUIC, H3 pipeline)
    ├── quic_server.js       — UDP listener, connection routing, retry/VN
    ├── quic_socket.js       — Client-side UDP socket + connection bootstrap
    ├── quic_connection.js   — QUIC state machine, loss detection, CC, flow control
    ├── transport.js         — Packet parsing, frame encoding/decoding
    ├── crypto.js            — AEAD, header protection, key derivation
    ├── tls_bridge.js        — LemonTLS integration, transport parameters
    ├── utils.js             — VarInt, ACK ranges, binary helpers
    └── webtransport.js      — WebTransport client + stream classes
```

---

## ⚠️ Known Limitations

Being explicit about what is **not** implemented yet:

| Area | Status |
|---|---|
| **0-RTT / session resumption** | Not implemented — every connection is a full handshake. |
| **ChaCha20-Poly1305** | Not implemented. AES-128-GCM and AES-256-GCM only. On hardware without AES acceleration this costs performance. |
| **Connection migration** | Not implemented; QUICO advertises `disable_active_migration`. Connections do not survive a client IP change. |
| **ECN** | Not implemented — Node's `dgram` does not expose the required socket options. |
| **Retry / address validation** | Not implemented (client does not consume Retry tokens; server does not issue them). |
| **Anti-amplification limit** | Not enforced (RFC 9000 §8.1). |
| **Stream priority** (RFC 9218) | Not implemented. |
| **Delayed ACK** | Not implemented — an ACK is sent per ack-eliciting packet. Correct, but more packets than necessary. |
| **`MAX_STREAMS` issuance** | Streams limits are honoured but not proactively raised, capping very-high-concurrency workloads. |
| **TypeScript types** | Not shipped yet. |

Performance has not been formally benchmarked. QUICO is pure JavaScript; expect it to
be slower than native implementations, especially for bulk transfer.

---

## 🛣 Roadmap

### ✅ Done
- QUIC v1 transport (RFC 9000) — Initial, Handshake, 1-RTT
- TLS 1.3 via LemonTLS — X25519, P-256, P-384, AES-128/256-GCM
- Version Negotiation, HelloRetryRequest
- Key Update — bidirectional key phase rotation (RFC 9001 §6)
- Loss detection, PTO with exponential backoff (RFC 9002)
- BBR-style congestion control with pacing
- Bidirectional flow control with sliding windows
- HTTP/3 server and client (RFC 9114)
- QPACK with static and dynamic tables (RFC 9204)
- WebTransport client and server — streams + datagrams (RFC 9297)
- Unreliable datagrams (RFC 9221)
- `node:https`-style API — `createServer`, `request`, `get`, `Agent`
- Express / Fastify / Koa support
- Connection pooling, coalescing and multiplexing
- TLS keylog export
- **Interop: 6/6 implementations green** (handshake, transfer, http3, both directions)

### 🔄 In Progress
- Delayed ACK and ACK piggybacking
- 0-RTT and session resumption
- Configurable transport parameters

### ⏳ Planned
- Connection migration (PATH_CHALLENGE / PATH_RESPONSE)
- ChaCha20-Poly1305 (0x1303)
- Retry / address validation + anti-amplification limit
- GOAWAY and graceful shutdown
- Stream priority (RFC 9218)
- TypeScript type definitions
- Performance benchmarks
- Fuzz testing

_Community contributions are welcome! Please ⭐ star the repo to follow progress._

---

## 🤝 Contributing

Contributions are very welcome — bug reports, reproductions, and PRs alike.

Useful things to know before you start:

- Run `node examples/test_integration.js` before and after your change (19 tests).
- `QUICO_DEBUG=1` gives a full packet trace; `QUICO_DEBUG_BBR=1` gives a congestion
  control timeline. Include the relevant excerpt in bug reports.
- If you can capture a `.pcap` plus a keylog file, that makes protocol bugs enormously
  easier to diagnose — see [Debugging](#-debugging).
- For interop-level changes, the [`interop/`](./interop) directory contains the Docker
  endpoint used with the QUIC Interop Runner.

---

## 🙏 Sponsors

QUICO is an evenings-and-weekends project.
Support development via **GitHub Sponsors** — or simply share the project.

---

## 💬 Contact

For feedback, ideas, or contributions:
📧 **support@quicojs.dev**

For security-related issues, please see [SECURITY.md](./SECURITY.md).

---

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
