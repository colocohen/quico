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
     - [The first round trips](#the-first-round-trips)
     - [A returning client: Careful Resume](#a-returning-client-careful-resume)
   - [Stream scheduling](#stream-scheduling-byte-level-round-robin)
   - [Loss detection](#loss-detection-timers-and-how-we-treat-late-acks)
   - [The handshake](#the-handshake-coalesced-datagrams-its-own-loss-detection)
   - [Flow control](#flow-control-consumption-based-windows)
7. [Interoperability](#-interoperability)
8. [API Reference](#-api-reference)
   - [`createServer()`](#quicocreateserveroptions-requestlistener)
   - [`request()` / `get()`](#quicorequesturloptions-options-callback)
   - [`IncomingMessage`](#incomingmessage) · [`ServerResponse`](#serverresponse) · [`ClientRequest`](#clientrequest)
   - [`Agent`](#agent) · [`createSecureContext()`](#quicocreatesecurecontextoptions)
   - [0-RTT (early data)](#0-rtt-early-data)
   - [Framework compatibility](#framework-compatibility)
   - [WebTransport](#webtransport-1)
   - [WebSocket](#websocket-1)
   - [CONNECT-UDP (proxying UDP)](#connect-udp-proxying-udp)
   - [Fingerprinting](#fingerprinting-1)
   - [Protocol layers](#protocol-layers)
   - [Low-level QUIC API](#low-level-quic-api)
9. [Configuration & Tuning](#-configuration--tuning)
10. [Debugging](#-debugging)
11. [Testing](#-testing)
12. [Project Structure](#-project-structure)
13. [Security](#-security)
14. [Known Limitations](#-known-limitations)
15. [Roadmap](#-roadmap)
16. [Contributing](#-contributing)
17. [Sponsors](#-sponsors)
18. [Contact](#-contact)
19. [License](#-license)

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
| **Dependencies** | [`lemon-tls`](https://github.com/colocohen/lemon-tls) (TLS 1.3) and [`flat-ranges`](https://www.npmjs.com/package/flat-ranges) (range arithmetic). Nothing else. |

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

> GET and HEAD requests are ended for you on the next tick. For any method with a
> body, call `.end()` — like `node:https`, the request isn't sent until you do.

> 📂 More examples in [`examples/`](./examples)

---


## ✨ Features

### One HTTP stack, three versions
QUICO does not import `node:http`, `node:https`, `node:http2` or `node:tls`. HTTP/1.1,
HTTP/2 and HTTP/3 are all implemented here, and all three hand the application the
same `IncomingMessage` / `ServerResponse` — so a framework written against `node:http`
runs over any of them without knowing which. For the network and cryptography, all
QUICO takes from Node is `node:net` (TCP), `node:dgram` (UDP) and `node:crypto`
(primitives).

- **HTTP/3** (RFC 9114) with QPACK, static and dynamic tables (RFC 9204); up to 100
  blocked streams — a field section that references an entry whose insertion has not
  arrived yet waits for it (`SETTINGS_QPACK_BLOCKED_STREAMS`)
- **HTTP/2** (RFC 9113) with HPACK, including h2c by connection preface
- **HTTP/1.1** with keep-alive, chunked transfer and trailers
- One server listens on UDP and TCP and serves all three; `Alt-Svc` is advertised
  on HTTPS HTTP/1.1 and HTTP/2 responses so browsers discover HTTP/3 (see `altSvc`)
- Client with automatic H3 → H2 → H1.1 fallback, connection pooling and
  per-origin coalescing
- `103 Early Hints` (`res.writeEarlyHints()`) on all three versions
- Extra protocols on the same TCP port through ALPN or byte sniffing
  (`server.addProtocol()`)

### QUIC Transport
- QUIC v1 (RFC 9000) and **QUIC v2** (RFC 9369) — Initial, Handshake and 1-RTT packet
  spaces; everything a version decides (salt, key labels, packet type bits, Retry key)
  in one profile per version (`quic_version.js`), the rest shared
- Compatible version negotiation (RFC 9368): a client that starts in v1 and offers v2 is
  moved to v2 without a round trip when the server prefers it (`quicVersions`); Version
  Negotiation and a second attempt when there is no compatible version
- TLS 1.3 handshake via LemonTLS, no OpenSSL (RFC 9001)
- Version Negotiation (RFC 9000 §6)
- HelloRetryRequest — X25519, P-256, P-384
- AES-128-GCM and AES-256-GCM
- Key Update — bidirectional key phase rotation (RFC 9001 §6)
- Session resumption on the server, with ticket keys shared across connections
  (`ticketKeys`)
- Retry and address validation, switchable at runtime (`validateAddress`)
- Handshakes under way counted for the application (`getPendingHandshakes()`,
  `'handshakeLoad'`), and capped per client address (`maxHandshakesPerAddress`)
- Anti-amplification limit — 3× until the client's address is validated (RFC 9000 §8.1)
- Connection migration (RFC 9000 §9): a client may move to another network (Wi-Fi to
  cellular) and go on in the same connection — each side issues spare connection IDs
  (NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, Retire Prior To) and the new path is
  addressed by one of its own (§9.5); NAT rebinding is followed too. Each new address is
  validated with PATH_CHALLENGE first, and congestion/RTT state starts over on a new IP
- NEW_TOKEN (RFC 9000 §8.1.3): a returning client's address needs no proof — no Retry,
  no 3× limit; the agent keeps one token per server and uses it once
- ACK frequency (draft-ietf-quic-ack-frequency): a receiver follows ACK_FREQUENCY and
  IMMEDIATE_ACK; a sender with many packets in flight asks for an ACK every ~10 packets —
  an 8 MB download, ~340 ACK packets instead of ~3,400
- `grease_quic_bit` (RFC 9287): the fixed bit sent unpredictable to a peer that allows it
  (not on a UDP port shared with other protocols)
- Certificate compression (RFC 8879, in LemonTLS): the server's chain compressed for a
  client that offers it (Chrome: brotli), only when it comes out smaller, and once per chain
  (cached). The client offers brotli, zstd and zlib on every version. A client certificate
  goes compressed when the server's CertificateRequest asks. Decompressing stops at the
  declared length and never goes past 128 KB. With an RSA-4096 chain, the server's
  Handshake flight over QUIC went from 9.6 KB to 6.0 KB. The server's algorithms are
  `createServer({ certificateCompression })`; what went on the wire, each way, is
  `socket.getNegotiationResult().certificateCompression` on every version. The chain is
  compressed when the server is made, in the background, not by the first client's
  handshake (brotli at quality 11: ~4 ms for a small chain, ~18 ms for 9 KB)
- Encrypted Client Hello (RFC 9849, in LemonTLS) — HTTP/3, HTTP/2 and HTTP/1.1 alike: the
  site name and ALPN travel encrypted, to a key published in DNS (`ech`; see
  [Encrypted Client Hello](#encrypted-client-hello-ech))
- Stateless reset with HMAC-derived tokens (`resetTokenSecret`)
- Stream and connection-level flow control with sliding windows
- Stream limits enforced in both directions, and raised with `MAX_STREAMS` as
  streams close (RFC 9000 §4.6)
- Loss detection with PTO and exponential backoff (RFC 9002)
- BBR-style congestion control with pacing
- Path MTU discovery (DPLPMTUD, RFC 8899)
- Unreliable datagrams (RFC 9221)
- Idle timeout, keep-alive, TLS keylog export for Wireshark

### WebTransport
- Client and server (RFC 9297 + draft-ietf-webtrans-http3)
- Bidirectional and unidirectional streams (Node.js Duplex API)
- Unreliable datagrams
- Natural API: `req.on('stream')`, `res.sendDatagram()`, `res.writeHead(200)` to accept
- Over HTTP/3 only: a session asked for over HTTP/1.1 or HTTP/2 is answered `501`,
  with no body, before the application sees it

### WebSocket
- Server over all three versions: HTTP/1.1 Upgrade, HTTP/2 extended CONNECT
  (RFC 8441) and HTTP/3 extended CONNECT (RFC 9220) — one `'upgrade'` event for all
- `WebSocketServer` in the shape of the `ws` package, and a WHATWG-style
  `WebSocket` client (HTTP/1.1)

### CONNECT-UDP
- A UDP proxy (RFC 9298, MASQUE) over HTTP/3 — QUIC datagrams — and HTTP/2 and
  HTTP/1.1 — capsules: `server.on('connectUdp', (req, tunnel) => tunnel.accept())`
- Its client: `quico.connectUdp(proxy, { host, port })`, a `dgram.Socket` that goes
  through the proxy

### Fingerprinting
- JA4H (HTTP request), HTTP/2 and HTTP/3 protocol fingerprints, per request
- TLS fingerprints (JA4, JA4S, JA5) through LemonTLS
- `profileRequest()` — scores how well a request's protocol behaviour matches the
  client it claims to be

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
keeps only this:

```js
{
  q:                [Uint8Array, …],  // the bytes the application wrote, as written
  acked_ranges:     [from, to, …],  // byte ranges the peer has confirmed
  in_flight_ranges: { 47: [from, to], 48: [from, to] },  // packet number → bytes it carries
  missing_ranges:   [from, to, …]   // the answer to the question below, kept (see below)
}
```

Every send opportunity asks one question, and it's a set operation:

```js
missing = invert(acked_ranges ∪ in_flight_ranges, 0, total_size)
```

Whatever's missing goes out. That's the whole algorithm. The sender doesn't remember
what it *did* — it asks what the peer *still needs*, every time. It's a declarative
model: continuously reconcile "what the peer has" against "what the peer should have",
and emit the difference.

**The answer is kept, not recomputed.** `acked_ranges ∪ in_flight_ranges` was computed
from every packet in flight, three or four times per send pass — with thousands of
packets in flight on a large transfer, that was a fifth of the CPU. Each stream now holds
the answer itself, as [flat-ranges](https://github.com/colocohen/flat-ranges)' three
states of what the peer has:

| flat-ranges | QUICO | the peer… |
|---|---|---|
| `have` | `acked_ranges` | has these bytes — acknowledged |
| `not_have` | `missing_ranges` | surely lacks them — never sent, or given up on |
| `unknown` | `in_flight_ranges` (by packet) | may have them — in flight |

`have` and `not_have` never overlap, and `missing_ranges` is what the sender sends from.
It changes at exactly five points ([`nothingMissing`](./src/quic_connection.js)
documents them):

| Event | `missing_ranges` |
|---|---|
| the application writes bytes | added |
| bytes yielded into a packet (`get_stream_chunks`) | removed |
| an ACK credits bytes — a late one included | removed |
| the expiry timer gives a packet up | its bytes added, except any acknowledged meanwhile (`add_not_have`) |
| a packet that never left (encryption failed) | its bytes added |

Adding a packet's bytes back is exact because each byte is in flight in one packet at
most: bytes are yielded only while missing, and become missing again only when the
packet that carried them expires. `sendstate_test` checks `missing_ranges` against the
complement of `acked_ranges ∪ in_flight_ranges`, rebuilt from scratch every few
milliseconds under loss, reordering and late ACKs, and that it never overlaps
`acked_ranges`.

Congestion control counts something else: **packets, by their size on the wire** — header,
frames, padding and AEAD tag, whatever they carry, as RFC 9002 counts bytes in flight.
Each packet the peer must acknowledge enters `pkt_in_flight` when it leaves and goes when
it is acknowledged or given up on; `app_bytes_in_flight` is their sum, kept as they come
and go, and an ACK delivers what its packets weighed. The window, the pacing rate and the
bandwidth BBR measures are one unit. (They used to be STREAM bytes, which left out the
packets' overhead, packets of control frames, and most of the handshake.)

**Loss detection, therefore, is still one step:**

```js
delete st.in_flight_ranges[pn];                    // not in flight any more
flat_ranges.add_not_have(acked, missing, lostRanges); // → missing again, unless acked
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

**What it costs.** A send opportunity reads a stream's few `missing_ranges` — usually
one or two — and keeping them is a range insert or removal per write, and per packet
sent, acknowledged or expired. The expiry walk visits a
stream's packets oldest first and stops at the first one still within the timeout, so
it costs the packets that expired, not every packet in flight.

**The receive side is symmetric.** Incoming data is recorded in a `ranges` array, and
delivery walks the contiguous prefix. Same range algebra, mirrored — which is exactly
why the receiver must tolerate chunks whose boundaries don't line up with anything it
saw before: on the sending side, they never had to. It does so at insertion: only the
bytes not already held are stored, so stored pieces never overlap, tile `ranges`
exactly, and delivery is an exact-key walk. A peer cannot make reassembly expensive
either — the number of gaps per stream is capped (1000, as in quic-go), and pieces are
compacted into one buffer per contiguous run when they outnumber the gaps.

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

#### The first round trips

A page's first view is decided before any of this has measured anything: by the window
the connection starts with, and how fast it grows. QUICO starts at **20 packets (24 KB)**
— `initialCongestionWindow` — where RFC 9002 suggests 10. That is where TCP effectively
is when its response goes out: a 10-segment TCP window has grown on the acknowledged
handshake segments by then, and a QUIC connection at 10 left a 60 KB page a round trip
behind HTTP/2 on the same path. In `startup` the window then grows by every byte the
peer acknowledges — the handshake's packets as well as the application's (RFC 9002
§7.3.1, TCP's slow start). Through an emulated 450 ms, 9 Mbps link, Chromium loading a
61 KB page that references a 61 KB script:

| | HTML after its first byte | the script | `load` |
|---|---|---|---|
| a 10-packet start | 934 ms (2 round trips) | 1384 ms | 2326 ms |
| 20 packets (default) | 490 ms (1) | 942 ms | 1890 ms |

The window's ceiling is **8 MB** — what a long fat path needs at the pacing ceiling
(14 MB/s × 450 ms ≈ 6.3 MB); a 4 MB download through the same link takes 5.4 s (it took
8.7 s under the earlier 300 KB ceiling). The window reaches it only where BBR measured
that much: on a short path, the BDP keeps it small.

#### A returning client: Careful Resume

A client back within the hour has already shown this server its path. QUICO keeps what
BBR measured — the bottleneck bandwidth and the minimum RTT — in the client's session
ticket, and a connection that resumes with it starts from there, as **RFC 9959 (Careful
Resume)** lays out, with its BBR appendix — when turned on (`carefulResume: true`; off by
default, for reasons measured at the end of this section):

- **Saved** once BBR has a measurement worth keeping (a capacity of at least four initial
  windows): during Startup at each round it grows by a quarter, then when it moves by a
  quarter either way — in a NewSessionTicket sent after the handshake (lemon-tls
  `sendTicket()`), inside the ticket's encryption: the client carries it, cannot read or
  forge it, and the server keeps nothing. A resumed connection carries it forward.
- **Not used** past an hour, from another network (the client's IPv4 /24 or IPv6 /48
  changed: a laptop moved from home to a café), or when the first flight shows another
  RTT — at most half, or over ten times, the saved one.
- **Reconnaissance → jump → validation.** The first flight goes out at the initial window,
  as on any connection. Once it is acknowledged without loss, the first time the sender
  has more than its window allows, the window jumps to **half** the saved capacity, paced
  over one round trip; slow start goes on from what that delivers.
- **Safe Retreat.** A loss while the jump is out is taken for congestion: the saved state is
  deleted, the window drops to half of what was actually delivered and holds until the jump
  is acknowledged, and BBR goes on in ProbeBW from there.

Chromium through the emulated link, the second download on a new connection resuming with
the first one's ticket:

| Path | File | First visit | Returning, Careful Resume | Returning, without |
|---|---|---|---|---|
| 450 ms, 9 Mbps | 512 KB | 2365 ms | **1736 ms** | 2384 ms |
| 450 ms, 9 Mbps | 2 MB | 4107 ms | **3353 ms** | 4152 ms |
| 100 ms, 50 Mbps | 4 MB | 1876 ms | **1428 ms** | 1634 ms |
| 450 ms, 9 Mbps, 2 % random loss on the return | 2 MB | 4026 ms | 5357 ms | **4608 ms** |

The last row is the RFC's price: a random loss during the jump looks like congestion, and
the retreat costs more than QUICO's BBR loses without it — it does not react to loss at all.
On a path that did get slower (the same RTT, a third of the rate), the jump is what the
retreat is for; measured there, the returning download was still faster with it (6.8 s
against 7.8 s), the queue having absorbed it.

**Off by default.** Those measurements were of one file, downloaded twice — so the first
visit had measured the path at full rate. A website's first visit is a page: a document and
its resources, which measure a lower rate, so the jump on the next visit is smaller. Measured
again that way (Chromium, the second visit on a new connection), and with the handshake
and loss recovery improved since, which made connections without it faster too:

| Path | Returning visit | With Careful Resume | Without |
|---|---|---|---|
| 100 ms, 50 Mbps | 4 MB download | 1314 ms | 1320 ms |
| 450 ms, 9 Mbps | 512 KB download | 2833 ms | 2918 ms |
| 100 ms, 50 Mbps | page (60 KB + 20 scripts) | 731 ms | **678 ms** |
| 250 ms, 20 Mbps | page | 1769 ms | **1660 ms** |
| 250 ms, 20 Mbps, 3 % random loss | page | 3583 ms | **2150 ms** |

Almost nothing on clean paths, and a lot lost on a lossy one: with a hundred packets in the
jump and a few percent of random loss, one is nearly always lost, Safe Retreat takes it for
congestion, and the connection goes on at a fraction of the link. `carefulResume: true`
turns it on — for an application whose returning clients download large files over clean
paths, as in the first table; `getStats().carefulResume` gives a connection's phase.

**Honest scope:** this is BBR-*style*, not a certified BBRv2. ProbeRTT — the periodic
cwnd collapse that re-measures RTprop on a permanently saturated path — is not
implemented, and there is no explicit loss response. The windowed filters bound the
damage of stale measurements in the meantime.

### Stream scheduling: byte-level round-robin, by priority

**The choice:** when several streams have data ready and one packet is going out, who
gets the space? Implementations differ sharply — many drain streams in priority or
creation order, filling each one before moving on.

QUICO interleaves at the **byte level, inside a single packet**
([`execute_quic_burst`](./src/quic_connection.js)). The scheduler cycles through the
active streams, taking a chunk from each until the packet is full, then cycles again —
so a 1200-byte packet can carry STREAM frames from three different streams:

```
┌─────────────────────────────── one QUIC packet ───────────────────────────────┐
│ ACK │ STREAM(id=0, 450B) │ STREAM(id=4, 450B) │ STREAM(id=8, 400B) │
└───────────────────────────────────────────────────────────────────────────────┘
```

The loop repeats while any stream still yields data and space remains (`progress`
flag), so a stream that runs dry doesn't hold a slot — the remaining bandwidth
redistributes to the others within the same packet.

**Each packet starts where the last one left off.** A stream takes what it has, up to
the room left — so a stream with plenty to send fills a whole packet on its own. If
every packet started from the lowest stream number, that stream would fill every
packet and the others would wait for it to finish: three 6 MB downloads ran one after
another. The scheduler remembers who opened the previous packet (`rr_cursor`) and starts
the next round just after it, so with three busy streams the packets go 0, 4, 8, 0, 4,
8… and the downloads progress at equal rates. The cost is fragmentation — more STREAM
frame headers per packet (~24 bytes each) than a drain-one-stream-at-a-time scheduler.
QUICO accepts that trade for fairness.

**Priorities decide who takes part in a round.** The streams with data are arranged in
tiers, and a packet takes from the first tier with something to send; only if that
runs dry does the next tier fill the rest of the same packet:

- by **urgency**, most urgent first — RFC 9218's `u=0..7`, default 3; urgency −1 is
  HTTP/3's own control and QPACK streams, ahead of everything (a header block that
  refers to a QPACK entry stuck behind response bytes would block);
- within an urgency, **non-incremental** streams go one at a time, by stream number,
  each a tier of its own — a stylesheet whole before the next;
- then the **incremental** ones, taking turns as above;
- a **group** (any object, given to `setStreamPriority`) takes *one* turn in its round,
  and passes it to its member with the highest `order` that has something to send;
  equal orders take turns. This is WebTransport's `sendGroup` / `sendOrder`, mapped in
  the WebTransport layer; QUIC only knows "streams that share one turn".

A stream nobody set a priority for takes turns at urgency 3 — as every stream did
before. The mechanism lives in QUIC (`setStreamPriority(id, { urgency, incremental,
group, order })`); the policy comes from above: HTTP/3 reads the client's `priority`
header and `PRIORITY_UPDATE` frames, the application can override them
(`res.setPriority`) — the client's later signals do not undo the application's decision
— and WebTransport maps its streams' `sendGroup` / `sendOrder`. A client asks for a
priority with the `priority` header on its request (`'u=1, i'`) — QUICO's client: the
`priority` option, `req.setPriority()`. HTTP/2 has the same
rules in its own scheduler (`h2.js`), for the DATA that waits for a window or for the
socket; what the socket already holds leaves in the order it was written. An HTTP/2
server sends `SETTINGS_NO_RFC7540_PRIORITIES = 1`: it reads RFC 9218's signals, not
RFC 7540's priority tree.

A scheduler can only order what is waiting. A stream fed in small writes with
backpressure has little queued at any moment, and while its queue is empty the next
tier sends — so an application that wants a stream strictly first should hand it its
data ahead of time, not a chunk per `'drain'`. Likewise a stream blocked by the peer's
flow control lets the next one go, rather than leaving the packet empty.

**The subtle part** falls straight out of the reconciliation model: the sender decides
what to send by asking which bytes aren't acked or in flight — but chunks selected
*earlier in the same burst* have no packet number yet, so they're in neither set, and
the next iteration would select them again. `get_stream_chunks` takes what it yields out
of `missing_ranges` at once, so the next iteration sees it as taken; the packet's number
records it in `in_flight_ranges` when it is sent. A packet that does not leave hands its
bytes back to `missing`. One packet can carry two pieces of one stream — new data and a
repaired gap — so a packet's entry in `in_flight_ranges` is a range list, read whole by
the ACK, the expiry timer and a stream reset.

**Many streams on one connection.** What the sender does per packet and per ACK does not
walk every stream: each packet in flight records the streams it carries, so an ACK (and
the expiry timer) visits those; the streams that hit flow control, and those whose FIN
is still to go, are kept apart the same way. Walked, those loops were most of the CPU of
a connection with many streams — a thousand concurrent responses on one connection ran
at 25 Mbps on loopback, two thousand at 10. Now 1000 run at ~60 and 2000 at ~55, against
~70 with 200 (one core, client and server in one process). What remains per stream is
the scheduler's arrangement of the streams with data, once per burst.

**Writes go out once per tick.** A write to a stream does not send: it asks for one send
pass at the end of the current tick, and every write until then rides in it. A response
written as headers, ten small writes and an end is one datagram, not fourteen. A pass
for any other reason — an ACK, a timer — still runs at once and takes what is waiting.

**Datagrams** (RFC 9221) are never retransmitted, but they go under the same congestion
control: they wait in a queue, are taken into packets ahead of stream data, and the
packets that carry them count in flight (with nothing to resend). A datagram sent with
a priority (WebTransport's `sendOrder` / `sendGroup`) is not first: it takes its place
in its group, as a member at its order. While the path cannot
keep up the oldest are dropped — any that have waited 250 ms (configurable), and past
1 MB queued — since a late datagram is worth nothing. The peer's
`max_datagram_frame_size` is honoured.

### The send queue: the application's buffers, not copies

What a stream holds for sending is the list of buffers the application wrote, by
reference, each with the stream offset it starts at. A packet takes a view of one of
them, or — where it straddles two — a copy of its own ~1200 bytes. Writes of up to
4 KB are the exception: they are gathered into a 16 KB buffer of the stream's own, so
ten thousand one-byte writes are a handful of pieces. A buffer leaves the queue the
moment the peer has acknowledged all of it.

The effect is on memory: `res.end(file)` holds the file once, not once per layer, and
any number of concurrent responses of the same `Buffer` share it. As with
`net.Socket`, **a buffer passed to `write()` / `end()` must not be modified afterwards**
— it is referenced until acknowledged, and a retransmission reads it again.

**Backpressure on the sending side** works as on a TCP socket. A write is complete —
its callback runs — once the stream has *sent* all but `writableHighWaterMark` of what
was written (bytes in flight are bounded by the congestion window, as the kernel
bounds them for TCP). So on HTTP/3 `res.write()` returns `false` and `'drain'` follows,
and `readable.pipe(res)` reads at the client's pace: a 30 MB file piped to a browser
holds ~5 MB of buffers on the server, not the file. The same applies to WebTransport
streams and to tunnels (WebSocket over HTTP/3, CONNECT).

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

- **Optimistic ACKs are caught** (RFC 9000 §21.4). Every 256–1023 packets, at random,
  one 1-RTT packet number is skipped; an ACK that covers it acknowledges a packet that
  was never sent, and closes the connection (PROTOCOL_VIOLATION). A peer acknowledging
  ahead of what arrived would otherwise inflate the congestion window at will. The send
  history keeps a zero-length placeholder for the skipped number, so its index math
  stays contiguous.

The PTO itself is `srtt + max(4·rttvar, 1ms) + max_ack_delay`. That last term is not
optional: peers may legitimately sit on an ACK for their full advertised delay (25 ms
is common), and a timer without it expires packets moments before their ACKs arrive.

The timer is the backstop, not the first word. On a new connection rttvar is half the
first RTT sample, so the timer comes ~3 RTTs after a packet left — and a lost packet in
a page's first response is exactly where those RTTs are paid. Two things come first:

- **Loss by ACK: the time threshold** (RFC 9002 §6.1.2). A packet is given up on once a
  packet sent after it is acknowledged and `max(9/8·RTT, RTT + 5 ms)` has passed since
  it was sent (RTT: the larger of srtt and the latest sample) — not the timer. Then
  exactly the timer's path: resent, parked for a late ACK, counted lost. The RFC's
  packet threshold (three later packets acknowledged) is left out on purpose: a packet
  that arrives out of order is not resent for that, only for being later than the
  threshold; the 5 ms floor keeps that so on short paths, where an eighth of the RTT is
  less than Wi-Fi's own retransmissions reorder by. A 60 KB response through a 200 ms
  path with one packet lost: ~10 ms longer than with none, where it was ~185 ms.
- **The tail loss probe** (RFC 8985). The last packet of a response — or a request in
  one packet — has no later one to be acknowledged: after `2·srtt + max_ack_delay`
  without an ACK, a copy of its data goes as a new packet. Nothing is given up on (the
  original stays in flight; whichever arrives counts), one probe until an ACK comes,
  only once the handshake is confirmed, and only while the timer is further off.

Chromium through 250 ms with 3 % loss (a 60 KB page and 20 scripts): page load p75
2.41 s → 2.02 s; through 20 ms with 1 % loss and 5 ms jitter: median 474 → 419 ms.

**Our own ACKs are delayed and batched** (RFC 9000 §13.2). In the 1-RTT space an ACK
goes out once two ack-eliciting packets are owed — decided at the end of the
event-loop turn, so datagrams that arrived together get one ACK — at once for a
packet out of order (that is what lets the sender detect loss quickly), and
otherwise within `max_ack_delay`. Any packet we send anyway carries the ACK that is
owed, and the ACK Delay field reports how long it was held, so the peer can take it
out of its RTT. Initial and Handshake packets are acknowledged immediately, as the
RFC requires — in the handshake's flush, with whatever else those spaces send (see
[the handshake](#the-handshake-coalesced-datagrams-its-own-loss-detection)). Before this, every ack-eliciting packet got an ACK packet of its own:
a 20 MB download had the receiver send ~18,000 of them; now ~1,200.

The ACK timer runs at `max_ack_delay − 15 ms` (10 ms against the 25 ms we
advertise): timers fire late by up to their granularity, ~15.6 ms on Windows, and
the peer's loss timer counts on our ACK arriving within the advertised value.

**ACK ranges are capped at 32** (RFC 9000 §13.2.4 permits acking a subset). Under
loss, packet-number gaps never close — a lost PN is gone forever, its data returns
under a new PN — so an uncapped ACK frame grows with the cumulative loss count until
it no longer fits in a packet. We measured exactly that against a line-rate sender:
ACK packets inflating 325 B → 1017 B second by second, until they crossed the MTU and
stopped being sendable at all.


### The handshake: coalesced datagrams, its own loss detection

The handshake is the one place where every datagram must arrive before anything can
go on — so it is built to send as few as it can (RFC 9000 §12.2):

- **One flush, coalesced datagrams.** Initial and Handshake packets are not sent as
  TLS produces each message. What the two spaces have to send — CRYPTO data neither
  acknowledged nor in flight, an ACK they owe — goes out at the end of the turn, in
  packets as full as the datagram allows, the packets in as few datagrams as they fit.
  The datagram is padded to 1200 bytes, not an Initial packet with zeros ahead of the
  Handshake packets that could have filled it. A server's whole flight (ServerHello,
  EncryptedExtensions, Certificate, CertificateVerify, Finished, and the ACK of the
  ClientHello) is **one datagram** with a small chain, where it was seven; a client's
  answer one, where it was up to eight.
- **RTT from the first round trip.** ACKs of Initial and Handshake packets give RTT
  samples, as 1-RTT ones do (RFC 9002 §4.1: RTT measurement is "unified across packet
  number spaces"); the client has one when its handshake completes, not only after its
  first 1-RTT packet is acknowledged.
- **ACK-based loss detection, in these two spaces only.** A packet is lost once a later
  one is acknowledged and three more are, or 9/8 of an RTT has passed (RFC 9002 §6.1);
  its range is sent again at once. The retransmission timer stays as the backstop. The
  1-RTT space keeps the recovery described above.
- **The client's anti-deadlock probe** (RFC 9002 §6.2.2.1). Until one of its Handshake
  packets is acknowledged, a client keeps its timer even with nothing in flight — and
  sends a PING when it fires: a server held by its anti-amplification limit has no
  timer of its own, and waits for any datagram from the client.
- **The first 1-RTT packet rides in the last handshake datagram.** When 1-RTT keys
  exist, the flush's last datagram waits for the end of the turn, and the first 1-RTT
  packet made in it goes in it, last (a short header has no length): the server's
  SETTINGS with its flight, the client's request — with its control streams — with its
  Finished, in room the Initial's padding took anyway. A connection with one request:
  8 datagrams where it was 13; before the response, one datagram each way after the
  ClientHello. Not where it would cost the server a round trip: a datagram the
  anti-amplification budget would have let through alone is not made too large for it.
- **The peer's retransmission is news** (RFC 9002 §6.2.3). Handshake data received
  again means the peer has not heard from us: what we sent in answer and is still
  unacknowledged goes again at once, with the ACK the packet is owed — a server seeing
  the ClientHello again, a client seeing the server's flight again — not a
  retransmission timeout (three RTTs on the first sample) later. Twice per connection
  at most. A 1-RTT packet that rode in a datagram found lost this way, or by the
  ACK-based detection above, is lost with it and sent again in the new datagram — the
  request does not wait for the 1-RTT space's own timeout because it travelled with the
  Finished. A late ACK for either still counts.

Chromium against a QUICO server through a 250 ms path with 3 % loss: time to first byte
went from a median of 1182 ms to 516 ms (two round trips — the floor), and the page from
2.8 s to 2.0 s. QUICO's client through the same path (100 connections): the 90th
percentile of time to first byte from ~1150 ms to ~850 ms, mostly the lost
Finished-and-request datagram answered on the server's retransmission.


### Path MTU discovery

Packets start at what every QUIC path carries — 1200 bytes of frames — and most paths
carry more: ~1450 on Ethernet. Every byte more in a packet is a packet less, and a packet
is an encryption, a system call and its bookkeeping — where a JavaScript sender spends its
time: a 4 MB download goes out in ~16 % fewer packets at 1452.

A round trip after the handshake is confirmed — the first responses go first; a probe is
1.4 KB of padding a slow link would put ahead of them — the sender probes (DPLPMTUD,
RFC 8899 / RFC 9000 §14.3), in a send pass of its own if nothing else would run one (a
client that only downloads may have nothing to send), and after the data of the pass it
shares:
a PING padded to a size, sent in the paced flow of the connection, and acknowledged — by
its own packet number — only if that size crossed the path. Sizes are whole UDP datagrams.
The first probe is at **the largest datagram the peer has sent on this path** (the limit is
most often the peer's own link — a PPPoE line, a VPN — and the same both ways), then at the
ceiling (1452, and the peer's `max_udp_payload_size`), and past a failure a binary search
down to 16 bytes. A size fails after three unacknowledged probes; the search runs again ten
minutes after it ends. A probe carries no stream data: a lost one — and a probe too large is
lost by design — holds nothing back, and is no loss to congestion control (§14.4).

**Black holes.** The MTU can shrink mid-connection. Packets above the floor lost in a row,
with none acknowledged since, are a suspicion, not a verdict — congestion loses packets in
runs too (Startup's overshoot does, every connection). A probe of the current size settles
it: acknowledged, it was congestion; lost three times, packets go back to 1200 and the
search starts again later. A new path starts from 1200, as its congestion state does.

| Path (largest datagram) | Found | Probes dropped |
|---|---|---|
| Ethernet (1472) | 1452 — the ceiling | 0 |
| a VPN (1392) | 1387, within the search's 16 bytes | ~9 |
| 1452, cut to 1300 mid-download | back to 1200 after 3 confirming probes | — |

### Flow control: consumption-based windows

**The choice:** when do you tell the peer it may send more? The naive trigger is
"bytes arrived"; QUICO slides its receive windows on **consumption** — a
`MAX_STREAM_DATA` / `MAX_DATA` update goes out once in-order data has been delivered
up the stack and half a window has been used, never for bytes still sitting out of
order in the reassembly buffer.

**Where "consumed" is measured.** For what the application reads — a request body on
the server, a response body on the client, a WebTransport stream on either side — it is
the application's read: the
bytes that have left the Node stream's buffer, counted after each `read()` (which
flowing mode, `pipe()` and async iteration all go through). A reader that reads
nothing holds the peer to one stream window; one that reads slowly sets the peer's
pace. Everything else — HTTP/3's own streams — is consumed at the hand-off from QUIC to the HTTP/3 layer, and bounded there by its
own limits (a HEADERS frame by the field-section size we advertise, control frames by
a fixed cap).

These bytes count in the connection's window too (`initial_max_data`, 1 MB by
default): a few streams that nobody reads can hold the whole connection. An
application with many parallel streams — MoQT's stream per group — reads or stops
(`stopSending`) each one, and sizes the windows for it with `transportParams`.

**Autotuning.** A window caps the peer at one window a round trip: 256 KB a stream is
10 Mbit/s at 200 ms. So, as Chromium and quiche do, a window the application consumed
half of within two round trips of the last update — the window is what limits, not the
path — doubles, up to **16 MB** a stream and **24 MB** the connection (a larger
`transportParams` value is kept as given); the connection's grows with its streams, to
1.5× the largest. It grows only with what is consumed, so a reader that falls behind
keeps the window it has. Measured through an emulated 20 Mbit/s, 200 ms link, a 4 MB
download by QUICO's client: 7.8 s before, 4.2 s now (Chromium: 3.1 s).

**HTTP/2, over TCP.** The client's stream window is **6 MB** (Chrome's), not
HTTP/2's 64 KB, and the connection's 16 MB. Credit still goes back as the
application reads, so a response nobody reads stops at 6 MB. The 64 KB default held a
response to 64 KB a round trip: 16 MB through a 100 ms round trip took 52 s, and takes
under 1 s now. An application that wants less sets `initialWindowSize` on the request.

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

0-RTT over TCP is verified with OpenSSL both ways (`s_client -early_data`, `s_server
-early_data`: taken, refused and sent again, and after a HelloRetryRequest). Over QUIC,
0-RTT is verified with Chromium (its second visit's request in its first flight, and its
retry after a `425`), and with aioquic and quic-go in both directions.

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

Creates a server for HTTP/3, HTTP/2 and HTTP/1.1. Returns a server object with
`listen()`, `close()` and `on()`.

**Options**

| Option | Type | Default | Description |
|---|---|---|---|
| `key` | `Buffer \| string \| Array` | — | Private key in PEM format (a string without `-----` is read as a file path). Required unless `SNICallback` is used. An array — `node:tls`'s form, keys or `{ pem, passphrase }` — for several certificates of different kinds, each key paired with the chain in `cert` that carries its public key (see [Post-quantum TLS](#post-quantum-tls)). |
| `cert` | `Buffer \| string \| Array` | — | Certificate chain in PEM format (or a file path, as for `key`); an array, one chain per key. |
| `ca` | `Buffer \| string \| Array` | `null` | Additional trusted CAs. |
| `SNICallback` | `Function` | `null` | `(servername, cb, info) => cb(null, secureContext)` for multi-domain setups. `info.transport` is `'tcp'` or `'quic'`. |
| `http3` | `boolean` | `true` | Listen for HTTP/3 over UDP. |
| `http2` | `boolean` | `true` | Also listen for HTTP/2 over TCP (fallback for non-QUIC clients). |
| `http1` | `boolean` | `true` | Also listen for HTTP/1.1 over TCP. |
| `ALPNProtocols` | `string[]` | — | ALPN names to accept, in preference order, as in `node:tls`. Served HTTP versions missing from the list are put first; naming a version that is disabled throws. |
| `maxConnections` | `number` | `10000` | Maximum concurrent QUIC connections. |
| `ticketKeys` | `Buffer` (48 bytes) | random | Session-ticket key, shared by TCP and QUIC. Pass a stable one to keep resumption working across restarts. |
| `ech` | `{ keys }` | — | Encrypted Client Hello keys, TCP and QUIC alike: `{ keys: [{ config, privateKey, retry }] }`, from `quico.generateEchKey()`. A key that does not match its config throws here. See [Encrypted Client Hello](#encrypted-client-hello-ech). |
| `earlyData` | `boolean` | `false` | Accept 0-RTT — a returning client's request in its first flight, answered one round trip sooner: over HTTP/3, and over TLS 1.3 on TCP (HTTP/2, HTTP/1.1). Off by default: early data can be replayed. See [0-RTT](#0-rtt-early-data). |
| `earlyDataMaxAge` | `number` (ms) | `10000` | 0-RTT: how far the age a client states for its ticket may be from what the server measures (RFC 8446 §8.3) — a captured first flight is good for this long at most. 1–600000. |
| `earlyDataReplay` | `(id, ttl, cb) => void` | in memory | 0-RTT's anti-replay store: `cb(null, true)` if `id` is new (and keep it `ttl` ms), `cb(null, false)` if seen. Share one (Redis, memcached) between servers that share `ticketKeys`. No answer in 100 ms, or an error: no 0-RTT, the handshake goes on. |
| `earlyDataFilter` | `(req, cb) => void` | `GET`, `HEAD`, `OPTIONS` | 0-RTT: whether a request that came early may be handled before the handshake completes — `cb(null, true)`; otherwise the client gets `425 Too Early` and sends it again after the handshake (RFC 8470). No answer in 100 ms: `425`. |
| `sessionTimeout` | `number` | `7200` | Seconds a session ticket stays good, TCP and QUIC alike (`node:tls`'s option; its default is 300). `0`–`604800` (RFC 8446's 7 days); `0` issues tickets that never resume. |
| `requestCert`, `rejectUnauthorized` | `boolean` | `false`, `true` | Client certificates, as in `node:tls`, on every version — HTTP/3 included — verified against `ca`. With `rejectUnauthorized` (the default) a client without a valid one is refused; with `false` it gets in, and `req.socket.authorized` says which. `req.socket.getPeerCertificate()` / `authorizationError` as on a `TLSSocket`; on a resumed connection, the certificate it proved on its first. |
| `minVersion`, `maxVersion` | `string` | `'TLSv1.2'`, `'TLSv1.3'` | `'TLSv1.2'` or `'TLSv1.3'`. HTTP/3 is TLS 1.3 only: `maxVersion: 'TLSv1.2'` needs `http3: false`. |
| `certificateCompression` | `string[]` \| `boolean` | `true` | The algorithms the server's certificate may go compressed in (RFC 8879), in order: `['brotli', 'zstd', 'zlib']` — the default, `true`, is all of them that Node has (zstd from 22.15). It goes compressed only to a client that offered one, and only when that comes out smaller. `false`: always plain. TCP and QUIC alike; a name unknown throws from `createServer`. |
| `honorCipherOrder` | `boolean` | `false` | As `node:tls`: the cipher suite by the server's order (`ciphers`). By default the client's — a client that asks for AES-256 first gets it. |
| `ciphers`, `ecdhCurve`, `sigalgs` | `string` | — | As `node:tls` takes them (OpenSSL's colon-separated names; `ecdhCurve: 'X25519:P-256'`). The server's default groups: every post-quantum one Node has, then X25519, P-256, P-384 (see [Post-quantum TLS](#post-quantum-tls)). HTTP/3 uses the TLS 1.3 suites of `ciphers` (AES-GCM and ChaCha20-Poly1305); a list without one needs `http3: false`. A value naming nothing usable throws from `createServer`. |
| `handshakeTimeout` | `number` | TCP `120000`, QUIC `10000` | Milliseconds a TLS handshake may take. Over QUIC, counted from the connection's first packet, and on a server until the client's Finished is verified — not only until the server's own Finished has gone: a client that sends a ClientHello and nothing more holds the connection for this long, not for the idle timeout. |
| `passphrase` | `string` | — | For an encrypted `key`. |
| `validateAddress` | `boolean` | `false` | Validate client addresses with a QUIC Retry before any handshake work. |
| `handshakeLoadThreshold` | `number` | `500` | HTTP/3 handshakes under way at which `'handshakeLoad'` fires (`high: true`), and again under half of it (`high: false`). `0`: off. |
| `maxHandshakesPerAddress` | `number` | `64` | HTTP/3 handshakes under way from one client address; past it an Initial from there makes no connection. `0`: no cap. |
| `resetTokenSecret` | `Buffer` (≥ 16 bytes) | random | Secret for QUIC stateless-reset tokens. Keep it stable across restarts so clients of a crashed instance get a reset instead of a timeout. |
| `tokenSecret` | `Buffer` (≥ 16 bytes) | random | Secret the HTTP/3 address-validation tokens (Retry, and NEW_TOKEN for a client's next connection) are sealed under — node:quic's name. Servers that share it open each other's tokens: several on one port (a thread each, `SO_REUSEPORT`), or one restarted. |
| `socket` | `dgram.Socket` | `null` | Use an externally-bound IPv4 UDP socket instead of creating one. Must already be bound. |
| `socket6` | `dgram.Socket` | `null` | Same, for IPv6. |
| `greaseQuicBit` | `boolean` | `true`; `false` with `socket` / `socket6` | QUIC: invite clients to send the fixed bit unpredictable (RFC 9287), so the bit stays free to change. Off by default on an external socket, whose port may be shared with STUN, TURN or DTLS — told apart from QUIC by that bit (RFC 9443). `true` when that port carries QUIC alone. |
| `port` | `number` | `443` | The port advertised in `Alt-Svc` when `listen()` is not used (externally fed server). |
| `altSvc` | `string \| false` | — | The `Alt-Svc` header on HTTPS HTTP/1.1 and HTTP/2 responses. By default `h3=":<port>"; ma=86400` when this server runs HTTP/3, and none with `http3: false`. A string is sent as is — for HTTP/3 served by something else (`'h3=":443"; ma=86400'`); `false` sends none. A response's own `alt-svc` header wins. |
| `connectUdp` | `object` | — | CONNECT-UDP's policy: `{ template, allowPrivate, maxTunnelsPerConnection, idleTimeout, lookup, proxyName }` — see [CONNECT-UDP](#connect-udp-proxying-udp). |
| `shouldUpgradeCallback` | `(req) => boolean` | listens for `'upgrade'`? | As in `node:http`: whether an upgrade request (HTTP/1.1 `Upgrade`, or extended CONNECT over HTTP/2 and HTTP/3) is taken up as `'upgrade'`, or handled as an ordinary `'request'`. |
| `headersTimeout` | `number` | `60000` | How long a request's head may take to arrive. HTTP/1.1: `408` and close. HTTP/2: a header block left open (HEADERS without END_HEADERS) blocks the whole connection, so the connection goes (GOAWAY). HTTP/3: the request stream is reset, `H3_REQUEST_INCOMPLETE`. `0` disables it. |
| `requestTimeout` | `number` | `300000` | As `node:http`: the whole request, body included, must arrive within it, counted from the end of its head. HTTP/1.1: `408` and close. HTTP/2 and HTTP/3: that request's stream is reset (`CANCEL` / `H3_REQUEST_INCOMPLETE`) and the request gets `'aborted'`; the connection serves on. Not applied to `CONNECT` (WebSocket, WebTransport), whose stream is meant to stay open. The response is not timed. `0` disables it. |
| `keepAliveTimeout` | `number` | `5000` | HTTP/1.1 only: an idle connection between requests. |
| `streamResetBurst`, `streamResetRate` | `number` | `1000`, `33` | Rapid Reset (CVE-2023-44487) protection, `node:http2`'s options and defaults: a client may cancel `streamResetBurst` requests at once, then `streamResetRate` a second. Past it the connection is closed — HTTP/2 `GOAWAY` `ENHANCE_YOUR_CALM` (a `'sessionError'`, `ERR_HTTP2_STREAM_RESET_RATE`), HTTP/3 `H3_EXCESSIVE_LOAD`. HTTP/3 counts cancelled request streams (`RESET_STREAM` or `STOP_SENDING`, once each), not a WebTransport session's own streams. `Infinity` for either: no limit. The `'stream_reset'` event remains for a policy of your own. |
| `maxRequestsPerSocket` | `number` | `0` (no limit) | `node:http`'s: requests one connection may carry. HTTP/1.1: the Nth response says `Connection: close` and the connection ends (a request past it, pipelined, gets `503`). HTTP/2 and HTTP/3: `GOAWAY` after the Nth — requests in flight finish, the client takes the next to a new connection (nginx's `keepalive_requests`). |
| `maxHeaderSize` | `number` | `16384` | HTTP/1.1: request line plus headers, in bytes (`node:http`'s option and default). Over it: `431`. |
| `maxHeaderCount` | `number` | `2000` | HTTP/1.1: header lines. Over it: `431` (`node:http` drops the extra ones instead). |
| `noDelay`, `keepAlive`, `keepAliveInitialDelay` | | `true`, `false`, `0` | TCP socket options. |
| `transportParams` | `object` | — | QUIC's windows and stream limits, as sent to every client: `initialMaxData`, `initialMaxStreamDataBidiLocal`, `initialMaxStreamDataBidiRemote`, `initialMaxStreamDataUni`, `initialMaxStreamsBidi`, `initialMaxStreamsUni`, `maxIdleTimeout`. See [Transport parameters](#transport-parameters). |
| `initialCongestionWindow` | `number` | `20` | QUIC: the congestion window a connection starts with, in full-size packets (1200 B), `2`–`100`. See [The first round trips](#the-first-round-trips). |
| `carefulResume` | `boolean` | `false` | QUIC: a returning client's connection starts from what the server measured on its last one (RFC 9959). Off by default: for page loads it gains almost nothing and costs a lot with random loss. Worth it where returning clients download large files on clean paths. See [Careful Resume](#a-returning-client-careful-resume). |
| `startupCap` | `'stall'` \| `'always'` \| `'off'` | `'stall'` | QUIC: Startup's cap on the congestion window, 2 × BDP plus ACK aggregation (BBR v3). `'stall'`: from the first round in which bandwidth stopped growing — fewer drops at a router's queue where the window used to overshoot, no cost to a page's ramp-up. `'always'`: the whole of Startup — fewest drops, a slower ramp on long lossy paths (for bulk transfers). `'off'`: none. Also per connection (`connectionOptions`, `conn.setOptions`), at runtime (`setOptions`), and a client's own option for what it sends. |
| `pmtuDiscovery` | `boolean` | `true` (`false` on Windows) | QUIC: path MTU discovery. Off on Windows by default — Node cannot set the Don't Fragment bit there, so a probe may cross fragmented and be taken for a fit. Off, packets stay at 1200 bytes of frames (or what was found before it was turned off). |
| `maxUdpPayloadSize` | `number` | `1452` | QUIC: the largest UDP payload sent (1200–65527): where path MTU discovery stops. Lower it for a VPN or a tunnel; raise it for jumbo frames on a LAN. |
| `initialRtt` | `number` (ms) | `333` | QUIC: the RTT assumed before there is a sample (RFC 9002's kInitialRtt) — how soon a lost handshake packet is sent again. Lower for clients known to be near (one country, a CDN edge); too low against far clients, handshake packets are resent needlessly. 10–10000. |
| `reorderWindow` | `number` (ms) | `5` | QUIC: the least a packet is allowed to arrive out of order before a later one's ACK gives it up (the floor of the time threshold, see [Loss detection](#loss-detection-timers-and-how-we-treat-late-acks)). Raise it on paths that reorder more (some mobile networks, per-packet load balancing) — `getStats().spuriousLosses` counting up says so. 0–1000. |
| `quicVersions` | `Array` | `['v1', 'v2']` | QUIC versions accepted, in preference (`'v1'`, `'v2'`, or the numbers). A client that offers both through `version_information` gets the first of these it can be moved to without a round trip (RFC 9368) — v1 by default; `['v2', 'v1']` moves such clients to v2. A client whose version is not listed gets Version Negotiation. `req.socket.quicVersion` says which. |
| `connectionOptions` | `(info, callback) => void` | — | QUIC: each connection's own `initialCongestionWindow`, `transportParams`, `carefulResume` and `startupCap`, decided when its ClientHello arrives. See [Per-connection settings](#per-connection-settings-connectionoptions). |
| `maxWebTransportSessions` | `number` | no limit | WebTransport sessions a connection may have open at once — sent as `SETTINGS_WT_MAX_SESSIONS`; a CONNECT past it is refused with `H3_REQUEST_REJECTED` before the application hears of it. |
| `maxConcurrentStreams`, `headerTableSize`, `initialWindowSize`, `maxFrameSize`, `maxHeaderListSize`, `connectionWindowSize`, `enableConnectProtocol` | | `100`, `4096`, `65535`, `16384`, `131072`, 16 MB, `true` | HTTP/2 settings. |
| `maxSessionMemory` | `number` | `10` | HTTP/2: megabytes a connection may have queued for a peer that is not reading (`node:http2`'s option). DATA waits for the socket instead of queueing; past this, the connection is closed. |

#### Per-connection settings: `connectionOptions`

The server's settings are everyone's. `connectionOptions` decides them per QUIC connection —
from the client's address, the name it asked for, and whether it has been here before:

```js
createServer({
  key, cert,
  connectionOptions(info, callback) {
    // info: { remoteAddress, remotePort, servername, resumed,
    //         previous: { rtt, bandwidth, age } | null }
    lookupNetwork(info.remoteAddress, (err, net) => {
      if (err) return callback(err);                       // → the server's settings
      callback(null, {
        initialCongestionWindow: net.satellite ? 40 : 20,  // packets
        transportParams: { initialMaxData: 32 * 1024 * 1024 },
        carefulResume: !net.shared,
        startupCap: net.bulk ? 'always' : 'stall',
      });
    });
  },
}, handler);
```

It is asked once the ClientHello is in and before anything is answered: the handshake waits
for it, as it waits for an asynchronous `SNICallback` (whose turn it takes first), and
`transportParams` — merged over the server's — go out in that same handshake. `previous` is
what the client's last connection from the same network measured, within the hour: what
[Careful Resume](#a-returning-client-careful-resume) would start from (`rtt` in ms,
`bandwidth` in bits/s, `age` in seconds); `null` on a first visit, from another network, or
past its lifetime. Every field of the answer is optional: `transportParams`, and any of
the connection options — `initialCongestionWindow`, `carefulResume`, `startupCap`,
`pmtuDiscovery`, `maxUdpPayloadSize`, `initialRtt`, `reorderWindow`. What a connection
has is the answer's, else what the server had when it was made (`createServer`, or
`setOptions` since), else the default; `conn.setOptions` changes it afterwards.

It cannot hold a connection hostage: no answer within **1 s**, an error, a throw, or an
answer that does not check out (checked whole — nothing of it is taken) leaves the
connection on the server's settings, and `process.emitWarning` says why (code
`QUICO_CONNECTION_OPTIONS`). It runs for every Initial that opens a connection — spoofed
ones included — so anything it calls out to should be cached; `validateAddress` screens
spoofed addresses before it is asked.

Setting `http2: false` and `http1: false` makes the server **HTTP/3 only** — no TCP
listener is opened. Without `key`/`cert`/`SNICallback`, the TCP side serves cleartext
HTTP/1.1 and h2c.

**Methods**

- `server.listen(port[, host][, callback])` — start listening. Binds UDP (unless
  `http3: false` or external sockets were given) and TCP (unless both fallbacks are
  disabled). Port `0` picks a free port.
- `server.close([callback])` — stop listening and close all connections.
- `server.address()`
- `server.handleConnection(socket)` — serve a TCP socket accepted elsewhere.
- `server.setTimeout([msecs][, callback])` / `server.timeout` — as in `node:http`:
  a connection idle for `msecs` emits `'timeout'` with its socket, and is destroyed
  if nothing listens. `0` (default) disables it; changes apply to new connections.
  TCP connections (HTTP/1.1, HTTP/2) — an HTTP/3 connection has QUIC's idle timeout.
- `server.handlePacket(msg, rinfo)` / `server.hasConnection(rinfo[, msg])` — feed UDP
  datagrams yourself when sharing a port (external socket mode). `hasConnection(rinfo)`
  asks by the sender's address; `hasConnection(rinfo, msg)` by the connection ID the
  datagram is addressed to — for servers sharing a port across threads, where a client
  whose address changed can reach one that does not hold its connection. Ask it before
  `handlePacket`: given a short-header packet for an ID it does not know, `handlePacket`
  answers with a Stateless Reset, which would end a connection another server holds.
- `server.addProtocol(name, handler, { sniff? })` — serve another protocol on the same
  TCP port: by ALPN `name`, or for TLS connections without ALPN, by
  `sniff(firstBytes) → true | false | null`. `handler(socket, protocol)`.
- `server.getTicketKeys()` / `setTicketKeys(keys)`,
  `getEchKeys()` / `setEchKeys(ech)`,
  `getValidateAddress()` / `setValidateAddress(on)`,
  `getResetTokenSecret()` / `setResetTokenSecret(secret)`,
  `getTokenSecret()` / `setTokenSecret(secret)` — change these at runtime.
- `server.setOptions(options)` / `server.getOptions()` — every other option that can
  change while the server runs, in one call, by the names `createServer` takes. See
  [Changing options while running](#changing-options-while-running).
- `server.getPendingHandshakes()` — HTTP/3 handshakes under way: connections made whose
  handshake is not complete (the client's Finished verified) and has not failed.
  What load is, and what to do about it, is the application's — see `'handshakeLoad'`:

  ```js
  // Retry (one round trip more) for new clients only while handshakes pile up.
  server.on('handshakeLoad', ({ high }) => server.setOptions({ validateAddress: high }));
  ```

  `maxHandshakesPerAddress` is a cap, not a judgement of load: an address with that
  many handshakes under way gets no more connections until some end. High enough for
  many clients behind one address (a carrier NAT); with Retry on, it counts only
  addresses that came back with a token.
- `server.getStats()` — the server's counters since it was made (a copy). Counts only:
  no addresses, names, headers or payloads. Codes are the protocol's, as hex strings,
  each mapped to how many times it was seen:

  | Field | Counts |
  |---|---|
  | `connections.quic` / `.tcp` | Connections taken: a QUIC Initial that began a handshake; a TCP socket accepted |
  | `handshakes.quic` / `.tcp` | `{ completed, failed }` — failed: an alert either way, a timeout, the client gone first |
  | `handshakes.resumed` | Completed with a session ticket |
  | `protocols` | `{ h3, h2, 'http/1.1', other }` — connections by the protocol they spoke |
  | `earlyData` | `{ accepted, rejected, tooEarly }` — 0-RTT the clients offered, and requests answered 425 |
  | `closes.quic` | `{ sent, received, silent }` — QUIC's CONNECTION_CLOSE by code (`'0x12f'`: a TLS alert, illegal_parameter); silent: ended with none (idle timeout, stateless reset) |
  | `closes.h3` | `{ sent, received }` — HTTP/3's CONNECTION_CLOSE by code (`'0x100'`: H3_NO_ERROR) |
  | `closes.h2` | `{ sent, received }` — HTTP/2 GOAWAY by code |
  | `closes.http1` | `{ sent }` — HTTP/1.1 requests refused before the application saw them, by status (`'400'`) |
  | `streamResets.h3` / `.h2` | `{ sent, received }` — RESET_STREAM / RST_STREAM by code |
  | `amplificationBlocked` | Datagrams held at the anti-amplification limit (RFC 9000 §8.1) until the client's address was validated |
  | `internalErrors` | Exceptions of ours caught in the QUIC and HTTP/3 layers — a bug, never the client's |
  | `since`, `uptime` | When counting began; milliseconds since |

  ```js
  setInterval(() => {
    const s = server.getStats();
    metrics.gauge('tls_failed', s.handshakes.quic.failed + s.handshakes.tcp.failed);
    metrics.gauge('h3_errors', Object.entries(s.closes.h3.sent).filter(([c]) => c !== '0x100').reduce((n, [, k]) => n + k, 0));
  }, 10000);
  ```

#### Changing options while running

`server.setOptions(partial)` changes what can change, by `createServer`'s names;
`server.getOptions()` returns all of them as they are now (a copy).

```js
const server = createServer({ key, cert, startupCap: 'stall', initialRtt: 100 }, app);

server.on('handshakeLoad', ({ high }) => {
  server.setOptions({ validateAddress: high, maxHandshakesPerAddress: high ? 16 : 64 });
});

server.setOptions({ startupCap: 'always' });          // returns server: chainable
const { startupCap, validateAddress } = server.getOptions();

try {
  server.setOptions({ startupCap: 'off', initialRtt: -5 });
} catch (e) {
  e.code;      // 'ERR_OUT_OF_RANGE' — "initialRtt must be between 10 and 10000 (ms), got -5"
  server.getOptions().startupCap;   // unchanged: one bad value, and nothing changes
}
server.setOptions({ cert });        // TypeError: "cert cannot be changed with setOptions(): use setSecureContext()"
```

| Option | Applies |
|---|---|
| `validateAddress` | from the next new client |
| `handshakeLoadThreshold` | at once (the count as it stands) |
| `maxHandshakesPerAddress` | from the next Initial |
| `earlyData`, `earlyDataMaxAge` | from the next handshake (`earlyData: false` refuses early data on tickets already given out too) |
| `startupCap`, `initialCongestionWindow`, `carefulResume`, `pmtuDiscovery`, `maxUdpPayloadSize`, `initialRtt`, `reorderWindow` | to HTTP/3 connections made from then on — those open keep theirs |

**One connection's.** The same two calls on a connection — the handle of `'connection'`
(its first packet) and `'secureConnection'`, and an HTTP/3 request's `req.socket`; on the
client, an HTTP/3 response's `res.socket`. Every request on that connection shares it.

```js
server.on('connection', (conn) => {
  if (conn.setOptions) conn.setOptions({ initialRtt: 80 });        // QUIC: before the handshake
});

app.get('/downloads/*', (req, res) => {
  if (req.socket.setOptions) req.socket.setOptions({ startupCap: 'always' });   // HTTP/3 only
  // …
});
```

Over TCP (HTTP/1.1, HTTP/2) there is no `setOptions`: these options are QUIC's. Some are
about how a connection begins, and past that point the call throws `ERR_INVALID_STATE`
rather than take a value that would do nothing:

| Option | On a running connection |
|---|---|
| `reorderWindow`, `startupCap` | any time (`startupCap` matters only while in Startup) |
| `pmtuDiscovery` | any time: off — probes stop, the size found stays; on — the search starts |
| `maxUdpPayloadSize` | any time: lower — packets shrink at once; higher — the search may go there |
| `initialRtt` | before the first RTT sample |
| `initialCongestionWindow` | before the first 1-RTT packet |
| `carefulResume` | before the handshake is confirmed |
| `transportParams` | not: they went out in the handshake (`connectionOptions` decides them) |
| `validateAddress`, `handshakeLoadThreshold`, `maxHandshakesPerAddress` | not: the server's |

A client sets them in its request options (`request`, `connect`, `WebTransport`,
`connectUdp`) for what it sends: `startupCap`, `initialCongestionWindow`, `pmtuDiscovery`,
`maxUdpPayloadSize`, `initialRtt`, `reorderWindow`.

**Events**

| Event | Arguments | |
|---|---|---|
| `'request'` | `(req, res)` | Same as the `requestListener` argument. |
| `'upgrade'` | `(req, socket, head)` | WebSocket and other upgrades, on all three versions — see [WebSocket](#websocket-1). With no listener, an upgrade request arrives as an ordinary `'request'`, as in Node (see `shouldUpgradeCallback`). |
| `'connectUdp'` | `(req, tunnel)` | A request to proxy UDP (RFC 9298), on all three versions — see [CONNECT-UDP](#connect-udp-proxying-udp). With no listener, such a request arrives as before (`'upgrade'` or `'request'`). |
| `'timeout'` | `(socket)` | A TCP connection was idle for `server.timeout` ms. |
| `'connection'` | TCP: the socket, before TLS. QUIC: a connection handle, on the first packet. | Destroy it here to refuse a peer before any crypto is done. |
| `'secureConnection'` | TCP: the TLS socket. QUIC: the connection handle. | After the handshake. |
| `'stream_open'` | `(conn, streamId)` | HTTP/2 and HTTP/3: a request stream announced itself, before its headers are decoded. |
| `'handshakeLoad'` | `({ pending, high })` | HTTP/3 handshakes under way reached `handshakeLoadThreshold` (`high: true`), or are back under half of it (`high: false`). |
| `'stream_reset'` | `(conn, streamId, code)` | HTTP/2 RST_STREAM; HTTP/3 RESET_STREAM or STOP_SENDING — once per stream. A default limit applies (`streamResetBurst`, `streamResetRate`); this is for a policy of your own on top, for both versions. |
| `'OCSPRequest'` | `(certificate, issuer, callback)` | As `node:tls`: a client asked for the certificate's OCSP status, TCP or QUIC. `certificate` and `issuer` are DER `Buffer`s (`issuer` `null` when the chain has none); `callback(null, response)` staples a DER OCSP response, `callback(null, null)` none, `callback(err)` fails the handshake. The handshake waits for the answer — fetch and cache responses ahead of time. Without a listener nothing is stapled. (Chromium asks over TCP, not over QUIC.) |
| `'tlsClientError'` | `(err, socket \| conn)` | A handshake failed, as in `node:tls`: over TCP the TLS socket, over QUIC the connection handle. Either side may have ended it — plain HTTP sent to the TLS port (`ERR_SSL_WRONG_VERSION_NUMBER`), no common ALPN, or a client refusing the certificate (`ERR_TLS_ALERT_RECEIVED`, `err.alert` = 42 for `bad_certificate`). |
| `'clientError'` | `(err, socket)` | HTTP/1.1, once the connection is up (parse errors, the socket's errors). TLS handshake failures are `'tlsClientError'`. |
| `'sessionError'` | `(err, session)` | HTTP/2: the connection failed (a protocol error — GOAWAY already sent —, the socket's error, a peer not reading past `maxSessionMemory`). `session` is the connection handle of `'stream_open'`. As `node:http2`. |
| `'listening'` | | |
| `'error'` | `(err)` | |

The `conn` handle given to the HTTP/2 and HTTP/3 stream events has `remoteAddress`,
`remotePort`, `fingerprint()`, `sendRstStream(streamId, 'refused' | 'cancelled' | code)`,
`goaway([code])` and `destroy([code])` — the same on both versions, so one rate limiter
serves both:

- `goaway()` stops new requests; those already in flight finish. HTTP/2 sends GOAWAY;
  HTTP/3 sends GOAWAY too, refuses any later request with `H3_REQUEST_REJECTED` (safe for
  the client to retry elsewhere), and closes the connection once the last response has
  been delivered. `goaway('overloaded')` says why: `ENHANCE_YOUR_CALM` / `H3_EXCESSIVE_LOAD`.
- `destroy()` cuts the connection now, in-flight requests included (`'overloaded'` or a
  number sets the HTTP/3 close code).

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

Issues an HTTP request — HTTP/3 first, falling back to HTTP/2 and HTTP/1.1. Returns a
[`ClientRequest`](#clientrequest). Accepts a URL string, an options object, or both
(options override the URL). Requests are always made over TLS.

**Options**

| Option | Type | Default | Description |
|---|---|---|---|
| `hostname` / `host` | `string` | `'localhost'` | Target host. |
| `port` | `number` | `443` | Target port. |
| `path` | `string` | `'/'` | Request path including query string. |
| `method` | `string` | `'GET'` | HTTP method. |
| `headers` | `object` | `{}` | Request headers. |
| `priority` | `object` | — | `{ urgency: 0..7, incremental }` — the request's priority (RFC 9218), as the `priority` header; `req.setPriority()` changes it later. |
| `ech` | `Buffer \| string` | — | The server's ECH key list (an ECHConfigList; base64 — the `ech=` of its HTTPS record — or bytes): the ClientHello goes encrypted, on every version. See [ECH](#encrypted-client-hello-ech). |
| `echGrease` | `boolean` | `true` | Without `ech`: send GREASE ECH, as browsers do. |
| `ecdhCurve` | `string` | `'auto'` | The key-exchange groups to offer, in order — `node:tls`'s option, on every version. `'auto'` is what `node:tls` offers and the browsers do: the post-quantum hybrid X25519MLKEM768 first, with an X25519 share beside it (a server without it needs no retry), then X25519, P-256, P-384 — the hybrid where Node has ML-KEM (24.7+), the classical groups alone before that. `'X25519:P-256'` and the like for classical only; `'MLKEM1024'`, `'SecP384r1MLKEM1024'` and the other post-quantum groups by name (see [Post-quantum TLS](#post-quantum-tls)). A name not implemented, or the hybrid in a Node without ML-KEM (it needs 24.7+ on OpenSSL 3.5), throws from `request()`. A request shares only connections opened with the same groups. |
| `startupCap` | `'stall'` \| `'always'` \| `'off'` | `'stall'` | HTTP/3: Startup's window cap on what the client sends (an upload) — as the server's option. |
| `pmtuDiscovery`, `maxUdpPayloadSize`, `initialRtt`, `reorderWindow`, `initialCongestionWindow` | | | HTTP/3: this client's connection options — as the server's. `res.socket.setOptions()` changes them while it runs. |
| `rejectUnauthorized` | `boolean` | `true` | Verify the server certificate. Set `false` for self-signed certs. |
| `ca` | `Buffer \| string \| Array` | `null` | Trust these CAs instead of the platform roots (as in Node). |
| `sigalgs` | `string` | lemon-tls's list | The signature schemes to offer, in order — `node:tls`'s option. `'mldsa65:mldsa87:ecdsa_secp256r1_sha256'` asks a server that holds an ML-DSA certificate for it; the default offers ML-DSA after the classical schemes. A request shares only connections opened with the same list. |
| `key`, `cert`, `passphrase` | | — | A client certificate, for a server that asks for one — on HTTP/3, HTTP/2 and HTTP/1.1. A request with one shares only connections opened with the same certificate (see `Agent`). |
| `earlyData` | `boolean` | `false` | With a session whose ticket allows it, send a `GET`, `HEAD` or `OPTIONS` in the first flight (0-RTT) — on every version. Refused or answered `425`, it is sent again after the handshake by itself; `res.earlyData` says what happened. See [0-RTT](#0-rtt-early-data). |
| `session` | `Buffer` | the agent's | A TLS session to resume with, from an earlier `'session'` event (as `https.request`). Without it the agent offers its own (see `Agent`). |
| `requestOCSP` | `boolean` | `false` | Ask the server for its stapled OCSP response (`tls.connect`'s option), on every version; it comes as the request's `'OCSPResponse'` (a DER `Buffer`). Only a full handshake carries one — a resumed session has no certificate. |
| `quicVersions` | `Array` | `['v1', 'v2']` | HTTP/3: the QUIC version of the first flight, then the others it offers (RFC 9368) — a server that prefers v2 moves the connection there. `['v2']`: v2 from the first packet. |
| `agent` | `Agent \| false` | `globalAgent` | Connection pool to use. `false`, as in Node: a connection of this request's own, closed when it is done (over HTTP/2 and HTTP/1.1 it went on a pool shared by every `agent: false` request), and no sessions kept — pass `session` to resume. |
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

Same as `request()` with `method: 'GET'`. (`request()` itself ends GET and HEAD
requests on the next tick.)

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
| `earlyData` | Server: `true` if the request came in 0-RTT (it could be a replay). Client: `'accepted'` (sent early, taken), `'rejected'` (sent again after the handshake), `null` (not sent early). |
| `socket` / `connection` | Compatibility shim for frameworks |

Standard `Readable` behaviour applies: `'data'`, `'end'`, `'error'`, `pipe()`,
`for await (const chunk of req)`, and `setTimeout(ms, cb)`.

A body cut short — on the server, a request the client cancels or whose connection
drops; on the client, a response the server resets or cuts off — gets `aborted = true`,
an `'aborted'` event, an `'error'` (`ECONNRESET`, or the cause) only if something listens
for one, and `'close'`; never `'end'`, which would say the body arrived whole, and never
an unhandled `'error'`, because a browser cancelling a request is ordinary traffic. This
is node:http's behaviour, on all three versions. HTTP/2 requests have
`req.h2Fingerprint()`, HTTP/3 requests `req.h3Fingerprint()`; over HTTP/2 and HTTP/3,
`req.headers` also keeps the pseudo-headers (`:method`, `:path`, `:authority`, …), as
`node:http2` does, plus `host` taken from `:authority`.

A request handler that throws ends only its own exchange — HTTP/1.1 answers `500` and
closes the connection, HTTP/2 and HTTP/3 reset that one stream (`INTERNAL_ERROR`,
`H3_INTERNAL_ERROR`), and other requests on the connection go on — and the exception is
then rethrown on the next tick, so it reaches `process.on('uncaughtException')` (or ends
the process) exactly as in Node. A response already ended before the throw is delivered.

---

### `ServerResponse`

A Node.js `Writable` stream.

- `res.writeHead(statusCode[, statusMessage][, headers])`
- `res.setHeader(name, value)` / `getHeader` / `getHeaders` / `getHeaderNames` /
  `hasHeader` / `removeHeader`
- `res.flushHeaders()`
- `res.write(chunk)` / `res.end([chunk])` — over HTTP/1.1, a body given whole to `end()`
  (nothing written before it) is sent with `Content-Length`, otherwise chunked, as
  `node:http` does
- `res.statusCode`, `res.headersSent`
- `res.writeEarlyHints(hints[, callback])` — `103 Early Hints`, on all three versions
- `res.destroy([err])` / `req.destroy([err])` — give up on the exchange, as in Node: the
  stream is reset, the connection serves on. HTTP/3: RESET_STREAM and STOP_SENDING with
  `H3_REQUEST_CANCELLED` (`H3_INTERNAL_ERROR` with an `err`; RFC 9114 §4.1.1); after a
  finished response, only STOP_SENDING with `H3_NO_ERROR` for a request body still
  coming. HTTP/2: RST_STREAM `CANCEL` (`INTERNAL_ERROR` with an `err`). HTTP/1.1: the
  socket. Both went unsent: a destroyed exchange held its stream until the idle timeout.
- `res.addTrailers({ … })` before `end()` — response trailers, on all three versions
  (HTTP/1.1 chunked; HTTP/2 and HTTP/3 a HEADERS frame after the body). What gRPC
  answers with: `grpc-status` / `grpc-message` go only there. A request's trailers are in
  `req.trailers` / `req.rawTrailers` by `'end'`; on the client, `res.trailers`
- `res.setPriority({ urgency, incremental })` — HTTP/2 and HTTP/3 (over HTTP/1.1, one
  response at a time, it does nothing — the same handler runs on all three): the response's
  priority (RFC 9218: urgency 0..7, 0 first, default 3; incremental: shares the
  connection with others of its urgency rather than going whole, one at a time). Without
  it, the client's `priority` header and `PRIORITY_UPDATE` frames decide; set, it is the
  server's decision and later signals from the client do not override it. The client's
  header is in `req.headers.priority`. See
  [Stream scheduling](#stream-scheduling-byte-level-round-robin-by-priority).

For WebTransport sessions, `ServerResponse` additionally exposes
`sendDatagram()`, `maxDatagramSize()`, `datagrams`, `getStats()`, `createBidirectionalStream()`,
`createUnidirectionalStream()`, `canOpenStream()`, `createSendGroup()`, `setWebTransportProtocol()`,
`closeSession()` and `drainSession()` — see
[WebTransport](#webtransport-1).

---

### `ClientRequest`

A Node.js `Writable` stream.

- `req.write(chunk)` / `req.end([chunk])` — the body streams, as `node:http`'s does: written
  while the connection is being made it is held (past 64 KB `write()` returns `false`, then
  `'drain'`), and from then on it goes as it is written, with the transport's backpressure —
  the QUIC stream's, HTTP/2's window, the socket's. Over HTTP/1.1 a body not yet complete goes
  chunked, unless a `content-length` was set: the bytes must then add up to it (too many or too
  few fails the request with `ERR_HTTP_CONTENT_LENGTH_MISMATCH`; on a pooled connection the
  difference would be read as another request). The first protocol to be ready takes the
  request, and only it sends: a request whose answer takes HTTP/3 longer than `h3Timeout` is not
  sent over TCP as well. The first 64 KB of a body are kept, so that a request refused
  unprocessed (`REFUSED_STREAM`, `H3_REQUEST_REJECTED`, past a GOAWAY), or whose protocol failed
  before it was sent, goes again whole; a larger one that has started cannot, and fails.
- `req.addTrailers({ … })` before `end()` — request trailers (`node:http`'s), on all three
  versions: a HEADERS frame after the body over HTTP/2 and HTTP/3, after the last chunk over
  HTTP/1.1 (so only chunked, as in `node:http`). Connection-specific and forbidden fields are
  dropped, as for responses.
- `req.setPriority({ urgency, incremental })`, or the `priority` option of `request()` — the
  request's priority (RFC 9218: urgency 0..7, 0 first, default 3; incremental: its response
  may share the connection with others of its urgency). Before the request goes it is the
  `priority` header (`'u=1, i'`; the default sends none), on all three versions; after, a
  `PRIORITY_UPDATE` frame over HTTP/2 and HTTP/3 (HTTP/1.1 has none — nothing is sent). It
  is the client's signal: a server whose application set the response's priority
  (`res.setPriority`) keeps its own.
- `req.abort()` / `req.destroy([err])` — stop the exchange where it is carried: the
  request's stream over HTTP/3 and HTTP/2 (a pooled connection serves on), the socket over
  HTTP/1.1. `res.destroy()` on an unfinished response does the same. A request the server
  reset after it was sent — a non-idempotent one (RFC 9110 §9.2.2) — fails with the reset,
  and is not sent again over another version; one it refused is. As in Node, the response then sees `'aborted'` and `'close'` (an `'error'` only
  if it listens for one), never `'end'`; `destroy()` before any response fails the request
  with `ECONNRESET` (`socket hang up`), `abort()` emits `'abort'` and no error.
- `req.protocol` — which transport was actually used: `'h3'`, `'h2'` or `'https'`
- Events: `'response'`, `'error'`, `'timeout'`, `'session'` (a `Buffer`: a TLS session the
  server sent, to resume with — as a `TLSSocket`'s, once per ticket, on the request that
  opened the connection), `'OCSPResponse'` (with `requestOCSP`: the server's stapled OCSP
  response, DER, on the request that opened the connection)
- A request the server did not process — refused (HTTP/2 `REFUSED_STREAM`, HTTP/3
  `H3_REQUEST_REJECTED`) or past its `GOAWAY` (a server that closes its connections after
  `maxRequestsPerSocket` requests does that to the ones in flight) — is sent again once,
  on a new connection (RFC 9113 §8.7, RFC 9114 §4.1.1, §5.2). When every protocol fails,
  the `'error'` has the last one's reason as its `cause`.

---

### `Agent`

Connection pool and protocol cache, analogous to `https.Agent`.

```js
import { Agent } from 'quico';

const agent = new Agent({
  http2: true,          // allow H2 in the fallback chain
  http1: true,          // allow H1.1 in the fallback chain
  h3Timeout: 3000,      // ms before falling back from H3
  maxSockets: 256,      // HTTP/1.1 sockets per origin; more requests wait
  maxCachedSessions: 100, // TLS sessions kept to resume with
  ecdhCurve: 'X25519:P-256'  // its requests' key exchange (default 'auto': post-quantum first), unless one names its own
});

quico.request({ hostname: 'example.com', agent }, handler).end();
```

HTTP/2 and HTTP/3 multiplex every request to an origin over one connection, which
the agent keeps and shares. HTTP/1.1 needs a socket per request, and for those the
agent takes `node:http.Agent`'s options, with Node's meanings:

| Option | Default | |
|---|---|---|
| `keepAlive` | `true` | Keep a socket for the next request (Node's `globalAgent` default; a plain `new http.Agent()` defaults to `false`). |
| `keepAliveMsecs` | `1000` | TCP keep-alive initial delay on kept sockets. |
| `maxSockets` | `256` | Sockets per origin at once. Requests beyond it wait for a socket. |
| `maxFreeSockets` | `256` | Idle sockets kept per origin. |
| `timeout` | `5000` | How long an idle socket is kept. |

**Protocol discovery.** The agent remembers which protocol worked for each origin,
and separately what each origin advertises in `Alt-Svc` (RFC 7838), for its `ma=`
lifetime. When an origin advertises HTTP/3 — on its own port or another — the next
request tries HTTP/3 there first, and falls back to the origin over TCP (or its own
HTTP/3) if that fails; a failed alternative is left alone for five minutes, as
browsers do. Concurrent requests to an origin share one connection.

**Which connections a request shares.** As `https.Agent` names its connections
(`agent.getName(options)`), a pooled connection is keyed by its origin and its TLS
identity — `ca`, `cert` / `key`, `rejectUnauthorized`, `servername` (hashed). A
connection opened with `rejectUnauthorized: false` never carries a request that
verifies, nor one verified against a private `ca` a request that trusts the public
roots; before, any connection to the origin was reused. The same goes for the
standalone `h1Request` / `h2Request` pools.

**Session resumption.** As `https.Agent`, the agent keeps the TLS sessions each
origin's server sent — up to 4 per origin, newest last; `maxCachedSessions` (default
`100`, the oldest dropped; `0` keeps none) bounds the origins — and a new connection
resumes with one — no certificate exchange — over HTTP/3, HTTP/2 and HTTP/1.1, and for
`WebSocket` (`wss://`) and `connectUdp` too. Each session is used **once** (RFC 8446
§C.4): two connections opened at once take two, so they cannot be linked, and both can
send 0-RTT — with one kept per origin, the second's early data was always refused as a
replay. A QUICO server sends two tickets per full handshake (one per resumption), as
OpenSSL and BoringSSL do. An expired session is not offered (lemon-tls `sessionInfo`).
TCP sessions are kept per ALPN (`h2`, `http/1.1`): a ticket carries 0-RTT only for the
protocol it was issued under. Before, every connection was a full handshake, and a QUICO server
never saw its own ticket again: what it saves there about the path (Careful Resume,
above) is only used by a client that resumes. A session is offered only where it was
made: the same transport (a TCP session is not offered to QUIC), origin, server name and
verification — one from a connection with `rejectUnauthorized: false`, or another `ca`, is
not offered to one that verifies. A session the handshake fails with is dropped. A
resumed connection reports the server's certificate and `authorized` from the session, as
Node does. For QUIC it also keeps the server's NEW_TOKEN token (RFC 9000 §8.1.3) — used
once, by the next connection, which then needs no proof of address.

`quico.globalAgent` is the default instance used when no `agent` option is given.
Call `agent.destroy()` to close everything it pools.

---

### `quico.createSecureContext(options)`

Creates a TLS context for use with `SNICallback`. Accepts `key`, `cert` and `ca`.
Re-exported from LemonTLS.

---

### 0-RTT (early data)

A returning visitor's request can go in its first flight, with the ClientHello, under a
key from its last session — the answer comes one round trip sooner. On a phone at
150 ms RTT, that is 150 ms off the first byte of every page that opens a new connection.
It works the same on every version: over HTTP/3 in QUIC's 0-RTT packets, and over TLS 1.3 on
TCP (HTTP/2, HTTP/1.1) as TLS early data — with Encrypted Client Hello as well (the early
data is the inner hello's, RFC 9849 §6.1). Chromium and Firefox send 0-RTT over HTTP/3.

The price: early data has no protection against replay. Someone who captured the first
flight can send it again, and the server would run the request again. So it is **off by
default**, and turned on it is held to four rules:

1. **A ticket carries early data once.** The server remembers each ticket's early data
   (`earlyDataReplay`, in memory by default) for twice `earlyDataMaxAge`; the second time,
   the handshake goes on without it.
2. **Only for a short while.** The age the client states for its ticket must be within
   `earlyDataMaxAge` (10 s) of what the server measures — a captured flight goes stale.
3. **Only under the same settings.** A ticket from before a change of transport
   parameters or of the HTTP/3 SETTINGS this server sends (or a restart with other ones),
   or one a connection with lower limits (`connectionOptions`) would not honour, resumes
   the session without early data: a client sends its early data under what it remembered
   (RFC 9000 §7.4.1, RFC 9114 §7.2.4.2).
4. **Only safe requests.** `earlyDataFilter` decides which requests may run before the
   handshake completes — by default `GET`, `HEAD` and `OPTIONS`; the others get
   `425 Too Early` and the client sends them again once the handshake is done (RFC 8470),
   by itself — a browser does, and so does `quico.request`.

Refused early data costs nothing but the round trip saved: the request is served as it
would have been without it.

```js
const server = quico.createServer({
  key, cert,
  ticketKeys,                       // stable keys, or tickets die with the process
  earlyData: true,
  earlyDataFilter(req, cb) {        // asynchronous: a database, a rule engine
    if (req.url.startsWith('/api/')) return cb(null, false);   // → 425, after the handshake
    cb(null, true);
  }
}, (req, res) => {
  // req.earlyData: this request may be a replay — never act on it (a payment,
  // a login) without the handshake; the filter is where to say so.
  res.end('hello');
});
```

**A restart.** The default store is in memory and starts empty: a ticket issued before a
restart (with `ticketKeys` kept) gets no early data for twice `earlyDataMaxAge` after it —
a flight captured just before the restart cannot be sent again just after it. One 1-RTT
handshake for such a client, and its new ticket is fine.

**More than one server.** Each server remembers in its own memory, so a flight captured
at one could be replayed at another that shares `ticketKeys`. Give them one store:

```js
const server = quico.createServer({
  key, cert, ticketKeys, earlyData: true,
  // id: the ticket (a SHA-256, hex); ttl: how long to remember it, ms.
  earlyDataReplay(id, ttl, cb) {
    redis.set('0rtt:' + id, '1', 'PX', ttl, 'NX', (err, ok) => cb(err, ok === 'OK'));
  }
});
```

`server.setOptions({ earlyData: false })` turns it off at once — tickets already given out
included.

**What the client remembers.** Each session keeps, with the ticket, the server's transport
parameters and its HTTP/3 SETTINGS; early data goes within them (RFC 9000 §7.4.1, RFC 9114
§7.2.4.2). A server that accepts the 0-RTT and then gives less — a transport parameter
lower than remembered, a setting omitted or lower — breaks the connection it took the
early data on: the client closes it, `PROTOCOL_VIOLATION` or `H3_SETTINGS_ERROR`, naming
what changed.

**The client.** `earlyData: true` on a request with a session (its own, or the agent's):

```js
const req = quico.request('https://example.com/', { earlyData: true }, (res) => {
  console.log(res.earlyData);   // 'accepted', 'rejected' or null
});
req.end();
```

Only `GET`, `HEAD` and `OPTIONS` are sent early; anything else waits for the
handshake. Refused — by the server's TLS, or with a `425` — the request is sent again after
the handshake, and the response is the one to that.

**Over TCP.** The same options, the same checks (one use per ticket, the age, the context —
a ticket from the HTTP/3 side carries no early data here, nor the other way round), the same
`earlyDataFilter` and `425`. A ticket allows up to 16 KB of early data — room for a request,
not an upload; what does not fit goes after the handshake. The server reads the early
request as it comes and may answer as soon as its own handshake flight is out, so the
client has the answer one round trip after its first flight.

---

### Encrypted Client Hello (ECH)

Without ECH, the first message of every TLS connection — the ClientHello, with the
site's name (SNI) and the ALPN list — crosses the network in the clear: anyone on the
path sees which site is being visited, HTTPS or not. With ECH (RFC 9849) the browser
sends the real ClientHello encrypted, inside an outer one that names only a shared
*public name*, to a key the server publishes in its DNS HTTPS record. The server
decrypts it and the handshake goes on as usual — `SNICallback` gets the real name.

ECH hides names that **share an address**: when many sites sit behind one IP and one
public name (a CDN, a host with many domains), the network sees only which group. A
single site on its own IP is still known by the IP.

**1. A key, kept across restarts** — like DNSSEC keys:

```js
import quico from 'quico';
const k = quico.generateEchKey({ publicName: 'ech.example.com' });
// save k.config and k.privateKey (bytes); publish k.configListBase64 in DNS
```

**2. The DNS record** — the `ech` key of the domain's HTTPS record (RFC 9460), e.g.
with [dnssec-server](https://github.com/colocohen/dnssec-server):

```
www  IN HTTPS 1 . alpn="h3,h2" ech="AEb+DQBC…"
```

**3. The server** — with a certificate for the public name as well, served when a
client's key could not be used:

```js
const server = quico.createServer({
  SNICallback: (name, cb) => cb(null, contexts[name]),   // incl. ech.example.com
  ech: { keys: [{ config: saved.config, privateKey: saved.privateKey }] },
}, (req, res) => {
  res.end(req.socket.servername + ' ' + req.socket.echStatus);
});
```

`req.socket.echStatus` is `'accepted'` (the hidden name was used), `'rejected'` (the
client's key was not one of ours: the handshake ran as the public name, and the client
was sent our current keys — `retry_configs` — to connect again with), or `null` (no ECH
offered). `req.socket.echAccepted` is the boolean.

**Rotation** — new key in DNS first, then on the server, the old one kept with
`retry: false` until the old record's TTL has passed:

```js
server.setEchKeys({ keys: [
  { config: next.config, privateKey: next.privateKey },
  { config: prev.config, privateKey: prev.privateKey, retry: false },
] });
```

The key itself is not certified by anyone: its trust comes from DNS (DNSSEC, and
DNS-over-HTTPS on the client). A substituted key could reveal which name was asked
for, never let anyone impersonate the site — the certificate is still checked against
that name. Tested against Go's `crypto/tls` client (accept, retry, HelloRetryRequest,
resumption); DTLS is not covered.

#### The client

`quico.request`, `WebTransport` and `connectUdp` take the server's key list as `ech` —
the `ech=` value of its HTTPS record (base64), or the bytes. The real ClientHello goes
encrypted, over HTTP/3, HTTP/2 and HTTP/1.1 alike:

```js
const req = quico.request({ hostname: 'www.example.com', path: '/', ech: 'AEb+DQBC…' }, (res) => {
  console.log(res.socket.echStatus);   // 'accepted'
});
req.end();
```

`res.socket.echStatus` (and `echAccepted`) on every version: `'accepted'`, `'grease'`, or
`null`. When the server cannot use the key (it rotated its keys, say), it proves itself
for the public name and sends its current keys; the request is tried once more with
them, automatically. The agent keeps those keys (RFC 9849 §6.1.8) and uses them first on
the next requests given the same `ech` — `quico.request` and `connectUdp` — so a server
that rotated its keys costs one retry, not one per connection until your DNS has the new
ones. They are kept as TLS sessions are: per origin and TLS settings, a day at most, none
with `agent: false` or `maxCachedSessions: 0`. Rejected in their turn, they are forgotten
and your `ech` is tried again. If it sends none — its ECH is off — the request fails with
`ERR_ECH_REJECTED` (`err.retryConfigs` null) instead of falling back to a ClientHello
in the clear: going on without ECH is the caller's decision.

Without `ech`, the client sends **GREASE ECH** (RFC 9849 §6.2), as Chrome and Firefox
do: an ECH extension no server can decrypt, so that clients that do use ECH do not stand
out. `echGrease: false` turns it off. QUICO does not look up HTTPS records itself (no
DNS-over-HTTPS here): the application passes the key list it resolved.

ECH is TLS 1.3 only. Tested against Go's `crypto/tls` server (accept, retry,
HelloRetryRequest, GREASE) and QUICO's own server, over QUIC and TCP.

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

**Only over HTTP/3.** A WebTransport session is an extended CONNECT over HTTP/3 (RFC 9220).
When one is asked for over HTTP/1.1 or HTTP/2, the server answers it itself: **`501` with no
body** (`content-length: 0`, `cache-control: no-store`). The request never reaches the handler,
`'request'` or `'upgrade'`. Two signs mark such a request, and either one is enough:

- the browser's Fetch destination, `Sec-Fetch-Dest: webtransport`;
- an extended CONNECT for `:protocol: webtransport` over HTTP/2.

A browser that cannot reach HTTP/3 may still send its session request over TCP. Firefox 158 does
this when HTTP/3 has been excluded for an origin: it sends a plain `GET` with
`Sec-Fetch-Dest: webtransport` on a new HTTP/1.1 connection. If that request were answered as a
page, the body would land in the browser's WebTransport session, and Firefox would abort the whole
browser. With the `501`, the session fails cleanly (`wt.ready` rejects in the page), and the page
can fall back to WebSocket.

**Datagrams** (`res.sendDatagram(data)`) are never retransmitted, but they are sent under
the connection's congestion control (RFC 9221 §5.4): they wait for room in a packet and
go ahead of stream data. While the path cannot keep up, the oldest are dropped — any that
have waited 250 ms, and past 1 MB queued. `sendDatagram` returns `true` when the datagram
is queued, `false` when it cannot be sent at all (larger than `res.maxDatagramSize()`, or
the peer takes no datagrams). Datagrams sent right after accepting the session are held
until the `200` has left: a browser drops datagrams for a session it does not know yet.

`res.datagrams` is the browser's datagrams object too — the client's `wt.datagrams`,
the same code: `readable`, `createWritable({ sendOrder, sendGroup })`, `maxDatagramSize`,
`incomingMaxAge`, `outgoingMaxAge`, `incomingMaxBufferedDatagrams` and
`outgoingMaxBufferedDatagrams`, as the current W3C spec has them. Each writable has its own
queue and backpressure: `writer.ready` waits while `outgoingMaxBufferedDatagrams` of its
datagrams wait to go. A write that is not an `ArrayBuffer` or a view onto one, or is
empty, rejects with a `TypeError`; one larger than `maxDatagramSize` is dropped. The
setters take values as the browser's do: an age of `0` is no limit (`null`), a negative
one is a `RangeError`; a buffer count below 1 is 1. Its `outgoingMaxAge` is the session's
own: sessions on one connection share its queue, each with its own age limit and its own
count of datagrams dropped. The names from before the spec changed still work, for code
written then: `datagrams.writable` (one writable, made on first use) and
`incomingHighWaterMark` / `outgoingHighWaterMark` (the same settings as
`…MaxBufferedDatagrams`).

**Statistics** — `res.getStats()`, as the client's `wt.getStats()` (the same function):
a Promise of the browser's `WebTransportConnectionStats` — `bytesSent` (the application's
bytes: new stream data and datagram payloads, without framing or retransmissions),
`bytesSentOverhead` (what the packets carried besides), `bytesAcknowledged` (the payload the
peer acknowledged), `packetsSent`, `packetsLost` and `bytesLost` (packets of stream data or
datagrams declared lost, and their size), `bytesReceived`, `packetsReceived` (whole
packets), `smoothedRtt`,
`rttVariation`, `minRtt` (ms), `estimatedSendRate` (bits/s, the congestion control's
bandwidth estimate; `null` until measured), `atSendCapacity` (the congestion window is
full) — with QUICO's `congestionWindow` and `bytesInFlight` besides, and `datagrams`:
`{ droppedIncoming, expiredIncoming, expiredOutgoing, lostOutgoing }`, this session's.
The connection's figures are shared by every session on it, as in the browser. A sender
that has to choose what to drop for a slow receiver reads `atSendCapacity`, or
`bytesInFlight` against `congestionWindow`: the congestion is the connection's, not one
stream's.

**Keying material** — `res.exportKeyingMaterial(label, context, outputLength)`, as the
client's `wt.exportKeyingMaterial()`: a Promise of `outputLength` bytes (1 to 4096) from the
TLS exporter, this session's own (draft-ietf-webtrans-http3: the label
`EXPORTER-WebTransport`, the session ID, the application's label and context, each at most
255 bytes). Both ends get the same bytes for the same label and context, which lets a token
be bound to the session it was sent on.

**Priorities** are the browser's: a stream's `sendOrder` and `sendGroup`
(`stream.sendGroup = res.createSendGroup()`), and `res.sendDatagram(data, { sendOrder,
sendGroup })` as the browser's `datagrams.createWritable({ sendOrder, sendGroup })`. The
groups of a session share its sending equally; within a group the highest `sendOrder`
with something to send goes first, equal orders taking turns; a stream in no group is in
the session's own. Datagrams sent without them go ahead of every stream. The session's
urgency — the CONNECT request's `priority`, or `res.setPriority()` — is its streams'.

**Streams** are Node streams: a `Duplex` for a bidirectional stream, a `Readable` for the
client's unidirectional one (`'unidirectionalStream'`), a `Writable` for ours. What the
client sends is credited back to it as the application reads, so a stream nobody reads
holds one stream window (256 KB bidirectional, 128 KB unidirectional, or as set with
`transportParams`), not the whole upload. Each direction can be given up with an
application error code (32-bit, mapped onto HTTP/3's codes as draft-ietf-webtrans-http3
§4.4 defines), on its own — as in the browser, the two directions of a bidirectional
stream are independent:

| | |
|---|---|
| `stream.resetStream(code[, { reliableSize }])` | Stop sending: what was written and not yet sent is dropped. A browser's reader fails with `streamErrorCode`. With `reliableSize`, the first that many bytes written still arrive whole before the reset (RESET_STREAM_AT, draft-ietf-quic-reliable-stream-reset) — a MOQT subgroup's header, say; the stream's own WebTransport header always does (draft-ietf-webtrans-http3 §4.4), so the peer knows its session. Needs a peer that takes RESET_STREAM_AT (`stream.reliableResetSupported`; QUICO advertises it); otherwise a RESET_STREAM. Also after `end()`, until all of it is acknowledged (RFC 9000 §3.1) — a MOQT subgroup past its delivery timeout is dropped, not sent to the end. Returns `true` when a reset went, `false` when there was nothing left to reset. |
| `stream.stopSending(code)` | Stop reading (STOP_SENDING): the peer stops. A browser's writer fails with `streamErrorCode`. |
| `stream.destroy()` | Both, with code 0, for whatever direction is unfinished. |
| `'peerReset'` (`code`) | The peer stopped sending (RESET_STREAM): our reading is over — what was read stands, the readable side ends, and its WHATWG `readable` fails with the code. Our writing goes on. |
| `'peerStopSending'` (`code`) | The peer stopped reading (STOP_SENDING): our writing is over — writes from now on are dropped, the WHATWG `writable` fails. Our reading goes on. |
| `stream.streamErrorCode` | The peer's code from either (`null` if it sent none). |
| `'committed'` | Our sending part is "all data committed" (draft-ietf-webtrans-overview §4.3; "Data Recvd", RFC 9000 §3.1): every byte written and the FIN acknowledged by the peer. Once; never for a stream reset first. `'finish'` (and `end()`'s callback) only says the bytes were handed to QUIC — a delivery deadline (MOQT's SUBGROUP_DELIVERY_TIMEOUT) runs from the FIN to here, and `resetStream()` before it drops what is left. `sendState` is then `'committed'`. |
| `stream.id`, `stream.sessionId` | Its QUIC stream ID, and its session's — read-only. |
| `stream.sendState`, `stream.recvState` | Each direction, read-only: `'open'`, `'finished'` (the FIN sent / received), `'committed'` (ours: all of it and the FIN acknowledged), `'reset'` (we gave up sending / the peer did), `'stopped'` (the peer asked us to stop / we stopped reading); `null` for the direction a unidirectional stream does not have. A `'drain'` says the writer may write; `sendState` says whether what it writes still goes anywhere. |
| `'close'` | Once both directions are over — by FIN, reset or stop, from either side, in any order. When the peer's reset or stop is what ends the last one, an `Error` (`ERR_WEBTRANSPORT_STREAM_RESET` / `ERR_WEBTRANSPORT_STOP_SENDING`) goes to an `'error'` listener — only if there is one. `pipe()` adds a listener of its own that re-throws, as it does for a `net.Socket`: a stream piped with `pipe()` needs an `'error'` listener of yours, or use `stream.pipeline()`. The session's end is not such a cancel: when the peer closes the session it resets the streams with `WT_SESSION_GONE`, and they close without an `'error'`. |

**Opening streams** is the browser's: `res.createBidirectionalStream(options[, callback])`
and `res.createUnidirectionalStream(options[, callback])` take `{ sendOrder, sendGroup,
waitUntilAvailable }` and return the stream at once, in Node's way (`net.connect`'s).
Past the client's `MAX_STREAMS` without `waitUntilAvailable` they return `null`
(`res.canOpenStream({ bidirectional })` says beforehand); with it, the stream is opened
and its bytes wait for the client to allow more. Until then `stream.pending` is `true`;
when it is open, `'ready'` and `callback(null, stream)` — or `callback(err)` (code
`ERR_WEBTRANSPORT_STREAM_NOT_OPEN`) if it was given up first, its session closed.

```js
const st = res.createUnidirectionalStream({ waitUntilAvailable: true, sendOrder: 5 }, (err) => {
  if (err) return;          // never opened: the session went first
  // open: the client has allowed it
});
st.write(object);           // may be written at once; it waits with the stream
```

**The subprotocol** — the browser's `new WebTransport(url, { protocols: [...] })`: the
client's offer is `req.webTransportProtocols`, in its order of preference (parsed from
WT-Available-Protocols), and `res.setWebTransportProtocol(name)` before `writeHead(200)`
picks one — sent as WT-Protocol, what the client's `wt.protocol` then says. A name the
client did not offer throws: the client would fail the session over it.

```js
const chosen = req.webTransportProtocols.find(p => SUPPORTED.includes(p));
if (chosen) res.setWebTransportProtocol(chosen);
res.writeHead(200);
```

**Streams that arrive early** — opened by the client right after its CONNECT, before
the application accepts the session, or even read before the CONNECT itself — are
held (one stream window each, up to 64 per connection) and delivered as
`'stream'` / `'unidirectionalStream'` once `res.writeHead(200)` accepts it. If the
application answers otherwise, or the CONNECT never comes, they are reset with
`WEBTRANSPORT_BUFFERED_STREAM_REJECTED`.

**The session** ends with `'close'` on `req`. `res.closeSession(code, reason)` closes it with
CLOSE_WEBTRANSPORT_SESSION — a 32-bit code and a reason of up to 1024 bytes, what a
browser's `wt.closed` resolves with — and resets its streams. A client's close arrives the
same way: `req.closeInfo` is `{ closeCode, reason }` when it sent one. `res.drainSession()`
sends DRAIN_WEBTRANSPORT_SESSION (finish up, start nothing new); a client's DRAIN is
`'draining'` on `req`.

#### Client (Node.js)

QUICO's `WebTransport` is the browser's API — the same class, promises, streams and
options — so a client written for the browser runs in Node unchanged:

```js
import { WebTransport, WebTransportError } from 'quico';   // in a browser: globals

const wt = new WebTransport('https://example.com:4433/live', {
  serverCertificateHashes: [{ algorithm: 'sha-256', value: certHash }],   // or a CA-signed cert
});
await wt.ready;

const { readable, writable } = await wt.createBidirectionalStream();
const writer = writable.getWriter();
await writer.write(new TextEncoder().encode('hello'));
await writer.close();
for (const reader = readable.getReader();;) { const { value, done } = await reader.read(); if (done) break; /* … */ }

const uni = await wt.createUnidirectionalStream();             // a WritableStream
await uni.getWriter().abort(new WebTransportError({ streamErrorCode: 7 }));   // RESET_STREAM, code 7

const incoming = wt.incomingUnidirectionalStreams.getReader(); // ReadableStream of ReadableStreams
const dgWriter = wt.datagrams.createWritable().getWriter();    // and wt.datagrams.readable

wt.close({ closeCode: 0, reason: 'done' });
const { closeCode, reason } = await wt.closed;                 // the server's, if it closed first
```

The whole browser API is there: `ready`, `closed` (see [How the session ends](#how-the-session-ends) below),
`draining`, `close()`, `createBidirectionalStream()` / `createUnidirectionalStream()` with
`sendOrder`, `sendGroup` and `waitUntilAvailable`, `incomingBidirectionalStreams`,
`incomingUnidirectionalStreams`, `datagrams` (`readable`, `createWritable()`,
`maxDatagramSize`, `incomingMaxAge`, `outgoingMaxAge`, `incomingMaxBufferedDatagrams`,
`outgoingMaxBufferedDatagrams` — see the server's `res.datagrams` above), `createSendGroup()`, `getStats()`, `reliability`,
`congestionControl`, `protocol`, `responseHeaders`, `exportKeyingMaterial()`,
`WebTransport.supportsReliableOnly` (`false`: HTTP/3 only), and stream `getStats()`; the options
`serverCertificateHashes` (the leaf's SHA-256, a certificate valid for at most 14 days, as
the browser requires), `protocols`, `requireUnreliable`, `congestionControl`,
`transportParams` (QUICO's own: the windows and stream limits, as the server's),
`key` / `cert` / `passphrase` (a client certificate, as `https.request` takes it),
`quicVersions` and `ecdhCurve` (as `quico.request`'s),
`session` (a TLS session from an earlier `'session'` event, to resume — not with
`serverCertificateHashes`: a resumed handshake has no certificate to pin),
`initialCongestionWindow` (as the server's),
`allowPooling`, the `anticipatedConcurrent…` hints and `datagramsReadableType`. A test runs the same
client function in Chromium and in Node against a QUICO server and checks both see the same.
`sendOrder` and `sendGroup` order what the client sends, as on the server (see above).

**The browser's interfaces** are exported, for `instanceof` as in the browser:
`WebTransportBidirectionalStream`, `WebTransportSendStream`, `WebTransportReceiveStream`,
`WebTransportWriter`, `WebTransportSendGroup`, `WebTransportDatagramsWritable`,
`WebTransportDatagramDuplexStream`. As in the browser, none of them can be constructed by
the application. `WebTransportError` is a `DOMException` (its `name` is
`'WebTransportError'`, with `source` and `streamErrorCode`) and takes the browser's
`{ message, source, streamErrorCode }` form as well as the spec's `(message, options)`. Where
QUICO gives a Node code too (`ERR_WEBTRANSPORT_SESSION_LOST`, say), it is in `err.code`, in
place of the `DOMException`'s number.

| | |
|---|---|
| `wt.responseHeaders` | The server's answer to the CONNECT: a `Headers` that cannot be changed, `null` until `ready`. No pseudo-headers and no `wt-protocol` (that is `wt.protocol`). `set-cookie` is there (`getSetCookie()`): a browser keeps it from its page, but in Node the program is the user agent, as with Node's `fetch`. |
| `writer.atomicWrite(chunk)` | `getWriter()` of a send stream gives a `WebTransportWriter`. An atomic write goes only if all of it fits the flow-control window when its turn comes; otherwise none of it is sent and it rejects with an `AbortError`, as does any atomic write queued behind it, and the stream goes on. A plain write queued behind it fails the stream, as the spec has it. |
| `writer.commit()` | What was written so far is delivered even if the stream is aborted later: `abort()` then sends RESET_STREAM_AT with that many bytes reliable (a MOQT subgroup's header, say) — `stream.resetStream(code, { reliableSize })` in the Node API. A peer that does not take RESET_STREAM_AT gets a plain RESET_STREAM. |
| `readable.getReader({ mode: 'byob' })` | Streams are byte streams, as the browser's: a BYOB reader reads into its own buffer, and what does not fit stays for the next read. Datagrams too, with `datagramsReadableType: 'bytes'`: each datagram whole into the reader's buffer, a `RangeError` if it does not fit. |

It behaves as the browser's does where the web-platform-tests check it:

- **The constructor checks its arguments.** A URL that does not parse, is not `https:`, or
  has a fragment is a `SyntaxError` (a `DOMException`, as Node's own `WebSocket` throws), and
  so is a protocol in `protocols` that is empty, longer than 512, not printable ASCII, or
  given twice. A malformed `serverCertificateHashes` entry, a `congestionControl` that is
  not one of the three, or an `anticipatedConcurrent…` hint outside 0–65535 is a
  `TypeError`. The hints are attributes that can be set later, with the same checks.
- **Streams and datagrams can be used before `ready`.** `create…Stream()` waits for the
  session and then resolves; a datagram written meanwhile goes once the session is up.
- **The Promises reject as the browser's do.** `create…Stream()` on a session that is over
  rejects with an `InvalidStateError`, a send group of another session's with a
  `TypeError`, and a stream past the server's limit without `waitUntilAvailable` with a
  `QuotaExceededError`. `getStats()` on a session that failed rejects with an
  `InvalidStateError`.
- **A stream fails as soon as its direction is given up on.** The server's `STOP_SENDING`
  rejects `writer.closed`, its `RESET_STREAM` rejects `reader.closed`, and the session's
  end fails both, without waiting for the next read or write. A stream write that is not
  an `ArrayBuffer` or a view onto one, or is empty, rejects with a `TypeError`.
- **The anticipated-streams hints take effect.** Given to the constructor, they raise the
  stream limits the client grants the server from the start, unless `transportParams`
  sets those limits itself.

The same object also has a Node-style API, for Node code:

| | |
|---|---|
| `wt.on('stream', duplex)`, `wt.on('unidirectionalStream', readable)` | The server's streams as Node streams. A stream goes to a Node listener if there is one, otherwise to `incoming…Streams` once that is read, and waits for either. |
| `wt.on('datagram', buf)`, `wt.sendDatagram(buf[, { sendOrder, sendGroup }])` → `true`/`false`, `wt.maxDatagramSize()` | Datagrams; with a `sendOrder` / `sendGroup` one takes its place among the streams, as the server's `res.sendDatagram`. |
| `'ready'`, `'draining'`, `'close'` | The session's events. |
| `'session'` (`Buffer`) | A TLS session the server sent, to pass back as `session` next time and resume. |
| `stream.write()`, `stream.on('data')`, `stream.pipe()` | Every stream is a Node stream too: `createBidirectionalStream()` gives a `Duplex` that has the browser's `readable` / `writable`; `createUnidirectionalStream()` gives the browser's `WritableStream` that is Node's `Writable` too — `write()` / `'drain'`, `end()`, `resetStream()`, its events, `writableLength` and the rest of its state, and `readable.pipe()` into it. |
| `stream.resetStream(code)`, `stream.stopSending(code)`, `stream.streamErrorCode` | Give up on a direction with a code; the peer's code when it gave up. |
| `stream.id`, `stream.sessionId`, `stream.sendState`, `stream.recvState`, `stream.pending` | As on the server. `create…Stream()`'s Promise is settled once the stream is open — at once, or with `waitUntilAvailable` when the server allows it — as the browser's is. |
| `wt.canOpenStream({ bidirectional })`, `wt.getStats()` | As the server's `res.canOpenStream()` and `res.getStats()`. |
| `'peerReset'` / `'peerStopSending'` (`code`), `'close'` | As on the server: the direction the peer gave up on ends, the other goes on; `'close'` once both are over. |
| `stream.sendOrder`, `stream.sendGroup` | Its place among the session's streams (see [Priorities](#webtransport-1) on the server — the same rules). |

The client's streams are the server's kind: the server's are recognised by their
WebTransport prefix, not guessed from stream numbers, and what the server sends is credited
back as the application reads — a stream nobody reads holds one stream window.

Besides the browser's options, the second argument takes `ca` and `rejectUnauthorized`
(default `true`), as in `https.request`: the server's certificate is verified against the
platform roots unless `ca` is given or `serverCertificateHashes` pins it. If the session
cannot be established, `ready` and `closed` reject with a `WebTransportError` (source
`'session'`, keeping node:tls's `err.code`, e.g. `DEPTH_ZERO_SELF_SIGNED_CERT`, when TLS is
the reason), `state` becomes `'failed'` and the connection is closed, as in the browser.
`'error'` is emitted too, but only when a listener is attached. Any `2xx` answer to the
CONNECT establishes the session, as in the browser (draft-ietf-webtrans-http3 §3.3), not
only `200`.

**Fields on the CONNECT request.** A browser always sends its page's `Origin`, and servers
check it (the web-platform-tests WebTransport server refuses a session without one). Node has
no page, so the client takes `origin`, and `headers` for other fields, as QUICO's WebSocket
client does:

```js
new WebTransport(url, { origin: 'https://app.example', headers: { authorization: 'Bearer …' } });
```

`headers` is the browser's `HeadersInit`: a `Headers`, a list of `[name, value]` pairs, or
an object. The fields go after the pseudo-headers and are treated as the browser's
`Headers` treats them: names are lower-cased, leading and trailing whitespace is removed
from values, and a name given twice is sent once with its values joined by `, `.

| Field | What happens |
|---|---|
| A pseudo-header, `wt-available-protocols` (that is `protocols`), a name or value that is not valid | The constructor throws a `TypeError`, as the browser's does |
| `host`, `te`, `content-length`, `trailer`, connection-specific fields (`connection`, `keep-alive`, `transfer-encoding`, `upgrade`, …) | Dropped, as the browser drops them: they cannot go on an HTTP/3 request (the authority is `:authority`) |
| `cookie`, `referer`, `sec-*` and the rest | Sent. A browser keeps them from a page for the page's safety; in Node the program is the user agent, as with Node's `fetch` |

##### How the session ends

| | `closed` | `'close'` |
|---|---|---|
| Either side sends `CLOSE_WEBTRANSPORT_SESSION` (`wt.close({ closeCode, reason })`, `res.closeSession(code, reason)`) | resolves with `{ closeCode, reason }` | emitted |
| The server ends the CONNECT stream with a FIN and no capsule | resolves with `{ closeCode: 0, reason: '' }`, at once (draft-ietf-webtrans-http3 §5) | emitted |
| The session is lost: the server resets the CONNECT stream, or the connection goes (an error, the idle timeout, the server gone) | **rejects** with a `WebTransportError` (source `'session'`, `code` `'ERR_WEBTRANSPORT_SESSION_LOST'`, and `quicError` `{ code, application, reason }` when the peer closed the connection), as soon as the server's CONNECTION_CLOSE arrives, not after QUIC's draining period; `state` is `'failed'` | emitted |
| The session could not be established, or `wt.close()` was called before `ready` | rejects, with the same error as `ready` | emitted |

As in the browser, `{ closeCode: 0 }` means a close someone asked for; a session that was
lost rejects instead. The session's streams, its incoming-stream queues and its datagrams
fail with it. When the session was lost or never established, they fail with the very
error object `closed` rejects with. After our own `close()` they fail with an
`AbortError`, and after the server's with a `WebTransportError`. A clean close closes the
incoming-stream queues and the datagrams' `readable` instead of failing them.

#### Client (Browser)

A QUICO server works with the **native browser WebTransport API** — no client library
needed:

```js
const wt = new WebTransport('https://yourserver.com:4433/live');
await wt.ready;

const writer = wt.datagrams.createWritable().getWriter();
await writer.write(new TextEncoder().encode('Hello QUIC'));

const reader = wt.datagrams.readable.getReader();
const { value } = await reader.read();
console.log('Received:', new TextDecoder().decode(value));
```

---

### WebSocket

#### Server

One handler serves WebSocket over HTTP/1.1, HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220):
all three arrive as the server's `'upgrade'` event.

```js
import quico, { WebSocketServer } from 'quico';

const server = quico.createServer({ key: KEY, cert: CERT });
const wss = new WebSocketServer({ server, path: '/chat', pingInterval: 30000 });

wss.on('connection', (ws, req) => {
  ws.on('message', (data, isBinary) => ws.send(data, { binary: isBinary }));
});

server.listen(4433);
```

`WebSocketServer(options)` takes `server` (or `noServer: true` and call
`wss.handleUpgrade(req, socket, head, cb)` yourself), `path`, `pingInterval` (clients
that miss a pong are dropped) and the options of `upgradeWebSocket`:

- `origin` — a string, an array, or `fn(origin, req)`; a mismatch is answered with 403
- `verifyClient(req)` — return `false` (401) or `{ code, message, headers }`
- `protocol` (string or `fn(offered, req)`) / `protocols` (preference list)
- `headers` — extra response headers
- `maxPayload` — default 100 MB

`wss.clients` is the set of open connections; `wss.close([code][, reason])` closes them.
For a single upgrade without a server object, `upgradeWebSocket(req, socket, head,
options)` returns the socket, or `null` after answering the client itself.

Sockets have both surfaces: WHATWG (`onmessage`, `addEventListener`, `binaryType`) and
the `ws` package's (`on('message', (data, isBinary))`, `on('close', (code, reason))`,
`ping()`, `on('pong')`). Pings are answered automatically.

#### Client

```js
import { WebSocket } from 'quico';

const ws = new WebSocket('wss://localhost:4433/chat', [], { rejectUnauthorized: false });
ws.onopen = () => ws.send('hello');
ws.onmessage = (e) => console.log(e.data);
```

The client connects over HTTP/1.1. Options beyond the WHATWG constructor: `origin`,
`headers`, `ca`, `rejectUnauthorized`, `maxPayload`, `agent` (whose TLS sessions a
`wss://` connection resumes with and keeps — `globalAgent` by default) and `session` (one
to resume with, from an earlier `'session'`). `ws.on('session', buf)`: each one the server
sends.

---

### CONNECT-UDP (proxying UDP)

A QUICO server can be a UDP proxy (RFC 9298, the MASQUE working group's): a client
asks it for a UDP "socket" to one target, a host and a port, and from then on sends
the target UDP payloads through it and receives the target's. This is what a browser's
or an OS's privacy relay does for QUIC traffic.

```js
const server = quico.createServer({ key: KEY, cert: CERT });

server.on('connectUdp', (req, tunnel) => {
  if (req.headers.authorization !== 'Bearer ' + TOKEN) return tunnel.reject(407);
  tunnel.accept();   // to tunnel.target, from the request
  tunnel.on('close', (stats) => console.log(tunnel.target, stats.bytesToClient, tunnel.closeReason));
});

server.listen(443);
```

**How it travels.** The request names the target in its path, by a URI template the
clients are configured with: by default `/.well-known/masque/udp/{target_host}/{target_port}/`
(an IPv6 address with its colons percent-encoded). Over HTTP/3 it is an extended CONNECT
(`:protocol: connect-udp`), and each UDP payload is an HTTP Datagram (RFC 9297) in a QUIC
DATAGRAM frame — unreliable, as UDP is. A client that did not negotiate datagrams,
HTTP/2 (extended CONNECT) and HTTP/1.1 (`Upgrade: connect-udp`, answered 101) carry them
as DATAGRAM capsules on the request stream. The proxy relays from a UDP socket of its own,
connected to the target, so only the target's packets come back through it. A payload
larger than a QUIC datagram can carry is dropped, not moved to the stream (§5: a
reliable, ordered copy of a UDP packet is not one).

**What the application decides** — in `'connectUdp'`, now or later (the client may
send before the answer; the first 32 payloads wait):

| | |
|---|---|
| `tunnel.accept()` | Relay to `tunnel.target`. The host is resolved (`lookup`), the socket connected, then the 2xx goes. |
| `tunnel.accept({ target: { host, port } })` | Relay to another target. |
| `tunnel.accept({ socket })` | Relay through the application's own `dgram` socket (bound where it wants, say). Packets from senders other than the target are not relayed; the socket is not closed with the tunnel. |
| `tunnel.accept({ relay: false })` | No relay: the application gets each payload from the client as `'message'` (a `Buffer`) and answers with `tunnel.send(buf)`. |
| `tunnel.accept({ headers, allowPrivate })` | Extra response fields; the private-address rule for this tunnel. |
| `tunnel.reject(status[, headers])` | Refuse it. |
| `tunnel.send(buf)` | A payload to the client, in any mode. `false`: not sent (too large, or the stream is full — dropped, as UDP drops). |
| `tunnel.close()` | End it (the request stream is ended). |

`tunnel.req` is the request (an `IncomingMessage`), `tunnel.target` `{ host, port }`,
`tunnel.state` `'pending'` / `'open'` / `'closed'`. Events: `'open'`, `'message'` (with
`relay: false`), `'close'` (with the stats; `tunnel.closeReason` says why: `'client'`,
`'local'`, `'idle'`, `'aborted'` — the stream was reset or the connection went —,
`'socket'` — the target's socket failed, an ICMP unreachable, say — or `'rejected'`;
`tunnel.error` holds the error when there was one).

**Figures.** `tunnel.stats`: `{ target, address, port, httpVersion, state, transport
('datagram' | 'capsule'), openedAt, closedAt, durationMs, packetsFromClient,
bytesFromClient, packetsToClient, bytesToClient, droppedFromClient, droppedToClient }`.
`server.getConnectUdpStats()`: `{ active, accepted, rejected, closed }` and the same
counters summed over every tunnel, open ones included.

**Refused on its own** — before `'connectUdp'`, or at `accept()`:

| Case | Answer |
|---|---|
| A path that is not the template's | 404 |
| An empty host, a port outside 1..65535 | 400 |
| HTTP/1.1, not a GET | 400 |
| More tunnels on one connection than `maxTunnelsPerConnection` | 429 |
| The host does not resolve | 502, `Proxy-Status: quico; error=dns_error` |
| The host resolves only to private addresses | 403, `Proxy-Status: quico; error=destination_ip_prohibited` |
| No `'connectUdp'` listener | Not a tunnel: the request goes to `'upgrade'` or `'request'`, as before |

**Options** (`createServer({ connectUdp: { … } })`):

| Option | Default | |
|---|---|---|
| `template` | `/.well-known/masque/udp/{target_host}/{target_port}/` | The URI template — variables in the path, or a query (`/masque{?target_host,target_port}`). |
| `allowPrivate` | `false` | Allow targets in private, loopback, link-local, CGNAT, multicast and reserved ranges (IPv4 and IPv6, IPv4-mapped included). Off, a proxy cannot be used to reach its own network (RFC 9298 §7). |
| `maxTunnelsPerConnection` | `16` | |
| `idleTimeout` | `120000` | ms with nothing either way before a tunnel is closed; never under two minutes (RFC 9298 §3.1), `0` for none. |
| `lookup` | `dns.lookup` | `(host, { all: true }, cb)`, as `dns.lookup`. |
| `proxyName` | `'quico'` | The name in `Proxy-Status`. |

RFC 9298 asks that a UDP proxy serve authenticated users only — the check is the
application's, in `'connectUdp'`.

#### Client: `quico.connectUdp(proxy, target[, options][, callback])`

A UDP socket to `target` (`{ host, port }`) through a proxy. What it returns behaves as a
connected `dgram.Socket`, so code written for `dgram` moves to a proxied path by changing
the line that makes the socket:

```js
import { connectUdp } from 'quico';

const sock = connectUdp('https://proxy.example', { host: '1.1.1.1', port: 53 },
                        { headers: { 'proxy-authorization': 'Bearer ' + TOKEN } });
sock.on('connect', () => sock.send(dnsQuery));
sock.on('message', (msg, rinfo) => { /* rinfo: the target, as dgram gives it */ });
sock.on('error', console.error);
```

`proxy` is the proxy's URL — and, if it contains `{target_host}`, the URI template too
(`'https://proxy.example/masque{?target_host,target_port}'`); without one, the default
template's path — or `{ hostname, port, template }`.

HTTP/3 first, each payload a QUIC datagram. If QUIC has not connected within `h3Timeout`
(UDP blocked on the way, a proxy without HTTP/3), TCP: HTTP/2 extended CONNECT or HTTP/1.1
Upgrade, as ALPN decides, the payloads in capsules.

Over HTTP/3 the tunnels to one proxy share a connection (RFC 9298's tunnels are requests;
their datagrams are told apart by Quarter Stream ID): a tunnel joins the connection opened
with the same TLS settings, or waits for the one being made — no handshake of its own, one
congestion controller, one UDP port — and the connection closes with its last tunnel. A
tunnel the proxy refuses, or one closed, leaves the others as they are; a connection lost
ends each tunnel on it with `ERR_CONNECT_UDP_CLOSED`. `shareConnection: false` gives a
tunnel its own. Over TCP each tunnel has its own connection.

| | |
|---|---|
| `send(msg[, offset, length][, callback])` | A connected socket's forms: a `Buffer`, a typed array, a string, or an array of them (one payload). Before `'connect'`, up to 64 are held and go when the tunnel opens. Larger than `maxPayloadSize`: `EMSGSIZE`. When the stream already holds too much (capsules), dropped as UDP drops — no error. With a port and address: `ERR_SOCKET_DGRAM_IS_CONNECTED`. |
| `close([callback])` | Ends the tunnel: the request stream's end, and the connection's when it was the last on it. |
| `remoteAddress()` | The target `{ address, family, port }`. |
| `address()` | The local end of the connection to the proxy. |
| `maxPayloadSize` | The largest payload `send()` takes now: over HTTP/3, what a QUIC datagram carries on this path (~1195 bytes at the start; more after path MTU discovery); over capsules, 65527. |
| `protocol` | `'h3'`, `'h2'` or `'http/1.1'`, once open. |
| `statusCode`, `responseHeaders` | The proxy's answer. |
| `closeReason` | `'local'`, `'proxy'` (it ended the tunnel) or `'error'`. |
| `stats` | `{ protocol, transport ('datagram' \| 'capsule'), target, openedAt, closedAt, durationMs, packetsSent, bytesSent, packetsReceived, bytesReceived, dropped }` |

TLS sessions to the proxy are kept and resumed with as `quico.request`'s are: the
`agent` option's (`globalAgent` by default; `false`: none), each used once, or `session`;
each the proxy sends is the socket's `'session'` event.

Events: `'connect'`, `'message'` `(msg, rinfo)`, `'error'`, `'close'`, `'session'`. A refusal is an
`'error'` with `code: 'ERR_CONNECT_UDP_REFUSED'`, `statusCode` and `proxyStatus` (the
proxy's `Proxy-Status`), then `'close'`.

| Option | Default | |
|---|---|---|
| `protocol` | `'auto'` | `'h3'` (no fallback), `'h2'` or `'http/1.1'` to use only that. |
| `h3Timeout` | `3000` | ms to wait for QUIC before TCP. |
| `fallback` | `true` | `false`: HTTP/3 only, even with `'auto'`. |
| `shareConnection` | `true` | `false`: an HTTP/3 connection of its own, not shared with the proxy's other tunnels. |
| `headers` | — | Fields for the request (authorization). |
| `ech`, `echGrease` | | Encrypted Client Hello to the proxy, as `quico.request`'s. |
| `ecdhCurve` | | The key-exchange groups to offer the proxy, as `quico.request`'s. |
| `template` | the default | When the proxy URL carries none. |
| `rejectUnauthorized`, `ca`, `key`, `cert`, `passphrase`, `servername`, `quicVersions` | | As `quico.request`. |

Tested against quic-go's masque-go in both directions — its client through QUICO's proxy
(an HTTP/3 request inside the tunnel: QUIC in QUIC), QUICO's client through its proxy.

---

### Fingerprinting

Who is really on the other end? A browser and a script sending the same User-Agent
still differ in how they speak the protocols underneath. QUICO exposes those
differences, on every layer it implements.

| Function | Input | Returns |
|---|---|---|
| `ja4h(req)` | a request | JA4H: `{ hash, raw, a, b, c, d }` — method, version, header names and order, cookie names (never values) |
| `req.h2Fingerprint()` | HTTP/2 request | `{ hash, raw, … }` from the client's SETTINGS, WINDOW_UPDATE, PRIORITY and pseudo-header order |
| `req.h3Fingerprint()` | HTTP/3 request | `{ hash, raw, … }` from the client's QUIC transport parameters, HTTP/3 SETTINGS and pseudo-header order |
| `h2Fingerprint(observed)` / `h3Fingerprint(observed)` | raw observations | the same, computed from your own data |
| `req.socket.getJA4()` / `getJA4S()` / `getJA5()` | TLS | TLS fingerprints, from LemonTLS — `null` when the installed LemonTLS does not provide them |
| `req.socket.getNegotiationResult()` / `res.socket.getNegotiationResult()` | TLS | What the handshake settled, on every version: `{ versionName, cipherName, groupName, alpn, resumed, helloRetried, certificateCompression: { sent, received }, … }` — `sent` and `received` the algorithm each side's certificate went in (`'brotli'`, `'zlib'`, `'zstd'`), `null` where it went plain or not at all (a resumed connection) |
| `profileRequest(req)` | a request | `{ claimed, protocol, fingerprints: { ja4, ja4s, h2, h2raw, h3, h3raw }, signals, suspicion }` — signals where the request's TLS and HTTP/2 behaviour contradicts the client it claims to be, and a 0–100 score. HTTP/3 fingerprints are reported, not yet checked against browsers. |

```js
server.on('request', (req, res) => {
  const p = quico.profileRequest(req);
  if (p.suspicion >= 60) { res.writeHead(403); return res.end(); }
  // …
});
```

---

### Protocol layers

The unified server and client are built from layers you can use on their own — for a
custom transport, a proxy, or protocols other than HTTP.

| Export | What it is |
|---|---|
| `createH1Server(options, handler)` | HTTP/1.1 server on its own |
| `createH2Server(options, handler)` | HTTP/2 server on its own |
| `createH3Server(options, handler)` | HTTP/3 + WebTransport server on its own (over `createQuicServer`) |
| `h1Request(options, cb)` / `h2Request(options, cb)` / `h3Request(options, cb)` | Single-protocol clients, no fallback. Each takes `session` and emits `'session'`, as `https.request`. `h2Request` streams its body: `write()` sends as it is called and returns `false` while the stream's window or the socket is full, then `'drain'` — an upload is never held whole |
| `createTcpListener(options)` | TCP accept + TLS + ALPN dispatch: `register(alpn, handler, { sniff })`, `listen()` |
| `createQuicServer(options)` | QUIC transport server — see below |
| `createQuicClientSocket(opts)` | A UDP socket driving one client `QUICConnection` (`remoteIp`, `remotePort`, `hostname`, `alpn`, `ecdhCurve`, `onConnect(quic)`, `onSocket(quic)` before the handshake — the place to attach `'keylog'`) |

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
| `ticketKeys` | `Buffer` | random | Session-ticket key |
| `sessionTimeout` | `number` | `7200` | Seconds a session ticket stays good |
| `requestCert`, `rejectUnauthorized`, `ciphers`, `ecdhCurve`, `sigalgs`, `handshakeTimeout`, `passphrase`, `certificateCompression` | | | As `createServer` (TLS 1.3) |
| `initialCongestionWindow` | `number` | `20` | Initial congestion window, in packets |
| `carefulResume` | `boolean` | `false` | Careful Resume (RFC 9959) for returning clients |
| `startupCap` | `string` | `'stall'` | Startup's window cap: `'stall'`, `'always'`, `'off'` (as `createServer`) |
| `quicVersions` | `Array` | `['v1', 'v2']` | QUIC versions accepted, in preference (RFC 9368, RFC 9369) |
| `connectionOptions` | `Function` | — | Per-connection settings (see above) |
| `validateAddress` | `boolean` | `false` | Address validation with Retry |
| `earlyData`, `earlyDataMaxAge`, `earlyDataReplay` | | `false`, `10000`, in memory | 0-RTT, as `createServer` (`quic.isEarlyStream(id)`: whether a stream came early) |
| `handshakeLoadThreshold`, `maxHandshakesPerAddress` | `number` | `500`, `64` | As `createServer`; `getPendingHandshakes()`, `setOptions()` / `getOptions()` too |
| `pmtuDiscovery`, `maxUdpPayloadSize`, `initialRtt`, `reorderWindow` | | | As `createServer` |
| `resetTokenSecret` | `Buffer` | random | Stateless-reset secret |
| `tokenSecret` | `Buffer` (≥ 16 bytes) | random | Address-validation token secret (Retry, NEW_TOKEN), as `createServer` |
| `socket` / `socket6` | `dgram.Socket` | `null` | External, already-bound UDP sockets |

Returns `{ listen, close, on, handlePacket, hasConnection }` plus the runtime getters and
setters for ticket keys, address validation, the reset secret and the token secret. The `'connection'`
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

`handlePacket(msg, rinfo)` and `hasConnection(rinfo[, msg])` support **external socket
mode**, where QUICO shares a UDP port with another protocol (STUN/TURN, for example)
and you route datagrams yourself.

#### `QUICConnection`

| Member | Description |
|---|---|
| `quic.state` | `'idle'`, `'handshaking'`, `'connected'`, `'closing'`, `'draining'`, `'closed'` |
| `quic.sendStream(id, data, fin)` | Write to a stream. A new stream beyond the peer's `MAX_STREAMS` waits until the peer raises the limit. |
| `quic.whenStreamCommitted(id, cb)` | `cb()` once every byte and the FIN of the stream are acknowledged ("Data Recvd"); never if it is reset first |
| `quic.resetStream(id, code[, reliableSize])` | Abandon the sending part of a stream (RESET_STREAM); with `reliableSize`, its first bytes still delivered (RESET_STREAM_AT, when the peer takes it: `quic.resetStreamAtSupported`) |
| `quic.stopSending(id, code)` | Ask the peer to stop sending on a stream (STOP_SENDING) |
| `quic.sendDatagram(data[, prio])` | Send an unreliable datagram; `false` if not connected or too large. With `prio` (`{ urgency, group, order }`) it is scheduled among the streams instead of ahead of them |
| `quic.setStreamPriority(id, { urgency, incremental, group, order }[, fromPeer])` | A stream's place in the scheduler — see [Stream scheduling](#stream-scheduling-byte-level-round-robin-by-priority). `fromPeer`: the peer's signal, which does not replace what the application set |
| `quic.getStreamPriority(id)` | What is set for a stream, or `null` |
| `quic.canOpenStream(bidi)` | Whether a stream of ours could be opened now, within the peer's `MAX_STREAMS` |
| `quic.isReceiving(id)` | Whether a stream's receiving part is open (opened, and neither finished nor reset) |
| `quic.maxDatagramSize()` | Largest datagram payload that fits one packet (a local estimate) |
| `quic.close(errorCode, reason[, application])` | Send CONNECTION_CLOSE; `application: true` for application error codes |
| `quic.remoteAddress` / `remotePort` | The peer's current address — follows NAT rebinding |
| `quic.earlyDataStatus` | 0-RTT: `null` (none), `'offered'` (a client's, undecided), `'accepted'`, `'rejected'` |
| `quic.isEarlyStream(id)` | Server: whether the stream was opened by 0-RTT data |
| `quic.whenConfirmed(cb)` | `cb()` once the handshake is confirmed (RFC 9001 §4.1.2), at once if it is |
| `quic.alpnProtocol`, `servername`, `getCertificate()`, `getTicketInfo()`, `isSessionReused()` | What the handshake decided, with `TLSSocket`'s names |
| `quic.on(event, fn)` / `off` | Event subscription |

**Events:** `'connect'`, `'stream'` (`id, data, fin`), `'stream_reset'` (`id, code,
finalSize`), `'stop_sending'` (`id, code`), `'datagram'`, `'path'` (`address, port`),
`'peer_transport_params'`, `'close'`, `'error'`, `'keylog'`; a client's 0-RTT: `'early'` (it may
send application data now), `'early_accepted'`, `'early_rejected'` (what went early is forgotten — send it again).
`'closing'` (`peerClose` — `{ error, application, reason }` when the peer's CONNECTION_CLOSE
ended it, `null` when we did) fires once, the moment the connection is over for the
application; `'close'` follows when the closing or draining period ends (RFC 9000 §10.2, up to
3 s), which is packet housekeeping. Code that reacts to the end belongs on `'closing'`.

**Connection options** (when constructing directly): `idleTimeout` (default `30000`),
`handshakeTimeout` (default `10000`), `keepAlive` (`true` → half the idle timeout, or
a number of ms), `alpn`, `hostname`, `rejectUnauthorized`, `ca`.


---

## ⚙️ Configuration & Tuning

### Transport parameters

These are the values QUICO advertises to peers. The windows, stream limits and idle timeout can be
set — `createServer({ transportParams })`, `new WebTransport(url, { transportParams })`
— by RFC 9000's names in camelCase; a value out of range throws when the server or
client is made.

| Parameter | Option | Default | Meaning |
|---|---|---|---|
| `initial_max_data` | `initialMaxData` | 1 MB | Connection-level receive window |
| `initial_max_stream_data_bidi_local` | `initialMaxStreamDataBidiLocal` | 256 KB | Receive window of a bidirectional stream we open |
| `initial_max_stream_data_bidi_remote` | `initialMaxStreamDataBidiRemote` | 256 KB | Receive window of one the peer opens |
| `initial_max_stream_data_uni` | `initialMaxStreamDataUni` | 128 KB | Receive window of a unidirectional stream the peer opens |
| `initial_max_streams_bidi` | `initialMaxStreamsBidi` | 100 | Bidirectional streams the peer may have open at once |
| `initial_max_streams_uni` | `initialMaxStreamsUni` | 100 | Unidirectional streams the peer may have open at once (HTTP/3 keeps three for itself; at least 3) |
| `max_idle_timeout` | `maxIdleTimeout` | 30 s | Milliseconds without a packet from the peer before the connection is closed — silently, with no CONNECTION_CLOSE (RFC 9000 §10.1); `0`: no limit. The one in force is the **smaller** of the two sides' (RFC 9000 §10.1), and never under three PTOs; `keepAlive: true` pings at half of it |
| `disable_active_migration` | `disableActiveMigration` | not sent | `true`: clients may not move to another address (connection migration, RFC 9000 §9). Unset, they may — a phone from Wi-Fi to cellular goes on in the same connection |
| `max_ack_delay` | | 25 ms | Maximum ACK delay we advertise |
| `max_datagram_frame_size` | | 65527 | Datagram support (RFC 9221) |
| `active_connection_id_limit` | | 4 | Connection IDs we will track (and issue to the peer, up to its own) |
| `version_information` | `quicVersions` | v1, v2 | The versions offered or chosen (RFC 9368) |
| `grease_quic_bit` | | sent | The peer may send the fixed bit as 0 (RFC 9287); not on a shared UDP port |
| `reset_stream_at` | | sent | RESET_STREAM_AT is taken (draft-ietf-quic-reliable-stream-reset): a peer's reset can keep its stream's first bytes delivered |
| `min_ack_delay` | | 1 ms (16 ms on Windows) | ACK_FREQUENCY and IMMEDIATE_ACK are taken (draft-ietf-quic-ack-frequency) |

Receive windows slide automatically as data is consumed, and grow (autotuning) while
the application keeps up, so large downloads are not limited by the initial values. Stream limits work the same way: as
the peer's streams close, `MAX_STREAMS` gives them back, keeping the number open at
once, so a long-lived connection is not capped at 100 requests.

### Per-connection timers

```js
// via the low-level API
new QUICConnection({
  idleTimeout: 60000,      // default 30000 — what we advertise (transportParams.maxIdleTimeout)
  handshakeTimeout: 10000, // default 10000
  keepAlive: true          // PING at half the idle timeout in force; or a number of ms
});
```

The idle timeout in force is the smaller of ours and the peer's, as RFC 9000 §10.1 has
it — the peer's arrives with its transport parameters; `createQuicClientSocket` takes
`idleTimeout` and `keepAlive` too.

---

## 🐛 Debugging

### Environment variables

| Variable | Effect |
|---|---|
| `QUICO_DEBUG=1` | Full per-packet trace: every datagram, packet, frame, stream write, and TLS transition. **Very verbose** — it can become the bottleneck it observes, so don't use it for throughput measurements. |
| `QUICO_DEBUG_BBR=1` | One line per round-trip with congestion-control state: `BtlBw`, `RTprop`, `BDP`, `cwnd`, pacing rate. Cheap enough to leave on. |
| `QUICO_TRACE_ACK=1` | One line per packet received and per ACK sent — enough to line up with a peer's log when it rejects an acknowledgement. |

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
    ├── server.js            — Unified server: HTTP/3 + HTTP/2 + HTTP/1.1 (drop-in for node:https)
    ├── server_stats.js      — The server's counters (server.getStats())
    ├── client.js            — Unified client with H3 → H2 → H1 fallback
    ├── agent.js             — Connection pooling, coalescing, Alt-Svc cache
    ├── streams.js           — IncomingMessage, ServerResponse, ClientRequest
    ├── http_common.js       — Shared header and message helpers
    │
    ├── h3.js                — HTTP/3 framing, QPACK, WebTransport detection
    ├── h3_server.js         — HTTP/3 + WebTransport server
    ├── h3_client.js         — HTTP/3 client
    ├── qpack.js             — QPACK encoder and decoder tables
    ├── quic_version.js      — QUIC versions: v1 and v2 (RFC 9369), one profile each
    ├── webtransport.js      — WebTransport client
    ├── wt_stream.js         — WebTransport streams (both sides)
    ├── connect_udp.js       — CONNECT-UDP proxy (RFC 9298): templates, capsules, the relay
    ├── connect_udp_client.js — quico.connectUdp(): CONNECT-UDP's client
    │
    ├── h2.js                — HTTP/2 connection: frames, streams, flow control
    ├── h2_frames.js         — HTTP/2 frame encoding/decoding
    ├── h2_server.js         — HTTP/2 server
    ├── h2_client.js         — HTTP/2 client and session pool
    ├── hpack.js             — HPACK
    ├── hpack_primitives.js  — Prefixed integers, string literals, Huffman (shared by HPACK and QPACK)
    │
    ├── h1.js                — HTTP/1.1 parser and serializer
    ├── h1_server.js         — HTTP/1.1 server
    ├── h1_client.js         — HTTP/1.1 client and socket pool
    ├── tcp_listener.js      — TCP accept, TLS, ALPN dispatch and sniffing
    │
    ├── ws.js                — WebSocket framing, and the WHATWG and ws-style event surfaces
    ├── ws_server.js         — WebSocketServer, upgradeWebSocket
    ├── ws_client.js         — WebSocket client
    │
    ├── ja4h.js              — JA4H request fingerprint
    ├── h2_fingerprint.js    — HTTP/2 and HTTP/3 fingerprints
    ├── client_profile.js    — profileRequest()
    │
    ├── quic_server.js       — UDP listener, connection routing, Retry, stateless reset
    ├── quic_socket.js       — Client-side UDP socket + connection bootstrap
    ├── quic_connection.js   — QUIC state machine, loss detection, CC, flow control
    ├── transport.js         — Packet parsing, frame encoding/decoding
    ├── crypto.js            — AEAD, header protection, key derivation
    ├── tls_bridge.js        — LemonTLS integration, transport parameters
    └── utils.js             — VarInt, binary helpers, debug flags
```

---

## 🔐 Security

### Post-quantum TLS

With Node 24.7+ (ML-KEM and ML-DSA in `node:crypto`, OpenSSL 3.5), on every version —
HTTP/3, HTTP/2, HTTP/1.1 — and checked against OpenSSL 3.5 in both directions:

- **Key exchange** — the hybrids X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024
  (draft-ietf-tls-ecdhe-mlkem), and ML-KEM alone: MLKEM512, MLKEM768, MLKEM1024
  (draft-ietf-tls-mlkem; MLKEM1024 is CNSA 2.0's). A server takes any of them, post-quantum
  before classical: the client's first post-quantum group, by the client's order — a
  HelloRetryRequest for it when the client sent no key share for it (a browser sends one
  for X25519MLKEM768, its first: one round trip; a CNSA 2.0 client listing MLKEM1024 first
  gets MLKEM1024). The client
  offers X25519MLKEM768 by default, as `node:tls` and the browsers do; the others by
  `ecdhCurve`. Each costs 1–1.7 KB in a ClientHello, so they are not offered unasked.
- **Authentication** — ML-DSA-44, -65 and -87 certificates (FIPS 204,
  draft-ietf-tls-mldsa), and chains signed with ML-DSA, verified and presented. A server
  can hold an ML-DSA and a classical certificate at once — `key` and `cert` arrays, as in
  `node:tls` — and presents the one the client's `signature_algorithms` ask for first:
  a client that puts ML-DSA first gets ML-DSA, a browser (which offers none) gets ECDSA or
  RSA. The client offers ML-DSA after the classical schemes (an ML-DSA chain is several
  KB more in every handshake); `sigalgs: 'mldsa65:…'` asks for it first.

  ```js
  createServer({
    key:  [fs.readFileSync('ecdsa.key'), fs.readFileSync('mldsa.key')],
    cert: [fs.readFileSync('ecdsa.pem'), fs.readFileSync('mldsa.pem')],   // in any order
    minVersion: 'TLSv1.3',      // TLS 1.2 has no post-quantum key exchange
  }, app);
  ```
- **What was negotiated** — `socket.getNegotiationResult()`: `groupName`
  (`'MLKEM1024'`, …) and `signatureAlgorithmName` (`'mldsa65'`, …).
- **TLS 1.2** has no post-quantum key exchange; a server that still accepts it is open to
  a client pushed onto it. `minVersion: 'TLSv1.3'` closes it (CNSA 2.0 admits TLS 1.3
  alone). The default stays `node:tls`'s, TLS 1.2 and up; TLS 1.3's downgrade sentinel
  (RFC 8446 §4.1.3) is sent and checked either way.
- **The cipher suite** is the client's choice among ours, as in `node:tls` — AES-256 for a
  client that asks for it first; `honorCipherOrder: true` for the server's.
- An **empty `key_share`** (RFC 8446 §4.2.8 — the client asks the server to choose; how
  scanners enumerate a server's groups) is answered with a HelloRetryRequest.

QUICO parses everything a peer sends, so every buffer a peer can make it hold has a
bound — and when a peer breaks the rules, the connection (or the stream) is closed
with the error the RFC names, not left to grow.

- **Stream limits are enforced** before any state is allocated: a stream ID beyond the
  advertised `MAX_STREAMS` is `STREAM_LIMIT_ERROR`; a frame for a stream that cannot
  exist is `STREAM_STATE_ERROR`; a closed stream cannot be reopened.
- **Every way a stream ends** — FIN, RESET_STREAM, STOP_SENDING, a WebTransport
  session closing, the connection closing — goes through one release path per layer,
  so nothing a stream allocated outlives it.
- **Reassembly is bounded**: gaps per stream are capped, and out-of-order data costs
  linear, not quadratic, work.
- **The handshake's CRYPTO data** is held to 64 KB past what was read and 128 pieces
  ahead of a gap (`CRYPTO_BUFFER_EXCEEDED`, RFC 9000 §7.5), each byte copied once; pieces
  sent again in other boundaries, overlapping, join as they should. A ClientHello split
  over several Initial packets — a post-quantum one is — is joined the same way. Over TCP,
  a handshake message declaring more than 128 KB is refused on sight (`illegal_parameter`),
  before its bytes are kept.
- **Transport parameters are checked** before any is used (RFC 9000 §7.4, §18.2): out of
  range (`ack_delay_exponent` above 20, `max_ack_delay` of 2^14 or more,
  `active_connection_id_limit` below 2, `max_udp_payload_size` below 1200, a stream
  count above 2^60), malformed (truncated, an integer that does not fill its value, a
  connection ID over 20 bytes, a reset token not 16 bytes), sent twice, or — from a client
  — one only a server sends: `TRANSPORT_PARAMETER_ERROR`, on both sides.
- **QUIC frames**: an unknown frame type, or a frame cut short, is
  `FRAME_ENCODING_ERROR`; a packet with no frames, a frame its packet type may not
  carry, or a DATAGRAM larger than we allowed, `PROTOCOL_VIOLATION` (§12.4, RFC 9221 §3).
- **Connection IDs are bounded**: a peer's retired IDs are not kept, the
  `RETIRE_CONNECTION_ID`s it has not acknowledged are capped at twice our
  `active_connection_id_limit` (`CONNECTION_ID_LIMIT_ERROR`, §5.1.2), as are its active IDs; a
  server issues at most 32 IDs per connection, and every route to a connection goes with it.
- **HTTP/3 and QPACK buffers are bounded**: a HEADERS frame larger than the field
  section size we advertise is refused before it is buffered; unknown frames are
  skipped as they arrive; a QPACK capacity or literal larger than we advertised is
  `QPACK_ENCODER_STREAM_ERROR`; bytes already parsed are dropped, not re-scanned.
- **0-RTT is off by default**, and on, held to one use per ticket, a freshness window,
  the same transport parameters, and safe requests only — see [0-RTT](#0-rtt-early-data).
- **HTTP/3 framing rules** are enforced: DATA before HEADERS is
  `H3_FRAME_UNEXPECTED`, a request stream without HEADERS is `H3_REQUEST_INCOMPLETE`;
  a control-stream frame on a request stream, or one of HTTP/2's reserved frame types
  anywhere, is `H3_FRAME_UNEXPECTED`; a payload that is not exactly its fields,
  `H3_FRAME_ERROR`.
- **HTTP/3's direction rules** (RFC 9114 §4.6, §5.2, §7.2): neither side takes part in
  server push, and each holds the other to that — at the server, `PUSH_PROMISE` is
  `H3_FRAME_UNEXPECTED`, a push stream `H3_STREAM_CREATION_ERROR`, `CANCEL_PUSH`
  `H3_ID_ERROR`; at the client, `MAX_PUSH_ID` is `H3_FRAME_UNEXPECTED`, a push stream,
  `PUSH_PROMISE` or `CANCEL_PUSH` `H3_ID_ERROR`. `MAX_PUSH_ID` that goes down, `GOAWAY`
  that goes up, or a server's `GOAWAY` naming anything but a request stream:
  `H3_ID_ERROR`. `SETTINGS` with one of HTTP/2's identifiers, one twice, or
  `SETTINGS_H3_DATAGRAM` / `SETTINGS_ENABLE_CONNECT_PROTOCOL` other than 0 or 1:
  `H3_SETTINGS_ERROR`.
- **HTTP/1.1 line endings**: a request must end its lines with CRLF — a bare LF is `400`,
  since a server that took one where a hop in front did not would read another message
  (request smuggling). A response may end them with LF alone, as RFC 9112 §2.2 allows and
  browsers and curl accept: the client is its last reader, with no one behind it to
  disagree. A bare CR is refused either way.
- **Key shares** (RFC 8446 §4.2.8): one of the wrong length, an ML-KEM key that is not
  one, a share for a group the client did not list, two for one group, or `key_share`
  without `supported_groups` — a fatal alert, never a handshake in a group the client did
  not agree to.
- **Our own failures are ours**: an exception inside the HTTP/3 code closes with
  `H3_INTERNAL_ERROR`, not a code that blames the peer; one inside the QUIC packet path
  drops that packet and is counted (`quic.context.internal_errors`).
- **Fuzzed**: every parser in front of a peer's bytes — QUIC frames, transport
  parameters, packet headers, HTTP/1.1, WebSocket, HPACK and HTTP/2 connections, QPACK,
  capsules — and HTTP/3 and QUIC frames on live connections, with mutated valid input and
  noise; none ends in an exception of its own, a hang, or an internal-error close.
- **Closing says so**: `server.close()` sends every connection its `CONNECTION_CLOSE`
  and closes the socket only once those have left, so clients learn at once rather than
  by their idle timeout.

To report a vulnerability, please see [SECURITY.md](./SECURITY.md) — or write to
**support@quicojs.dev** — rather than opening a public issue.

---

## ⚠️ Known Limitations

Being explicit about what is **not** implemented yet:

| Area | Status |
|---|---|
| **0-RTT** | HTTP/3, HTTP/2 and HTTP/1.1 (TLS 1.3); not DTLS. The client sends early only `GET`, `HEAD` and `OPTIONS` requests. Over HTTP/3, what it sends early assumes the default SETTINGS (no QPACK dynamic table), not the ones it was given last time — the safe choice, at the cost of a few header bytes. |
| **ECH** | Server and client (see [Encrypted Client Hello](#encrypted-client-hello-ech)). The client takes the key list from the application — it does not resolve HTTPS records itself. TLS only, not DTLS. |
| **Client-initiated migration** | The server takes a client that moves; the QUICO client itself has no API to move to another local address. |
| **ECN** | Not implemented — Node's `dgram` does not expose the required socket options. |
| **Path MTU discovery** | DPLPMTUD up to 1452-byte datagrams (see [Path MTU discovery](#path-mtu-discovery)). Its probes rely on the Don't Fragment bit, which Node's `dgram` cannot set: Linux sets it on UDP by default, Windows does not — there a probe can cross fragmented and be taken for a fit. |
| **Request bodies (`quico.request`)** | Streamed; only the first 64 KB are kept for sending again, so a larger body that started over one protocol cannot move to another. |
| **Server push** | Not implemented, on either side: the server sends no `PUSH_PROMISE`, the client allows none (it sends no `MAX_PUSH_ID`). Browsers have dropped it too. |
| **Post-quantum TLS** | Needs ML-KEM and ML-DSA in `node:crypto` (Node 24.7+, OpenSSL 3.5). Before that, classical only — `node:tls` there offers the hybrid through OpenSSL, which lemon-tls cannot reach. The hybrid ClientHello is ~1.4 KB: two QUIC Initial packets rather than one. Public CAs do not issue ML-DSA certificates yet. |
| **WebSocket** | No permessage-deflate. The client connects over HTTP/1.1 only. |
| **CONNECT-UDP** | Context ID 0 only (UDP payloads) — no CONNECT-IP, no extensions that register contexts. The client opens a connection per socket (no pooling of tunnels on one connection). |
| **Other transport parameters** | `max_ack_delay` and the rest are compiled in (see [Configuration](#-configuration--tuning)); the windows, stream limits, idle timeout and `disableActiveMigration` can be set. |

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
- Stream limits enforced in both directions, raised with `MAX_STREAMS`
- Delayed and batched ACKs, piggybacked on outgoing packets (RFC 9000 §13.2)
- Retry / address validation and the anti-amplification limit
- NAT rebinding with path validation
- Stateless reset
- Session resumption, server and client
- 0-RTT, server and client, over QUIC (RFC 9001 §4.6) and TLS 1.3 on TCP (RFC 8446 §4.2.10), with RFC 8470's 425; off by default
- HTTP/3 server and client (RFC 9114)
- QPACK with static and dynamic tables (RFC 9204)
- HTTP/2 and HTTP/1.1, implemented in QUICO — one stack for all three versions
- WebTransport client and server — streams + datagrams (RFC 9297)
- WebSocket over HTTP/1.1, HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220)
- Unreliable datagrams (RFC 9221)
- CONNECT-UDP proxy and client (RFC 9298)
- Stream priorities (RFC 9218) for HTTP/2 and HTTP/3, and WebTransport's `sendOrder` / `sendGroup`
- GOAWAY, 103 Early Hints
- JA4H, HTTP/2 and HTTP/3 fingerprints, `profileRequest()`
- `node:https`-style API — `createServer`, `request`, `get`, `Agent`
- Express / Fastify / Koa support
- Connection pooling, coalescing and multiplexing
- TLS keylog export
- **Interop: 6/6 implementations green** (handshake, transfer, http3, both directions)

### ⏳ Planned
- ChaCha20-Poly1305 (0x1303)
- Backpressure from a slow application reader into QUIC flow control
- TypeScript type definitions, kept in step with the API
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
