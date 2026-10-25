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

// ============================================================
//  quico.connectUdp(proxy, target[, options][, callback]) — CONNECT-UDP's
//  client (RFC 9298)
//
//  A UDP "socket" to one target, through a proxy: what it returns behaves as
//  a connected dgram.Socket — 'connect', send(msg[, cb]), 'message' (msg,
//  rinfo), close(), 'close', 'error', remoteAddress() — so code written for
//  dgram moves to a proxied path by changing the line that makes the socket.
//
//  HTTP/3 first: each UDP payload a QUIC DATAGRAM frame (Quarter Stream ID,
//  Context ID 0, the payload) — unreliable, as UDP. If the proxy has not
//  answered QUIC within h3Timeout (UDP blocked on the way, a proxy without
//  HTTP/3), TCP: HTTP/2 extended CONNECT or HTTP/1.1 Upgrade, as ALPN
//  decides, with DATAGRAM capsules on the stream. The capsule format, and the
//  template, are the server's (connect_udp.js).
//
//  Over HTTP/3 the tunnels to one proxy share a connection (see below);
//  shareConnection: false gives a tunnel one of its own.
// ============================================================

import { EventEmitter } from 'node:events';
import dns from 'node:dns';
import net from 'node:net';
import lemonTls from 'lemon-tls';
import { readVarInt, writeVarInt } from './utils.js';
import { tlsIdentity, globalAgent } from './agent.js';
import { H3Connection, H3_ERR_NAME } from './h3.js';
import { H2Connection } from './h2.js';
import { createQuicClientSocket } from './quic_socket.js';
import { createCapsuleParser, datagramCapsule, udpPayloadOf, MAX_UDP_PAYLOAD, STREAM_QUEUE_MAX } from './connect_udp.js';

var DEFAULT_TEMPLATE_PATH = '/.well-known/masque/udp/{target_host}/{target_port}/';
var QUEUE_MAX = 64;   // payloads sent before the tunnel opened, held


// The request's path: the template with the target in it — the host
// percent-encoded (an IPv6 literal's colons too, §3), the port as a number.
// A query expansion ({?target_host,target_port}) is filled in as one.
function expandTemplate(template, host, port) {
  var vals = { target_host: encodeURIComponent(host), target_port: String(port) };
  return template.replace(/\{(\?)?([^}]*)\}/g, function (m, q, names) {
    var list = names.split(',').map(function (s) { return s.trim(); });
    if (q) return '?' + list.map(function (n) { return n + '=' + (vals[n] != null ? vals[n] : ''); }).join('&');
    return list.map(function (n) { return vals[n] != null ? vals[n] : ''; }).join(',');
  });
}

// The proxy: a URL — its origin, and, when it has {target_host}, the
// template too (as RFC 9298 clients are configured) — or { hostname, port,
// template }.
function parseProxy(proxy, options) {
  var p = {};
  if (typeof proxy === 'string' || proxy instanceof URL) {
    var s = String(proxy);
    var m = /^(https?):\/\/([^/?#]+)(.*)$/i.exec(s);
    if (!m) throw new TypeError('connectUdp: the proxy must be an https:// URL');
    var auth = m[2], rest = m[3] || '';
    var hp = /^\[([^\]]+)\](?::(\d+))?$/.exec(auth) || /^([^:]+)(?::(\d+))?$/.exec(auth);
    if (!hp) throw new TypeError('connectUdp: bad proxy authority ' + JSON.stringify(auth));
    p.hostname = hp[1]; p.port = hp[2] ? Number(hp[2]) : 443;
    p.template = rest.indexOf('{') >= 0 ? rest : (options.template || DEFAULT_TEMPLATE_PATH);
  } else if (proxy && typeof proxy === 'object') {
    p.hostname = proxy.hostname || proxy.host;
    p.port = Number(proxy.port) || 443;
    p.template = proxy.template || options.template || DEFAULT_TEMPLATE_PATH;
  } else throw new TypeError('connectUdp: a proxy URL or { hostname, port } is needed');
  if (!p.hostname) throw new TypeError('connectUdp: the proxy has no host');
  if (p.template.indexOf('{target_host}') < 0 && !/\{\?[^}]*target_host/.test(p.template)) {
    throw new TypeError('connectUdp: the template must contain {target_host} and {target_port}');
  }
  return p;
}

function connectUdp(proxy, target, options, callback) {
  if (typeof options === 'function') { callback = options; options = null; }
  options = options || {};
  var px = parseProxy(proxy, options);
  if (!target || !target.host) throw new TypeError('connectUdp: target { host, port } is needed');
  var port = Number(target.port);
  if (!(port >= 1 && port <= 65535)) throw new TypeError('connectUdp: target.port must be in 1..65535');
  var protocol = options.protocol || 'auto';
  if (['auto', 'h3', 'h2', 'http/1.1'].indexOf(protocol) < 0) throw new TypeError("connectUdp: protocol is 'auto', 'h3', 'h2' or 'http/1.1'");
  var sock = new UdpProxySocket(px, { host: String(target.host), port: port }, options, protocol);
  if (typeof callback === 'function') sock.once('connect', callback);
  return sock;
}


// ============================================================
//  The socket
// ============================================================

function UdpProxySocket(proxy, target, options, protocol) {
  EventEmitter.call(this);
  this._proxy = proxy;
  this._target = target;
  this._options = options;
  // The key-exchange groups to offer (tls.connect's ecdhCurve): a name not
  // implemented throws now, as tls.connect's does.
  if (options && options.ecdhCurve != null) lemonTls.parseEcdhCurve(options.ecdhCurve);
  if (options && options.sigalgs != null) lemonTls.parseSigalgs(options.sigalgs);
  this._wanted = protocol;
  this.protocol = null;          // 'h3', 'h2', 'http/1.1' — once the tunnel is open
  this.closeReason = null;       // 'local', 'proxy' (it ended the tunnel), 'error'
  this.statusCode = null;        // the proxy's answer
  this.responseHeaders = null;
  this._state = 'connecting';    // → 'open' → 'closed'
  this._t = null;                // the transport: { send(u8) → 'sent'|'dropped'|'too-big', mode(), maxPayload(), close(), destroy(), address() }
  this._queue = [];
  this._stats = { packetsSent: 0, bytesSent: 0, packetsReceived: 0, bytesReceived: 0, dropped: 0, openedAt: null, closedAt: null };
  this._path = expandTemplate(proxy.template, target.host, target.port);
  // Encrypted Client Hello to the proxy: options.ech, or GREASE ECH unless
  // echGrease is false. Rejected with new keys: once more, with them.
  // The keys the proxy sent on rejecting these before (retry_configs) are
  // kept by the agent and tried first, as quico.request's (client.js).
  this._echOriginal = options.ech || null;
  var echAgent = !this._echOriginal || options.agent === false ? null
    : (options.agent && typeof options.agent._getEchRetry === 'function' ? options.agent : globalAgent);
  this._echAgent = echAgent;
  this._echKey = echAgent ? echAgent._sessionKey('ech', proxy.hostname, proxy.port, {
    servername: options.servername, rejectUnauthorized: options.rejectUnauthorized, ca: options.ca, cert: options.cert, key: options.key,
    ech: options.ech, ecdhCurve: options.ecdhCurve, sigalgs: options.sigalgs
  }) : null;
  this._echKept = this._echKey ? echAgent._getEchRetry(this._echKey) : null;
  this._ech = this._echKept || this._echOriginal;
  this._echRetried = false;
  var self = this;
  process.nextTick(function () { self._start(); });
}
Object.setPrototypeOf(UdpProxySocket.prototype, EventEmitter.prototype);

// ECH rejected with the proxy's current keys: true when another attempt,
// with them, has been made.
UdpProxySocket.prototype._echRetry = function (err, again) {
  if (!err || err.code !== 'ERR_ECH_REJECTED' || this._state !== 'connecting') return false;
  // The kept keys rejected too: forgotten, and the caller's tried again.
  if (this._echKept) {
    this._echAgent._evictEchRetry(this._echKey);
    this._echKept = null;
    this._ech = this._echOriginal;
    again();
    return true;
  }
  if (!err.retryConfigs || this._echRetried) return false;
  this._echRetried = true;
  this._ech = err.retryConfigs;
  again();
  return true;
};
UdpProxySocket.prototype._echOptions = function () {
  return { ech: this._ech || undefined, echGrease: !this._ech && this._options.echGrease !== false };
};

UdpProxySocket.prototype._start = function () {
  if (this._state !== 'connecting') return;
  if (this._wanted === 'h2' || this._wanted === 'http/1.1') this._startTcp([this._wanted]);
  else this._startH3();
};

// The request's own fields: the extended CONNECT's pseudo-headers, the
// application's (a Proxy-Authorization, say), capsule-protocol.
UdpProxySocket.prototype._authority = function () {
  var h = this._proxy.hostname;
  if (net.isIPv6(h)) h = '[' + h + ']';
  return h + (this._proxy.port !== 443 ? ':' + this._proxy.port : '');
};
UdpProxySocket.prototype._extraHeaders = function () {
  var out = {}, h = this._options.headers || {};
  for (var n in h) out[String(n).toLowerCase()] = String(h[n]);
  if (out['capsule-protocol'] == null) out['capsule-protocol'] = '?1';
  return out;
};

// ---- the proxy answered ----

UdpProxySocket.prototype._answered = function (status, headers, protocol) {
  if (this._state !== 'connecting') return;
  this.statusCode = status;
  this.responseHeaders = headers;
  var ok = protocol === 'http/1.1' ? status === 101 : (status >= 200 && status < 300);
  if (!ok) {
    var err = new Error('CONNECT-UDP refused by the proxy: ' + status + (headers['proxy-status'] ? ' (' + headers['proxy-status'] + ')' : ''));
    err.code = 'ERR_CONNECT_UDP_REFUSED';
    err.statusCode = status;
    err.proxyStatus = headers['proxy-status'] || null;
    this._fail(err);
    return;
  }
  this.protocol = protocol;
  this._state = 'open';
  if (this._echRetried && this._echKey) this._echAgent._cacheEchRetry(this._echKey, this._ech);
  this._stats.openedAt = Date.now();
  var q = this._queue; this._queue = null;
  for (var i = 0; i < q.length; i++) this._sendNow(q[i].data, q[i].cb);
  this.emit('connect');
};

UdpProxySocket.prototype._payload = function (u8) {
  if (this._state === 'closed' || !u8) return;
  this._stats.packetsReceived++;
  this._stats.bytesReceived += u8.byteLength;
  var buf = Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);
  this.emit('message', buf, { address: this._target.host, family: net.isIPv6(this._target.host) ? 'IPv6' : net.isIPv4(this._target.host) ? 'IPv4' : '',
                              port: this._target.port, size: buf.length });
};

UdpProxySocket.prototype._fail = function (err) {
  if (this._state === 'closed') return;
  this._finish('error', err);
};

// The tunnel's end: its stream ended by the proxy, reset, or the connection
// gone.
UdpProxySocket.prototype._ended = function (err) {
  if (this._state === 'closed') return;
  if (this._state === 'connecting' && !err) {
    err = new Error('CONNECT-UDP: the proxy closed before answering'); err.code = 'ERR_CONNECT_UDP_CLOSED';
  }
  this._finish(err ? 'error' : 'proxy', err);
};

UdpProxySocket.prototype._finish = function (reason, err) {
  this._state = 'closed';
  this.closeReason = reason;
  this._stats.closedAt = Date.now();
  var q = this._queue; this._queue = null;
  for (var i = 0; q && i < q.length; i++) if (q[i].cb) process.nextTick(q[i].cb, notOpen());
  var t = this._t;
  if (t) { if (reason === 'local') t.close(); else t.destroy(); }
  if (err) this.emit('error', err);
  var self = this;
  process.nextTick(function () { self.emit('close'); });   // as a socket's: after 'error', a tick later
};

function notOpen() {
  var e = new Error('Not running'); e.code = 'ERR_SOCKET_DGRAM_NOT_RUNNING'; return e;
}

// ---- dgram.Socket's surface ----

// send(msg[, offset, length][, callback]) — a connected socket's forms.
// msg: a Buffer, a TypedArray, a DataView, a string, or an array of them
// (sent as one payload). Before the tunnel opens, held — as many as
// QUEUE_MAX — and sent when it does.
UdpProxySocket.prototype.send = function (msg, offset, length, port, address, callback) {
  var args = Array.prototype.slice.call(arguments);
  var cb = typeof args[args.length - 1] === 'function' ? args.pop() : null;
  // A port (and an address) — told from (offset, length) as dgram tells
  // them: by the address being a string. Not for a connected socket.
  if (args.length === 2 || args.length > 3 || (args.length === 3 && typeof args[2] === 'string')) {
    var ce = new Error('Already connected'); ce.code = 'ERR_SOCKET_DGRAM_IS_CONNECTED'; throw ce;
  }
  var data = toBytes(msg);
  if (args.length === 3) data = data.subarray(Number(args[1]) || 0, (Number(args[1]) || 0) + Number(args[2]));
  if (this._state === 'closed') { if (cb) process.nextTick(cb, notOpen()); return; }
  if (this._state === 'connecting') {
    if (this._queue.length >= QUEUE_MAX) { this._stats.dropped++; if (cb) process.nextTick(cb, null, data.byteLength); return; }
    this._queue.push({ data: Uint8Array.prototype.slice.call(data), cb: cb });
    return;
  }
  this._sendNow(data, cb);
};

UdpProxySocket.prototype._sendNow = function (data, cb) {
  if (data.byteLength > MAX_UDP_PAYLOAD) { if (cb) process.nextTick(cb, emsgsize()); return; }
  var r = this._t.send(data);
  if (r === 'too-big') { this._stats.dropped++; if (cb) process.nextTick(cb, emsgsize()); return; }
  if (r === 'dropped') this._stats.dropped++;    // as the kernel drops on a full queue: no error
  else { this._stats.packetsSent++; this._stats.bytesSent += data.byteLength; }
  if (cb) process.nextTick(cb, null, data.byteLength);
};

function emsgsize() {
  var e = new Error('send EMSGSIZE: larger than the tunnel carries (see maxPayloadSize)'); e.code = 'EMSGSIZE'; return e;
}

function toBytes(msg) {
  if (typeof msg === 'string') return Buffer.from(msg);
  if (Array.isArray(msg)) return Buffer.concat(msg.map(toBytes));
  if (msg instanceof Uint8Array) return msg;
  if (ArrayBuffer.isView(msg)) return new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength);
  if (msg instanceof ArrayBuffer) return new Uint8Array(msg);
  throw new TypeError('The "msg" argument must be a Buffer, TypedArray, DataView, string or array');
}

// Ends the tunnel: the request stream's end, then the connection's.
UdpProxySocket.prototype.close = function (callback) {
  if (typeof callback === 'function') this.once('close', callback);
  if (this._state === 'closed') return this;
  this._finish('local', null);
  return this;
};

// The target, as a connected dgram socket names its peer.
UdpProxySocket.prototype.remoteAddress = function () {
  if (this._state !== 'open') { var e = new Error('Not connected'); e.code = 'ERR_SOCKET_DGRAM_NOT_CONNECTED'; throw e; }
  var h = this._target.host;
  return { address: h, family: net.isIPv6(h) ? 'IPv6' : net.isIPv4(h) ? 'IPv4' : '', port: this._target.port };
};
// The local end of the connection to the proxy.
UdpProxySocket.prototype.address = function () {
  return this._t && this._t.address ? this._t.address() : {};
};
UdpProxySocket.prototype.ref = function () { return this; };
UdpProxySocket.prototype.unref = function () { return this; };

// The largest payload send() takes now: over HTTP/3 datagrams, what a QUIC
// DATAGRAM frame can carry on this path; over capsules, a UDP payload's.
Object.defineProperty(UdpProxySocket.prototype, 'maxPayloadSize', { get: function () {
  return this._t ? this._t.maxPayload() : 0;
} });
Object.defineProperty(UdpProxySocket.prototype, 'stats', { get: function () {
  var s = Object.assign({ protocol: this.protocol, transport: this._t ? this._t.mode() : null,
                          target: { host: this._target.host, port: this._target.port } }, this._stats);
  s.durationMs = s.openedAt ? (s.closedAt || Date.now()) - s.openedAt : 0;
  return s;
} });


// ============================================================
//  HTTP/3: one connection per proxy, shared by its tunnels
// ============================================================
//
// RFC 9298's tunnels are requests: as many as the proxy allows run over one
// HTTP/3 connection, each its own request stream, their datagrams told apart
// by Quarter Stream ID (RFC 9297 §2.1). A socket per connection — as this
// was — cost each tunnel a handshake (a round trip, two before 0.5 RTT of
// data on a lossy path), a congestion controller starting from nothing, and
// a UDP port; a VPN or a game client opening a tunnel per flow paid it per
// flow. Now a tunnel joins the connection its proxy already has — opened
// with the same TLS settings (agent.js tlsIdentity) — or waits for the one
// being made; the connection ends with its last tunnel.
// shareConnection: false keeps a tunnel on a connection of its own.

var h3Connections = new Map();   // pool key → ProxyH3Connection
var unsharedSeq = 0;

function h3PoolKey(proxy, o, ech) {
  if (o.shareConnection === false) return 'unshared#' + (++unsharedSeq);
  return [proxy.hostname, proxy.port, (o.quicVersions || []).join(','), tlsIdentity({
    servername: o.servername, rejectUnauthorized: o.rejectUnauthorized, ca: o.ca, cert: o.cert, key: o.key,
    ech: ech.ech, ecdhCurve: o.ecdhCurve, sigalgs: o.sigalgs
  }), ech.echGrease ? 'grease' : ''].join('|');
}

// TLS session resumption to the proxy, as quico.request has it: a session
// from the agent's cache (options.agent, or the global one; agent: false —
// none), each used once, and each the proxy sends kept there. An explicit
// options.session wins. Every tunnel began with a full handshake.
// transport: 'quic', or 'tcp:<alpn>'. A session the handshake then failed
// with is dropped.
function proxySessions(o, transport, proxy, ech) {
  var agent = o.agent === false ? null : (o.agent && typeof o.agent._sessionKey === 'function' ? o.agent : globalAgent);
  var key = agent ? agent._sessionKey(transport, proxy.hostname, proxy.port, {
    servername: o.servername, rejectUnauthorized: o.rejectUnauthorized, ca: o.ca, cert: o.cert, key: o.key,
    ech: ech.ech, ecdhCurve: o.ecdhCurve, sigalgs: o.sigalgs
  }) : null;
  var taken = false, offered;
  return {
    take: function () {
      if (o.session) return o.session;
      if (!taken) { taken = true; offered = key ? agent._takeSession(key) : undefined; }
      return offered;
    },
    keep: function (s) { if (key) agent._cacheSession(key, s); },
    failed: function () { if (key && taken && offered && !o.session) agent._evictSession(key); }
  };
}

function ProxyH3Connection(key, proxy, o, ech) {
  this.key = key;
  this.state = 'connecting';     // → 'open' → 'closing' | 'closed'
  this.quic = null; this.h3 = null; this.udp = null;
  this.waiters = [];             // (err, conn), until the handshake ends
  this.tunnels = new Map();      // request stream ID → the tunnel's handlers
  this.nextSid = 0;              // client bidirectional: 0, 4, 8, …
  this.sessions = proxySessions(o, 'quic', proxy, ech);
  var self = this;
  resolve(proxy.hostname, function (err, ip) {
    if (err) { self._failed(err); return; }
    if (self.state !== 'connecting') return;
    self.udp = createQuicClientSocket({
      remoteIp: ip, remotePort: proxy.port, hostname: o.servername || proxy.hostname,
      rejectUnauthorized: o.rejectUnauthorized !== false, ca: o.ca || null,
      key: o.key || null, cert: o.cert || null, passphrase: o.passphrase,
      quicVersions: o.quicVersions,
      startupCap: o.startupCap, pmtuDiscovery: o.pmtuDiscovery, maxUdpPayloadSize: o.maxUdpPayloadSize,
      initialRtt: o.initialRtt, reorderWindow: o.reorderWindow,
      ech: ech.ech, echGrease: ech.echGrease,
      ecdhCurve: o.ecdhCurve,
      sigalgs: o.sigalgs,
      session: self.sessions.take() || null,
      // Each ticket the proxy sends: the agent's, and each tunnel's 'session'.
      onSocket: function (q) {
        self.quic = q;
        // The connection is over the moment either side's CONNECTION_CLOSE is
        // known ('closing'), not when its draining period (RFC 9000 §10.2,
        // some 3 s) ends and 'close' comes: each tunnel on it is told at
        // once, and the connection leaves the pool at once — a tunnel opened
        // meanwhile joined a connection already closed, and failed. As the
        // WebTransport client hears it (r69). Only once open: a handshake
        // that ends is onError's to report — an ECH rejection is retried
        // there with the server's new keys, not failed.
        q.on('closing', function () { if (self.quic === q && self.state === 'open') self._gone(); });
        q.on('session', function (s) {
          self.sessions.keep(s);
          self.tunnels.forEach(function (t) { if (t.session) t.session(s); });
        });
      },
      onError: function (e) { if (self.state === 'connecting') { self.sessions.failed(); self._failed(e); } },
      onConnect: function (q, s) { self._connected(q, s); },
      // The connection went: each tunnel on it with it.
      onClose: function () { self._gone(); }
    });
  });
}

ProxyH3Connection.prototype._failed = function (err) {
  if (this.state !== 'connecting') return;
  this.state = 'closed';
  if (h3Connections.get(this.key) === this) h3Connections.delete(this.key);
  var w = this.waiters; this.waiters = [];
  for (var i = 0; i < w.length; i++) w[i](err, null);
};

ProxyH3Connection.prototype._connected = function (q, s) {
  var self = this;
  this.quic = q; this.udp = s;
  if (this.state !== 'connecting') { try { q.close(0x100, 'done', true); } catch (e) {} return; }
  // Every tunnel that waited gave up on HTTP/3 meanwhile (h3Timeout).
  if (this.waiters.length === 0) { this.state = 'closed'; h3Connections.delete(this.key); try { q.close(0x100, 'done', true); } catch (e) {} return; }
  this.state = 'open';
  var h3c = this.h3 = new H3Connection({ quicConnection: q, isServer: false, enableDatagrams: true });
  h3c.on('error', function () {});
  // The connection's events, each to the tunnel whose stream it names.
  function to(name) { return function (id) { var t = self.tunnels.get(id); if (t) t[name].apply(null, Array.prototype.slice.call(arguments, 1)); }; }
  h3c.on('http_headers', to('headers'));
  h3c.on('http_body', to('body'));
  h3c.on('http_end', to('end'));
  h3c.on('stream_reset', to('reset'));
  h3c.on('stream_error', to('error'));
  q.on('datagram', function (raw) {
    if (!raw || raw.byteLength === 0) return;
    var qid = readVarInt(raw, 0);
    if (!qid) return;
    var t = self.tunnels.get(qid.value * 4);
    if (t) t.datagram(raw.subarray(qid.byteLength));
  });
  h3c.sendControlStreams();
  var w = this.waiters; this.waiters = [];
  for (var i = 0; i < w.length; i++) w[i](null, this);
};

ProxyH3Connection.prototype._gone = function () {
  var was = this.state;
  this.state = 'closed';
  if (h3Connections.get(this.key) === this) h3Connections.delete(this.key);
  if (was === 'connecting') { this._failed(connLost()); return; }
  var ts = Array.from(this.tunnels.values()); this.tunnels.clear();
  for (var i = 0; i < ts.length; i++) ts[i].lost();
};

// A tunnel's stream, and its handlers.
ProxyH3Connection.prototype.open = function (handlers) {
  var sid = this.nextSid; this.nextSid += 4;
  this.tunnels.set(sid, handlers);
  return sid;
};

// A tunnel done with its stream. The last one closes the connection — once
// what was sent has been acknowledged (or a second has passed); a tunnel
// made after that opens another.
ProxyH3Connection.prototype.release = function (sid) {
  if (!this.tunnels.delete(sid) || this.tunnels.size > 0 || this.state !== 'open') return;
  this.state = 'closing';
  if (h3Connections.get(this.key) === this) h3Connections.delete(this.key);
  var q = this.quic;
  var t = setTimeout(done, 1000);
  q.whenAllSent(function () { clearTimeout(t); done(); });
  function done() { try { q.close(0x100, 'done', true); } catch (e) {} }
};

// The connection for this proxy: the open one, the one being made, or a new
// one. cb(err, conn) — once; cancel() takes the tunnel out of the wait.
function acquireH3(proxy, o, ech, cb) {
  var key = h3PoolKey(proxy, o, ech);
  var c = h3Connections.get(key);
  if (!c || c.state === 'closing' || c.state === 'closed') { c = new ProxyH3Connection(key, proxy, o, ech); h3Connections.set(key, c); }
  if (c.state === 'open') { var conn = c; process.nextTick(function () { cb(null, conn); }); return function () {}; }
  c.waiters.push(cb);
  return function cancel() {
    var i = c.waiters.indexOf(cb);
    if (i >= 0) c.waiters.splice(i, 1);
  };
}

UdpProxySocket.prototype._startH3 = function () {
  var self = this, o = this._options;
  var fallback = this._wanted === 'auto' && o.fallback !== false;
  var given = false, timer = null, cancel = null;

  // HTTP/3 given up on: this tunnel out of the wait, and TCP tried — or,
  // with no fallback, the socket fails.
  function giveUp(err) {
    if (given || self._state !== 'connecting') return;
    given = true;
    if (timer) { clearTimeout(timer); timer = null; }
    if (cancel) cancel();
    if (self._echRetry(err, function () { self._startH3(); })) return;
    if (fallback) self._startTcp(['h2', 'http/1.1']);
    else self._fail(err);
  }

  var h3Timeout = o.h3Timeout != null ? o.h3Timeout : 3000;
  if (fallback && h3Timeout > 0) {
    timer = setTimeout(function () {
      timer = null;
      var e = new Error('HTTP/3: no answer within h3Timeout'); e.code = 'ERR_HTTP3_TIMEOUT';
      giveUp(e);
    }, h3Timeout);
  }

  cancel = acquireH3(this._proxy, o, this._echOptions(), function (err, conn) {
    if (given) return;
    if (err) { giveUp(err); return; }
    given = true;
    if (timer) { clearTimeout(timer); timer = null; }
    if (self._state !== 'connecting') return;      // closed meanwhile
    self._overH3(conn);
  });
};

UdpProxySocket.prototype._overH3 = function (conn) {
  var self = this, q = conn.quic, h3c = conn.h3;
  var read = createCapsuleParser(function (u8) { self._payload(udpPayloadOf(u8)); }, function () { self._stats.dropped++; });
  function datagramsOn() { return h3c.context.remote_datagram_support === true && q.maxDatagramSize() > 0; }
  var busy = false, done = false;
  var sid = conn.open({
    headers: function (hdrs) {
      var status = parseInt(hdrs[':status'], 10) || 0;
      if (status >= 100 && status < 200) return;          // 1xx: the answer follows
      if (self._state !== 'connecting') return;           // trailers
      var fields = {};
      for (var n in hdrs) if (n.charAt(0) !== ':') fields[n] = hdrs[n];
      self._answered(status, fields, 'h3');
    },
    body: function (data) { if (self._state === 'open') read(data); },
    end: function () { release(); self._ended(null); },
    reset: function (code) {
      release();
      var e = new Error('CONNECT-UDP stream reset by the proxy: ' + (H3_ERR_NAME[code] || code)); e.code = 'ERR_CONNECT_UDP_RESET'; e.errorCode = code;
      self._ended(e);
    },
    error: function (code, reason) {
      release();
      var e = new Error('CONNECT-UDP stream error: ' + reason); e.code = 'ERR_HTTP3_STREAM_ERROR'; e.errorCode = code;
      self._ended(e);
    },
    datagram: function (u8) { self._payload(udpPayloadOf(u8)); },
    // The connection went: before the answer, the tunnel was never made;
    // after it, it was lost (a tunnel the proxy ended had its FIN first).
    session: function (s) { self.emit('session', s); },
    lost: function () { done = true; self._ended(self._state === 'open' ? connLost() : null); }
  });
  var qsid = writeVarInt(sid / 4);
  function release() { if (done) return; done = true; conn.release(sid); }

  this._t = {
    mode: function () { return datagramsOn() ? 'datagram' : 'capsule'; },
    maxPayload: function () {
      if (!datagramsOn()) return MAX_UDP_PAYLOAD;
      return Math.max(0, q.maxDatagramSize() - qsid.length - 1);   // Quarter Stream ID, Context ID 0
    },
    send: function (u8) {
      if (datagramsOn()) {
        var dg = new Uint8Array(qsid.length + 1 + u8.byteLength);
        dg.set(qsid, 0); dg[qsid.length] = 0;      // Quarter Stream ID, Context ID 0
        dg.set(u8, qsid.length + 1);
        if (dg.byteLength > q.maxDatagramSize()) return 'too-big';
        return q.sendDatagram(dg, null, null) ? 'sent' : 'dropped';
      }
      if (busy) return 'dropped';
      h3c.sendBody(sid, datagramCapsule(u8), false);
      busy = true;
      q.whenStreamSent(sid, STREAM_QUEUE_MAX, function () { busy = false; });
      return 'sent';
    },
    // Ours ends: FIN on the stream; the connection's end is the last
    // tunnel's (release).
    close: function () {
      if (done) return;
      try { h3c.sendBody(sid, null, true); } catch (e) {}
      release();
    },
    // Given up on: the stream reset (H3_REQUEST_CANCELLED), the others on
    // the connection untouched.
    destroy: function () {
      if (done) return;
      try { h3c.abortStream(sid, 0x10c); } catch (e) {}
      release();
    },
    address: function () { try { return conn.udp.address(); } catch (e) { return {}; } }
  };

  var h = { ':method': 'CONNECT', ':protocol': 'connect-udp', ':scheme': 'https', ':authority': this._authority(), ':path': this._path };
  var extra = this._extraHeaders();
  for (var k in extra) h[k] = extra[k];
  h3c.sendHeaders(sid, h, false);
};


// ============================================================
//  TCP: HTTP/2 (extended CONNECT, RFC 8441) or HTTP/1.1 (Upgrade)
// ============================================================

UdpProxySocket.prototype._startTcp = function (alpn) {
  var self = this, o = this._options;
  var socket;
  var sessions = proxySessions(o, 'tcp:' + alpn[0], this._proxy, this._echOptions());
  try {
    socket = lemonTls.connect({
      session: sessions.take() || undefined,
      host: this._proxy.hostname, port: this._proxy.port,
      servername: o.servername || (net.isIP(this._proxy.hostname) ? undefined : this._proxy.hostname),
      ALPNProtocols: alpn,
      rejectUnauthorized: o.rejectUnauthorized !== false, ca: o.ca,
      key: o.key, cert: o.cert, passphrase: o.passphrase,
      ech: this._echOptions().ech, echGrease: this._echOptions().echGrease,
      ecdhCurve: o.ecdhCurve,
      sigalgs: o.sigalgs
    }, function () {
      if (self._state !== 'connecting') { try { socket.destroy(); } catch (e) {} return; }   // closed meanwhile
      var p = socket.alpnProtocol;
      if (p === 'h2' && alpn.indexOf('h2') >= 0) self._overH2(socket);
      else if ((p === 'http/1.1' || !p) && alpn.indexOf('http/1.1') >= 0) self._overH1(socket);
      else {
        try { socket.destroy(); } catch (e) {}
        var e = new Error('the proxy negotiated ' + JSON.stringify(p) + ', not ' + alpn.join(' or ')); e.code = 'ERR_CONNECT_UDP_ALPN';
        self._fail(e);
      }
    });
  } catch (err) { this._fail(err); return; }
  socket.on('session', function (s) { sessions.keep(s); self.emit('session', s); });
  socket.on('error', function (err) {
    if (self._state === 'connecting') sessions.failed();
    if (self._echRetry(err, function () { self._startTcp(alpn); })) return;
    if (self._state === 'connecting') self._fail(err);
    else self._ended(err);
  });
};

// Capsules on a byte stream: what both TCP versions write, and how much may
// wait — past STREAM_QUEUE_MAX, a payload is dropped, as UDP drops.
function streamTransport(writable, write, close, destroy, address) {
  return {
    mode: function () { return 'capsule'; },
    maxPayload: function () { return MAX_UDP_PAYLOAD; },
    send: function (u8) {
      if (writable.destroyed || writable.writableLength > STREAM_QUEUE_MAX) return 'dropped';
      write(datagramCapsule(u8));
      return 'sent';
    },
    close: close, destroy: destroy, address: address
  };
}

UdpProxySocket.prototype._overH2 = function (socket) {
  var self = this;
  var h2 = new H2Connection({ isServer: false });
  var id = 1, opened = false, ended = false;
  var read = createCapsuleParser(function (u8) { self._payload(udpPayloadOf(u8)); }, function () { self._stats.dropped++; });
  h2.on('send', function (b) { if (!socket.destroyed) socket.write(b); });
  h2.on('error', function (err) { self._ended(err); try { socket.destroy(); } catch (e) {} });
  socket.on('data', function (d) { try { h2.execute(d); } catch (e) { self._ended(e); try { socket.destroy(); } catch (e2) {} } });
  socket.on('close', function () { self._ended(self._state === 'open' && !ended ? connLost() : null); });

  self._t = streamTransport(socket, function (bytes) { h2.sendData(id, Buffer.from(bytes), false); },
    function () { try { h2.sendData(id, null, true); } catch (e) {} setTimeout(function () { try { socket.end(); } catch (e) {} }, 50); },
    function () { try { socket.destroy(); } catch (e) {} },
    function () { try { return socket.address(); } catch (e) { return {}; } });

  // RFC 8441 §3: :protocol only once the server has said it takes it
  // (SETTINGS_ENABLE_CONNECT_PROTOCOL).
  h2.on('settings', function (o, list) {
    if (opened) return;
    opened = true;
    var ok = (list || []).some(function (s) { return s.id === 8 && s.value === 1; });
    if (!ok) {
      var e = new Error('the proxy does not take extended CONNECT over HTTP/2'); e.code = 'ERR_CONNECT_UDP_NOT_SUPPORTED';
      self._fail(e);
      return;
    }
    var list2 = [[':method', 'CONNECT'], [':protocol', 'connect-udp'], [':scheme', 'https'], [':authority', self._authority()], [':path', self._path]];
    var extra = self._extraHeaders();
    for (var k in extra) list2.push([k, extra[k]]);
    h2.sendHeaders(id, list2, false);
  });
  h2.on('headers', function (sid, hd) {
    if (sid !== id || self._state !== 'connecting') return;
    var fields = {}, status = 0;
    var pairs = Array.isArray(hd) ? hd : Object.keys(hd).map(function (k) { return [k, hd[k]]; });
    for (var i = 0; i < pairs.length; i++) {
      if (pairs[i][0] === ':status') status = parseInt(pairs[i][1], 10) || 0;
      else if (pairs[i][0].charAt(0) !== ':') fields[pairs[i][0]] = pairs[i][1];
    }
    if (status >= 100 && status < 200) return;
    self._answered(status, fields, 'h2');
  });
  h2.on('data', function (sid, d) { if (sid === id && self._state === 'open') read(d); });
  h2.on('end', function (sid) { if (sid === id) { ended = true; self._ended(null); } });
  h2.on('rst', function (sid, code) {
    if (sid !== id) return;
    var e = new Error('CONNECT-UDP stream reset by the proxy (HTTP/2 error ' + code + ')'); e.code = 'ERR_CONNECT_UDP_RESET'; e.errorCode = code;
    self._ended(e);
  });
  h2.sendPreface();
};

UdpProxySocket.prototype._overH1 = function (socket) {
  var self = this;
  var head = Buffer.alloc(0), inHead = true;
  var read = createCapsuleParser(function (u8) { self._payload(udpPayloadOf(u8)); }, function () { self._stats.dropped++; });
  self._t = streamTransport(socket, function (bytes) { socket.write(bytes); },
    function () { try { socket.end(); } catch (e) {} },
    function () { try { socket.destroy(); } catch (e) {} },
    function () { try { return socket.address(); } catch (e) { return {}; } });
  socket.on('data', function (d) {
    if (!inHead) { if (self._state === 'open') read(d); return; }
    head = Buffer.concat([head, d]);
    var end = head.indexOf('\r\n\r\n');
    if (end < 0) { if (head.length > 65536) self._fail(new Error('CONNECT-UDP: response head too large')); return; }
    inHead = false;
    var lines = head.subarray(0, end).toString('latin1').split('\r\n');
    var m = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0]);
    var fields = {};
    for (var i = 1; i < lines.length; i++) {
      var c = lines[i].indexOf(':');
      if (c > 0) fields[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim();
    }
    var status = m ? Number(m[1]) : 0;
    if (status === 101 && String(fields.upgrade || '').toLowerCase() !== 'connect-udp') status = 0;
    self._answered(status, fields, 'http/1.1');
    if (self._state === 'open' && head.length > end + 4) read(head.subarray(end + 4));
    head = null;
  });
  socket.on('end', function () { self._ended(null); });
  socket.on('close', function () { self._ended(null); });
  var req = 'GET ' + self._path + ' HTTP/1.1\r\nHost: ' + self._authority() + '\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n';
  var extra = self._extraHeaders();
  for (var k in extra) req += k + ': ' + extra[k].replace(/[\r\n]/g, '') + '\r\n';
  socket.write(req + '\r\n');
};

function connLost() {
  var e = new Error('CONNECT-UDP: the connection to the proxy was lost'); e.code = 'ERR_CONNECT_UDP_CLOSED'; return e;
}

function resolve(host, cb) {
  if (net.isIP(host)) { cb(null, host); return; }
  if (host === 'localhost') { cb(null, '127.0.0.1'); return; }
  dns.lookup(host, function (err, address) { cb(err, address); });
}


export { connectUdp, UdpProxySocket, expandTemplate };
