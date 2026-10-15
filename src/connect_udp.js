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
//  Proxying UDP in HTTP — CONNECT-UDP (RFC 9298), the server's side
//
//  A client asks the proxy for a UDP "socket" to one target — a host and a
//  port, named in the request's path by a URI template — and from then on
//  sends it UDP payloads, and receives the target's, as HTTP Datagrams
//  (RFC 9297): over HTTP/3 a QUIC DATAGRAM frame each (unreliable, as UDP
//  is), and otherwise — HTTP/2, HTTP/1.1, or an HTTP/3 peer that did not
//  negotiate datagrams — DATAGRAM capsules on the request stream.
//
//  This file is the protocol and the policy; it never touches a frame. Each
//  HTTP version hands it a carrier (h3_server, server.js for HTTP/2 and
//  HTTP/1.1) with five things it can do — accept, reject, send a payload to
//  the client, end, abort — and three it reports: a datagram, stream bytes
//  (capsules), the client's end or a reset. So the parsing, the relay, the
//  limits and the figures are written once for all three.
//
//  The application decides (server.on('connectUdp', (req, tunnel) => …)):
//
//    tunnel.accept()                        the proxy relays, to the target
//                                           the request names
//    tunnel.accept({ target: {host, port} }) …to another one
//    tunnel.accept({ socket })              …through the application's own
//                                           dgram socket
//    tunnel.accept({ relay: false })        no relay: the application gets
//                                           the client's payloads ('message')
//                                           and answers with tunnel.send()
//    tunnel.reject(status)
//
//  Defaults that protect the network the proxy sits in (RFC 9298 §7): a
//  target that resolves only to a private, loopback, link-local, multicast
//  or otherwise special address is refused (403, destination_ip_prohibited)
//  unless allowed; a connection may hold a bounded number of tunnels; a
//  tunnel with nothing passing for idleTimeout is closed (never under two
//  minutes, §3.1).
// ============================================================

import { EventEmitter } from 'node:events';
import dgram from 'node:dgram';
import dns from 'node:dns';
import net from 'node:net';
import { readVarInt, writeVarInt } from './utils.js';

var DEFAULT_TEMPLATE = '/.well-known/masque/udp/{target_host}/{target_port}/';
var MIN_IDLE_MS = 120000;           // §3.1: "SHOULD NOT use a period lower than two minutes"
var DEFAULT_MAX_PER_CONNECTION = 16;
var MAX_UDP_PAYLOAD = 65527;        // §5: the largest a UDP payload can be
var CAPSULE_DATAGRAM = 0x00;        // RFC 9297 §3.5
var EARLY_PAYLOADS_MAX = 32;        // payloads the client sent before the tunnel opened
var STREAM_QUEUE_MAX = 256 * 1024;  // capsules waiting to be sent before we drop (UDP's way)


// ============================================================
//  The target, from the request's path — the URI template (RFC 6570)
//
//  The proxy's template is what its clients are configured with; the
//  default is the one RFC 9298 §3 suggests. Two forms are read: variables in
//  the path ('{target_host}'), and a query expansion ('{?target_host,
//  target_port}'), whose parameters may come in any order. Values are
//  percent-decoded; an IPv6 literal arrives with its colons encoded (§3).
// ============================================================

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function compileTemplate(template) {
  template = String(template || DEFAULT_TEMPLATE);
  // An absolute template names the proxy's origin too; only its path and
  // query are matched here (the authority is the connection's).
  var m = /^[a-z][a-z0-9+.-]*:\/\/[^/]*(.*)$/i.exec(template);
  if (m) template = m[1] || '/';
  var query = null;
  var qm = /\{\?([^}]*)\}$/.exec(template);
  if (qm) { query = qm[1].split(',').map(function (s) { return s.trim(); }); template = template.slice(0, qm.index); }
  var names = [], re = '';
  var parts = template.split(/(\{[^}]*\})/);
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i];
    if (!p) continue;
    if (p.charAt(0) === '{') {
      var name = p.slice(1, -1).trim();
      names.push(name);
      re += '([^/?#&]*)';
    } else re += escapeRe(p);
  }
  // A trailing slash is the template's — a client that left it off means the
  // same resource.
  if (/\/$/.test(re)) re += '?';
  var vars = names.concat(query || []);
  if (vars.indexOf('target_host') < 0 || vars.indexOf('target_port') < 0) {
    throw new TypeError('connectUdp.template must contain {target_host} and {target_port}');
  }
  return { path: new RegExp('^' + re + (query ? '(?:\\?(.*))?' : '(?:\\?.*)?') + '$'), names: names, query: query };
}

function decode(s) {
  try { return decodeURIComponent(s); } catch (e) { return null; }
}

// { host, port } — or { error: 404 } when the path is not this proxy's
// resource, { error: 400 } when it is, with a target that cannot be (§3:
// empty, a port outside 1..65535).
function parseTarget(compiled, url) {
  var m = compiled.path.exec(String(url || ''));
  if (!m) return { error: 404 };
  var vars = {};
  for (var i = 0; i < compiled.names.length; i++) vars[compiled.names[i]] = m[i + 1];
  if (compiled.query) {
    var qs = m[compiled.names.length + 1] || '';
    qs.split('&').forEach(function (kv) {
      var eq = kv.indexOf('=');
      if (eq > 0) vars[kv.slice(0, eq)] = kv.slice(eq + 1);
    });
  }
  var host = vars.target_host != null ? decode(vars.target_host) : null;
  var portStr = vars.target_port != null ? decode(vars.target_port) : null;
  if (!host || !portStr || !/^[0-9]{1,5}$/.test(portStr)) return { error: 400 };
  var port = Number(portStr);
  if (port < 1 || port > 65535) return { error: 400 };
  if (host.charAt(0) === '[' && host.charAt(host.length - 1) === ']') host = host.slice(1, -1);
  if (host.indexOf('%') >= 0 && net.isIPv6(host.split('%')[0])) return { error: 400 };   // §3: no zone identifiers
  return { host: host, port: port };
}


// ============================================================
//  Addresses a proxy should not reach for a stranger (RFC 9298 §7)
//
//  Its own and its network's: loopback, private ranges, link-local,
//  carrier-grade NAT, multicast and broadcast, the unspecified address, and
//  the IPv6 forms of all of these (unique-local, an IPv4-mapped address).
// ============================================================

var blocked = new net.BlockList();
[['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
 ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
 ['224.0.0.0', 4], ['240.0.0.0', 4]].forEach(function (r) { blocked.addSubnet(r[0], r[1], 'ipv4'); });
[['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]].forEach(function (r) { blocked.addSubnet(r[0], r[1], 'ipv6'); });

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) return blocked.check(ip, 'ipv4');
  if (!net.isIPv6(ip)) return true;
  // An IPv4 address in IPv6 clothing (::ffff:10.0.0.1, or in hex) is that
  // IPv4 address.
  var low = ip.toLowerCase();
  var mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(low);
  if (mapped) return isPrivateAddress(mapped[1]);
  var hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(low);
  if (hex) {
    var a = parseInt(hex[1], 16), b = parseInt(hex[2], 16);
    return isPrivateAddress([a >> 8, a & 255, b >> 8, b & 255].join('.'));
  }
  return blocked.check(ip, 'ipv6');
}


// ============================================================
//  HTTP Datagrams and capsules (RFC 9297)
// ============================================================

// A UDP payload as an HTTP Datagram's payload: Context ID 0, then the bytes
// (§4 of RFC 9298).
function contextZero(payload) {
  var out = new Uint8Array(1 + payload.byteLength);
  out[0] = 0;
  out.set(payload, 1);
  return out;
}

// …and as a DATAGRAM capsule: type, length, value.
function datagramCapsule(payload) {
  var len = writeVarInt(1 + payload.byteLength);
  var out = new Uint8Array(1 + len.byteLength + 1 + payload.byteLength);
  out[0] = CAPSULE_DATAGRAM;
  out.set(len, 1);
  out[1 + len.byteLength] = 0;
  out.set(payload, 2 + len.byteLength);
  return out;
}

// An HTTP Datagram's payload → the UDP payload in it, or null: a Context ID
// other than 0 is one nobody registered here (§4: dropped).
function udpPayloadOf(u8) {
  var c = readVarInt(u8, 0);
  if (!c || c.value !== 0) return null;
  return u8.subarray(c.byteLength);
}

// Capsules from the request stream, however the bytes are split. DATAGRAM
// capsules go to onDatagram (their value: an HTTP Datagram payload); a
// capsule of another type is skipped (RFC 9297 §3.2: unknown types are
// ignored), and so is a DATAGRAM too large to carry a UDP payload — without
// buffering it (§5 of RFC 9298), so neither costs memory.
function createCapsuleParser(onDatagram, onDropped) {
  var pending = null, skip = 0;
  var MAX_VALUE = MAX_UDP_PAYLOAD + 8;
  return function feed(chunk) {
    if (!chunk || chunk.byteLength === 0) return;
    var u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
    while (u8.byteLength > 0) {
      if (skip > 0) {
        var n = Math.min(skip, u8.byteLength);
        skip -= n;
        u8 = u8.subarray(n);
        continue;
      }
      if (pending) {
        var joined = new Uint8Array(pending.byteLength + u8.byteLength);
        joined.set(pending, 0); joined.set(u8, pending.byteLength);
        u8 = joined; pending = null;
      }
      for (;;) {
        var t = readVarInt(u8, 0);
        var l = t && readVarInt(u8, t.byteLength);
        if (!t || !l) { pending = u8.byteLength ? u8 : null; u8 = new Uint8Array(0); break; }
        var hdr = t.byteLength + l.byteLength, len = l.value;
        if (t.value !== CAPSULE_DATAGRAM || len > MAX_VALUE) {
          if (t.value === CAPSULE_DATAGRAM && onDropped) onDropped();
          var avail = u8.byteLength - hdr;
          if (avail >= len) { u8 = u8.subarray(hdr + len); continue; }
          skip = len - avail;
          u8 = new Uint8Array(0);
          break;
        }
        if (u8.byteLength < hdr + len) { pending = u8; u8 = new Uint8Array(0); break; }
        onDatagram(u8.subarray(hdr, hdr + len));
        u8 = u8.subarray(hdr + len);
        if (u8.byteLength === 0) break;
      }
    }
  };
}


// ============================================================
//  The manager: one per server
//
//  Holds the policy (options.connectUdp) and the figures across tunnels;
//  handle(req, carrier, emit) is what each HTTP version calls with a
//  CONNECT-UDP request.
// ============================================================

function createConnectUdp(options) {
  options = options || {};
  var compiled = compileTemplate(options.template);
  var allowPrivateDefault = options.allowPrivate === true;
  var maxPerConnection = options.maxTunnelsPerConnection > 0 ? Math.floor(options.maxTunnelsPerConnection) : DEFAULT_MAX_PER_CONNECTION;
  var idleTimeout = options.idleTimeout === 0 ? 0 : Math.max(MIN_IDLE_MS, Number(options.idleTimeout) || MIN_IDLE_MS);
  var lookup = typeof options.lookup === 'function' ? options.lookup : dns.lookup;
  var proxyName = options.proxyName || 'quico';

  var perConnection = new WeakMap();   // carrier.connKey → tunnels open on it
  var active = new Set();
  var totals = { accepted: 0, rejected: 0, closed: 0,
                 packetsFromClient: 0, bytesFromClient: 0, packetsToClient: 0, bytesToClient: 0,
                 droppedFromClient: 0, droppedToClient: 0 };
  var COUNTERS = ['packetsFromClient', 'bytesFromClient', 'packetsToClient', 'bytesToClient', 'droppedFromClient', 'droppedToClient'];

  function proxyStatus(error, details) {
    return proxyName + '; error=' + error + (details ? '; details="' + String(details).replace(/["\\]/g, '') + '"' : '');
  }

  // A CONNECT-UDP request (HTTP/2, HTTP/3) or Upgrade (HTTP/1.1). `emit`
  // hands the tunnel to the application; false when nothing listens.
  function handle(req, carrier, emit) {
    var target = parseTarget(compiled, req.url);
    if (carrier.httpVersion === '1.1' && String(req.method).toUpperCase() !== 'GET') target = { error: 400 };   // §3.2
    if (target.error) {
      totals.rejected++;
      carrier.reject(target.error, null);
      return;
    }
    var key = carrier.connKey;
    var count = (key && perConnection.get(key)) || 0;
    if (count >= maxPerConnection) {
      totals.rejected++;
      carrier.reject(429, null);
      return;
    }
    if (key) perConnection.set(key, count + 1);
    var tunnel = new UdpTunnel(req, carrier, target);
    active.add(tunnel);
    tunnel.once('close', function () {
      active.delete(tunnel);
      if (key) { var c = perConnection.get(key) || 1; if (c <= 1) perConnection.delete(key); else perConnection.set(key, c - 1); }
      totals.closed++;
      if (tunnel._wasOpen) totals.accepted++; else totals.rejected++;
      for (var i = 0; i < COUNTERS.length; i++) totals[COUNTERS[i]] += tunnel._stats[COUNTERS[i]];
    });
    if (!emit(tunnel)) tunnel.reject(501);
  }

  // The figures: tunnels open now, and totals — those of open tunnels
  // included.
  function stats() {
    var out = { active: active.size, accepted: totals.accepted, rejected: totals.rejected, closed: totals.closed };
    for (var i = 0; i < COUNTERS.length; i++) out[COUNTERS[i]] = totals[COUNTERS[i]];
    active.forEach(function (t) {
      if (t._wasOpen && t.state === 'open') out.accepted++;
      for (var i = 0; i < COUNTERS.length; i++) out[COUNTERS[i]] += t._stats[COUNTERS[i]];
    });
    return out;
  }


  // ============================================================
  //  A tunnel
  // ============================================================

  function UdpTunnel(req, carrier, target) {
    EventEmitter.call(this);
    var self = this;
    this.req = req;
    this.target = { host: target.host, port: target.port };
    this.httpVersion = carrier.httpVersion;
    this.state = 'pending';        // → 'open' → 'closed'
    this.error = null;             // why it was refused or ended, when it was not the client
    this.closeReason = null;       // 'client', 'aborted', 'idle', 'local', 'socket', 'rejected'
    this._carrier = carrier;
    this._wasOpen = false;
    this._relay = null;            // { socket, own, address, port, onMessage, onError }
    this._early = [];              // payloads from the client before 'open'
    this._last = Date.now();
    this._idleTimer = null;
    this._stats = { openedAt: null, closedAt: null, address: null, port: null,
                    packetsFromClient: 0, bytesFromClient: 0, packetsToClient: 0, bytesToClient: 0,
                    droppedFromClient: 0, droppedToClient: 0 };
    carrier.sink = {
      datagram: function (u8) { self._fromClient(udpPayloadOf(u8)); },
      data: createCapsuleParser(function (u8) { self._fromClient(udpPayloadOf(u8)); },
                                function () { self._stats.droppedFromClient++; }),
      end: function () { self._ended('client'); },
      abort: function () { self._ended('aborted'); }
    };
  }
  Object.setPrototypeOf(UdpTunnel.prototype, EventEmitter.prototype);

  // A copy of the figures, with how the datagrams travel to the client now:
  // 'datagram' (QUIC DATAGRAM frames) or 'capsule' (the request stream).
  Object.defineProperty(UdpTunnel.prototype, 'stats', { get: function () {
    var s = Object.assign({ target: { host: this.target.host, port: this.target.port }, httpVersion: this.httpVersion,
                            state: this.state, transport: this._carrier.mode ? this._carrier.mode() : 'capsule' }, this._stats);
    s.durationMs = s.openedAt ? (s.closedAt || Date.now()) - s.openedAt : 0;
    return s;
  } });

  UdpTunnel.prototype.accept = function (opts) {
    if (this.state !== 'pending' || this._accepting) return this;
    opts = opts || {};
    var self = this;
    this._accepting = true;
    if (opts.target) {
      var p = Number(opts.target.port);
      if (!opts.target.host || !(p >= 1 && p <= 65535)) throw new TypeError('accept({ target }) needs a host and a port in 1..65535');
      this.target = { host: String(opts.target.host), port: p };
    }
    var headers = opts.headers || null;
    if (opts.relay === false) { this._open(headers); return this; }

    var allowPrivate = opts.allowPrivate != null ? !!opts.allowPrivate : allowPrivateDefault;
    var host = this.target.host;
    lookup(host, { all: true }, function (err, list) {
      if (self.state !== 'pending') return;
      if (err || !list || !list.length) {
        self._refuse(502, proxyStatus('dns_error', err && err.code), err || new Error('no address for ' + host));
        return;
      }
      if (!Array.isArray(list)) list = [{ address: list, family: net.isIPv6(list) ? 6 : 4 }];
      var pick = null;
      for (var i = 0; i < list.length && !pick; i++) if (allowPrivate || !isPrivateAddress(list[i].address)) pick = list[i];
      if (!pick) {
        var e = new Error('target ' + host + ' resolves only to addresses not allowed'); e.code = 'ERR_DESTINATION_PROHIBITED';
        self._refuse(403, proxyStatus('destination_ip_prohibited'), e);
        return;
      }
      var family = pick.family === 6 || pick.family === 'IPv6' ? 6 : 4;
      if (opts.socket) self._useSocket(opts.socket, false, pick.address, headers);
      else {
        var sock;
        try { sock = dgram.createSocket(family === 6 ? 'udp6' : 'udp4'); }
        catch (e2) { self._refuse(502, proxyStatus('proxy_internal_error'), e2); return; }
        sock.once('error', function (e3) {
          if (self.state === 'pending') self._refuse(502, proxyStatus('destination_ip_unroutable', e3.code), e3);
        });
        sock.connect(self.target.port, pick.address, function () {
          if (self.state !== 'pending') { try { sock.close(); } catch (e4) {} return; }
          self._useSocket(sock, true, pick.address, headers);
        });
      }
    });
    return this;
  };

  // The relay's socket: ours (connected to the target — the kernel keeps
  // other senders out), or the application's, whose senders are checked
  // here (§5: "MUST validate the IP source address and UDP source port").
  UdpTunnel.prototype._useSocket = function (sock, own, address, headers) {
    var self = this, port = this.target.port;
    var connected = own;
    if (!own) { try { connected = !!sock.remoteAddress(); } catch (e) { connected = false; } }
    var relay = { socket: sock, own: own, connected: connected, address: address, port: port };
    relay.onMessage = function (msg, rinfo) {
      if (!relay.connected && (rinfo.port !== port || rinfo.address !== address)) return;
      self._toClient(msg);
    };
    // The socket can no longer be used — an ICMP port unreachable, on a
    // connected socket: the request stream closes with it (§3.1).
    relay.onError = function (err) {
      if (self.state === 'closed') return;
      self.error = err;
      self._close('socket');
    };
    sock.on('message', relay.onMessage);
    sock.on('error', relay.onError);
    this._relay = relay;
    this._stats.address = address; this._stats.port = port;
    this._open(headers);
  };

  UdpTunnel.prototype._open = function (headers) {
    var h = { 'capsule-protocol': '?1' };
    for (var n in (headers || {})) h[String(n).toLowerCase()] = headers[n];
    this.state = 'open';
    this._wasOpen = true;
    this._stats.openedAt = Date.now();
    this._carrier.accept(h);
    this._touch();
    this._armIdle();
    this.emit('open');
    var early = this._early; this._early = null;
    for (var i = 0; early && i < early.length && this.state === 'open'; i++) this._deliver(early[i]);
  };

  UdpTunnel.prototype._refuse = function (status, ps, err) {
    if (this.state !== 'pending') return;
    this.error = err || null;
    this._carrier.reject(status, ps ? { 'proxy-status': ps } : null);
    this._close('rejected');
  };

  UdpTunnel.prototype.reject = function (status, headers) {
    if (this.state !== 'pending') return this;
    this._carrier.reject(status || 403, headers || null);
    this._close('rejected');
    return this;
  };

  // A UDP payload to the client — the target's (the relay), or the
  // application's (tunnel.send). false: not sent (closed, too large for the
  // path, or the stream already holds too much — UDP's answer to a full
  // queue is to drop).
  UdpTunnel.prototype.send = function (data) {
    if (typeof data === 'string') data = Buffer.from(data);
    if (!(data instanceof Uint8Array)) throw new TypeError('tunnel.send() takes a Buffer, a Uint8Array or a string');
    return this._toClient(data);
  };

  UdpTunnel.prototype._toClient = function (u8) {
    if (this.state !== 'open') return false;
    if (u8.byteLength > MAX_UDP_PAYLOAD || !this._carrier.sendPayload(u8)) { this._stats.droppedToClient++; return false; }
    this._stats.packetsToClient++;
    this._stats.bytesToClient += u8.byteLength;
    this._touch();
    return true;
  };

  UdpTunnel.prototype._fromClient = function (payload) {
    if (this.state === 'closed') return;
    if (!payload || payload.byteLength > MAX_UDP_PAYLOAD) { this._stats.droppedFromClient++; return; }
    if (this.state === 'pending') {
      // §3.4: a client may send before it has the 2xx. Kept, a few — they go
      // once the tunnel opens.
      if (this._early.length >= EARLY_PAYLOADS_MAX) { this._stats.droppedFromClient++; return; }
      this._early.push(Uint8Array.prototype.slice.call(payload));
      return;
    }
    this._deliver(payload);
  };

  UdpTunnel.prototype._deliver = function (payload) {
    this._stats.packetsFromClient++;
    this._stats.bytesFromClient += payload.byteLength;
    this._touch();
    var relay = this._relay;
    if (!relay) { this.emit('message', Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength)); return; }
    var self = this;
    var cb = function (err) { if (err) self._stats.droppedFromClient++; };
    try {
      if (relay.connected) relay.socket.send(payload, cb);
      else relay.socket.send(payload, relay.port, relay.address, cb);
    } catch (e) { this._stats.droppedFromClient++; }
  };

  UdpTunnel.prototype._touch = function () { this._last = Date.now(); };

  // One timer for the tunnel's life, not one per packet: when it fires it
  // looks at the last activity, and sleeps for what is left.
  UdpTunnel.prototype._armIdle = function () {
    if (!idleTimeout || this.state !== 'open') return;
    var self = this, wait = Math.max(1000, this._last + idleTimeout - Date.now());
    this._idleTimer = setTimeout(function () {
      self._idleTimer = null;
      if (self.state !== 'open') return;
      if (Date.now() - self._last >= idleTimeout) self._close('idle');
      else self._armIdle();
    }, wait);
    if (this._idleTimer.unref) this._idleTimer.unref();
  };

  UdpTunnel.prototype.close = function () {
    if (this.state === 'closed') return this;
    if (this.state === 'pending') return this.reject(503);
    this._close('local');
    return this;
  };

  // The client ended its side, or the stream went.
  UdpTunnel.prototype._ended = function (reason) {
    if (this.state === 'closed') return;
    this._close(reason);
  };

  UdpTunnel.prototype._close = function (reason) {
    if (this.state === 'closed') return;
    var wasPending = this.state === 'pending';
    this.state = 'closed';
    this.closeReason = reason;
    this._stats.closedAt = Date.now();
    this._early = null;
    if (this._idleTimer) { clearTimeout(this._idleTimer); this._idleTimer = null; }
    var relay = this._relay;
    this._relay = null;
    if (relay) {
      relay.socket.removeListener('message', relay.onMessage);
      relay.socket.removeListener('error', relay.onError);
      if (relay.own) { relay.socket.on('error', function () {}); try { relay.socket.close(); } catch (e) {} }
    }
    // The request stream with it (§3.1): ended (FIN) after the client's
    // end, ours (close()) or an idle one; reset when it broke — the socket
    // failed, the stream was reset, or the client left before any answer.
    // A refusal has sent its answer already.
    if (reason !== 'rejected') {
      if (wasPending || reason === 'aborted' || reason === 'socket') this._carrier.abort();
      else this._carrier.end();
    }
    this.emit('close', this.stats);
  };

  return { handle: handle, stats: stats, compiled: compiled };
}


// Is this request a CONNECT-UDP? Over HTTP/2 and HTTP/3, a CONNECT with
// :protocol connect-udp; over HTTP/1.1, an Upgrade to it (§3.2).
function isConnectUdp(req) {
  var h = (req && req.headers) || {};
  if (h[':protocol'] != null) return String(h[':protocol']).toLowerCase() === 'connect-udp';
  var up = h.upgrade;
  if (up == null) return false;
  return String(up).split(',').some(function (t) { return t.trim().toLowerCase() === 'connect-udp'; });
}


export { createConnectUdp, isConnectUdp, parseTarget, compileTemplate, isPrivateAddress,
         createCapsuleParser, datagramCapsule, contextZero, udpPayloadOf, MAX_UDP_PAYLOAD, STREAM_QUEUE_MAX };
