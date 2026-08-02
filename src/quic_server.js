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

import dgram from 'node:dgram';
import { DEBUG, Emitter } from './utils.js';
import {
  parse_quic_datagram,
  is_supported_version,
  build_version_negotiation
} from './transport.js';
import { QUICConnection } from './quic_connection.js';
import { createSecureContext } from './tls_bridge.js';


// ============================================================
//  createQuicServer(options)
//
//  Transport-only QUIC server. Owns the UDP socket(s), demultiplexes
//  incoming datagrams to per-peer QUICConnection objects, and emits a
//  'connection' event carrying the raw QUICConnection. It knows nothing
//  about HTTP/3 — application protocols (HTTP/3, DNS-over-QUIC, ...) are
//  layered on top by listening for 'connection' and then using the
//  connection's own stream/datagram API.
//
//  This is the connection-management harness that used to live inside
//  h3_server.js. h3_server now builds on it (wrapping each connection in
//  an H3Connection); other consumers (e.g. a DoQ server) can use it
//  directly.
//
//  Events:
//    'connection' (quic, peer)  — new QUICConnection created for a peer.
//                                  peer = { address, port }. Handlers
//                                  attach quic.on('connect'|'stream'|
//                                  'datagram'|'close') as needed.
//    'error'      (err)         — UDP socket / send error.
//
//  Options:
//    alpn            — ALPN protocol(s) to advertise (default 'h3').
//                      DoQ servers pass 'doq'.
//    SNICallback     — TLS SNI callback returning a SecureContext.
//    key/cert/ca     — convenience: build a default SecureContext when no
//                      SNICallback is given.
//    maxConnections  — capacity cap (default 10000).
//    socket/socket6  — externally-owned, already-bound UDP sockets
//                      (shared-port mode, RFC 9443). When provided, the
//                      caller feeds datagrams via handlePacket(msg, rinfo).
// ============================================================

function createQuicServer(options) {
  options = options || {};

  var ev = Emitter();
  var udp4 = null;
  var udp6 = null;
  var port = null;

  // ALPN to advertise on every accepted connection. Default ['h3'].
  var alpn = options.alpn || ['h3'];

  // ── External socket mode (shared UDP port) ──
  // When socket/socket6 are provided, the UDP layer is owned externally.
  // The caller demuxes packets and feeds them via handlePacket(msg, rinfo).
  // See RFC 9443 for the shared-port multiplexing scheme.
  var externalSocket4 = options.socket  || null;
  var externalSocket6 = options.socket6 || null;

  if (externalSocket4) {
    try { externalSocket4.address(); }
    catch (e) { throw new Error('options.socket must be bound before createQuicServer()'); }
  }
  if (externalSocket6) {
    try { externalSocket6.address(); }
    catch (e) { throw new Error('options.socket6 must be bound before createQuicServer()'); }
  }

  var isExternal = !!(externalSocket4 || externalSocket6);

  // Build SNICallback
  var sniCallback = options.SNICallback || null;

  if (!sniCallback && options.key && options.cert) {
    var defaultCtx = createSecureContext({ key: options.key, cert: options.cert, ca: options.ca });
    sniCallback = function (servername, cb) { cb(null, defaultCtx); };
  }

  // ---- Connection tracking ----
  var connections = {};     // connId → { quic, peer }
  var addressMap = {};      // "ip:port" → connId
  var maxConnections = options.maxConnections || 10000;
  var sweepTimer = null;


  // ============================================================
  //  UDP → connection routing
  // ============================================================

  function onUdpMessage(msg, rinfo) {
    var data = new Uint8Array(msg);
    var fromIp = rinfo.address;
    var fromPort = rinfo.port;
    if (DEBUG) console.log('[qserver] UDP from ' + fromIp + ':' + fromPort + ' len=' + data.length);

    var addressKey = fromIp + ':' + fromPort;
    var packets = parse_quic_datagram(data);
    if (packets.length === 0) return;

    // Route the whole datagram by its first packet. Coalesced packets in one
    // UDP datagram belong to the same connection (RFC 9000 §12.2), so a single
    // routing decision covers them all — and the datagram is parsed only once
    // here, handing the parsed packets straight to the connection (previously
    // each packet's raw bytes were re-parsed inside feedDatagram).
    // ── Version Negotiation (RFC 9000 §6) ──
    // Must happen before any connection is created. A long-header packet
    // carrying a version we don't speak gets a Version Negotiation packet in
    // reply — that is how a client discovers what we support, and how a prober
    // checks we are alive without completing a handshake.
    //
    // Getting this wrong is silent and confusing: without it, findConnectionId
    // below happily creates a connection for the unknown-version Initial, maps
    // the address to it, and every subsequent probe is routed into a
    // connection that cannot do anything with it. The peer sees no reply at
    // all and concludes the server is down.
    var firstPkt = packets[0];
    if (firstPkt.form === 'long' &&
        firstPkt.type !== 'version_negotiation' &&
        !is_supported_version(firstPkt.version)) {

      // Anti-amplification (RFC 9000 §14.1): only answer datagrams that are
      // at least 1200 bytes, so we can't be used to reflect traffic at a
      // spoofed source. A genuine Initial is always padded to that size.
      if (data.length < 1200) {
        if (DEBUG) console.log('[qserver] unsupported version 0x' +
          firstPkt.version.toString(16) + ' in a short datagram (' +
          data.length + 'B) — dropping without VN');
        return;
      }

      var vn = build_version_negotiation(firstPkt.dcid, firstPkt.scid);
      if (DEBUG) console.log('[qserver] version 0x' +
        firstPkt.version.toString(16) + ' unsupported — sending Version Negotiation');
      sendUdp(fromIp, fromPort, vn);
      return;
    }

    var connId = findConnectionId(firstPkt, addressKey);
    if (connId === null) return;  // stray/unmatched non-Initial packet — drop

    if (!(connId in connections)) {
      // Reject new connections when at capacity
      if (Object.keys(connections).length >= maxConnections) return;
      createConnection(connId, fromIp, fromPort, addressKey);
    }

    connections[connId].quic.feedPackets(fromIp, fromPort, packets);
  }


  function findConnectionId(pkt, addressKey) {
    var dcidStr = null;
    if (pkt.dcid && pkt.dcid.byteLength > 0) {
      dcidStr = Array.from(pkt.dcid).join('');
    }

    if (dcidStr && dcidStr in connections) return dcidStr;
    if (addressKey in addressMap && addressMap[addressKey] in connections) return addressMap[addressKey];

    // No existing connection matches. Only an Initial packet may *start* a new
    // connection; any other unmatched packet (a stray/late short-header packet,
    // or a Handshake whose Initial was lost, etc.) is dropped rather than
    // spawning a phantom connection keyed by a random id.
    if (pkt.type !== 'initial') return null;

    var id = dcidStr || String(Math.floor(Math.random() * 9007199254740991));
    addressMap[addressKey] = id;
    return id;
  }


  function createConnection(connId, fromIp, fromPort, addressKey) {
    var quic = new QUICConnection({ SNICallback: sniCallback, alpn: alpn });

    connections[connId] = {
      quic: quic,
      peer: { address: fromIp, port: fromPort }
    };

    addressMap[addressKey] = connId;

    // Send packets back via UDP
    quic.on('packet', function (data) {
      sendUdp(fromIp, fromPort, data);
    });

    // Drop our bookkeeping when the connection closes.
    quic.on('close', function () {
      delete connections[connId];
      if (addressMap[addressKey] === connId) delete addressMap[addressKey];
    });

    // Hand the raw connection to the application layer (H3, DoQ, ...).
    ev.emit('connection', quic, { address: fromIp, port: fromPort });
  }


  // ============================================================
  //  UDP send
  // ============================================================

  function sendUdp(toIp, toPort, data) {
    var isV6 = toIp.indexOf(':') >= 0;
    // Prefer external socket (shared mode) over internally-bound socket
    var socket = isV6
      ? (externalSocket6 || udp6)
      : (externalSocket4 || udp4);
    if (!socket) return;
    socket.send(data, toPort, toIp, function (err) {
      if (err) ev.emit('error', err);
    });
  }


  // ============================================================
  //  listen / close
  // ============================================================

  function listen(listenPort, host, callback) {
    if (typeof host === 'function') { callback = host; host = null; }
    port = listenPort || 443;
    host = host || '::';

    if (isExternal) {
      // External sockets already bound — wire up incoming messages.
      // Starting the sweep timer is safe here (idempotent check below).
      // Externally-owned sockets are already bound, so enlarge them here.
      // The owner may not have done it, and the cost of asking twice is nil.
      if (externalSocket4) {
        externalSocket4.on('message', onUdpMessage);
        try { externalSocket4.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
        try { externalSocket4.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}
      }
      if (externalSocket6) {
        externalSocket6.on('message', onUdpMessage);
        try { externalSocket6.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
        try { externalSocket6.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}
      }
      startSweepTimer();
      if (typeof callback === 'function') setImmediate(callback);
      return;
    }

    // Grow the kernel socket buffers once the socket is bound.
    //
    // Node's defaults are small. A full send buffer drops the datagram
    // locally and silently — indistinguishable from network loss, so loss
    // recovery engages and throughput collapses. See LOSS_PTO_PLAN 7.4: this
    // is what defeated the third pacer-calibration attempt.
    //
    // try/catch because some platforms cap the value and throw; not being
    // able to enlarge the buffer must not stop the server from listening.
    function growBuffers(sock) {
      try { sock.setSendBufferSize(2 * 1024 * 1024); } catch (e) {}
      try { sock.setRecvBufferSize(2 * 1024 * 1024); } catch (e) {}
    }

    udp4 = dgram.createSocket('udp4');
    udp4.on('message', onUdpMessage);
    udp4.on('error', function (err) { ev.emit('error', err); });
    var host4 = host.indexOf('.') !== -1 ? host : '0.0.0.0';
    udp4.bind(port, host4, function () { growBuffers(udp4); });

    udp6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
    udp6.on('message', onUdpMessage);
    udp6.on('error', function (err) { ev.emit('error', err); });
    var host6 = host.indexOf(':') !== -1 ? host : '::';
    udp6.bind(port, host6, function () {
      growBuffers(udp6);
      if (typeof callback === 'function') callback();
    });

    startSweepTimer();
  }

  // Periodic sweep for dead connections (safety net). Runs independently
  // of socket ownership so external-mode agents get the same cleanup.
  function startSweepTimer() {
    if (sweepTimer) return;  // idempotent
    sweepTimer = setInterval(function () {
      for (var id in connections) {
        var st = connections[id].quic.state;
        if (st === 'closed') {
          delete connections[id];
          // Clean address map
          for (var addr in addressMap) {
            if (addressMap[addr] === id) delete addressMap[addr];
          }
        }
      }
    }, 30000);
    if (sweepTimer.unref) sweepTimer.unref();
  }

  function close(callback) {
    // Stop sweep
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }

    // Close all connections
    for (var id in connections) {
      try { connections[id].quic.close(0, 'server closing'); } catch (e) { }
    }
    connections = {};
    addressMap = {};

    var closed = 0;
    var total = (udp4 ? 1 : 0) + (udp6 ? 1 : 0);
    if (total === 0) { if (callback) callback(); return; }

    function onClose() {
      closed++;
      if (closed >= total && typeof callback === 'function') callback();
    }

    if (udp4) { udp4.close(onClose); udp4 = null; }
    if (udp6) { udp6.close(onClose); udp6 = null; }
  }


  // ============================================================
  //  External packet API (for shared UDP port scenarios)
  // ============================================================

  // Query whether the given 5-tuple matches an active QUIC connection.
  // Used by the demuxer to disambiguate byte 0 in range 64-79 between
  // QUIC short header and TURN ChannelData (RFC 9443). Fresh connections
  // must be classified by byte 0 range (80-127 or 192+ = QUIC).
  function hasConnection(rinfo) {
    var key = rinfo.address + ':' + rinfo.port;
    return (key in addressMap) && (addressMap[key] in connections);
  }


  // ============================================================
  //  Server API
  // ============================================================

  return {
    listen: listen,
    close: close,
    on: function (name, fn) { ev.on(name, fn); },

    /** Feed an incoming UDP packet when running in external-socket mode.
     *  rinfo must be in Node's dgram format: { address, port, family, size }. */
    handlePacket: onUdpMessage,

    /** Returns true if the 5-tuple matches an active QUIC connection.
     *  Used by demuxers for routing decisions on shared UDP ports. */
    hasConnection: hasConnection
  };
}


export { createQuicServer };
