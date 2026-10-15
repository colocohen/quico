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
//  QUIC versions — what differs between them, in one place
//
//  QUIC v1 (RFC 9000/9001) and v2 (RFC 9369) are one protocol: the same
//  frames, the same handshake, the same recovery. v2 changes what an
//  on-path device could have learned to depend on — the version number, the
//  salt the Initial keys come from, the labels every packet key is derived
//  with, the Retry integrity key, and which long-header type bits mean
//  Initial, 0-RTT, Handshake and Retry — so that QUIC stays free to change
//  (anti-ossification). Everything a version decides lives in its profile
//  here, and every place that builds or reads a packet, or derives a key,
//  asks the connection's profile: the rest of the code is the same for all
//  versions, as lemon-tls's is for TLS 1.2 and 1.3.
//
//  A new version is a profile here, and its entry in COMPATIBLE when a first
//  flight in one can be read as the other (RFC 9368 §2.3).
// ============================================================

var QUIC_V1 = 0x00000001;
var QUIC_V2 = 0x6b3343cf;

function hex(s) { return new Uint8Array(Buffer.from(s, 'hex')); }

var PROFILES = {};

PROFILES[QUIC_V1] = {
  version: QUIC_V1,
  name: 'v1',
  // RFC 9001 §5.2
  initialSalt: hex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
  // RFC 9001 §5.1, §6.1
  labels: { key: 'quic key', iv: 'quic iv', hp: 'quic hp', ku: 'quic ku' },
  // RFC 9001 §5.8
  retryKey: hex('be0c690b9f66575a1d766b54e368c84e'),
  retryNonce: hex('461599d35d632bf2239825bb'),
  // RFC 9000 §17.2: long header type bits → packet type
  longTypes: ['initial', '0rtt', 'handshake', 'retry']
};

PROFILES[QUIC_V2] = {
  version: QUIC_V2,
  name: 'v2',
  // RFC 9369 §3.3.1
  initialSalt: hex('0dede3def700a6db819381be6e269dcbf9bd2ed9'),
  // RFC 9369 §3.3.2
  labels: { key: 'quicv2 key', iv: 'quicv2 iv', hp: 'quicv2 hp', ku: 'quicv2 ku' },
  // RFC 9369 §3.3.3
  retryKey: hex('8fb4b01b56ac48e260fbcbcead7ccc92'),
  retryNonce: hex('d86969bc2d7c6d9990efb04a'),
  // RFC 9369 §3.2: Retry 0b00, Initial 0b01, 0-RTT 0b10, Handshake 0b11
  longTypes: ['retry', 'initial', '0rtt', 'handshake']
};

// Which first flights can be read as another version's (RFC 9368 §2.3):
// v1 and v2 differ in nothing a ClientHello carries, both ways (RFC 9369 §4).
var COMPATIBLE = {};
COMPATIBLE[QUIC_V1] = [QUIC_V2];
COMPATIBLE[QUIC_V2] = [QUIC_V1];

/** The versions this implementation speaks, in its default preference. */
var SUPPORTED_VERSIONS = [QUIC_V1, QUIC_V2];

function versionProfile(version) {
  return PROFILES[version >>> 0] || null;
}

function isSupportedVersion(version) {
  return !!PROFILES[version >>> 0];
}

/** Whether a first flight in `from` can be taken as one in `to`. */
function isCompatible(from, to) {
  from >>>= 0; to >>>= 0;
  return from === to || (COMPATIBLE[from] || []).indexOf(to) >= 0;
}

/** Long header type bits → 'initial' | '0rtt' | 'handshake' | 'retry', or null. */
function longPacketType(version, typeBits) {
  var p = PROFILES[version >>> 0];
  return p ? p.longTypes[typeBits & 3] : null;
}

/** Packet type → its long header type bits in `version`. */
function longTypeBits(version, packetType) {
  var p = PROFILES[version >>> 0];
  var i = p ? p.longTypes.indexOf(packetType) : -1;
  if (i < 0) throw new Error('no long header type ' + packetType + ' in QUIC version 0x' + (version >>> 0).toString(16));
  return i;
}

/**
 * A version as an application names it — 1, 0x6b3343cf, 'v1', 'v2' — as a
 * version number; throws on one this implementation does not speak.
 */
function parseVersion(v, what) {
  var n = null;
  if (typeof v === 'number' && Number.isInteger(v)) n = v >>> 0;
  else if (typeof v === 'string') {
    var s = v.toLowerCase();
    for (var k in PROFILES) if (PROFILES[k].name === s) n = PROFILES[k].version;
  }
  if (n === null || !PROFILES[n]) throw new TypeError((what || 'quicVersions') + ': unsupported QUIC version ' + JSON.stringify(v) + ' (v1 or v2)');
  return n;
}

/** An option listing versions in preference order → [number, …]. */
function parseVersionList(list, what) {
  if (list === undefined || list === null) return null;
  if (!Array.isArray(list) || list.length === 0) throw new TypeError((what || 'quicVersions') + ' must be a non-empty array of QUIC versions');
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var n = parseVersion(list[i], what);
    if (out.indexOf(n) < 0) out.push(n);
  }
  return out;
}

function versionName(version) {
  var p = PROFILES[version >>> 0];
  return p ? p.name : '0x' + (version >>> 0).toString(16);
}

export {
  QUIC_V1, QUIC_V2, SUPPORTED_VERSIONS,
  versionProfile, isSupportedVersion, isCompatible,
  longPacketType, longTypeBits,
  parseVersion, parseVersionList, versionName
};
