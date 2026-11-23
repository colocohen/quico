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

import { random_bytes_sync } from 'cryptographic-primitives/random.js';
import { equal_sync } from 'cryptographic-primitives/ct.js';
import { aes_gcm_create, aes_ecb_create, aes_ecb_encrypt_sync } from 'cryptographic-primitives/aes.js';
import { chacha20poly1305_create, chacha20_sync } from 'cryptographic-primitives/chacha.js';

// The TLS key schedule's helpers, lemon-tls's (on cryptographic-primitives)
import {
  crypto as tlsCrypto
} from 'lemon-tls';

var hkdf_extract = tlsCrypto.hkdf_extract;
var hkdf_expand_label = tlsCrypto.hkdf_expand_label;
var getHashFn = tlsCrypto.getHashFn;
var getHashLen = tlsCrypto.getHashLen;
var TLS_CIPHER_SUITES = tlsCrypto.TLS_CIPHER_SUITES;

import {
  concatUint8Arrays,
  readVarInt,
  varIntSize,
  writeVarIntInto
} from './utils.js';
import { versionProfile, longTypeBits, longPacketType, QUIC_V1 } from './quic_version.js';

// The profile of a version that keys are being derived for, or an error.
function profileOf(version) {
  var p = versionProfile(version === undefined ? QUIC_V1 : version);
  if (!p) throw new Error('Unsupported QUIC version: 0x' + (version >>> 0).toString(16));
  return p;
}


// ============================================================
//  Key derivation
// ============================================================

/**
 * Derive an Initial-packet secret + keys from the client's original DCID.
 *
 * `direction` selects WHICH endpoint's Initial secret to derive — it is NOT
 * "the keys I read/write with" in the obvious sense:
 *   'read'  → the client's secret  (TLS label "client in")
 *   'write' → the server's secret  (TLS label "server in")
 * Each role then maps these to its own read/write keys: a client WRITES with
 * the "client in" secret and READS with "server in"; a server is the mirror.
 * So callers pass 'read' to get the client-side keys and 'write' for the
 * server-side keys, and assign them to initial_read / initial_write per role.
 */
function quic_derive_init_secrets(client_dcid, version, direction) {
  var hashName = 'sha256';
  var profile = profileOf(version);
  var L = profile.labels;

  var label = direction === 'read' ? 'client in' : 'server in';
  var initial_secret = hkdf_extract(hashName, profile.initialSalt, client_dcid);

  var side_secret = hkdf_expand_label(
    hashName, initial_secret, label, new Uint8Array(0), 32
  );

  return {
    key: hkdf_expand_label(hashName, side_secret, L.key, new Uint8Array(0), 16),
    iv:  hkdf_expand_label(hashName, side_secret, L.iv,  new Uint8Array(0), 12),
    hp:  hkdf_expand_label(hashName, side_secret, L.hp,  new Uint8Array(0), 16)
  };
}


/**
 * Derive QUIC keys from a TLS traffic secret (handshake or app).
 * cipher: TLS cipher suite code (e.g. 0x1301). Used to determine key length.
 * version: the connection's QUIC version (its labels).
 */
function quic_derive_from_tls_secrets(traffic_secret, hashName, cipher, version) {
  if (!traffic_secret) return null;
  var L = profileOf(version).labels;
  var keyLen = 16; // default AES-128
  if (cipher && TLS_CIPHER_SUITES[cipher]) {
    keyLen = TLS_CIPHER_SUITES[cipher].keylen;
  } else if (hashName === 'sha384') {
    keyLen = 32; // AES-256 for SHA-384 based cipher suites
  }
  return {
    key: hkdf_expand_label(hashName, traffic_secret, L.key, new Uint8Array(0), keyLen),
    iv:  hkdf_expand_label(hashName, traffic_secret, L.iv,  new Uint8Array(0), 12),
    hp:  hkdf_expand_label(hashName, traffic_secret, L.hp,  new Uint8Array(0), keyLen),
    aead: aead_for_suite(cipher, keyLen)
  };
}


/**
 * Key Update (RFC 9001 §6): derive next secret + keys from current secret.
 * next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", hash_len)
 */
function quic_derive_key_update(current_secret, hashName, cipher, version) {
  var L = profileOf(version).labels;
  var hashLen = getHashLen(hashName);
  var keyLen = 16;
  if (cipher && TLS_CIPHER_SUITES[cipher]) {
    keyLen = TLS_CIPHER_SUITES[cipher].keylen;
  } else if (hashName === 'sha384') {
    keyLen = 32;
  }
  // The header protection key does not change with a key update (RFC 9001
  // §6); derived here only to keep the shape, the caller keeps the old one.
  var next_secret = hkdf_expand_label(hashName, current_secret, L.ku, new Uint8Array(0), hashLen);
  return {
    secret: next_secret,
    key: hkdf_expand_label(hashName, next_secret, L.key, new Uint8Array(0), keyLen),
    iv:  hkdf_expand_label(hashName, next_secret, L.iv,  new Uint8Array(0), 12),
    hp:  hkdf_expand_label(hashName, next_secret, L.hp,  new Uint8Array(0), keyLen),
    aead: aead_for_suite(cipher, keyLen)
  };
}


// ============================================================
//  AEAD (AES-GCM)
// ============================================================

function compute_nonce(iv, packetNumber) {
  var nonce = new Uint8Array(iv);
  var n = packetNumber;
  for (var i = 11; n > 0 && i >= 0; i--) {
    nonce[i] ^= n & 0xff;
    n = Math.floor(n / 256);
  }
  return nonce;
}

// compute_nonce into one scratch array, for the packet paths: the AEAD reads
// the nonce during the call and keeps nothing of it, and one packet is sealed
// or opened before the next, so a new 12-byte array per packet is not needed.
// Valid until the next call.
var NONCE = new Uint8Array(12);
function packet_nonce(iv, packetNumber) {
  if (iv.length !== 12) return compute_nonce(iv, packetNumber);
  for (var j = 0; j < 12; j++) NONCE[j] = iv[j];
  var n = packetNumber;
  for (var i = 11; n > 0 && i >= 0; i--) {
    NONCE[i] ^= n & 0xff;
    n = Math.floor(n / 256);
  }
  return NONCE;
}

// The AEAD of a key set (RFC 9001 §5.3): named by the TLS 1.3 suite that
// derived it — not guessed from the key's length, which is 32 bytes for both
// AES-256-GCM and ChaCha20-Poly1305. A set without one (Initial keys, which
// are always AES-128-GCM — §5.2) goes by its length, AES.
function aead_for_suite(cipher, keyLen) {
  if (cipher === 0x1303) return 'chacha20-poly1305';
  return keyLen === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
}
function aead_algo(key, aead) {
  if (aead) return aead;
  if (key.length === 16) return 'aes-128-gcm';
  if (key.length === 32) return 'aes-256-gcm';
  throw new Error('Unsupported key length: ' + key.length);
}

// One keyed AEAD context per key, from cryptographic-primitives: the key
// schedule (and GCM's hash table) once, where createCipheriv redid it for
// every packet. The library picks the engine per packet by its size - a
// short one in JavaScript, a long one in node:crypto. Kept with the key
// array itself (a key set's, which lives as long as the keys and is never
// written to: a key update derives new arrays).
var aeadContexts = new WeakMap();
function aead_of(key, algo) {
  var c = aeadContexts.get(key);
  if (!c) {
    c = algo === 'chacha20-poly1305' ? chacha20poly1305_create(key) : aes_gcm_create(key);
    aeadContexts.set(key, c);
  }
  return c;
}

function aead_encrypt(key, iv, packetNumber, plaintext, aad, aead) {
  try {
    return aead_of(key, aead_algo(key, aead)).encrypt_sync(compute_nonce(iv, packetNumber), plaintext, aad);
  } catch (e) {
    return null;
  }
}

function aead_decrypt(key, nonce, ciphertext, tag, aad, aead) {
  try {
    // ciphertext || tag: one view when they are adjacent in the packet,
    // joined otherwise
    var sealed = (ciphertext.buffer === tag.buffer && ciphertext.byteOffset + ciphertext.length === tag.byteOffset)
      ? new Uint8Array(ciphertext.buffer, ciphertext.byteOffset, ciphertext.length + tag.length)
      : concatUint8Arrays([ciphertext, tag]);
    return aead_open(key, nonce, sealed, aad, aead);
  } catch (e) {
    return null;
  }
}

// `sealed` (ciphertext || tag) opened: the plaintext over its own memory (the
// library's output, never a slice of a larger buffer the stream data handed
// on from it would keep alive), or null when it does not authenticate.
function aead_open(key, nonce, sealed, aad, aead) {
  try {
    return aead_of(key, aead_algo(key, aead)).decrypt_sync(nonce, sealed, aad);
  } catch (e) {
    return null;
  }
}


// ============================================================
//  Retry packets (RFC 9000 §17.2.5, RFC 9001 §5.8)
// ============================================================

// The Retry Integrity Tag: AES-128-GCM under a key and nonce fixed by each
// version (RFC 9001 §5.8, RFC 9369 §3.3.3), over nothing, authenticating the
// "Retry Pseudo-Packet" — the client's original DCID (length-prefixed)
// followed by the Retry packet itself. The key is public: the tag proves not
// who sent the Retry but that it answers this client's Initial, which only
// something that saw that Initial could know the DCID of.
function retry_integrity_tag(originalDcid, retryWithoutTag, version) {
  var profile = profileOf(version);
  var aad = new Uint8Array(1 + originalDcid.length + retryWithoutTag.length);
  aad[0] = originalDcid.length;
  aad.set(originalDcid, 1);
  aad.set(retryWithoutTag, 1 + originalDcid.length);
  // an empty plaintext: what is sealed is the tag alone
  return aead_of(profile.retryKey, 'aes-128-gcm').encrypt_sync(profile.retryNonce, EMPTY, aad);
}
var EMPTY = new Uint8Array(0);

/**
 * A Retry packet (§17.2.5): to `dcid` (the client's SCID), from `scid` (the
 * ID the client is to use next), carrying `token`, tagged for the client's
 * original DCID — in `version`, the version of the client's Initial (a Retry
 * is always in it, RFC 9369 §4.1).
 */
function build_retry_packet(dcid, scid, token, originalDcid, version) {
  if (version === undefined) version = QUIC_V1;
  var head = new Uint8Array(1 + 4 + 1 + dcid.length + 1 + scid.length + token.length);
  var o = 0;
  // Long header, fixed bit, the version's Retry type; the low four bits are
  // unused and random.
  head[o++] = 0xc0 | (longTypeBits(version, 'retry') << 4) | (random_bytes_sync(1)[0] & 0x0f);
  head[o++] = (version >>> 24) & 0xff; head[o++] = (version >>> 16) & 0xff;
  head[o++] = (version >>> 8) & 0xff; head[o++] = version & 0xff;
  head[o++] = dcid.length; head.set(dcid, o); o += dcid.length;
  head[o++] = scid.length; head.set(scid, o); o += scid.length;
  head.set(token, o);
  var out = new Uint8Array(head.length + 16);
  out.set(head, 0);
  out.set(retry_integrity_tag(originalDcid, head, version), head.length);
  return out;
}

/**
 * A client's view of a Retry packet it received (the whole packet, `raw`):
 * { scid, token } if its tag is right for `originalDcid`, else null.
 */
function open_retry_packet(raw, originalDcid) {
  if (raw.length < 1 + 4 + 1 + 1 + 16) return null;
  var version = ((raw[1] << 24) | (raw[2] << 16) | (raw[3] << 8) | raw[4]) >>> 0;
  if (!versionProfile(version)) return null;
  var o = 5;
  var dcidLen = raw[o++]; o += dcidLen;
  if (o >= raw.length) return null;
  var scidLen = raw[o++];
  var scid = raw.slice(o, o + scidLen); o += scidLen;
  if (o > raw.length - 16) return null;
  var body = raw.subarray(0, raw.length - 16);
  var expected = retry_integrity_tag(originalDcid, body, version);
  if (!equal_sync(expected, raw.subarray(raw.length - 16))) return null;
  return { scid: scid, token: raw.slice(o, raw.length - 16) };
}


// ============================================================
//  Header protection (RFC 9001 §5.4)
// ============================================================

function aes_ecb_encrypt(key, plaintext) {
  return aes_ecb_encrypt_sync(key, plaintext);
}

// The AES header-protection context of a key, made once and kept with it:
// the key schedule once, then one block per packet (the library runs a
// 16-byte block in JavaScript - faster than a call into OpenSSL). One cipher
// was created per packet, on each side: about 3% of all CPU in a bulk
// transfer, for a 16-byte encryption. Keyed by the key array itself (a key
// set's `hp`, which lives as long as the keys), and forgotten with it.
var hpCiphers = new WeakMap();
function aes_hp_cipher(key) {
  var c = hpCiphers.get(key);
  if (!c) {
    c = aes_ecb_create(key);
    hpCiphers.set(key, c);
  }
  return c;
}

// The AES sample copied into one scratch array, not viewed: a packet's mask
// is computed before the next packet's (all of it synchronous), and the
// library takes a plain 16-byte array for less than a view of the packet.
// (Its encrypt_into_sync, into a scratch mask, cost more than the new mask
// it saves - measured.)
var HP_SAMPLE = new Uint8Array(16);

var ZERO5 = new Uint8Array(5);
// The 5-byte mask from the 16-byte sample at packet[at..at+16). AES
// (§5.4.3): the sample encrypted under the HP key. ChaCha20 (§5.4.4): the
// sample's first 4 bytes are the block counter (little-endian), the other 12
// the nonce, and the mask is ChaCha20 of five zero bytes, from that counter
// and nonce - in JavaScript, where a call into OpenSSL per packet cost more
// than the five bytes.
function hp_mask(hpKey, packet, at, aead) {
  if (aead === 'chacha20-poly1305') {
    var counter = (packet[at] | (packet[at + 1] << 8) | (packet[at + 2] << 16) | (packet[at + 3] << 24)) >>> 0;
    return chacha20_sync(hpKey, packet.subarray(at + 4, at + 16), ZERO5, counter);
  }
  for (var i = 0; i < 16; i++) HP_SAMPLE[i] = packet[at + i];
  return aes_hp_cipher(hpKey).encrypt_sync(HP_SAMPLE);
}

function apply_header_protection(packet, pnOffset, hpKey, pnLength, aead) {
  // The mask is computed from the sample before anything is changed, and
  // nothing the sample covers is changed.
  // (Written so that a NaN offset, from a header cut short, fails it too.)
  if (!(pnOffset + 4 + 16 <= packet.length)) throw new Error('Not enough bytes for HP sample');

  var mask = hp_mask(hpKey, packet, pnOffset + 4, aead);
  var isLong = (packet[0] & 0x80) !== 0;

  packet[0] ^= mask[0] & (isLong ? 0x0f : 0x1f);

  for (var i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }
  return packet;
}

function remove_header_protection(array, pnOffset, hpKey, isShort, aead) {
  if (!(pnOffset + 4 + 16 <= array.length)) return null;   // too short to carry a sample: not a packet
  var mask = hp_mask(hpKey, array, pnOffset + 4, aead);

  if (isShort) {
    array[0] ^= mask[0] & 0x1f;
  } else {
    array[0] ^= mask[0] & 0x0f;
  }

  var pnLength = (array[0] & 0x03) + 1;

  for (var i = 0; i < pnLength; i++) {
    array[pnOffset + i] ^= mask[1 + i];
  }
  return pnLength;
}


// ============================================================
//  Packet number encoding
// ============================================================

// RFC 9000 Appendix A.3: the packet number closest to the next expected one
// whose low pnLen bytes are `truncated` — but never below 0 nor at 2^62 or
// above. The closest alone (one formula, as it was) went negative for a
// number more than half a window above the expected one: with nothing
// received yet (largestReceived -1) a first packet numbered 129..255 in one
// byte, or the first after 128 lost in a row, came out as -127..-1 — the
// wrong nonce, the packet dropped, and those after it until the numbers
// took two bytes.
// (Math.pow, not <<: 1 << 32 === 1 in JavaScript.)
var PN_MAX = Math.pow(2, 62);
function expandPacketNumber(truncated, pnLen, largestReceived) {
  var pnWin = Math.pow(2, pnLen * 8);
  var pnHalf = pnWin / 2;
  var expected = largestReceived + 1;
  // expected with its low pnLen bytes replaced by truncated
  var candidate = Math.floor(expected / pnWin) * pnWin + truncated;
  if (candidate <= expected - pnHalf && candidate < PN_MAX - pnWin) return candidate + pnWin;
  if (candidate > expected + pnHalf && candidate >= pnWin) return candidate - pnWin;
  return candidate;
}

// The packet number's length on the wire: the fewest bytes that hold it.
function packet_number_length(packetNumber) {
  if (packetNumber <= 0xff) return 1;
  if (packetNumber <= 0xffff) return 2;
  if (packetNumber <= 0xffffff) return 3;
  return 4;
}


// ============================================================
//  Packet-level encrypt / decrypt
// ============================================================

/**
 * Encrypt a QUIC packet (frames → encrypted packet with HP).
 */
// greaseBit: send the fixed ("QUIC") bit as 0 (RFC 9287) — only to a peer
// that advertised grease_quic_bit.
//
// The packet is built in place, in one allocation: the header written
// straight into it, then the packet number - the AAD as they stand - then
// the ciphertext and the tag after them. The header was assembled from a
// new array per field (each varint, the packet number, the first byte),
// joined, and copied into the packet: a 1200-byte packet's seal left 3.3 KB
// of garbage, 1.5 KB without them.
function encrypt_quic_packet(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token, keyPhase, aead, version, greaseBit) {
  var pnLength = packet_number_length(packetNumber);

  // At least 4 bytes of frames, zeros added (PADDING) when there are fewer:
  // the header protection sample is the 16 bytes from 4 past the packet
  // number's start, whatever its length (RFC 9001 §5.4.2).
  if (encodedFrames.length < 4) {
    var padded = new Uint8Array(4);
    padded.set(encodedFrames, 0);
    encodedFrames = padded;
  }
  var payloadLen = encodedFrames.length + pnLength + 16; // 16 = AEAD tag

  var isLong = packetType !== '1rtt';
  var pnOffset;
  if (isLong) {
    // Long header: the type bits are the version's (RFC 9369 §3.2).
    if (version === undefined) version = QUIC_V1;
    if (packetType !== 'initial' && packetType !== 'handshake' && packetType !== '0rtt') {
      throw new Error('Unsupported packet type: ' + packetType);
    }
    if (packetType === 'initial' && !token) token = EMPTY;
    pnOffset = 1 + 4 + varIntSize(dcid.length) + dcid.length + varIntSize(scid.length) + scid.length +
      (packetType === 'initial' ? varIntSize(token.length) + token.length : 0) + varIntSize(payloadLen);
  } else {
    pnOffset = 1 + dcid.length;
  }

  var aadLen = pnOffset + pnLength;
  var fullPacket = new Uint8Array(aadLen + encodedFrames.length + 16);
  var o = 0;
  if (isLong) {
    fullPacket[o++] = (greaseBit ? 0x80 : 0xc0) | (longTypeBits(version, packetType) << 4) | ((pnLength - 1) & 0x03);
    fullPacket[o++] = (version >>> 24) & 0xff;
    fullPacket[o++] = (version >>> 16) & 0xff;
    fullPacket[o++] = (version >>> 8) & 0xff;
    fullPacket[o++] = version & 0xff;
    o = writeVarIntInto(fullPacket, o, dcid.length);
    fullPacket.set(dcid, o); o += dcid.length;
    o = writeVarIntInto(fullPacket, o, scid.length);
    fullPacket.set(scid, o); o += scid.length;
    if (packetType === 'initial') {
      o = writeVarIntInto(fullPacket, o, token.length);
      fullPacket.set(token, o); o += token.length;
    }
    o = writeVarIntInto(fullPacket, o, payloadLen);
  } else {
    var firstByte = (greaseBit ? 0 : 0x40) | ((pnLength - 1) & 0x03);
    if (keyPhase) firstByte |= 0x04; // key_phase bit
    fullPacket[o++] = firstByte;
    fullPacket.set(dcid, o); o += dcid.length;
  }
  // The packet number's low pnLength bytes, big-endian.
  for (var i = pnLength - 1; i >= 0; i--) fullPacket[o++] = (packetNumber >>> (8 * i)) & 0xff;

  if (!aead_seal_into(writeKey, writeIv, packetNumber, encodedFrames, fullPacket, aadLen, aead)) return null;

  return apply_header_protection(fullPacket, pnOffset, writeHp, pnLength, aead);
}

// AEAD-seal `plaintext` with out[0..aadLen) as the AAD, writing the
// ciphertext and then the tag into `out` from aadLen. false on failure.
function aead_seal_into(key, iv, packetNumber, plaintext, out, aadLen, aead) {
  try {
    aead_of(key, aead_algo(key, aead)).encrypt_into_sync(out, aadLen, packet_nonce(iv, packetNumber),
                                                          plaintext, out.subarray(0, aadLen));
    return true;
  } catch (e) {
    return false;
  }
}


/**
 * Decrypt a QUIC packet (raw bytes → plaintext frames).
 *
 * `ownCid` is the connection ID by which the receiver is addressed. It is used
 * ONLY for short (1-RTT) headers, which carry no DCID-length field — the
 * receiver must already know its own CID length to locate the packet number.
 * Long headers encode the DCID length on the wire, so `ownCid` is ignored there.
 */
function decrypt_quic_packet(array, readKey, readIv, readHp, ownCid, largestPn, aead) {
  if (!(array instanceof Uint8Array)) throw new Error('Invalid input');

  // This function must not mutate its input.
  //
  // Removing header protection in place (remove_header_protection) is fine
  // for exactly one decryption attempt, but the key update path retries this
  // function on the same packet with derived keys (RFC 9001 §6): the second
  // call re-applies the (unchanged) HP mask to a header that is already
  // unprotected, re-scrambling it — and reads pnLength from the scrambled
  // byte, so it may even XOR the wrong number of bytes. The retry then fails
  // even with the correct keys, every phase-flipped packet is dropped, and
  // the connection goes permanently deaf in that direction. Measured against
  // quic-go (which key-updates shortly after handshake confirmation): ACK
  // processing died at t≈2s, BBR froze mid-startup, and the sender spent 58s
  // retransmitting one 8 KB band 29 times.
  //
  // So the unprotected first byte and packet number are read with the mask
  // applied on the way, and only the header — the AAD, which must carry them
  // unprotected — is copied, into an array of its own; the ciphertext is
  // opened where it lies. The whole packet was copied per attempt, and with
  // the views on the copy, a 1200-byte packet's open left 4.7 KB of garbage
  // (JS heap and ArrayBuffers); 2.8 KB without.
  var firstByte = array[0];
  var isShort = (firstByte & 0x80) === 0;

  var pnOffset, sealed, keyPhase = false;

  if (!isShort) {
    // Long Header
    var offset = 6;
    var dcidLen = array[5];
    offset += dcidLen;
    var scidLen = array[offset++];
    offset += scidLen;

    // Initial — read token. Which type bits mean Initial is the version's.
    var hdrVersion = ((array[1] << 24) | (array[2] << 16) | (array[3] << 8) | array[4]) >>> 0;
    if (longPacketType(hdrVersion, (firstByte & 0x30) >> 4) === 'initial') {
      var tokenLen = readVarInt(array, offset);
      offset += tokenLen.byteLength + tokenLen.value;
    }

    var len = readVarInt(array, offset);
    offset += len.byteLength;
    pnOffset = offset;
  } else {
    // Short Header
    pnOffset = 1 + ownCid.length;
  }

  // Too short to carry a sample: not a packet. (Written so that a NaN
  // offset, from a header cut short, fails it too.)
  if (!(pnOffset + 4 + 16 <= array.length)) return null;
  var mask = hp_mask(readHp, array, pnOffset + 4, aead);
  firstByte ^= mask[0] & (isShort ? 0x1f : 0x0f);
  var pnLength = (firstByte & 0x03) + 1;

  // The header, unprotected: the AAD.
  var aadLen = pnOffset + pnLength;
  var aad = new Uint8Array(aadLen);
  for (var i = 0; i < pnOffset; i++) aad[i] = array[i];
  aad[0] = firstByte;
  var truncated = 0;
  for (var j = 0; j < pnLength; j++) {
    aad[pnOffset + j] = array[pnOffset + j] ^ mask[1 + j];
    // *256 (not <<8): a 4-byte packet number whose leading byte has the high
    // bit set would overflow JS's 32-bit signed bitwise math and go negative.
    truncated = truncated * 256 + aad[pnOffset + j];
  }
  var packetNumber = expandPacketNumber(truncated, pnLength, largestPn);

  if (!isShort) {
    var payloadEnd = aadLen + (len.value - pnLength);
    if (payloadEnd > array.length) return null;
    if (payloadEnd - aadLen < 16) return null;
    sealed = array.subarray(aadLen, payloadEnd);
  } else {
    keyPhase = Boolean((firstByte & 0x04) >>> 2);
    if (array.length - aadLen < 16) return null;
    sealed = array.subarray(aadLen);
  }

  var plaintext = aead_open(readKey, packet_nonce(readIv, packetNumber), sealed, aad, aead);

  return {
    packet_number: packetNumber,
    key_phase: keyPhase,
    // The first byte with header protection removed: its reserved bits are
    // the caller's to check — only once the AEAD has passed the packet
    // (RFC 9000 §17.2, §17.3.1), since before that anyone could set them.
    first_byte: firstByte,
    // null: the AEAD refused the packet. An empty Uint8Array: it passed, and
    // there was nothing in it — a different thing (RFC 9000 §12.4).
    plaintext: plaintext
  };
}


// (CRYPTO frames are reassembled into TLS messages in quic_connection.js,
//  processCryptoFrame.)


// ============================================================
//  Exports
// ============================================================

export {
  // Re-exports from LemonTLS
  TLS_CIPHER_SUITES,
  hkdf_expand_label,
  getHashFn,
  getHashLen,

  // QUIC key derivation
  quic_derive_init_secrets,
  quic_derive_from_tls_secrets,
  quic_derive_key_update,

  // Packet encrypt/decrypt
  encrypt_quic_packet,
  decrypt_quic_packet,

  // Retry
  build_retry_packet,
  open_retry_packet,

  // TLS message reassembly

  // Low-level (for testing)
  compute_nonce,
  aead_encrypt,
  aead_decrypt,
  apply_header_protection,
  remove_header_protection
};
