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

import crypto from 'node:crypto';

// Import crypto primitives from LemonTLS (already node:crypto based)
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
  writeVarInt
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

function aead_encrypt(key, iv, packetNumber, plaintext, aad, aead) {
  try {
    var nonce = compute_nonce(iv, packetNumber);
    var algo = aead_algo(key, aead);
    // Node takes the tag length for ChaCha20-Poly1305 explicitly; 16, as GCM.
    var cipher = algo === 'chacha20-poly1305'
      ? crypto.createCipheriv(algo, key, nonce, { authTagLength: 16 })
      : crypto.createCipheriv(algo, key, nonce);
    cipher.setAAD(aad);

    var encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    var tag = cipher.getAuthTag();

    var result = new Uint8Array(encrypted.length + tag.length);
    result.set(encrypted, 0);
    result.set(tag, encrypted.length);
    return result;
  } catch (e) {
    return null;
  }
}

function aead_decrypt(key, nonce, ciphertext, tag, aad, aead) {
  try {
    var algo = aead_algo(key, aead);
    var decipher = algo === 'chacha20-poly1305'
      ? crypto.createDecipheriv(algo, key, nonce, { authTagLength: 16 })
      : crypto.createDecipheriv(algo, key, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(aad);

    // Stream modes: update() is the whole plaintext, final() checks the tag
    // and gives nothing — unless a build ever does, then they are joined.
    var pt = decipher.update(ciphertext);
    var rest = decipher.final();
    if (rest.length) pt = Buffer.concat([pt, rest]);
    // A Uint8Array over the plaintext's own memory — a copy only if it is a
    // slice of a larger (pooled) buffer, which the stream data handed on
    // from it must not keep alive.
    if (pt.byteOffset === 0 && pt.buffer.byteLength === pt.length) return new Uint8Array(pt.buffer, 0, pt.length);
    return new Uint8Array(pt);
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
  var cipher = crypto.createCipheriv('aes-128-gcm', profile.retryKey, profile.retryNonce);
  cipher.setAAD(aad);
  cipher.final();
  return new Uint8Array(cipher.getAuthTag());
}

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
  head[o++] = 0xc0 | (longTypeBits(version, 'retry') << 4) | (crypto.randomBytes(1)[0] & 0x0f);
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
  if (!crypto.timingSafeEqual(expected, raw.subarray(raw.length - 16))) return null;
  return { scid: scid, token: raw.slice(o, raw.length - 16) };
}


// ============================================================
//  Header protection (RFC 9001 §5.4)
// ============================================================

function aes_ecb_encrypt(key, plaintext) {
  var algo = key.length === 32 ? 'aes-256-ecb' : 'aes-128-ecb';
  var cipher = crypto.createCipheriv(algo, key, null);
  cipher.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
}

// The AES header-protection cipher of a key, made once and kept with it.
// ECB carries nothing from one block to the next and, with padding off and a
// whole block in, update() gives the whole block out — so one cipher serves
// every packet of the key's life. One was created per packet, on each side:
// about 3% of all CPU in a bulk transfer, for a 16-byte encryption. Keyed by
// the key array itself (a key set's `hp`, which lives as long as the keys),
// and forgotten with it.
var hpCiphers = new WeakMap();
function aes_hp_mask(key, sample) {
  var c = hpCiphers.get(key);
  if (!c) {
    c = crypto.createCipheriv(key.length === 32 ? 'aes-256-ecb' : 'aes-128-ecb', key, null);
    c.setAutoPadding(false);
    hpCiphers.set(key, c);
  }
  return c.update(sample);
}

var ZERO5 = new Uint8Array(5);
// The 5-byte mask from a 16-byte sample. AES (§5.4.3): the sample encrypted
// under the HP key. ChaCha20 (§5.4.4): the sample's first 4 bytes are the
// block counter (little-endian), the other 12 the nonce, and the mask is
// ChaCha20 of five zero bytes — which is what node:crypto's 'chacha20' does
// with the sample as its 16-byte IV (counter ‖ nonce, the counter LE).
function hp_mask(hpKey, sample, aead) {
  if (aead === 'chacha20-poly1305') {
    var c = crypto.createCipheriv('chacha20', hpKey, sample);   // the sample is the IV: one per packet
    return new Uint8Array(c.update(ZERO5));
  }
  return aes_hp_mask(hpKey, sample);
}

function apply_header_protection(packet, pnOffset, hpKey, pnLength, aead) {
  // A view, not a copy: the mask is computed from it before anything is
  // changed, and nothing it covers is changed.
  var sample = packet.subarray(pnOffset + 4, pnOffset + 4 + 16);
  if (sample.length < 16) throw new Error('Not enough bytes for HP sample');

  var mask = hp_mask(hpKey, sample, aead);
  var isLong = (packet[0] & 0x80) !== 0;

  packet[0] ^= mask[0] & (isLong ? 0x0f : 0x1f);

  for (var i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }
  return packet;
}

function remove_header_protection(array, pnOffset, hpKey, isShort, aead) {
  var sample = array.subarray(pnOffset + 4, pnOffset + 4 + 16);
  if (sample.length < 16) return null;   // too short to carry a sample: not a packet
  var mask = hp_mask(hpKey, sample, aead);

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

function expandPacketNumber(truncated, pnLen, largestReceived) {
  // Use Math.pow instead of << to avoid JavaScript 32-bit overflow (1 << 32 === 1)
  var pnWin = Math.pow(2, pnLen * 8);
  var pnHalf = pnWin / 2;
  var expected = largestReceived + 1;
  return truncated + pnWin * Math.floor((expected - truncated + pnHalf) / pnWin);
}

function decode_packet_number(array, offset, pnLength) {
  var value = 0;
  // Use *256 (not <<8): a 4-byte packet number whose leading byte has the high
  // bit set would overflow JS's 32-bit signed bitwise math and go negative.
  for (var i = 0; i < pnLength; i++) {
    value = value * 256 + array[offset + i];
  }
  return value;
}

function encode_packet_number(packetNumber) {
  var pnLength;
  if (packetNumber <= 0xff) pnLength = 1;
  else if (packetNumber <= 0xffff) pnLength = 2;
  else if (packetNumber <= 0xffffff) pnLength = 3;
  else pnLength = 4;

  var buf = new Uint8Array(4);
  buf[0] = (packetNumber >>> 24) & 0xff;
  buf[1] = (packetNumber >>> 16) & 0xff;
  buf[2] = (packetNumber >>> 8) & 0xff;
  buf[3] = packetNumber & 0xff;

  return { bytes: buf.slice(4 - pnLength), length: pnLength };
}


// ============================================================
//  Packet-level encrypt / decrypt
// ============================================================

/**
 * Build QUIC header for a packet (before encryption).
 */
// greaseBit: send the fixed ("QUIC") bit as 0 (RFC 9287) — only to a peer
// that advertised grease_quic_bit.
function build_quic_header(packetType, dcid, scid, token, lengthField, pnLen, keyPhase, version, greaseBit) {
  var hdr = [];
  var firstByte;

  if (packetType === '1rtt') {
    firstByte = (greaseBit ? 0 : 0x40) | ((pnLen - 1) & 0x03);
    if (keyPhase) firstByte |= 0x04; // key_phase bit
    hdr.push(Uint8Array.of(firstByte));
    hdr.push(dcid);
    var header = concatUint8Arrays(hdr);
    return { header: header, pnOffset: header.length };
  }

  // Long header: the type bits are the version's (RFC 9369 §3.2).
  if (version === undefined) version = QUIC_V1;
  if (packetType !== 'initial' && packetType !== 'handshake' && packetType !== '0rtt') {
    throw new Error('Unsupported packet type: ' + packetType);
  }
  firstByte = (greaseBit ? 0x80 : 0xc0) | (longTypeBits(version, packetType) << 4) | ((pnLen - 1) & 0x03);

  hdr.push(Uint8Array.of(firstByte));
  hdr.push(new Uint8Array([(version >>> 24) & 0xff, (version >>> 16) & 0xff, (version >>> 8) & 0xff, version & 0xff]));
  hdr.push(writeVarInt(dcid.length), dcid);
  hdr.push(writeVarInt(scid.length), scid);

  if (packetType === 'initial') {
    if (!token) token = new Uint8Array(0);
    hdr.push(writeVarInt(token.length), token);
  }

  hdr.push(lengthField);

  var header = concatUint8Arrays(hdr);
  return { header: header, pnOffset: header.length };
}


/**
 * Encrypt a QUIC packet (frames → encrypted packet with HP).
 */
function encrypt_quic_packet(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token, keyPhase, aead, version, greaseBit) {
  var pn = encode_packet_number(packetNumber);
  var pnLength = pn.length;
  var pnBytes = pn.bytes;

  var payloadLen = encodedFrames.length + pnLength + 16; // 16 = GCM tag
  var lengthField = writeVarInt(payloadLen);
  var hdrInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength, keyPhase, version, greaseBit);

  var header = hdrInfo.header;
  var pnOffset = hdrInfo.pnOffset;

  // Ensure minimum packet size for HP sample (pnOffset + pnLength + 20 for sample)
  var minTotal = pnOffset + pnLength + 20;
  var fullLen = header.length + pnLength + encodedFrames.length + 16;

  if (fullLen < minTotal) {
    var extra = minTotal - fullLen;
    var padded = new Uint8Array(encodedFrames.length + extra);
    padded.set(encodedFrames, 0);
    encodedFrames = padded;
    // Rebuild header with new length
    payloadLen = encodedFrames.length + pnLength + 16;
    lengthField = writeVarInt(payloadLen);
    hdrInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength, keyPhase, version, greaseBit);
    header = hdrInfo.header;
    pnOffset = hdrInfo.pnOffset;
  }

  // The packet built in place, in one allocation: header and packet number,
  // which are the AAD as they stand, then the ciphertext and the tag written
  // after them. It took five copies — the AAD, the ciphertext concatenated,
  // ciphertext and tag into one array, all of it into the packet — about 5%
  // of a bulk transfer's CPU with the garbage they left.
  var aadLen = header.length + pnLength;
  var fullPacket = new Uint8Array(aadLen + encodedFrames.length + 16);
  fullPacket.set(header, 0);
  fullPacket.set(pnBytes, header.length);
  if (!aead_seal_into(writeKey, writeIv, packetNumber, encodedFrames, fullPacket, aadLen, aead)) return null;

  return apply_header_protection(fullPacket, pnOffset, writeHp, pnLength, aead);
}

// AEAD-seal `plaintext` with out[0..aadLen) as the AAD, writing the
// ciphertext and then the tag into `out` from aadLen. false on failure.
// GCM and ChaCha20-Poly1305 are stream modes: update() gives back as many
// bytes as it is given, and final() none.
function aead_seal_into(key, iv, packetNumber, plaintext, out, aadLen, aead) {
  try {
    var algo = aead_algo(key, aead);
    var nonce = compute_nonce(iv, packetNumber);
    var cipher = algo === 'chacha20-poly1305'
      ? crypto.createCipheriv(algo, key, nonce, { authTagLength: 16 })
      : crypto.createCipheriv(algo, key, nonce);
    cipher.setAAD(out.subarray(0, aadLen));
    var ct = cipher.update(plaintext);
    var rest = cipher.final();
    out.set(ct, aadLen);
    if (rest.length) out.set(rest, aadLen + ct.length);
    out.set(cipher.getAuthTag(), aadLen + ct.length + rest.length);
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

  // Work on a private copy — this function must not mutate its input.
  //
  // remove_header_protection XORs the first byte and the packet-number bytes
  // IN PLACE. That is fine for exactly one decryption attempt, but the key
  // update path retries this function on the same packet with derived keys
  // (RFC 9001 §6): the second call re-applies the (unchanged) HP mask to a
  // header that is already unprotected, re-scrambling it — and reads pnLength
  // from the scrambled byte, so it may even XOR the wrong number of bytes.
  // The retry then fails even with the correct keys, every phase-flipped
  // packet is dropped, and the connection goes permanently deaf in that
  // direction. Measured against quic-go (which key-updates shortly after
  // handshake confirmation): ACK processing died at t≈2s, BBR froze mid-
  // startup, and the sender spent 58s retransmitting one 8 KB band 29 times.
  //
  // One ≤1500 B copy per decryption attempt is noise next to the AEAD itself.
  array = array.slice();

  var firstByte = array[0];
  var isShort = (firstByte & 0x80) === 0;

  var pnOffset, pnLength, aad, ciphertext, tag, packetNumber, nonce, keyPhase = false;

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
    pnLength = remove_header_protection(array, pnOffset, readHp, false, aead);
    if (pnLength === null) return null;

    packetNumber = expandPacketNumber(
      decode_packet_number(array, pnOffset, pnLength),
      pnLength, largestPn
    );
    nonce = compute_nonce(readIv, packetNumber);

    var payloadStart = pnOffset + pnLength;
    var payloadLength = len.value - pnLength;
    var payloadEnd = payloadStart + payloadLength;

    if (payloadEnd > array.length) return null;

    // Views on the private copy above — nothing changes it from here on.
    var payload = array.subarray(payloadStart, payloadEnd);
    if (payload.length < 16) return null;

    ciphertext = payload.subarray(0, payload.length - 16);
    tag = payload.subarray(payload.length - 16);
    aad = array.subarray(0, pnOffset + pnLength);

  } else {
    // Short Header
    var dcidLen = ownCid.length;
    pnOffset = 1 + dcidLen;

    pnLength = remove_header_protection(array, pnOffset, readHp, true, aead);
    if (pnLength === null) return null;

    keyPhase = Boolean((array[0] & 0x04) >>> 2);

    packetNumber = expandPacketNumber(
      decode_packet_number(array, pnOffset, pnLength),
      pnLength, largestPn
    );
    nonce = compute_nonce(readIv, packetNumber);

    var payload = array.subarray(pnOffset + pnLength);
    if (payload.length < 16) return null;

    ciphertext = payload.subarray(0, payload.length - 16);
    tag = payload.subarray(payload.length - 16);
    aad = array.subarray(0, pnOffset + pnLength);
  }

  var plaintext = aead_decrypt(readKey, nonce, ciphertext, tag, aad, aead);

  return {
    packet_number: packetNumber,
    key_phase: keyPhase,
    // The first byte with header protection removed: its reserved bits are
    // the caller's to check — only once the AEAD has passed the packet
    // (RFC 9000 §17.2, §17.3.1), since before that anyone could set them.
    first_byte: array[0],
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
