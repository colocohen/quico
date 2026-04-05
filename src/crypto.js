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


// ============================================================
//  Initial salts per QUIC version (RFC 9001 §5.2)
// ============================================================

var INITIAL_SALTS = {
  0x00000001: new Uint8Array([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
  ]),
  0xff00001d: new Uint8Array([
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
    0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99
  ]),
  0xff000020: new Uint8Array([
    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0x77,
    0x7b, 0xe3, 0x0e, 0xbd, 0x5f, 0xa5, 0x15, 0x87,
    0x3d, 0x8d, 0x6e, 0x67
  ])
};


// ============================================================
//  Key derivation
// ============================================================

/**
 * Derive Initial encryption keys from the client DCID.
 * direction: 'read' = client keys, 'write' = server keys
 */
function quic_derive_init_secrets(client_dcid, version, direction) {
  var hashName = 'sha256';
  var hashFn = getHashFn(hashName);
  var salt = INITIAL_SALTS[version];
  if (!salt) throw new Error('Unsupported QUIC version: 0x' + version.toString(16));

  var label = direction === 'read' ? 'client in' : 'server in';
  var initial_secret = hkdf_extract(hashName, salt, client_dcid);

  var side_secret = hkdf_expand_label(
    hashName, initial_secret, label, new Uint8Array(0), 32
  );

  return {
    key: hkdf_expand_label(hashName, side_secret, 'quic key', new Uint8Array(0), 16),
    iv:  hkdf_expand_label(hashName, side_secret, 'quic iv',  new Uint8Array(0), 12),
    hp:  hkdf_expand_label(hashName, side_secret, 'quic hp',  new Uint8Array(0), 16)
  };
}


/**
 * Derive QUIC keys from a TLS traffic secret (handshake or app).
 * cipher: TLS cipher suite code (e.g. 0x1301). Used to determine key length.
 */
function quic_derive_from_tls_secrets(traffic_secret, hashName, cipher) {
  if (!traffic_secret) return null;
  var keyLen = 16; // default AES-128
  if (cipher && TLS_CIPHER_SUITES[cipher]) {
    keyLen = TLS_CIPHER_SUITES[cipher].keylen;
  } else if (hashName === 'sha384') {
    keyLen = 32; // AES-256 for SHA-384 based cipher suites
  }
  return {
    key: hkdf_expand_label(hashName, traffic_secret, 'quic key', new Uint8Array(0), keyLen),
    iv:  hkdf_expand_label(hashName, traffic_secret, 'quic iv',  new Uint8Array(0), 12),
    hp:  hkdf_expand_label(hashName, traffic_secret, 'quic hp',  new Uint8Array(0), keyLen)
  };
}


/**
 * Key Update (RFC 9001 §6): derive next secret + keys from current secret.
 * next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", hash_len)
 */
function quic_derive_key_update(current_secret, hashName, cipher) {
  var hashLen = getHashLen(hashName);
  var keyLen = 16;
  if (cipher && TLS_CIPHER_SUITES[cipher]) {
    keyLen = TLS_CIPHER_SUITES[cipher].keylen;
  } else if (hashName === 'sha384') {
    keyLen = 32;
  }
  var next_secret = hkdf_expand_label(hashName, current_secret, 'quic ku', new Uint8Array(0), hashLen);
  return {
    secret: next_secret,
    key: hkdf_expand_label(hashName, next_secret, 'quic key', new Uint8Array(0), keyLen),
    iv:  hkdf_expand_label(hashName, next_secret, 'quic iv',  new Uint8Array(0), 12),
    hp:  hkdf_expand_label(hashName, next_secret, 'quic hp',  new Uint8Array(0), keyLen)
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

function aead_algo(keyLen) {
  if (keyLen === 16) return 'aes-128-gcm';
  if (keyLen === 32) return 'aes-256-gcm';
  throw new Error('Unsupported key length: ' + keyLen);
}

function aead_encrypt(key, iv, packetNumber, plaintext, aad) {
  try {
    var nonce = compute_nonce(iv, packetNumber);
    var cipher = crypto.createCipheriv(aead_algo(key.length), key, nonce);
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

function aead_decrypt(key, nonce, ciphertext, tag, aad) {
  try {
    var decipher = crypto.createDecipheriv(aead_algo(key.length), key, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(aad);

    var decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return new Uint8Array(decrypted);
  } catch (e) {
    return null;
  }
}


// ============================================================
//  Header protection (AES-ECB mask)
// ============================================================

function aes_ecb_encrypt(key, plaintext) {
  var algo = key.length === 32 ? 'aes-256-ecb' : 'aes-128-ecb';
  var cipher = crypto.createCipheriv(algo, key, null);
  cipher.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
}

function apply_header_protection(packet, pnOffset, hpKey, pnLength) {
  var sample = packet.slice(pnOffset + 4, pnOffset + 4 + 16);
  if (sample.length < 16) throw new Error('Not enough bytes for HP sample');

  var mask = aes_ecb_encrypt(hpKey, sample);
  var isLong = (packet[0] & 0x80) !== 0;

  packet[0] ^= mask[0] & (isLong ? 0x0f : 0x1f);

  for (var i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }
  return packet;
}

function remove_header_protection(array, pnOffset, hpKey, isShort) {
  var sample = array.slice(pnOffset + 4, pnOffset + 4 + 16);
  var mask = aes_ecb_encrypt(hpKey, sample);

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
  for (var i = 0; i < pnLength; i++) {
    value = (value << 8) | array[offset + i];
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
function build_quic_header(packetType, dcid, scid, token, lengthField, pnLen, keyPhase) {
  var hdr = [];
  var firstByte;

  if (packetType === '1rtt') {
    firstByte = 0x40 | ((pnLen - 1) & 0x03);
    if (keyPhase) firstByte |= 0x04; // key_phase bit
    hdr.push(Uint8Array.of(firstByte));
    hdr.push(dcid);
    var header = concatUint8Arrays(hdr);
    return { header: header, pnOffset: header.length };
  }

  // Long header
  if (packetType === 'initial') {
    firstByte = 0xc0 | ((pnLen - 1) & 0x03);
  } else if (packetType === 'handshake') {
    firstByte = 0xe0 | ((pnLen - 1) & 0x03);
  } else if (packetType === '0rtt') {
    firstByte = 0xd0 | ((pnLen - 1) & 0x03);
  } else {
    throw new Error('Unsupported packet type: ' + packetType);
  }

  hdr.push(Uint8Array.of(firstByte));
  hdr.push(new Uint8Array([0x00, 0x00, 0x00, 0x01])); // version 1
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
function encrypt_quic_packet(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token, keyPhase) {
  var pn = encode_packet_number(packetNumber);
  var pnLength = pn.length;
  var pnBytes = pn.bytes;

  var payloadLen = encodedFrames.length + pnLength + 16; // 16 = GCM tag
  var lengthField = writeVarInt(payloadLen);
  var hdrInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength, keyPhase);

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
    hdrInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength, keyPhase);
    header = hdrInfo.header;
    pnOffset = hdrInfo.pnOffset;
  }

  // AAD = header + packet number bytes (unprotected)
  var aad = concatUint8Arrays([header, pnBytes]);

  var ciphertext = aead_encrypt(writeKey, writeIv, packetNumber, encodedFrames, aad);
  if (ciphertext === null) return null;

  var fullPacket = concatUint8Arrays([header, pnBytes, ciphertext]);

  return apply_header_protection(fullPacket, pnOffset, writeHp, pnLength);
}


/**
 * Decrypt a QUIC packet (raw bytes → plaintext frames).
 */
function decrypt_quic_packet(array, readKey, readIv, readHp, dcid, largestPn) {
  if (!(array instanceof Uint8Array)) throw new Error('Invalid input');

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

    var typeBits = (firstByte & 0x30) >> 4;
    if (typeBits === 0) { // Initial — read token
      var tokenLen = readVarInt(array, offset);
      offset += tokenLen.byteLength + tokenLen.value;
    }

    var len = readVarInt(array, offset);
    offset += len.byteLength;

    pnOffset = offset;
    pnLength = remove_header_protection(array, pnOffset, readHp, false);
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

    var payload = array.slice(payloadStart, payloadEnd);
    if (payload.length < 16) return null;

    ciphertext = payload.slice(0, payload.length - 16);
    tag = payload.slice(payload.length - 16);
    aad = array.slice(0, pnOffset + pnLength);

  } else {
    // Short Header
    var dcidLen = dcid.length;
    pnOffset = 1 + dcidLen;

    pnLength = remove_header_protection(array, pnOffset, readHp, true);
    if (pnLength === null) return null;

    keyPhase = Boolean((array[0] & 0x04) >>> 2);

    packetNumber = expandPacketNumber(
      decode_packet_number(array, pnOffset, pnLength),
      pnLength, largestPn
    );
    nonce = compute_nonce(readIv, packetNumber);

    var payload = array.slice(pnOffset + pnLength);
    if (payload.length < 16) return null;

    ciphertext = payload.slice(0, payload.length - 16);
    tag = payload.slice(payload.length - 16);
    aad = array.slice(0, pnOffset + pnLength);
  }

  var plaintext = aead_decrypt(readKey, nonce, ciphertext, tag, aad);

  return {
    packet_number: packetNumber,
    key_phase: keyPhase,
    plaintext: plaintext
  };
}


// ============================================================
//  TLS CRYPTO message reassembly from CRYPTO frame chunks
// ============================================================

function extract_tls_messages_from_chunks(chunks, from_offset) {
  var offset = from_offset;
  var buffers = [];

  while (chunks[offset]) {
    buffers.push(chunks[offset]);
    offset += chunks[offset].length;
  }

  if (buffers.length === 0) return false;

  var combined = concatUint8Arrays(buffers);
  var tls_messages = [];
  var i = 0;

  while (i + 4 <= combined.length) {
    var msgType = combined[i];
    var length = (combined[i + 1] << 16) | (combined[i + 2] << 8) | combined[i + 3];
    if (i + 4 + length > combined.length) break;

    tls_messages.push(combined.slice(i, i + 4 + length));
    i += 4 + length;
  }

  if (i > 0) {
    // Delete all consumed chunks
    var cleanupOffset = from_offset;
    while (cleanupOffset < offset) {
      var c = chunks[cleanupOffset];
      if (!c) break;
      var nextOffset = cleanupOffset + c.length;
      delete chunks[cleanupOffset];
      cleanupOffset = nextOffset;
    }
    // Store remaining data at the correct position
    var newFromOffset = from_offset + i;
    if (i < combined.length) {
      chunks[newFromOffset] = combined.slice(i);
    }
    from_offset = newFromOffset;
  }

  return { tls_messages: tls_messages, new_from_offset: from_offset };
}


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

  // TLS message reassembly
  extract_tls_messages_from_chunks,

  // Low-level (for testing)
  compute_nonce,
  aead_encrypt,
  aead_decrypt,
  apply_header_protection,
  remove_header_protection
};
