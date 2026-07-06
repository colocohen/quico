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

import { TLSSession, createSecureContext as _lemonCreateSecureContext } from 'lemon-tls';
import nodeTls from 'node:tls';
import { DEBUG, Emitter } from './utils.js';
import { build_transport_params, parse_transport_params } from './transport.js';
import {
  TLS_CIPHER_SUITES
} from './crypto.js';


function defaultTransportParams() {
  return {
    max_udp_payload_size: 65527,
    max_idle_timeout: 30000,
    initial_max_data: 1048576,
    initial_max_stream_data_bidi_local: 262144,
    initial_max_stream_data_bidi_remote: 262144,
    initial_max_stream_data_uni: 131072,
    initial_max_streams_bidi: 100,
    initial_max_streams_uni: 3,
    ack_delay_exponent: 3,
    max_ack_delay: 25,
    disable_active_migration: true,
    active_connection_id_limit: 4,
    max_datagram_frame_size: 65527
  };
}


function TLSBridge(options) {
  options = options || {};

  var ev = Emitter();
  var session = null;
  var handshakeSecretsEmitted = false;
  var appSecretsEmitted = false;
  var helloHandled = false;
  var isServer = !!options.isServer;
  var originalDcid = options.originalDcid || new Uint8Array(0);
  var localCid = options.localCid || new Uint8Array(0); // client's own SCID
  var hostname = options.hostname || null;
  // ALPN protocol(s) to advertise. Default ['h3']; normalize string → array.
  var supportedAlpns = (function () {
    var a = options.alpn || ['h3'];
    return Array.isArray(a) ? a : [a];
  })();

  function feedMessage(data) {
    if (!session) {
      var sessionOpts = { isServer: isServer, SNICallback: options.SNICallback };
      if (!isServer) {
        sessionOpts.sessionId = new Uint8Array(0); // QUIC: no compatibility mode
        if (hostname) sessionOpts.servername = hostname;
      }
      session = new TLSSession(sessionOpts);
      setupSessionEvents();

      // Client: set ALPN + transport params NOW, before setTimeout builds ClientHello
      if (!isServer) {
        var tp = defaultTransportParams();
        tp.initial_source_connection_id = localCid;
        var quicParams = build_transport_params(tp);

        session.set_context({
          local_supported_versions: [0x0304],
          local_supported_alpns: supportedAlpns,
          local_supported_groups: [29, 23, 24],
          local_supported_cipher_suites: [0x1301, 0x1302],
          local_extensions: [{ type: 0x39, data: quicParams }],
          // Signature schemes offered to the peer (client: in the ClientHello;
          // server: in CertificateRequest). Full modern list, ordered PSS/ECDSA/
          // EdDSA first, legacy pkcs1 last (TLS 1.2 compat only — TLS 1.3 never
          // signs pkcs1). Two bugs lived in the old pkcs1-only list:
          //   1. Cloudflare zones with ECDSA-only certs reject the ClientHello
          //      outright (alert 40 handshake_failure — seen live against
          //      speed.cloudflare.com; claude.ai worked only because that zone
          //      also carries an RSA cert).
          //   2. lemon-tls hardcodes THIS full list in the HRR CH2, and RFC 8446
          //      §4.1.2 requires CH2 to match CH1 exactly — offering a different
          //      list in CH1 made every HRR flow non-compliant.
          local_supported_signature_algorithms: [
            0x0804, 0x0805, 0x0806,          // rsa_pss_rsae_sha256/384/512
            0x0403, 0x0503, 0x0603,          // ecdsa_secp256r1/384r1/521r1
            0x0807, 0x0808,                  // ed25519, ed448
            0x0401, 0x0501, 0x0601           // rsa_pkcs1 (TLS 1.2 legacy)
          ],
        });
        helloHandled = true; // ClientHello will be generated from this set_context
      }
    }
    session.message(data);
  }

  function setupSessionEvents() {

    // Peer's QUIC transport parameters ride in the TLS quic_transport_parameters
    // extension (type 0x39): client's in the ClientHello, server's in the
    // EncryptedExtensions. lemon-tls surfaces every received handshake message via
    // 'handshakeMessage' with the parsed extensions, so we extract the 0x39 data,
    // parse it, and hand the params to the QUIC layer (which seeds remote_max_data,
    // max_ack_delay, ack_delay_exponent, etc. — previously hardcoded defaults).
    var peerParamsEmitted = false;
    session.on('handshakeMessage', function (type, data, message) {
      if (peerParamsEmitted || !message || !Array.isArray(message.extensions)) return;
      for (var i = 0; i < message.extensions.length; i++) {
        var e = message.extensions[i];
        if (e && (e.type === 0x39 || e.type === 57) && e.data) {
          try {
            var parsed = parse_transport_params(e.data, 0);
            peerParamsEmitted = true;
            if (DEBUG) console.log('[tls] peer transport params parsed (' + e.data.length + 'B)');
            ev.emit('peerTransportParams', parsed);
          } catch (err) {
            if (DEBUG) console.log('[tls] peer transport params parse failed: ' + err.message);
          }
          break;
        }
      }
    });

    session.on('hello', function () {
      if (helloHandled) return; // prevent double-fire
      helloHandled = true;
      if (DEBUG) console.log('[tls] hello — configuring TLS');

      // Transport params — shared defaults + role-specific fields
      var tp = defaultTransportParams();

      if (isServer) {
        // Server must echo original DCID and provide SCID
        tp.original_destination_connection_id = originalDcid;
        tp.initial_source_connection_id = originalDcid;
        tp.stateless_reset_token = new Uint8Array(16).fill(0xab); // TODO: random per connection
      } else {
        // Client: initial_source_connection_id = our SCID (not DCID!)
        tp.initial_source_connection_id = localCid;
      }

      var quicParams = build_transport_params(tp);

      var tlsContext = {
        local_supported_versions: [0x0304],
        local_supported_alpns: supportedAlpns,
        local_supported_groups: [29, 23, 24],
        local_supported_cipher_suites: [0x1301, 0x1302, 0xc02f, 0xc030, 0xcca8],
        local_extensions: [
          { type: 0x39, data: quicParams }
        ],
        // Signature schemes offered to the peer (client: in the ClientHello;
        // server: in CertificateRequest). Full modern list, ordered PSS/ECDSA/
        // EdDSA first, legacy pkcs1 last (TLS 1.2 compat only — TLS 1.3 never
        // signs pkcs1). Two bugs lived in the old pkcs1-only list:
        //   1. Cloudflare zones with ECDSA-only certs reject the ClientHello
        //      outright (alert 40 handshake_failure — seen live against
        //      speed.cloudflare.com; claude.ai worked only because that zone
        //      also carries an RSA cert).
        //   2. lemon-tls hardcodes THIS full list in the HRR CH2, and RFC 8446
        //      §4.1.2 requires CH2 to match CH1 exactly — offering a different
        //      list in CH1 made every HRR flow non-compliant.
        local_supported_signature_algorithms: [
          0x0804, 0x0805, 0x0806,          // rsa_pss_rsae_sha256/384/512
          0x0403, 0x0503, 0x0603,          // ecdsa_secp256r1/384r1/521r1
          0x0807, 0x0808,                  // ed25519, ed448
          0x0401, 0x0501, 0x0601           // rsa_pkcs1 (TLS 1.2 legacy)
        ],
      };

      session.set_context(tlsContext);
    });

    session.on('message', function (epoch, seq, type, data) {
      var quicEpoch;
      if (epoch === 0) quicEpoch = 'initial';
      else if (epoch === 1) quicEpoch = 'handshake';
      else quicEpoch = 'app';

      if (DEBUG) console.log('[tls] outgoing: epoch=' + quicEpoch + ' type=' + type + ' len=' + data.length);
      ev.emit('send', quicEpoch, data);
    });

    // Native events from LemonTLS — no polling needed
    session.on('handshakeSecrets', function (localSecret, remoteSecret) {
      if (handshakeSecretsEmitted) return;
      handshakeSecretsEmitted = true;
      var cipher = session.getCipher();
      var hashName = TLS_CIPHER_SUITES[cipher] ? TLS_CIPHER_SUITES[cipher].hash : 'sha256';
      if (DEBUG) console.log('[tls] handshake secrets ready');
      ev.emit('handshakeSecrets', { local: localSecret, remote: remoteSecret, cipher: cipher, hash: hashName });
    });

    session.on('appSecrets', function (localSecret, remoteSecret) {
      if (appSecretsEmitted) return;
      appSecretsEmitted = true;
      var cipher = session.getCipher();
      var hashName = TLS_CIPHER_SUITES[cipher] ? TLS_CIPHER_SUITES[cipher].hash : 'sha256';
      if (DEBUG) console.log('[tls] app secrets ready');
      ev.emit('appSecrets', { local: localSecret, remote: remoteSecret, cipher: cipher, hash: hashName });
    });

    session.on('secureConnect', function () {
      if (DEBUG) console.log('[tls] secureConnect');
      ev.emit('secureConnect');
    });

    session.on('keyUpdate', function (info) {
      ev.emit('keyUpdate', info.direction, info.secret);
    });
  }

  return {
    on: function (name, fn) { ev.on(name, fn); },
    off: function (name, fn) { ev.off(name, fn); },
    feedMessage: feedMessage,
    requestKeyUpdate: function () { if (session) session.requestKeyUpdate(true); },
    getHandshakeSecrets: function () {
      if (!session) return null;
      var hs = session.getHandshakeSecrets();
      if (!hs || !hs.localSecret) return null;
      var cipher = session.getCipher();
      var hashName = TLS_CIPHER_SUITES[cipher] ? TLS_CIPHER_SUITES[cipher].hash : 'sha256';
      return { local: hs.localSecret, remote: hs.remoteSecret, cipher: cipher, hash: hashName };
    },
    getTrafficSecrets: function () {
      if (!session) return null;
      var secrets = session.getTrafficSecrets();
      if (!secrets || !secrets.localAppSecret) return null;
      var cipher = session.getCipher();
      var hashName = TLS_CIPHER_SUITES[cipher] ? TLS_CIPHER_SUITES[cipher].hash : 'sha256';
      return { local: secrets.localAppSecret, remote: secrets.remoteAppSecret, cipher: cipher, hash: hashName };
    },
    getCipher: function () { return session ? session.getCipher() : null; },
    close: function () { if (session && session.close) session.close(); }
  };
}

/**
 * Drop-in replacement for tls.createSecureContext.
 * Builds both a lemon-tls context (for H3/QUIC) and a node:tls
 * context (for HTTP/2 + HTTP/1.1 over TCP) from the same credentials.
 */
function createSecureContext(options) {
  var ctx = _lemonCreateSecureContext(options);
  if (ctx && options) {
    ctx._rawKey = options.key || null;
    ctx._rawCert = options.cert || null;
    ctx._rawCa = options.ca || null;
    try {
      var nodeOpts = {};
      if (options.key) nodeOpts.key = options.key;
      if (options.cert) nodeOpts.cert = options.cert;
      if (options.ca) nodeOpts.ca = options.ca;
      ctx._nodeContext = nodeTls.createSecureContext(nodeOpts);
    } catch (e) {
      ctx._nodeContext = null;
    }
  }
  return ctx;
}

export { TLSBridge, createSecureContext };