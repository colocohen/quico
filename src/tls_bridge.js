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

import {
  TLSSession,
  createSecureContext as _lemonCreateSecureContext,
  certificateObject
} from 'lemon-tls';
import { X509Certificate } from 'node:crypto';
import { DEBUG, Emitter } from './utils.js';
import { rootCertificates as lemonRoots, parseEcdhCurve as lemonParseEcdhCurve, DEFAULT_SERVER_GROUPS as lemonServerGroups,
         DEFAULT_SIGNATURE_SCHEMES as lemonSigSchemes } from 'lemon-tls';

// The platform trust store for a QUIC client given no `ca` — lemon-tls's own
// export, the list its TCP path uses (compat.js). Not node:tls: quico imports
// none of Node's network stack (test/integration.mjs checks).
function defaultRoots() {
  return lemonRoots || [];
}
import { build_transport_params, parse_transport_params } from './transport.js';
import {
  TLS_CIPHER_SUITES
} from './crypto.js';


// The transport parameters we send (RFC 9000 §18.2) — these, with the
// application's choices in place of the defaults for the ones it may set
// (options.transportParams, camelCase, RFC 9000's names):
//   initialMaxData                  the connection's receive window (1 MB)
//   initialMaxStreamDataBidiLocal   a bidirectional stream we open (256 KB)
//   initialMaxStreamDataBidiRemote  one the peer opens (256 KB)
//   initialMaxStreamDataUni         a unidirectional stream the peer opens (128 KB)
//   initialMaxStreamsBidi           streams the peer may have open at once (100)
//   initialMaxStreamsUni            (100)
//   maxIdleTimeout                  ms without a packet from the peer before the
//                                   connection is closed (30000); 0: no limit.
//                                   The effective one is the smaller of the two
//                                   sides' (RFC 9000 §10.1)
// The windows slide as the application reads, keeping these sizes; the
// stream limits are raised as streams close, keeping these counts.
var SETTABLE_TRANSPORT_PARAMS = {
  initialMaxData: 'initial_max_data',
  initialMaxStreamDataBidiLocal: 'initial_max_stream_data_bidi_local',
  initialMaxStreamDataBidiRemote: 'initial_max_stream_data_bidi_remote',
  initialMaxStreamDataUni: 'initial_max_stream_data_uni',
  initialMaxStreamsBidi: 'initial_max_streams_bidi',
  initialMaxStreamsUni: 'initial_max_streams_uni',
  maxIdleTimeout: 'max_idle_timeout',
  disableActiveMigration: 'disable_active_migration'
};

// A client's key-exchange groups by default: what node:tls offers (OpenSSL
// 3.5) and the browsers do — the hybrid post-quantum X25519MLKEM768 first,
// then X25519, P-256, P-384 — where node:crypto has ML-KEM (Node 24.7+);
// without it, the classical groups alone. lemon-tls's own client default is
// the same (session/ecdh.js); named here because the QUIC hello's context is
// set by this bridge. The hybrid share goes with an X25519 share beside it,
// so a server without it needs no retry.
var CLIENT_DEFAULT_GROUPS = (function () {
  try { return lemonParseEcdhCurve('X25519MLKEM768:X25519:P-256:P-384'); }
  catch (e) { return [29, 23, 24]; }
})();

function defaultTransportParams(overrides) {
  var tp = baseTransportParams();
  for (var name in (overrides || {})) {
    if (!Object.prototype.hasOwnProperty.call(overrides, name) || overrides[name] == null) continue;
    var key = SETTABLE_TRANSPORT_PARAMS[name];
    if (!key) throw new TypeError('transportParams.' + name + ' is not a transport parameter that can be set');
    var v = overrides[name];
    if (key === 'disable_active_migration') {
      if (typeof v !== 'boolean') throw new TypeError('transportParams.' + name + ' must be a boolean');
      if (v) tp[key] = true; else delete tp[key];
      continue;
    }
    // Varints (§16); stream counts at most 2^60 (§4.6). A window of 0 would
    // let the peer send nothing; a count of 0 for unidirectional streams
    // would leave HTTP/3 no room for its own.
    var max = key.indexOf('streams') >= 0 ? Math.pow(2, 60) : Number.MAX_SAFE_INTEGER;
    var min = key === 'initial_max_streams_uni' ? 3 : ((key === 'initial_max_streams_bidi' || key === 'max_idle_timeout') ? 0 : 1);
    if (typeof v !== 'number' || Math.floor(v) !== v || v < min || v > max) {
      throw new RangeError('transportParams.' + name + ' must be an integer from ' + min + ' to ' + max);
    }
    tp[key] = v;
  }
  return tp;
}

function baseTransportParams() {
  return {
    max_udp_payload_size: 65527,
    max_idle_timeout: 30000,
    initial_max_data: 1048576,
    initial_max_stream_data_bidi_local: 262144,
    initial_max_stream_data_bidi_remote: 262144,
    initial_max_stream_data_uni: 131072,
    initial_max_streams_bidi: 100,
    // HTTP/3 takes three of these for itself (control, QPACK encoder and
    // decoder) and keeps them for the whole connection, and credit comes
    // back only as the peer's streams close: with 3, a peer could open no
    // stream of its own — no WebTransport stream, no MOQT. Browsers grant 100.
    initial_max_streams_uni: 100,
    ack_delay_exponent: 3,
    max_ack_delay: 25,
    // Active migration allowed (RFC 9000 §9): a client may move to another
    // network — Wi-Fi to cellular — and go on in the same connection. Each
    // new address is validated before more than three times what it sent
    // goes to it (§8), with congestion and RTT state started over (§9.4),
    // and addressed by a connection ID of its own (§9.5). It was disabled.
    // transportParams.disableActiveMigration: true says no again.
    active_connection_id_limit: 4,
    max_datagram_frame_size: 65527,
    // RESET_STREAM_AT taken (draft-ietf-quic-reliable-stream-reset): a peer
    // may reset a stream and still have its first bytes delivered — a
    // WebTransport stream's header, a MOQT subgroup's.
    reset_stream_at: true
  };
}


// The server's transport parameters a client keeps for 0-RTT (RFC 9000
// §7.4.1; RFC 9221 §3 for max_datagram_frame_size): its limits on what may
// be sent before this handshake's parameters arrive.
var REMEMBERED_PARAMS = ['active_connection_id_limit', 'initial_max_data', 'initial_max_stream_data_bidi_local',
  'initial_max_stream_data_bidi_remote', 'initial_max_stream_data_uni', 'initial_max_streams_bidi',
  'initial_max_streams_uni', 'max_datagram_frame_size', 'reset_stream_at'];
function rememberedParams(tp) {
  var out = {};
  for (var i = 0; i < REMEMBERED_PARAMS.length; i++) {
    var k = REMEMBERED_PARAMS[i];
    // A flag (reset_stream_at, draft-ietf-quic-reliable-stream-reset §3) as 1 or 0.
    out[k] = tp && typeof tp[k] === 'number' ? tp[k] : (tp && tp[k] === true ? 1 : 0);
  }
  return out;
}

// The fingerprint options with QUIC's transport character — see getJA4.
function quicOpts(opts) {
  return Object.assign({ protocol: 'q' }, opts || {});
}


function TLSBridge(options) {
  options = options || {};

  var ev = Emitter();
  var session = null;
  var handshakeSecretsEmitted = false;
  var appSecretsEmitted = false;
  var helloHandled = false;
  // A client's: what it keeps with each session it saves — the server's
  // transport parameters (tp), and the application's own (app: HTTP/3's
  // SETTINGS) once it has them — for 0-RTT next time.
  var sessionAppData = null;
  function keepAppData(k, v) {
    sessionAppData = Object.assign({}, sessionAppData || {});
    sessionAppData[k] = v;
    if (session && session.setSessionAppData) session.setSessionAppData(sessionAppData);
  }
  var serverHelloSent = false;   // our parameters went out with it (EncryptedExtensions)
  var isServer = !!options.isServer;
  var originalDcid = options.originalDcid || new Uint8Array(0);
  // The connection ID this endpoint chose for itself — the Source Connection
  // ID of its long headers, echoed as initial_source_connection_id (RFC 9000
  // §7.3). The server's is its own too, not the one the client picked.
  var localCid = options.localCid || new Uint8Array(0);
  // Server: the stateless reset token for localCid (RFC 9000 §10.3), from
  // quic_server, which alone holds the key it is derived from.
  var statelessResetToken = options.statelessResetToken || null;
  // Server, after a Retry: the SCID of that Retry, echoed as
  // retry_source_connection_id (RFC 9000 §7.3).
  var retrySourceCid = options.retrySourceCid || null;
  var hostname = options.hostname || null;
  // Peer certificate verification. Defaults to true, matching node:tls — but
  // until now the option was never plumbed through at all, so quico could not
  // talk to a server whose certificate wasn't signed by a publicly trusted CA:
  // no local development against self-signed certs, no internal PKI, and no
  // interop (the QUIC interop runner mints its own CA and addresses hosts as
  // server4 / server6, so every implementation disables verification there).
  var rejectUnauthorized = options.rejectUnauthorized !== false;
  var ca = options.ca || null;
  // Server: its TLS options as tls_options.js reads them, or null.
  var serverTls = isServer ? (options.tlsOptions || null) : null;
  // ALPN protocol(s) to advertise. Default ['h3']; normalize string → array.
  var supportedAlpns = (function () {
    var a = options.alpn || ['h3'];
    return Array.isArray(a) ? a : [a];
  })();

  function feedMessage(data) {
    if (!session) {
      var sessionOpts = {
        isServer: isServer,
        SNICallback: options.SNICallback,
        rejectUnauthorized: rejectUnauthorized
      };
      if (ca) sessionOpts.ca = ca;
      // No `ca`: a client verifies against the platform roots. Without them
      // lemon-tls has no trust anchors and checks only the name in the
      // certificate — a self-signed certificate for the right name passed,
      // so an HTTP/3 request was open to a man-in-the-middle.
      if (!isServer) sessionOpts.defaultCA = defaultRoots;
      // Client: a certificate to send if the server asks for one
      // (CertificateRequest) — tls.connect's key / cert / passphrase.
      if (!isServer && options.key && options.cert) {
        sessionOpts.key = options.key;
        sessionOpts.cert = options.cert;
        if (options.passphrase != null) sessionOpts.passphrase = options.passphrase;
      }
      // Session tickets (server). The keys come from the server, one set for
      // all its connections: without them lemon-tls draws a fresh key per
      // session, so every ticket was sealed with a key that died with its
      // connection and no returning client could ever resume. ticketData is
      // the application's (see lemon-tls): carried in the ticket, returned by
      // getTicketInfo() on the connection that presents it.
      if (isServer && options.ticketKeys) sessionOpts.ticketKeys = options.ticketKeys;
      if (isServer && options.ticketData) sessionOpts.ticketData = options.ticketData;
      // Encrypted Client Hello (RFC 9849): lemon-tls decrypts the real
      // ClientHello — SNI, ALPN, transport parameters — and the handshake
      // runs on it; QUIC needs nothing of its own for it.
      if (isServer && options.ech) sessionOpts.ech = options.ech;
      // OCSP stapling: lemon-tls asks it when a client requests status, and
      // staples the answer in the Certificate (RFC 8446 §4.4.2.1).
      if (isServer && options.ocspRequest) sessionOpts.ocspRequest = options.ocspRequest;
      // What the tickets are for beyond TLS: the QUIC version (RFC 9369 §5),
      // set again once it is negotiated (setTicketContext).
      if (isServer && options.ticketContext) sessionOpts.ticketContext = options.ticketContext;
      // 0-RTT (RFC 9001 §4.6): tickets that allow it, and accepting it —
      // max_early_data_size 0xffffffff, as QUIC requires (§4.6.1); under the
      // transport parameters the client will remember (earlyDataContext:
      // another set and the 0-RTT is refused, RFC 9000 §7.4.1).
      if (isServer && options.earlyData) {
        sessionOpts.earlyData = true;
        sessionOpts.maxEarlyData = 0xffffffff;
        if (options.earlyDataMaxAge != null) sessionOpts.earlyDataMaxAge = options.earlyDataMaxAge;
        if (options.earlyDataReplay) sessionOpts.earlyDataReplay = options.earlyDataReplay;
        sessionOpts.earlyDataContext = options.earlyDataContext || '';
      }
      // The server's TLS options (tls_options.js, read once by quic_server):
      // the ticket lifetime, certificate compression and client certificates
      // here; the suites, groups and signature schemes at 'hello' below.
      if (isServer && serverTls) {
        if (serverTls.sessionTimeout !== undefined) sessionOpts.ticketLifetime = serverTls.sessionTimeout;
        if (serverTls.certificateCompression) sessionOpts.certificateCompression = serverTls.certificateCompression;
        if (serverTls.honorCipherOrder) sessionOpts.honorCipherOrder = true;
        if (serverTls.requestCert) {
          sessionOpts.requestCert = true;
          sessionOpts.rejectUnauthorized = serverTls.rejectUnauthorized;
        }
      }
      if (!isServer) {
        // The server's certificate chain may come compressed (RFC 8879):
        // brotli, zstd, zlib — what Chrome and Firefox offer. A server here
        // compresses for any client that offers it (lemon-tls's default).
        sessionOpts.certificateCompression = true;
        sessionOpts.sessionId = new Uint8Array(0); // QUIC: no compatibility mode
        if (hostname) sessionOpts.servername = hostname;
        // A saved session to resume (lemon-tls offers it only where it may be
        // used: the same server name, within its lifetime, and — when the
        // server must be verified — one that was).
        if (options.session) sessionOpts.session = options.session;
        // A stapled OCSP response for the server's certificate (tls.connect's
        // requestOCSP); it comes as 'OCSPResponse'.
        if (options.requestOCSP) sessionOpts.requestOCSP = true;
        // Encrypted Client Hello (RFC 9849): the server's ECHConfigList — the
        // real ClientHello, its name and transport parameters, goes
        // encrypted — or GREASE ECH without one. lemon-tls builds both hellos.
        if (options.ech) sessionOpts.ech = options.ech;
        if (options.echGrease) sessionOpts.echGrease = true;
        // 0-RTT with a session whose ticket allows it.
        if (options.earlyData) sessionOpts.earlyData = true;
      }
      session = new TLSSession(sessionOpts);
      setupSessionEvents();

      // Client: set ALPN + transport params NOW, before setTimeout builds ClientHello
      if (!isServer) {
        var quicParams = localQuicParams();

        session.set_context({
          local_supported_versions: [0x0304],
          local_supported_alpns: supportedAlpns,
          local_supported_groups: clientGroups(),
          local_supported_cipher_suites: [0x1301, 0x1302, 0x1303],
          local_extensions: [{ type: 0x39, data: quicParams }],
          // Signature schemes offered: lemon-tls's list, ML-DSA included (see
          // the server's below). A pkcs1-only list here once had Cloudflare's
          // ECDSA-only zones refuse the ClientHello (handshake_failure).
          local_supported_signature_algorithms: (options.sigalgs && options.sigalgs.length) ? options.sigalgs.slice() : lemonSigSchemes.slice(),
        });
        helloHandled = true; // ClientHello will be generated from this set_context
      }
    }
    // Only feed real handshake bytes. QUICConnection.connect() calls
    // feedMessage(new Uint8Array(0)) as a "trigger" to start the handshake,
    // but the ClientHello is actually built by lemon-tls from set_context()
    // above, on its own timer — the empty feed was always a no-op in intent.
    //
    // It stopped being harmless once lemon-tls hardened parse failures into
    // fatalAlert(): an empty buffer fails as "truncated u8 at 0", which sets
    // the session state to 'error' permanently, so the ClientHello timer then
    // early-returns and NO handshake is ever sent. Guard here rather than
    // making lemon-tls lenient — rejecting malformed handshake input is the
    // correct behavior for a TLS stack facing a hostile peer.
    if (data && data.length > 0) session.message(data);
  }

  // The groups a client offers: the application's (ecdhCurve), or the
  // default — node:tls's and the browsers' (see CLIENT_DEFAULT_GROUPS).
  function clientGroups() {
    return (options.groups && options.groups.length) ? options.groups.slice() : CLIENT_DEFAULT_GROUPS.slice();
  }

  // Our transport parameters as they go into the handshake: the connection's
  // (defaults and the application's) and the fields of our role.
  function localQuicParams() {
    var tp = Object.assign({}, options.transportParams || defaultTransportParams());
    // version_information (RFC 9368): what the connection says about
    // versions when its parameters go out — the client's first flight, the
    // server's after it has chosen.
    if (typeof options.versionInformation === 'function') tp.version_information = options.versionInformation();
    // grease_quic_bit (RFC 9287): this side accepts packets with the fixed
    // bit 0 — the parser never checks it. Not on a UDP port shared with
    // other protocols (RFC 9443), which tells QUIC apart by that bit.
    if (options.greaseQuicBit !== false) tp.grease_quic_bit = true;
    // min_ack_delay (draft-ietf-quic-ack-frequency): ACK_FREQUENCY is taken.
    if (typeof options.minAckDelay === 'number') tp.min_ack_delay = options.minAckDelay;
    if (isServer) {
      // RFC 9000 §7.3: the server echoes the DCID of the client's first
      // Initial, and names the SCID it put in its own long headers.
      tp.original_destination_connection_id = originalDcid;
      tp.initial_source_connection_id = localCid;
      // §10.3: the token a client will recognise our Stateless Reset by.
      // Only a secret one: a client accepts any datagram ending in these 16
      // bytes as our reset, so a value an attacker can know — the fixed one
      // that stood here — let anyone end a client's connection with a
      // single forged packet. Without one the parameter is left out.
      if (statelessResetToken) tp.stateless_reset_token = statelessResetToken;
      if (retrySourceCid) tp.retry_source_connection_id = retrySourceCid;
    } else {
      // Client: initial_source_connection_id = our SCID (not DCID!)
      tp.initial_source_connection_id = localCid;
    }
    return build_transport_params(tp);
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
            // A client keeps, with the sessions this connection saves, the
            // server's parameters that 0-RTT must stay within (RFC 9000
            // §7.4.1) — given back with the early secret next time.
            if (!isServer) keepAppData('tp', rememberedParams(parsed));
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

      var quicParams = localQuicParams();

      var tlsContext = {
        local_supported_versions: [0x0304],
        local_supported_alpns: supportedAlpns,
        // Server: X25519MLKEM768 (0x11ec, hybrid post-quantum) first — what
        // browsers offer — then the classical groups. Client: classical only;
        // see lemon-tls ecdh.js on why a client offers the hybrid only when
        // asked.
        local_supported_groups: (serverTls && serverTls.groups) || (isServer ? lemonServerGroups.slice() : clientGroups()),
        // QUIC is TLS 1.3 (RFC 9001 §4.2): its three suites, ChaCha20 among
        // them (crypto.js protects packets with either AEAD). The TLS 1.2
        // suites that were listed could never be chosen. The server's
        // `ciphers`, narrowed to these, where it set them.
        local_supported_cipher_suites: (serverTls && serverTls.cipherSuites) || [0x1301, 0x1302, 0x1303],
        local_extensions: [
          { type: 0x39, data: quicParams }
        ],
        // Signature schemes offered to the peer (client: in the ClientHello;
        // server: in CertificateRequest): lemon-tls's list, as over TCP —
        // ECDSA, EdDSA, RSA-PSS, then ML-DSA where Node has it, the legacy
        // schemes last (accepted on certificates in the chain, never used in
        // a TLS 1.3 CertificateVerify). The short list kept here by hand had
        // no ML-DSA: a server with an ML-DSA certificate could not be
        // verified over QUIC. The HRR's second ClientHello repeats it exactly
        // (RFC 8446 §4.1.2).
        local_supported_signature_algorithms: (serverTls && serverTls.sigalgs) || lemonSigSchemes.slice(),
      };

      session.set_context(tlsContext);
    });

    session.on('message', function (epoch, seq, type, data) {
      if (isServer && type === 'hello') serverHelloSent = true;   // lemon-tls names the ServerHello so
      // A TLS alert is never CRYPTO data in QUIC (RFC 9001 §4.8): it becomes
      // a CONNECTION_CLOSE carrying 0x100 + the alert code. It was sent down
      // the CRYPTO stream like a handshake message — two bytes the peer could
      // only read as a broken handshake — while this side went on waiting:
      // a certificate refused, a handshake failed, and the connection stayed
      // open until the handshake timeout with nothing reported.
      if (type === 'alert') {
        if (data && data.length >= 2 && data[0] === 2) ev.emit('alert', data[1]);
        return;
      }
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

    // 0-RTT: the client_early_traffic_secret — the client's to write with,
    // as soon as its ClientHello offers early data (with what it saved last
    // time: the server's parameters, `remembered`); the server's to read
    // with, once it has decided to take it. Then the verdict ('earlyData').
    session.on('earlySecret', function (secret, info) {
      var cipher = info && info.cipher ? info.cipher : session.getCipher();
      var hashName = TLS_CIPHER_SUITES[cipher] ? TLS_CIPHER_SUITES[cipher].hash : 'sha256';
      ev.emit('earlySecret', { secret: secret, cipher: cipher, hash: hashName,
        remembered: info && info.appData && info.appData.tp ? info.appData.tp : null,
        rememberedApp: info && info.appData && info.appData.app != null ? info.appData.app : null });
    });
    session.on('earlyData', function (accepted) { ev.emit('earlyData', accepted); });

    // Why the handshake failed: a certificate refused, a signature that does
    // not verify, a size limit. lemon-tls has already sent the alert (it
    // arrives above as 'alert' and closes the connection); this is the reason.
    // Nothing listened here, so the reason was lost and the caller saw only a
    // connection that went away. The code is the one node:tls reports for the
    // same failure (authorizationError, e.g. DEPTH_ZERO_SELF_SIGNED_CERT).
    session.on('error', function (err) {
      if (err && !err.code && session.authorizationError) err.code = session.authorizationError;
      ev.emit('error', err);
    });

    // Client: each NewSessionTicket, as the session to resume with (a
    // Buffer, as node:tls gives it). lemon-tls emits it on a server too, for
    // each ticket it issues — that is not ours to hand on.
    if (!isServer) {
      session.on('session', function (blob) { ev.emit('session', Buffer.from(blob)); });
      session.on('OCSPResponse', function (r) { ev.emit('OCSPResponse', Buffer.from(r)); });
    }

    session.on('keyUpdate', function (info) {
      ev.emit('keyUpdate', info.direction, info.secret);
    });

    // NSS SSLKEYLOGFILE lines, forwarded to whoever owns the connection.
    //
    // lemon-tls already formats these correctly for TLS 1.3 — including
    // picking client_random from the right side based on role — and QUIC uses
    // the identical label set (CLIENT_HANDSHAKE_TRAFFIC_SECRET,
    // SERVER_TRAFFIC_SECRET_0, ...), so no translation is needed here.
    //
    // Note that subscribing has a cost: lemon-tls skips building these strings
    // entirely while listenerCount('keylog') is 0. We accept that, matching
    // node:tls, which also always emits 'keylog'. Two short buffers per
    // handshake is not a measurable expense, and having key logs available
    // without a rebuild is worth far more when debugging a live capture.
    session.on('keylog', function (line) {
      ev.emit('keylog', line);
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

    /** The ALPN protocol the handshake settled on, or null before it has. */
    getALPN: function () { return session ? (session.getALPN() || null) : null; },

    /** Encrypted Client Hello (server): null (not offered) | 'accepted' | 'rejected'. */
    getEchStatus: function () { return session ? session.getEchStatus() : null; },

    /** This connection's ticket: { data, resumed, offered } (lemon-tls
     *  TLSSession.getTicketInfo); null before the handshake has started. */
    getTicketInfo: function () { return session && session.getTicketInfo ? session.getTicketInfo() : null; },

    /** Server: replace our transport parameters before the ServerHello is
     *  built — connectionOptions answering after the ClientHello, while the
     *  handshake waits for it (see quic_connection). Returns whether it was
     *  still in time. */
    updateTransportParams: function (tp) {
      options.transportParams = tp;
      if (!session || !helloHandled) return true;   // taken at 'hello'
      if (serverHelloSent) return false;
      session.set_context({ local_extensions: [{ type: 0x39, data: localQuicParams() }] });
      return true;
    },

    /** Server: the transport's own state in the tickets issued from now on
     *  (lemon-tls setTicketState — apart from the application's ticketData),
     *  and another ticket sent now to carry it (sendTicket). Careful Resume's
     *  path measurements go this way. Each returns whether it was done. */
    /** Server: the context tickets are issued and accepted under (lemon-tls
     *  setTicketContext) — the negotiated QUIC version. */
    setTicketContext: function (ctx) { if (session && session.setTicketContext) session.setTicketContext(ctx); },
    /** Server: the context early data is accepted under (lemon-tls
     *  setEarlyDataContext) — changed with the transport parameters. */
    /** Client: the application protocol's settings to keep with the
     *  sessions saved from now on (RFC 9114 §7.2.4.2), for 0-RTT. */
    setRememberedApp: function (v) { if (!isServer) keepAppData('app', v); },
    setEarlyDataContext: function (ctx) { options.earlyDataContext = ctx; if (session && session.setEarlyDataContext) session.setEarlyDataContext(ctx); },
    setTicketState: function (st) { return !!(session && session.setTicketState && session.setTicketState(st)); },
    sendTicket: function () { return !!(session && session.sendTicket && session.sendTicket()); },

    /** Whether the handshake resumed a session (a ticket was accepted). */
    isResumed: function () { return !!(session && session.isResumed); },

    /** 'TLSv1.3' — as TLSSocket.getProtocol() words it; QUIC has no other. */
    getProtocol: function () {
      var v = session ? session.getVersion() : null;
      return v === 0x0304 ? 'TLSv1.3' : v === 0x0303 ? 'TLSv1.2' : null;
    },

    /** { name, standardName, version } — TLSSocket.getCipher()'s shape. */
    getCipherInfo: function () {
      var code = session ? session.getCipher() : null;
      if (code == null) return null;
      var info = TLS_CIPHER_SUITES[code];
      var protocol = this.getProtocol();
      if (!info) return { name: '0x' + code.toString(16), standardName: 'unknown', version: protocol };
      return {
        name: info.name || info.cipher || '0x' + code.toString(16),
        standardName: info.standardName || info.cipher || 'unknown',
        version: protocol
      };
    },

    /**
     * The TLS fingerprints of this QUIC handshake: JA4 and JA5 of the
     * ClientHello, JA4S of the ServerHello — { hash, raw }, or null.
     *
     * The same methods a TLSSocket has over TCP — the session computes them
     * either way, and only the path out to the caller was missing. Over QUIC
     * there is no socket object to hang them on, so they come from here.
     *
     * `protocol: 'q'` is not cosmetic: the first character encodes the
     * transport, and the same client produces a different fingerprint over
     * QUIC than over TCP. Reporting a 't' for a QUIC connection would file it
     * under the wrong client entirely.
     */
    getJA4: function (opts) { return session && session.getJA4 ? session.getJA4(quicOpts(opts)) : null; },

    /** TLS keying material (RFC 8446 §7.5), as node:tls's exportKeyingMaterial(length, label, context) — or null before the handshake has the secret. */
    exportKeyingMaterial: function (length, label, context) {
      return session && session.exportKeyingMaterial ? session.exportKeyingMaterial(length, label, context) : null;
    },
    /** The peer's certificate chain, leaf first, as DER — or null. */
    getPeerCertificateChain: function () {
      var chain = session && session.getPeerCertificate ? session.getPeerCertificate() : null;
      return chain ? chain.map(function (e) { return e.cert; }) : null;
    },
    /** The peer's certificate as node:tls's getPeerCertificate() describes
     *  it (lemon-tls certificateObject) — {} when it sent none, as Node
     *  answers. On a resumed connection, the one its ticket carried. */
    getPeerCertificate: function () {
      var chain = session && session.getPeerCertificate ? session.getPeerCertificate() : null;
      return (chain && chain.length > 0 && certificateObject(chain[0].cert)) || {};
    },
    /** Whether the peer's certificate was verified (TLSSocket.authorized):
     *  false when it sent none. And why not (authorizationError). */
    isAuthorized: function () { return !!(session && session.authorized); },
    authorizationError: function () { return session && session.authorized ? null : ((session && session.authorizationError) || null); },
    getJA5: function (opts) { return session && session.getJA5 ? session.getJA5(quicOpts(opts)) : null; },
    getJA4S: function (opts) { return session && session.getJA4S ? session.getJA4S(quicOpts(opts)) : null; },
    /** What the handshake settled — version, cipher, group, ALPN, resumed,
     *  and the certificate compression used each way — as a TLSSocket's
     *  getNegotiationResult() (lemon-tls); null before there is a session. */
    getNegotiationResult: function () { return session && session.getNegotiationResult ? session.getNegotiationResult() : null; },

    /**
     * The name the client asked for in its ClientHello (SNI), or false —
     * TLSSocket.servername, same values. A client dialling a bare IP address
     * sends none (RFC 6066 §3 forbids an IP literal there).
     */
    getServername: function () {
      return (session && session.context && session.context.remote_sni) || false;
    },

    /**
     * The certificate this connection presents — TLSSocket.getCertificate()'s
     * shape: { subject, issuer, subjectaltname, valid_from, valid_to,
     * fingerprint, fingerprint256, serialNumber, raw }, or {} when none. On a
     * server, the one the SNI lookup chose; on a resumed connection, the one
     * the lookup chose again for the same name.
     */
    getCertificate: function () {
      var chain = session && session.getCertificate ? session.getCertificate() : null;
      if (!chain || chain.length === 0) return {};
      try {
        var der = chain[0].cert || chain[0];
        var x509 = new X509Certificate(Buffer.isBuffer(der) ? der : Buffer.from(der));
        return {
          subject: x509.subject,
          issuer: x509.issuer,
          subjectaltname: x509.subjectAltName,
          valid_from: x509.validFrom,
          valid_to: x509.validTo,
          fingerprint: x509.fingerprint,
          fingerprint256: x509.fingerprint256,
          serialNumber: x509.serialNumber,
          raw: der
        };
      } catch (e) {
        return {};
      }
    },

    close: function () { if (session && session.close) session.close(); }
  };
}

/**
 * Drop-in replacement for tls.createSecureContext.
 *
 * One context now serves every protocol. It used to build a second, node:tls
 * context alongside the lemon-tls one, because HTTP/2 and HTTP/1.1 ran on
 * node:http2 and node:https and those need node's own context object. Both are
 * gone — h2_server and h1_server run on lemon-tls through tcp_listener — so
 * the duplicate context, and the three-way bridge in server.js that had to
 * work out which kind it was holding, go with them.
 *
 * The raw credentials are still kept on the context: an SNICallback may hand
 * one to a layer that needs to rebuild it, and throwing away the inputs would
 * make that impossible.
 */
function createSecureContext(options) {
  var ctx = _lemonCreateSecureContext(options);
  if (ctx && options) {
    ctx._rawKey = options.key || null;
    ctx._rawCert = options.cert || null;
    ctx._rawCa = options.ca || null;
  }
  return ctx;
}

// defaultTransportParams is exported so quic_connection raises its stream
// limits from the same numbers it advertised, rather than a second copy.
export { TLSBridge, createSecureContext, defaultTransportParams, rememberedParams };