// ============================================================
//  The server's TLS options, as node:tls names them — read once
// ============================================================
//
// createServer takes node:tls's options and hands them to both of its TLS
// stacks: lemon-tls's TLSSocket for HTTP/1.1 and HTTP/2 (tcp_listener), and
// lemon-tls's TLSSession inside each QUIC connection (quic_server →
// quic_connection → tls_bridge). Each side reads them here, once, when it is
// created: a bad value throws from createServer, as from node:tls, and not
// from the first handshake.
//
// Several of them were accepted and dropped. tcp_listener knew requestCert,
// minVersion, maxVersion and handshakeTimeout, but createServer never passed
// them on: `createServer({ minVersion: 'TLSv1.3' })` ran TLS 1.2 all the
// same, and said nothing. ciphers, ecdhCurve and sigalgs were not read at all.
//
//   requestCert, rejectUnauthorized  client certificates (with `ca`) —
//                                    rejectUnauthorized defaults to true, as
//                                    in node:tls, and only matters with
//                                    requestCert
//   minVersion, maxVersion           'TLSv1.2' | 'TLSv1.3' (TCP; QUIC is TLS 1.3)
//   handshakeTimeout                 ms, both
//   ciphers, ecdhCurve, sigalgs      OpenSSL strings (lemon-tls node_options)
//   passphrase                       for an encrypted `key`
//   sessionTimeout                   seconds a ticket stays good
//   honorCipherOrder                 the cipher suite by the server's order
//                                    (`ciphers`); default false, the
//                                    client's — as node:tls
//   certificateCompression           RFC 8879: the algorithms our certificate
//                                    may go compressed in, in order —
//                                    ['brotli', 'zstd', 'zlib'], true (all,
//                                    the default) or false (never)

import lemonTls from 'lemon-tls';

// RFC 8446 §4.6.1 caps a ticket's lifetime at 7 days; a value past it is
// refused, where node:tls would take it — a lifetime the client will not
// honour is a configuration mistake. 0 issues tickets that never open: no
// resumption. Unset: lemon-tls's own default (7200 s).
var MAX_TICKET_LIFETIME = 604800;
function sessionTimeout(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'number' || !Number.isInteger(value))
    throw new TypeError('sessionTimeout must be an integer (seconds), got ' + value);
  if (value < 0 || value > MAX_TICKET_LIFETIME)
    throw new RangeError('sessionTimeout must be 0..' + MAX_TICKET_LIFETIME + ' seconds (RFC 8446 §4.6.1), got ' + value);
  return value;
}

// The suites a QUIC connection can use: TLS 1.3's (RFC 9001 §4.2) — not
// TLS_AES_128_CCM_8_SHA256, which nothing here implements.
var TLS13_SUITES = [0x1301, 0x1302, 0x1303];

/**
 * options → { requestCert, rejectUnauthorized, minVersion, maxVersion,
 *             handshakeTimeout, passphrase, cipherSuites, groups, sigalgs,
 *             sessionTimeout, certificateCompression, honorCipherOrder }
 * with the lists as code points (null: the stack's default). `forQuic`:
 * checked for QUIC — TLS 1.3 only, and the cipher list narrowed to its
 * suites.
 */
function serverTlsOptions(options, forQuic) {
  options = options || {};
  var minV = lemonTls.parseTlsVersion(options.minVersion, 'minVersion');
  var maxV = lemonTls.parseTlsVersion(options.maxVersion, 'maxVersion');
  if (minV && maxV && minV > maxV) throw new RangeError('minVersion ' + options.minVersion + ' is above maxVersion ' + options.maxVersion);
  if (forQuic && maxV && maxV < 0x0304)
    throw new RangeError('maxVersion ' + options.maxVersion + ' rules out HTTP/3, which is TLS 1.3 only — set http3: false, or allow TLSv1.3');
  var ht = options.handshakeTimeout;
  if (ht !== undefined && ht !== null && !(typeof ht === 'number' && ht > 0 && isFinite(ht)))
    throw new TypeError('handshakeTimeout must be a positive number (ms), got ' + ht);
  if (options.passphrase !== undefined && options.passphrase !== null && typeof options.passphrase !== 'string')
    throw new TypeError('passphrase must be a string');
  var suites = lemonTls.parseCiphers(options.ciphers);
  if (forQuic && suites) {
    suites = suites.filter(function (c) { return TLS13_SUITES.indexOf(c) >= 0; });
    if (suites.length === 0) throw new Error('ciphers "' + options.ciphers + '" names no TLS 1.3 suite, and HTTP/3 needs one — set http3: false, or add one (TLS_AES_128_GCM_SHA256)');
  }
  return {
    requestCert: !!options.requestCert,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    minVersion: options.minVersion || undefined,
    maxVersion: options.maxVersion || undefined,
    handshakeTimeout: ht == null ? undefined : ht,
    passphrase: options.passphrase == null ? undefined : options.passphrase,
    cipherSuites: suites,
    groups: lemonTls.parseEcdhCurve(options.ecdhCurve),
    sigalgs: lemonTls.parseSigalgs(options.sigalgs),
    sessionTimeout: sessionTimeout(options.sessionTimeout),
    certificateCompression: lemonTls.parseCertificateCompression(options.certificateCompression),
    honorCipherOrder: options.honorCipherOrder === true,
  };
}

// The names createServer passes on to both stacks.
var TLS_OPTION_NAMES = ['requestCert', 'rejectUnauthorized', 'minVersion', 'maxVersion', 'handshakeTimeout',
                        'passphrase', 'ciphers', 'ecdhCurve', 'sigalgs', 'sessionTimeout',
                        'certificateCompression', 'honorCipherOrder'];
function pickTlsOptions(options) {
  var out = {};
  for (var i = 0; i < TLS_OPTION_NAMES.length; i++) {
    var k = TLS_OPTION_NAMES[i];
    if (options[k] !== undefined) out[k] = options[k];
  }
  return out;
}

export { serverTlsOptions, pickTlsOptions, sessionTimeout };
