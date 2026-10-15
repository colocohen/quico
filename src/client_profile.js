/*
 * quico: a full HTTP stack in JavaScript
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://github.com/colocohen/quico
 */


// ============================================================
//  Cross-layer consistency.
//
//  Four fingerprints are now available for a request — JA4 for the TLS stack,
//  JA4H for the HTTP client, h2Fingerprint for the HTTP/2 implementation, and
//  the User-Agent the caller typed. Each on its own is a label. Their value is
//  in DISAGREEING.
//
//  The reason this works is that the layers are produced by different parts of
//  a real client and cannot be changed independently:
//
//    the TLS fingerprint comes from the crypto library that built the
//    ClientHello — BoringSSL in Chrome, NSS in Firefox, OpenSSL in curl
//
//    the HTTP/2 fingerprint comes from the network stack that opened the
//    connection, which is a different component again
//
//    the User-Agent comes from a string constant that anyone can edit
//
//  A scraper can change the last one for free. Changing the first two means
//  reimplementing TLS and HTTP/2 to match a specific browser build — possible,
//  and the reason curl-impersonate and similar tools exist, but expensive and
//  fragile in a way a header edit is not.
//
//  WHAT THIS IS NOT
//
//  Not an identifier. Every Chrome of the same version on the same platform
//  shares one fingerprint, so this describes a population, never a person.
//
//  Not a verdict. It reports observations and lets the application decide.
//  The right response to "claims Chrome, does not look like Chrome" is almost
//  never a block: a corporate TLS-inspecting proxy produces exactly that
//  signature, and so does an old browser behind a CDN. Rate-limit, challenge,
//  log — and reserve blocking for cases where a false positive is cheap.
//
//  Not stable across upgrades. Chrome changes its TLS profile between
//  versions. Anything matching an exact hash will break on the next release;
//  match on prefixes and on structure instead, which is what the checks below
//  do.
// ============================================================


/** Signals, in rough order of how hard they are to fake. */
var SEVERITY = { INFO: 0, WEAK: 1, STRONG: 2 };


// The JA4 prefix a browser produces, up to the counts, which drift between
// versions. `t13d` alone says TLS 1.3 over TCP with a domain — true of almost
// every modern client — so the cipher COUNT is what separates them: browsers
// offer a curated list, libraries offer whatever their TLS build supports.
var BROWSER_CIPHER_COUNTS = {
  chrome:  [15, 16],
  firefox: [15, 16, 17],
  safari:  [12, 13, 14]
};

// Over QUIC the same browsers offer far fewer, and it is not a different
// profile so much as a different requirement: RFC 9001 mandates TLS 1.3, so
// there is nothing older to stay compatible with and the list collapses to
// the three TLS 1.3 suites. Chrome offers 15 over TCP and 3 over QUIC — the
// same browser, and comparing one against the other reports a mismatch that
// is not there.
var BROWSER_CIPHER_COUNTS_QUIC = {
  chrome:  [3],
  firefox: [3],
  safari:  [3]
};

// Pseudo-header order is set deep in each browser's network stack and has not
// changed in years. Most HTTP libraries use an order matching no browser at
// all, which is why this is the single most useful h2 signal.
var PSEUDO_ORDER = {
  chrome:  'm,a,s,p',
  firefox: 'm,p,a,s',
  safari:  'm,s,p,a'
};


/** Which browser family a User-Agent CLAIMS. Claims only — never trust it. */
function claimedBrowser(ua) {
  ua = String(ua || '');
  // Order matters: Edge and Opera both carry "Chrome" in their UA, and Chrome
  // carries "Safari". Check the more specific strings first.
  if (/\bEdg\//.test(ua)) return 'edge';
  if (/\bOPR\//.test(ua)) return 'opera';
  if (/\bFirefox\//.test(ua)) return 'firefox';
  if (/\bChrome\//.test(ua)) return 'chrome';
  if (/\bSafari\//.test(ua) && /\bVersion\//.test(ua)) return 'safari';
  if (/curl\//i.test(ua)) return 'curl';
  if (/python|go-http|java|okhttp|axios|node-fetch|wget/i.test(ua)) return 'library';
  return null;
}

/** Chrome, Edge and Opera are all Chromium: same TLS and HTTP/2 profile. */
function family(name) {
  if (name === 'edge' || name === 'opera') return 'chrome';
  return name;
}


/**
 * profileRequest(req) — observations about one request, and what they add up
 * to.
 *
 * Returns:
 *
 *   {
 *     claimed: 'chrome',            what the User-Agent says
 *     protocol: '2.0',
 *     fingerprints: { ja4, ja4s, h2, h2raw, h3, h3raw },
 *     signals: [ { id, severity, detail } ],
 *     suspicion: 0..100
 *   }
 *
 * `suspicion` is a convenience, not a truth. It exists so a caller can set one
 * threshold rather than reading every signal, and the signals are there so
 * that a caller who cares can ignore the number.
 */
function profileRequest(req) {
  var sock = req.socket || {};
  var ua = req.headers && req.headers['user-agent'];
  var claimed = claimedBrowser(ua);
  var fam = family(claimed);

  // TLS fingerprints from the socket, by TLSSocket's names: getJA4() and
  // getJA4S(), each { hash, raw } or null. Over TCP that is the TLS socket;
  // over QUIC, the connection's socket stand-in, which answers the same.
  // (This read getFingerprints(), a method no socket has any more — so JA4
  // was always missing, and every TLS check below silently skipped.)
  var ja4r = typeof sock.getJA4 === 'function' ? sock.getJA4() : null;
  var ja4sr = typeof sock.getJA4S === 'function' ? sock.getJA4S() : null;
  var ja4 = ja4r && ja4r.hash ? ja4r.hash : null;
  var h2 = (req.h2Fingerprint ? req.h2Fingerprint() : null) || null;
  // HTTP/3's protocol fingerprint is reported, but not yet checked against
  // browsers: the expected values below are HTTP/2's, measured from browser
  // HTTP/2 stacks, and HTTP/3 is a different stack in every browser.
  var h3 = (req.h3Fingerprint ? req.h3Fingerprint() : null) || null;

  var signals = [];
  function signal(id, severity, detail) {
    signals.push({ id: id, severity: severity, detail: detail });
  }

  // ---- No TLS fingerprint at all ----
  if (!ja4) {
    // Not suspicious by itself: a request arriving over plain HTTP, or through
    // a proxy that terminated TLS upstream, has nothing to fingerprint. It
    // only means the strongest signal is unavailable.
    signal('no-tls-fingerprint', SEVERITY.INFO, 'no TLS fingerprint available');
  }

  // ---- A browser must offer ALPN ----
  if (ja4 && claimed && fam !== 'curl' && fam !== 'library') {
    var alpnPart = ja4.split('_')[0].slice(8);
    if (alpnPart === '00') {
      // Browsers always offer ALPN — they have to, since HTTP/2 requires it.
      // A client claiming to be one that offers none is not one.
      signal('browser-without-alpn', SEVERITY.STRONG,
             'claims ' + claimed + ' but offered no ALPN');
    }
  }

  // ---- Cipher count against the claimed browser ----
  // The first character of JA4 is the transport: 'q' for QUIC, 't' for TCP.
  // Which table applies follows from it.
  var overQuic = ja4 && ja4.charAt(0) === 'q';
  var cipherTable = overQuic ? BROWSER_CIPHER_COUNTS_QUIC : BROWSER_CIPHER_COUNTS;

  if (ja4 && cipherTable[fam]) {
    var count = parseInt(ja4.slice(4, 6), 10);
    var expected = cipherTable[fam];
    if (!isNaN(count) && expected.indexOf(count) === -1) {
      // Deliberately WEAK, not STRONG. The counts drift between browser
      // versions, and a corporate TLS-inspecting proxy rewrites the
      // ClientHello entirely — both produce a mismatch with nothing wrong.
      signal('cipher-count-mismatch', SEVERITY.WEAK,
             'claims ' + claimed + ' over ' + (overQuic ? 'QUIC' : 'TCP') +
             ' (expected ' + expected.join(' or ') + ' ciphers) but offered ' + count);
    }
  }

  // ---- Pseudo-header order: the strongest HTTP/2 signal ----
  if (h2 && h2.ps && h2.ps !== '0' && PSEUDO_ORDER[fam]) {
    if (h2.ps !== PSEUDO_ORDER[fam]) {
      // This one is worth trusting. The order is a constant in each browser's
      // source, unchanged for years, and no proxy rewrites it — an
      // intermediary that re-encodes HTTP/2 would have to reorder
      // pseudo-headers deliberately, which none do.
      signal('pseudo-header-order', SEVERITY.STRONG,
             'claims ' + claimed + ' (expects ' + PSEUDO_ORDER[fam] +
             ') but sent ' + h2.ps);
    }
  }

  // ---- A browser opens a large connection window ----
  if (h2 && !overQuic && claimed && PSEUDO_ORDER[fam]) {
    if (h2.wu === '0') {
      // Browsers widen the connection window immediately because they fetch
      // dozens of resources at once. Libraries keep the 65535 default and send
      // no WINDOW_UPDATE at all.
      signal('no-window-update', SEVERITY.WEAK,
             'claims ' + claimed + ' but sent no connection WINDOW_UPDATE');
    }
  }

  // ---- Client Hints ----
  if (fam === 'chrome' && req.headers && !req.headers['sec-ch-ua']) {
    // Chromium has sent sec-ch-ua on every secure request since version 89.
    // Absent, on a request claiming a recent Chrome, means the headers were
    // written by something that only knows about User-Agent.
    signal('missing-client-hints', SEVERITY.WEAK,
           'claims Chrome but sent no sec-ch-ua');
  }

  // ---- Fetch metadata ----
  if (PSEUDO_ORDER[fam] && req.headers && !req.headers['sec-fetch-mode'] &&
      req.method === 'GET') {
    signal('missing-fetch-metadata', SEVERITY.WEAK,
           'claims ' + claimed + ' but sent no Sec-Fetch-* headers');
  }

  // ---- No User-Agent at all ----
  if (!ua) {
    signal('no-user-agent', SEVERITY.WEAK, 'no User-Agent header');
  }

  // A blunt sum, capped. Deliberately blunt: a caller that wants nuance should
  // read `signals`, and one that does not is better served by a single number
  // than by a formula it will not tune.
  var suspicion = 0;
  for (var i = 0; i < signals.length; i++) {
    if (signals[i].severity === SEVERITY.STRONG) suspicion += 45;
    else if (signals[i].severity === SEVERITY.WEAK) suspicion += 15;
  }
  if (suspicion > 100) suspicion = 100;

  return {
    claimed: claimed,
    protocol: req.httpVersion,
    fingerprints: {
      ja4: ja4,
      ja4s: ja4sr && ja4sr.hash ? ja4sr.hash : null,
      h2: h2 ? h2.hash : null,
      h2raw: h2 ? h2.raw : null,
      h3: h3 ? h3.hash : null,
      h3raw: h3 ? h3.raw : null
    },
    signals: signals,
    suspicion: suspicion
  };
}


export { profileRequest, claimedBrowser, SEVERITY, PSEUDO_ORDER };
