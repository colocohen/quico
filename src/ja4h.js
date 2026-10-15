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



import { sha12 } from './http_common.js';


// ============================================================
//  JA4H — HTTP client fingerprint.
//
//  The companion to the TLS fingerprints lemon-tls produces. JA4 says which
//  TLS stack built the ClientHello; JA4H says which HTTP client sent the
//  request. Together they catch a class of thing neither finds alone: a
//  request whose TLS says "Chrome 131" and whose headers say "python-requests"
//  is not a browser, however convincing its User-Agent.
//
//  Format:  a_b_c_d
//
//    a  ge20cn11enus   method, version, cookie, referer, header count, lang
//    b  3a41b52c00e1   hash of the header NAMES, in the order sent
//    c  000000000000   hash of the cookie names, sorted
//    d  000000000000   hash of the cookie name=value pairs, sorted
//
//  The sections are separately useful, which is the point of the a_b_c_d
//  shape. FoxIO's own description: JA4H_c identifies the SITE (every Plex
//  server sets the same cookie names, so every client of one produces the same
//  _c), while JA4H_d identifies the USER (their values differ). That makes _d
//  a per-user handle that contains no personal data — a tracking key that is
//  a hash of a hash, rather than a logged identity.
//
//  A caution worth stating plainly: _d IS a user identifier, GDPR-friendly in
//  form or not. Log it if you need per-user correlation, and think before you
//  keep it longer than the session it describes.
//
//  The published spec (JA4H.md) is 278 bytes and documents ONLY the
//  header-count rule. Everything else here is reconstructed from FoxIO's
//  reference implementations — chiefly the F5 iRule, which carries their
//  copyright — and then verified against a published fingerprint rather than
//  trusted.
//
//  That verification mattered, because FoxIO's own implementations disagree
//  about _b: the Rust CLI documents `--original-order` as DISABLING the
//  sorting of headers, implying it sorts by default, while the iRule appends
//  header names in the order received and never sorts them.
//
//  The disagreement was settled by arithmetic. The Sliver C2 analysis
//  publishes po11cn050000_bb52516416a2_eb49a3237520 for a request whose five
//  counted headers are Host, User-Agent, Content-Length,
//  Upgrade-Insecure-Requests, Accept-Encoding. Hashing every plausible
//  variant of that list gives exactly one match:
//
//      original order, original case  ->  bb52516416a2   <-- published value
//      original order, lowercased     ->  4637073cda60
//      sorted, original case          ->  a56dc1e0e2e6
//      sorted, lowercased             ->  7c182098df7a
//
//  So: order as received, case as received. Which is also the reading that
//  makes sense — ORDER is most of the signal, since browsers emit a stable
//  header order and HTTP libraries emit a different, equally stable one, and
//  sorting would discard exactly that.
// ============================================================

var EMPTY_HASH = '000000000000';


// Two lowercase characters. Anything not in this list is "xx" — which is
// itself a signal, since browsers only ever send these.
var METHOD_CODES = {
  GET: 'ge', POST: 'po', HEAD: 'he', PUT: 'pu', DELETE: 'de',
  CONNECT: 'co', OPTIONS: 'op', TRACE: 'tr', PATCH: 'pa'
};

function methodCode(method) {
  var m = String(method || '').toUpperCase();
  return METHOD_CODES[m] || 'xx';
}

function versionCode(httpVersion) {
  var v = String(httpVersion || '');
  if (v === '1.0' || v === '10') return '10';
  if (v === '1.1' || v === '11') return '11';
  if (v === '2.0' || v === '2' || v === '20') return '20';
  if (v === '3.0' || v === '3' || v === '30') return '30';
  return '00';
}

/**
 * Four characters from Accept-Language, or "0000" when absent.
 *
 * "en-US,en;q=0.9,he;q=0.8" -> "enus": take the first language, drop the
 * q-value, remove the hyphen, lowercase, then truncate or zero-pad to four.
 *
 * Four characters is deliberately coarse. It separates populations — a client
 * with no Accept-Language at all stands out sharply, and most HTTP libraries
 * send none — without turning a language preference into an identifier.
 */
function languageCode(acceptLanguage) {
  if (!acceptLanguage) return '0000';

  // Bounded before anything else. Accept-Language is attacker-controlled and
  // unbounded; the reference implementation truncates to 64 bytes first for
  // exactly that reason.
  var v = String(acceptLanguage).slice(0, 64);

  // Hyphens removed and semicolons turned into commas BEFORE splitting, so
  // that the q-value separator and the language separator are treated alike.
  // "en-US,en;q=0.9" -> "enus,en,q=09" -> first token "enus".
  v = v.replace(/-/g, '').replace(/;/g, ',').toLowerCase();
  var first = v.split(',')[0].slice(0, 4);
  if (first.length === 0) return '0000';

  // Padded by OVERWRITING the leading characters of "0000", so a 2-character
  // language becomes "he00" rather than "00he".
  return first + '0'.repeat(4 - first.length);
}

/** Cookie names and values, in the order sent. */
function parseCookies(cookieHeader) {
  var out = [];
  if (!cookieHeader) return out;
  var parts = String(cookieHeader).split(';');
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (!p) continue;
    var eq = p.indexOf('=');
    if (eq < 0) out.push({ name: p, value: '' });
    else out.push({ name: p.slice(0, eq).trim(), value: p.slice(eq + 1).trim() });
  }
  return out;
}


/**
 * Compute JA4H for one request.
 *
 * Pass a quico (or node:http) IncomingMessage, or a plain object with
 * `method`, `httpVersion`, `headers` and optionally `rawHeaders`.
 *
 * rawHeaders matters and is used when present: it preserves the ORDER the
 * client sent, and order is most of what distinguishes a browser from a
 * library. A `headers` object cannot preserve it reliably — repeated fields
 * are folded and insertion order is an implementation detail — so passing only
 * `headers` still produces a valid fingerprint, just a weaker one.
 *
 * Returns { hash, raw, a, b, c, d } so a caller can match on the whole thing
 * or on any section: `_ab` identifies the client software, `_c` the site, `_d`
 * the user.
 */
function ja4h(req) {
  var headers = (req && req.headers) || {};
  var method = req && (req.method || headers[':method']);
  var version = req && req.httpVersion;

  // Header names in the order the client sent them.
  // ORIGINAL CASE, not lowercased.
  //
  // FoxIO's own iRule appends `${hname}` — the name as sent — and lowercases
  // only for its comparisons. Casing is real signal: HTTP/1.1 clients choose
  // it freely and choose differently ("User-Agent" from a browser,
  // "user-agent" from many libraries), so folding it throws away a
  // distinguishing bit. HTTP/2 and HTTP/3 require lowercase on the wire, so
  // there is nothing to lose there either way.
  var names = [];
  if (req && Array.isArray(req.rawHeaders) && req.rawHeaders.length >= 2) {
    for (var i = 0; i < req.rawHeaders.length; i += 2) {
      names.push(String(req.rawHeaders[i]));
    }
  } else {
    for (var k in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, k)) names.push(String(k));
    }
  }

  // Pseudo-headers are HTTP/2 and HTTP/3 framing, not client-chosen fields,
  // and counting them would make the same client fingerprint differently
  // depending on which version carried the request — the opposite of what a
  // client fingerprint is for.
  names = names.filter(function (n) { return n.charAt(0) !== ':'; });

  function lower(n) { return String(n).toLowerCase(); }
  var lowered = names.map(lower);

  var hasCookie = lowered.indexOf('cookie') !== -1;
  // "referer" only — the misspelling is the one in the HTTP spec, and
  // "referrer" is a different header that a client would have invented.
  var hasReferer = lowered.indexOf('referer') !== -1;

  // Cookie and Referer are excluded from both the count and the hash: they are
  // properties of the SITE and the navigation, not of the client. Their
  // presence is already recorded as the c/r characters, and the cookies
  // themselves get their own sections.
  // "cookie*", not just "cookie": the reference implementation matches the
  // prefix, which also excludes Cookie2 and any other cookie-carrying variant.
  var counted = names.filter(function (n) {
    var l = lower(n);
    return l.indexOf('cookie') !== 0 && l !== 'referer';
  });

  var count = counted.length;
  if (count > 99) count = 99;
  var countStr = (count < 10 ? '0' : '') + count;

  var a = methodCode(method) +
          versionCode(version) +
          (hasCookie ? 'c' : 'n') +
          (hasReferer ? 'r' : 'n') +
          countStr +
          languageCode(headers['accept-language']);

  // Order preserved, not sorted. Browsers emit a stable header order and HTTP
  // libraries emit a different, equally stable one, so the order carries more
  // signal than the set does.
  var bRaw = counted.join(',');
  var b = counted.length ? sha12(bRaw) : EMPTY_HASH;

  // Keyed off hasCookie — the same flag that produced the 'c' character —
  // rather than off whether any cookie parsed. A Cookie header that is present
  // but empty still means "this client sends cookies", and the two sections
  // must agree with the character or the fingerprint contradicts itself.
  var cookies = hasCookie ? parseCookies(headers['cookie']) : [];

  // Sorted, unlike the header names: cookie order is not under the client's
  // control in the way header order is, so sorting removes noise rather than
  // signal.
  var cookieNames = cookies.map(function (x) { return x.name; }).sort();
  var cRaw = cookieNames.join(',');
  var c = hasCookie ? sha12(cRaw) : EMPTY_HASH;

  var cookiePairs = cookies.map(function (x) { return x.name + '=' + x.value; }).sort();
  var dRaw = cookiePairs.join(',');
  var d = hasCookie ? sha12(dRaw) : EMPTY_HASH;

  return {
    hash: a + '_' + b + '_' + c + '_' + d,

    // The raw form deliberately STOPS at the cookie names and omits their
    // values, which is what the reference implementation does and for a reason
    // worth repeating: cookie values are session tokens. The _d hash above
    // already captures that dimension, so printing the values into a log adds
    // nothing but a credential leak.
    raw: a + '_' + bRaw + '_' + cRaw,
    a: a, b: b, c: c, d: d
  };
}


export { ja4h, languageCode, methodCode, versionCode };
