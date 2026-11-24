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
//  What every HTTP version agrees on.
//
//  The three versions differ in how a message is put on the wire and in
//  nothing else: the same methods, the same status codes, the same rules about
//  which field may repeat and how repeats combine, the same meaning for
//  Content-Length. Those rules live in RFC 9110, which is deliberately
//  version-independent, and so does this file.
//
//  What does NOT belong here is anything a version does its own way: framing,
//  compression, stream state, flow control. h1.js, h2.js and h3.js keep those.
//  The test is simple — if a rule cites RFC 9110 it is shared, and if it cites
//  9112 / 9113 / 9114 it is not.
// ============================================================


import fs from 'node:fs';
import { Duplex } from 'node:stream';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';
import { createEmitter } from './utils.js';


// ============================================================
//  Emitter
//
//  One implementation, because there were four: h1.js, h2.js and ws.js each
//  grew a private copy, and utils.js has a fifth that differs in the one way
//  that matters — it wraps every listener in try/catch and discards what it
//  catches. That is how a QPACK failure reached nobody at all: it threw, and
//  the emitter ate it.
//
//  This one does NOT swallow. A listener that throws is a bug in the listener,
//  and the caller that pumped bytes in is the right place to see it — every
//  such caller in this codebase already wraps execute() and turns a throw into
//  a protocol error with the correct code.
// ============================================================

function Emitter() { return createEmitter(false); }   // one implementation: utils.js


// ============================================================
//  Tokens and field values (RFC 9110 §5.1, §5.5)
// ============================================================

// tchar, per RFC 9110 §5.6.2. A table because these run over every byte of
// every field name.
var IS_TCHAR = (function () {
  var t = new Uint8Array(256);
  var s = "!#$%&'*+-.^_`|~0123456789" +
          'abcdefghijklmnopqrstuvwxyz' +
          'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  for (var i = 0; i < s.length; i++) t[s.charCodeAt(i)] = 1;
  return t;
})();

function isToken(str) {
  if (typeof str !== 'string' || str.length === 0) return false;
  for (var i = 0; i < str.length; i++) {
    if (!IS_TCHAR[str.charCodeAt(i)]) return false;
  }
  return true;
}

/**
 * A field value may hold VCHAR, SP, HTAB and obs-text. It may NOT hold CR, LF
 * or NUL.
 *
 * The most important check in the HTTP stack, and it applies to every version.
 * In HTTP/1.1 a CR or LF in a value injects a field line or a whole message —
 * response splitting in any application that reflects user input into a
 * header. HTTP/2 and HTTP/3 do not frame by line, so this cannot split a
 * message there; but the value is very often forwarded to an HTTP/1.1 origin
 * behind a proxy, where it can. Validating only in h1.js would leave that door
 * open, so it is validated everywhere.
 */
function isValidFieldValue(str) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c === 0x0d || c === 0x0a || c === 0x00) return false;
    if (c < 0x20 && c !== 0x09) return false;
    if (c === 0x7f) return false;
  }
  return true;
}

/** A field value may not begin or end with whitespace (RFC 9110 §5.5). */
function isTrimmedFieldValue(str) {
  if (str.length === 0) return true;
  var first = str.charCodeAt(0), last = str.charCodeAt(str.length - 1);
  return first !== 0x20 && first !== 0x09 && last !== 0x20 && last !== 0x09;
}


// ============================================================
//  Repeated fields (RFC 9110 §5.3)
// ============================================================

/**
 * Add a field to a header object, combining repeats the way each field
 * requires.
 *
 * Three different rules, and using the wrong one corrupts data rather than
 * merely looking untidy:
 *
 *   set-cookie  — never combined. Its own grammar contains commas (in Expires
 *                 dates), so joining with ", " makes every cookie after the
 *                 first unparseable. RFC 9110 §5.3 carves it out by name.
 *   cookie      — combined with "; ", not ",". RFC 9113 §8.2.3 permits an
 *                 HTTP/2 sender to split it across fields precisely so it
 *                 compresses better, and the receiver must rejoin it in the
 *                 form the Cookie grammar uses.
 *   everything  — combined with ", ", the general list rule.
 *
 * h1.js and h2.js had two separate copies of this, already differing: h1
 * handled set-cookie and h2 handled set-cookie and cookie.
 */
// "Already present" means an own property. `name in headers` also found the
// object's prototype: a field named `constructor` was taken
// for a repeat and joined onto the inherited function's text, and one named
// `__proto__` replaced the object's prototype instead of being stored.
var hasOwn = Object.prototype.hasOwnProperty;
function addHeader(headers, name, value) {
  if (!hasOwn.call(headers, name)) {
    var v = name === 'set-cookie' ? [value] : value;
    if (name === '__proto__') Object.defineProperty(headers, name, { value: v, enumerable: true, writable: true, configurable: true });
    else headers[name] = v;
    return headers;
  }
  if (name === 'set-cookie') {
    if (!Array.isArray(headers[name])) headers[name] = [headers[name]];
    headers[name].push(value);
  } else if (name === 'cookie') {
    headers[name] += '; ' + value;
  } else {
    headers[name] += ', ' + value;
  }
  return headers;
}


// ============================================================
//  Content-Length (RFC 9110 §8.6)
// ============================================================

/**
 * Parse a Content-Length value, which may already have been combined from
 * repeats into "5, 5".
 *
 * Returns the number, or null when the field is absent. Throws when it is
 * unusable — and "unusable" is strict on purpose. "+5", " 5", "0x5" and "5\v"
 * are each read as a number by some parser somewhere and as zero by another,
 * and a length two hops disagree about is exactly what request smuggling is
 * built from. Repeats with the SAME value are permitted (§8.6): that is one
 * length stated twice. Differing values are the classic desync.
 */
function parseContentLength(raw) {
  if (raw === undefined || raw === null) return null;
  var parts = String(raw).split(',');
  var first = null;
  for (var i = 0; i < parts.length; i++) {
    // OWS is SP and HTAB (RFC 9110 §5.6.3), and nothing else is taken off:
    // trim() also took \v, \f and NBSP (0xA0, obs-text — legal in a value),
    // so "5\xA0" was a length of 5 here and malformed to a parser that reads
    // the grammar.
    var p = parts[i].replace(/^[ \t]+|[ \t]+$/g, '');
    if (!/^[0-9]+$/.test(p)) throw new Error('invalid Content-Length: ' + JSON.stringify(raw));
    if (first === null) first = p;
    else if (p !== first) throw new Error('conflicting Content-Length values: ' + raw);
  }
  var n = parseInt(first, 10);
  if (!isFinite(n) || n > Number.MAX_SAFE_INTEGER) {
    throw new Error('Content-Length out of range: ' + raw);
  }
  return n;
}


// ============================================================
//  Method and status semantics (RFC 9110 §9, §15)
// ============================================================

/** A response to these carries no body regardless of what its headers claim. */
function statusHasNoBody(statusCode) {
  return (statusCode >= 100 && statusCode < 200) || statusCode === 204 || statusCode === 304;
}

/**
 * Does a response to `method` with `statusCode` carry a body?
 *
 * Version-independent, and each clause is a real desync if omitted: a 304
 * usually carries the Content-Length of the cached representation, and a HEAD
 * response carries the length of the body it is not sending. Believing either
 * makes an HTTP/1.1 client read the next response as this one's body, and
 * makes an HTTP/2 client wait for DATA that never comes.
 */
function responseHasBody(method, statusCode) {
  if (statusHasNoBody(statusCode)) return false;
  if (method === 'HEAD') return false;
  if (method === 'CONNECT' && statusCode >= 200 && statusCode < 300) return false;
  return true;
}

var STATUS_TEXT = {
  100: 'Continue', 101: 'Switching Protocols', 102: 'Processing', 103: 'Early Hints',
  200: 'OK', 201: 'Created', 202: 'Accepted', 203: 'Non-Authoritative Information',
  204: 'No Content', 205: 'Reset Content', 206: 'Partial Content', 207: 'Multi-Status',
  208: 'Already Reported', 226: 'IM Used',
  300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
  304: 'Not Modified', 305: 'Use Proxy', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 402: 'Payment Required', 403: 'Forbidden',
  404: 'Not Found', 405: 'Method Not Allowed', 406: 'Not Acceptable',
  407: 'Proxy Authentication Required', 408: 'Request Timeout', 409: 'Conflict',
  410: 'Gone', 411: 'Length Required', 412: 'Precondition Failed',
  413: 'Content Too Large', 414: 'URI Too Long', 415: 'Unsupported Media Type',
  416: 'Range Not Satisfiable', 417: 'Expectation Failed', 418: "I'm a Teapot",
  421: 'Misdirected Request', 422: 'Unprocessable Content', 423: 'Locked',
  424: 'Failed Dependency', 425: 'Too Early',
  426: 'Upgrade Required', 428: 'Precondition Required', 429: 'Too Many Requests',
  431: 'Request Header Fields Too Large', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway',
  503: 'Service Unavailable', 504: 'Gateway Timeout', 505: 'HTTP Version Not Supported',
  506: 'Variant Also Negotiates', 507: 'Insufficient Storage', 508: 'Loop Detected',
  509: 'Bandwidth Limit Exceeded', 510: 'Not Extended', 511: 'Network Authentication Required'
};


// ============================================================
//  Connection-specific fields (RFC 9113 §8.2.2, RFC 9114 §4.2)
//
//  Meaningless in HTTP/2 and HTTP/3, and their presence is how a message that
//  means one thing over h2 becomes two requests after an HTTP/1.1 hop. Both
//  versions require a receiver to treat them as malformed rather than ignore
//  them, and both name the same set — so it lives here rather than being
//  written out twice.
// ============================================================

var CONNECTION_SPECIFIC = {
  'connection': 1, 'proxy-connection': 1, 'keep-alive': 1,
  'transfer-encoding': 1, 'upgrade': 1
};

/**
 * Fields no trailer section may carry, whatever the version (RFC 9110
 * §6.5.1): framing and routing (content-length, transfer-encoding, host),
 * request modifiers (te, expect), the trailer list itself, authentication.
 * One list for the parser that refuses them (h1.js) and for trailerFields,
 * which does not send them.
 */
var TRAILER_FORBIDDEN = { 'content-length': true, 'transfer-encoding': true, 'host': true, 'te': true,
                          'trailer': true, 'connection': true, 'expect': true, 'authorization': true };

/**
 * A message's trailers (res.addTrailers) as they may go on the wire, every
 * version: lower-case names; no pseudo-header, no connection-specific field
 * (RFC 9113 §8.2.2, RFC 9114 §4.2) and none of TRAILER_FORBIDDEN; a list
 * value joined, as one field. Sent as given, a `connection` trailer made the
 * peer refuse the whole response as malformed — over HTTP/1.1 too, where
 * QUICO's own parser rightly refuses it. null when nothing is left.
 */
function trailerFields(trailers) {
  if (!trailers) return null;
  var out = {}, any = false;
  for (var name in trailers) {
    if (!Object.prototype.hasOwnProperty.call(trailers, name)) continue;
    var lower = String(name).toLowerCase();
    if (lower.charCodeAt(0) === 58 || isConnectionSpecific(lower) || TRAILER_FORBIDDEN[lower]) continue;
    var value = trailers[name];
    if (value === undefined || value === null) continue;
    out[lower] = Array.isArray(value) ? value.map(String).join(', ') : String(value);
    any = true;
  }
  return any ? out : null;
}

function isConnectionSpecific(name) {
  return CONNECTION_SPECIFIC[name] === true || CONNECTION_SPECIFIC[name] === 1;
}


// ============================================================
//  Pseudo-headers ↔ HTTP/1.1 request line
//
//  HTTP/2 and HTTP/3 encode the request line as four pseudo-headers and the
//  Host header as :authority. The translation is identical in both, and was
//  being written by hand in h3_client, in the H2 branch of client.js, and
//  would have been written a third time in h2_client.
// ============================================================

// `:protocol` is the extended CONNECT pseudo-header of RFC 8441, which is what
// carries WebSocket over HTTP/2 and HTTP/3. It is only legal on a CONNECT
// request, and only once the peer has advertised ENABLE_CONNECT_PROTOCOL — a
// receiver that has not enabled it must treat the request as malformed, which
// is checked where the settings are known rather than here.
//
// The same mechanism, with a different value, is how WebTransport rides on
// HTTP/3: h3.js already sends SETTINGS_ENABLE_CONNECT_PROTOCOL for it.
var REQUEST_PSEUDO = { ':method': 1, ':scheme': 1, ':authority': 1, ':path': 1, ':protocol': 1 };
var RESPONSE_PSEUDO = { ':status': 1 };

// ---- Host names and authorities (RFC 3986 §3.2.2) ----
//
// An IPv6 literal is written in brackets in an authority — a URL, Host,
// :authority, an Alt-Svc value — and without them everywhere a host is
// connected to or compared: net.connect, a QUIC socket, a pool's key. node's
// urlToHttpOptions takes them off a URL's hostname, and its client puts them
// back on Host. Neither was done: "https://[::1]/" connected to "[::1]", which
// no resolver knows, and a hostname of "::1" went out as "Host: ::1:8443".

/** A URL's (or an authority's) host as one connects to it: no brackets. */
function urlHostname(hostname) {
  if (typeof hostname !== 'string') return hostname;
  return hostname.charCodeAt(0) === 0x5b && hostname.charCodeAt(hostname.length - 1) === 0x5d
    ? hostname.slice(1, -1) : hostname;
}

/**
 * The authority of a request to `hostname` on `port` — for Host and
 * :authority: an IPv6 literal in brackets, the port left out when it is the
 * scheme's default (`defaultPort`), as every client does: including it
 * changes the origin for virtual-host routing and for CORS.
 */
function formatAuthority(hostname, port, defaultPort) {
  var h = String(hostname);
  if (h.indexOf(':') >= 0 && h.charCodeAt(0) !== 0x5b) h = '[' + h + ']';
  return port && Number(port) !== defaultPort ? h + ':' + port : h;
}

function isPseudoHeader(name) {
  return typeof name === 'string' && name.charCodeAt(0) === 0x3a;
}

/**
 * Build the header list for an HTTP/2 or HTTP/3 request.
 *
 * Returns [ [name, value], ... ] with the pseudo-headers first, because both
 * versions require that ordering and a receiver treats a pseudo-header after a
 * regular field as malformed.
 *
 * `Host` is dropped in favour of `:authority` — sending both is permitted only
 * when they agree, and there is no reason to risk them disagreeing. The
 * authority is formatAuthority's.
 */
function buildRequestPseudoHeaders(options) {
  var method = String(options.method || 'GET').toUpperCase();
  var scheme = options.scheme || 'https';
  var port = options.port;
  var defaultPort = scheme === 'http' ? 80 : 443;
  var authority = options.authority || formatAuthority(options.hostname, port, defaultPort);

  var list = [
    [':method', method],
    [':scheme', scheme],
    [':authority', authority],
    [':path', options.path || '/']
  ];

  var headers = options.headers || {};
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    var lower = String(name).toLowerCase();
    if (isPseudoHeader(lower)) continue;          // never set by the caller
    if (lower === 'host') continue;               // :authority carries it
    if (isConnectionSpecific(lower)) continue;    // malformed in h2/h3

    var value = headers[name];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) list.push([lower, String(value[i])]);
    } else {
      list.push([lower, String(value)]);
    }
  }
  return list;
}

/**
 * Turn a decoded h2/h3 request header set into the shape a Node-style
 * IncomingMessage wants: a method, a url, and the headers.
 *
 * The pseudo-headers stay in `headers`, as node:http2 keeps them
 * (req.headers[':path'], [':authority'], [':scheme']) — code written against
 * node reads them there, and HTTP/3 requests always carried them. They were
 * dropped here, so the same application saw them on HTTP/3 and not on HTTP/2.
 */
function pseudoHeadersToRequest(headers) {
  var out = { method: headers[':method'], url: headers[':path'], headers: {} };
  for (var name in headers) out.headers[name] = headers[name];
  // Frameworks read req.headers.host; :authority is where it lives now.
  if (headers[':authority'] !== undefined && out.headers.host === undefined) {
    out.headers.host = headers[':authority'];
  }
  return out;
}

/** Build the header list for an h2/h3 response. */
function buildResponsePseudoHeaders(statusCode, headers) {
  var list = [[':status', String(statusCode)]];
  headers = headers || {};
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    var lower = String(name).toLowerCase();
    if (isPseudoHeader(lower)) continue;
    if (isConnectionSpecific(lower)) continue;
    var value = headers[name];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) list.push([lower, String(value[i])]);
    } else {
      list.push([lower, String(value)]);
    }
  }
  return list;
}


/**
 * A truncated SHA-256, the hash every JA4-family fingerprint uses.
 *
 * Twelve hex characters is what the published formats specify, and it is
 * enough: these identify a client population, not a person, so collisions
 * between two unrelated TLS stacks are a curiosity rather than a failure.
 */
function sha12(str) {
  return Buffer.from(sha256_sync(str)).toString('hex').slice(0, 12);   // the string as its UTF-8
}


// ============================================================
//  A received field section, HTTP/2 or HTTP/3 (RFC 9113 §8.1–8.3, RFC 9114
//  §4.1–4.3 — the same rules in both): one function, so the two versions
//  cannot drift. h2 checked them and h3 checked none — a value with CR LF, a
//  connection-specific field, a request with no :path all reached an HTTP/3
//  handler as they came.
//
//  list: [[name, value], ...] in the order received.
//  opts: isServer — a request (else a response);
//        trailers — a trailing section (no pseudo-headers, no request rules);
//        connectProtocol — extended CONNECT is permitted (we advertised it).
//  Returns { headers, pseudoOrder, protocol }. Throws an Error whose message
//  says what was malformed; the caller answers with its own code.
// ============================================================
// ============================================================
//  Authority — Host, :authority (RFC 9110 §7.2, RFC 3986 §3.2)
// ============================================================
//
// host [":" port]: a bracketed IP literal, or a reg-name (letters, digits,
// - . _ ~, sub-delims, %-escapes) — nothing else: no space, no control
// character, no "@" (userinfo is not part of Host, and deprecated in
// :authority, RFC 9113 §8.3.1), no "/" "?" "#". The name is what requests are
// routed by — virtual hosts, certificates, access rules — and a value that
// one component reads differently from another (a space, a "user@" before
// it, a path after it) is where they disagree about which site was asked
// for. nginx checks the same since 1.29.4.
var AUTHORITY_RE = /^(?:\[[0-9A-Fa-f:.]+\]|\[v[0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+\]|[A-Za-z0-9\-._~%!$&'()*+,;=]*)(?::[0-9]*)?$/;
function isValidAuthority(value) {
  return typeof value === 'string' && AUTHORITY_RE.test(value);
}

// The site an authority names, for comparing two of them: the host in
// lowercase, the port without the scheme's default (example.com and
// EXAMPLE.com:443 are one site over https).
function authorityKey(value, scheme) {
  var v = String(value).toLowerCase();
  var def = scheme === 'http' ? ':80' : scheme === 'https' ? ':443' : null;
  if (def && v.slice(-def.length) === def) v = v.slice(0, -def.length);
  if (v.charAt(v.length - 1) === ':') v = v.slice(0, -1);
  return v;
}

function validateFieldSection(list, opts) {
  var isServer = !!opts.isServer, trailers = !!opts.trailers;
  var headers = {};
  var seenRegular = false;
  var pseudo = isServer ? REQUEST_PSEUDO : RESPONSE_PSEUDO;
  // The order pseudo-headers arrive in. The RFCs fix that they come before
  // regular fields and say nothing about their order among themselves, so
  // each implementation chose one and kept it — Chrome m,a,s,p, Firefox
  // m,p,a,s, Safari m,s,p,a. See h2_fingerprint.js. Collected here because
  // this loop is the only place that sees the list in its original sequence.
  var pseudoOrder = [];
  // The fields as they came, one name and value per field line, pseudo-headers
  // first: for rawHeaders, which node:http2 keeps that way (the map combines
  // repeated ones).
  var raw = [];
  var bad = function (m) { var e = new Error(m); e.malformed = true; return e; };

  for (var i = 0; i < list.length; i++) {
    var name = list[i][0];
    var value = String(list[i][1]);

    // A field value with CR, LF or NUL, or starting or ending with whitespace,
    // makes the message malformed. Passed through, an application proxying to
    // an HTTP/1.1 upstream writes it where CR LF ends a line: one request
    // becomes a second, injected, one.
    if (!isValidFieldValue(value) || !isTrimmedFieldValue(value)) throw bad('invalid value for field ' + name);

    if (isPseudoHeader(name)) {
      pseudoOrder.push(name);
      if (trailers) throw bad('pseudo-header in trailers');
      if (seenRegular) throw bad('pseudo-header after a regular field');
      if (!pseudo[name]) throw bad('unknown or misdirected pseudo-header ' + name);
      if (hasOwn.call(headers, name)) throw bad('duplicate pseudo-header ' + name);
      headers[name] = value;
      raw.push(name, value);   // node:http2 keeps them in rawHeaders too
      continue;
    }
    seenRegular = true;

    // A field name is a token, in lowercase.
    if (!isToken(name) || name !== name.toLowerCase()) throw bad('invalid field name ' + JSON.stringify(name));
    // Carrying these across is how a request that means one thing here
    // becomes two requests after an HTTP/1.1 hop.
    if (isConnectionSpecific(name)) throw bad('connection-specific field ' + name + ' is not permitted');
    if (name === 'te' && value.toLowerCase() !== 'trailers') throw bad('te may only be "trailers"');

    // Repeat-combining is RFC 9110 §5.3: set-cookie never joins, cookie joins
    // with "; " (which h2 and h3 rely on: a sender may split it to compress).
    addHeader(headers, name, value);
    raw.push(name, value);
  }

  var protocol = null;
  if (isServer && !trailers) {
    var isConnect = headers[':method'] === 'CONNECT';
    if (headers[':protocol'] !== undefined) {
      // Extended CONNECT (RFC 8441 §4, RFC 9220): only on CONNECT, only if we
      // said it could be used — and, unlike a plain CONNECT, with :scheme and
      // :path, which is what lets a WebSocket handshake name an endpoint.
      if (!opts.connectProtocol) throw bad('extended CONNECT used but not enabled');
      if (!isConnect) throw bad(':protocol is only valid on a CONNECT request');
      if (!headers[':scheme'] || !headers[':path']) throw bad('extended CONNECT requires :scheme and :path');
      protocol = headers[':protocol'].toLowerCase();
    } else if (isConnect) {
      // A plain CONNECT is a tunnel: no :scheme or :path; :authority is the target.
      if (headers[':scheme'] !== undefined || headers[':path'] !== undefined) throw bad('CONNECT must omit :scheme and :path');
      if (!headers[':authority']) throw bad('CONNECT requires :authority');
    } else if (!headers[':method'] || !headers[':scheme'] || !headers[':path']) {
      throw bad('request is missing a mandatory pseudo-header');
    }
    if (headers[':path'] !== undefined) {
      // The path of an http(s) request is absolute ("/…"), or "*" for
      // OPTIONS — and, as in a request line, holds no space or control
      // character (the HTTP/1.1 parser refuses the same).
      var p = headers[':path'];
      if (!(p.charCodeAt(0) === 0x2f || (p === '*' && headers[':method'] === 'OPTIONS')) || /[\x00-\x20\x7f]/.test(p)) {
        throw bad('invalid :path');
      }
    }
    if (headers[':method'] !== undefined && !isToken(headers[':method'])) throw bad('invalid :method');

    // The site asked for (RFC 9113 §8.3.1, RFC 9114 §4.3.1): :authority or
    // Host, well formed — and, when both are present, the same site. A
    // request naming one site in :authority and another in Host is routed by
    // whichever a component reads: the certificate check and the virtual host
    // by one, a framework's req.hostname by the other. "A server SHOULD treat
    // a request as malformed if it contains a Host header field that
    // identifies an entity that differs from the entity in the :authority".
    var auth = headers[':authority'], host = headers['host'];
    if (auth !== undefined && (auth === '' || !isValidAuthority(auth))) throw bad('invalid :authority');
    if (host !== undefined && !isValidAuthority(host)) throw bad('invalid host');
    if (auth !== undefined && host !== undefined &&
        authorityKey(auth, headers[':scheme']) !== authorityKey(host, headers[':scheme'])) {
      throw bad(':authority and host name different sites');
    }
    if (auth === undefined && host === undefined && !isConnect &&
        (headers[':scheme'] === 'http' || headers[':scheme'] === 'https')) {
      throw bad('request names no authority (:authority or host)');
    }
  }
  if (!isServer && !trailers) {
    if (!headers[':status']) throw bad('response is missing :status');
    // Three digits (RFC 9110 §15), as the HTTP/1.1 parser reads a status
    // line: what was only checked for presence went to parseInt ("200abc"
    // a 200) and to h3's /^1/ (an informational response for "1abc").
    if (!/^[0-9]{3}$/.test(headers[':status'])) throw bad('invalid :status');
  }

  Object.defineProperty(headers, '_rawHeaders', { value: raw, enumerable: false });
  return { headers: headers, pseudoOrder: pseudoOrder, protocol: protocol };
}


// ============================================================
//  Validation of what an APPLICATION hands us — node:http's rules, codes and
//  messages, thrown at the call, where node throws them.
//
//  Values often come from user input; a CR/LF in one is a header injected or
//  a request split on the wire (node's CVE-2018-12116 is the client-path
//  case). Nothing reached the wire before — but the check came late (at
//  writeHead/end, with an internal error code) or not at all (client: an
//  'error' event later), so `try { res.setHeader(...) } catch` written for
//  node caught nothing. node:http exports the same two functions.
// ============================================================

// node's checkInvalidHeaderChar: anything but HTAB, SP–~ and obs-text.
var INVALID_HEADER_CHAR = /[^\t\x20-\x7e\x80-\xff]/;
// node's INVALID_PATH_REGEX: a request path is ! … ÿ, nothing else.
var INVALID_PATH_CHAR = /[^\u0021-\u00ff]/;

function nodeError(Ctor, code, message) {
  var e = new Ctor(message);
  e.code = code;
  return e;
}

function validateHeaderName(name, label) {
  if (typeof name !== 'string' || !isToken(name)) {
    throw nodeError(TypeError, 'ERR_INVALID_HTTP_TOKEN', (label || 'Header name') + ' must be a valid HTTP token ["' + name + '"]');
  }
}

function validateHeaderValue(name, value) {
  if (value === undefined) {
    throw nodeError(TypeError, 'ERR_HTTP_INVALID_HEADER_VALUE', 'Invalid value "' + value + '" for header "' + name + '"');
  }
  var list = Array.isArray(value) ? value : [value];
  for (var i = 0; i < list.length; i++) {
    if (INVALID_HEADER_CHAR.test(String(list[i]))) {
      throw nodeError(TypeError, 'ERR_INVALID_CHAR', 'Invalid character in header content ["' + name + '"]');
    }
  }
}

// writeHead: a status code of three digits, a reason phrase without CR/LF.
function validateStatus(statusCode, statusMessage) {
  var n = statusCode | 0;
  if (n < 100 || n > 999 || n !== Number(statusCode)) {
    throw nodeError(RangeError, 'ERR_HTTP_INVALID_STATUS_CODE', 'Invalid status code: ' + statusCode);
  }
  if (statusMessage !== undefined && INVALID_HEADER_CHAR.test(String(statusMessage))) {
    throw nodeError(TypeError, 'ERR_INVALID_CHAR', 'Invalid character in statusMessage');
  }
}

// A client request's path and method.
function validateRequestTarget(path, method) {
  if (path !== undefined && INVALID_PATH_CHAR.test(String(path))) {
    throw nodeError(TypeError, 'ERR_UNESCAPED_CHARACTERS', 'Request path contains unescaped characters');
  }
  if (method !== undefined) validateHeaderName(String(method), 'Method');
}

/**
 * Run the application's request handler (and the 'request' listeners).
 *
 * node:http calls it straight from the socket's 'data' — a throw goes up to
 * process 'uncaughtException', and the request is left as it was: open, never
 * answered. Here the throw is caught long enough to end that one exchange —
 * `fail(err)`: HTTP/1.1 answers 500 and closes, HTTP/2 and HTTP/3 reset only
 * that stream — and then thrown again, on the next tick, so it still reaches
 * 'uncaughtException' (or ends the process) exactly as in node. It is not
 * swallowed: a bug in a handler must stay visible.
 *
 * Before, the throw went wherever the caller's frame took it: on HTTP/1.1 into
 * the parser's catch, reported as 'clientError' — the client blamed, the
 * connection dropped, the exception hidden; on HTTP/2 into the frame loop, a
 * GOAWAY that took every other stream of the connection with it.
 */
function runRequestHandler(call, fail) {
  try {
    call();
  } catch (err) {
    try { fail(err); } catch (e) { /* the exchange is gone either way */ }
    process.nextTick(function () { throw err; });
  }
}

/**
 * Hold a socket's writes until the end of this tick, then send them as one.
 *
 * A response is written in pieces — the head, a frame header, a body chunk,
 * the next frame — each its own socket.write(), and on an idle socket each
 * of those was a system call and, with Nagle off, a TCP segment of its own.
 * Corked, everything written in the same tick goes out in one writev. The
 * tick ends before any I/O is waited on, so nothing is delayed.
 */
function corkForTick(socket) {
  if (socket.writableCorked) return;
  socket.cork();
  process.nextTick(uncork, socket);
}
function uncork(socket) { socket.uncork(); }

// ---- Extensible priorities (RFC 9218), HTTP/2 and HTTP/3 alike ----
//
// A request's `priority` field, or a PRIORITY_UPDATE frame's value: a
// Structured Field Dictionary (RFC 8941) of which two members mean anything —
//   u  urgency, an integer 0 (most urgent) to 7; default 3
//   i  incremental, a boolean: served a share at a time alongside others of
//      its urgency (true) or one after another, whole (false, the default)
// Unknown members, and members of the wrong type, are ignored (§4.1); a value
// that does not parse is the defaults (§4). Returned as { urgency,
// incremental } — what the senders' schedulers take (quic_connection's
// setStreamPriority, h2.js).
function parsePriority(value) {
  var out = { urgency: 3, incremental: false };
  if (value == null) return out;
  var str = Array.isArray(value) ? value.join(',') : String(value);
  var members = str.split(',');
  for (var k = 0; k < members.length; k++) {
    var m = members[k].trim();
    if (!m) continue;
    var semi = m.indexOf(';');               // parameters: not used here
    if (semi >= 0) m = m.slice(0, semi).trim();
    var eq = m.indexOf('=');
    var key = (eq >= 0 ? m.slice(0, eq) : m).trim();
    var val = eq >= 0 ? m.slice(eq + 1).trim() : '?1';   // a bare key is true
    if (key === 'u') {
      if (/^[0-7]$/.test(val)) out.urgency = Number(val);
    } else if (key === 'i') {
      if (val === '?1') out.incremental = true;
      else if (val === '?0') out.incremental = false;
    }
  }
  return out;
}

// What an application passes to res.setPriority, as the senders take it:
// the fields given, urgency within RFC 9218's 0..7 (below it is the
// transport's own: HTTP/3's control streams).
function responsePriority(p) {
  var q = {};
  if (!p) return q;
  if (p.urgency != null) q.urgency = Math.max(0, Math.min(7, Math.floor(Number(p.urgency)) || 0));
  if (p.incremental != null) q.incremental = !!p.incremental;
  return q;
}

// The other way: { urgency, incremental } as a Priority Field Value, for a
// `priority` header or a PRIORITY_UPDATE. Defaults are left out (§4.1, §4.2),
// so the defaults are the empty string.
function formatPriority(p) {
  var parts = [];
  var u = p && p.urgency != null ? Math.floor(Number(p.urgency)) : 3;
  if (u >= 0 && u <= 7 && u !== 3) parts.push('u=' + u);
  if (p && p.incremental) parts.push('i');
  return parts.join(', ');
}

// ---- Structured-field strings (RFC 8941 §3.3.3) ----
//
// WebTransport's subprotocol negotiation names its protocols as these:
// WT-Available-Protocols, a list of strings (the client's offer), and
// WT-Protocol, one string (the server's choice). Both sides use these.
function sfString(v) { return '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }

// One string, its parameters ignored; null if the value is not one.
function parseSfString(v) {
  if (typeof v !== 'string') return null;
  var m = /^\s*"((?:[^"\\]|\\.)*)"\s*(?:;.*)?$/.exec(v);
  return m ? m[1].replace(/\\(.)/g, '$1') : null;
}

// A list of strings, in order. Members that are not strings are skipped; a
// list that does not parse is none at all (§4.2: the field is ignored).
function parseSfStringList(v) {
  if (Array.isArray(v)) v = v.join(',');
  if (typeof v !== 'string') return [];
  var out = [], i = 0, n = v.length;
  while (i < n) {
    while (i < n && (v[i] === ' ' || v[i] === '\t')) i++;
    if (i >= n) break;
    var start = i, inStr = false;
    for (; i < n; i++) {
      if (inStr) { if (v[i] === '\\') i++; else if (v[i] === '"') inStr = false; }
      else if (v[i] === '"') inStr = true;
      else if (v[i] === ',') break;
    }
    if (inStr) return [];
    var member = v.slice(start, i).trim();
    if (member === '') return [];            // an empty member: not a list
    var s = parseSfString(member);
    if (s !== null) out.push(s);
    i++;                                     // past the comma
  }
  return out;
}

// ---- How long a request may take to arrive ----
//
// A peer that sends a request slowly — its head a byte at a time, its body a
// byte now and then — holds what the request holds for as long as it is let.
// Every version bounds it with the same two options, node:http's:
//   headersTimeout  until the head (the field section) is complete;
//   requestTimeout  until the whole request, body and all, has arrived —
//                   counted from the end of the head, as h1_server does.
// The response is not timed: a long download or an event stream runs as long
// as the application keeps writing. 0 turns either off.
var DEFAULT_HEADERS_TIMEOUT = 60 * 1000;
var DEFAULT_REQUEST_TIMEOUT = 300000;     // node:http's: 5 min

// ---- 0-RTT: may a request read from early data be handled now? ----
//
// RFC 8470: the application's earlyDataFilter(req, callback(err, allow)), or
// by default GET, HEAD and OPTIONS. decide(true) once allowed; decide(false)
// for anything else — refused, an error, a throw, or no answer within
// EARLY_FILTER_TIMEOUT_MS — and the caller answers 425 Too Early, which a
// client sends again after its handshake. Once only. HTTP/3 (h3_server) and
// HTTP/2 / HTTP/1.1 (server.js) each kept their own copy.
var EARLY_FILTER_TIMEOUT_MS = 100;
function defaultEarlyDataFilter(req, cb) {
  cb(null, req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS');
}
function runEarlyDataFilter(filter, req, decide) {
  var done = false;
  var timer = setTimeout(function () { finish(false); }, EARLY_FILTER_TIMEOUT_MS);
  if (timer.unref) timer.unref();
  function finish(allow) {
    if (done) return;
    done = true;
    clearTimeout(timer);
    decide(allow);
  }
  try { (typeof filter === 'function' ? filter : defaultEarlyDataFilter)(req, function (err, allow) { finish(!err && allow === true); }); }
  catch (e) { finish(false); }
}

// ---- The Date header (RFC 9110 §6.6.1) ----
//
// An origin server with a clock sends it on every response. The string
// changes once a second; it was built — a Date and its formatting — for
// every response.
var dateCache = { second: -1, value: '' };
function httpDate() {
  var now = Date.now(), s = Math.floor(now / 1000);
  if (s !== dateCache.second) { dateCache.second = s; dateCache.value = new Date(now).toUTCString(); }
  return dateCache.value;
}

// A deadline that does not keep the process alive; none for 0 or less.
function startDeadline(ms, fn) {
  if (!(ms > 0)) return null;
  var t = setTimeout(fn, ms);
  if (t.unref) t.unref();
  return t;
}

// node names it per version: ERR_HTTP2_HEADERS_SENT on an HTTP/2 response.
function headersSentError(what, httpVersion) {
  return nodeError(Error, httpVersion === '2.0' ? 'ERR_HTTP2_HEADERS_SENT' : 'ERR_HTTP_HEADERS_SENT',
    'Cannot ' + what + ' headers after they are sent to the client');
}


// node:http's maxRequestsPerSocket: requests one connection may carry
// (0, the default: no limit). Read by every version's server (h1, h2, h3).
function maxRequestsPerSocket(v) {
  if (v === undefined || v === null) return 0;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0)
    throw new TypeError('maxRequestsPerSocket must be a non-negative integer, got ' + v);
  return v;
}

// Rapid Reset (CVE-2023-44487): a client opens a request stream and cancels
// it at once, over and over. No stream stays open, so the concurrency limit
// never applies, and each request still reaches the handler. node:http2
// stops it by default (nghttp2's rate limit on RST_STREAM) and so does every
// version here now: a token bucket of streamResetBurst cancellations (1000),
// refilled at streamResetRate a second (33) — node:http2's option names and
// values. Past it, the connection is closed: HTTP/2 GOAWAY
// ENHANCE_YOUR_CALM, HTTP/3 H3_EXCESSIVE_LOAD. HTTP/2 counts RST_STREAM
// frames, HTTP/3 cancelled request streams (RESET_STREAM or STOP_SENDING,
// once per stream: either cancels a request; a WebTransport session's own
// streams are not counted). Infinity for either turns it off.
// Returns a counter for one connection: true when a cancellation is one too
// many. The 'stream_reset' event stays, for a policy of one's own.
var DEFAULT_STREAM_RESET_BURST = 1000;
var DEFAULT_STREAM_RESET_RATE = 33;
function streamResetOption(name, v, def) {
  if (v === undefined || v === null) return def;
  if (typeof v !== 'number' || !(v > 0))
    throw new TypeError(name + ' must be a positive number (Infinity: no limit), got ' + v);
  return v;
}
function streamResetLimiter(options) {
  var burst = streamResetOption('streamResetBurst', options && options.streamResetBurst, DEFAULT_STREAM_RESET_BURST);
  var rate = streamResetOption('streamResetRate', options && options.streamResetRate, DEFAULT_STREAM_RESET_RATE);
  if (burst === Infinity || rate === Infinity) return function () { return false; };
  var tokens = burst, at = Date.now();
  return function () {
    var now = Date.now();
    tokens = Math.min(burst, tokens + (now - at) / 1000 * rate);
    at = now;
    if (tokens < 1) return true;
    tokens -= 1;
    return false;
  };
}

// node:http2's errors for the session API, with its codes and messages.
function argType(name, type, value) {
  var e = new TypeError('The "' + name + '" argument must be of type ' + type + '. Received ' + (value === null ? 'null' : typeof value));
  e.code = 'ERR_INVALID_ARG_TYPE';
  return e;
}
function sessionGone() {
  var e = new Error('The session has been destroyed');
  e.code = 'ERR_HTTP2_INVALID_SESSION';
  return e;
}
// A client stream that never got its id, its session gone (node:http2's
// ERR_HTTP2_STREAM_CANCEL for the pending streams), with the cause if any.
function pendingCancel(cause) {
  var e = nodeError(Error, 'ERR_HTTP2_STREAM_CANCEL', 'The pending stream has been canceled' + (cause ? ' (caused by: ' + cause.message + ')' : ''));
  if (cause) e.cause = cause;
  return e;
}
function sessionCodeError(code) {
  var e = new Error('Session closed with error code ' + code);
  e.code = 'ERR_HTTP2_SESSION_ERROR';
  return e;
}

// The fields a node:http2 stream may carry only once (node's
// kSingleValueHeaders): the pseudo-headers and the fields RFC 9110 defines
// as a single value. A list for one of them, or the name twice, throws.
var HTTP2_SINGLE_VALUE = new Set([
  ':status', ':method', ':authority', ':scheme', ':path', ':protocol',
  'access-control-allow-credentials', 'access-control-max-age', 'access-control-request-method',
  'age', 'authorization', 'content-encoding', 'content-language', 'content-length',
  'content-location', 'content-md5', 'content-range', 'content-type', 'date', 'dnt', 'etag',
  'expires', 'from', 'host', 'if-match', 'if-modified-since', 'if-none-match', 'if-range',
  'if-unmodified-since', 'last-modified', 'location', 'max-forwards', 'proxy-authorization',
  'range', 'referer', 'retry-after', 'tk', 'upgrade-insecure-requests', 'user-agent',
  'x-content-type-options'
]);

/**
 * A header block as node:http2's stream API takes it — an object, or the flat
 * [name, value, name, value, …] array — as the [[name, value], …] list
 * H2Connection sends, pseudo-headers first. The checks are nghttp2's
 * (node's buildNgHeaderString), with node's codes: a pseudo-header
 * `pseudoOk` does not allow, a name that is not a token, a connection-
 * specific field (TE only as "trailers"), a single-value field given twice.
 * A list value is one field line per value; an undefined one is left out.
 */
function http2FieldList(headers, pseudoOk) {
  var pseudo = [], fields = [], singles = new Set();
  function one(key, value) {
    key = String(key).toLowerCase();
    var single = HTTP2_SINGLE_VALUE.has(key);
    var many = Array.isArray(value);
    if (many) {
      if (value.length === 0) return;
      if (value.length === 1) { value = String(value[0]); many = false; }
      else if (single) throw http2SingleValue(key);
    } else {
      value = String(value);
    }
    if (single) {
      if (singles.has(key)) throw http2SingleValue(key);
      singles.add(key);
    }
    if (key.charCodeAt(0) === 0x3a) {
      if (!pseudoOk(key)) throw nodeError(TypeError, 'ERR_HTTP2_INVALID_PSEUDOHEADER', '"' + key + '" is an invalid pseudoheader or is used incorrectly');
      pseudo.push([key, value]);
      return;
    }
    if (!isToken(key)) throw nodeError(TypeError, 'ERR_INVALID_HTTP_TOKEN', 'Header name must be a valid HTTP token ["' + key + '"]');
    if (key === 'http2-settings' || (key === 'te' ? value !== 'trailers' : isConnectionSpecific(key))) {
      throw nodeError(TypeError, 'ERR_HTTP2_INVALID_CONNECTION_HEADERS', 'HTTP/1 Connection specific headers are forbidden: "' + key + '"');
    }
    if (many) for (var j = 0; j < value.length; j++) fields.push([key, String(value[j])]);
    else fields.push([key, value]);
  }
  if (Array.isArray(headers)) {
    for (var i = 0; i < headers.length; i += 2) {
      if (headers[i + 1] === undefined || headers[i] === '') continue;
      one(headers[i], headers[i + 1]);
    }
  } else {
    for (var name of Object.keys(headers)) {
      if (headers[name] === undefined || name === '') continue;
      one(name, headers[name]);
    }
  }
  return pseudo.concat(fields);
}
/**
 * A received header block as node:http2 hands it to the application (node's
 * toHeaderObject), from its field lines in order (a flat [name, value, …]):
 * a null-prototype object, :status a number, set-cookie always a list, a
 * repeated cookie joined with "; ", any other repeated field with ", " — and
 * a single-value field that came twice keeps its first value.
 */
function http2HeaderObject(raw) {
  var obj = Object.create(null);
  for (var n = 0; n < raw.length; n += 2) {
    var name = raw[n], value = raw[n + 1];
    if (name === ':status') value |= 0;
    var existing = obj[name];
    if (existing === undefined) obj[name] = name === 'set-cookie' ? [value] : value;
    else if (!HTTP2_SINGLE_VALUE.has(name)) {
      if (name === 'cookie') obj[name] = existing + '; ' + value;
      else if (name === 'set-cookie') existing.push(value);
      else obj[name] = existing + ', ' + value;
    }
  }
  return obj;
}
// A stream's state as node:http2's stream.state has it, for a stream with
// no HTTP/2 state machine (HTTP/3's): nghttp2's state number — OPEN 2,
// HALF_CLOSED_LOCAL 5, HALF_CLOSED_REMOTE 6, CLOSED 7 — from which sides
// have ended. (Its weight and window are HTTP/2's: RFC 9218 replaces the
// one, QUIC's flow control the other.)
function streamStateOf(localClose, remoteClose) {
  return {
    state: localClose && remoteClose ? 7 : localClose ? 5 : remoteClose ? 6 : 2,
    localClose: localClose ? 1 : 0,
    remoteClose: remoteClose ? 1 : 0
  };
}

// A client's request head, as node:http2's ClientHttp2Session.request()
// builds it: [name, value] pairs, :method (GET), :scheme and :path ('/')
// unless CONNECT, :authority (the session's), then the fields — lower-cased,
// a list one line per value, :protocol let through (extended CONNECT), other
// pseudo-headers and the connection-specific fields thrown on with node's
// codes. HTTP/2's and HTTP/3's alike (h2_client, h3_client).
function http2RequestFields(headers, scheme, authority) {
  var list = [];
  var method = headers[':method'] !== undefined ? String(headers[':method']).toUpperCase() : 'GET';
  var isConnect = method === 'CONNECT';
  if (headers[':authority'] !== undefined) authority = String(headers[':authority']);
  list.push([':method', method]);
  if (!isConnect) list.push([':scheme', headers[':scheme'] !== undefined ? String(headers[':scheme']) : scheme]);
  list.push([':authority', authority]);
  if (!isConnect) list.push([':path', headers[':path'] !== undefined ? String(headers[':path']) : '/']);
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    var lower = String(name).toLowerCase();
    if (lower.charCodeAt(0) === 0x3a) {
      if (lower === ':method' || lower === ':scheme' || lower === ':authority' || lower === ':path') continue;
      if (lower === ':protocol') { list.push([lower, String(headers[name])]); continue; }
      throw nodeError(TypeError, 'ERR_HTTP2_INVALID_PSEUDOHEADER', '"' + lower + '" is an invalid pseudoheader or is used incorrectly');
    }
    var value = headers[name];
    if (value === undefined || value === null) continue;
    if (isConnectionSpecific(lower) && !(lower === 'te' && String(value).toLowerCase() === 'trailers')) {
      throw nodeError(TypeError, 'ERR_HTTP2_INVALID_CONNECTION_HEADERS', 'HTTP/1 Connection specific headers are forbidden: "' + lower + '"');
    }
    if (Array.isArray(value)) for (var j = 0; j < value.length; j++) list.push([lower, String(value[j])]);
    else list.push([lower, String(value)]);
  }
  return { list: list, method: method };
}

function http2SingleValue(key) {
  return nodeError(TypeError, 'ERR_HTTP2_HEADER_SINGLE_VALUE', 'Header field "' + key + '" must only have a single value');
}



// node:http2's validateInt32 / getTimerDuration checks, with its codes.
function checkInt(value, name, min, max) {
  if (typeof value !== 'number') throw argType(name, 'number', value);
  if (!Number.isInteger(value)) {
    throw nodeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "' + name + '" is out of range. It must be an integer. Received ' + value);
  }
  if (value < min || value > max) {
    throw nodeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "' + name + '" is out of range. It must be >= ' + min + ' && <= ' + max + '. Received ' + value);
  }
}


// ============================================================
//  node:http2's Http2Stream — what a server's stream and a client's share
//
//  The state and the operations node gives both: close(code) and rstCode,
//  'aborted', setTimeout() and 'timeout', trailers (waitForTrailers,
//  'wantTrailers', sendTrailers()), state, and how a stream ends — node's
//  closeStream, onStreamClose and _destroy, whose rules are the API (which
//  code is sent, when 'aborted' and 'error' come). What differs is how each
//  reaches the wire, given by the subclass:
//
//    _sendRst(code)          RST_STREAM (the stream is still open)
//    _sendTrailers(list)     trailers; an empty list is END_STREAM alone
//    _streamState()          H2Connection.getStreamInfo, or null
//    _endReads()             a clean close: end the readable side
//    _sessionCode()          the session's GOAWAY or destroy code, or 0
//    _release()              the stream is destroyed: let go of it
//
// `codes`: the version's stream codes — none, cancel, internal, the largest
// code (max), wire(code) (a code given to close() as it goes on the wire)
// and name(code) (for the error's message): H2_STREAM_CODES (h2.js),
// H3_STREAM_CODES (h3_server.js).
// ============================================================

var RST_NONE = 0, RST_SUBMIT = 1, RST_FORCE = 2;

function streamCodeError(code, codes) {
  return nodeError(Error, 'ERR_HTTP2_STREAM_ERROR', 'Stream closed with error code ' + codes.name(code));
}

class StreamBase extends Duplex {
  constructor(session, codes) {
    super({ allowHalfOpen: true, decodeStrings: false, autoDestroy: false });
    this._session = session;
    this._codes = codes;
    this._streamClosed = false;
    this._aborted = false;
    this._timer = null;
    this._waitTrailers = false;    // waitForTrailers: 'wantTrailers' at the end of the body
    this._trailersReady = false;
    this._sentTrailers = undefined;
    this.rstCode = undefined;
    this.timeout = 0;
  }

  get session() { return this._session; }
  get closed() { return this._streamClosed; }
  get aborted() { return this._aborted; }
  get sentTrailers() { return this._sentTrailers; }
  get state() {
    if (this.destroyed || this.id === undefined) return {};
    return this._streamState() || {};
  }

  /**
   * node's close(code = NO_ERROR, callback): RST_STREAM with the code —
   * once a response that has ended has gone, for NO_ERROR. 'aborted' if the
   * writable side was still open; the callback at 'close'.
   */
  close(code, callback) {
    if (code === undefined) code = this._codes.none;
    checkInt(code, 'code', 0, this._codes.max);
    code = this._codes.wire(code);
    if (callback !== undefined && typeof callback !== 'function') throw argType('callback', 'function', callback);
    if (this._streamClosed) return;
    if (callback !== undefined) this.once('close', callback);
    this._closeStream(code, RST_SUBMIT);
  }

  // node's closeStream.
  _closeStream(code, rst) {
    this._streamClosed = true;
    this.rstCode = code;
    this.setTimeout(0);
    this.removeAllListeners('timeout');
    var ending = this._writableState.ending;
    if (!ending) {
      if (!this._aborted) { this._aborted = true; this.emit('aborted'); }
      this.end();
    }
    if (rst === RST_NONE) return;
    var self = this;
    // Then it ends as a stream the peer closed would (the transport's own
    // notice of the close, if it has one, says the same).
    var reset = function () { self._sendRst(code); process.nextTick(function () { self._gone(code); }); };
    if (!ending || this.writableFinished || code !== this._codes.none || rst === RST_FORCE) reset();
    else this.once('finish', reset);
  }

  /**
   * The HTTP/2 stream closed, with this code (node's onStreamClose): a reset,
   * or the session gone (`now`), destroys it at once; a clean close ends its
   * reads, and it is destroyed at their end.
   */
  _gone(code, now) {
    if (this._goneDone) return;
    this._goneDone = true;
    if (!this._streamClosed) this._closeStream(code, RST_NONE);
    if (this.destroyed) return;
    if (now || code !== this._codes.none || !this.readable || this.readableEnded) { this.destroy(); return; }
    var self = this;
    this.once('end', function () { self.destroy(); });
    this._endReads();
    if (this.readableFlowing === null) this.resume();
    else this.read(0);
  }

  // node's _destroy: the code is the close's, or the session's; with an
  // error, INTERNAL_ERROR (CANCEL for an AbortError). An open stream is
  // reset with it. A code other than NO_ERROR and CANCEL is an error.
  _destroy(err, callback) {
    var sessionCode = this._sessionCode();
    var c = this._codes;
    // A session code of 0, or NO_ERROR: the session ended cleanly (or did
    // not end) — the stream's own codes decide.
    if (sessionCode === c.none) sessionCode = 0;
    var code = this._streamClosed ? this.rstCode : (sessionCode || c.none);
    if (err != null) code = sessionCode || (err.name === 'AbortError' ? c.cancel : c.internal);
    if (!this._streamClosed) this._closeStream(code, RST_FORCE);
    // The reads end too ('end' before 'close' when nothing went wrong).
    if (!this._readableState.ended) this.push(null);
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    this._release();
    if (err == null && code !== c.none && code !== c.cancel) err = streamCodeError(code, c);
    this._session = undefined;
    callback(err);
  }

  // node's setTimeout(msecs[, callback]): 'timeout' after msecs with nothing
  // sent or received on the stream.
  setTimeout(msecs, callback) {
    if (this.destroyed) return this;
    this.timeout = msecs;
    if (typeof msecs !== 'number') throw argType('msecs', 'number', msecs);
    if (msecs < 0 || !Number.isFinite(msecs)) {
      throw nodeError(RangeError, 'ERR_OUT_OF_RANGE', 'The value of "msecs" is out of range. It must be a non-negative finite number. Received ' + msecs);
    }
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    if (msecs === 0) {
      if (callback !== undefined) {
        if (typeof callback !== 'function') throw argType('callback', 'function', callback);
        this.removeListener('timeout', callback);
      }
      return this;
    }
    var self = this;
    this._timer = setTimeout(function () { if (!self.destroyed) self.emit('timeout'); }, msecs);
    if (this._timer.unref) this._timer.unref();
    if (callback !== undefined) {
      if (typeof callback !== 'function') throw argType('callback', 'function', callback);
      this.once('timeout', callback);
    }
    return this;
  }

  // Activity on the stream: the timeout starts over.
  _touch() { if (this._timer) this._timer.refresh(); }

  /**
   * The body has been written and waitForTrailers was asked for:
   * 'wantTrailers', for sendTrailers(); nobody listening, the stream ends
   * with no trailers.
   */
  _wantTrailers() {
    this._trailersReady = true;
    if (this.destroyed || this._streamClosed) return;
    if (!this.emit('wantTrailers')) this.sendTrailers({});
  }

  sendTrailers(headers) {
    if (this.destroyed || this._streamClosed) throw nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed');
    if (this._sentTrailers) throw nodeError(Error, 'ERR_HTTP2_TRAILERS_ALREADY_SENT', 'Trailing headers have already been sent');
    if (!this._trailersReady) throw nodeError(Error, 'ERR_HTTP2_TRAILERS_NOT_READY', 'Trailing headers cannot be sent until after the wantTrailers event is emitted');
    if (headers !== undefined && (headers === null || typeof headers !== 'object' || Array.isArray(headers))) throw argType('headers', 'object', headers);
    headers = Object.assign(Object.create(null), headers);
    var list = http2FieldList(headers, function () { return false; });
    this._touch();
    this._sentTrailers = headers;
    var self = this;
    // As node's, on the next turn (not from inside 'wantTrailers').
    setImmediate(function () { if (!self.destroyed) self._sendTrailers(list); });
  }

  // node's priority(): RFC 7540's priority signals are gone (RFC 9113 §5.3),
  // and node's is a deprecated no-op too.
  priority() {
    if (this.destroyed) throw nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed');
  }

  _endReads() { this.push(null); }
  _sessionCode() { return this._codes.none; }
  _release() {}
}


// ============================================================
//  ServerStream — node:http2's ServerHttp2Stream, for HTTP/2 and HTTP/3
//
//  The core API's view of one request's stream: a Duplex whose reads are the
//  request body and whose writes are the response body, answered with
//  respond(). It holds no state of the exchange itself: the head, the body
//  and the end go through the same functions as the ServerResponse of the
//  same request (`hooks`: h2_server's wireResponse, server.js's HTTP/3
//  wrapping), so the two APIs can be mixed —
//  respond() here and res.end() there — and agree on what was sent.
// ============================================================

// node's prepareResponseHeadersObject: a copy of the headers, :status a
// number (200 when there is none), a Date unless sendDate is false.
function prepareHeadObject(headers, options) {
  if (headers !== undefined && (headers === null || typeof headers !== 'object' || Array.isArray(headers))) throw argType('headers', 'object', headers);
  var prepared = Object.create(null);
  for (var k in headers) if (Object.prototype.hasOwnProperty.call(headers, k)) prepared[k] = headers[k];
  prepared[':status'] = (prepared[':status'] | 0) || 200;
  if ((options.sendDate == null || options.sendDate) && prepared.date == null) prepared.date = httpDate();
  return prepared;
}

// respondWithFile's and respondWithFD's options, checked as node's.
function fileOptions(options) {
  if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options))) throw argType('options', 'object', options);
  options = Object.assign({}, options);
  var bad = function (name) {
    return nodeError(TypeError, 'ERR_INVALID_ARG_VALUE', "The property 'options." + name + "' is invalid. Received " + String(options[name]));
  };
  if (options.offset !== undefined && typeof options.offset !== 'number') throw bad('offset');
  if (options.length !== undefined && typeof options.length !== 'number') throw bad('length');
  if (options.statCheck !== undefined && typeof options.statCheck !== 'function') throw bad('statCheck');
  return options;
}

class ServerStream extends StreamBase {
  constructor(session, id, hooks, codes) {
    super(session, codes);
    this._id = id;
    this._hooks = hooks;
    this._sent = undefined;       // sentHeaders, as respond() was given them (an object) …
    this._sentRaw = undefined;    // … or as a flat array, made an object when asked for
    this._info = undefined;       // sentInfoHeaders
    this._endWaiting = false;     // end() before respond(): the head ends the stream
  }

  get id() { return this._id; }
  // node's: no id yet. A stream the server is given always has one.
  get pending() { return false; }
  get headersSent() { return this._hooks.headersSent(); }
  get endAfterHeaders() { return this._hooks.endAfterHeaders; }
  get headRequest() { return this._hooks.isHead; }
  get sentInfoHeaders() { return this._info; }

  get sentHeaders() {
    if (this._sent || !this._sentRaw) return this._sent;
    var raw = this._sentRaw, o = Object.create(null);
    for (var i = 0; i < raw.length; i += 2) {
      var e = o[raw[i]];
      if (e === undefined) o[raw[i]] = raw[i + 1];
      else if (Array.isArray(e)) e.push(raw[i + 1]);
      else o[raw[i]] = [e, raw[i + 1]];
    }
    return (this._sent = o);
  }

  /**
   * node:http2's respond(headers, { endStream, waitForTrailers, sendDate }):
   * the response's head — :status (200 when there is none), a Date unless
   * sendDate is false. It ends the stream when asked to, and for a response
   * that has no body (204, 205, 304, an answer to HEAD) or whose end()
   * already came; with waitForTrailers, the end is the trailers', after
   * 'wantTrailers'. The checks and codes are node's; a call that throws has
   * sent nothing.
   */
  respond(headers, options) {
    if (this.destroyed || this.closed) throw nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed');
    if (this.headersSent) throw nodeError(Error, 'ERR_HTTP2_HEADERS_SENT', 'Response has already been initiated.');
    if (options !== undefined && (options === null || typeof options !== 'object' || Array.isArray(options))) throw argType('options', 'object', options);
    options = Object.assign({}, options);
    this._touch();
    var sendDate = options.sendDate == null || !!options.sendDate;
    var status, prepared;
    if (Array.isArray(headers)) {
      prepared = headers.slice();
      var dated = false;
      for (var i = 0; i < prepared.length; i += 2) {
        var n = String(prepared[i]).toLowerCase();
        if (n === ':status') status = prepared[i + 1] | 0;
        else if (n === 'date') dated = true;
      }
      if (!status) { status = 200; prepared.unshift(':status', status); }
      if (!dated && sendDate) prepared.push('date', httpDate());
    } else {
      prepared = prepareHeadObject(headers, options);
      status = prepared[':status'];
    }
    if (status < 200 || status > 599) throw nodeError(RangeError, 'ERR_HTTP2_STATUS_INVALID', 'Invalid status code: ' + status);
    var list = http2FieldList(prepared, function (name) { return name === ':status'; });

    var end = !!options.endStream || status === 204 || status === 205 || status === 304 ||
              this._hooks.isHead || this._endWaiting;
    if (options.waitForTrailers) this._waitTrailers = true;
    if (Array.isArray(headers)) this._sentRaw = prepared; else this._sent = prepared;
    try { this._hooks.respond(list, status, end && !this._waitTrailers); }
    catch (e) { this.destroy(e); return; }
    // The writable side closes with a head that ended the stream.
    if (end && !this.writableEnded) this.end();
    // end() came first: the body is over, the trailers are wanted now.
    else if (this._endWaiting && this._waitTrailers) this._wantTrailers();
  }

  /**
   * node:http2's additionalHeaders(headers): a 1xx head (103 Early Hints,
   * say) before the response, the stream left open.
   */
  additionalHeaders(headers) {
    if (this.destroyed || this.closed) throw nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed');
    if (this.headersSent) throw nodeError(Error, 'ERR_HTTP2_HEADERS_AFTER_RESPOND', 'Cannot specify additional headers after response initiated');
    if (headers !== undefined && (headers === null || typeof headers !== 'object' || Array.isArray(headers))) throw argType('headers', 'object', headers);
    headers = Object.assign(Object.create(null), headers);
    if (headers[':status'] != null) {
      var code = headers[':status'] |= 0;
      if (code === 101) throw nodeError(Error, 'ERR_HTTP2_STATUS_101', 'HTTP status code 101 (Switching Protocols) is forbidden in HTTP/2');
      if (code < 100 || code >= 200) throw nodeError(RangeError, 'ERR_HTTP2_INVALID_INFO_STATUS', 'Invalid informational status code: ' + code);
    }
    this._touch();
    var list = http2FieldList(headers, function (name) { return name === ':status'; });
    (this._info || (this._info = [])).push(headers);
    try { this._hooks.info(list); } catch (e) { this.destroy(e); }
  }

  /**
   * node:http2's respondWithFile(path[, headers[, options]]): the response
   * is a file — opened, checked (a regular file; a directory is
   * ERR_HTTP2_SEND_FILE), statCheck(stat, headers) given its say, then its
   * bytes from `offset` for `length` (the rest of it, by default) with a
   * content-length. A failure goes to options.onError when there is one;
   * otherwise it destroys the stream. The file is closed at the end.
   */
  respondWithFile(path, headers, options) {
    if (this.destroyed || this.closed) throw nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed');
    if (this.headersSent) throw nodeError(Error, 'ERR_HTTP2_HEADERS_SENT', 'Response has already been initiated.');
    options = fileOptions(options);
    this._touch();
    var prepared = this._fileHead(headers, options);
    // Armed once nothing can throw (a throw leaves the stream as it was).
    if (options.waitForTrailers) this._waitTrailers = true;
    var self = this, onError = options.onError;
    var fail = function (err, fd) {
      if (fd !== undefined) fs.close(fd, function () {});
      if (onError) onError(err); else self.destroy(err);
    };
    fs.open(path, 'r', function (err, fd) {
      if (err) { fail(err); return; }
      if (self.destroyed || self.closed) { fs.close(fd, function () {}); return; }
      fs.fstat(fd, function (err2, stat) {
        if (err2) { fail(err2, fd); return; }
        if (!stat.isFile()) {
          var dir = stat.isDirectory();
          if (options.offset !== undefined || options.length !== undefined || dir) {
            fail(dir ? nodeError(Error, 'ERR_HTTP2_SEND_FILE', 'Directories cannot be sent')
                     : nodeError(Error, 'ERR_HTTP2_SEND_FILE_NOSEEK', 'Offset or length can only be specified for regular files'), fd);
            return;
          }
          options.offset = -1;   // a pipe, a device: read as it comes
          options.length = -1;
        }
        if (self.destroyed || self.closed) {
          fs.close(fd, function () {});
          self.destroy(nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed'));
          return;
        }
        var offset = options.offset !== undefined ? options.offset : 0;
        var length = options.length !== undefined ? options.length : -1;
        // statCheck may change the headers, answer otherwise, or cancel (false).
        if ((typeof options.statCheck === 'function' && options.statCheck.call(self, stat, prepared) === false) || self.headersSent) {
          fs.close(fd, function () {});
          return;
        }
        if (stat.isFile()) {
          length = length < 0 ? stat.size - offset : Math.min(stat.size - offset, length);
          prepared['content-length'] = length;
        }
        self._sendFile(fd, prepared, offset | 0, length | 0, true);
      });
    });
  }

  /**
   * node:http2's respondWithFD(fd[, headers[, options]]): the response is
   * what is read from an open file descriptor (or FileHandle), from `offset`
   * for `length`. It is not closed here — it is the caller's. With a
   * statCheck, it is fstat()ed first, and statCheck(stat, headers,
   * { offset, length }) may change them or cancel (false).
   */
  respondWithFD(fd, headers, options) {
    if (this.destroyed || this.closed) throw nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed');
    if (this.headersSent) throw nodeError(Error, 'ERR_HTTP2_HEADERS_SENT', 'Response has already been initiated.');
    options = fileOptions(options);
    if (fd !== null && typeof fd === 'object' && typeof fd.fd === 'number' && typeof fd.close === 'function') fd = fd.fd;   // a FileHandle
    else if (typeof fd !== 'number') {
      throw nodeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "fd" argument must be of type number or an instance of FileHandle. Received ' + typeof fd);
    }
    this._touch();
    var prepared = this._fileHead(headers, options);
    // Armed once nothing can throw (a throw leaves the stream as it was).
    if (options.waitForTrailers) this._waitTrailers = true;
    var self = this;
    if (options.statCheck === undefined) {
      this._sendFile(fd, prepared, options.offset !== undefined ? options.offset : 0, options.length !== undefined ? options.length : -1, false);
      return;
    }
    fs.fstat(fd, function (err, stat) {
      if (err) { self.destroy(err); return; }
      if (self.destroyed || self.closed) { self.destroy(nodeError(Error, 'ERR_HTTP2_INVALID_STREAM', 'The stream has been destroyed')); return; }
      var so = { offset: options.offset !== undefined ? options.offset : 0, length: options.length !== undefined ? options.length : -1 };
      if (options.statCheck.call(self, stat, prepared, so) === false || self.headersSent) return;
      self._sendFile(fd, prepared, so.offset | 0, so.length | 0, false);
    });
  }

  // The head of a file response, as respond()'s; a status that has no body
  // (or an answer to HEAD) cannot carry one.
  _fileHead(headers, options) {
    var prepared = prepareHeadObject(headers, options);
    var status = prepared[':status'];
    if (status === 204 || status === 205 || status === 304 || this._hooks.isHead) {
      throw nodeError(Error, 'ERR_HTTP2_PAYLOAD_FORBIDDEN', 'Responses with ' + status + ' status must not have a payload');
    }
    return prepared;
  }

  /**
   * The head, then the file's bytes: read a chunk at a time, each read only
   * once the one before has been taken (the send window and the socket hold
   * them back), from `offset` (-1: from where the descriptor is) for
   * `length` bytes (-1: to its end). The writable side is closed: the body
   * is the file's. A read that fails resets the stream, INTERNAL_ERROR.
   */
  _sendFile(fd, prepared, offset, length, owns) {
    var list;
    try { list = http2FieldList(prepared, function (name) { return name === ':status'; }); }
    catch (err) { if (owns) fs.close(fd, function () {}); this.destroy(err); return; }
    this._sent = prepared;
    this._fileBody = true;
    this.end();
    var status = prepared[':status'];
    try { this._hooks.respond(list, status, false); }
    catch (err) { if (owns) fs.close(fd, function () {}); this.destroy(err); return; }
    var self = this;
    var position = offset < 0 ? null : offset;
    var remaining = length < 0 ? Infinity : length;
    var done = function () { if (owns) fs.close(fd, function () {}); };
    (function next() {
      if (self.destroyed || self.closed) { done(); return; }
      var n = Math.min(65536, remaining);
      if (n <= 0) { done(); self._fileEnd(); return; }
      fs.read(fd, Buffer.allocUnsafe(n), 0, n, position, function (err, bytes, buf) {
        if (self.destroyed || self.closed) { done(); return; }
        if (err) { done(); self.close(self._codes.internal); return; }
        if (bytes === 0) { done(); self._fileEnd(); return; }
        if (position !== null) position += bytes;
        remaining -= bytes;
        self._touch();
        self._hooks.body(bytes === buf.length ? buf : buf.subarray(0, bytes), null, next);
      });
    })();
  }

  _fileEnd() {
    if (this._waitTrailers) this._wantTrailers();
    else this._hooks.end();
  }

  // node's: whether the client takes pushed streams. quico does not push
  // (RFC 9113 §8.4 makes it optional, and browsers have dropped it).
  get pushAllowed() { return false; }

  pushStream() {
    throw nodeError(Error, 'ERR_HTTP2_PUSH_DISABLED', 'HTTP/2 client has disabled push streams');
  }

  _read() { this._hooks.read(); }

  // A write before respond() sends the default head first, as node's does.
  _write(chunk, encoding, callback) {
    if (this.closed) { callback(); return; }
    if (!this.headersSent) {
      try { this.respond(); } catch (e) { callback(e); return; }
    }
    this._touch();
    this._hooks.body(chunk, encoding, callback);
  }

  // end() before respond() sends nothing: the head, when it comes, ends the
  // stream (node's order — a stream may be ended and answered later).
  _final(callback) {
    if (this.closed || this._fileBody) { callback(); return; }
    if (!this.headersSent) this._endWaiting = true;
    else if (this._waitTrailers) this._wantTrailers();
    else this._hooks.end();
    callback();
  }

  _sendRst(code) { this._hooks.reset(code); }
  _sendTrailers(list) { this._hooks.trailers(list); }
  _streamState() { return this._hooks.state(); }
  _endReads() { this._hooks.endReads(); }
}


export {
  argType, sessionGone, sessionCodeError, pendingCancel,
  streamResetLimiter,
  runEarlyDataFilter,
  httpDate,
  maxRequestsPerSocket,
  validateFieldSection,
  isValidAuthority,
  urlHostname,
  formatAuthority,
  validateHeaderName,
  validateHeaderValue,
  validateStatus,
  validateRequestTarget,
  headersSentError,
  runRequestHandler,
  corkForTick,
  DEFAULT_HEADERS_TIMEOUT,
  DEFAULT_REQUEST_TIMEOUT,
  startDeadline,
  parsePriority,
  formatPriority,
  sfString,
  parseSfString,
  parseSfStringList,
  responsePriority,
  sha12,
  Emitter,
  isToken,
  isValidFieldValue,
  isTrimmedFieldValue,
  IS_TCHAR,
  addHeader,
  parseContentLength,
  statusHasNoBody,
  responseHasBody,
  STATUS_TEXT,
  CONNECTION_SPECIFIC,
  isConnectionSpecific,
  http2FieldList,
  checkInt,
  http2RequestFields,
  streamStateOf,
  StreamBase,
  ServerStream,
  http2HeaderObject,
  nodeError,
  trailerFields,
  TRAILER_FORBIDDEN,
  REQUEST_PSEUDO,
  RESPONSE_PSEUDO,
  isPseudoHeader,
  buildRequestPseudoHeaders,
  pseudoHeadersToRequest,
  buildResponsePseudoHeaders
};
