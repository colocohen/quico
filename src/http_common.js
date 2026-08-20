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

function Emitter() {
  var listeners = {};
  return {
    on: function (name, fn) { (listeners[name] = listeners[name] || []).push(fn); return this; },
    once: function (name, fn) {
      var self = this;
      function wrapper() { self.off(name, wrapper); fn.apply(null, arguments); }
      wrapper.__original = fn;
      return this.on(name, wrapper);
    },
    off: function (name, fn) {
      var a = listeners[name];
      if (!a) return this;
      for (var i = 0; i < a.length; i++) {
        if (a[i] === fn || a[i].__original === fn) { a.splice(i, 1); break; }
      }
      return this;
    },
    emit: function (name) {
      var args = Array.prototype.slice.call(arguments, 1);
      // Copied before iterating: a listener may add or remove listeners, and
      // mutating the array mid-loop silently skips one.
      var a = (listeners[name] || []).slice();
      for (var i = 0; i < a.length; i++) a[i].apply(null, args);
      return a.length > 0;
    },
    listenerCount: function (name) { return (listeners[name] || []).length; },
    removeAllListeners: function (name) {
      if (name === undefined) listeners = {};
      else delete listeners[name];
      return this;
    }
  };
}


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
function addHeader(headers, name, value) {
  if (!(name in headers)) {
    headers[name] = name === 'set-cookie' ? [value] : value;
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
    var p = parts[i].trim();
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
  300: 'Multiple Choices', 301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
  304: 'Not Modified', 305: 'Use Proxy', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 402: 'Payment Required', 403: 'Forbidden',
  404: 'Not Found', 405: 'Method Not Allowed', 406: 'Not Acceptable',
  407: 'Proxy Authentication Required', 408: 'Request Timeout', 409: 'Conflict',
  410: 'Gone', 411: 'Length Required', 412: 'Precondition Failed',
  413: 'Content Too Large', 414: 'URI Too Long', 415: 'Unsupported Media Type',
  416: 'Range Not Satisfiable', 417: 'Expectation Failed', 418: "I'm a Teapot",
  421: 'Misdirected Request', 422: 'Unprocessable Content', 425: 'Too Early',
  426: 'Upgrade Required', 428: 'Precondition Required', 429: 'Too Many Requests',
  431: 'Request Header Fields Too Large', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway',
  503: 'Service Unavailable', 504: 'Gateway Timeout', 505: 'HTTP Version Not Supported',
  507: 'Insufficient Storage', 508: 'Loop Detected', 511: 'Network Authentication Required'
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

var REQUEST_PSEUDO = { ':method': 1, ':scheme': 1, ':authority': 1, ':path': 1 };
var RESPONSE_PSEUDO = { ':status': 1 };

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
 * default port is omitted from the authority, as every client does: including
 * it changes the origin for virtual-host routing and for CORS.
 */
function buildRequestPseudoHeaders(options) {
  var method = String(options.method || 'GET').toUpperCase();
  var scheme = options.scheme || 'https';
  var port = options.port;
  var defaultPort = scheme === 'http' ? 80 : 443;
  var authority = options.authority ||
    (options.hostname + (port && port !== defaultPort ? ':' + port : ''));

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
 * IncomingMessage wants: a method, a url, and headers without pseudo-headers.
 */
function pseudoHeadersToRequest(headers) {
  var out = { method: headers[':method'], url: headers[':path'], headers: {} };
  for (var name in headers) {
    if (isPseudoHeader(name)) continue;
    out.headers[name] = headers[name];
  }
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


export {
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
  REQUEST_PSEUDO,
  RESPONSE_PSEUDO,
  isPseudoHeader,
  buildRequestPseudoHeaders,
  pseudoHeadersToRequest,
  buildResponsePseudoHeaders
};
