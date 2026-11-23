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
//  HTTP/1.1 message parsing and serialization (RFC 9110 / RFC 9112).
//
//  No I/O and no sockets: feed bytes in with execute(), get events out. The
//  same shape as h3.js — which is handed already-ordered stream bytes by QUIC
//  and turns them into http_headers / http_body / http_end — so h1_client and
//  h1_server can stay as thin as h3_client and h3_server.
//
//  What makes HTTP/1.1 harder than it looks is not the grammar, which is
//  trivial, but that the grammar is ambiguous unless you refuse the ambiguous
//  cases. Where a message can be read two ways, an intermediary may read it
//  one way and the origin the other, and the difference is a smuggled request
//  (RFC 9112 §11.2). Every rejection below exists for that reason, and every
//  one of them is a deliberate refusal to guess. A parser that is "lenient"
//  here is not being kind to anyone.
// ============================================================


import {
  Emitter, isToken, isValidFieldValue, isValidAuthority, addHeader, parseContentLength,
  responseHasBody, STATUS_TEXT, TRAILER_FORBIDDEN
} from './http_common.js';


// Head = request/status line plus all field lines. Bounded because it arrives
// before we know anything about the sender: an unbounded head is a trivial
// memory exhaustion, and the peer can hold the connection open while sending
// it one byte at a time.
//
// The defaults are node:http's: 16 KB for the whole head (its maxHeaderSize),
// 2000 field lines (its maxHeadersCount — which drops the extra lines; here
// they are refused, as a dropped header is a header two hops disagree about).
// The head was allowed 80 KB and only 128 lines: a 20 KB request line that
// node answers with 431 was served, and a request with 200 headers that node
// serves was refused.
var MAX_HEAD_SIZE = 16 * 1024;
var MAX_HEADER_COUNT = 2000;

// A chunk size is a hex number. 16 digits already exceeds any real body and
// Number.MAX_SAFE_INTEGER; more than that is an attack or a bug.
var MAX_CHUNK_SIZE_DIGITS = 16;
// A chunk's size line, extensions and all: node:http's bound on extensions
// (16 KB, HPE_CHUNK_EXTENSIONS_OVERFLOW — answered 413).
var MAX_CHUNK_LINE = 16 * 1024;
var HTTP_SLASH = Buffer.from('HTTP/', 'latin1');
// What follows the request line of HTTP/2's preface (RFC 9113 §3.4).
var PRI_TAIL = Buffer.from('\r\n\r\nSM\r\n\r\n', 'latin1');

var EMPTY = Buffer.alloc(0);

// chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
// chunk-ext-name = token; chunk-ext-val = token / quoted-string (RFC 9112 §7.1.1)
var TOKEN_RE = "[!#$%&'*+\\-.^_`|~0-9A-Za-z]+";
var QSTRING_RE = '"(?:[\\t \\x21\\x23-\\x5b\\x5d-\\x7e\\x80-\\xff]|\\\\[\\t \\x21-\\x7e\\x80-\\xff])*"';
var CHUNK_EXT = new RegExp('^(?:[ \\t]*;[ \\t]*' + TOKEN_RE + '(?:[ \\t]*=[ \\t]*(?:' + TOKEN_RE + '|' + QSTRING_RE + '))?)*$');
var CRLF = Buffer.from('\r\n');
var CRLFCRLF = Buffer.from('\r\n\r\n');


// Token and field-value validation now live in http_common.js: the rules are
// RFC 9110's, not RFC 9112's, and h2/h3 need exactly the same checks before
// putting a caller-supplied header on the wire.


// A list field's members (RFC 9110 §5.6.1): split on ",", OWS (SP, HTAB)
// around each taken off — and nothing else, which trim() would.
function listMembers(value) {
  return value.split(',').map(function (s) { return s.replace(/^[ \t]+|[ \t]+$/g, ''); });
}


// ============================================================
//  Errors
//
//  A parse failure is named as node:http names it — llhttp's: `code` its
//  error code (HPE_*), `reason` its reason, the message 'Parse Error: ' and
//  the reason; and, from the parser that saw it, `rawPacket` (the bytes it was
//  given then) and `bytesParsed` (how far into them it had got: the end of a
//  head refused as a whole, the bare LF of one, all of a head too large; the
//  start of a chunk line or trailer section at fault). Where llhttp has
//  no such failure (a refusal of quico's own, below), the nearest code.
//  quico's own: `detail`, what exactly was wrong, and `statusCode`, the status
//  the server answers with, so h1_server does not have to re-derive it.
//  Every one ends the connection: once framing is in doubt, where the next
//  message starts is too.
// ============================================================

function h1Error(code, reason, detail, statusCode) {
  var err = new Error('Parse Error: ' + reason);
  err.code = code;
  err.reason = reason;
  err.detail = detail || reason;
  err.statusCode = statusCode || 400;
  return err;
}
function isH1Error(err) { return !!err && typeof err.code === 'string' && err.code.indexOf('HPE_') === 0 && err.statusCode !== undefined; }

// A Content-Length that http_common's parseContentLength refused, by why.
function contentLengthError(e) {
  if (/^conflicting/.test(e.message)) return h1Error('HPE_UNEXPECTED_CONTENT_LENGTH', 'Duplicate Content-Length', e.message);
  if (/out of range/.test(e.message)) return h1Error('HPE_INVALID_CONTENT_LENGTH', 'Content-Length overflow', e.message);
  return h1Error('HPE_INVALID_CONTENT_LENGTH', 'Invalid character in Content-Length', e.message);
}

// Outgoing heads that cannot be written: node:http's errors for them (its
// setHeader / writeHead checks, which the callers make first).
function outError(Ctor, code, message) {
  var err = new Ctor(message);
  err.code = code;
  return err;
}


// ============================================================
//  H1Parser
//
//  Events:
//    'headers'  (info)          — head complete. info = { method, url,
//                                 statusCode, statusMessage, httpVersion,
//                                 headers, rawHeaders, keepAlive, upgrade,
//                                 hasBody }
//    'body'     (chunk)         — body bytes (de-chunked)
//    'trailers' (obj, raw)      — trailer fields, chunked bodies only; raw:
//                                 [name, value, ...] as they came
//    'end'      ()              — message complete; another may follow
//    'upgrade'  (info, head)    — protocol switch. `head` is the bytes already
//                                 received that belong to the NEW protocol.
//                                 The parser stops after this.
//
//  From a 'headers' listener, skipBody(upgrade) overrides the framing just
//  decided, as an llhttp on_headers_complete's return value does (1 and 2):
//  the message has no body and ends now — or, `upgrade`, the bytes after the
//  head are another protocol's: the parser stops, and leaves them unread
//  (execute()'s return value, `buffered`). For a layer that knows more than
//  the parser does: node:http's own lib over this parser (deep-runtime's
//  http_parser), which decides HEAD and CONNECT responses and upgrades itself.
//
//  Options:
//    isServer      parse requests (true) or responses (false)
//    maxHeadSize, maxHeaderCount
//    requireHostHeader  false: an HTTP/1.1 request without Host is served
//    shouldUpgrade(info)  server: whether an upgrade request switches
//    insecureHTTPParser  node:http's: read what is malformed in the ways
//                   below, as llhttp's lenient flags do — what a hop in front
//                   may read otherwise (see the README, "HTTP/1.1 parse errors")
// ============================================================

function H1Parser(options) {
  if (!(this instanceof H1Parser)) return new H1Parser(options);
  options = options || {};

  var ev = Emitter();
  var isServer = options.isServer !== false;
  var maxHeadSize = options.maxHeadSize || MAX_HEAD_SIZE;
  var maxHeaderCount = options.maxHeaderCount || MAX_HEADER_COUNT;
  // node:http's requireHostHeader: an HTTP/1.1 request without Host is
  // refused (400), unless this is false.
  var requireHost = options.requireHostHeader !== false;
  // Server side: whether an upgrade request is taken up (true) or handled as
  // an ordinary request (false) — node:http's shouldUpgradeCallback. Absent,
  // every upgrade request switches, as before.
  var shouldUpgrade = typeof options.shouldUpgrade === 'function' ? options.shouldUpgrade : null;
  // node:http's insecureHTTPParser: a field line folded (obs-fold) is unfolded,
  // a control character in a field value taken (not NUL, CR, LF), a bare LF a
  // line end in a request too, Transfer-Encoding with Content-Length read by
  // the chunks (RFC 9112 §6.3: and the connection closed after it), and SP or
  // HTAB after a chunk size skipped. Each is a way two hops can read one
  // message two ways, so it is for a peer known to send it, behind nothing.
  var insecure = options.insecureHTTPParser === true;

  // Line endings. A request must end its lines with CRLF (see splitLines):
  // a server that took a bare LF where a hop in front of it did not would
  // read another message than that hop did — request smuggling. A response
  // is read by its final recipient, the client, which has no one behind it
  // to disagree with; RFC 9112 §2.2 lets it take a bare LF as a line end,
  // and browsers and curl do, so a server that ends its lines with LF alone
  // — old ones, hand-written ones — can be talked to. Only here: the
  // request parser's rule is unchanged, and so is its code path.
  var lenientLf = !isServer || insecure;
  var teOverCl = false;   // the head being read: chunked, a Content-Length beside it

  var buf = EMPTY;
  var lfScanned = 0;      // how far into buf the head has been checked for bare LF
  var paused = false;
  var state = 'head';
  var msg = null;
  var bodyRemaining = 0;
  var chunkRemaining = 0;
  var trailerBytes = 0;

  // Response framing depends on the REQUEST that produced it: a HEAD response
  // carries the Content-Length of the body it is not sending, and a 2xx to
  // CONNECT becomes a tunnel. A response parser that does not know the method
  // will read the next response's head as this one's body and desynchronise —
  // which is exactly the desync a smuggler wants. Clients push the method
  // here as they send it.
  var pendingMethods = [];

  // skipBody() from the 'headers' listener running now: 'body' or 'upgrade'.
  var skipAsked = null;

  // The bytes execute() was given, and how many of `buf` were there before
  // them: for an error's rawPacket and bytesParsed.
  var curChunk = null, curBefore = 0;

  // at: where in `buf` the parse had got to (0, its start).
  function report(err, at) {
    state = 'error';
    if (curChunk) {
      err.rawPacket = curChunk;
      // What of this chunk was consumed before the part at fault (`buf` holds
      // that part and what follows it), and what of that part was read.
      err.bytesParsed = Math.max(0, Math.min(curChunk.length, curBefore + curChunk.length - buf.length + (at || 0)));
    } else {
      err.bytesParsed = 0;
    }
    ev.emit('error', err);
    return err;
  }

  function fail(code, reason, detail, statusCode, at) {
    return report(h1Error(code, reason, detail, statusCode), at);
  }


  // ---- Head parsing ----

  /**
   * Split a head block into its start line and field lines.
   *
   * Line terminators must be CRLF. RFC 9112 §2.2 permits a recipient to
   * accept a bare LF, and that permission is precisely how CL.0 and LF-based
   * smuggling work: two hops disagreeing about whether a lone LF ended a line
   * see two different messages in one byte stream. Nothing in practice sends
   * bare LF — every client, proxy and curl sends CRLF — so accepting it buys
   * no compatibility and costs the guarantee.
   */
  // Where the line starting at `from` ends: { idx, len } — its terminator's
  // position and length (CRLF 2; a bare LF 1, in a response) — or null when
  // it has not arrived yet.
  function lineEnd(b, from) {
    if (!lenientLf) {
      var c = b.indexOf(CRLF, from);
      return c === -1 ? null : { idx: c, len: 2 };
    }
    var lf = b.indexOf(0x0a, from);
    if (lf === -1) return null;
    return (lf > from && b[lf - 1] === 0x0d) ? { idx: lf - 1, len: 2 } : { idx: lf, len: 1 };
  }

  // The end of a field section — the empty line after it, in a response
  // with either terminator: { head, rest } (head: up to and including its
  // last line's terminator; rest: after the empty line), or null.
  function sectionEnd(b) {
    if (!lenientLf) {
      var c = b.indexOf(CRLFCRLF);
      return c === -1 ? null : { head: c + 2, rest: c + 4 };
    }
    var at = 0;
    while (true) {
      var e = lineEnd(b, at);
      if (!e) return null;
      if (e.idx === at) return { head: at, rest: at + e.len };
      at = e.idx + e.len;
    }
  }

  // A response's head, split on LF with an optional CR before it. A CR
  // anywhere else — a bare CR — is refused (§2.2: "MUST consider that
  // element to be invalid"): some parsers end the line there.
  function splitLinesLenient(head) {
    var lines = [];
    var start = 0;
    while (start < head.length) {
      var e = lineEnd(head, start);
      if (!e) throw h1Error('HPE_LF_EXPECTED', 'Missing expected LF after header value', 'malformed line terminator');
      var cr = head.indexOf(0x0d, start);
      if (cr !== -1 && cr < e.idx) throw h1Error('HPE_LF_EXPECTED', 'Missing expected LF after header value', 'bare CR in message head');
      lines.push(head.toString('latin1', start, e.idx));
      start = e.idx + e.len;
    }
    return lines;
  }

  function splitLines(head) {
    if (lenientLf) return splitLinesLenient(head);
    // Reject a bare LF explicitly, before splitting.
    //
    // This check is deliberately redundant: a bare LF inside a field line also
    // trips isValidFieldValue below, because the line it produces still
    // contains the LF. But relying on that is relying on an accident of where
    // the split happened to land, and a later refactor of the field parser
    // would remove the protection without any test noticing. State the rule
    // where the rule lives.
    //
    // The rule itself: line terminators are CRLF. RFC 9112 §2.2 permits a
    // recipient to accept a bare LF, and that permission is precisely how
    // LF-based smuggling works — two hops disagreeing about whether a lone LF
    // ended a line see two different messages in one byte stream. Nothing in
    // practice sends bare LF, so accepting it buys no compatibility.
    for (var i = 0; i < head.length; i++) {
      if (head[i] === 0x0a && (i === 0 || head[i - 1] !== 0x0d)) throw bareLfError(head, i);
    }

    var lines = [];
    var start = 0;
    while (start < head.length) {
      var idx = head.indexOf(CRLF, start);
      // Unreachable in practice — the caller only passes a block that ends in
      // CRLF — but a future caller might not, and silently dropping a trailing
      // fragment is exactly the kind of leniency this file exists to avoid.
      if (idx === -1) {
        throw h1Error('HPE_CR_EXPECTED', 'Missing expected CR after header value', 'malformed line terminator (CRLF required)');
      }
      lines.push(head.toString('latin1', start, idx));
      start = idx + 2;
    }
    return lines;
  }

  /**
   * Parse field lines into a lowercased map plus the original-case rawHeaders
   * array, the way node:http surfaces them.
   */
  function parseFields(lines, from) {
    var headers = {};
    var rawHeaders = [];
    var count = 0;

    // insecureHTTPParser: each obs-fold replaced by a SP (RFC 9112 §5.2's other
    // way), the continuation joined to the field line before it.
    if (insecure) lines = unfold(lines, from);

    for (var i = from; i < lines.length; i++) {
      var line = lines[i];
      if (line.length === 0) continue;

      // obs-fold: a field line continued by starting the next with SP/HTAB.
      // Deprecated by RFC 9112 §5.2, which tells a server to reject it with
      // 400. Unfolding instead is another two-readings-of-one-message hazard.
      if (line.charCodeAt(0) === 0x20 || line.charCodeAt(0) === 0x09) {
        throw h1Error('HPE_INVALID_HEADER_TOKEN', 'Unexpected whitespace after header value', 'obsolete line folding is not permitted');
      }

      if (++count > maxHeaderCount) {
        throw h1Error('HPE_HEADER_OVERFLOW', 'Header overflow', 'too many header fields', 431);
      }

      var colon = line.indexOf(':');
      if (colon < 1) throw h1Error('HPE_INVALID_HEADER_TOKEN', 'Invalid header token', 'malformed header field');

      var name = line.slice(0, colon);

      // "No whitespace is allowed between the field name and colon" — RFC 9112
      // §5.1, which then requires a server to reject the message outright.
      // Some intermediaries strip the space and forward; if we accepted it and
      // they stripped it, "Content-Length : 5" would be a header to one hop and
      // not the other.
      if (!isToken(name)) {
        throw h1Error('HPE_INVALID_HEADER_TOKEN', 'Invalid header token', 'invalid header field name: ' + JSON.stringify(name));
      }

      // OWS around the value is stripped and is not part of it (§5.1).
      var value = line.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, '');
      if (insecure ? /[\x00\r\n]/.test(value) : !isValidFieldValue(value)) {
        // A CR in it is a line that did not end where it should have.
        if (value.indexOf('\r') !== -1) throw h1Error('HPE_LF_EXPECTED', 'Missing expected LF after header value', 'bare CR in a field value');
        throw h1Error('HPE_INVALID_HEADER_TOKEN', 'Invalid header value char', 'invalid header field value');
      }

      rawHeaders.push(name, value);
      // Repeat-combining rules are RFC 9110 §5.3 and differ per field
      // (set-cookie never joins, cookie joins with "; "), so they live in
      // http_common.js where h2 uses the same ones.
      addHeader(headers, name.toLowerCase(), value);
    }

    return { headers: headers, rawHeaders: rawHeaders };
  }

  // The field lines from `from` on, each continuation (a line starting with SP
  // or HTAB) joined to the one before it by a SP. One with none before it is
  // left, to be refused.
  function unfold(lines, from) {
    var out = lines.slice(0, from);
    for (var i = from; i < lines.length; i++) {
      var l = lines[i];
      var c = l.charCodeAt(0);
      if ((c === 0x20 || c === 0x09) && out.length > from && out[out.length - 1].length > 0) {
        out[out.length - 1] = out[out.length - 1].replace(/[ \t]+$/, '') + ' ' + l.replace(/^[ \t]+/, '');
      } else {
        out.push(l);
      }
    }
    return out;
  }

  function parseRequestLine(line) {
    // METHOD SP request-target SP HTTP-version — exactly one SP each, and no
    // tolerance for runs of spaces: a target containing a space would then
    // parse differently here than at the next hop.
    var sp1 = line.indexOf(' ');
    if (sp1 < 1) throw h1Error('HPE_INVALID_METHOD', 'Invalid method encountered', 'malformed request line');
    if (!isToken(line.slice(0, sp1))) throw h1Error('HPE_INVALID_METHOD', 'Invalid method encountered', 'invalid method');
    var sp2 = line.indexOf(' ', sp1 + 1);
    if (sp2 < 0) throw h1Error('HPE_INVALID_CONSTANT', 'Expected HTTP/, RTSP/ or ICE/', 'request line without an HTTP version');

    var method = line.slice(0, sp1);
    var target = line.slice(sp1 + 1, sp2);
    var version = line.slice(sp2 + 1);

    if (target.length === 0) throw h1Error('HPE_INVALID_URL', 'Unexpected start char in url', 'empty request target');
    // No control characters in the target (RFC 9112 §3.2, RFC 3986): a NUL
    // reached the handler in req.url, where a file path built from it is cut
    // short by the system call that reads it. node:http answers 400.
    if (/[\x00-\x1f\x7f]/.test(target)) throw h1Error('HPE_INVALID_URL', 'Invalid char in url path', 'invalid character in request target');
    if (line.indexOf(' ', sp2 + 1) !== -1) throw h1Error('HPE_INVALID_CONSTANT', 'Expected HTTP/, RTSP/ or ICE/', 'a space in the request target');

    var v = parseVersion(version);
    return { method: method, url: target, httpVersion: v };
  }

  function parseStatusLine(line) {
    var sp1 = line.indexOf(' ');
    if (sp1 < 1) {
      if (line.slice(0, 5) === 'HTTP/') throw h1Error('HPE_INVALID_VERSION', 'Expected space after version', 'malformed status line', 502);
      throw h1Error('HPE_INVALID_CONSTANT', 'Expected HTTP/, RTSP/ or ICE/', 'malformed status line', 502);
    }

    var version = line.slice(0, sp1);
    var rest = line.slice(sp1 + 1);
    var sp2 = rest.indexOf(' ');
    var codeStr = sp2 === -1 ? rest : rest.slice(0, sp2);
    var reason = sp2 === -1 ? '' : rest.slice(sp2 + 1);

    var httpVersion = parseVersion(version);
    if (!/^[0-9]{3}$/.test(codeStr)) throw h1Error('HPE_INVALID_STATUS', 'Invalid status code', 'invalid status code', 502);

    return {
      httpVersion: httpVersion,
      statusCode: parseInt(codeStr, 10),
      statusMessage: reason
    };
  }

  // HTTP/1.x, any minor (RFC 9112 §2.3). Not "HTTP/" at all: no version, 400
  // (a response's: 502); "HTTP/" and not DIGIT "." DIGIT: a malformed one,
  // 400; another major version: 505, the status for it (RFC 9110 §15.6.6).
  function parseVersion(str) {
    var bad = isServer ? 400 : 502;
    if (str.slice(0, 5) !== 'HTTP/') {
      throw h1Error('HPE_INVALID_CONSTANT', 'Expected HTTP/, RTSP/ or ICE/', 'not an HTTP version: ' + JSON.stringify(str), bad);
    }
    var m = /^HTTP\/(\d)\.(\d)$/.exec(str);
    if (!m) throw h1Error('HPE_INVALID_VERSION', 'Invalid HTTP version', 'malformed HTTP version: ' + JSON.stringify(str), bad);
    var major = parseInt(m[1], 10);
    if (major !== 1) throw h1Error('HPE_INVALID_VERSION', 'Invalid HTTP version', 'unsupported HTTP major version: ' + JSON.stringify(str), isServer ? 505 : 502);
    return m[1] + '.' + m[2];
  }

  // A bare LF at `i` of `b` (a head from its start): llhttp's error for one
  // ending the request line, or a field line.
  function bareLfError(b, i) {
    var crlf = b.indexOf(CRLF);
    if (isServer && (crlf === -1 || crlf > i)) return h1Error('HPE_INVALID_VERSION', 'Expected CRLF after version', 'bare LF in message head (CRLF required)');
    return h1Error('HPE_CR_EXPECTED', 'Missing expected CR after header value', 'bare LF in message head (CRLF required)');
  }


  /**
   * Decide how the body is delimited (RFC 9112 §6.1–§6.3). This is where the
   * smuggling defences live, because "how long is the body" IS the question a
   * smuggled request answers differently at two hops.
   */
  function resolveFraming(info) {
    var h = info.headers;
    var hasTE = 'transfer-encoding' in h;
    var hasCL = 'content-length' in h;

    // RFC 9112 §6.1: an HTTP/1.0 message with Transfer-Encoding is to be
    // treated as having faulty framing — 1.0 has no chunked coding, and a hop
    // that speaks 1.0 reads the body by Content-Length or to the close, not
    // by the chunks this one would. Refused, as nginx does since 1.21.2.
    if (hasTE && isServer && info.httpVersion === '1.0') {
      throw h1Error('HPE_INVALID_TRANSFER_ENCODING', 'Request has invalid `Transfer-Encoding`', 'Transfer-Encoding in an HTTP/1.0 request');
    }

    if (hasTE && hasCL && !insecure) {
      // §6.1: a message with both is an attack or a broken sender, and the RFC
      // says to reject it rather than pick one — picking one is the whole
      // vulnerability, since the other hop may pick the other.
      // llhttp's names it by which came last.
      var lastTe = -1, lastCl = -1, raw = info.rawHeaders || [];
      for (var ri = 0; ri < raw.length; ri += 2) {
        var rn = String(raw[ri]).toLowerCase();
        if (rn === 'transfer-encoding') lastTe = ri; else if (rn === 'content-length') lastCl = ri;
      }
      if (lastCl > lastTe) throw h1Error('HPE_INVALID_CONTENT_LENGTH', "Content-Length can't be present with Transfer-Encoding", 'both Transfer-Encoding and Content-Length present');
      throw h1Error('HPE_INVALID_TRANSFER_ENCODING', "Transfer-Encoding can't be present with Content-Length", 'both Transfer-Encoding and Content-Length present');
    }

    if (hasTE) {
      var te = String(h['transfer-encoding']).toLowerCase();
      // Members are split on "," with OWS around them (RFC 9110 §5.6.1) —
      // SP and HTAB, nothing else: trim() took NBSP (0xA0, obs-text, legal
      // in a value) too, so "chunked\xA0" was chunked here and an unknown
      // coding to a parser that reads the grammar: the two disagree about
      // where the body ends, which is TE request smuggling.
      var codings = listMembers(te).filter(Boolean);

      // §6.1: chunked must be the FINAL coding. Anything else and we cannot
      // find the end of the body at all.
      if (codings[codings.length - 1] !== 'chunked') {
        throw h1Error('HPE_INVALID_TRANSFER_ENCODING',
                      codings.indexOf('chunked') !== -1 ? 'Invalid `Transfer-Encoding` header value' : 'Request has invalid `Transfer-Encoding`',
                      'Transfer-Encoding must end with chunked');
      }
      // "chunked, chunked" is not double-chunking, it is a sender trying to
      // get two hops to decode a different number of times.
      for (var i = 0; i < codings.length - 1; i++) {
        if (codings[i] === 'chunked') {
          throw h1Error('HPE_INVALID_TRANSFER_ENCODING', 'Invalid `Transfer-Encoding` header value', 'chunked appears more than once in Transfer-Encoding');
        }
      }
      // Any coding BEFORE chunked (gzip, deflate, compress) is applied to the
      // body underneath the chunking, and we do not undo it. Accepting the
      // message would mean de-chunking and then handing the application
      // compressed bytes it believes are plaintext — a Content-Length that
      // does not match, a JSON parse that fails on binary, or worse if the
      // application acts on the bytes. RFC 9112 §7.1 says to answer an
      // unsupported transfer coding with 501, which is the honest reply.
      //
      // Note this is transfer-coding, NOT Content-Encoding: `Content-Encoding:
      // gzip` is untouched by this and still passes straight through, which is
      // the header real-world compression actually uses.
      if (codings.length > 1) {
        throw h1Error('HPE_INVALID_TRANSFER_ENCODING', 'Unsupported `Transfer-Encoding`', 'unsupported transfer coding: ' + codings.slice(0, -1).join(', '), 501);
      }
      info.framing = 'chunked';
      // insecureHTTPParser's: Content-Length beside it is not read, and the
      // connection ends after the message (§6.3).
      teOverCl = hasCL;
      return;
    }

    if (hasCL) {
      var len;
      try {
        len = parseContentLength(h['content-length']);
      } catch (e) {
        // The strictness lives in http_common.js because h2 needs the same
        // rules; the status to answer with is HTTP/1.1's business.
        throw contentLengthError(e);
      }
      info.framing = 'length';
      info.contentLength = len;
      return;
    }

    // No framing headers.
    if (isServer) {
      // A request without either has no body. It cannot be read-until-close:
      // the client is not going to close, it is waiting for a response.
      info.framing = 'none';
    } else {
      // A response without either runs to end of connection (§6.3 case 7).
      info.framing = 'eof';
    }
  }

  /**
   * Does this message carry a body at all? For responses the status and the
   * originating method override the framing headers entirely (§6.3).
   */
  function resolveHasBody(info) {
    if (isServer) return info.framing !== 'none';

    var method = pendingMethods.length ? pendingMethods.shift() : 'GET';
    info.requestMethod = method;

    // Which responses carry a body is RFC 9110 §6.4 and identical in every
    // version, so the rule lives in http_common.js. Getting it wrong is a
    // desync, not a cosmetic bug: a 304 usually carries the Content-Length of
    // the cached representation, and believing it consumes the NEXT response
    // as this one's body.
    if (!responseHasBody(method, info.statusCode)) {
      info.framing = (method === 'CONNECT' && info.statusCode >= 200 && info.statusCode < 300)
                   ? 'tunnel' : 'none';
      return false;
    }

    return info.framing !== 'none';
  }

  function resolveKeepAlive(info) {
    var conn = String(info.headers['connection'] || '').toLowerCase();
    var tokens = listMembers(conn);

    if (tokens.indexOf('close') !== -1) return false;
    if (info.httpVersion === '1.0') return tokens.indexOf('keep-alive') !== -1;

    // A response with no way to delimit its body ends when the connection
    // does, so it can never be followed by another message.
    if (info.framing === 'eof') return false;

    return true;
  }

  function resolveUpgrade(info) {
    var conn = String(info.headers['connection'] || '').toLowerCase();
    var hasUpgradeToken = listMembers(conn).indexOf('upgrade') !== -1;
    if (!hasUpgradeToken) return null;
    var up = info.headers['upgrade'];
    if (!up) return null;
    // HTTP/1.0 has no Upgrade mechanism.
    if (info.httpVersion === '1.0') return null;
    return String(up);
  }


  // ---- The state machine ----

  // Where the bytes from `from` to `to` hold a bare LF — one with no CR before
  // it — or -1. A request's lines end with CRLF (see splitLines).
  function bareLf(b, from, to) {
    for (var i = from; i < to; i++) {
      if (b[i] === 0x0a && (i === 0 || b[i - 1] !== 0x0d)) return i;
    }
    return -1;
  }

  function processHead() {
    // Empty lines before a request line are ignored (RFC 9112 §2.2: "SHOULD
    // ignore at least one"): buggy clients append a CRLF after a body, and it
    // is unambiguous — however TCP cut the bytes. Before a status line too, as
    // llhttp does: a server's CRLF after a body (no response starts with one).
    var skip = 0;
    while (skip + 1 < buf.length && buf[skip] === 0x0d && buf[skip + 1] === 0x0a) skip += 2;
    if (skip > 0) { buf = buf.subarray(skip); lfScanned = Math.max(0, lfScanned - skip); }
    if (buf.length === 0) return false;

    // A response starts "HTTP/": one that does not is refused as it comes, as
    // llhttp does, not when a line, or the head limit, is reached — which a peer
    // speaking something else may never send.
    // (A lone CR may be an empty line's, still coming.)
    if (!isServer && !(buf.length === 1 && buf[0] === 0x0d)) {
      for (var k = 0; k < buf.length && k < 5; k++) {
        if (buf[k] !== HTTP_SLASH[k]) {
          fail('HPE_INVALID_CONSTANT', 'Expected HTTP/, RTSP/ or ICE/', 'not an HTTP response', 502, k);
          return false;
        }
      }
    }

    // The method PRI is HTTP/2's connection preface (RFC 9113 §3.4:
    // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), never a request: an HTTP/2
    // client that reached an HTTP/1.1 server. Named as llhttp names it — the
    // whole preface, HPE_PAUSED_H2_UPGRADE (its end the bytes parsed); a PRI
    // line followed by anything else, HPE_INVALID_VERSION. It was a request
    // line with version 2.0, refused as a version (505), and a PRI request on
    // HTTP/1.1 was served.
    if (isServer && buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x52 && buf[2] === 0x49 && buf[3] === 0x20) {
      var priLine = buf.indexOf(CRLF);
      if (priLine === -1) {
        if (buf.length > maxHeadSize) { fail('HPE_HEADER_OVERFLOW', 'Header overflow', 'header section exceeds ' + maxHeadSize + ' bytes', 431, buf.length); return false; }
        return false;
      }
      for (var pk = 0; pk < PRI_TAIL.length; pk++) {
        if (priLine + pk >= buf.length) return false;   // more to come
        if (buf[priLine + pk] !== PRI_TAIL[pk]) {
          fail('HPE_INVALID_VERSION', 'Expected HTTP/2 Connection Preface', 'PRI request that is not the HTTP/2 preface', 400, priLine);
          return false;
        }
      }
      fail('HPE_PAUSED_H2_UPGRADE', 'Pause on PRI/Upgrade', 'HTTP/2 connection preface (an HTTP/2 client)', 505, priLine + PRI_TAIL.length);
      return false;
    }

    var end = sectionEnd(buf);
    var idx = end ? end.head - 2 : -1;

    // A bare LF is refused as it arrives (see splitLines for the rule), in
    // the head — not in what follows it: the scan ran over the whole buffer,
    // so a body with a newline that came in the same read as its head (any
    // small POST of text or JSON) was refused as "bare LF in message head".
    // It is checked before the head is complete, as a head written with LF
    // alone has no CRLFCRLF and would wait, unanswered, for the head limit;
    // node:http answers 400 at once. From where the last pass stopped, so a
    // head arriving in pieces is scanned once. (A request only: a response
    // may end its lines with LF — see lenientLf.)
    if (!lenientLf) {
      var scanTo = end ? end.head : buf.length;
      var lfAt = bareLf(buf, Math.max(lfScanned, 0), scanTo);
      if (lfAt !== -1) {
        report(bareLfError(buf, lfAt), lfAt);
        return false;
      }
      lfScanned = scanTo;
    }

    if (!end) {
      if (buf.length > maxHeadSize) {
        fail('HPE_HEADER_OVERFLOW', 'Header overflow', 'header section exceeds ' + maxHeadSize + ' bytes', 431, buf.length);
        return false;
      }
      return false;   // need more
    }

    if (idx > maxHeadSize) { fail('HPE_HEADER_OVERFLOW', 'Header overflow', 'header section too large', 431, end.rest); return false; }

    var head = buf.subarray(0, end.head);   // include the final field line's CRLF
    var rest = buf.subarray(end.rest);

    var info;
    try {
      var lines = splitLines(head);
      if (lines.length === 0) throw h1Error(isServer ? 'HPE_INVALID_METHOD' : 'HPE_INVALID_CONSTANT', isServer ? 'Invalid method encountered' : 'Expected HTTP/, RTSP/ or ICE/', 'empty message head');

      info = isServer ? parseRequestLine(lines[0]) : parseStatusLine(lines[0]);

      var fields = parseFields(lines, 1);
      info.headers = fields.headers;
      info.rawHeaders = fields.rawHeaders;

      // RFC 9112 §3.2: an HTTP/1.1 request MUST carry Host, and exactly one.
      // Two Host headers let two hops route to two different origins.
      if (isServer && info.httpVersion === '1.1') {
        // node:http answers it 400 without a 'clientError' (`quiet`).
        if (requireHost && !('host' in info.headers)) {
          var noHost = h1Error('HPE_STRICT', 'Missing Host header', 'missing Host header');
          noHost.quiet = true;
          throw noHost;
        }
      }
      // One Host, and a well-formed one (see isValidAuthority) — on HTTP/1.0
      // too, which need not send it but must not send two.
      if (isServer && 'host' in info.headers) {
        if (String(info.headers['host']).indexOf(',') !== -1) {
          throw h1Error('HPE_STRICT', 'Multiple Host headers', 'multiple Host headers');
        }
        if (!isValidAuthority(String(info.headers['host']))) throw h1Error('HPE_STRICT', 'Invalid Host header', 'invalid Host header');
      }

      teOverCl = false;
      resolveFraming(info);
      info.hasBody = resolveHasBody(info);
      info.keepAlive = resolveKeepAlive(info) && !teOverCl;
      info.upgrade = resolveUpgrade(info);

    } catch (err) {
      report(isH1Error(err) ? err : h1Error('HPE_INTERNAL', 'Internal error', err.message), end.rest);
      return false;
    }

    buf = rest;
    lfScanned = 0;
    msg = info;

    // ---- Upgrade / tunnel: hand the socket over ----
    //
    // The bytes already sitting in `buf` belong to the NEW protocol. A client
    // may legitimately put its first WebSocket frame in the same TCP segment
    // as the handshake request, and if we drop these bytes that frame is gone
    // — a bug that only shows under load, when segments happen to coalesce.
    // node:http calls this parameter `head` and so do we.
    var switching = (!isServer && info.statusCode === 101) ||
                    (!isServer && info.framing === 'tunnel') ||
                    (isServer && info.upgrade && info.framing === 'none' &&
                     (!shouldUpgrade || !!shouldUpgrade(info)));

    if (switching) {
      state = 'upgraded';
      var head2 = buf;
      buf = EMPTY;
      // ONLY 'upgrade' — not 'headers' as well. The same `info` is the first
      // argument, so emitting both says nothing extra and forces every
      // consumer to recognise and discard the duplicate. The client did not:
      // it built a response object from 'headers' and reported "unexpected
      // server response: 101" for a handshake that had in fact succeeded.
      ev.emit('upgrade', info, head2);
      return false;
    }

    skipAsked = null;
    ev.emit('headers', info);
    var skipped = skipAsked;
    skipAsked = null;
    if (skipped === 'upgrade') { state = 'upgraded'; msg = null; return false; }
    if (skipped === 'body') { finishMessage(); return true; }

    if (!info.hasBody) { finishMessage(); return true; }

    if (info.framing === 'chunked') { state = 'chunk-size'; return true; }
    if (info.framing === 'eof')     { state = 'body-eof';  return true; }

    bodyRemaining = info.contentLength;
    if (bodyRemaining === 0) { finishMessage(); return true; }
    state = 'body-length';
    return true;
  }

  function processBodyLength() {
    if (buf.length === 0) return false;
    var take = Math.min(buf.length, bodyRemaining);
    var chunk = buf.subarray(0, take);
    buf = buf.subarray(take);
    bodyRemaining -= take;
    ev.emit('body', chunk);
    if (bodyRemaining === 0) { finishMessage(); return true; }
    return buf.length > 0;
  }

  function processBodyEof() {
    if (buf.length === 0) return false;
    var chunk = buf;
    buf = EMPTY;
    ev.emit('body', chunk);
    return false;
  }

  function processChunkSize() {
    var le = lineEnd(buf, 0);
    var idx = le ? le.idx : -1;
    // node:http's bound on chunk extensions (16 KB), and its 413: on a line still
    // coming, and on one that came whole.
    if ((idx === -1 ? buf.length : idx) > MAX_CHUNK_LINE) {
      fail('HPE_CHUNK_EXTENSIONS_OVERFLOW', 'Chunk extensions overflow', 'chunk size line too long', 413);
      return false;
    }
    if (idx === -1) return false;

    var line = buf.toString('latin1', 0, idx);

    // chunk-ext (";name=value") is permitted and ignored, but the size itself
    // must be bare hex with no sign, no whitespace and no 0x prefix. Every
    // tolerance here is a place where two parsers can read two sizes.
    var semi = line.indexOf(';');
    var sizeStr = semi === -1 ? line : line.slice(0, semi);
    if (insecure) sizeStr = sizeStr.replace(/[ \t]+$/, '');

    // The extensions themselves are ignored, but they must be well formed
    // (RFC 9112 §7.1.1): ;name[=value], a token or a quoted string. They were
    // skipped unread — so a control character or a bare CR in them, which
    // another parser on the path may treat as the end of the line, passed
    // here (the class of node's CVE-2021-22960).
    // A request's size line ended by a bare LF: it reads on to the CRLF.
    if (!lenientLf && line.indexOf('\n') !== -1) {
      fail('HPE_CR_EXPECTED', 'Missing expected CR after chunk size', 'bare LF in a chunk size line');
      return false;
    }
    if (semi !== -1 && !CHUNK_EXT.test(line.slice(semi))) {
      fail('HPE_STRICT', 'Invalid character in chunk extensions', 'invalid chunk extension');
      return false;
    }

    if (sizeStr.length === 0 || !/^[0-9a-fA-F]+$/.test(sizeStr)) {
      fail('HPE_INVALID_CHUNK_SIZE', 'Invalid character in chunk size', 'invalid chunk size: ' + JSON.stringify(sizeStr));
      return false;
    }
    if (sizeStr.length > MAX_CHUNK_SIZE_DIGITS) {
      fail('HPE_INVALID_CHUNK_SIZE', 'Chunk size overflow', 'chunk size out of range: ' + JSON.stringify(sizeStr));
      return false;
    }

    var size = parseInt(sizeStr, 16);
    if (!isFinite(size) || size > Number.MAX_SAFE_INTEGER) { fail('HPE_INVALID_CHUNK_SIZE', 'Chunk size overflow', 'chunk size out of range'); return false; }

    buf = buf.subarray(idx + le.len);

    if (size === 0) { state = 'trailers'; trailerBytes = 0; lfScanned = 0; return true; }

    chunkRemaining = size;
    state = 'chunk-data';
    return true;
  }

  function processChunkData() {
    if (buf.length === 0) return false;
    var take = Math.min(buf.length, chunkRemaining);
    var chunk = buf.subarray(0, take);
    buf = buf.subarray(take);
    chunkRemaining -= take;
    ev.emit('body', chunk);
    if (chunkRemaining === 0) state = 'chunk-crlf';
    return buf.length > 0;
  }

  function processChunkCrlf() {
    // A response's chunk may end in LF alone (see lenientLf).
    if (lenientLf && buf.length >= 1 && buf[0] === 0x0a) {
      buf = buf.subarray(1);
      state = 'chunk-size';
      return true;
    }
    if (buf.length < 2) return false;
    if (buf[0] !== 0x0d || buf[1] !== 0x0a) {
      fail('HPE_STRICT', 'Expected LF after chunk data', 'chunk data not terminated by CRLF');
      return false;
    }
    buf = buf.subarray(2);
    state = 'chunk-size';
    return true;
  }

  function processTrailers() {
    // A bare LF in a request's trailer section is refused as it arrives, as
    // in its head: the section waited for a CRLFCRLF it would never get. Up
    // to the section's end only — what follows is the next message.
    if (!lenientLf) {
      var tEnd = sectionEnd(buf);
      var scanTo = buf.length >= 2 && buf[0] === 0x0d && buf[1] === 0x0a ? 0 : (tEnd ? tEnd.head : buf.length);
      if (bareLf(buf, Math.max(lfScanned, 0), scanTo) !== -1) {
        fail('HPE_CR_EXPECTED', 'Missing expected CR after header value', 'bare LF in trailer section (CRLF required)');
        return false;
      }
      lfScanned = Math.max(lfScanned, scanTo);
    }

    var le = lineEnd(buf, 0);
    var idx = le ? le.idx : -1;
    if (idx === -1) {
      trailerBytes += buf.length;
      if (trailerBytes > maxHeadSize) { fail('HPE_HEADER_OVERFLOW', 'Header overflow', 'trailer section too large', 431); return false; }
      return false;
    }

    if (idx === 0) {            // blank line — trailer section done
      buf = buf.subarray(le.len);
      finishMessage();
      return true;
    }

    // Collect the whole trailer section before parsing it.
    var tend = sectionEnd(buf);
    if (!tend) {
      trailerBytes = buf.length;
      if (trailerBytes > maxHeadSize) { fail('HPE_HEADER_OVERFLOW', 'Header overflow', 'trailer section too large', 431); return false; }
      return false;
    }

    var section = buf.subarray(0, tend.head);
    var afterSection = buf.subarray(tend.rest);

    try {
      var parsed = parseFields(splitLines(section), 0);
      // RFC 9110 §6.5.1: framing and routing fields are forbidden in trailers.
      // A Content-Length or Transfer-Encoding that arrives AFTER the body has
      // been read is a re-framing attempt against whoever reads it late.
      for (var fname in parsed.headers) {
        if (TRAILER_FORBIDDEN[fname]) {
          var why = 'field not permitted in trailers: ' + fname;
          if (fname === 'content-length') throw h1Error('HPE_INVALID_CONTENT_LENGTH', "Content-Length can't be present with Transfer-Encoding", why);
          if (fname === 'transfer-encoding') throw h1Error('HPE_INVALID_TRANSFER_ENCODING', 'Invalid `Transfer-Encoding` header value', why);
          throw h1Error('HPE_INVALID_HEADER_TOKEN', 'Field not permitted in trailers', why);
        }
      }
    } catch (err) {
      // `buf` still at the section: bytesParsed is where it starts.
      report(isH1Error(err) ? err : h1Error('HPE_INTERNAL', 'Internal error', err.message));
      return false;
    }
    buf = afterSection;
    lfScanned = 0;
    ev.emit('trailers', parsed.headers, parsed.rawHeaders);

    finishMessage();
    return true;
  }

  function finishMessage() {
    var wasKeepAlive = msg ? msg.keepAlive : false;
    msg = null;
    bodyRemaining = 0;
    chunkRemaining = 0;
    state = wasKeepAlive ? 'head' : 'done';
    ev.emit('end');
  }


  /**
   * Feed bytes. Returns the number of bytes consumed from `chunk`; the
   * remainder (non-zero only after an upgrade) belongs to the next protocol.
   *
   * Never throws: failures arrive as an 'error' event carrying the status code
   * the server should reply with.
   */
  function execute(chunk) {
    if (state === 'error' || state === 'upgraded' || state === 'done') return 0;

    if (typeof chunk === 'string') chunk = Buffer.from(chunk, 'latin1');
    else if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk.buffer || chunk,
                                                          chunk.byteOffset || 0,
                                                          chunk.byteLength);

    var before = buf.length;
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    curChunk = chunk; curBefore = before;

    var keepGoing = true;
    while (keepGoing) {
      // A paused parser stops between messages but keeps accepting bytes: they
      // accumulate in `buf` and TCP back-pressures the peer. This is how a
      // server answers pipelined requests in order (RFC 9112 §9.3) without an
      // ordered write queue — it simply does not look at request N+1 until
      // response N is out. Pausing must NOT stop mid-message, or a body would
      // stall; hence the flag is only honoured at the top of the loop, and
      // callers set it from the 'end' event.
      if (paused) break;
      switch (state) {
        case 'head':         keepGoing = processHead();       break;
        case 'body-length':  keepGoing = processBodyLength();  break;
        case 'body-eof':     keepGoing = processBodyEof();     break;
        case 'chunk-size':   keepGoing = processChunkSize();   break;
        case 'chunk-data':   keepGoing = processChunkData();   break;
        case 'chunk-crlf':   keepGoing = processChunkCrlf();   break;
        case 'trailers':     keepGoing = processTrailers();    break;
        default:             keepGoing = false;                break;
      }
    }

    curChunk = null;
    var consumed = before + chunk.length - buf.length;
    return consumed < 0 ? 0 : consumed;
  }

  /**
   * Tell the parser the connection ended.
   *
   * For an 'eof'-framed response this is the legitimate end of the body. In
   * the middle of any other body it is a truncated message, and the caller
   * must NOT treat what it has as complete.
   */
  function eof() {
    if (state === 'body-eof') { finishMessage(); return; }
    if (state === 'head' && buf.length === 0) { state = 'done'; return; }
    if (state === 'done' || state === 'upgraded' || state === 'error') return;
    // node:http's: 'Parse Error', no packet (nothing was being parsed).
    curChunk = null;
    var cut = h1Error('HPE_INVALID_EOF_STATE', 'Invalid EOF state', 'connection closed mid-message');
    cut.message = 'Parse Error';
    report(cut);
  }

  this.on = ev.on;
  this.off = ev.off;
  this.execute = execute;
  this.eof = eof;

  /** Stop consuming buffered bytes. Bytes already handed to execute() stay
   *  buffered; new ones are still accepted. Safe to call from any event. */
  this.pause = function () { paused = true; };

  /** Resume, draining whatever accumulated while paused. */
  this.resume = function () {
    if (!paused) return;
    paused = false;
    if (buf.length > 0) execute(EMPTY);
  };

  /** Client-side: record the method of a request as it is sent, so the
   *  response parser can frame the reply (HEAD / CONNECT). */
  this.pushRequestMethod = function (method) {
    pendingMethods.push(String(method).toUpperCase());
  };

  /** From a 'headers' listener: no body after all — or (upgrade) the rest is
   *  another protocol's. See the event list above. */
  this.skipBody = function (upgrade) {
    if (state !== 'head' || !msg) return;
    skipAsked = upgrade ? 'upgrade' : 'body';
  };

  Object.defineProperty(this, 'state', { get: function () { return state; } });
  Object.defineProperty(this, 'paused', { get: function () { return paused; } });
  /** Bytes held back awaiting more input — the `head` after an upgrade. */
  Object.defineProperty(this, 'buffered', { get: function () { return buf; } });

  return this;
}


// ============================================================
//  Serialization
// ============================================================

/**
 * Reject anything that would let a header inject a line break.
 *
 * Called on the way OUT as well as in. Applications set headers from user
 * input constantly — a filename in Content-Disposition, a URL in Location —
 * and a CR or LF there splits our own response. Validating only inbound
 * traffic leaves the more damaging direction open.
 */
// A head is written as latin-1, one byte per character, and a character past
// 0xFF does not survive that: Buffer.from(…, 'latin1') keeps its low byte, so
// U+010D U+010A went out as CR LF — past isValidFieldValue, which looks at
// the characters — and split the message: a header value, a reason phrase, a
// request target. The callers' own checks (node:http's, http_common) refuse
// such a character too; the serializer does not rely on every path having
// made them.
var NOT_LATIN1 = /[^\x00-\xff]/;

function assertHeaderSafe(name, value) {
  if (!isToken(name)) {
    throw outError(TypeError, 'ERR_INVALID_HTTP_TOKEN', 'Header name must be a valid HTTP token ["' + name + '"]');
  }
  if (!isValidFieldValue(value) || NOT_LATIN1.test(value)) {
    throw outError(TypeError, 'ERR_INVALID_CHAR', 'Invalid character in header content ["' + name + '"]');
  }
}

function serializeHeaders(headers, out) {
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    var value = headers[name];
    if (value === undefined || value === null) continue;

    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) {
        var v = String(value[i]);
        assertHeaderSafe(name, v);
        out.push(name + ': ' + v);
      }
    } else {
      var s = String(value);
      assertHeaderSafe(name, s);
      out.push(name + ': ' + s);
    }
  }
}

/** Serialize a request head. Returns a Buffer ending in CRLFCRLF. */
function buildRequestHead(method, target, headers) {
  var m = String(method).toUpperCase();
  if (!isToken(m)) throw outError(TypeError, 'ERR_INVALID_HTTP_TOKEN', 'Method must be a valid HTTP token ["' + method + '"]');
  // ! … ÿ, node's INVALID_PATH_REGEX (and validateRequestTarget's): no space,
  // no control character, nothing the latin-1 head cannot hold.
  if (!target || /[^\x21-\xff]/.test(target)) throw outError(TypeError, 'ERR_UNESCAPED_CHARACTERS', 'Request path contains unescaped characters');

  var lines = [m + ' ' + target + ' HTTP/1.1'];
  serializeHeaders(headers || {}, lines);
  return Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1');
}

/** Serialize a response head. Returns a Buffer ending in CRLFCRLF. */
function buildResponseHead(statusCode, statusMessage, headers) {
  var code = parseInt(statusCode, 10);
  if (!(code >= 100 && code <= 599)) throw outError(RangeError, 'ERR_HTTP_INVALID_STATUS_CODE', 'Invalid status code: ' + statusCode);

  var reason = statusMessage != null ? String(statusMessage)
                                     : (STATUS_TEXT[code] || '');
  if (!isValidFieldValue(reason) || NOT_LATIN1.test(reason)) throw outError(TypeError, 'ERR_INVALID_CHAR', 'Invalid character in statusMessage');

  var lines = ['HTTP/1.1 ' + code + (reason ? ' ' + reason : '')];
  serializeHeaders(headers || {}, lines);
  return Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1');
}

/**
 * One chunk of a chunked body — hex size, CRLF, data, CRLF — as the three
 * pieces to write, the data among them as given: not copied into one buffer
 * with its framing, which for a large body was a second copy of all of it.
 * Written in the same tick to a corked socket, they still leave as one.
 * Nothing for empty data: a zero-size chunk would end the body.
 */
function encodeChunk(data) {
  if (typeof data === 'string') data = Buffer.from(data);
  if (data.length === 0) return [];
  return [Buffer.from(data.length.toString(16) + '\r\n', 'latin1'), data, CRLF];
}

/** Terminating chunk, with optional trailers. */
function encodeLastChunk(trailers) {
  if (!trailers) return Buffer.from('0\r\n\r\n', 'latin1');
  var lines = [];
  serializeHeaders(trailers, lines);
  if (lines.length === 0) return Buffer.from('0\r\n\r\n', 'latin1');
  return Buffer.from('0\r\n' + lines.join('\r\n') + '\r\n\r\n', 'latin1');
}


export {
  H1Parser,
  buildRequestHead,
  buildResponseHead,
  encodeChunk,
  encodeLastChunk,
  STATUS_TEXT,
  isToken,
  isValidFieldValue,
  h1Error
};
