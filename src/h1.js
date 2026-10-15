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


// ============================================================
//  Errors
//
//  Every parse failure carries the status the server should answer with, so
//  h1_server does not have to re-derive it. `close` marks the failures after
//  which the connection cannot be reused: once framing is ambiguous we no
//  longer know where the next message starts, so keep-alive is over.
// ============================================================

function h1Error(message, statusCode, mustClose) {
  var err = new Error(message);
  err.code = 'H1_PARSE_ERROR';
  err.statusCode = statusCode || 400;
  err.mustClose = mustClose !== false;
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
//    'trailers' (obj)           — trailer fields, chunked bodies only
//    'end'      ()              — message complete; another may follow
//    'upgrade'  (info, head)    — protocol switch. `head` is the bytes already
//                                 received that belong to the NEW protocol.
//                                 The parser stops after this.
//
//  Options:
//    isServer      parse requests (true) or responses (false)
//    maxHeadSize, maxHeaderCount
// ============================================================

function H1Parser(options) {
  if (!(this instanceof H1Parser)) return new H1Parser(options);
  options = options || {};

  var ev = Emitter();
  var isServer = options.isServer !== false;
  var maxHeadSize = options.maxHeadSize || MAX_HEAD_SIZE;
  var maxHeaderCount = options.maxHeaderCount || MAX_HEADER_COUNT;
  // Server side: whether an upgrade request is taken up (true) or handled as
  // an ordinary request (false) — node:http's shouldUpgradeCallback. Absent,
  // every upgrade request switches, as before.
  var shouldUpgrade = typeof options.shouldUpgrade === 'function' ? options.shouldUpgrade : null;

  // Line endings. A request must end its lines with CRLF (see splitLines):
  // a server that took a bare LF where a hop in front of it did not would
  // read another message than that hop did — request smuggling. A response
  // is read by its final recipient, the client, which has no one behind it
  // to disagree with; RFC 9112 §2.2 lets it take a bare LF as a line end,
  // and browsers and curl do, so a server that ends its lines with LF alone
  // — old ones, hand-written ones — can be talked to. Only here: the
  // request parser's rule is unchanged, and so is its code path.
  var lenientLf = !isServer;

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

  function fail(message, statusCode, mustClose) {
    var err = h1Error(message, statusCode, mustClose);
    state = 'error';
    ev.emit('error', err);
    return err;
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
      if (!e) throw h1Error('malformed line terminator', 400);
      var cr = head.indexOf(0x0d, start);
      if (cr !== -1 && cr < e.idx) throw h1Error('bare CR in message head', 400);
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
      if (head[i] === 0x0a && (i === 0 || head[i - 1] !== 0x0d)) {
        throw h1Error('bare LF in message head (CRLF required)', 400);
      }
    }

    var lines = [];
    var start = 0;
    while (start < head.length) {
      var idx = head.indexOf(CRLF, start);
      // Unreachable in practice — the caller only passes a block that ends in
      // CRLF — but a future caller might not, and silently dropping a trailing
      // fragment is exactly the kind of leniency this file exists to avoid.
      if (idx === -1) {
        throw h1Error('malformed line terminator (CRLF required)', 400);
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

    for (var i = from; i < lines.length; i++) {
      var line = lines[i];
      if (line.length === 0) continue;

      // obs-fold: a field line continued by starting the next with SP/HTAB.
      // Deprecated by RFC 9112 §5.2, which tells a server to reject it with
      // 400. Unfolding instead is another two-readings-of-one-message hazard.
      if (line.charCodeAt(0) === 0x20 || line.charCodeAt(0) === 0x09) {
        throw h1Error('obsolete line folding is not permitted', 400);
      }

      if (++count > maxHeaderCount) {
        throw h1Error('too many header fields', 431);
      }

      var colon = line.indexOf(':');
      if (colon < 1) throw h1Error('malformed header field', 400);

      var name = line.slice(0, colon);

      // "No whitespace is allowed between the field name and colon" — RFC 9112
      // §5.1, which then requires a server to reject the message outright.
      // Some intermediaries strip the space and forward; if we accepted it and
      // they stripped it, "Content-Length : 5" would be a header to one hop and
      // not the other.
      if (!isToken(name)) {
        throw h1Error('invalid header field name: ' + JSON.stringify(name), 400);
      }

      // OWS around the value is stripped and is not part of it (§5.1).
      var value = line.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, '');
      if (!isValidFieldValue(value)) {
        throw h1Error('invalid header field value', 400);
      }

      rawHeaders.push(name, value);
      // Repeat-combining rules are RFC 9110 §5.3 and differ per field
      // (set-cookie never joins, cookie joins with "; "), so they live in
      // http_common.js where h2 uses the same ones.
      addHeader(headers, name.toLowerCase(), value);
    }

    return { headers: headers, rawHeaders: rawHeaders };
  }

  function parseRequestLine(line) {
    // METHOD SP request-target SP HTTP-version — exactly one SP each, and no
    // tolerance for runs of spaces: a target containing a space would then
    // parse differently here than at the next hop.
    var sp1 = line.indexOf(' ');
    if (sp1 < 1) throw h1Error('malformed request line', 400);
    var sp2 = line.indexOf(' ', sp1 + 1);
    if (sp2 < 0) throw h1Error('malformed request line', 400);

    var method = line.slice(0, sp1);
    var target = line.slice(sp1 + 1, sp2);
    var version = line.slice(sp2 + 1);

    if (!isToken(method)) throw h1Error('invalid method', 400);
    if (target.length === 0) throw h1Error('empty request target', 400);
    // No control characters in the target (RFC 9112 §3.2, RFC 3986): a NUL
    // reached the handler in req.url, where a file path built from it is cut
    // short by the system call that reads it. node:http answers 400.
    if (/[\x00-\x1f\x7f]/.test(target)) throw h1Error('invalid character in request target', 400);
    if (line.indexOf(' ', sp2 + 1) !== -1) throw h1Error('malformed request line', 400);

    var v = parseVersion(version);
    return { method: method, url: target, httpVersion: v };
  }

  function parseStatusLine(line) {
    var sp1 = line.indexOf(' ');
    if (sp1 < 1) throw h1Error('malformed status line', 502);

    var version = line.slice(0, sp1);
    var rest = line.slice(sp1 + 1);
    var sp2 = rest.indexOf(' ');
    var codeStr = sp2 === -1 ? rest : rest.slice(0, sp2);
    var reason = sp2 === -1 ? '' : rest.slice(sp2 + 1);

    if (!/^[0-9]{3}$/.test(codeStr)) throw h1Error('invalid status code', 502);

    return {
      httpVersion: parseVersion(version),
      statusCode: parseInt(codeStr, 10),
      statusMessage: reason
    };
  }

  function parseVersion(str) {
    var m = /^HTTP\/(\d)\.(\d)$/.exec(str);
    if (!m) throw h1Error('unsupported HTTP version: ' + JSON.stringify(str), 505);
    var major = parseInt(m[1], 10);
    if (major !== 1) throw h1Error('unsupported HTTP major version', 505);
    return m[1] + '.' + m[2];
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
      throw h1Error('Transfer-Encoding in an HTTP/1.0 request', 400);
    }

    if (hasTE && hasCL) {
      // §6.1: a message with both is an attack or a broken sender, and the RFC
      // says to reject it rather than pick one — picking one is the whole
      // vulnerability, since the other hop may pick the other.
      throw h1Error('both Transfer-Encoding and Content-Length present', 400);
    }

    if (hasTE) {
      var te = String(h['transfer-encoding']).toLowerCase();
      var codings = te.split(',').map(function (s) { return s.trim(); }).filter(Boolean);

      // §6.1: chunked must be the FINAL coding. Anything else and we cannot
      // find the end of the body at all.
      if (codings[codings.length - 1] !== 'chunked') {
        throw h1Error('Transfer-Encoding must end with chunked', 400);
      }
      // "chunked, chunked" is not double-chunking, it is a sender trying to
      // get two hops to decode a different number of times.
      for (var i = 0; i < codings.length - 1; i++) {
        if (codings[i] === 'chunked') {
          throw h1Error('chunked appears more than once in Transfer-Encoding', 400);
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
        throw h1Error('unsupported transfer coding: ' + codings.slice(0, -1).join(', '), 501);
      }
      info.framing = 'chunked';
      return;
    }

    if (hasCL) {
      var len;
      try {
        len = parseContentLength(h['content-length']);
      } catch (e) {
        // The strictness lives in http_common.js because h2 needs the same
        // rules; the status to answer with is HTTP/1.1's business.
        throw h1Error(e.message, 400);
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
    var tokens = conn.split(',').map(function (s) { return s.trim(); });

    if (tokens.indexOf('close') !== -1) return false;
    if (info.httpVersion === '1.0') return tokens.indexOf('keep-alive') !== -1;

    // A response with no way to delimit its body ends when the connection
    // does, so it can never be followed by another message.
    if (info.framing === 'eof') return false;

    return true;
  }

  function resolveUpgrade(info) {
    var conn = String(info.headers['connection'] || '').toLowerCase();
    var hasUpgradeToken = conn.split(',').some(function (s) { return s.trim() === 'upgrade'; });
    if (!hasUpgradeToken) return null;
    var up = info.headers['upgrade'];
    if (!up) return null;
    // HTTP/1.0 has no Upgrade mechanism.
    if (info.httpVersion === '1.0') return null;
    return String(up);
  }


  // ---- The state machine ----

  function processHead() {
    // A bare LF is refused as it arrives (see splitLines for the rule). It was
    // checked only once a CRLFCRLF had been found — and a head written with LF
    // alone has none, so the connection waited, unanswered, for the head
    // limit or the timeout. node:http answers 400 at once. Checked from where
    // the last pass stopped, so a head arriving in pieces is scanned once.
    // (A request only: a response may end its lines with LF — see lenientLf.)
    if (!lenientLf) {
      for (var li = Math.max(lfScanned, 0); li < buf.length; li++) {
        if (buf[li] === 0x0a && (li === 0 || buf[li - 1] !== 0x0d)) {
          fail('bare LF in message head (CRLF required)', 400);
          return false;
        }
      }
      lfScanned = buf.length;
    }

    var end = sectionEnd(buf);
    var idx = end ? end.head - 2 : -1;

    if (!end) {
      // A leading CRLF before a request line is tolerated (RFC 9112 §2.2):
      // buggy clients append one after a body, and it is unambiguous.
      if (isServer && buf.length >= 2 && buf[0] === 0x0d && buf[1] === 0x0a) {
        buf = buf.subarray(2);
        lfScanned = Math.max(0, lfScanned - 2);
        return true;
      }
      if (buf.length > maxHeadSize) {
        fail('header section exceeds ' + maxHeadSize + ' bytes', 431);
        return false;
      }
      return false;   // need more
    }

    if (idx > maxHeadSize) { fail('header section too large', 431); return false; }

    var head = buf.subarray(0, end.head);   // include the final field line's CRLF
    var rest = buf.subarray(end.rest);

    var info;
    try {
      var lines = splitLines(head);
      if (lines.length === 0) throw h1Error('empty message head', 400);

      info = isServer ? parseRequestLine(lines[0]) : parseStatusLine(lines[0]);

      var fields = parseFields(lines, 1);
      info.headers = fields.headers;
      info.rawHeaders = fields.rawHeaders;

      // RFC 9112 §3.2: an HTTP/1.1 request MUST carry Host, and exactly one.
      // Two Host headers let two hops route to two different origins.
      if (isServer && info.httpVersion === '1.1') {
        if (!('host' in info.headers)) throw h1Error('missing Host header', 400);
      }
      // One Host, and a well-formed one (see isValidAuthority) — on HTTP/1.0
      // too, which need not send it but must not send two.
      if (isServer && 'host' in info.headers) {
        if (String(info.headers['host']).indexOf(',') !== -1) {
          throw h1Error('multiple Host headers', 400);
        }
        if (!isValidAuthority(String(info.headers['host']))) throw h1Error('invalid Host header', 400);
      }

      resolveFraming(info);
      info.hasBody = resolveHasBody(info);
      info.keepAlive = resolveKeepAlive(info);
      info.upgrade = resolveUpgrade(info);

    } catch (err) {
      state = 'error';
      ev.emit('error', err.code === 'H1_PARSE_ERROR' ? err
                     : h1Error(err.message, 400));
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

    ev.emit('headers', info);

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
    if (idx === -1) {
      if (buf.length > 1024) { fail('chunk size line too long', 400); return false; }
      return false;
    }

    var line = buf.toString('latin1', 0, idx);

    // chunk-ext (";name=value") is permitted and ignored, but the size itself
    // must be bare hex with no sign, no whitespace and no 0x prefix. Every
    // tolerance here is a place where two parsers can read two sizes.
    var semi = line.indexOf(';');
    var sizeStr = semi === -1 ? line : line.slice(0, semi);

    // The extensions themselves are ignored, but they must be well formed
    // (RFC 9112 §7.1.1): ;name[=value], a token or a quoted string. They were
    // skipped unread — so a control character or a bare CR in them, which
    // another parser on the path may treat as the end of the line, passed
    // here (the class of node's CVE-2021-22960).
    if (semi !== -1 && !CHUNK_EXT.test(line.slice(semi))) {
      fail('invalid chunk extension', 400);
      return false;
    }

    if (sizeStr.length === 0 || sizeStr.length > MAX_CHUNK_SIZE_DIGITS ||
        !/^[0-9a-fA-F]+$/.test(sizeStr)) {
      fail('invalid chunk size: ' + JSON.stringify(sizeStr), 400);
      return false;
    }

    var size = parseInt(sizeStr, 16);
    if (!isFinite(size)) { fail('chunk size out of range', 400); return false; }

    buf = buf.subarray(idx + le.len);

    if (size === 0) { state = 'trailers'; trailerBytes = 0; return true; }

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
      fail('chunk data not terminated by CRLF', 400);
      return false;
    }
    buf = buf.subarray(2);
    state = 'chunk-size';
    return true;
  }

  function processTrailers() {
    var le = lineEnd(buf, 0);
    var idx = le ? le.idx : -1;
    if (idx === -1) {
      trailerBytes += buf.length;
      if (trailerBytes > maxHeadSize) { fail('trailer section too large', 431); return false; }
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
      if (trailerBytes > maxHeadSize) { fail('trailer section too large', 431); return false; }
      return false;
    }

    var section = buf.subarray(0, tend.head);
    buf = buf.subarray(tend.rest);

    try {
      var parsed = parseFields(splitLines(section), 0);
      // RFC 9110 §6.5.1: framing and routing fields are forbidden in trailers.
      // A Content-Length or Transfer-Encoding that arrives AFTER the body has
      // been read is a re-framing attempt against whoever reads it late.
      for (var fname in parsed.headers) {
        if (TRAILER_FORBIDDEN[fname]) throw h1Error('field not permitted in trailers: ' + fname, 400);
      }
      ev.emit('trailers', parsed.headers);
    } catch (err) {
      state = 'error';
      ev.emit('error', err.code === 'H1_PARSE_ERROR' ? err : h1Error(err.message, 400));
      return false;
    }

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
    fail('connection closed mid-message', 400);
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
function assertHeaderSafe(name, value) {
  if (!isToken(name)) {
    throw h1Error('invalid header name: ' + JSON.stringify(name), 500);
  }
  if (!isValidFieldValue(value)) {
    throw h1Error('invalid characters in value of header ' + name, 500);
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
  if (!isToken(m)) throw h1Error('invalid method', 500);
  if (!target || /[ \r\n]/.test(target)) throw h1Error('invalid request target', 500);

  var lines = [m + ' ' + target + ' HTTP/1.1'];
  serializeHeaders(headers || {}, lines);
  return Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1');
}

/** Serialize a response head. Returns a Buffer ending in CRLFCRLF. */
function buildResponseHead(statusCode, statusMessage, headers) {
  var code = parseInt(statusCode, 10);
  if (!(code >= 100 && code <= 599)) throw h1Error('invalid status code', 500);

  var reason = statusMessage != null ? String(statusMessage)
                                     : (STATUS_TEXT[code] || '');
  if (!isValidFieldValue(reason)) throw h1Error('invalid reason phrase', 500);

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
