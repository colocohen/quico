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

import { EventEmitter } from 'node:events';
import dns from 'node:dns';
import { H3Connection, wtCloseCapsule, createCapsuleReader } from './h3.js';
import { createQuicClientSocket } from './quic_socket.js';
import lemonTls from 'lemon-tls';
import { createHash, X509Certificate } from 'node:crypto';
import { readVarInt, wt_datagram_payload } from './utils.js';
import { createWtStream, openWtStream, createSendGroup, wtScheduling, createDatagrams, sessionStats, setErrorCode,
         exporterArgs, exportSessionKeyingMaterial,
         WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
         WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream } from './wt_stream.js';
import { defaultTransportParams } from './tls_bridge.js';
import { initialCongestionWindow, checkConnectionOptions } from './quic_connection.js';
import { sfString, parseSfString, validateHeaderName, validateHeaderValue, isConnectionSpecific } from './http_common.js';
import { parseVersionList } from './quic_version.js';


// ============================================================
//  WebTransport — Client
//
//  The browser's WebTransport API (W3C), complete — code written for the
//  browser runs here unchanged — and a Node-style API on the same object:
//
//    Browser API                              Node API
//    -----------                              --------
//    wt.ready / wt.closed / wt.draining       'ready' / 'close' / 'draining'
//    wt.close({ closeCode, reason })
//    wt.datagrams.readable / .writable /      wt.sendDatagram(buf), 'datagram'
//      .createWritable() / .maxDatagramSize   wt.maxDatagramSize()
//    wt.incomingBidirectionalStreams          'stream' (a Duplex)
//    wt.incomingUnidirectionalStreams         'unidirectionalStream' (a Readable)
//    await wt.createBidirectionalStream()     → a Duplex that also has
//                                               .readable / .writable (WHATWG)
//    await wt.createUnidirectionalStream()    → a WritableStream (WHATWG) that
//                                               also has write() / end()
//    wt.createSendGroup(), wt.getStats(), wt.reliability, wt.congestionControl,
//    wt.protocol, WebTransportError
//
//    Options: the browser's — serverCertificateHashes, protocols,
//    congestionControl, allowPooling, requireUnreliable, anticipatedConcurrent…
//    — and Node's, as for https.request: rejectUnauthorized (default true),
//    origin and headers (fields for the CONNECT request, as the WebSocket
//    client takes them: a browser sends its page's Origin, Node has none),
//    ca, key / cert / passphrase (a client certificate), and session (one
//    saved from the 'session' event, to resume the TLS session). The
//    server's certificate is verified against the platform roots
//    unless `ca` is given, or serverCertificateHashes pins it as a browser
//    does.
//
//  A server stream goes to a Node listener if there is one, otherwise to the
//  browser API's incoming…Streams once that is read; it waits for either.
// ============================================================

// What the client's unidirectional stream (a WritableStream) carries over
// from the Node Writable underneath it — see createUnidirectionalStream.
var UNI_METHODS = ['write', 'end', 'destroy', 'cork', 'uncork', 'setDefaultEncoding', 'resetStream', 'getStats',
  'on', 'once', 'off', 'addListener', 'removeListener', 'removeAllListeners', 'prependListener',
  'prependOnceListener', 'emit', 'listeners', 'listenerCount', 'eventNames'];
var UNI_STATE = ['_streamId', 'id', 'sessionId', 'sendState', 'pending', 'streamErrorCode', 'destroyed', 'writableLength', 'writableHighWaterMark',
  'writableNeedDrain', 'writableEnded', 'writableFinished', 'writableCorked', 'writableObjectMode', 'closed', 'errored'];

// The CONNECT request's own fields, besides those the session sets:
// options.headers — the browser's HeadersInit: a Headers, a sequence of
// [name, value] pairs, or an object of them — and Origin (options.origin):
// a browser always sends its page's, and servers check it (WPT's
// WebTransport server refuses a CONNECT without one); Node has no page.
//
// As the browser's Headers takes them: names lower-cased, values with their
// leading and trailing whitespace removed (a field value may not begin or end
// with it — RFC 9110 §5.5 — and a server refuses the request), a name given
// twice sent once with its values joined by ", ". An invalid name or value,
// or a field the session sets itself, throws a TypeError now, not later on
// the wire:
//   a pseudo-header (not a token: TypeError from validateHeaderName);
//   wt-available-protocols (that is options.protocols).
// Fields that cannot go on an HTTP/3 request at all are dropped, as the
// browser drops them: connection-specific ones (RFC 9114 §4.2), host (the
// authority is :authority, §4.3.1), te, and content-length and trailer,
// which do not apply to a CONNECT whose stream carries capsules. The fields
// a browser keeps from a page for its own safety — cookie, referer, sec-* —
// are sent: Node is the user agent itself here, as with Node's fetch.
var CONNECT_DROPPED = { 'host': 1, 'te': 1, 'content-length': 1, 'trailer': 1 };
var HTTP_WHITESPACE = /^[\t\n\r ]+|[\t\n\r ]+$/g;
function headersInitEntries(h) {
  if (h == null) return [];
  if (typeof h !== 'object' && typeof h !== 'function') {
    throw new TypeError('options.headers must be a Headers, a sequence of [name, value] pairs, or an object');
  }
  var out = [];
  if (typeof Headers !== 'undefined' && h instanceof Headers) {
    h.forEach(function (value, name) { out.push([name, value]); });
    return out;
  }
  if (typeof h[Symbol.iterator] === 'function') {
    for (var pair of h) {
      if (pair == null || typeof pair !== 'object' || typeof pair[Symbol.iterator] !== 'function') {
        throw new TypeError('options.headers: each item must be a [name, value] pair');
      }
      var p = Array.from(pair);
      if (p.length !== 2) throw new TypeError('options.headers: each pair must have exactly two items, a name and a value; got ' + p.length);
      out.push([p[0], p[1]]);
    }
    return out;
  }
  for (var name in h) {
    if (!Object.prototype.hasOwnProperty.call(h, name)) continue;
    var v = h[name];
    if (v === undefined || v === null) continue;
    // A list, as Node's http takes it: each value a field of its own.
    if (Array.isArray(v)) { for (var i = 0; i < v.length; i++) out.push([name, v[i]]); }
    else out.push([name, v]);
  }
  return out;
}
function connectRequestFields(options) {
  var out = {};
  var entries = headersInitEntries(options.headers);
  for (var i = 0; i < entries.length; i++) {
    var name = String(entries[i][0]);
    validateHeaderName(name);
    var lower = name.toLowerCase();
    if (lower === 'wt-available-protocols') {
      throw new TypeError('options.headers: wt-available-protocols cannot be set; it is options.protocols');
    }
    var value = String(entries[i][1]).replace(HTTP_WHITESPACE, '');
    validateHeaderValue(lower, value);
    if (isConnectionSpecific(lower) || CONNECT_DROPPED[lower]) continue;
    out[lower] = Object.prototype.hasOwnProperty.call(out, lower) ? out[lower] + ', ' + value : value;
  }
  if (options.origin != null) {
    var origin = String(options.origin).replace(HTTP_WHITESPACE, '');
    validateHeaderValue('origin', origin);
    out['origin'] = origin;
  }
  return out;
}

// The URL, as the browser's constructor checks it: one that does not parse,
// whose scheme is not https, or that has a fragment, is a SyntaxError
// (DOMException) — as Node's own WebSocket throws for its URL. An http: URL
// and a fragment were taken, and a port of 0 became 443.
function parseWebTransportUrl(url) {
  var u;
  try { u = new URL(String(url)); }
  catch (e) { throw new DOMException('Invalid URL: ' + url, 'SyntaxError'); }
  if (u.protocol !== 'https:') throw new DOMException('A WebTransport URL\'s scheme must be https:, not ' + u.protocol, 'SyntaxError');
  if (u.href.indexOf('#') >= 0) throw new DOMException('A WebTransport URL must not have a fragment', 'SyntaxError');
  return u;
}

// options.protocols, as the browser checks them: a list of strings, each
// one a valid structured-field string (printable ASCII), 1 to 512 long, none
// twice — otherwise a SyntaxError. They were sent as given: a CR or LF in
// one went into the field.
function checkProtocols(list) {
  if (list == null) return [];
  if (typeof list !== 'object' || typeof list[Symbol.iterator] !== 'function') {
    throw new TypeError('options.protocols must be a sequence of strings');
  }
  var out = [];
  for (var p of list) {
    p = String(p);
    if (p.length === 0 || p.length > 512 || !/^[\x20-\x7e]*$/.test(p) || out.indexOf(p) >= 0) {
      throw new DOMException('Invalid protocol in options.protocols: ' + JSON.stringify(p) +
                             ' (each must be printable ASCII, 1 to 512 characters, and given once)', 'SyntaxError');
    }
    out.push(p);
  }
  return out;
}

// options.serverCertificateHashes, as the browser's WebIDL takes it: each an
// object with an algorithm and a value — a BufferSource, not shared memory.
// A malformed one was skipped, and the connection then failed for a reason
// that did not say why.
function checkCertificateHashes(list) {
  if (list == null) return;
  if (typeof list !== 'object' || typeof list[Symbol.iterator] !== 'function') {
    throw new TypeError('options.serverCertificateHashes must be a sequence of { algorithm, value }');
  }
  for (var h of list) {
    if (h == null || typeof h !== 'object') throw new TypeError('options.serverCertificateHashes: each must be an object { algorithm, value }');
    if (h.algorithm === undefined) throw new TypeError('options.serverCertificateHashes: algorithm is required');
    var v = h.value;
    if (v === undefined) throw new TypeError('options.serverCertificateHashes: value is required');
    var shared = typeof SharedArrayBuffer !== 'undefined' &&
                 (v instanceof SharedArrayBuffer || (ArrayBuffer.isView(v) && v.buffer instanceof SharedArrayBuffer));
    if (shared || !(v instanceof ArrayBuffer || ArrayBuffer.isView(v))) {
      throw new TypeError('options.serverCertificateHashes: value must be an ArrayBuffer or an ArrayBufferView, not shared memory');
    }
  }
}

// The anticipatedConcurrentIncoming… hints, as WebIDL's [EnforceRange]
// unsigned short? takes them: null, or an integer 0 to 65535 (a fraction
// dropped); anything else a TypeError.
function streamHint(v, name) {
  if (v === null || v === undefined) return null;
  var n = Number(v);
  if (!isFinite(n)) throw new TypeError(name + ' must be null or an integer from 0 to 65535, got ' + v);
  n = Math.trunc(n);
  if (n < 0 || n > 65535) throw new TypeError(name + ' must be null or an integer from 0 to 65535, got ' + v);
  return n;
}

var CONGESTION_CONTROL = ['default', 'throughput', 'low-latency'];

// The browser's responseHeaders: the server's answer to the CONNECT, as a
// Headers that cannot be changed — without the pseudo-headers, and without
// wt-protocol, which is negotiation (its outcome is wt.protocol). A browser
// also keeps Set-Cookie from its page; here it is there, as with Node's
// fetch: the program is the user agent (getSetCookie() reads it).
class ImmutableHeaders extends Headers {
  set() { throw new TypeError('responseHeaders cannot be changed'); }
  append() { throw new TypeError('responseHeaders cannot be changed'); }
  delete() { throw new TypeError('responseHeaders cannot be changed'); }
}
function responseHeadersOf(headers) {
  var list = headers && headers._list ? headers._list
           : Object.keys(headers || {}).map(function (k) { return [k, headers[k]]; });
  var pairs = [];
  for (var i = 0; i < list.length; i++) {
    var name = String(list[i][0]).toLowerCase(), value = list[i][1];
    if (name.charAt(0) === ':' || name === 'wt-protocol') continue;
    var values = Array.isArray(value) ? value : [value];
    for (var j = 0; j < values.length; j++) {
      var pair = [name, String(values[j])];
      try { new Headers([pair]); pairs.push(pair); }
      catch (e) {}   // a field Headers cannot hold is left out, not the whole answer
    }
  }
  return new ImmutableHeaders(pairs);
}

function invalidState(message) { return new DOMException(message, 'InvalidStateError'); }

class WebTransport extends EventEmitter {

  constructor(url, options) {
    super();

    // The URL and the browser's options, checked as the browser checks them.
    var parsed = parseWebTransportUrl(url);
    this._hostname = parsed.hostname.replace(/^\[(.*)\]$/, '$1');   // an IPv6 literal, without its brackets
    this._authority = parsed.host;                                  // with them, and the port unless 443
    this._port = parsed.port === '' ? 443 : Number(parsed.port);
    this._path = parsed.pathname + (parsed.search || '');
    this._options = options || {};
    this._protocols = checkProtocols(this._options.protocols);
    checkCertificateHashes(this._options.serverCertificateHashes);
    if (this._options.datagramsReadableType != null && String(this._options.datagramsReadableType) !== 'bytes') {
      throw new TypeError("options.datagramsReadableType must be 'bytes'");
    }
    if (this._options.congestionControl != null && CONGESTION_CONTROL.indexOf(String(this._options.congestionControl)) < 0) {
      throw new TypeError('options.congestionControl must be one of ' + CONGESTION_CONTROL.join(', '));
    }
    this._hintUni = streamHint(this._options.anticipatedConcurrentIncomingUnidirectionalStreams, 'anticipatedConcurrentIncomingUnidirectionalStreams');
    this._hintBidi = streamHint(this._options.anticipatedConcurrentIncomingBidirectionalStreams, 'anticipatedConcurrentIncomingBidirectionalStreams');
    // Checked here, as the browser checks its options: a bad value throws now,
    // not later inside the connection.
    defaultTransportParams(this._options.transportParams);
    this._transportParams = this._hintedTransportParams();
    if (this._options.ecdhCurve != null) lemonTls.parseEcdhCurve(this._options.ecdhCurve);
    if (this._options.sigalgs != null) lemonTls.parseSigalgs(this._options.sigalgs);
    initialCongestionWindow(this._options.initialCongestionWindow);
    (function (o) { var c = {}; ['startupCap', 'pmtuDiscovery', 'maxUdpPayloadSize', 'initialRtt', 'reorderWindow'].forEach(function (k) { if (o[k] != null) c[k] = o[k]; }); checkConnectionOptions(c, 'WebTransport'); })(this._options);
    parseVersionList(this._options.quicVersions, 'quicVersions');
    this._connectFields = connectRequestFields(this._options);

    // State
    this._state = 'connecting'; // connecting → connected → closed, or connecting → failed
    this._sessionId = null;     // stream ID of the CONNECT request
    this._quic = null;
    this._h3 = null;
    this._udpSocket = null;

    // This session's streams, ours and the server's: streamId → stream.
    this._streams = {};
    // The server's streams not handed over yet: those that arrived before
    // its 200 (a packet can overtake another), and those nobody listens for
    // yet — the server opens streams with its 200, before `await wt.ready`
    // has even returned to the code that will listen. As the browser's
    // incomingUnidirectionalStreams holds them until read, they wait here for
    // a 'stream' / 'unidirectionalStream' listener. Emitted at once, they
    // were lost.
    this._waiting = [];   // [event, stream]

    // The browser API's promises. A rejection nobody awaits is logged by a
    // browser; in Node it would end the process — so each has a handler of
    // its own, and a caller that awaits it still sees the rejection.
    var self = this;
    this.ready = new Promise(function (resolve, reject) {
      self._readyResolve = resolve;
      self._readyReject = reject;
    });
    this.ready.catch(function () {});
    this.closed = new Promise(function (resolve, reject) {
      self._closedResolve = resolve;
      self._closedReject = reject;
    });
    this.closed.catch(function () {});
    this.draining = new Promise(function (resolve) { self._drainingResolve = resolve; });

    // The browser API's attributes.
    var o = this._options;
    this.reliability = 'pending';     // then 'supports-unreliable' or 'reliable-only'
    this.congestionControl = 'default';
    this.protocol = '';               // the server's choice among options.protocols
    this._responseHeaders = null;     // responseHeaders: the server's, once the session is up
    this._incoming = { stream: null, unidirectionalStream: null };   // the browser API's queues, once read
    // The session, as wt_stream's createDatagrams / sessionStats take it —
    // the server's res hands in the same.
    var self = this;
    this._dgStats = { droppedIncoming: 0, expiredIncoming: 0 };
    this._dgOwner = { maxAge: null, expired: 0 };
    this._session = {
      get quic() { return self._quic; },
      connected: function () { return self._state === 'connected'; },
      connecting: function () { return self._state === 'connecting'; },
      readableType: this._options.datagramsReadableType != null ? 'bytes' : undefined,
      get transport() { return self; },
      send: function (u8, options) { return self.sendDatagram(u8, options); },
      maxDatagramSize: function () { return self.maxDatagramSize(); },
      owner: this._dgOwner,
      dgStats: this._dgStats
    };
    this.datagrams = createDatagrams(this._session);

    // A listener for the server's streams: those waiting go to it — once it
    // is in place ('newListener' comes just before).
    this.on('newListener', function (event) {
      if ((event === 'stream' || event === 'unidirectionalStream') && self._waiting.length > 0) {
        queueMicrotask(function () { self._handOver(); });
      }
    });

    // Start connection
    this._connect();
  }


  // ---- Connection setup ----

  // The session could not be established. `ready` rejects — that is how the
  // browser API reports it, and how a caller written against it (try/await
  // ready) expects to hear. 'error' is emitted as well, but only to listeners:
  // an unheard 'error' would throw from inside a socket callback and take the
  // process down where the browser would have rejected a promise.
  //
  // As in the browser the state becomes 'failed' and the connection is torn
  // down: a session refused by the server (a CONNECT answered 403, say) left
  // its QUIC connection open until the idle timeout.
  _failSetup(err) {
    if (this._state !== 'connecting') return;
    this._state = 'failed';
    this._attempt = (this._attempt || 0) + 1;   // whatever is still on its way is ignored from now
    // As the browser's: a WebTransportError, source 'session' — keeping the
    // cause's message and code (node:tls's, say) for a Node caller.
    if (!(err instanceof WebTransportError)) {
      var we = new WebTransportError(err.message, { source: 'session' });
      if (err.code) setErrorCode(we, err.code);
      we.cause = err;
      err = we;
    }
    this._readyReject(err);
    this._closedReject(err);
    this._destroyStreams(err, false);
    if (this.listenerCount('error') > 0) this.emit('error', err);
    // Over: 'close' now — the connection's own end is ignored from here.
    if (!this._closedDone) { this._closedDone = true; this.emit('close'); }
    // The connection goes: the one the CONNECT was sent on, or the one still
    // in its handshake (close() before `ready`: it went on, and `ready`
    // resolved once the server answered).
    var q = this._quic || this._handshaking;
    if (q) { try { q.close(0x0100, 'WebTransport session not established', true); } catch (e) {} }  // H3_NO_ERROR
  }

  _connect() {
    var host = this._hostname;
    var self = this;

    // Port 0 names no server (RFC 6335 §6): nothing can answer, and the
    // attempt waited for a handshake timeout — the browser fails it.
    if (this._port === 0) {
      process.nextTick(function () { self._failSetup(new WebTransportError('port 0 cannot be connected to', { source: 'session' })); });
      return;
    }

    if (/^[\d.]+$/.test(host) || host.indexOf(':') >= 0 || host === 'localhost') {
      var ip = (host === 'localhost') ? '127.0.0.1' : host;
      this._startQuic(ip);
    } else {
      dns.lookup(host, function (err, address) {
        if (self._state !== 'connecting') return;   // closed meanwhile
        if (err) { self._failSetup(err); return; }
        self._startQuic(address);
      });
    }
  }

  _startQuic(remoteIp) {
    var self = this;
    var remotePort = this._port;
    // Encrypted Client Hello: options.ech (the server's ECHConfigList), or
    // GREASE ECH — as a browser sends — unless echGrease is false. Rejected
    // with new keys, the session is attempted once more with them; an
    // attempt given up for another is ignored from then on.
    var attempt = this._attempt = (this._attempt || 0) + 1;
    var ech = this._echConfig || this._options.ech || null;

    this._udpSocket = createQuicClientSocket({
      remoteIp: remoteIp,
      remotePort: remotePort,
      hostname: this._hostname,
      // serverCertificateHashes pins the certificate instead of a CA (checked
      // in onConnect, before anything is sent on the connection).
      rejectUnauthorized: this._options.serverCertificateHashes ? false : this._options.rejectUnauthorized,
      key: this._options.key, cert: this._options.cert, passphrase: this._options.passphrase,
      ca: this._options.ca,
      // A saved session ('session' event) to resume with, as tls.connect
      // takes it. Not with serverCertificateHashes: a resumed handshake has
      // no certificate to pin, and the pin is the only check there is.
      session: this._options.serverCertificateHashes ? null : (this._options.session || null),
      onSocket: function (q) {
        if (attempt === self._attempt) self._handshaking = q;
        q.on('session', function (buf) { self.emit('session', buf); });
      },
      transportParams: this._transportParams,
      quicVersions: this._options.quicVersions,
      initialCongestionWindow: this._options.initialCongestionWindow,
      startupCap: this._options.startupCap,
      pmtuDiscovery: this._options.pmtuDiscovery,
      maxUdpPayloadSize: this._options.maxUdpPayloadSize,
      initialRtt: this._options.initialRtt,
      reorderWindow: this._options.reorderWindow,
      ech: ech,
      echGrease: !ech && this._options.echGrease !== false,
      // The key-exchange groups to offer (tls.connect's ecdhCurve; checked
      // in the constructor).
      ecdhCurve: this._options.ecdhCurve,
      sigalgs: this._options.sigalgs,

      onError: function (err) {
        if (attempt !== self._attempt) return;
        if (self._state === 'connecting' && err && err.code === 'ERR_ECH_REJECTED' && err.retryConfigs && !self._echRetried) {
          self._echRetried = true;
          self._echConfig = err.retryConfigs;
          self._startQuic(remoteIp);
          return;
        }
        if (self._state === 'connecting') { self._failSetup(err); return; }
        if (self.listenerCount('error') > 0) self.emit('error', err);
      },

      onConnect: function (q, s) {
        if (attempt !== self._attempt) { try { q.close(0x100, 'superseded', true); } catch (e) {} return; }
        self._quic = q;
        self._handshaking = null;
        self._udpSocket = s;
        q.on('closing', function () { if (attempt === self._attempt) self._connectionEnded(); });
        var pinErr = self._checkCertificateHashes();
        if (pinErr) { self._failSetup(pinErr); return; }
        self._h3 = new H3Connection({ quicConnection: self._quic, isServer: false, enableWebTransport: true });
        self._setupH3Handlers();
        self._sendConnect();
      },

      onClose: function () {
        if (attempt !== self._attempt) return;
        self._connectionEnded();
        // The helper closes the UDP socket.
      }
    });
  }


  // ---- H3 + QUIC event handlers ----

  _setupH3Handlers() {
    var self = this;

    // The CONNECT stream after the 200: capsules. The server's
    // CLOSE_WEBTRANSPORT_SESSION ends the session, its DRAIN asks us to wind
    // down ('draining').
    var readCapsules = createCapsuleReader(function (info) {
      if (!self.closeInfo) self.closeInfo = info;
      self._close(info);
    }, function () { self._drainingResolve(); self.emit('draining'); });
    this._h3.on('http_body', function (streamId, data) {
      if (streamId === self._sessionId && self._state === 'connected') readCapsules(data);
    });

    // CONNECT response headers
    this._h3.on('http_headers', function (streamId, headers) {
      if (streamId === self._sessionId) {
        var status = parseInt(headers[':status']) || 0;
        // 1xx (103 Early Hints) is not the answer to the CONNECT: it follows.
        if (status >= 100 && status < 200) return;
        // Any 2xx establishes the session (draft-ietf-webtrans-http3 §3.3,
        // as in the browser): a 204 failed here as "CONNECT failed".
        if (status >= 200 && status < 300) {
          var reliability = self._quic.maxDatagramSize() > 0 ? 'supports-unreliable' : 'reliable-only';
          if (self._options.requireUnreliable && reliability !== 'supports-unreliable') {
            self._failSetup(new Error('the server does not take datagrams (requireUnreliable)'));
            return;
          }
          self._state = 'connected';
          self.reliability = reliability;
          // The server's choice among options.protocols (WT-Protocol, a
          // structured-field string), if it made one from them.
          var chosen = parseSfString(headers['wt-protocol']);
          if (chosen !== null && self._protocols.indexOf(chosen) >= 0) self.protocol = chosen;
          self._responseHeaders = responseHeadersOf(headers);
          self._readyResolve();
          self.emit('ready');
          self._handOver();
          self.datagrams._flush();   // what was written before `ready`
        } else {
          self._failSetup(new Error('WebTransport CONNECT failed: HTTP ' + status));
          return;
        }
      }
    });

    // The server's streams. h3.js recognises them by their prefix — 0x41 or
    // 0x54 and this session's ID — exactly as it does the client's on the
    // server, and hands them over. They were picked out here by stream number
    // (3, 7, 11 taken for HTTP/3's own, 15 and up for WebTransport), true only
    // while the server opened its streams in that order and no others; and
    // their bytes were read past HTTP/3's back, uncredited and unbounded.
    this._h3.on('wt_stream', function (sessionId, streamId, data, fin, isBidi) {
      if (sessionId !== self._sessionId) return;
      var stream = self._newStream(streamId, isBidi ? 'bidi' : 'uni-in');
      if (data.byteLength > 0) stream._pushData(data);
      if (fin) stream._endData();
      self._waiting.push([isBidi ? 'stream' : 'unidirectionalStream', stream]);
      self._handOver();
    });
    this._h3.on('wt_data', function (sessionId, streamId, data, fin) {
      var stream = self._streams[streamId];
      if (!stream) return;
      if (data.byteLength > 0) stream._pushData(data);
      if (fin) stream._endData();
    });

    // The server gave up on a stream: it ends with the server's code.
    this._h3.on('stream_reset', function (streamId, code) { self._peerCancelled(streamId, 'stream_reset', code); });
    this._h3.on('stop_sending', function (streamId, code) { self._peerCancelled(streamId, 'stop_sending', code); });

    // The server ended the CONNECT stream with a FIN and no
    // CLOSE_WEBTRANSPORT_SESSION: a clean close, code 0 and an empty reason
    // (draft-ietf-webtrans-http3 §5: "semantically equivalent to
    // terminating it with a CLOSE_WEBTRANSPORT_SESSION capsule that has an
    // error code of 0 and an empty error string"). `closed` waited for the
    // QUIC idle timeout, and 'close' never came.
    this._h3.on('http_end', function (streamId) {
      if (streamId === self._sessionId && self._state === 'connected') self._close(self.closeInfo || { closeCode: 0, reason: '' });
    });

    // The session is over in HTTP/3 (its CONNECT stream ended): its streams,
    // already reset there, end here too. Still 'connected' here means it
    // ended with neither side closing it — no capsule, no FIN (a FIN closes
    // it cleanly just above): the server reset the CONNECT stream. As in
    // the browser, the session was lost, not closed.
    this._h3.on('wt_session_closed', function (sessionId) {
      if (sessionId !== self._sessionId) return;
      if (self._state === 'connected') self._sessionLost('the server reset the session\'s CONNECT stream');
    });

    // Datagrams — QUIC DATAGRAM payload = VarInt(quarter_stream_id) + app data (RFC 9297)
    this._quic.on('datagram', function (rawData) {
      if (!rawData || rawData.byteLength === 0) return;

      // Always parse VarInt quarter_stream_id from payload
      var result = readVarInt(rawData, 0);
      if (!result) return;
      var qsid = result.value;

      var expectedQsid = Math.floor(self._sessionId / 4);
      if (self._sessionId !== null && qsid === expectedQsid) {
        // One copy, into a buffer of its own: exact size, byteOffset 0 — not
        // slice() + Buffer.from(), which copied twice and put anything under
        // 4KB into Node's shared 8KB Buffer pool (see h3_server.js).
        var payload = new Uint8Array(rawData.byteLength - result.byteLength);
        payload.set(rawData.subarray(result.byteLength));
        self.datagrams._push(payload);
        self.emit('datagram', Buffer.from(payload.buffer));
      }
    });
  }

  // A stream of this session, ours or the server's (wt_stream.js), forgotten
  // when it closes.
  _newStream(streamId, kind, prefixLength) {
    var self = this;
    var stream = createWtStream(this._quic, streamId, kind, function () {
      if (self._streams[streamId] === stream) delete self._streams[streamId];
      if (self._h3) self._h3.releaseWebTransportStream(streamId);
    }, prefixLength, this._sched, this._sessionId);
    stream._owner = this;   // its sendGroup must be one of this session's
    this._streams[streamId] = stream;
    return stream;
  }

  // The peer gave up on one direction of a stream: that direction ends (the
  // stream is forgotten when it closes — see _newStream).
  _peerCancelled(streamId, how, code) {
    var stream = this._streams[streamId];
    if (stream) stream._peerCancelled(how, code);
  }

  // Hand the server's waiting streams to whoever listens for them, in
  // order; the rest keep waiting (see _waiting).
  // A Node listener first; otherwise the browser API's queue, once it is
  // read (incomingBidirectionalStreams yields the Duplex, which has the
  // browser's .readable and .writable; incomingUnidirectionalStreams yields
  // the stream's ReadableStream, as the browser does).
  _handOver() {
    if (this._state !== 'connected') return;
    var keep = [];
    for (var i = 0; i < this._waiting.length; i++) {
      var w = this._waiting[i];
      if (w[1].destroyed) continue;
      if (this.listenerCount(w[0]) > 0) this.emit(w[0], w[1]);
      else if (this._incoming[w[0]]) this._incoming[w[0]].enqueue(w[0] === 'stream' ? w[1] : w[1].readable);
      else keep.push(w);
    }
    this._waiting = keep;
  }

  _incomingStreams(event) {
    var self = this;
    var rs = new ReadableStream({
      start: function (controller) {
        self._incoming[event] = controller;
        if (self._incomingEnd) { if (self._incomingEnd.error) controller.error(self._incomingEnd.error); else controller.close(); }
      }
    });
    queueMicrotask(function () { self._handOver(); });
    return rs;
  }

  // The session is over (the browser's "cleanup"): each stream still open
  // goes with WT_SESSION_GONE (draft-ietf-webtrans-http3 §4.6), not an
  // application code, and its browser views fail with `err` — the session's
  // error when it was lost or never established, the same object `closed`
  // rejects with; an AbortError when we closed it; a WebTransportError when
  // the server did. Closed (`closed` true), the incoming-stream queues and
  // the datagrams' readable close; otherwise they fail with `err` too.
  _destroyStreams(err, closed) {
    if (this._cleanedUp) return;
    this._cleanedUp = true;
    for (var id in this._streams) { this._streams[id]._sessionGone(err); this._streams[id].destroy(); }
    for (var i = 0; i < this._waiting.length; i++) { var w = this._waiting[i][1]; if (w._sessionGone) w._sessionGone(err); w.destroy(); }
    this._waiting = [];
    for (var ev in this._incoming) {
      if (this._incoming[ev]) { try { if (closed) this._incoming[ev].close(); else this._incoming[ev].error(err); } catch (e) {} }
    }
    this._incomingEnd = { error: closed ? null : err };   // for a queue first read after this
    this.datagrams._close(closed ? null : err);
  }

  // serverCertificateHashes (the browser's way to trust a certificate it
  // cannot verify by CA): the leaf's SHA-256 must be one of them, and — as
  // the browser requires of such a certificate — it must be valid now, for
  // no more than 14 days. Checked once the handshake is done and before
  // anything is sent: the handshake has already proved the server holds the
  // certificate's key. null when it passes (or none were given).
  _checkCertificateHashes() {
    var hashes = this._options.serverCertificateHashes;
    if (!hashes || !hashes.length) return null;
    var chain = this._quic.getPeerCertificateChain && this._quic.getPeerCertificateChain();
    if (!chain || !chain.length) return new Error('serverCertificateHashes: the server sent no certificate');
    var der = Buffer.from(chain[0]);
    var digest = createHash('sha256').update(der).digest();
    var match = hashes.some(function (h) {
      if (!h || String(h.algorithm).toLowerCase() !== 'sha-256' || !h.value) return false;
      var v = ArrayBuffer.isView(h.value) ? Buffer.from(h.value.buffer, h.value.byteOffset, h.value.byteLength) : Buffer.from(h.value);
      return v.length === digest.length && v.equals(digest);
    });
    if (!match) return new Error('serverCertificateHashes: the certificate matches none of them');
    var cert = new X509Certificate(der), now = Date.now();
    var from = Date.parse(cert.validFrom), to = Date.parse(cert.validTo);
    if (!(now >= from && now <= to)) return new Error('serverCertificateHashes: the certificate is not valid now');
    if (to - from > 14 * 24 * 3600 * 1000) return new Error('serverCertificateHashes: the certificate is valid for more than 14 days');
    return null;
  }

  // ---- Send CONNECT ----

  _sendConnect() {
    // Send H3 control streams (SETTINGS)
    this._h3.sendControlStreams();

    // The CONNECT goes on the first bidirectional stream; its number is the
    // session's ID, and the server's streams for it carry that ID — so they
    // are recognised from now on, even one that overtakes the 200.
    this._sessionId = this._quic.nextLocalStreamId(true);
    this._sched = wtScheduling(this._quic, this._sessionId);

    // Send Extended CONNECT — no FIN (session stays open)
    var headers = {
      ':method': 'CONNECT',
      ':protocol': 'webtransport',
      ':scheme': 'https',
      ':authority': this._authority,
      ':path': this._path
    };
    for (var f in this._connectFields) headers[f] = this._connectFields[f];
    // The browser's `protocols`: the application protocols it offers, as a
    // structured-field list of strings; the server answers with WT-Protocol.
    if (this._protocols.length > 0) {
      headers['wt-available-protocols'] = this._protocols.map(sfString).join(', ');
    }

    this._h3.sendHeaders(this._sessionId, headers, false);
    this._h3.registerWebTransportSession(this._sessionId);
  }


  // ============================================================
  //  Public API
  // ============================================================

  // The browser's stream options — sendOrder, sendGroup, waitUntilAvailable
  // (wt_stream's openWtStream, as the server's). As the browser's
  // createBidirectionalStream / createUnidirectionalStream:
  //   a sendGroup of another session's      rejects, TypeError;
  //   the session over ('closed', 'failed')  rejects, InvalidStateError —
  //     also when it ends while the stream waits to be opened;
  //   still connecting                       waits for `ready` (it was refused);
  //   past the server's limit, without waitUntilAvailable
  //                                          rejects, QuotaExceededError;
  // otherwise resolved once the stream is open — at once if the server allows
  // it, or when it does (waitUntilAvailable).
  _openStream(bidi, options) {
    var self = this;
    options = options || {};
    if (options.sendGroup != null && options.sendGroup._owner !== this) {
      return Promise.reject(new TypeError('options.sendGroup belongs to another WebTransport session'));
    }
    if (this._state === 'closed' || this._state === 'failed') return Promise.reject(invalidState('the session is ' + this._state));
    var up = this._state === 'connected' ? Promise.resolve() : this.ready;
    return up.then(function () {
      if (self._state !== 'connected') throw invalidState('the session is ' + self._state);
      return new Promise(function (resolve, reject) {
        var stream = openWtStream(self._h3, self._quic, self._sessionId, bidi, options,
          function (id, kind, prefix) { return self._newStream(id, kind, prefix); },
          function (err, st) {
            if (!err) resolve(st);
            else reject(self._state !== 'connected' ? invalidState('the session is ' + self._state) : new WebTransportError(err.message, { source: 'session' }));
          });
        if (!stream) reject(new DOMException('the server allows no more streams now', 'QuotaExceededError'));
      });
    }, function () {
      throw invalidState('the session was not established');
    });
  }

  /** Whether a stream could be opened now, within the server's MAX_STREAMS — as the server's res.canOpenStream(). */
  canOpenStream(options) {
    return this._state === 'connected' && !!this._quic && this._quic.canOpenStream(!!(options && options.bidirectional));
  }

  /**
   * A bidirectional stream: a Duplex (wt_stream.js) — and, as the browser's
   * WebTransportBidirectionalStream, it has .readable and .writable.
   */
  createBidirectionalStream(options) {
    return this._openStream(true, options);
  }

  /**
   * A unidirectional stream: as the browser's, a WritableStream
   * (getWriter(), pipeTo() into it) — and Node's Writable on the same object,
   * whole: write() / 'drain', end(), resetStream(), its events, the
   * writable* state, and readable.pipe() into it, as the server's stream is.
   * Only write(), end() and a few events were carried over: there was no
   * writableLength, no destroyed, and pipe() failed on the missing emit().
   */
  createUnidirectionalStream(options) {
    return this._openStream(false, options).then(function (stream) {
      var w = stream.writable;
      UNI_METHODS.forEach(function (m) {
        if (!(m in w) || m === 'getStats') w[m] = stream[m].bind(stream);
      });
      UNI_STATE.forEach(function (k) {
        Object.defineProperty(w, k, { configurable: true, get: function () { return stream[k]; } });
      });
      return w;
    });
  }

  /** The browser's incoming streams, as ReadableStreams of streams. */
  get incomingBidirectionalStreams() {
    return this._incomingBidi || (this._incomingBidi = this._incomingStreams('stream'));
  }
  get incomingUnidirectionalStreams() {
    return this._incomingUni || (this._incomingUni = this._incomingStreams('unidirectionalStream'));
  }

  /** The server's answer to the CONNECT (an immutable Headers) — null until the session is up. */
  get responseHeaders() { return this._responseHeaders; }

  /** As the browser's: no WebTransport over HTTP/2 (reliable-only) here — HTTP/3 alone. */
  static get supportsReliableOnly() { return false; }

  /**
   * The browser's exportKeyingMaterial(label, context, outputLength): keying
   * material of this session's own, from the TLS exporter (see wt_stream's
   * exportSessionKeyingMaterial) — a Promise of a Uint8Array. While the
   * session is being set up, it waits for it; a session that is over (or
   * ends meanwhile) is an InvalidStateError.
   */
  exportKeyingMaterial(label, context, outputLength) {
    var self = this, a;
    try { a = exporterArgs(arguments); } catch (e) { return Promise.reject(e); }
    if (this._state === 'closed' || this._state === 'failed') return Promise.reject(invalidState('the session is ' + this._state));
    var up = this._state === 'connected' ? Promise.resolve() : this.ready;
    return up.then(function () {
      if (self._state !== 'connected') throw invalidState('the session is ' + self._state);
      return exportSessionKeyingMaterial(self._quic, self._sessionId, a);
    }, function () { throw invalidState('the session was not established'); });
  }

  /** The browser's WebTransportSendGroup — of this session's alone. */
  createSendGroup() {
    return createSendGroup(this);
  }

  /**
   * The browser's getStats(): the connection's figures, as QUIC has them.
   * A session that failed has none: InvalidStateError, as the browser's.
   */
  getStats() {
    if (this._state === 'failed') return Promise.reject(invalidState('the session failed'));
    return sessionStats(this._session);   // wt_stream: as the server's res.getStats()
  }

  // The browser's anticipatedConcurrentIncoming… hints: null or 0 to 65535
  // (a TypeError otherwise, the value unchanged). Given to the constructor,
  // they raise the stream limits we grant the server at the start, if they
  // are above them (see _hintedTransportParams).
  get anticipatedConcurrentIncomingUnidirectionalStreams() { return this._hintUni; }
  set anticipatedConcurrentIncomingUnidirectionalStreams(v) { this._hintUni = streamHint(v, 'anticipatedConcurrentIncomingUnidirectionalStreams'); }
  get anticipatedConcurrentIncomingBidirectionalStreams() { return this._hintBidi; }
  set anticipatedConcurrentIncomingBidirectionalStreams(v) { this._hintBidi = streamHint(v, 'anticipatedConcurrentIncomingBidirectionalStreams'); }

  // options.transportParams, with the hints applied: the server may open as
  // many streams as anticipated from the start (unidirectional ones on top
  // of the three HTTP/3 keeps for itself). A limit set in transportParams is
  // the caller's and stays.
  _hintedTransportParams() {
    var given = this._options.transportParams || {};
    var base = defaultTransportParams(given);
    var tp = Object.assign({}, given);
    if (this._hintBidi !== null && given.initialMaxStreamsBidi == null && this._hintBidi > base.initial_max_streams_bidi) {
      tp.initialMaxStreamsBidi = this._hintBidi;
    }
    if (this._hintUni !== null && given.initialMaxStreamsUni == null && this._hintUni + 3 > base.initial_max_streams_uni) {
      tp.initialMaxStreamsUni = this._hintUni + 3;
    }
    return tp;
  }

  /**
   * Send an unreliable datagram.
   */
  // As the server's res.sendDatagram: true when queued (sent under
  // congestion control, never retransmitted), false when it cannot be sent at
  // all — larger than maxDatagramSize(), or the server takes no datagrams.
  // options { sendOrder, sendGroup }: its place among the session's streams
  // (wt_stream's wtScheduling); without them, ahead of every stream.
  sendDatagram(data, options) {
    if (this._state !== 'connected') throw new Error('WebTransport is not connected');
    if (typeof data === 'string') data = Buffer.from(data);
    if (Buffer.isBuffer(data)) data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    // VarInt(quarter stream ID) + payload (RFC 9297)
    return this._quic.sendDatagram(wt_datagram_payload(this._sessionId, data), this._sched.forDatagram(options), this._dgOwner);
  }

  /** The largest datagram this session can send, in bytes of payload. */
  maxDatagramSize() {
    if (this._state !== 'connected') return 0;
    return Math.max(0, this._quic.maxDatagramSize() - wt_datagram_payload(this._sessionId, new Uint8Array(0)).byteLength);
  }

  /**
   * Close the WebTransport session.
   */
  // The QUIC connection is over: 'closing' (the peer's CONNECTION_CLOSE, or
  // ours) — as the browser hears it, at once — or 'close' at the end of the
  // closing/draining period, whichever comes first; the second finds it done.
  _connectionEnded() {
    // Gone before the CONNECT was answered — after the QUIC handshake, so
    // onError did not see it. `ready` must settle (it rejects in the
    // browser too); left pending, the caller would wait forever.
    if (this._state === 'connecting') {
      var err = new Error('WebTransport connection closed before the session was established');
      err.code = 'ERR_WEBTRANSPORT_SESSION_FAILED';
      this._failSetup(err);
      return;
    }
    // Lost while established: neither a CLOSE_WEBTRANSPORT_SESSION, nor
    // the CONNECT stream's FIN, nor our close() — the connection went
    // (an error, the idle timeout, the server gone). `closed` rejects,
    // as the browser's does; it used to resolve { closeCode: 0 }, which
    // is a close the peer asked for.
    if (this._state === 'connected') { this._sessionLost('the connection was lost'); return; }
    this._sessionClosed();
  }

  // The session ended without being closed — the connection lost, or the
  // CONNECT stream reset. As the browser's: the state is 'failed', `closed`
  // rejects with a WebTransportError (source 'session'), and every stream,
  // the incoming-stream queues and the datagrams fail with that same error
  // object; 'close' is emitted all the same, so a Node listener hears the end
  // either way. The QUIC connection, this session's alone, goes with it.
  _sessionLost(message) {
    if (this._closedDone) return;
    this._state = 'failed';
    this._closedDone = true;
    var err = new WebTransportError('WebTransport session lost: ' + message, { source: 'session' });
    setErrorCode(err, 'ERR_WEBTRANSPORT_SESSION_LOST');
    var pc = this._quic && this._quic.context && this._quic.context.peer_close;
    if (pc) err.quicError = { code: pc.error, application: !!pc.application, reason: pc.reason || '' };
    this._destroyStreams(err, false);
    this._closedReject(err);
    this.emit('close');
    if (this._quic) { try { this._quic.close(0x0100, 'WebTransport session lost', true); } catch (e) {} }
  }

  // The session is over: `closed` resolves and 'close' is emitted, once. As
  // in the browser, closed resolves with the code and reason the session was
  // closed with — the server's CLOSE_WEBTRANSPORT_SESSION, or ours — and
  // { closeCode: 0, reason: '' } when there was none. At the session's close,
  // not the QUIC connection's: that one lingers in its closing period
  // (RFC 9000 §10.2) for three PTOs after, and `closed` waited it out.
  // streamError: what the streams' browser views fail with (see close()).
  _sessionClosed(streamError) {
    if (this._closedDone) return;
    this._closedDone = true;
    this._destroyStreams(streamError || new WebTransportError('the session is closed', { source: 'session' }), true);
    this._closedResolve(this.closeInfo || { closeCode: 0, reason: '' });
    this.emit('close');
  }

  // The browser's close(): before the session is up, it is abandoned —
  // `ready` and `closed` reject with a WebTransportError (source 'session')
  // and the connection goes; `ready` used to resolve all the same once the
  // server answered. Once up, CLOSE_WEBTRANSPORT_SESSION with the code and
  // reason, and `closed` resolves with them (the reason as given; what goes
  // on the wire is cut at 1024 bytes); the streams' views fail with an
  // AbortError, as the browser's.
  close(info) {
    if (this._state === 'closed' || this._state === 'failed') return;
    if (this._state === 'connecting') {
      this._failSetup(new WebTransportError('the session was closed before it was established', { source: 'session' }));
      return;
    }
    this._close(info, new DOMException('the session was closed', 'AbortError'));
  }

  // Closed: by us (close()), or by the server (its CLOSE_WEBTRANSPORT_SESSION
  // or the CONNECT stream's FIN — then a WebTransportError for the streams).
  _close(info, streamError) {
    if (this._state === 'closed' || this._state === 'failed') return;
    this._state = 'closed';

    // CLOSE_WEBTRANSPORT_SESSION with the code and reason, and the CONNECT
    // stream's end — so the server learns them, as from a browser's
    // wt.close(). Then the QUIC connection, which is this session's alone,
    // once the capsule has left: closed at once, it was dropped unsent.
    var quic = this._quic;
    if (!this.closeInfo) this.closeInfo = { closeCode: (info && info.closeCode) || 0, reason: (info && info.reason) || '' };
    if (quic) {
      var closeQuic = function () { quic.close(0x0100, 'WebTransport closed', true); };   // H3_NO_ERROR
      if (this._h3 && this._sessionId !== null) {
        this._h3.sendBody(this._sessionId, wtCloseCapsule(this.closeInfo.closeCode, this.closeInfo.reason), true);
        quic.whenStreamSent(this._sessionId, 0, closeQuic);
        var t = setTimeout(closeQuic, 1000);   // a capsule that cannot leave does not hold the close
        if (t.unref) t.unref();
      } else {
        closeQuic();
      }
    }
    this._sessionClosed(streamError || new WebTransportError('the server closed the session', { source: 'session' }));
  }

  /**
   * Current state.
   */
  get state() {
    return this._state;
  }

  /**
   * URL this session connected to.
   */
  get url() {
    var h = this._hostname.indexOf(':') >= 0 ? '[' + this._hostname + ']' : this._hostname;
    return 'https://' + h + ':' + this._port + this._path;
  }
}


export { WebTransport, WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
         WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream };
