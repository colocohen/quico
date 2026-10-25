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
//  A WebTransport stream, as a Node stream — one for both sides
// ============================================================
//
// The server (h3_server) and the client (webtransport.js) build their
// streams here, so they behave alike: a Duplex for a bidirectional stream,
// a Readable for the peer's unidirectional one ('uni-in'), a Writable for
// ours ('uni-out'). The client had classes of its own, which had none of
// what follows.
//
// Reading: what the peer sends is credited back to it as the application
// reads (_read), not as it arrives — as for a request body. The peer can be
// one stream window ahead of the reader, no more; a stream nobody read was
// taken in whole.
//
// Each direction can be given up on its own, with a code of the
// application's (draft-ietf-webtrans-http3 §4.4, mapped by wtErrorToH3):
//   stream.resetStream(code)  — stop sending: RESET_STREAM; what was written
//                               and not yet sent is dropped;
//   stream.stopSending(code)  — stop reading: STOP_SENDING; the peer stops.
// destroy() with a direction unfinished does the same with code 0 — the peer
// is told, as a browser is when a WebTransport stream is aborted or
// cancelled. It was told nothing: what was queued kept going out, and the
// peer waited for a FIN that would not come.
//
// The peer giving up on a direction (RESET_STREAM or STOP_SENDING, through
// stream._peerCancelled) ends that direction: 'peerReset' / 'peerStopSending'
// with the application's code (stream.streamErrorCode; null when the peer
// sent none). The other direction of a bidirectional stream goes on; the
// stream closes ('close') once both are over — with an Error carrying the
// code only to an 'error' listener, since a cancelled stream is ordinary
// traffic, not a crash.
//
// And the browser's shape too: stream.readable and stream.writable are WHATWG
// ReadableStream / WritableStream views of it, as a browser's
// WebTransportBidirectionalStream has them — so code written against the
// browser API runs here: getReader(), getWriter(), pipeTo(); reader.cancel()
// and writer.abort() with a WebTransportError({ streamErrorCode }) send
// STOP_SENDING / RESET_STREAM with that code; a stream the peer reset or
// stopped fails reads or writes with a WebTransportError carrying its code.
// The reader reads only when asked, so one that does not read holds the peer
// back as a Node consumer does (the client's classes read with on('data'),
// which drained the stream whatever the reader did). Node's own converters
// (Duplex.toWeb) would not do for a bidirectional stream: their reader ends
// only once our side has finished writing too, where the browser's ends when
// the peer finishes. Node's stream utilities — pipe(), finished(),
// pipeline() — are unaffected by the two names.

import { Duplex, Readable, Writable } from 'node:stream';
import { wtErrorToH3, h3ErrorToWt } from './h3.js';
import { wt_stream_header, creditAsRead } from './utils.js';

// quic: the QUIC connection. kind: 'bidi', 'uni-in' or 'uni-out'. onClose:
// called once, when the stream is done with — for the owner's bookkeeping.
// prefixLength: the bytes of WebTransport prefix we sent on it ourselves (on a
// stream we opened), which are not the application's in its statistics.
// sched: its session's wtScheduling (below) — where its sending part goes in
// QUIC's scheduler. sessionId: its session's (the CONNECT stream's) ID.
function createWtStream(quic, wtStreamId, kind, onClose, prefixLength, sched, sessionId) {
  var sends = kind !== 'uni-in', reads = kind !== 'uni-out';
  var sendDone = !sends;   // the FIN queued, or the direction reset
  var recvDone = !reads;   // the FIN received, or reading stopped
  var finSent = false;
  // For getStats(), as the browser's streams report them.
  var stats = { bytesWritten: 0, bytesSent: 0, bytesAcknowledged: 0, bytesReceived: 0 };
  prefixLength = prefixLength || 0;

  function write(chunk, encoding, cb) {
    if (sendDone) { cb(); return; }   // reset: nothing more goes out
    if (typeof chunk === 'string') chunk = Buffer.from(chunk, encoding);
    stats.bytesWritten += chunk.byteLength;
    quic.sendStream(wtStreamId, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength), false);
    quic.whenStreamSent(wtStreamId, stream.writableHighWaterMark, cb);   // backpressure
  }
  // The FIN queued; 'committed' once it and every byte are acknowledged.
  function final(cb) {
    if (!sendDone) {
      sendDone = true; finSent = true;
      quic.sendStream(wtStreamId, new Uint8Array(0), true);
      if (quic.whenStreamCommitted) quic.whenStreamCommitted(wtStreamId, function () {
        if (sendReset || stream._writeStopped) return;
        committed = true;
        stream.emit('committed');
      });
    }
    cb();
  }
  var committed = false;

  // What QUIC has sent and had acknowledged of it, in the application's bytes.
  // A stream whose every byte and FIN were acknowledged is gone from QUIC's
  // table — all of it, then.
  function sendStats() {
    var st = quic.context && quic.context.send_streams[wtStreamId];
    if (st) {
      stats.bytesSent = Math.max(stats.bytesSent, Math.min(stats.bytesWritten, st.max_sent_offset - prefixLength));
      var acked = st.acked_ranges.length >= 2 && st.acked_ranges[0] === 0 ? st.acked_ranges[1] - prefixLength : 0;
      stats.bytesAcknowledged = Math.max(stats.bytesAcknowledged, Math.min(stats.bytesWritten, acked));
    } else if (finSent) {
      stats.bytesSent = stats.bytesAcknowledged = stats.bytesWritten;
    }
    return { bytesWritten: stats.bytesWritten, bytesSent: stats.bytesSent, bytesAcknowledged: stats.bytesAcknowledged };
  }
  function recvStats() {
    return { bytesReceived: stats.bytesReceived, bytesRead: stats.bytesReceived - (stream.readableLength || 0) };
  }

  // The browser's send order and group (WebTransportSendStream), handed to
  // QUIC's scheduler as they change (see wtScheduling).
  var sendOrder = 0, sendGroup = null;
  function sendProps(target) {
    Object.defineProperty(target, 'sendOrder', { configurable: true, enumerable: true,
      get: function () { return sendOrder; }, set: function (v) { sendOrder = Number(v) || 0; schedule(); } });
    Object.defineProperty(target, 'sendGroup', { configurable: true, enumerable: true,
      get: function () { return sendGroup; }, set: function (g) {
        // A group of another session's (the browser's: InvalidStateError).
        if (g != null && g._owner && stream._owner && g._owner !== stream._owner) {
          throw new DOMException('this send group belongs to another WebTransport session', 'InvalidStateError');
        }
        if (sendGroup && sendGroup._remove) sendGroup._remove(sendStats);
        sendGroup = g || null;
        if (sendGroup && sendGroup._add) sendGroup._add(sendStats);
        schedule();
      } });
  }
  function schedule() {
    if (sends && sched && !sendDone) quic.setStreamPriority(wtStreamId, sched.forStream(sendGroup, sendOrder));
  }
  schedule();

  var stream = kind === 'bidi' ? new Duplex({ read: function () {}, write: write, final: final })
             : kind === 'uni-in' ? new Readable({ read: function () {} })
             : new Writable({ write: write, final: final });

  stream._streamId = wtStreamId;
  stream._sessionId = sessionId;
  if (kind === 'bidi') Object.defineProperty(stream, '_wtBidirectional', { value: true });   // instanceof WebTransportBidirectionalStream

  // The code what is still open goes with when the stream is destroyed:
  //   destroy(err) with err.streamErrorCode — the browser's
  //     WebTransportError({ streamErrorCode }) — that application code;
  //   its session gone (_sessionGone) — WT_SESSION_GONE, an HTTP/3 code of
  //     its own, not an application one (draft-ietf-webtrans-http3 §4.6:
  //     "MUST reset ... with WT_SESSION_GONE");
  //   otherwise application code 0.
  // destroy() always sent code 0: the application's code was dropped, and a
  // session's end reached its streams as an ordinary cancel.
  var closeH3Code = null;
  var WT_SESSION_GONE = 0x170d7b68;
  // At once, not when 'close' comes a tick later: the session's end is
  // often the connection's (a WebTransport client's own), whose
  // CONNECTION_CLOSE would go first and these with it.
  //
  // `err` is what the browser's views fail with (the WHATWG readable and
  // writable): the session's own error — the very object its `closed`
  // rejects with when the session was lost, an AbortError when we closed it
  // (W3C WebTransport, "cleanup"). Without one, a WebTransportError, source
  // 'session'. The views failed only on the next read or write, and a
  // reader or writer waiting on `closed` waited for good.
  stream._sessionGone = function (err) {
    if (!stream._sessionError) stream._sessionError = err || new WebTransportError('the session is gone', { source: 'session' });
    failViews(stream._sessionError);
    if (closeH3Code === null) closeH3Code = WT_SESSION_GONE;
    if (!sendDone) { sendDone = true; sendReset = true; resetSending(closeH3Code, 0); }
    if (!recvDone) { recvDone = true; readStopped = true; quic.stopSending(wtStreamId, closeH3Code); }
  };
  var baseDestroy = stream.destroy;
  stream.destroy = function (err) {
    if (closeH3Code === null && err && typeof err.streamErrorCode === 'number') closeH3Code = wtErrorToH3(err.streamErrorCode);
    return baseDestroy.apply(this, arguments);
  };
  stream.streamErrorCode = null;
  stream._bytesWritten = function () { return stats.bytesWritten; };   // a writer's commit()
  // Its QUIC stream ID and its session's — read-only, for logs and maps.
  Object.defineProperty(stream, 'id', { enumerable: true, get: function () { return wtStreamId; } });
  Object.defineProperty(stream, 'sessionId', { enumerable: true, get: function () { return sessionId; } });

  // The WHATWG views (see above), made on first use — with what the
  // browser's WebTransportReceiveStream / WebTransportSendStream add.
  //
  // Each view fails at once when its direction is given up on — the peer's
  // RESET_STREAM fails the readable, its STOP_SENDING the writable, the
  // session's end both — so a reader or writer waiting on `closed` hears it,
  // as in the browser; not only the next read or write. One made after that
  // starts failed.
  var webReadable = null, webWritable = null;
  var readView = null, writeView = null;   // { fail(err) } of each, once made
  function failRead(err) { if (readView) readView.fail(err); }
  function failWrite(err) { if (writeView) writeView.fail(err); }
  function failViews(err) { failRead(err); failWrite(err); }
  if (reads) {
    Object.defineProperty(stream, 'readable', { configurable: true, get: function () {
      if (!webReadable) {
        readView = webReadableOf(stream, recvStats);
        webReadable = readView.stream;
        if (stream._sessionError) failRead(stream._sessionError);
        else if (stream._readReset && !stream.readableLength) failRead(endedError(stream));
      }
      return webReadable;
    } });
  }
  if (sends) {
    sendProps(stream);
    Object.defineProperty(stream, 'writable', { configurable: true, get: function () {
      if (!webWritable) {
        writeView = webWritableOf(stream, sendStats, quic, wtStreamId);
        webWritable = writeView.stream;
        sendProps(webWritable);
        if (stream._sessionError) failWrite(stream._sessionError);
        else if (stream._writeStopped) failWrite(endedError(stream));
      }
      return webWritable;
    } });
  }
  stream.getStats = function () {
    return Promise.resolve(Object.assign({}, sends ? sendStats() : {}, reads ? recvStats() : {}));
  };

  // Credit for what the application has read (utils' creditAsRead): a
  // stream nobody reads holds one window, not a window and Node's buffer.
  var received = reads ? creditAsRead(stream, function (n) { quic.creditStream(wtStreamId, n); }) : null;
  stream._pushData = function (data) {
    if (recvDone) return;
    if (data instanceof Uint8Array) data = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    stats.bytesReceived += data.byteLength;
    received(data.byteLength);
    stream.push(data);
  };
  stream._endData = function () {
    if (recvDone) return;
    recvDone = true;
    stream.push(null);
  };

  // The stream closes once both directions are over — each ended by a FIN
  // (sent, or received and read to the end), a reset, or a stop, by either
  // side, in any order. That was checked at some of those points and not
  // others: a stream whose reading we had stopped stayed open for good once
  // its writing finished after.
  var readStopped = false;   // we stopped reading it (stopSending)
  var sendReset = false;     // we reset it (resetStream; or the stream went with its direction open)
  stream._readReset = false;     // the peer reset it (RESET_STREAM)
  stream._writeStopped = false;  // the peer stopped reading it (STOP_SENDING)

  // Each direction's state, read-only — null for the one a unidirectional
  // stream does not have. A 'drain' says the writer may write; sendState
  // says whether what it writes still goes anywhere.
  //   sendState: 'open', 'finished' (our FIN is queued), 'reset' (we gave up
  //              sending), 'stopped' (the peer asked us to stop: STOP_SENDING)
  //   recvState: 'open', 'finished' (the peer's FIN arrived), 'reset' (the
  //              peer gave up sending: RESET_STREAM), 'stopped' (we stopped
  //              reading: stopSending)
  Object.defineProperty(stream, 'sendState', { enumerable: true, get: function () {
    if (!sends) return null;
    return stream._writeStopped ? 'stopped' : sendReset ? 'reset' : committed ? 'committed' : finSent ? 'finished' : 'open';
  } });
  Object.defineProperty(stream, 'recvState', { enumerable: true, get: function () {
    if (!reads) return null;
    return stream._readReset ? 'reset' : readStopped ? 'stopped' : recvDone ? 'finished' : 'open';
  } });
  function readOver() { return !reads || readStopped || stream._readReset || stream.readableEnded; }
  function writeOver() { return !sends || sendDone; }
  function closeIfDone(err) {
    if (!stream.destroyed && readOver() && writeOver()) stream.destroy(err || null);
  }
  if (reads) stream.on('end', function () { closeIfDone(); });
  if (sends) stream.on('finish', function () { closeIfDone(); });

  // options.reliableSize: the first bytes the application wrote that still
  // reach the peer, whole, before the reset (RESET_STREAM_AT, draft-ietf-
  // quic-reliable-stream-reset) — a MOQT subgroup's header, say. More than
  // was written: what was written. Only with a peer that takes
  // RESET_STREAM_AT (stream.reliableResetSupported); without, a RESET_STREAM.
  //
  // After end() too (RFC 9000 §3.1: "Data Sent" → "Reset Sent"), for as long
  // as what was written is not all acknowledged: a MOQT subgroup past its
  // delivery timeout, ended but still on its way, is dropped instead of sent
  // to the end. It did nothing once end() had been called — the FIN queued
  // counted as the direction being over — and the stream went on being sent
  // and resent until it had all arrived. Everything acknowledged already:
  // nothing to reset (false). Returns whether a reset was sent.
  stream.resetStream = function (code, options) {
    if (!sends || sendReset || stream._writeStopped) return false;
    var reliable = options && options.reliableSize != null ? Number(options.reliableSize) : 0;
    if (!(reliable >= 0) || Math.floor(reliable) !== reliable) throw new RangeError('reliableSize must be a non-negative integer, got ' + (options && options.reliableSize));
    var wasOpen = !sendDone;
    if (!resetSending(wtErrorToH3(code || 0), reliable) && !wasOpen) return false;   // all delivered
    sendDone = true;
    sendReset = true;
    if (stream._onClosePending) stream._onClosePending(true);   // given up before it was open
    if (wasOpen) closeIfDone();
    return true;
  };
  // The sending part reset. Our stream's header (signal value and session
  // ID) is always delivered (draft-ietf-webtrans-http3 §4.4: "MUST use the
  // RESET_STREAM_AT frame with a Reliable Size set to at least the size of
  // the WebTransport header") — without it the peer cannot tell which
  // session the reset is for — and `reliable` bytes of the application's
  // after it. QUIC sends RESET_STREAM_AT when the peer takes it, RESET_STREAM
  // otherwise.
  function resetSending(h3code, reliable) {
    return quic.resetStream(wtStreamId, h3code, prefixLength + (reliable || 0));
  }
  Object.defineProperty(stream, 'reliableResetSupported', { enumerable: true,
    get: function () { return !!quic.resetStreamAtSupported; } });
  stream.stopSending = function (code) {
    if (recvDone) return;
    recvDone = true;
    readStopped = true;
    quic.stopSending(wtStreamId, wtErrorToH3(code || 0));   // and its held credit goes
    closeIfDone();
  };

  // The peer gave up on one direction, with the application's code:
  // RESET_STREAM ends our reading, STOP_SENDING our sending (QUIC has
  // answered that one with RESET_STREAM already). The other direction goes
  // on, as in the browser — a bidirectional stream's two halves are
  // independent; the peer giving up on one used to destroy the stream, and
  // reset the half it had not touched. 'peerReset' / 'peerStopSending' (code)
  // say which ended, stream.streamErrorCode holds the code, and the stream
  // closes once both directions are over: at once when the other one already
  // is — then with an Error carrying the code, for an 'error' listener only
  // (a cancelled stream is ordinary traffic, not a crash).
  //
  // Reading reset: what was read stands, and the readable side ends (its
  // WHATWG view fails with the code instead — a reset is not a FIN). Sending
  // stopped: writes from then on are dropped (the WHATWG view's fail).
  stream._peerCancelled = function (how, h3code) {
    if (stream.destroyed) return;
    // WT_SESSION_GONE is not the peer giving up on this stream: it is its
    // session ending (draft-ietf-webtrans-http3 §4.6 — every stream of a
    // closed session is reset or stopped with it). The stream ends as its
    // session's streams end here (_sessionGone): both directions, the views
    // failed with the session's error, closed without an 'error'. Taken as a
    // cancel, it was destroyed with one whenever an 'error' listener was there
    // — and pipe() adds one of its own, which re-throws: a server echoing a
    // stream with s.pipe(s) crashed whenever a client closed its session.
    if (h3code === WT_SESSION_GONE) {
      stream._sessionGone();
      stream.destroy();
      return;
    }
    var stop = how === 'stop_sending';
    if (stop ? stream._writeStopped : stream._readReset) return;
    // The RESET_STREAM that answers our own STOP_SENDING (RFC 9000 §3.5): our
    // doing, not the peer giving up — reported as 'peerReset' it was.
    if (!stop && readStopped) return;
    stream.streamErrorCode = h3ErrorToWt(h3code);
    if (stop) { sendDone = true; stream._writeStopped = true; }
    else { recvDone = true; stream._readReset = true; }
    stream.emit(stop ? 'peerStopSending' : 'peerReset', stream.streamErrorCode);
    // The writable fails at once. The readable too, unless bytes received
    // before the reset are still unread — those a RESET_STREAM_AT sent
    // reliably (its Reliable Size) must reach the reader whole: the view
    // reads them, then fails (see its pull).
    if (stop) failWrite(endedError(stream));
    else if (!stream.readableLength) failRead(endedError(stream));
    if (readOver() && writeOver()) {
      var err = new Error(stop ? 'the peer stopped reading this stream' : 'the peer reset this stream');
      err.code = stop ? 'ERR_WEBTRANSPORT_STOP_SENDING' : 'ERR_WEBTRANSPORT_STREAM_RESET';
      err.streamErrorCode = stream.streamErrorCode;
      closeIfDone(stream.listenerCount('error') > 0 ? err : null);
    } else if (!stop) {
      stream.push(null);
    }
  };

  stream.once('close', function () {
    if (sends) sendStats();   // the last figures, while QUIC still has them
    if (sendGroup && sendGroup._remove) sendGroup._remove(sendStats);
    var code = closeH3Code !== null ? closeH3Code : wtErrorToH3(0);
    if (!sendDone) { sendDone = true; sendReset = true; resetSending(code, 0); }
    if (!recvDone) { recvDone = true; readStopped = true; quic.stopSending(wtStreamId, code); }
    // Still waiting to be opened (openWtStream): given up if its sending was
    // cut short; ended normally (end() before it opened), its bytes still go
    // once it opens.
    if (stream._onClosePending) stream._onClosePending(sendReset);
    quic.releaseStreamCredit(wtStreamId);
    if (onClose) onClose();
  });

  return stream;
}

// ---- The WHATWG views ----

// Made only here: the browser's interfaces have no constructor a page can
// call ("Illegal constructor"), and neither do these.
var INTERNAL = Symbol('quico.webtransport.internal');
function illegal() { throw new TypeError('Illegal constructor'); }

// WebIDL [Clamp] unsigned long: clamped to 0 – 2^32-1, rounded half to even.
function clampUint32(v) {
  v = Number(v);
  if (isNaN(v)) return 0;
  v = Math.min(Math.max(v, 0), 4294967295);
  var f = Math.floor(v), d = v - f;
  return d > 0.5 || (d === 0.5 && f % 2 === 1) ? f + 1 : f;
}

// The browser's WebTransportError — a DOMException, as the spec has it (so
// `err instanceof DOMException`, and `err.name` is 'WebTransportError'): what
// a stream's reads and writes fail with when the peer reset or stopped it
// (source 'stream', its streamErrorCode), what a session's end fails things
// with (source 'session'), and what an application passes to cancel() /
// abort() to send a code. It was an Error.
//
// Takes either form: the spec's (message, { source, streamErrorCode }) or the
// one browsers implement, a single { message, source, streamErrorCode }. A
// Node code (err.code, 'ERR_…') is set with setErrorCode: a DOMException's
// own `code` is a read-only number.
class WebTransportError extends DOMException {
  constructor(message, options) {
    if (message && typeof message === 'object') { options = message; message = message.message; }
    super(message === undefined || message === null ? '' : String(message), 'WebTransportError');
    var source = options && options.source != null ? String(options.source) : 'stream';
    if (source !== 'stream' && source !== 'session') throw new TypeError("WebTransportError source must be 'stream' or 'session', got " + JSON.stringify(source));
    var code = options && options.streamErrorCode != null ? clampUint32(options.streamErrorCode) : null;
    Object.defineProperty(this, '_wt', { value: { source: source, streamErrorCode: code } });
  }
  get source() { return this._wt.source; }
  get streamErrorCode() { return this._wt.streamErrorCode; }
}
function setErrorCode(err, code) {
  Object.defineProperty(err, 'code', { value: code, writable: true, configurable: true, enumerable: false });
  return err;
}

// The browser's stream classes. A bidirectional stream here is a Node Duplex
// (with the browser's .readable and .writable), so WebTransportBidirectionalStream
// recognises it rather than being its class; the other two are the
// WHATWG streams themselves.
class WebTransportBidirectionalStream {
  constructor() { illegal(); }
  static [Symbol.hasInstance](o) { return o != null && o._wtBidirectional === true; }
}
class WebTransportReceiveStream extends ReadableStream {
  constructor(token, source, strategy, stats) {
    if (token !== INTERNAL) illegal();
    super(source, strategy);
    Object.defineProperty(this, '_wtStats', { value: stats });
  }
  /** { bytesReceived, bytesRead } */
  getStats() { return Promise.resolve(this._wtStats()); }
}
class WebTransportSendStream extends WritableStream {
  constructor(token, sink, strategy, hooks) {
    if (token !== INTERNAL) illegal();
    super(sink, strategy);
    Object.defineProperty(this, '_wtHooks', { value: hooks });
  }
  /** A WebTransportWriter: the browser's writer, with atomicWrite() and commit(). */
  getWriter() { return new WebTransportWriter(this); }
  /** { bytesWritten, bytesSent, bytesAcknowledged } */
  getStats() { return Promise.resolve(this._wtHooks.stats()); }
}

// The browser's WebTransportWriter (getWriter() of a send stream):
//   atomicWrite(chunk)  written only if all of it fits the flow-control
//                       window as it is when its turn comes — otherwise not
//                       sent at all, and the Promise rejects (AbortError),
//                       with any atomic write queued behind it; a plain write
//                       queued behind it then fails the stream, as the spec
//                       has it. The stream itself goes on.
//   commit()            what was written so far is delivered even if the
//                       stream is aborted later: abort() then resets it with
//                       RESET_STREAM_AT, that many bytes reliable (a MOQT
//                       subgroup's header, say) — with a peer that takes it;
//                       without, a plain RESET_STREAM.
class WebTransportWriter extends WritableStreamDefaultWriter {
  constructor(stream) {
    super(stream);
    Object.defineProperty(this, '_wtHooks', { value: stream && stream._wtHooks ? stream._wtHooks : null });
  }
  write(chunk) {
    var h = this._wtHooks, p = super.write(chunk);
    if (!h) return p;
    h.plainPending++;
    var done = function () { h.plainPending--; };
    p.then(done, done);
    return p;
  }
  atomicWrite(chunk) {
    var h = this._wtHooks;
    if (!h) return super.write(chunk);
    var ticket = h.markAtomic(chunk);
    var p = super.write(chunk);
    return p.then(function () {
      if (ticket.aborted) throw new DOMException('the chunk does not fit the flow-control window', 'AbortError');
    }, function (err) { ticket.aborted = true; throw err; });
  }
  commit() {
    if (this._wtHooks) this._wtHooks.commit();
  }
}

// The browser's WebTransportSendGroup: streams (and datagram writables) that
// share a send-order space; getStats() sums its streams' figures.
class WebTransportSendGroup {
  constructor(token, owner) {
    if (token !== INTERNAL) illegal();
    Object.defineProperty(this, '_owner', { value: owner || null });
    Object.defineProperty(this, '_members', { value: new Set() });
  }
  _add(f) { this._members.add(f); }
  _remove(f) { this._members.delete(f); }
  getStats() {
    var t = { bytesWritten: 0, bytesSent: 0, bytesAcknowledged: 0 };
    this._members.forEach(function (f) { var s = f(); t.bytesWritten += s.bytesWritten; t.bytesSent += s.bytesSent; t.bytesAcknowledged += s.bytesAcknowledged; });
    return Promise.resolve(t);
  }
}

class WebTransportDatagramsWritable extends WritableStream {
  constructor(token, sink, strategy) {
    if (token !== INTERNAL) illegal();
    super(sink, strategy);
  }
}
class WebTransportDatagramDuplexStream {
  constructor() { illegal(); }
}

// The code a cancel() or abort() reason carries; 0 for any other reason.
function codeOf(reason) {
  return reason && typeof reason.streamErrorCode === 'number' ? reason.streamErrorCode : 0;
}

// Why the stream ended early: the peer's code if it gave one.
function endedError(stream) {
  return new WebTransportError(stream.streamErrorCode != null ? 'the peer gave up on this stream' : 'stream closed',
                               { streamErrorCode: stream.streamErrorCode });
}

// What a write into a WHATWG view may carry: a BufferSource — an ArrayBuffer
// or a view onto one, not shared memory — and not an empty one (as the
// browsers reject it; WPT sendstream-bad-chunk, datagram-bad-chunk). A string
// was turned into whatever its missing .buffer gave. Copied: the caller may
// reuse its buffer once write() returns.
function bufferSourceBytes(chunk, what) {
  var u8 = null;
  if (chunk instanceof ArrayBuffer) u8 = new Uint8Array(chunk);
  else if (ArrayBuffer.isView(chunk) && !(typeof SharedArrayBuffer !== 'undefined' && chunk.buffer instanceof SharedArrayBuffer)) {
    u8 = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (!u8) throw new TypeError(what + ' must be an ArrayBuffer or an ArrayBufferView');
  if (u8.byteLength === 0) throw new TypeError(what + ' must not be empty');
  return u8.slice();
}

// Each returns { stream, fail(err) }: the WHATWG stream, and how its owner
// fails it from outside — the peer giving up on that direction, or the
// session's end — while nothing is reading or writing.
//
// The readable is a byte stream, as the browser's WebTransportReceiveStream:
// a BYOB reader (getReader({ mode: 'byob' })) fills its own buffer, what does
// not fit kept for the next read. A default reader gets each chunk in a
// buffer of its own — a copy: enqueue() takes the buffer over, and a chunk
// read here can share its memory with others.
function webReadableOf(stream, stats) {
  var controller = null, failed = false;
  var rs = new WebTransportReceiveStream(INTERNAL, {
    type: 'bytes',
    start: function (c) { controller = c; },
    pull: function (controller) {
      return new Promise(function (resolve) {
        function attempt() {
          if (failed) return done();
          var chunk = stream.read();
          if (chunk !== null) {
            var req = controller.byobRequest;
            if (req && req.view) {
              var v = req.view, n = Math.min(v.byteLength, chunk.length);
              new Uint8Array(v.buffer, v.byteOffset, n).set(chunk.subarray(0, n));
              if (chunk.length > n) stream.unshift(chunk.subarray(n));
              req.respond(n);
            } else {
              controller.enqueue(new Uint8Array(chunk));
            }
            return done();
          }
          if (stream._readReset) { fail(endedError(stream)); return done(); }
          if (stream.readableEnded) {
            controller.close();
            if (controller.byobRequest) controller.byobRequest.respond(0);
            return done();
          }
          if (stream.destroyed) { fail(stream._sessionError || endedError(stream)); return done(); }
          return false;
        }
        function done() {
          stream.removeListener('readable', attempt);
          stream.removeListener('end', attempt);
          stream.removeListener('close', attempt);
          resolve();
          return true;
        }
        if (attempt()) return;
        stream.on('readable', attempt);
        stream.on('end', attempt);
        stream.on('close', attempt);
      });
    },
    cancel: function (reason) { failed = true; stream.stopSending(codeOf(reason)); }
  }, { highWaterMark: 0 }, stats);   // read only when the reader asks: backpressure
  function fail(err) {
    if (failed) return;
    failed = true;
    try { controller.error(err); } catch (e) {}   // already closed: nothing to fail
  }
  return { stream: rs, fail: fail };
}

function webWritableOf(stream, stats, quic, streamId) {
  var controller = null, failed = false;
  var committed = 0;          // commit(): bytes delivered even if aborted
  var atomic = new Map();     // chunk → its atomic tickets, in write order
  var hooks = {
    stats: stats,
    plainPending: 0,
    markAtomic: function (chunk) {
      var t = { aborted: false };
      var list = atomic.get(chunk);
      if (list) list.push(t); else atomic.set(chunk, [t]);
      return t;
    },
    commit: function () { committed = stream._bytesWritten(); }
  };
  // The sink is told a chunk is atomic by its ticket (markAtomic, just before
  // the writer queues it); plain writes are counted by the writer's write().
  function takeTicket(chunk) {
    var list = atomic.get(chunk);
    if (!list) return null;
    var t = list.shift();
    if (list.length === 0) atomic.delete(chunk);
    return t;
  }
  // An atomic write that does not fit: it, and every atomic write still
  // queued, are not sent; a plain write queued behind it fails the stream.
  function abortAtomic(t) {
    t.aborted = true;
    atomic.forEach(function (list) { list.forEach(function (x) { x.aborted = true; }); });
    if (hooks.plainPending > 0) fail(new DOMException('a write queued behind an atomic write that did not fit', 'AbortError'));
  }
  var ws = new WebTransportSendStream(INTERNAL, {
    start: function (c) { controller = c; },
    write: function (chunk) {
      var ticket = takeTicket(chunk);
      var u8 = bufferSourceBytes(chunk, 'a chunk written to a WebTransport stream');
      if (ticket) {
        if (ticket.aborted) return;
        if (!quic.streamSendWindow || quic.streamSendWindow(streamId) < u8.byteLength) { abortAtomic(ticket); return; }
      }
      return new Promise(function (resolve, reject) {
        if (stream.destroyed || stream._writeStopped) { reject(stream._sessionError || endedError(stream)); return; }
        stream.write(Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength), function (err) {
          if (err || stream.destroyed || stream._writeStopped) reject(stream._sessionError || endedError(stream)); else resolve();
        });
      });
    },
    close: function () {
      return new Promise(function (resolve, reject) {
        if (stream.destroyed || stream._writeStopped) { reject(stream._sessionError || endedError(stream)); return; }
        stream.end(resolve);
      });
    },
    // RESET_STREAM_AT with what was committed, when anything was.
    abort: function (reason) {
      failed = true;
      stream.resetStream(codeOf(reason), committed > 0 ? { reliableSize: committed } : undefined);
    }
  }, undefined, hooks);
  function fail(err) {
    if (failed) return;
    failed = true;
    try { controller.error(err); } catch (e) {}   // already closed: nothing to fail
  }
  return { stream: ws, fail: fail };
}

// ---- Opening a stream of our own ----
//
// The browser's way, for both sides (the server's res.create…Stream, the
// client's wt.create…Stream): options { sendOrder, sendGroup,
// waitUntilAvailable }. Without waitUntilAvailable, a stream past the peer's
// MAX_STREAMS is refused at once — null here; the browser rejects — rather
// than opened to wait unseen; with it, it is opened and its bytes wait for
// the peer to allow more. make(streamId, kind, prefixLength) builds the
// stream object, recorded by its owner.
//
// Opened is not open yet: past the peer's limit the stream waits for it to
// allow more. stream.pending says so (as net.Socket's does) until it is
// open; then 'ready', and callback(null, stream) — or callback(err) if it
// closes first (its session or connection did). Both after this returns,
// as Node's are, whether or not it had to wait. The client's Promise is
// settled from the same callback: resolved once the stream is open, as the
// browser's is — it was resolved at once, open or not.
function openWtStream(h3, quic, sessionId, bidi, options, make, callback) {
  options = options || {};
  if (!options.waitUntilAvailable && !quic.canOpenStream(bidi)) return null;
  var streamId = h3.createWebTransportStream(sessionId, bidi);
  var stream = make(streamId, bidi ? 'bidi' : 'uni-out', wt_stream_header(bidi, sessionId).byteLength);
  if (options.sendGroup) stream.sendGroup = options.sendGroup;
  if (options.sendOrder != null) stream.sendOrder = options.sendOrder;
  stream.pending = true;
  var settled = false;
  function settle(err) {
    if (settled) return;
    settled = true;
    stream._onClosePending = null;
    stream.pending = false;
    if (err) { err = new Error('the stream closed before it was open'); err.code = 'ERR_WEBTRANSPORT_STREAM_NOT_OPEN'; }
    process.nextTick(function () {
      if (!err) stream.emit('ready');
      if (typeof callback === 'function') callback(err || null, stream);
    });
  }
  stream._onClosePending = function (aborted) { if (aborted) settle(true); };
  quic.whenStreamPermitted(streamId, settle);
  return stream;
}

// ---- A session's place in QUIC's scheduler ----
//
// The browser's model (W3C WebTransport, sendGroup / sendOrder): the streams
// of a send group share the group's turns, the highest sendOrder with
// something to send taking them, equal orders taking turns; the groups share
// the session's sending equally. A stream in no group is in its session's own
// group. QUIC's scheduler has exactly that as `group` and `order`
// (setStreamPriority); this maps one onto the other. Every stream and group
// of the session is at the urgency of its CONNECT stream — RFC 9218's
// `priority` on the CONNECT request, or what the application set for it —
// taken as each stream is placed.
//
// Datagrams go first by default, ahead of any stream (sendDatagram). Sent
// with a sendGroup or a sendOrder other than 0, they take their place among
// the streams instead, as the browser's createWritable({ sendOrder,
// sendGroup }) has it: a member of that group (or of the session's), at
// that order.
function wtScheduling(quic, sessionStreamId) {
  var sessionGroup = {};
  function urgency() {
    var p = quic.getStreamPriority(sessionStreamId);
    return p && p.urgency != null ? p.urgency : 3;
  }
  return {
    forStream: function (group, order) {
      return { urgency: urgency(), incremental: true, group: group || sessionGroup, order: Number(order) || 0 };
    },
    forDatagram: function (options) {
      if (!options || (!options.sendGroup && !Number(options.sendOrder))) return null;
      return { urgency: urgency(), group: options.sendGroup || sessionGroup, order: Number(options.sendOrder) || 0 };
    }
  };
}

// ---- A session's datagrams and statistics, for both sides ----
//
// The client's WebTransport and the server's res share these, so a session
// looks the same from either end. `session` is what they hand in:
//   quic                       the QUIC connection (a getter on the client:
//                              made after the session object)
//   connected()                whether the session is up
//   send(u8, options)          its sendDatagram (options: sendOrder, sendGroup)
//   maxDatagramSize()          the largest payload it can send
//   owner                      { maxAge, expired } — its datagrams in QUIC's
//                              queue: their age limit (outgoingMaxAge) and how
//                              many were dropped unsent (sendDatagram's owner)
//   dgStats                    { droppedIncoming, expiredIncoming }
//   connecting()               (the client's) the session is still being
//                              set up: datagrams written meanwhile wait
//   transport                  (the client's) its WebTransport — a send group
//                              of another session's is refused

// WebIDL's unsigned long, as a setter takes it: a number, its fraction
// dropped, modulo 2^32 (-1 is 4294967295); NaN and ±Infinity are 0.
function toUint32(v) {
  v = Number(v);
  if (!isFinite(v)) return 0;
  v = Math.trunc(v) % 4294967296;
  return v < 0 ? v + 4294967296 : v;
}
// An age limit, as the browser's setters take it: null, or milliseconds —
// negative or NaN is a RangeError, 0 means none (null).
function maxAgeOf(v, name) {
  if (v === null || v === undefined) return null;
  v = Number(v);
  if (isNaN(v) || v < 0) throw new RangeError(name + ' must be null or a non-negative number, got ' + v);
  return v === 0 ? null : v;
}

// The browser's WebTransportDatagramDuplexStream (W3C WebTransport):
//   readable                   the incoming datagrams, read only when asked;
//                              past incomingMaxBufferedDatagrams the oldest
//                              goes, one older than incomingMaxAge is skipped
//   createWritable({ sendOrder, sendGroup })
//                              a WebTransportDatagramsWritable of its own:
//                              each has its queue, its place among the
//                              session's streams, and its backpressure —
//                              writer.ready waits while outgoingMaxBufferedDatagrams
//                              of its datagrams wait to go
//   maxDatagramSize, incomingMaxAge, outgoingMaxAge,
//   incomingMaxBufferedDatagrams, outgoingMaxBufferedDatagrams
// What is written before the session is up waits for it (and goes once it
// is, those past outgoingMaxAge dropped); one larger than maxDatagramSize is
// dropped, as the browser drops it. outgoingMaxAge is this session's alone (a
// session on a shared connection used to set the whole connection's).
//
// Also, as before the browser's API changed, and for code written then:
// `writable` (one writable, made on first use), and incomingHighWaterMark /
// outgoingHighWaterMark — the same settings as …MaxBufferedDatagrams.
function createDatagrams(session) {
  var queue = [], controller = null, pull = null, readable = null, legacy = null;
  var inMax = 256, outMax = 256, inAge = null;
  var writers = new Set();   // each writable's { w, q, release, fail }
  var ended = null;          // the session's end: { error } (null error: closed cleanly)
  var flushing = false;
  var dg = Object.create(WebTransportDatagramDuplexStream.prototype);
  var bytesType = session.readableType === 'bytes';   // datagramsReadableType: a BYOB reader, as the browser's
  var pullReject = null;

  function deliver() {
    if (!pull) return;
    var now = Date.now();
    while (queue.length > 0) {
      var d = queue.shift();
      if (inAge != null && now - d.t > inAge) { session.dgStats.expiredIncoming++; continue; }
      var p = pull, r = pullReject; pull = pullReject = null;
      var req = bytesType ? controller.byobRequest : null;
      if (req && req.view) {
        // A BYOB read: the whole datagram into the reader's buffer — one too
        // small is a RangeError, a view of elements wider than a byte a
        // TypeError (W3C pullDatagrams); either fails the readable.
        var v = req.view;
        if (v.byteLength < d.data.byteLength) { r(new RangeError('the buffer (' + v.byteLength + ' bytes) is smaller than the datagram (' + d.data.byteLength + ')')); return; }
        if (!(v instanceof Uint8Array || v instanceof Int8Array || v instanceof Uint8ClampedArray)) { r(new TypeError('a datagram is read into a view of bytes')); return; }
        new Uint8Array(v.buffer, v.byteOffset, d.data.byteLength).set(d.data);
        req.respond(d.data.byteLength);
      } else {
        controller.enqueue(d.data);
      }
      p();
      return;
    }
  }

  function connecting() { return !!(session.connecting && session.connecting()); }

  // What the writables hold goes to QUIC — on the next turn, so that a burst
  // of writes queues up to outgoingMaxBufferedDatagrams and its writer feels
  // it (writer.ready), as the browser's does; or, while the session is being
  // set up, waits for it. Older than outgoingMaxAge: dropped unsent.
  function scheduleFlush() {
    if (flushing) return;
    flushing = true;
    setImmediate(flush);
  }
  function flush() {
    flushing = false;
    var up = session.connected(), now = Date.now(), age = session.owner.maxAge;
    writers.forEach(function (r) {
      while (r.q.length > 0 && age != null && now - r.q[0].t > age) { r.q.shift(); session.owner.expired = (session.owner.expired || 0) + 1; }
      if (!up) return;
      while (r.q.length > 0) {
        var u8 = r.q.shift().data;
        if (u8.byteLength <= session.maxDatagramSize()) session.send(u8, r.w);   // its sendOrder / sendGroup, as they are now
      }
      r.release();
      if (r.closing) writers.delete(r);
    });
  }

  function foreignGroup(g) {
    return g != null && g._owner && session.transport && g._owner !== session.transport;
  }

  function makeWritable(options) {
    options = options || {};
    var r = { q: [], bp: null, bpResolve: null, controller: null };
    r.release = function () {
      if (r.bpResolve && r.q.length < outMax) { var f = r.bpResolve; r.bp = r.bpResolve = null; f(); }
    };
    r.fail = function (err) { try { r.controller.error(err); } catch (e) {} };
    var w = new WebTransportDatagramsWritable(INTERNAL, {
      start: function (c) { r.controller = c; },
      write: function (chunk) {
        var t = Date.now();
        var u8 = bufferSourceBytes(chunk, 'a datagram');
        if (ended) {
          if (ended.error) throw ended.error;
          throw new WebTransportError('the session is closed', { source: 'session' });
        }
        if (!session.connected() && !connecting()) throw new WebTransportError('the session is not connected', { source: 'session' });
        // Larger than can be sent: dropped, the write resolves (as the browser's).
        if (session.connected() && u8.byteLength > session.maxDatagramSize()) return;
        r.q.push({ data: u8, t: t });
        scheduleFlush();
        if (r.q.length >= outMax) {
          if (!r.bp) r.bp = new Promise(function (resolve) { r.bpResolve = resolve; });
          return r.bp;
        }
      },
      // Closed: what it holds still goes, then it is forgotten (flush).
      close: function () { r.closing = true; scheduleFlush(); },
      abort: function () { r.q = []; writers.delete(r); }
    }, { highWaterMark: 1 });
    var sendOrder = Number(options.sendOrder) || 0, sendGroup = options.sendGroup || null;
    Object.defineProperty(w, 'sendOrder', { enumerable: true,
      get: function () { return sendOrder; }, set: function (v) { sendOrder = Number(v) || 0; } });
    Object.defineProperty(w, 'sendGroup', { enumerable: true,
      get: function () { return sendGroup; },
      set: function (g) {
        if (foreignGroup(g)) throw new DOMException('this send group belongs to another WebTransport session', 'InvalidStateError');
        sendGroup = g || null;
      } });
    r.w = w;
    writers.add(r);
    return w;
  }

  Object.defineProperty(dg, 'readable', { enumerable: true, get: function () {
    if (!readable) {
      var source = {
        start: function (c) {
          controller = c;
          if (ended) { if (ended.error) c.error(ended.error); else c.close(); }
        },
        pull: function () { return new Promise(function (resolve, reject) { pull = resolve; pullReject = reject; deliver(); }); }
      };
      if (bytesType) source.type = 'bytes';
      readable = new ReadableStream(source, { highWaterMark: 0 });
    }
    return readable;
  } });
  // The browser's createWritable: a group of another session's is a
  // TypeError, a session that is over an InvalidStateError — in that order.
  dg.createWritable = function (options) {
    if (options && foreignGroup(options.sendGroup)) throw new TypeError('options.sendGroup belongs to another WebTransport session');
    if (ended || (!session.connected() && !connecting())) throw new DOMException('the session is closed', 'InvalidStateError');
    return makeWritable(options);
  };
  Object.defineProperty(dg, 'writable', { enumerable: true, get: function () {
    return legacy || (legacy = makeWritable());
  } });
  Object.defineProperty(dg, 'maxDatagramSize', { enumerable: true, get: function () { return session.maxDatagramSize(); } });
  Object.defineProperty(dg, 'incomingMaxAge', { enumerable: true,
    get: function () { return inAge; },
    set: function (v) { inAge = maxAgeOf(v, 'incomingMaxAge'); } });
  Object.defineProperty(dg, 'outgoingMaxAge', { enumerable: true,
    get: function () { return session.owner.maxAge; },
    set: function (v) { session.owner.maxAge = maxAgeOf(v, 'outgoingMaxAge'); } });
  function inMaxProp() {
    return { enumerable: true, get: function () { return inMax; },
             set: function (v) { inMax = Math.max(1, toUint32(v)); } };
  }
  function outMaxProp() {
    return { enumerable: true, get: function () { return outMax; },
             set: function (v) { outMax = Math.max(1, toUint32(v)); writers.forEach(function (r) { r.release(); }); } };
  }
  Object.defineProperty(dg, 'incomingMaxBufferedDatagrams', inMaxProp());
  Object.defineProperty(dg, 'outgoingMaxBufferedDatagrams', outMaxProp());
  Object.defineProperty(dg, 'incomingHighWaterMark', inMaxProp());
  Object.defineProperty(dg, 'outgoingHighWaterMark', outMaxProp());

  // A datagram arrived: for the readable, once anything reads it.
  dg._push = function (data) {
    if (!readable || ended) return;
    queue.push({ data: data, t: Date.now() });
    while (queue.length > inMax) { queue.shift(); session.dgStats.droppedIncoming++; }
    deliver();
  };
  // The session is up: what was written meanwhile goes.
  dg._flush = function () { scheduleFlush(); };
  // The session is over (W3C "cleanup"): the queues emptied, each writer
  // released; closed cleanly, the readable closes; lost (`err`), the readable
  // and every writable fail with the session's error.
  dg._close = function (err) {
    if (ended) return;
    ended = { error: err || null };
    queue = [];
    writers.forEach(function (r) { r.q = []; r.release(); if (err) r.fail(err); });
    if (controller) {
      try {
        if (err) controller.error(err);
        else { controller.close(); if (controller.byobRequest) controller.byobRequest.respond(0); }
      } catch (e) {}
    }
    if (pull) { var p = pull; pull = pullReject = null; p(); }
  };
  return dg;
}

// The browser's getStats(): the connection's figures (QUIC's getStats — shared
// by every session on it, as in the browser), and the session's datagrams.
function sessionStats(session) {
  var q = session.quic && session.quic.getStats ? session.quic.getStats() : {};
  var out = { timestamp: Date.now() };
  ['packetsSent', 'packetsLost', 'bytesLost', 'bytesReceived', 'packetsReceived', 'smoothedRtt', 'rttVariation',
   'minRtt', 'estimatedSendRate', 'atSendCapacity', 'congestionWindow', 'bytesInFlight'].forEach(function (k) {
    out[k] = q[k] !== undefined ? q[k] : null;
  });
  // As the spec counts them: bytesSent the application's bytes (new stream
  // data and datagram payloads — no framing, no retransmissions),
  // bytesSentOverhead what the packets carried besides, bytesAcknowledged
  // the payload the peer acknowledged. (bytesSent was the packets' size.)
  out.bytesSent = q.payloadBytesSent !== undefined ? q.payloadBytesSent : null;
  out.bytesSentOverhead = q.payloadBytesSent !== undefined && q.bytesSent !== undefined ? Math.max(0, q.bytesSent - q.payloadBytesSent) : null;
  out.bytesAcknowledged = q.payloadBytesAcknowledged !== undefined ? q.payloadBytesAcknowledged : null;
  out.datagrams = {
    droppedIncoming: session.dgStats.droppedIncoming,
    expiredIncoming: session.dgStats.expiredIncoming,
    expiredOutgoing: session.owner.expired || 0,
    lostOutgoing: null   // a datagram's packet lost is not traced back to it
  };
  return Promise.resolve(out);
}

// owner: the client's WebTransport, so that a group is not used on another
// session (its streams and datagram writables check it).
function createSendGroup(owner) { return new WebTransportSendGroup(INTERNAL, owner); }

// ---- Keying material (the browser's exportKeyingMaterial) ----
//
// draft-ietf-webtrans-http3 ("Exporting Keying Material"): the TLS exporter
// (RFC 8446 §7.5) with the label "EXPORTER-WebTransport" and, as its context,
//   WebTransport Session ID (64), Label Length (8), Label, Context Length (8), Context
// — so a session's keys are its own, not the connection's. Checked as the
// browser checks them: all three arguments required (TypeError), the label
// and the context BufferSources of at most 255 bytes, the length 1 to 4096
// (RangeError).
function bufferSourceView(v, name) {
  var shared = typeof SharedArrayBuffer !== 'undefined' &&
               (v instanceof SharedArrayBuffer || (ArrayBuffer.isView(v) && v.buffer instanceof SharedArrayBuffer));
  if (!shared && v instanceof ArrayBuffer) return new Uint8Array(v);
  if (!shared && ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new TypeError(name + ' must be an ArrayBuffer or an ArrayBufferView');
}
function exporterArgs(args) {
  if (args.length < 3) throw new TypeError('exportKeyingMaterial(label, context, outputLength): all three are required');
  var label = bufferSourceView(args[0], 'label'), context = bufferSourceView(args[1], 'context');
  if (label.byteLength > 255) throw new RangeError('the label is longer than 255 bytes');
  if (context.byteLength > 255) throw new RangeError('the context is longer than 255 bytes');
  var length = toUint32(args[2]);
  if (length === 0 || length > 4096) throw new RangeError('outputLength must be 1 to 4096, got ' + args[2]);
  return { label: label, context: context, length: length };
}
function exportSessionKeyingMaterial(quic, sessionId, a) {
  var L = a.label.byteLength, C = a.context.byteLength;
  var ctx = new Uint8Array(8 + 1 + L + 1 + C);
  new DataView(ctx.buffer).setBigUint64(0, BigInt(sessionId));
  ctx[8] = L; ctx.set(a.label, 9);
  ctx[9 + L] = C; ctx.set(a.context, 10 + L);
  var out = quic && quic.exportKeyingMaterial ? quic.exportKeyingMaterial(a.length, 'EXPORTER-WebTransport', ctx) : null;
  if (!out) throw new DOMException('the connection cannot export keying material', 'InvalidStateError');
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength).slice();
}

export { createWtStream, openWtStream, createSendGroup, wtScheduling, createDatagrams, sessionStats, setErrorCode,
         exporterArgs, exportSessionKeyingMaterial,
         WebTransportError, WebTransportBidirectionalStream, WebTransportReceiveStream, WebTransportSendStream,
         WebTransportWriter, WebTransportSendGroup, WebTransportDatagramsWritable, WebTransportDatagramDuplexStream };
