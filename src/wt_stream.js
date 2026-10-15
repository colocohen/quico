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
  stream._sessionGone = function () {
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
  // Its QUIC stream ID and its session's — read-only, for logs and maps.
  Object.defineProperty(stream, 'id', { enumerable: true, get: function () { return wtStreamId; } });
  Object.defineProperty(stream, 'sessionId', { enumerable: true, get: function () { return sessionId; } });

  // The WHATWG views (see above), made on first use — with what the
  // browser's WebTransportReceiveStream / WebTransportSendStream add.
  var webReadable = null, webWritable = null;
  if (reads) {
    Object.defineProperty(stream, 'readable', { configurable: true, get: function () {
      if (!webReadable) {
        webReadable = webReadableOf(stream);
        webReadable.getStats = function () { return Promise.resolve(recvStats()); };
      }
      return webReadable;
    } });
  }
  if (sends) {
    sendProps(stream);
    Object.defineProperty(stream, 'writable', { configurable: true, get: function () {
      if (!webWritable) {
        webWritable = webWritableOf(stream);
        sendProps(webWritable);
        webWritable.getStats = function () { return Promise.resolve(sendStats()); };
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
    var stop = how === 'stop_sending';
    if (stop ? stream._writeStopped : stream._readReset) return;
    // The RESET_STREAM that answers our own STOP_SENDING (RFC 9000 §3.5): our
    // doing, not the peer giving up — reported as 'peerReset' it was.
    if (!stop && readStopped) return;
    stream.streamErrorCode = h3ErrorToWt(h3code);
    if (stop) { sendDone = true; stream._writeStopped = true; }
    else { recvDone = true; stream._readReset = true; }
    stream.emit(stop ? 'peerStopSending' : 'peerReset', stream.streamErrorCode);
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

// The browser's WebTransportError: what a stream's reads and writes fail with
// when the peer reset or stopped it (source 'stream', its streamErrorCode),
// and what an application passes to cancel() / abort() to send a code.
//
// Takes either form: the spec's (message, { source, streamErrorCode }) or the
// one browsers implement, a single { message, source, streamErrorCode }.
class WebTransportError extends Error {
  constructor(message, options) {
    if (message && typeof message === 'object') { options = message; message = message.message; }
    super(message || '');
    this.name = 'WebTransportError';
    this.source = (options && options.source) || 'stream';
    this.streamErrorCode = options && options.streamErrorCode != null ? options.streamErrorCode : null;
  }
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

function webReadableOf(stream) {
  return new ReadableStream({
    pull: function (controller) {
      return new Promise(function (resolve) {
        function attempt() {
          var chunk = stream.read();
          if (chunk !== null) { controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)); return done(); }
          if (stream._readReset) { controller.error(endedError(stream)); return done(); }
          if (stream.readableEnded) { controller.close(); return done(); }
          if (stream.destroyed) { controller.error(endedError(stream)); return done(); }
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
    cancel: function (reason) { stream.stopSending(codeOf(reason)); }
  }, { highWaterMark: 0 });   // read only when the reader asks: backpressure
}

function webWritableOf(stream) {
  return new WritableStream({
    write: function (chunk) {
      return new Promise(function (resolve, reject) {
        if (stream.destroyed || stream._writeStopped) { reject(endedError(stream)); return; }
        stream.write(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength), function (err) {
          if (err || stream.destroyed || stream._writeStopped) reject(endedError(stream)); else resolve();
        });
      });
    },
    close: function () {
      return new Promise(function (resolve, reject) {
        if (stream.destroyed || stream._writeStopped) { reject(endedError(stream)); return; }
        stream.end(resolve);
      });
    },
    abort: function (reason) { stream.resetStream(codeOf(reason)); }
  });
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

// The browser's WebTransportDatagramDuplexStream: readable, writable,
// createWritable({ sendOrder, sendGroup }), maxDatagramSize, the age limits
// and high-water marks. The readable reads only when asked; past
// incomingHighWaterMark the oldest goes, and one older than incomingMaxAge
// when read is skipped. outgoingMaxAge is this session's alone (a session
// on a shared connection used to set the whole connection's).
function createDatagrams(session) {
  var queue = [], controller = null, pull = null, readable = null, writable = null;
  var dg = { incomingMaxAge: null, incomingHighWaterMark: 256, outgoingHighWaterMark: 256 };

  function deliver() {
    if (!pull) return;
    var now = Date.now();
    while (queue.length > 0) {
      var d = queue.shift();
      if (dg.incomingMaxAge != null && now - d.t > dg.incomingMaxAge) { session.dgStats.expiredIncoming++; continue; }
      controller.enqueue(d.data);
      var p = pull; pull = null; p();
      return;
    }
  }
  function makeWritable(options) {
    var w = new WritableStream({
      write: function (chunk) {
        if (!session.connected()) throw new WebTransportError('the session is not connected', { source: 'session' });
        var u8 = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        if (u8.byteLength <= session.maxDatagramSize()) session.send(u8, w);   // its sendOrder / sendGroup, as they are now
      }
    }, { highWaterMark: dg.outgoingHighWaterMark });
    w.sendOrder = (options && options.sendOrder) || 0;
    w.sendGroup = (options && options.sendGroup) || null;
    return w;
  }

  Object.defineProperty(dg, 'readable', { enumerable: true, get: function () {
    if (!readable) {
      readable = new ReadableStream({
        start: function (c) { controller = c; },
        pull: function () { return new Promise(function (resolve) { pull = resolve; deliver(); }); }
      }, { highWaterMark: 0 });
    }
    return readable;
  } });
  Object.defineProperty(dg, 'writable', { enumerable: true, get: function () {
    return writable || (writable = makeWritable());
  } });
  Object.defineProperty(dg, 'maxDatagramSize', { enumerable: true, get: function () { return session.maxDatagramSize(); } });
  Object.defineProperty(dg, 'outgoingMaxAge', { enumerable: true,
    get: function () { return session.owner.maxAge; },
    set: function (v) { session.owner.maxAge = v == null ? null : Number(v); } });
  dg.createWritable = function (options) { return makeWritable(options); };
  // A datagram arrived: for the readable, once anything reads it.
  dg._push = function (data) {
    if (!readable) return;
    queue.push({ data: data, t: Date.now() });
    while (queue.length > dg.incomingHighWaterMark) { queue.shift(); session.dgStats.droppedIncoming++; }
    deliver();
  };
  dg._close = function () {
    queue = [];
    if (controller) { try { controller.close(); } catch (e) {} }
    if (pull) { var p = pull; pull = null; p(); }
  };
  return dg;
}

// The browser's getStats(): the connection's figures (QUIC's getStats — shared
// by every session on it, as in the browser), and the session's datagrams.
function sessionStats(session) {
  var q = session.quic && session.quic.getStats ? session.quic.getStats() : {};
  var out = { timestamp: Date.now() };
  ['bytesSent', 'packetsSent', 'packetsLost', 'bytesReceived', 'packetsReceived', 'smoothedRtt', 'rttVariation',
   'minRtt', 'estimatedSendRate', 'atSendCapacity', 'congestionWindow', 'bytesInFlight'].forEach(function (k) {
    out[k] = q[k] !== undefined ? q[k] : null;
  });
  out.datagrams = {
    droppedIncoming: session.dgStats.droppedIncoming,
    expiredIncoming: session.dgStats.expiredIncoming,
    expiredOutgoing: session.owner.expired || 0,
    lostOutgoing: null   // a datagram's packet lost is not traced back to it
  };
  return Promise.resolve(out);
}

// The browser's WebTransportSendGroup: streams that share a send order space.
// getStats() sums its streams' figures.
function createSendGroup() {
  var members = new Set();
  return {
    _add: function (f) { members.add(f); },
    _remove: function (f) { members.delete(f); },
    getStats: function () {
      var t = { bytesWritten: 0, bytesSent: 0, bytesAcknowledged: 0 };
      members.forEach(function (f) { var s = f(); t.bytesWritten += s.bytesWritten; t.bytesSent += s.bytesSent; t.bytesAcknowledged += s.bytesAcknowledged; });
      return Promise.resolve(t);
    }
  };
}

export { createWtStream, openWtStream, createSendGroup, wtScheduling, createDatagrams, sessionStats, WebTransportError };
