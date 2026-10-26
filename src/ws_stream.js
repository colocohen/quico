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
//  WebSocketStream — the browser's streams-based WebSocket
//
//    https://github.com/ricea/websocketstream-explainer
//    (WPT websockets/stream/tentative: not yet a standard; Chrome has it)
//
//  The same connection as WebSocket (ws_client.js underneath), with streams
//  in place of events, so that both directions have backpressure:
//
//    const wss = new WebSocketStream(url, { protocols, signal });
//    const { readable, writable, protocol, extensions } = await wss.opened;
//    for await (const message of readable) …        // a string or a Uint8Array
//    await writable.getWriter().write('hello');      // resolves once it is sent
//    wss.close({ closeCode, reason });
//    const { closeCode, reason } = await wss.closed;
//
//  Receiving: a message nobody has read holds the socket — it is paused, TCP
//  fills up, and the server feels it. WebSocket's 'message' events take every
//  message as it comes, however fast, into memory.
//  Sending: write() resolves when the frame has gone to the socket, not when
//  it was queued — so a writer that awaits it goes as fast as the connection
//  does. WebSocket's send() returns at once; bufferedAmount is all there is.
//
//  Besides the browser's protocols and signal, the options bag takes QUICO's
//  WebSocket options (origin, headers, ca, rejectUnauthorized, agent, …).
// ============================================================

import { WebSocket } from './ws_client.js';
import { userCloseCode, closeReasonBytes, subprotocolList, sendInOrder, OPCODE } from './ws.js';

// The browser's WebSocketError: a DOMException named 'WebSocketError', with
// the close code and reason. new WebSocketError(message, { closeCode, reason })
// takes the codes close() takes (1000, 3000–4999) and a reason of at most 123
// bytes; a reason without a code is 1000.
class WebSocketError extends DOMException {
  constructor(message, init) {
    super(message === undefined ? '' : String(message), 'WebSocketError');
    if (init !== undefined && init !== null && typeof init !== 'object') throw new TypeError('WebSocketError options must be an object');
    init = init || {};
    var code = init.closeCode !== undefined && init.closeCode !== null ? userCloseCode(init.closeCode) : null;
    var reason = init.reason !== undefined ? String(init.reason) : '';
    if (reason) closeReasonBytes(reason);
    if (code === null && reason) code = 1000;
    Object.defineProperty(this, '_wse', { value: { closeCode: code, reason: reason } });
  }
  get closeCode() { return this._wse.closeCode; }
  get reason() { return this._wse.reason; }
}

// One of ours, with a code a constructor would refuse (1006: the connection
// went without a closing handshake).
function connectionError(message, closeCode, reason) {
  var e = new WebSocketError(message);
  e._wse.closeCode = closeCode;
  e._wse.reason = reason || '';
  return e;
}

function invalidState(message) { return new DOMException(message, 'InvalidStateError'); }

// A chunk written: an ArrayBuffer or a view onto one goes as a binary message
// (not one on shared or resizable memory: a TypeError, as the browser has
// it), anything else as text, stringified (a value that cannot be: TypeError).
function messageOf(chunk) {
  if (chunk instanceof ArrayBuffer || ArrayBuffer.isView(chunk) ||
      (typeof SharedArrayBuffer !== 'undefined' && chunk instanceof SharedArrayBuffer)) {
    var buf = ArrayBuffer.isView(chunk) ? chunk.buffer : chunk;
    if ((typeof SharedArrayBuffer !== 'undefined' && buf instanceof SharedArrayBuffer) || buf.resizable || buf.growable) {
      throw new TypeError('a WebSocketStream cannot send shared or resizable memory');
    }
    var u8 = ArrayBuffer.isView(chunk) ? new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength) : new Uint8Array(chunk);
    return { opcode: OPCODE.BINARY, payload: Buffer.from(u8) };   // a copy: the caller may reuse its buffer
  }
  return { opcode: OPCODE.TEXT, payload: Buffer.from(String(chunk), 'utf8') };
}

class WebSocketStream {
  constructor(url, options) {
    if (arguments.length === 0) throw new TypeError('Failed to construct \'WebSocketStream\': 1 argument required, but only 0 present.');
    if (options !== undefined && options !== null && typeof options !== 'object') throw new TypeError('WebSocketStream options must be an object');
    options = options || {};
    var protocols = subprotocolList(options.protocols, true);
    var signal = options.signal;
    if (signal !== undefined && signal !== null && !(signal instanceof AbortSignal)) throw new TypeError('options.signal must be an AbortSignal');

    var nodeOptions = {};
    for (var k in options) if (k !== 'protocols' && k !== 'signal') nodeOptions[k] = options[k];

    // The URL is checked as WebSocket checks it (a SyntaxError); its
    // connection starts on the next turn — not at all if aborted by then.
    var ws = this._ws = new WebSocket(url, protocols, nodeOptions);
    ws.binaryType = 'nodebuffer';
    this._url = ws.url;

    var self = this;
    var openedResolve, openedReject, closedResolve, closedReject;
    this.opened = new Promise(function (res, rej) { openedResolve = res; openedReject = rej; });
    this.closed = new Promise(function (res, rej) { closedResolve = res; closedReject = rej; });
    this.opened.catch(function () {});
    this.closed.catch(function () {});

    var state = 'connecting';     // connecting → open → closed
    var pendingWrites = 0;
    var readCtl = null, writeCtl = null, writableClosing = null;
    this._state = function () { return state; };

    function settleFailed(err) {
      if (state === 'closed') return;
      state = 'closed';
      openedReject(err);
      closedReject(err);
    }

    // The signal: before the connection is made, it is never attempted;
    // during the handshake, it is abandoned; once open, it does nothing.
    function onAbort() {
      if (state !== 'connecting') return;
      var reason = signal.reason !== undefined ? signal.reason : new DOMException('The operation was aborted.', 'AbortError');
      settleFailed(reason);
      try { ws.close(); } catch (e) {}
    }
    if (signal) {
      if (signal.aborted) { onAbort(); return; }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    ws.addEventListener('open', function () {
      if (signal) signal.removeEventListener('abort', onAbort);
      if (state !== 'connecting') return;
      state = 'open';
      var socket = ws._socket;

      var readable = new ReadableStream({
        start: function (c) { readCtl = c; },
        // Read: the socket goes on. Unread: it is paused (see 'message').
        pull: function () { if (socket && !socket.destroyed && socket.isPaused()) socket.resume(); },
        cancel: function (reason) { closeWith(reason); }
      });

      var writable = new WritableStream({
        start: function (c) { writeCtl = c; },
        write: function (chunk) {
          var m = messageOf(chunk);
          if (ws.readyState !== WebSocket.OPEN) throw invalidState('the WebSocket is closed');
          return new Promise(function (resolve, reject) {
            pendingWrites++;
            sendInOrder(ws, m.opcode, m.payload, function (err) {
              pendingWrites--;
              if (err) reject(invalidState('the WebSocket closed before the message was sent'));
              else resolve();
            });
          });
        },
        // A clean close, no code; done once the closing handshake is.
        close: function () {
          return new Promise(function (resolve) {
            writableClosing = resolve;
            try { ws.close(); } catch (e) { resolve(); }
          });
        },
        abort: function (reason) { closeWith(reason); }
      });

      openedResolve({ readable: readable, writable: writable, protocol: ws.protocol, extensions: ws.extensions });
    });

    ws.addEventListener('message', function (e) {
      if (!readCtl) return;
      var data = typeof e.data === 'string' ? e.data : new Uint8Array(e.data);
      try { readCtl.enqueue(data); } catch (x) { return; }
      // Nobody reading: hold the socket until somebody does. The server's
      // sends then wait on TCP — the receiving side's backpressure.
      var socket = ws._socket;
      if (readCtl.desiredSize <= 0 && socket && !socket.isPaused()) socket.pause();
    });

    ws.addEventListener('close', function (e) {
      if (signal) signal.removeEventListener('abort', onAbort);
      if (writableClosing) { var done = writableClosing; writableClosing = null; done(); }
      if (state === 'connecting') {
        settleFailed(connectionError('the WebSocket connection could not be established', 1006, ''));
        return;
      }
      if (state === 'closed') return;
      state = 'closed';
      if (e.wasClean && pendingWrites === 0) {
        // Clean: the peer's code and reason. Nothing more can be written.
        closedResolve({ closeCode: e.code, reason: e.reason });
        try { readCtl.close(); } catch (x) {}
        try { writeCtl.error(invalidState('the WebSocket is closed')); } catch (x) {}
      } else {
        // Not clean — no closing handshake, or one that left messages
        // unsent: the same error for closed, the readable and the writable.
        var err = connectionError(e.wasClean ? 'the WebSocket closed with messages unsent' : 'the WebSocket connection was lost',
                                  e.wasClean ? e.code : 1006, e.wasClean ? e.reason : '');
        closedReject(err);
        try { readCtl.error(err); } catch (x) {}
        try { writeCtl.error(err); } catch (x) {}
      }
    });

    // abort() of the writable, cancel() of the readable: closed with the
    // code and reason of a WebSocketError given as the reason; anything else
    // is a close with no code.
    function closeWith(reason) {
      if (reason instanceof WebSocketError && reason.closeCode !== null) {
        try { ws.close(reason.closeCode, reason.reason); } catch (e) { try { ws.close(); } catch (x) {} }
      } else {
        try { ws.close(); } catch (e) {}
      }
    }

  }

  get url() { return this._url; }

  /**
   * close({ closeCode, reason }): as WebSocket's close() checks them; a
   * reason without a code is 1000, neither is a close with no code (1005 at
   * the peer). During the handshake: abandoned — opened and closed reject.
   */
  close(closeInfo) {
    if (closeInfo !== undefined && closeInfo !== null && typeof closeInfo !== 'object') {
      throw new TypeError('close() takes { closeCode, reason }');
    }
    var code = closeInfo && closeInfo.closeCode !== undefined ? userCloseCode(closeInfo.closeCode) : undefined;
    var reason = closeInfo && closeInfo.reason !== undefined ? String(closeInfo.reason) : '';
    closeReasonBytes(reason);
    if (code === undefined && reason) code = 1000;
    if (this._state() === 'closed') return;
    if (this._state() === 'connecting') { try { this._ws.close(); } catch (e) {} return; }
    this._ws.close(code, code === undefined ? undefined : reason);
  }
}

export { WebSocketStream, WebSocketError };
