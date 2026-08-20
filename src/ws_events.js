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
//  Two event surfaces on one WebSocket.
//
//  A WebSocket here answers to both of the interfaces people actually write
//  against, and each one behaves the way its own users expect:
//
//    WHATWG  — onmessage / onclose / addEventListener. Handlers receive an
//              Event: MessageEvent with .data, CloseEvent with .code and
//              .wasClean. This is what browser code is written against, and
//              such code runs here unchanged.
//
//    ws      — .on('message') / .on('close') / .once / .off. Handlers receive
//              the data directly: (data, isBinary), (code, reason), (err).
//              This is what Node code is written against, and such code also
//              runs here unchanged.
//
//  BOTH FIRE FOR THE SAME EVENT, WITH DIFFERENT ARGUMENTS. That is the
//  deliberate part and the one thing to know before reading anything else:
//
//      ws.onmessage = e => e.data;                    // MessageEvent
//      ws.on('message', (data, isBinary) => data);    // Buffer or string
//
//  The alternative was to make .on() an alias for addEventListener, so that
//  everything received an Event. That is more consistent with itself and worse
//  in practice: every `ws` example on the internet would then be subtly wrong
//  here — `data.length` on a MessageEvent is undefined, not an error — and a
//  method that looks familiar while meaning something else is a worse trap
//  than one that does not exist.
//
//  Two places where the interfaces disagree and both are kept as they are:
//
//    binaryType governs the WHATWG surface only. `ws` has no such concept and
//    always hands over a Buffer, so .on('message') always gets a Buffer even
//    when onmessage is producing Blobs.
//
//    close reason is a string in CloseEvent and a Buffer in ws's
//    .on('close', (code, reason)).
// ============================================================


/**
 * Install the `ws`-style surface on an object that already extends
 * EventTarget, and give it the emit helpers both surfaces go through.
 *
 * The class keeps its own `_onmessage` etc. slots for the WHATWG `on<event>`
 * properties; this only adds the second surface and the dispatch that feeds
 * both, so ws_client and ws_server do not each grow a copy.
 */
function installEventSurfaces(target) {
  // ws-style listeners, kept apart from EventTarget's own registry: they
  // receive different arguments, so they cannot share a list.
  var nodeListeners = Object.create(null);

  function add(type, fn, once) {
    if (typeof fn !== 'function') return target;
    (nodeListeners[type] = nodeListeners[type] || []).push({ fn: fn, once: !!once });
    return target;
  }

  target.on = function (type, fn) { return add(type, fn, false); };
  target.once = function (type, fn) { return add(type, fn, true); };
  target.addListener = target.on;

  target.off = function (type, fn) {
    var a = nodeListeners[type];
    if (!a) return target;
    for (var i = 0; i < a.length; i++) {
      if (a[i].fn === fn) { a.splice(i, 1); break; }
    }
    return target;
  };
  target.removeListener = target.off;

  target.removeAllListeners = function (type) {
    if (type === undefined) nodeListeners = Object.create(null);
    else delete nodeListeners[type];
    return target;
  };

  target.listenerCount = function (type) {
    return (nodeListeners[type] || []).length;
  };

  target.eventNames = function () { return Object.keys(nodeListeners); };

  /** Call the ws-style listeners for `type` with the given arguments. */
  target._emitNode = function (type, args) {
    var a = nodeListeners[type];
    if (!a || a.length === 0) return false;
    // Copied before iterating: a listener may remove itself (once) or another,
    // and mutating the array mid-loop silently skips one.
    var list = a.slice();
    for (var i = 0; i < list.length; i++) {
      if (list[i].once) target.off(type, list[i].fn);
      list[i].fn.apply(target, args);
    }
    return true;
  };

  return target;
}


/**
 * Fire one event on both surfaces.
 *
 * `event` is dispatched to the WHATWG side; `nodeArgs` is spread into the
 * ws-style listeners. Every emission in ws_client and ws_server goes through
 * here, so the two surfaces cannot drift apart — a new event added to one is
 * added to both or to neither.
 */
function emitBoth(target, type, event, nodeArgs) {
  if (event) target.dispatchEvent(event);
  target._emitNode(type, nodeArgs || []);
}


/**
 * The payload `ws` hands to .on('message'), regardless of binaryType.
 *
 * ALWAYS a Buffer, text included. That is not an oversight in `ws`: since v8 it
 * emits a Buffer for every message and passes `isBinary` alongside, leaving the
 * decision to decode to the consumer — which is why `ws` handlers are full of
 * `data.toString()`. Handing a string to a text message here would look more
 * convenient and would break exactly those handlers, silently, because
 * `.toString()` on a string is a no-op but `.length` and `.subarray()` are not.
 *
 * The differential test in ws_compat.test.mjs is what caught this: the same
 * handler recorded `Buffer(text)` against `ws` and `string(text)` against us.
 *
 * binaryType is deliberately not consulted. `ws` has no such concept, so a
 * Blob must never reach this surface even when the WHATWG side is producing
 * them.
 */
function nodeMessagePayload(data, isBinary) {
  if (typeof data === 'string') return Buffer.from(data, 'utf8');
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return data;
}


export { installEventSurfaces, emitBoth, nodeMessagePayload };
