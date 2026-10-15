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



import crypto from 'node:crypto';
import { sha12 } from './http_common.js';


// ============================================================
//  Protocol-layer fingerprints: HTTP/2 and HTTP/3.
//
//  The third layer, alongside the TLS fingerprints lemon-tls produces (JA4)
//  and the header fingerprint in ja4h.js. Each answers a different question:
//
//    JA4    which TLS library built the ClientHello
//    JA4H   which HTTP client wrote the headers
//    here   which HTTP/2 or HTTP/3 implementation set up the connection
//
//  Their value is in DISAGREEING. A request whose TLS says BoringSSL, whose
//  headers say Chrome, and whose SETTINGS frame says hyper-h2 is not Chrome,
//  and no amount of User-Agent spoofing hides it. All three layers have to
//  tell the same story, and each one a client fakes correctly is one more it
//  has to keep in sync with the others.
//
//  Naming: the HTTP/2 format below is the one published by Elad Shuster at
//  Black Hat Europe 2017 from more than 10 million connections observed at
//  Akamai's edge. It is a research format, not a licensed standard, and there
//  is no reference implementation with terms attached — unlike JA4+, where
//  everything except JA4 itself carries the FoxIO License. "Akamai" is their
//  trademark, so the function is named for what it does.
// ============================================================




// ============================================================
//  HTTP/2
// ============================================================

/**
 * h2Fingerprint(observed) — the four-section HTTP/2 fingerprint.
 *
 *   S[;] | WU | P[,] | PS[,]
 *
 *   1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p       <- Chrome
 *
 *   S   SETTINGS as ID:Value pairs, IN THE ORDER SENT. Which parameters are
 *       ABSENT matters as much as the values: Chrome sends only four of the
 *       six, omitting MAX_CONCURRENT_STREAMS and MAX_FRAME_SIZE entirely, so
 *       a client sending all six is not Chrome whatever it claims.
 *
 *   WU  The WINDOW_UPDATE increment on stream 0, or 0 if none was sent.
 *       Chrome sends 15663105 and Firefox 12517377 — browsers open large
 *       windows because they fetch dozens of resources at once, while
 *       libraries keep the 65535 default and send no WINDOW_UPDATE at all.
 *
 *   P   PRIORITY frames as StreamID:Exclusive:DependsOn:Weight, or 0.
 *       Mostly historical now: RFC 9218 deprecated the dependency tree, and
 *       modern Chrome sends no PRIORITY frames at all — it signals priority
 *       through the HEADERS frame and the `priority` header instead. The 0 IS
 *       the fingerprint. Firefox still sends them, so presence or absence
 *       remains a clean binary that has to match the claimed browser.
 *
 *   PS  Pseudo-header order. Chrome m,a,s,p — Firefox m,p,a,s —
 *       Safari m,s,p,a. The spec fixes that pseudo-headers come first but
 *       says nothing about their order among themselves, so each
 *       implementation picked one and kept it. This is the single strongest
 *       section: it is set deep in the network stack, and most HTTP libraries
 *       use an order matching no browser at all.
 */
function h2Fingerprint(observed) {
  observed = observed || {};

  // Pairs in the order received. An object would not do: insertion order is
  // an implementation detail, and the order IS the signal here.
  var settings = Array.isArray(observed.settings) ? observed.settings : [];
  var s = settings.map(function (p) { return p.id + ':' + p.value; }).join(';');

  var wu = observed.windowUpdate ? String(observed.windowUpdate) : '0';

  var priorities = Array.isArray(observed.priorities) ? observed.priorities : [];
  var p = priorities.length
    ? priorities.map(function (x) {
        return x.streamId + ':' + (x.exclusive ? 1 : 0) + ':' +
               x.dependsOn + ':' + x.weight;
      }).join(',')
    : '0';

  var ps = Array.isArray(observed.pseudoHeaderOrder) && observed.pseudoHeaderOrder.length
    ? observed.pseudoHeaderOrder.join(',')
    : '0';

  var raw = s + '|' + wu + '|' + p + '|' + ps;
  return {
    hash: sha12(raw),

    // The MD5 of the raw string is the form published alongside this format,
    // and it is what an external database is keyed by. Verified against an
    // independent capture of Chrome: the same header set yields
    // 52d84b11737d980aef856699f885ca86 there and here.
    //
    // Both are returned because they answer different questions. `hash` keeps
    // every fingerprint on a request looking alike; `md5` is for matching
    // anything outside quico, and without it a cross-check fails for no
    // visible reason.
    md5: crypto.createHash('md5').update(raw, 'utf8').digest('hex'),

    raw: raw, s: s, wu: wu, p: p, ps: ps
  };
}

/** ':method' -> 'm'. The four are the only pseudo-headers a request may carry. */
var PSEUDO_LETTER = { ':method': 'm', ':authority': 'a', ':scheme': 's', ':path': 'p' };

function pseudoHeaderOrder(names) {
  var out = [];
  for (var i = 0; i < (names || []).length; i++) {
    var l = PSEUDO_LETTER[names[i]];
    if (l) out.push(l);
  }
  return out;
}


// ============================================================
//  HTTP/3 over QUIC
// ============================================================

/**
 * h3Fingerprint(observed) — the same idea one layer down.
 *
 * QUIC transport parameters do for the transport what SETTINGS does for
 * HTTP/2, and each implementation ships different defaults: Chrome asks for
 * 15MB of connection data and 6291456 per stream — mirroring its HTTP/2
 * INITIAL_WINDOW_SIZE — and a 30s idle timeout.
 *
 * NO PUBLISHED FORMAT EXISTS. Unlike the HTTP/2 string above, nobody has
 * standardised how to serialise these, so the layout below is quico's own:
 * the same four-section, pipe-delimited shape, with QUIC's equivalents in
 * each slot.
 *
 *   TP | H3_SETTINGS | ALPN | GREASE
 *
 * That means these values are comparable ACROSS TIME and between quico
 * servers, but NOT against a third-party database — there is nothing to
 * compare them to. Which is fine for the actual use: catching a client whose
 * layers disagree with each other.
 *
 * A second caution: HTTP/3 fingerprinting is less settled than HTTP/2 in
 * general. Anti-bot products have not caught up to HTTP/2-level detection
 * here, and the parameters themselves are still moving.
 */
function h3Fingerprint(observed) {
  observed = observed || {};

  // Transport parameters SORTED by identifier, not left in the order sent.
  //
  // This is the opposite of the HTTP/2 section above, and measurement is why.
  // Chrome shuffles its QUIC transport parameters between connections: two
  // requests moments apart produced
  //
  //     5:6291456;9:103;15:L0;1:30000;17:0;3:1472;...
  //     8:100;3:1472;17:0;6:6291456;4:15728640;...
  //
  // — same parameters, same values, different order. Hashing them as sent
  // gives a fingerprint that never repeats, which is worse than no fingerprint
  // at all because it looks like it works.
  //
  // The shuffling is deliberate, and the same defensive idea as GREASE: it
  // stops anyone treating the order as fixed. So the order is noise here, and
  // sorting removes it — exactly as JA4 sorts TLS extensions and JA3, to its
  // cost, does not.
  //
  // Sorted NUMERICALLY, since these are numbers and a string sort would put
  // 17 before 3.
  var tp = Array.isArray(observed.transportParams) ? observed.transportParams : [];
  var t = tp.slice()
            .sort(function (a, b) { return Number(a.id) - Number(b.id); })
            .map(function (x) { return x.id + ':' + x.value; })
            .join(';');

  // HTTP/3's own SETTINGS frame — a different thing from the QUIC transport
  // parameters above: QPACK table size, blocked streams,
  // ENABLE_CONNECT_PROTOCOL.
  //
  // Left in the order sent, because unlike the transport parameters it IS
  // stable: the same Chrome produced 1:65536;6:262144;7:100;51:1 in that order
  // across every connection observed. Sorting it would throw away signal that
  // is really there.
  var h3s = Array.isArray(observed.h3Settings) ? observed.h3Settings : [];
  var h = h3s.map(function (x) { return x.id + ':' + x.value; }).join(';');

  // The connection-level flow-control window the client opened, mirroring the
  // WINDOW_UPDATE section of the HTTP/2 string. Chrome asks for 15MB over TCP
  // and a comparable figure over QUIC; libraries keep the default and ask for
  // nothing, which is its own signal.
  var wu = observed.windowUpdate ? String(observed.windowUpdate) : '0';

  // Pseudo-header order — the strongest section of the HTTP/2 fingerprint, and
  // no weaker here. Chrome sends m,a,s,p, Firefox m,p,a,s, Safari m,s,p,a;
  // the order is a constant in each browser's source and most HTTP libraries
  // match none of them.
  var ps = Array.isArray(observed.pseudoHeaderOrder) && observed.pseudoHeaderOrder.length
    ? observed.pseudoHeaderOrder.join(',')
    : '0';

  var raw = t + '|' + h + '|' + wu + '|' + ps;
  return {
    hash: sha12(raw),
    md5: crypto.createHash('md5').update(raw, 'utf8').digest('hex'),
    raw: raw,
    tp: t, h3: h, wu: wu, ps: ps,

    // GREASE stays OUTSIDE the hashed string, unlike the published HTTP/3
    // captures that write a literal "GREASE" token at the position it was
    // injected. Recording the position would be more informative, but only if
    // the position is stable — and it is not: the same Chrome shuffles its
    // transport parameters between connections, which is exactly why they are
    // sorted above. A position that moves would put the noise straight back
    // into the hash.
    //
    // So its PRESENCE is reported as a separate field, which is stable and is
    // most of the signal: browsers send GREASE, most libraries do not.
    grease: observed.grease ? '1' : '0'
  };
}


// ============================================================
//  Collection
// ============================================================

/**
 * Watch an H2Connection and accumulate what the fingerprint needs.
 *
 * Everything here arrives in the first flight, before any request, which is
 * the point: the fingerprint exists before the server has processed a single
 * byte of content and can be acted on before anything is served.
 *
 * Returns a getter; call it once a request has arrived, so the pseudo-header
 * order is known.
 */
function observeH2(conn) {
  var state = { settings: [], windowUpdate: 0, priorities: [], pseudoHeaderOrder: [] };

  // Two arguments: the object keyed by name, and the ordered list. The list is
  // the second one — the object cannot carry order, which is the whole point
  // of this section.
  conn.on('settings', function (settingsObj, settingsList) {
    if (state.settings.length) return;      // first SETTINGS only
    var list = settingsList || [];
    for (var i = 0; i < list.length; i++) {
      state.settings.push({ id: list[i].id, value: list[i].value });
    }
  });

  conn.on('window_update', function (streamId, increment) {
    // Stream 0 only — the connection-level window. Per-stream updates are
    // ordinary flow control and say nothing about the implementation.
    if (streamId === 0 && !state.windowUpdate) state.windowUpdate = increment;
  });

  conn.on('priority', function (streamId, exclusive, dependsOn, weight) {
    if (state.priorities.length >= 16) return;    // bounded; a peer controls this
    state.priorities.push({ streamId: streamId, exclusive: exclusive,
                            dependsOn: dependsOn, weight: weight });
  });

  conn.on('pseudo_order', function (names) {
    if (state.pseudoHeaderOrder.length) return;   // first request only
    state.pseudoHeaderOrder = pseudoHeaderOrder(names);
  });

  return function () { return h2Fingerprint(state); };
}


/**
 * Watch an H3Connection and its QUIC connection, and accumulate what the
 * HTTP/3 fingerprint needs.
 *
 * The mirror of observeH2, with the parts QUIC puts in different places: the
 * transport parameters arrive inside the TLS ClientHello and are read from the
 * QUIC connection, while the HTTP/3 SETTINGS arrive on the control stream.
 *
 * Returns a getter, callable once the handshake is complete.
 */
/**
 * Is this a GREASE identifier?
 *
 * RFC 9287 reserves identifiers of the form 31 * N + 27 for QUIC, and RFC 9114
 * uses the same construction for HTTP/3 settings. An endpoint sends one with a
 * random identifier and a random value purely to check that the peer ignores
 * what it does not recognise. Chrome does; most libraries do not.
 *
 * They MUST be stripped before hashing, for the same reason JA3 strips TLS
 * GREASE: identifier and value are both random per connection, so keeping them
 * yields a fingerprint that never repeats. What is kept is the single fact
 * that GREASE was present, which is a stable property of the implementation —
 * and, in practice, one of the cleaner browser-versus-library signals.
 *
 * The test is by MAGNITUDE, not by the 31N+27 formula, and that is deliberate.
 * A QUIC varint holds up to 2^62-1, well past the 2^53 where a JavaScript
 * number stops being exact — Chrome sent 4421552879925488000, which cannot be
 * represented and arrives already rounded. Any modulo on it answers a question
 * about the rounded value rather than the real one, and answers it wrongly.
 *
 * So: no real transport parameter or HTTP/3 setting is anywhere near that
 * range. Every one currently defined fits in a couple of bytes, and the
 * registry reserves the high space precisely so that GREASE can live there.
 * Treating "absurdly large" as "reserved" is exact where the arithmetic
 * cannot be.
 */
// Every identifier assigned by RFC 9000, RFC 9114 and their extensions is
// small: the transport parameters run to 0x20, the HTTP/3 settings to 0x33,
// and the registered extensions (datagrams, version negotiation) sit below
// 0x100. 4096 leaves an order of magnitude of headroom above anything real.
var GREASE_FLOOR = 0x1000;   // 4096

function isGrease(id) {
  var n = Number(id);
  if (!isFinite(n)) return false;

  // BY MAGNITUDE, not by the 31N+27 formula.
  //
  // The formula is what the RFCs describe for reserving the identifier space,
  // and it is the wrong test to apply here. Measured against what Chrome
  // actually sends — 12583, 12584, 41284154305, 4421552879925488000 — not one
  // satisfies it; their residues mod 31 are 1, 2, 6 and 8. Whatever Chrome
  // uses to pick a reserved identifier, it is not that formula, and a check
  // built on it lets every one of them into the hash along with its random
  // value.
  //
  // What IS true of all four, and of no assigned identifier, is that they are
  // enormous. That is the property to test.
  return n >= GREASE_FLOOR;
}


function observeH3(h3, quic, existingState) {
  // State may be handed in, because the two halves of an HTTP/3 connection
  // become available at different times: the QUIC transport parameters arrive
  // during the handshake, and the H3 control stream only afterwards. Passing
  // the accumulated state forward lets a caller attach to QUIC early and to H3
  // later without losing what the first pass collected.
  var state = existingState ||
              { transportParams: [], h3Settings: [], alpn: 'h3', grease: false,
                windowUpdate: 0, pseudoHeaderOrder: [] };

  if (h3 && h3.on) {
    h3.on('pseudo_order', function (names) {
      if (state.pseudoHeaderOrder.length) return;     // first request only
      state.pseudoHeaderOrder = pseudoHeaderOrder(names);
    });

    h3.on('peer_settings', function (ordered) {
      if (state.h3Settings.length) return;
      for (var i = 0; i < ordered.length; i++) {
        if (isGrease(ordered[i].id)) { state.grease = true; continue; }
        state.h3Settings.push({ id: ordered[i].id, value: ordered[i].value });
      }
    });
  }

  if (quic && quic.on) {
    quic.on('peer_max_data', function (bytes) {
      // initial_max_data from the transport parameters: the connection-level
      // window, and the QUIC equivalent of an HTTP/2 WINDOW_UPDATE on stream 0.
      if (!state.windowUpdate) state.windowUpdate = bytes;
    });

    quic.on('peer_transport_params', function (params) {
      if (state.transportParams.length) return;
      for (var k = 0; k < (params || []).length; k++) {
        if (isGrease(params[k].id)) { state.grease = true; continue; }
        // 0x04 is initial_max_data — the connection-level window. Captured
        // into its own section as well as the parameter list, so the string
        // has the same four-part shape as the HTTP/2 one.
        if (Number(params[k].id) === 0x04 && !state.windowUpdate) {
          state.windowUpdate = params[k].value;
        }
        state.transportParams.push({ id: params[k].id, value: params[k].value });
      }
    });
  }

  var getter = function () { return h3Fingerprint(state); };
  // Exposed so a second call can continue accumulating into the same object.
  getter.state = state;
  return getter;
}


export { h2Fingerprint, h3Fingerprint, observeH2, observeH3, pseudoHeaderOrder, isGrease };