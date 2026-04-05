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

import flat_ranges from 'flat-ranges';

import {
  Emitter,
  concatUint8Arrays,
  uint8Equal,
  ack_frame_to_ranges,
  ranges_to_ack_frame
} from './utils.js';

import {
  quic_derive_init_secrets,
  quic_derive_from_tls_secrets,
  quic_derive_key_update,
  encrypt_quic_packet,
  decrypt_quic_packet,
  extract_tls_messages_from_chunks
} from './crypto.js';

import {
  parse_quic_datagram,
  encode_quic_frames,
  parse_quic_frames
} from './transport.js';

import { TLSBridge } from './tls_bridge.js';


function QUICConnection(options) {
  if (!(this instanceof QUICConnection)) return new QUICConnection(options);
  options = options || {};

  var ev = Emitter();
  var tls = null;

  // ============================================================
  //  Context
  // ============================================================

  var context = {
    isServer: options.isServer !== false,
    state: 'idle',
    handshake_done: false,
    handshake_done_sent: false,

    version: 1,
    original_dcid: null,
    my_cids: [],
    their_cids: [],

    // Keys
    initial_read: null,
    initial_write: null,
    handshake_read: null,
    handshake_write: null,
    app_read: null,
    app_write: null,
    app_prev_read: null,       // previous read keys (kept during transition)
    key_phase: false,          // our current send key_phase
    read_key_phase: false,     // expected key_phase on incoming packets
    app_read_secret: null,     // current read secret (for deriving next)
    app_write_secret: null,    // current write secret (for deriving next)
    cipher_hash: 'sha256',     // hash for key derivation
    cipher_suite: null,        // TLS cipher suite code (for key length)

    // Packet numbers — sending
    send_pn: { initial: 0, handshake: 0, app: 0 },

    // Packet numbers — receiving
    recv_pn_largest: { initial: -1, handshake: -1, app: -1 },
    recv_pn_ranges: { initial: [], handshake: [], app: [] },

    // CRYPTO
    crypto_chunks: { initial: {}, handshake: {} },
    crypto_offset: { initial: 0, handshake: 0 },
    crypto_send_offset: { initial: 0, handshake: 0, app: 0 },

    // ACK
    pending_ack: { initial: [], handshake: [], app: [] },

    // Receiving streams
    recv_streams: {},

    // Sending streams
    send_streams: {},

    // In-flight tracking (Phase 1)
    sending_app_pn_in_flight: new Set(),
    sending_app_pn_history: [],

    // Burst scheduler config (Phase 2)
    max_packets_per_burst: 20,
    max_packets_per_sec: 5000,
    max_bytes_per_sec: 10000000,   // 10MB/s
    max_packet_payload: 1100,
    max_packets_in_flight: 100,
    max_bytes_in_flight: 5000000,  // 5MB
    burst_timer: null,

    // Pending app packets
    pending_app_packets: [],

    // Flow control — connection level
    bytes_sent: 0,                    // total STREAM bytes sent
    bytes_received: 0,                // total STREAM bytes received
    remote_max_data: 1048576,         // peer's limit on what we can send (default 1MB until parsed)
    local_max_data: 1048576,          // our limit on what peer can send (matches transport params)
    local_max_data_consumed: 0,       // how much of local_max_data has been used
    local_max_data_threshold: 0.5,    // send MAX_DATA when consumed > threshold × local_max_data
    remote_max_streams_bidi: 100,
    remote_max_streams_uni: 3,

    // RTT
    rtt_history: [],

    // Timers
    idle_timeout: options.idleTimeout || 30000,
    handshake_timeout: options.handshakeTimeout || 10000,
    last_activity: Date.now(),
    idle_timer: null,
    handshake_timer: null,

    SNICallback: options.SNICallback || null,
    hostname: options.hostname || null,
  };


  // ============================================================
  //  set_context
  // ============================================================

  function set_context(updates) {
    if (!updates || typeof updates !== 'object') return;
    var changed = {};

    if ('state' in updates && updates.state !== context.state) {
      context.state = updates.state;
      changed.state = true;
    }
    if ('handshake_done' in updates && updates.handshake_done !== context.handshake_done) {
      context.handshake_done = updates.handshake_done;
      changed.handshake_done = true;
    }
    if ('handshake_done_sent' in updates) {
      context.handshake_done_sent = updates.handshake_done_sent;
    }
    if ('original_dcid' in updates && updates.original_dcid !== null && context.original_dcid === null) {
      context.original_dcid = updates.original_dcid;
      changed.original_dcid = true;
    }
    if ('version' in updates && updates.version !== context.version) {
      context.version = updates.version;
    }
    if ('add_their_cid' in updates) {
      var cid = updates.add_their_cid;
      var found = false;
      for (var i = 0; i < context.their_cids.length; i++) {
        if (uint8Equal(cid, context.their_cids[i])) { found = true; break; }
      }
      if (!found) context.their_cids.push(cid);
    }
    if ('initial_read' in updates)   { context.initial_read = updates.initial_read; changed.initial_read = true; }
    if ('initial_write' in updates)  { context.initial_write = updates.initial_write; changed.initial_write = true; }
    if ('handshake_read' in updates) { context.handshake_read = updates.handshake_read; }
    if ('handshake_write' in updates){ context.handshake_write = updates.handshake_write; }
    if ('app_read' in updates)       { context.app_read = updates.app_read; }
    if ('app_write' in updates)      { context.app_write = updates.app_write; }
    if ('remote_max_data' in updates && updates.remote_max_data > context.remote_max_data) {
      context.remote_max_data = updates.remote_max_data; changed.remote_max_data = true;
    }
    if ('remote_max_streams_bidi' in updates) { context.remote_max_streams_bidi = updates.remote_max_streams_bidi; }
    if ('remote_max_streams_uni' in updates)  { context.remote_max_streams_uni = updates.remote_max_streams_uni; }
    if ('key_phase' in updates && updates.key_phase !== context.key_phase) {
      context.key_phase = updates.key_phase; changed.key_phase = true;
    }

    // ---- Reactive ----

    if (changed.initial_read || changed.initial_write) {
      if (context.state === 'idle') { context.state = 'handshaking'; changed.state = true; }
    }

    if (changed.handshake_done && context.handshake_done === true) {
      console.log('[quic] handshake done — flushing ' + context.pending_app_packets.length + ' pending');
      if (context.pending_app_packets.length > 0) {
        var pending = context.pending_app_packets;
        context.pending_app_packets = [];
        for (var i = 0; i < pending.length; i++) {
          processDecryptedPacket('app', pending[i].packet_number, pending[i].plaintext);
        }
      }
      startIdleTimer();
    }

    if (changed.state && context.state === 'connected') {
      // 'connect' event is emitted explicitly by TLS handlers (not here)
      // Server emits on appSecrets, Client emits on secureConnect
    }

    if (changed.state && context.state === 'draining') {
      clearIdleTimer();
      var _drainTimer = setTimeout(function () {
        if (context.state === 'draining') { context.state = 'closed'; ev.emit('close'); }
      }, Math.min(3000, context.idle_timeout / 3));
      if (_drainTimer.unref) _drainTimer.unref();
    }

    if (changed.state && context.state === 'closed') { clearIdleTimer(); ev.emit('close'); }
    if (changed.remote_max_data) { plan_quic_burst(); }
    if (changed.key_phase) {
      // We initiated key update — derive new write keys
      if (context.app_write_secret) {
        var next = quic_derive_key_update(context.app_write_secret, context.cipher_hash, context.cipher_suite);
        console.log('[quic] key update initiated — new write keys');
        context.app_write = { key: next.key, iv: next.iv, hp: context.app_write.hp };
        context.app_write_secret = next.secret;
      }
    }
  }


  // ============================================================
  //  Idle timeout
  // ============================================================

  function touchActivity() { context.last_activity = Date.now(); }

  function startIdleTimer() {
    clearIdleTimer();
    if (context.idle_timeout <= 0) return;
    context.idle_timer = setInterval(function () {
      if (Date.now() - context.last_activity >= context.idle_timeout) {
        console.log('[quic] idle timeout');
        close(0, 'idle timeout');
      }
    }, Math.max(1000, Math.floor(context.idle_timeout / 4)));
    if (context.idle_timer.unref) context.idle_timer.unref();
  }

  function clearIdleTimer() {
    if (context.idle_timer !== null) { clearInterval(context.idle_timer); context.idle_timer = null; }
  }


  // ============================================================
  //  TLS Bridge
  // ============================================================

  function initTLS() {
    // Start handshake timeout — if TLS doesn't complete in time, close
    if (context.handshake_timeout > 0 && !context.handshake_timer) {
      context.handshake_timer = setTimeout(function () {
        if (context.state !== 'connected' && context.state !== 'closed' && context.state !== 'draining') {
          console.log('[quic] handshake timeout (' + context.handshake_timeout + 'ms)');
          ev.emit('error', new Error('QUIC handshake timeout'));
          close(0x100, 'handshake timeout');  // 0x100 = CRYPTO_ERROR
        }
      }, context.handshake_timeout);
      if (context.handshake_timer.unref) context.handshake_timer.unref();
    }

    tls = new TLSBridge({
      isServer: context.isServer,
      SNICallback: context.SNICallback,
      originalDcid: context.original_dcid,
      localCid: context.my_cids.length > 0 ? context.my_cids[0] : new Uint8Array(0),
      hostname: context.hostname
    });

    tls.on('send', function (epoch, data) { cryptoWrite(epoch, data); });

    tls.on('handshakeSecrets', function (secrets) {
      set_context({
        handshake_read: quic_derive_from_tls_secrets(secrets.remote, secrets.hash, secrets.cipher),
        handshake_write: quic_derive_from_tls_secrets(secrets.local, secrets.hash, secrets.cipher)
      });
    });

    tls.on('appSecrets', function (secrets) {
      // Handshake complete — clear timeout
      if (context.handshake_timer) {
        clearTimeout(context.handshake_timer);
        context.handshake_timer = null;
      }

      // Store secrets for future key updates (RFC 9001 §6)
      context.app_read_secret = secrets.remote;
      context.app_write_secret = secrets.local;
      context.cipher_hash = secrets.hash;
      context.cipher_suite = secrets.cipher;

      set_context({
        app_read: quic_derive_from_tls_secrets(secrets.remote, secrets.hash, secrets.cipher),
        app_write: quic_derive_from_tls_secrets(secrets.local, secrets.hash, secrets.cipher),
        state: 'connected',
        handshake_done: true
      });

      // Server: emit connect now (Finished already sent)
      // Client: wait for secureConnect (after client Finished is generated)
      if (context.isServer) {
        ev.emit('connect');
      }
    });

    tls.on('secureConnect', function () {
      // Client: Finished has been generated and queued. 
      // Flush handshake first, then emit connect so 1-RTT goes after Finished.
      if (!context.isServer) {
        plan_quic_burst(); // flush any pending handshake data (Finished)
        ev.emit('connect');
      }
    });

    // Note: QUIC handles key updates via key_phase bit, not TLS KeyUpdate message.
    // RFC 9001 §6: "endpoints MUST treat the receipt of a TLS KeyUpdate message
    // as a connection error of type 0x010a" — but we silently ignore it.
  }


  // ============================================================
  //  Incoming packets
  // ============================================================

  function feedDatagram(from_ip, from_port, data) {
    console.log('[quic] datagram from ' + from_ip + ':' + from_port + ' len=' + data.length);
    touchActivity();
    var packets = parse_quic_datagram(data);
    for (var i = 0; i < packets.length; i++) {
      if (packets[i] !== null) feedPacket(packets[i]);
    }
  }

  function feedPacket(pkt) {
    if (context.state === 'draining' || context.state === 'closed') return;

    if (pkt.version && pkt.version !== context.version) set_context({ version: pkt.version });
    if (pkt.dcid && pkt.dcid.byteLength > 0) set_context({ original_dcid: pkt.dcid });
    if (pkt.scid && pkt.scid.byteLength > 0) set_context({ add_their_cid: pkt.scid });

    var space = pkt.type === 'initial' ? 'initial'
              : pkt.type === 'handshake' ? 'handshake'
              : pkt.type === '1rtt' ? 'app' : null;
    if (!space) return;

    if (space === 'initial' && !context.initial_read && context.original_dcid) {
      set_context({
        initial_read: quic_derive_init_secrets(context.original_dcid, context.version, 'read'),
        initial_write: quic_derive_init_secrets(context.original_dcid, context.version, 'write')
      });
    }

    var readKeys = space === 'initial' ? context.initial_read
                 : space === 'handshake' ? context.handshake_read : context.app_read;
    if (!readKeys) return;

    var decrypted = decrypt_quic_packet(
      pkt.raw, readKeys.key, readKeys.iv, readKeys.hp,
      context.original_dcid, context.recv_pn_largest[space]
    );

    // Key Update: if app decrypt fails, try with derived next keys
    if ((!decrypted || !decrypted.plaintext) && space === 'app' && context.app_read_secret) {
      var next = quic_derive_key_update(context.app_read_secret, context.cipher_hash, context.cipher_suite);
      decrypted = decrypt_quic_packet(
        pkt.raw, next.key, next.iv, readKeys.hp, // HP doesn't change
        context.original_dcid, context.recv_pn_largest[space]
      );

      if (decrypted && decrypted.plaintext && decrypted.plaintext.byteLength > 0) {
        // Key update confirmed — install new read keys
        console.log('[quic] key update detected — installing new read keys');
        context.app_prev_read = context.app_read;
        context.app_read = { key: next.key, iv: next.iv, hp: readKeys.hp };
        context.app_read_secret = next.secret;
        context.read_key_phase = !context.read_key_phase;
      }
    }

    // Also try prev keys for reordered packets from before key update
    if ((!decrypted || !decrypted.plaintext) && space === 'app' && context.app_prev_read) {
      decrypted = decrypt_quic_packet(
        pkt.raw, context.app_prev_read.key, context.app_prev_read.iv, context.app_prev_read.hp,
        context.original_dcid, context.recv_pn_largest[space]
      );
    }

    if (!decrypted || !decrypted.plaintext || decrypted.plaintext.byteLength === 0) {
      console.log('[quic] decrypt failed: ' + space + ' raw_len=' + pkt.raw.byteLength + ' first20=' + Array.from(pkt.raw.slice(0, 20)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ') + ' dcid_len=' + (context.original_dcid ? context.original_dcid.byteLength : 'null') + ' has_keys=' + !!readKeys + ' largest_pn=' + context.recv_pn_largest[space]);
      return;
    }

    console.log('[quic] decrypted ' + space + ' pn=' + decrypted.packet_number + ' len=' + decrypted.plaintext.byteLength);

    var pn = decrypted.packet_number;
    var ranges = context.recv_pn_ranges[space];
    var isNew = true;
    for (var ri = 0; ri < ranges.length; ri += 2) {
      if (pn >= ranges[ri] && pn < ranges[ri + 1]) { isNew = false; break; }
    }
    if (isNew) {
      flat_ranges.add(ranges, [pn, pn + 1]);
      if (pn > context.recv_pn_largest[space]) context.recv_pn_largest[space] = pn;
    }

    console.log('[quic] pn=' + pn + ' isNew=' + isNew);
    if (!isNew) return;

    if (space === 'app' && !context.handshake_done) {
      context.pending_app_packets.push(decrypted);
      return;
    }

    processDecryptedPacket(space, pn, decrypted.plaintext);
  }


  // ============================================================
  //  Frame processing
  // ============================================================

  function processDecryptedPacket(space, packetNumber, plaintext) {
    var frames = parse_quic_frames(plaintext);
    console.log('[quic] frames: ' + space + ' pn=' + packetNumber + ' [' + frames.map(function(f){ return f.type; }).join(',') + ']');
    var ackEliciting = false;

    if (context.isServer && space === 'app' && !context.handshake_done_sent) {
      set_context({ handshake_done_sent: true });
      sendFrames('app', [{ type: 'handshake_done' }]);
    }

    for (var i = 0; i < frames.length; i++) {
      var frame = frames[i];

      if (frame.type === 'crypto') {
        ackEliciting = true;
        processCryptoFrame(space, frame.offset, frame.data);
      } else if (frame.type === 'stream') {
        ackEliciting = true;
        processStreamFrame(frame);
      } else if (frame.type === 'ack') {
        processAckFrame(space, frame);
      } else if (frame.type === 'ping') {
        ackEliciting = true;
      } else if (frame.type === 'handshake_done') {
        ackEliciting = true;
      } else if (frame.type === 'path_challenge') {
        ackEliciting = true;
        sendFrames(space, [{ type: 'path_response', data: frame.data }]);
      } else if (frame.type === 'new_connection_id') {
        ackEliciting = true;
      } else if (frame.type === 'connection_close') {
        console.log('[quic] CONNECTION_CLOSE error=0x' + (frame.error || 0).toString(16) + ' frame_type=0x' + (frame.frameType || 0).toString(16) + ' reason="' + (frame.reason || '') + '"');
        set_context({ state: 'draining' });
        return;
      } else if (frame.type === 'stop_sending') {
        // Peer says: stop sending on this stream
        ackEliciting = true;
        if (frame.id in context.send_streams) {
          console.log('[quic] STOP_SENDING stream=' + frame.id + ' error=' + frame.error);
          delete context.send_streams[frame.id];
        }
      } else if (frame.type === 'reset_stream') {
        // Peer cancelled their stream
        ackEliciting = true;
        if (frame.id in context.recv_streams) {
          console.log('[quic] RESET_STREAM stream=' + frame.id + ' error=' + frame.error);
          delete context.recv_streams[frame.id];
        }
      } else if (frame.type === 'max_data') {
        ackEliciting = true;
        set_context({ remote_max_data: frame.max });
      } else if (frame.type === 'max_streams_bidi') {
        ackEliciting = true;
        set_context({ remote_max_streams_bidi: frame.max });
      } else if (frame.type === 'max_streams_uni') {
        ackEliciting = true;
        set_context({ remote_max_streams_uni: frame.max });
      } else if (frame.type === 'max_stream_data') {
        ackEliciting = true;
      } else if (frame.type === 'datagram') {
        ev.emit('datagram', frame.contextId, frame.data);
      }
    }

    if (ackEliciting) {
      flat_ranges.add(context.pending_ack[space], [packetNumber, packetNumber + 1]);
      var ackFrame = ranges_to_ack_frame(context.pending_ack[space], null, 0);
      if (ackFrame) {
        sendFrames(space, [ackFrame]);
        if (space !== 'app') context.pending_ack[space] = [];
      }
    }
  }


  // ============================================================
  //  CRYPTO → TLS
  // ============================================================

  function processCryptoFrame(space, offset, data) {
    if (space !== 'initial' && space !== 'handshake') return;
    console.log('[quic] CRYPTO: space=' + space + ' offset=' + offset + ' len=' + data.length);

    var chunks = context.crypto_chunks[space];
    var fromOffset = context.crypto_offset[space];
    if (!(offset in chunks) || chunks[offset].byteLength < data.byteLength) chunks[offset] = data;

    var result = extract_tls_messages_from_chunks(chunks, fromOffset);
    console.log('[quic] TLS messages: ' + (result ? result.tls_messages.length : 'none'));
    if (!result) return;

    context.crypto_offset[space] = result.new_from_offset;
    if (!tls) { console.log('[quic] initializing TLS bridge'); initTLS(); }

    for (var i = 0; i < result.tls_messages.length; i++) {
      var msg = result.tls_messages[i];
      var msgType = msg[0];
      console.log('[quic] → TLS msg #' + i + ' type=0x' + msgType.toString(16) + ' len=' + msg.length);

      // Detect HelloRetryRequest (type 0x02 with special random)
      if (msgType === 0x02 && msg.length >= 38) {
        var hrrRandom = [0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C];
        var isHRR = true;
        for (var j = 0; j < 32; j++) { if (msg[6 + j] !== hrrRandom[j]) { isHRR = false; break; } }
        if (isHRR) console.log('[quic] ⚠️  HelloRetryRequest detected! LemonTLS needs HRR support.');
      }

      tls.feedMessage(msg);
    }
  }


  // ============================================================
  //  Stream receive
  // ============================================================

  function processStreamFrame(frame) {
    var sid = frame.id;
    if (!(sid in context.recv_streams)) {
      context.recv_streams[sid] = { chunks: {}, ranges: [], total_size: 0, flushed_to: 0 };
    }
    var stream = context.recv_streams[sid];

    var alreadyHave = false;
    for (var ri = 0; ri < stream.ranges.length; ri += 2) {
      if (frame.offset >= stream.ranges[ri] && frame.offset + frame.data.length <= stream.ranges[ri + 1]) {
        alreadyHave = true; break;
      }
    }
    if (!alreadyHave) {
      flat_ranges.add(stream.ranges, [frame.offset, frame.offset + frame.data.length]);
      if (!(frame.offset in stream.chunks) || stream.chunks[frame.offset].byteLength < frame.data.byteLength) {
        stream.chunks[frame.offset] = frame.data;
      }
      // Track connection-level bytes received
      context.bytes_received += frame.data.byteLength;
      checkLocalFlowControl();
    }
    if (frame.fin && stream.total_size === 0) stream.total_size = frame.offset + frame.data.length;
    flushStream(sid);
  }

  /**
   * Check if we need to send MAX_DATA to give the peer more send capacity.
   * When consumed > threshold × window, double the window and notify peer.
   */
  function checkLocalFlowControl() {
    if (context.bytes_received > context.local_max_data * context.local_max_data_threshold) {
      var newMax = context.local_max_data * 2;
      context.local_max_data = newMax;
      sendFrames('app', [{ type: 'max_data', max: newMax }]);
    }
  }

  function flushStream(sid) {
    var stream = context.recv_streams[sid];
    if (!stream) return;
    var parts = [];
    var offset = stream.flushed_to;
    while (offset in stream.chunks) {
      var chunk = stream.chunks[offset];
      delete stream.chunks[offset];
      parts.push(chunk);
      offset += chunk.byteLength;
    }
    if (parts.length === 0) return;
    stream.flushed_to = offset;
    var data = parts.length === 1 ? parts[0] : concatUint8Arrays(parts);
    var fin = (stream.total_size > 0 && offset >= stream.total_size);
    ev.emit('stream', Number(sid), data, fin);
    if (fin) setTimeout(function () { delete context.recv_streams[sid]; }, 100);
  }


  // ============================================================
  //  ACK processing (Phase 1)
  // ============================================================

  function processAckFrame(space, frame) {
    var ackedRanges = ack_frame_to_ranges(frame);
    if (!ackedRanges || ackedRanges.length === 0) return;

    if (space === 'app') {
      // RTT measurement
      if ('largest' in frame && 'delay' in frame) {
        var largest_pn = frame.largest;
        if (context.sending_app_pn_in_flight.has(largest_pn)) {
          var now = Date.now();
          var ack_delay_ms = Math.round((frame.delay * Math.pow(2, 3)) / 1000);
          var pn_index = largest_pn - (context.send_pn.app - context.sending_app_pn_history.length);
          if (pn_index >= 0 && pn_index < context.sending_app_pn_history.length) {
            var measured_rtt = now - context.sending_app_pn_history[pn_index][0] - ack_delay_ms;
            if (measured_rtt > 0) context.rtt_history.push([now, measured_rtt]);
          }
        }
      }

      // Mark in-flight as acked
      for (var pn of context.sending_app_pn_in_flight) {
        var is_acked = false;
        for (var ri = 0; ri < ackedRanges.length; ri += 2) {
          if (pn >= ackedRanges[ri] && pn <= ackedRanges[ri + 1]) { is_acked = true; break; }
        }
        if (is_acked) {
          context.sending_app_pn_in_flight.delete(pn);
          for (var sid in context.send_streams) {
            var st = context.send_streams[sid];
            if (st.in_flight_ranges && pn in st.in_flight_ranges) {
              flat_ranges.add(st.acked_ranges, st.in_flight_ranges[pn]);
              delete st.in_flight_ranges[pn];
              if (st.total_size > 0 && st.acked_ranges.length === 2 &&
                  st.acked_ranges[0] === 0 && st.acked_ranges[1] >= st.total_size) {
                delete context.send_streams[sid];
              }
            }
          }
        }
      }

      // ACK freed capacity — try to send more
      plan_quic_burst();
    }
  }


  // ============================================================
  //  Sending
  // ============================================================

  function cryptoWrite(epoch, data) {
    var space = epoch === 'initial' ? 'initial' : epoch === 'handshake' ? 'handshake' : 'app';
    var offset = context.crypto_send_offset[space];
    context.crypto_send_offset[space] += data.byteLength;
    sendFrames(space, [{ type: 'crypto', offset: offset, data: data }]);
  }

  function sendFrames(space, frameList) {
    var writeKeys = space === 'initial' ? context.initial_write
                  : space === 'handshake' ? context.handshake_write : context.app_write;
    if (!writeKeys) { console.log('[quic] sendFrames(' + space + ') — no keys'); return; }

    var pn = context.send_pn[space]++;
    var packetType = space === 'initial' ? 'initial' : space === 'handshake' ? 'handshake' : '1rtt';

    var dcid, scid;
    if (packetType === '1rtt') {
      dcid = context.their_cids.length > 0 ? context.their_cids[0] : new Uint8Array(0);
      scid = new Uint8Array(0);
    } else if (context.isServer) {
      dcid = context.their_cids.length > 0 ? context.their_cids[0] : new Uint8Array(0);
      scid = context.original_dcid || new Uint8Array(0);
    } else {
      // Client: Initial uses original_dcid (for key derivation),
      // Handshake uses server's SCID (RFC 9000 §7.2)
      if (space === 'initial' || context.their_cids.length === 0) {
        dcid = context.original_dcid || new Uint8Array(0);
      } else {
        dcid = context.their_cids[0];
      }
      scid = context.my_cids.length > 0 ? context.my_cids[0] : new Uint8Array(0);
    }

    var encoded = encode_quic_frames(frameList);

    // RFC 9000 §14.1: Initial datagrams must be >= 1200 bytes
    if (space === 'initial') {
      var overhead = 1 + 4 + 1 + dcid.byteLength + 1 + scid.byteLength + 1 + 2 + 1 + 16;
      var minPayload = 1200 - overhead;
      if (encoded.length < minPayload) {
        encoded = concatUint8Arrays([encoded, new Uint8Array(minPayload - encoded.length)]);
      }
    }

    var encrypted = encrypt_quic_packet(
      packetType, encoded, writeKeys.key, writeKeys.iv, writeKeys.hp, pn, dcid, scid, null,
      space === 'app' ? context.key_phase : false
    );

    if (encrypted) {
      var fnames = frameList.map(function(f){ return f.type + (f.type === 'ack' ? '(lg=' + f.largest + ')' : ''); }).join(',');
      console.log('[quic] → ' + packetType + ' pn=' + pn + ' frames=[' + fnames + '] len=' + encrypted.length);
      touchActivity();

      if (space === 'app') {
        context.sending_app_pn_history.push([Date.now(), encoded.length]);
        var has_data = false;
        for (var i = 0; i < frameList.length; i++) {
          if (frameList[i].type === 'stream' || frameList[i].type === 'crypto') { has_data = true; break; }
        }
        if (has_data) context.sending_app_pn_in_flight.add(pn);

        for (var i = 0; i < frameList.length; i++) {
          if (frameList[i].type === 'stream') {
            var sid = frameList[i].id;
            var dataLen = frameList[i].data ? frameList[i].data.byteLength : 0;

            // Track connection-level bytes sent
            context.bytes_sent += dataLen;

            if (sid in context.send_streams) {
              if (!context.send_streams[sid].in_flight_ranges) context.send_streams[sid].in_flight_ranges = {};
              var from = frameList[i].offset;
              var to = from + (frameList[i].data ? frameList[i].data.byteLength : 0);
              if (!context.send_streams[sid].in_flight_ranges[pn]) {
                context.send_streams[sid].in_flight_ranges[pn] = [from, to];
              } else {
                flat_ranges.add(context.send_streams[sid].in_flight_ranges[pn], [from, to]);
              }
            }
          }
        }
      }

      ev.emit('packet', encrypted);
    }
  }


  // ============================================================
  //  Stream send + Burst scheduler (Phase 2)
  //  Adapted from old quic_socket.js, improved with set_context
  // ============================================================

  /**
   * Buffer data for a stream. Does NOT send immediately.
   * Calls plan_quic_burst() to schedule sending.
   */
  function set_sending_stream(streamId, options) {
    if (!(streamId in context.send_streams)) {
      context.send_streams[streamId] = {
        pending_data: null, pending_offset_start: 0,
        write_offset: 0, send_offset: 0, total_size: 0,
        fin_sent: false, acked_ranges: [], in_flight_ranges: {}
      };
    }

    var stream = context.send_streams[streamId];

    if (typeof options === 'object' && 'add_chunk' in options) {
      if (options.add_chunk.data === null || options.add_chunk.data === undefined) {
        if (stream.total_size === 0) {
          stream.total_size = stream.write_offset;
          console.log('[quic] stream ' + streamId + ' FIN via null data, total_size=' + stream.total_size);
        }
      } else {
        var chunk = options.add_chunk.data;
        if (typeof chunk === 'string') chunk = new TextEncoder().encode(chunk);
        var start = stream.write_offset;
        stream.write_offset += chunk.byteLength;
        console.log('[quic] stream ' + streamId + ' add_chunk len=' + chunk.byteLength + ' write_offset=' + stream.write_offset + ' fin=' + !!options.add_chunk.fin);

        if (stream.pending_data === null) {
          stream.pending_data = chunk;
          stream.pending_offset_start = start;
        } else {
          var old = stream.pending_data, old_off = stream.pending_offset_start;
          var ns = Math.min(old_off, start);
          var ne = Math.max(old_off + old.length, start + chunk.length);
          var merged = new Uint8Array(ne - ns);
          merged.set(old, old_off - ns);
          merged.set(chunk, start - ns);
          stream.pending_data = merged;
          stream.pending_offset_start = ns;
        }
        if (options.add_chunk.fin) {
          stream.total_size = stream.write_offset;
          console.log('[quic] stream ' + streamId + ' FIN via add_chunk.fin, total_size=' + stream.total_size);
        }
      }
    }

    // Don't send directly — let burst scheduler handle it
    plan_quic_burst();
  }

  function sendStream(streamId, data, fin) {
    set_sending_stream(streamId, { add_chunk: { data: data, fin: fin } });
  }

  function sendDatagram(data) {
    if (context.state !== 'connected') return;
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    sendFrames('app', [{ type: 'datagram', data: data }]);
  }


  /**
   * plan_quic_burst — calculates how many packets we can send,
   * calls execute_quic_burst, schedules next burst if needed.
   */
  function plan_quic_burst() {
    if (!context.app_write) return;
    if (context.state !== 'connected') return;

    // Cancel pending timer
    if (context.burst_timer !== null) {
      clearTimeout(context.burst_timer);
      clearImmediate(context.burst_timer);
      context.burst_timer = null;
    }

    var now = Date.now();
    var oneSecAgo = now - 1000;

    // Count bytes/packets sent in last second
    var bytesSentLastSec = 0;
    var packetsSentLastSec = 0;
    for (var i = 0; i < context.sending_app_pn_history.length; i++) {
      if (context.sending_app_pn_history[i][0] > oneSecAgo) {
        bytesSentLastSec += context.sending_app_pn_history[i][1];
        packetsSentLastSec++;
      }
    }

    // Prune old history (older than 2 seconds)
    var twoSecAgo = now - 2000;
    while (context.sending_app_pn_history.length > 0 && context.sending_app_pn_history[0][0] < twoSecAgo) {
      context.sending_app_pn_history.shift();
    }

    // Rate limits
    var bytesRemaining = context.max_bytes_per_sec - bytesSentLastSec;
    var packetsRemaining = context.max_packets_per_sec - packetsSentLastSec;
    if (bytesRemaining < 0) bytesRemaining = 0;
    if (packetsRemaining < 0) packetsRemaining = 0;

    // In-flight limits
    var inflightCount = context.sending_app_pn_in_flight.size;
    var inflightRoom = context.max_packets_in_flight - inflightCount;
    if (inflightRoom < 0) inflightRoom = 0;

    // Calculate burst size
    var burstCount = Math.min(
      context.max_packets_per_burst,
      packetsRemaining,
      inflightRoom,
      Math.floor(bytesRemaining / Math.max(1, 35))  // min packet ~35 bytes
    );
    if (burstCount < 0) burstCount = 0;

    // Check if there's anything to send
    var hasData = false;
    for (var sid in context.send_streams) {
      var st = context.send_streams[sid];
      if (!st.pending_data || st.pending_data.byteLength === 0) continue;
      var total = st.total_size > 0 ? st.total_size : st.write_offset;
      var known = st.acked_ranges.slice();
      if (st.in_flight_ranges) {
        for (var pn in st.in_flight_ranges) flat_ranges.add(known, st.in_flight_ranges[pn]);
      }
      var missing = flat_ranges.invert(known, 0, total);
      if (missing.length > 0) { hasData = true; break; }
      // Also check: all data sent but FIN not yet sent?
      if (st.total_size > 0 && !st.fin_sent && missing.length === 0) { hasData = true; break; }
    }
    // Also check pending ACK
    var hasPendingAck = context.pending_ack.app.length > 0;

    if (!hasData && !hasPendingAck) return;

    // Execute burst
    var sent = false;
    if (burstCount > 0) {
      sent = execute_quic_burst(burstCount);
    }

    // Schedule next burst if needed
    if (sent && hasData) {
      // More data to send — schedule next burst immediately (no timer delay)
      context.burst_timer = setImmediate(function () {
        context.burst_timer = null;
        plan_quic_burst();
      });
    } else if (burstCount === 0 && hasData) {
      // Rate limited — wait for capacity
      var waitMs = (packetsRemaining <= 0 || bytesRemaining < 35) ? 50 : 10;
      context.burst_timer = setTimeout(function () {
        context.burst_timer = null;
        plan_quic_burst();
      }, waitMs);
      if (context.burst_timer.unref) context.burst_timer.unref();
    }
  }


  /**
   * execute_quic_burst — fill up to packet_count packets.
   * Round-robin across active streams.
   * Returns true if at least one packet was sent.
   */
  function execute_quic_burst(packetCount) {
    var MAX_PAYLOAD = context.max_packet_payload;
    var OVERHEAD = 24; // STREAM frame header overhead estimate
    var sentAny = false;

    function getActiveIds() {
      var ids = [];
      for (var sid in context.send_streams) {
        var st = context.send_streams[sid];
        if (!st.pending_data || st.pending_data.byteLength === 0) continue;
        var total = st.total_size > 0 ? st.total_size : st.write_offset;
        // Build known_sent = acked + in_flight
        var known = st.acked_ranges.slice();
        if (st.in_flight_ranges) {
          for (var pn in st.in_flight_ranges) flat_ranges.add(known, st.in_flight_ranges[pn]);
        }
        var missing = flat_ranges.invert(known, 0, total);
        if (missing.length > 0) ids.push(Number(sid));
      }
      return ids;
    }

    var activeIds = getActiveIds();
    var burstYielded = {}; // track ranges yielded per-stream within this burst

    for (var p = 0; p < packetCount; p++) {
      var frames = [];
      var used = 0;

      // (1) ACK in first packet if pending
      if (p === 0 && context.pending_ack.app.length > 0) {
        var ackFrame = ranges_to_ack_frame(context.pending_ack.app, null, 0);
        if (ackFrame) {
          var ackEncoded = encode_quic_frames([ackFrame]);
          if (ackEncoded.byteLength <= MAX_PAYLOAD) {
            frames.push(ackFrame);
            used += ackEncoded.byteLength;
            context.pending_ack.app = [];
          }
        }
      }

      // (2) Round-robin STREAM data across active streams
      if (activeIds.length > 0 && used < MAX_PAYLOAD) {
        var progress = true;
        while (used < MAX_PAYLOAD && progress) {
          progress = false;

          for (var i = 0; i < activeIds.length; i++) {
            if (used >= MAX_PAYLOAD) break;

            var sid = activeIds[i];
            var st = context.send_streams[sid];
            if (!st || !st.pending_data) continue;

            var budget = Math.max(0, MAX_PAYLOAD - used - OVERHEAD);
            if (budget <= 0) break;

            var chunks = get_stream_chunks(sid, budget);
            if (!chunks || chunks.length === 0) continue;

            for (var c = 0; c < chunks.length; c++) {
              var ch = chunks[c];
              var fin = (st.total_size > 0 && ch.offset + ch.data.byteLength >= st.total_size);
              frames.push({ type: 'stream', id: sid, offset: ch.offset, fin: fin, data: ch.data });
              used += ch.data.byteLength + OVERHEAD;
              progress = true;

              // Immediately track as yielded so next round-robin iteration won't resend
              if (!burstYielded[sid]) burstYielded[sid] = [];
              flat_ranges.add(burstYielded[sid], [ch.offset, ch.offset + ch.data.byteLength]);
              // Also add to in_flight with temp key so get_stream_chunks sees it
              if (!st.in_flight_ranges) st.in_flight_ranges = {};
              if (!st.in_flight_ranges['_burst']) st.in_flight_ranges['_burst'] = [];
              flat_ranges.add(st.in_flight_ranges['_burst'], [ch.offset, ch.offset + ch.data.byteLength]);
            }
          }
        }
      }

      // (3) FIN-only frames: if all data sent/in-flight but FIN not yet sent
      for (var sid in context.send_streams) {
        var st = context.send_streams[sid];
        if (!st || st.total_size <= 0 || st.fin_sent) continue;
        // Check if all bytes are covered (acked + in_flight)
        var known = st.acked_ranges.slice();
        if (st.in_flight_ranges) {
          for (var pn in st.in_flight_ranges) flat_ranges.add(known, st.in_flight_ranges[pn]);
        }
        var missing = flat_ranges.invert(known, 0, st.total_size);
        console.log('[quic] FIN-only check stream=' + sid + ' total_size=' + st.total_size + ' fin_sent=' + st.fin_sent + ' missing=' + missing.length + ' known=' + JSON.stringify(known));
        if (missing.length === 0) {
          console.log('[quic] → sending FIN-only for stream ' + sid);
          // All data sent — send FIN-only STREAM frame
          frames.push({ type: 'stream', id: Number(sid), offset: st.total_size, fin: true, data: new Uint8Array(0) });
          st.fin_sent = true;
        }
      }

      // Send packet if it has content beyond just ACK-only
      if (frames.length > 0) {
        sendFrames('app', frames);
        sentAny = true;
        // Clean up temp _burst in_flight keys (real PN keys now recorded by sendFrames)
        for (var sid in burstYielded) {
          var st = context.send_streams[sid];
          if (st && st.in_flight_ranges && st.in_flight_ranges['_burst']) {
            delete st.in_flight_ranges['_burst'];
          }
        }
      } else {
        break; // nothing to fill further packets
      }

      // Refresh active list
      activeIds = getActiveIds();
      if (activeIds.length === 0) break;
    }

    return sentAny;
  }


  /**
   * get_stream_chunks — find what bytes are missing (not acked) and
   * extract up to maxBytes from pending_data.
   * Uses flat_ranges.invert(acked_ranges) — the heart of retransmit.
   * Adapted from old get_stream_chunks_to_send().
   *
   * Strategy: first forward from send_offset (new data),
   *           then fill gaps before send_offset (retransmit).
   * pending_data is NEVER deleted — only when stream is fully acked.
   */
  function get_stream_chunks(streamId, maxBytes) {
    var stream = context.send_streams[streamId];
    if (!stream || !stream.pending_data || stream.pending_data.byteLength === 0) return [];

    // Flow control: cap by remaining remote_max_data budget
    var fcBudget = context.remote_max_data - context.bytes_sent;
    if (fcBudget <= 0) return []; // blocked by flow control
    maxBytes = Math.min(maxBytes, fcBudget);

    var data = stream.pending_data;
    var baseOffset = stream.pending_offset_start;
    var totalSize = stream.total_size > 0 ? stream.total_size : stream.write_offset;

    // Build "known sent" = acked + in_flight (don't resend what's already in transit)
    var knownSent = stream.acked_ranges.slice(); // copy
    if (stream.in_flight_ranges) {
      for (var pn in stream.in_flight_ranges) {
        flat_ranges.add(knownSent, stream.in_flight_ranges[pn]);
      }
    }

    // What truly needs sending? = invert of knownSent over [0, totalSize)
    var missing = flat_ranges.invert(knownSent, 0, totalSize);
    if (!missing || missing.length === 0) return [];

    var sendOffset = stream.send_offset;
    var chunks = [];
    var used = 0;

    // Phase 1: forward from send_offset (new data, priority)
    for (var i = 0; i < missing.length; i += 2) {
      if (used >= maxBytes) break;
      var mFrom = missing[i];
      var mTo = missing[i + 1];

      // Only ranges at or after send_offset
      if (mTo <= sendOffset) continue;
      var from = Math.max(mFrom, sendOffset);
      var to = mTo;

      // Clamp to budget
      var len = Math.min(to - from, maxBytes - used);
      if (len <= 0) continue;

      // Clamp to buffer bounds
      var relStart = from - baseOffset;
      var relEnd = relStart + len;
      if (relStart < 0 || relStart >= data.byteLength) continue;
      if (relEnd > data.byteLength) { relEnd = data.byteLength; len = relEnd - relStart; }
      if (len <= 0) continue;

      chunks.push({ offset: from, data: data.slice(relStart, relEnd) });
      used += len;

      // Advance send_offset
      if (from + len > stream.send_offset) {
        stream.send_offset = from + len;
      }
    }

    // Phase 2: fill gaps before send_offset (retransmit lost data)
    // First update knownSent with what Phase 1 just yielded
    if (chunks.length > 0) {
      for (var ci = 0; ci < chunks.length; ci++) {
        flat_ranges.add(knownSent, [chunks[ci].offset, chunks[ci].offset + chunks[ci].data.byteLength]);
      }
      missing = flat_ranges.invert(knownSent, 0, totalSize);
    }
    if (used < maxBytes) {
      for (var i = 0; i < missing.length; i += 2) {
        if (used >= maxBytes) break;
        var mFrom = missing[i];
        var mTo = missing[i + 1];

        // Only ranges before send_offset
        if (mFrom >= sendOffset) break;
        var to = Math.min(mTo, sendOffset);

        var len = Math.min(to - mFrom, maxBytes - used);
        if (len <= 0) continue;

        var relStart = mFrom - baseOffset;
        var relEnd = relStart + len;
        if (relStart < 0 || relStart >= data.byteLength) continue;
        if (relEnd > data.byteLength) { relEnd = data.byteLength; len = relEnd - relStart; }
        if (len <= 0) continue;

        chunks.push({ offset: mFrom, data: data.slice(relStart, relEnd) });
        used += len;
      }
    }

    // Trim front of pending_data if beginning is fully acked (optimization)
    if (stream.acked_ranges.length >= 2 && stream.acked_ranges[0] === 0 && stream.acked_ranges[1] > baseOffset) {
      var trimTo = stream.acked_ranges[1];
      var trimBytes = trimTo - baseOffset;
      if (trimBytes > 0 && trimBytes < data.byteLength) {
        stream.pending_data = data.slice(trimBytes);
        stream.pending_offset_start = trimTo;
      }
    }

    return chunks;
  }


  // ============================================================
  //  Close
  // ============================================================

  function close(errorCode, reason) {
    if (context.state === 'closed' || context.state === 'draining') return;
    if (context.handshake_timer) { clearTimeout(context.handshake_timer); context.handshake_timer = null; }
    sendFrames('app', [{
      type: 'connection_close', application: false,
      error: errorCode || 0, frameType: 0, reason: reason || ''
    }]);
    set_context({ state: 'draining' });
  }


  // ============================================================
  //  Client connect (Phase 7)
  // ============================================================

  function connect() {
    if (context.isServer) return; // server waits for feedPacket, doesn't connect

    // Generate random DCID (8 bytes)
    var dcid = new Uint8Array(8);
    for (var i = 0; i < 8; i++) dcid[i] = Math.floor(Math.random() * 256);

    // Generate random SCID (8 bytes)
    var scid = new Uint8Array(8);
    for (var i = 0; i < 8; i++) scid[i] = Math.floor(Math.random() * 256);

    context.original_dcid = dcid;
    context.my_cids.push(scid);

    // Client initial keys: SWAPPED from server
    // Client writes with "client in" keys (direction='read' in our function)
    // Client reads with "server in" keys (direction='write' in our function)
    set_context({
      initial_write: quic_derive_init_secrets(dcid, context.version, 'read'),
      initial_read: quic_derive_init_secrets(dcid, context.version, 'write')
    });

    // Initialize TLS (client mode)
    console.log('[quic] client connecting, dcid=' + Array.from(dcid).map(function(b){ return b.toString(16).padStart(2,'0'); }).join(''));
    initTLS();

    // Trigger ClientHello by feeding empty message
    tls.feedMessage(new Uint8Array(0));
  }


  // ============================================================
  //  Public API
  // ============================================================

  var api = {
    context: context,
    on: function (name, fn) { ev.on(name, fn); },
    off: function (name, fn) { ev.off(name, fn); },
    feedDatagram: feedDatagram,
    sendStream: sendStream,
    sendDatagram: sendDatagram,
    close: close,
    connect: connect,
    set_context: set_context,
    get state() { return context.state; }
  };

  for (var k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }
  return this;
}

export { QUICConnection };
