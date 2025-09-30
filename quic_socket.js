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
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

// flat-ranges (CJS בלבד)
const flat_ranges = require('flat-ranges');

// Node core
import fs from 'node:fs';
import crypto from 'node:crypto';
import process from 'node:process';

// lemon-tls (מודול חיצוני, מניח שתומך ב-ESM)
import { TLSSession } from 'lemon-tls';

// ---- מודולים פנימיים ----
import {
  concatUint8Arrays,
  arraybufferEqual,
  quic_acked_info_to_ranges,
  build_ack_info_from_ranges,
  readVarInt,
  writeVarInt
} from './libs/utils.js';

import {
  decrypt_quic_packet,
  quic_derive_init_secrets,
  quic_derive_from_tls_secrets,
  build_quic_ext,
  hkdf_expand_label,
  encode_quic_frames,
  encrypt_quic_packet,
  parse_quic_datagram,
  parse_quic_packet,
  parse_quic_frames,
  extract_tls_messages_from_chunks,
  build_alpn_ext,
  parse_transport_parameters
} from './libs/crypto.js';

function Emitter(){
  var listeners = {};
  return {
    on: function(name, fn){ (listeners[name] = listeners[name] || []).push(fn); },
    emit: function(name){
      var args = Array.prototype.slice.call(arguments, 1);
      var arr = listeners[name] || [];
      for (var i=0;i<arr.length;i++){ try{ arr[i].apply(null, args); }catch(e){} }
    }
  };
}

var TLS_CIPHER_SUITES = {
  // ----------------------
  // TLS 1.3 (RFC 8446)
  // ----------------------
  0x1301: { // TLS_AES_128_GCM_SHA256
    tls:    13,
    kex:    'TLS13',
    sig:    'TLS13',
    cipher: 'AES_128_GCM',
    aead:   true,
    keylen: 16,
    ivlen:  12,
    hash:   'sha256'
  },
  0x1302: { // TLS_AES_256_GCM_SHA384
    tls:    13,
    kex:    'TLS13',
    sig:    'TLS13',
    cipher: 'AES_256_GCM',
    aead:   true,
    keylen: 32,
    ivlen:  12,
    hash:   'sha384'
  },
  0x1303: { // TLS_CHACHA20_POLY1305_SHA256
    tls:    13,
    kex:    'TLS13',
    sig:    'TLS13',
    cipher: 'CHACHA20_POLY1305',
    aead:   true,
    keylen: 32,
    ivlen:  12,
    hash:   'sha256'
  }
}

// ==== QUICSocket ====
function QUICSocket(options){
  if (!(this instanceof QUICSocket)) return new QUICSocket(options);
    options = options || {};

    var ev = Emitter();

    var context = {
        connection_status: 4,//0 - connecting... | 1 - connected | 2 - disconnected | ...

        version: 1,

        my_cids: [],             // SCIDים שאתה נתת (כנראה אחד ראשוני ועוד future)
        their_cids: [],          // DCIDים שהצד השני השתמש בהם (כלומר שלך כשרת)
        original_dcid: null,     // ל־Initial ול־Retry


        tls_session: null,

        SNICallback: options.SNICallback || null,

        //....
        init_read_key: null,
        init_read_iv: null,
        init_read_hp: null,

        init_write_key: null,
        init_write_iv: null,
        init_write_hp: null,
        
        handshake_read_key: null,
        handshake_read_iv: null,
        handshake_read_hp: null,

        handshake_write_key: null,
        handshake_write_iv: null,
        handshake_write_hp: null,

        app_prev_read_key: null,
        app_prev_read_iv: null,
        app_prev_read_hp: null,
        
        app_read_key: null,
        app_read_iv: null,
        app_read_hp: null,

        read_key_phase: false,

        app_write_key: null,
        app_write_iv: null,
        app_write_hp: null,

		handshake_done: false,
		handshake_done_sent: false,

        //sending...

        sending_init_pn_next: 1,
        sending_init_chunks: [],
        sending_init_offset_next: 0,
        sending_init_pn_acked_ranges: [],

        sending_handshake_pn_next: 1,
        sending_handshake_chunks: [],
        sending_handshake_offset_next: 0,
        sending_handshake_pn_acked_ranges: [],
        
        
        sending_streams: {},
        sending_stream_id_next: 0,

        

        max_sending_packets_per_sec: 1000,
        max_sending_total_bytes_per_sec: 150000,
        max_sending_packet_size: 1200,
        min_sending_packet_size: 35,

        max_sending_packets_in_flight: 20,
        max_sending_bytes_in_flight: 150000,

        sending_app_pn_base: 1,
        sending_app_pn_history: [],
        rtt_history: [],
        sending_app_pn_in_flight: new Set(),

        next_send_quic_packet_timer: null,
        sending_quic_packet_now: false,

        
        //received...

        receiving_init_pn_largest: -1,
        receiving_init_pn_ranges: [],
        receiving_init_chunks: {},
        receiving_init_from_offset: 0,
        receiving_init_ranges: [],//מערך שטוח של מ עד
        
        receiving_handshake_pn_largest: -1,
        receiving_handshake_pn_ranges: [],
        receiving_handshake_chunks: {},
        receiving_handshake_from_offset: 0,
        receiving_handshake_ranges: [],//מערך שטוח של מ עד

        receiving_app_pn_largest: -1,
        receiving_app_pn_ranges: [],
        receiving_app_pn_history: [],

        receiving_app_pn_pending_ack: [],


        receiving_streams: {}, // stream_id → stream object
        receiving_streams_next_check_timer: null,


        remote_ack_delay_exponent: 3,
        remote_max_udp_payload_size: 1000,

    };


	function set_context(options){
		var has_changed=false;

		var fields=[
			'connection_status',
		];

		var prev={};

		if (options && typeof options === 'object'){
			if('connection_status' in options){
				if(context.connection_status!==options.connection_status){
					prev['connection_status']=context['connection_status'];
					context.connection_status=options.connection_status;
					has_changed=true;
				}
			}
		}

		if(has_changed==true){
			if(context.connection_status==1 && context.connection_status!==prev.connection_status){
				

				ev.emit('connect');

				//we need to flush...

			}
		}
	}




	
	function get_quic_stream_chunks_to_send(stream_id, allowed_bytes) {

		var stream = context.sending_streams[stream_id];
		if (!stream || !stream.pending_data) {
			return {
			chunks: [],
			send_offset_next: stream ? stream.send_offset_next : 0
			};
		}

			// הגודל הכולל של ה־stream
		var total_bytes = stream.total_size;
		
		if(typeof total_bytes !== 'number' || total_bytes<=0){
			total_bytes = stream.write_offset_next;
		}

		var base_offset = stream.pending_offset_start;
		var send_offset_next = stream.send_offset_next;

		// טווחים חסרים (יחסיים)
		var relative_missing = flat_ranges.invert(stream.acked_ranges, 0, total_bytes);

		// המרה ל־offset מוחלט
		for (var i = 0; i < relative_missing.length; i++) {
			relative_missing[i] += base_offset;
		}

		var chunks = [];
		var total_bytes_used = 0;
		var first_chunk_offset = null;

		// שלב ראשון – קדימה מהמקום האחרון
		for (var i = 0; i < relative_missing.length; i += 2) {
			var f = relative_missing[i];
			var t = relative_missing[i + 1];

			if (f <= send_offset_next && send_offset_next < t) {
				var offset = send_offset_next;

				while (offset < t && total_bytes_used < allowed_bytes) {
					var space_left = allowed_bytes - total_bytes_used;
					var len = Math.min(space_left, t - offset);
					if (len <= 0) break;

					if (first_chunk_offset === null) first_chunk_offset = offset;

					var rel_start = offset - base_offset;
					var rel_end = rel_start + len;
					var chunk_data = stream.pending_data.slice(rel_start, rel_end);

					chunks.push({
					offset: offset,
					data: chunk_data
					});

					total_bytes_used += len;
					offset += len;
				}

				break;
			}
		}

		// שלב שני – התחלה עד first_chunk_offset
		if (total_bytes_used < allowed_bytes && first_chunk_offset !== null) {
			for (var i = 0; i < relative_missing.length; i += 2) {
				var f = relative_missing[i];
				var t = relative_missing[i + 1];

				var offset = f;
				while (offset < t && offset < first_chunk_offset && total_bytes_used < allowed_bytes) {
					var space_left = allowed_bytes - total_bytes_used;
					var len = Math.min(space_left, t - offset, first_chunk_offset - offset);
					if (len <= 0) break;

					var rel_start = offset - base_offset;
					var rel_end = rel_start + len;
					var chunk_data = stream.pending_data.slice(rel_start, rel_end);

					chunks.push({
					offset: offset,
					data: chunk_data
					});

					total_bytes_used += len;
					offset += len;
				}
			}
		}

		// חישוב המצביע הבא אם נשלחו רצפים מהמצביע הנוכחי
		var new_send_offset = send_offset_next;
		for (var i = 0; i < chunks.length; i++) {
			var chunk = chunks[i];
			if (chunk.offset === new_send_offset) {
				new_send_offset = chunk.offset + chunk.data.length;
			} else {
				break;
			}
		}

		return {
			chunks: chunks,
			send_offset_next: new_send_offset,
		};
	}


	function prepare_and_send_quic_packet() {

		//console.log('prepare_and_send_quic_packet...............');

		//console.log(context);

		//console.log(context.sending_streams);

		if(context.sending_quic_packet_now==false){
			context.sending_quic_packet_now=true;

			if(context.next_send_quic_packet_timer!==null){
				clearTimeout(context.next_send_quic_packet_timer);
				context.next_send_quic_packet_timer=null;
			}

			var now = Math.floor(performance.timeOrigin + performance.now());

			var total_bytes_last_1s = 0;
			var packet_count_last_1s = 0;

			var oldest_packet_time_bytes = null;
			var oldest_packet_time_packets = null;

			// סריקת ההיסטוריה
			for (var i in context.sending_app_pn_history) {
				var [ts, size] = context.sending_app_pn_history[i];

				if (ts > now - 1000) {
					total_bytes_last_1s += size;
					packet_count_last_1s++;
				} else {
					// שומרים מתי יפוג כל פאקט מההיסטוריה
					if (oldest_packet_time_bytes === null || ts < oldest_packet_time_bytes) {
						oldest_packet_time_bytes = ts;
					}
					if (oldest_packet_time_packets === null || ts < oldest_packet_time_packets) {
						oldest_packet_time_packets = ts;
					}
				}
			}

			var bytes_left = context.max_sending_total_bytes_per_sec - total_bytes_last_1s;
			var packets_left = context.max_sending_packets_per_sec - packet_count_last_1s;

			
			var in_flight_packet_count = context.sending_app_pn_in_flight.size;
			var in_flight_total_bytes = 0;
			for (var pn of context.sending_app_pn_in_flight) {
				var pn_index = Number(pn) - (context.sending_app_pn_base - context.sending_app_pn_history.length);
				if (pn_index >= 0 && pn_index < context.sending_app_pn_history.length) {
					var info = context.sending_app_pn_history[pn_index];
					if (info){
						in_flight_total_bytes=in_flight_total_bytes+info[1];//size
					}
				}
			}


			var in_flight_room = context.max_sending_bytes_in_flight - in_flight_total_bytes;


			var allowed_packet_size = Math.min(bytes_left, context.max_sending_packet_size, in_flight_room);

			//console.log('@@ 1');
			if (
			packets_left > 0 &&
			allowed_packet_size >= context.min_sending_packet_size &&
			in_flight_packet_count < context.max_sending_packets_in_flight &&
			in_flight_total_bytes + allowed_packet_size <= context.max_sending_bytes_in_flight
			) {
			// מותר לשלוח *******************************
				//console.log('@@ 2');

				var encoded_frames=[];
				var update_streams={};
				var remove_pending_ack=[];



				
				if(context.receiving_app_pn_pending_ack.length>0 && 1==1){
					var ack_delay_ms = 0;
					var largest_pn = context.receiving_app_pn_pending_ack[context.receiving_app_pn_pending_ack.length - 1];
					for (var i2 = 0; i2 < context.receiving_app_pn_history.length; i2++) {
						var [pn_recv, ts_recv, size_recv] = context.receiving_app_pn_history[i2];
						if(pn_recv==largest_pn){
							ack_delay_ms = now - ts_recv;
							break;
						}
					}

					var delay_ns = ack_delay_ms * 1_000_000;
					var ack_delay_raw = Math.floor(delay_ns / (1 << context.remote_ack_delay_exponent));
					
					var ack_frame = build_ack_info_from_ranges(context.receiving_app_pn_pending_ack, null, ack_delay_raw);

					//var padding=new Uint8Array([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]);
					encoded_frames.push(encode_quic_frames([ack_frame]));

					/*
					
					console.log('ack frame sent:');

					console.log(ack_frame);

					console.log('ack for ranges:');

					console.log(context.receiving_app_pn_pending_ack);

					console.log('raw:');
					console.log(encoded_frames);
					//allowed_packet_size=allowed_packet_size-encoded_frames[0].byteLength;

					*/

					remove_pending_ack = context.receiving_app_pn_pending_ack.slice();
				}



				var active_stream_count=0;
				for(var stream_id in context.sending_streams){
					//צריך שיהיה בדיקה אם זה סטרים שעדיין לא נשלח במלואו...
					active_stream_count++;
				}
				var per_stream_bytes = Math.floor(allowed_packet_size / active_stream_count);


				for(var stream_id in context.sending_streams){
					
					var chunks_ranges=[];

					var {chunks,send_offset_next}=get_quic_stream_chunks_to_send(Number(stream_id),per_stream_bytes);

					if(chunks.length>0){
					
						for(var i in chunks){

							var is_fin=false;

							if(typeof context.sending_streams[stream_id].total_size == 'number' && context.sending_streams[stream_id].total_size>0 && chunks[i].offset+chunks[i].data.byteLength>=context.sending_streams[stream_id].total_size){
								is_fin=true;
							}

							var stream_frame={
								type: 'stream', 
								id: Number(stream_id),
								offset: chunks[i].offset,
								fin: is_fin,
								data: chunks[i].data
							};

							encoded_frames.push(encode_quic_frames([stream_frame]));

							chunks_ranges.push(chunks[i].offset, chunks[i].offset + chunks[i].data.length);

						}

						chunks_ranges.sort(function(a, b) {
							return a - b;
						});
					
						update_streams[stream_id]={
							chunks_ranges: chunks_ranges,
							send_offset_next: send_offset_next
						};

					}
				}


				/*
				console.log('allowed_packet_size::::::::::::');
				console.log(allowed_packet_size);

				console.log('update_streams::::::::::::');
				console.log(update_streams);

				console.log('encoded_frames::::::::::::');
				console.log(encoded_frames);
				*/

				if(encoded_frames.length>0){

					

					if(encoded_frames.length==1){
						var all_encoded_frames =  encoded_frames[0];
					}else if(encoded_frames.length>1){
						var all_encoded_frames = concatUint8Arrays(encoded_frames);
					}

					send_quic_packet_frames('1rtt',all_encoded_frames);


					if(1==1 || is_sent==true){

						now = Math.floor(performance.timeOrigin + performance.now());

						var packet_number=context.sending_app_pn_base;
						context.sending_app_pn_history.push([now, all_encoded_frames.length]);
						context.sending_app_pn_in_flight.add(packet_number);

						for(var stream_id in update_streams){
							context.sending_streams[stream_id].in_flight_ranges[packet_number]=update_streams[stream_id].chunks_ranges;
							context.sending_streams[stream_id].send_offset_next=update_streams[stream_id].send_offset_next;
						}

						//console.log(context.sending_streams);

						if(remove_pending_ack.length>0){
							flat_ranges.remove(context.receiving_app_pn_pending_ack,remove_pending_ack);
						}


						context.sending_app_pn_base++;
					}

					// אם שלחנו הרגע פאקט ואין עדיין מגבלות, נמתין את הזמן הזה כדי לפזר נכון
					//var interval_between_packets = Math.ceil(1000 / server.max_sending_packets_per_sec);
					
					
					
					

					
					//context.next_send_quic_packet_timer=null;
					//prepare_and_send_quic_packet();

					context.next_send_quic_packet_timer=setTimeout(function(){
						context.sending_quic_packet_now=false;
						context.next_send_quic_packet_timer=null;
						prepare_and_send_quic_packet();
					}, 0);
					
					
				
				}else{

					context.next_send_quic_packet_timer=null;
					context.sending_quic_packet_now=false;

				}

			}else{

				//console.log('not now...');

				// ✋ לא ניתן לשלוח כרגע — צריך לחשב מתי כן יהיה אפשר
				var wait_options = [];

				// זמן עד שיימחק פאקט שמפחית מגבלת פאקטים
				if (packets_left <= 0 && oldest_packet_time_packets !== null) {
					var wait_packets = Math.max(0, (oldest_packet_time_packets + 1000) - now);
					wait_options.push(wait_packets);
				}

				// זמן עד שיימחק מספיק בייטים
				if (bytes_left < context.min_sending_packet_size && oldest_packet_time_bytes !== null) {
					var wait_bytes = Math.max(0, (oldest_packet_time_bytes + 1000) - now);
					wait_options.push(wait_bytes);
				}

			

				if (wait_options.length > 0) {
					context.next_send_quic_packet_timer = setTimeout(function(){
						context.next_send_quic_packet_timer=null;
						context.sending_quic_packet_now=false;
						prepare_and_send_quic_packet();
					}, Math.max(...wait_options));

					//console.log('next_time: ',(Math.max(...wait_options)));
				}else{
					context.sending_quic_packet_now=false;
				}

			}

		}
	
	}



	function stream_write(stream_id,data,fin){

		if(stream_id in context.sending_streams==false){
			context.sending_streams[stream_id]={
				pending_data: null,
				write_offset_next: 0,
				pending_offset_start: 0,
				send_offset_next: 0,
				total_size: 0,

				in_flight_ranges: {},
				acked_ranges: [],
			};
		}

		var stream = context.sending_streams[stream_id];

		if(data==null){

			if(stream.total_size==0){
				stream.total_size=stream.write_offset_next;
			}

		}else{

			var start_offset = stream.write_offset_next;
			var end_offset = start_offset + data.byteLength;
			stream.write_offset_next = end_offset;
			//stream.total_size = end_offset;

			// קבע את התחלת ה־pending לפי acked_ranges
			var pending_offset_start = 0;
			if (stream.acked_ranges.length > 0 && stream.acked_ranges[0] === 0) {
				pending_offset_start = stream.acked_ranges[1];
			}

			// גזור רק את החלק שטרם קיבל ACK
			var skip = Math.max(pending_offset_start - start_offset, 0);
			if (skip >= data.byteLength) return;  // אין מה להוסיף

			var trimmed_data = data.slice(skip);

			if (stream.pending_data === null) {
				stream.pending_data = trimmed_data;
				stream.pending_offset_start = start_offset + skip;
			} else {
				// מיזוג ל־Uint8Array חדש
				var old = stream.pending_data;
				var old_offset = stream.pending_offset_start;
				var new_offset = start_offset + skip;

				var new_start = Math.min(old_offset, new_offset);
				var new_end = Math.max(old_offset + old.length, new_offset + trimmed_data.length);
				var total_len = new_end - new_start;

				var merged = new Uint8Array(total_len);

				// העתק ישן
				merged.set(old, old_offset - new_start);

				// העתק חדש
				merged.set(trimmed_data, new_offset - new_start);

				stream.pending_data = merged;
				stream.pending_offset_start = new_start;

			}
		}

		if((typeof fin=='boolean' && fin==true) || data==null){
			if(stream.total_size==0){
				stream.total_size = stream.write_offset_next;
			}
		}
		

		prepare_and_send_quic_packet();
	}


	function send_quic_packet_frames(packet_type,encoded_frames){
		var write_key=null;
		var write_iv=null;
		var write_hp=null;

		var packet_number=1;

		if(packet_type=='initial'){

			if(context.init_write_key!==null && context.init_write_iv!==null && context.init_write_hp!==null){
				write_key=context.init_write_key;
				write_iv=context.init_write_iv;
				write_hp=context.init_write_hp;

			}else{
				var d = quic_derive_init_secrets(context.original_dcid,context.version,'write');
				write_key=d.key;
				write_iv=d.iv;
				write_hp=d.hp;

				context.init_write_key=d.key;
				context.init_write_iv=d.iv;
				context.init_write_hp=d.hp;
			}

			packet_number=Number(context.sending_init_pn_next)+0;

		}else if(packet_type=='handshake'){

			if(context.handshake_write_key!==null && context.handshake_write_iv!==null && context.handshake_write_hp!==null){
				write_key=context.handshake_write_key;
				write_iv=context.handshake_write_iv;
				write_hp=context.handshake_write_hp;

			}else if(context.tls_session.context.server_handshake_traffic_secret!==null){
				var d = quic_derive_from_tls_secrets(context.tls_session.context.server_handshake_traffic_secret,TLS_CIPHER_SUITES[context.tls_session.context.selected_cipher_suite].hash);

				write_key=d.key;
				write_iv=d.iv;
				write_hp=d.hp;

				context.handshake_write_key=d.key;
				context.handshake_write_iv=d.iv;
				context.handshake_write_hp=d.hp;
			}

			packet_number=Number(context.sending_handshake_pn_next)+0;

		}else if(packet_type=='1rtt'){
			
			if(context.app_write_key!==null && context.app_write_iv!==null && context.app_write_hp!==null){
				write_key=context.app_write_key;
				write_iv=context.app_write_iv;
				write_hp=context.app_write_hp;

			}else if(context.tls_session.context.server_app_traffic_secret!==null){
				var d = quic_derive_from_tls_secrets(context.tls_session.context.server_app_traffic_secret,TLS_CIPHER_SUITES[context.tls_session.context.selected_cipher_suite].hash);

				write_key=d.key;
				write_iv=d.iv;
				write_hp=d.hp;

				context.app_write_key=d.key;
				context.app_write_iv=d.iv;
				context.app_write_hp=d.hp;
			}

			packet_number=Number(context.sending_app_pn_base)+0;

		}

		var dcid=new Uint8Array(0);

		
		if(context.their_cids.length>0){
			dcid=context.their_cids[0];
		}

		var encrypted_quic_packet=encrypt_quic_packet(packet_type, encoded_frames, write_key, write_iv, write_hp, packet_number, dcid, context.original_dcid, new Uint8Array(0));

		if(packet_type=='initial'){
			context.sending_init_pn_next++;
		}else if(packet_type=='handshake'){
			context.sending_handshake_pn_next++;
		}else if(packet_type=='1rtt'){
			var now = Math.floor(performance.timeOrigin + performance.now());
			
			context.sending_app_pn_history.push([now, encoded_frames.length]);
			context.sending_app_pn_base++;
		}

		ev.emit('packet',encrypted_quic_packet);

	}


	function process_reset_stream_frame(packet_type,stream_id,final_size,reset_error_code){

		if(stream_id in context.receiving_streams==false){
			context.receiving_streams[stream_id]={
				data_chunks: {},
				total_size: 0,
				receiving_ranges: [],
				next_flush_offset: 0,
				next_flush_timer: null,

				reset_error_code: 0,
				delete_timer: null
			};
		}

		context.receiving_streams[stream_id].total_size = final_size|0;
		context.receiving_streams[stream_id].reset_error_code = reset_error_code|0;

	}

    function process_stream_frame(packet_type,stream_id,offset,data,fin){

		var is_new_chunk=false;

        if(stream_id in context.receiving_streams==false){
			context.receiving_streams[stream_id]={
				data_chunks: {},
				total_size: 0,
				receiving_ranges: [],
				next_flush_offset: 0,
				next_flush_timer: null,

				reset_error_code: 0,
				delete_timer: null
			};
		}

		if(flat_ranges.add(context.receiving_streams[stream_id].receiving_ranges, [offset, offset + data.length])==true){
		
			if(offset in context.receiving_streams[stream_id].data_chunks==false || context.receiving_streams[stream_id].data_chunks[offset].byteLength<data.byteLength){
				context.receiving_streams[stream_id].data_chunks[offset]=data;
			}

			if(typeof fin=='boolean' && fin==true){
				context.receiving_streams[stream_id].total_size=offset+data.byteLength;
			}

			is_new_chunk=true;

		}
        
		if(is_new_chunk==true){
			
			if(context.receiving_streams[stream_id].receiving_ranges.length==2 && typeof context.receiving_streams[stream_id].total_size == 'number' && context.receiving_streams[stream_id].total_size>0 && context.receiving_streams[stream_id].receiving_ranges[0]==0 && context.receiving_streams[stream_id].receiving_ranges[1]==context.receiving_streams[stream_id].total_size){

				flush_stream_chunk(stream_id);

			}else if(context.receiving_streams[stream_id].next_flush_timer==null){
				//run timer...
                context.receiving_streams[stream_id].next_flush_timer=setTimeout(function(){
                  context.receiving_streams[stream_id].next_flush_timer=null;
                  flush_stream_chunk(stream_id);
                },3);
			}
		}
    }

	function flush_stream_chunk(stream_id){

		if (stream_id in context.receiving_streams==true) {
			
			if(context.receiving_streams[stream_id].next_flush_timer!==null){
				clearTimeout(context.receiving_streams[stream_id].next_flush_timer);
				context.receiving_streams[stream_id].next_flush_timer=null;
			}

			var to_concat = [];

			var next_flush_offset=context.receiving_streams[stream_id].next_flush_offset;
			while ((next_flush_offset in context.receiving_streams[stream_id].data_chunks)) {
				var part = context.receiving_streams[stream_id].data_chunks[next_flush_offset];

				delete context.receiving_streams[stream_id].data_chunks[next_flush_offset];

				to_concat.push(part);
				next_flush_offset += part.byteLength;
			}

			if (to_concat.length > 0) {
				context.receiving_streams[stream_id].next_flush_offset=next_flush_offset;

				if(to_concat.length>2){
					var out = concatUint8Arrays(to_concat);
				}else{
					var out = to_concat[0];
				}

				if(context.receiving_streams[stream_id].total_size>0 && context.receiving_streams[stream_id].total_size<=context.receiving_streams[stream_id].next_flush_offset){
					var fin=true;
				}else{
					var fin=false;
				}
				
				ev.emit('stream', Number(stream_id), out, fin);
			}

		}
	}




	function crypto_write(packet_type,data){

		if(packet_type=='initial'){

			var encoded_frames=encode_quic_frames([{
				type: 'crypto', 
				offset: context.sending_init_offset_next, 
				data: data
			}]);

			context.sending_init_offset_next=context.sending_init_offset_next+data.byteLength;


		}else if(packet_type=='handshake'){

			var encoded_frames=encode_quic_frames([{
				type: 'crypto', 
				offset: context.sending_handshake_offset_next, 
				data: data
			}]);

			context.sending_handshake_offset_next=context.sending_handshake_offset_next+data.byteLength;

		}

		send_quic_packet_frames(packet_type,encoded_frames);

	}

    function process_crypto_frame(packet_type,offset,data){

        var is_new_chunk=false;

        if(packet_type=='initial'){

            if(flat_ranges.add(context.receiving_init_ranges, [offset, offset + data.length])==true){

                if(offset in context.receiving_init_chunks==false || context.receiving_init_chunks[offset].byteLength<data.byteLength){
                context.receiving_init_chunks[offset]=data;
                }
                
                is_new_chunk=true;

            }

        }else if(packet_type=='handshake'){

            if(flat_ranges.add(context.receiving_handshake_ranges, [offset, offset + data.length])==true){

                if(offset in context.receiving_handshake_chunks==false || context.receiving_handshake_chunks[offset].byteLength<data.byteLength){
                context.receiving_handshake_chunks[offset]=data;
                }
                
                is_new_chunk=true;

            }

        }


        if(is_new_chunk==true){
            
            var tls_messages=[];

            if(packet_type=='initial'){
                
                var ext=extract_tls_messages_from_chunks(context.receiving_init_chunks, context.receiving_init_from_offset);
                
                if(ext){
                    tls_messages=ext.tls_messages;
                    context.receiving_init_from_offset=ext.new_from_offset;
                }

            }else if(packet_type=='handshake'){

                var ext=extract_tls_messages_from_chunks(context.receiving_handshake_chunks, context.receiving_handshake_from_offset);
                
                if(ext){
                    tls_messages=ext.tls_messages;
                    context.receiving_handshake_from_offset=ext.new_from_offset;
                }

            }

            if(tls_messages && tls_messages.length>0){

                //console.log('tls messages ******');

                if(context.tls_session==null){
                    context.tls_session = new TLSSession({
                        isServer: true,
						SNICallback: context.SNICallback
                    });

                    context.tls_session.on('message', function(epoch, seq, type, data){

						//console.log('tls message to send:');
						//console.log(data);

                        if(epoch==0){
							crypto_write('initial',data);
                        }else if(epoch==1){
							crypto_write('handshake',data);
                        }else if(epoch==3){
							crypto_write('app',data);
						}

                    });

                    context.tls_session.on('hello', function(info){
                        //console.log('tls hello...');

						/*
						var quic_transport_params=parse_transport_parameters(parsed.quic_transport_parameters_raw);

						if ('ack_delay_exponent' in quic_transport_params) {
							context.remote_ack_delay_exponent=quic_transport_params['ack_delay_exponent'];
						}

						if ('max_udp_payload_size' in quic_transport_params) {
							context.remote_max_udp_payload_size=quic_transport_params['max_udp_payload_size'];
						}
						*/


						var quic_ext_data=build_quic_ext({
							original_destination_connection_id: context.original_dcid,
							initial_source_connection_id: context.original_dcid,
							max_udp_payload_size: 65527,
							max_idle_timeout: 30000,
							stateless_reset_token: new Uint8Array(16).fill(0xab),
							initial_max_data: 1048576,
							initial_max_stream_data_bidi_local: 262144,
							initial_max_stream_data_bidi_remote: 262144,
							initial_max_stream_data_uni: 131072,
							initial_max_streams_bidi: 100,
							initial_max_streams_uni: 3,
							ack_delay_exponent: 3,
							max_ack_delay: 25,
							disable_active_migration: true,
							active_connection_id_limit: 4,
							max_datagram_frame_size: 65527,
							web_accepted_origins: [
							"*" //or your domain
							]
						});

                        //var serverName=context.tls_session.context.selected_sni;

						context.tls_session.set_context({
							local_versions: [0x0304],
							local_alpns: ['h3'],
							local_groups: [29, 23, 24],
							local_cipher_suites: [
								0x1301, 
								0x1302, 
								0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
								0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
								0xCCA8  // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (אם מימשת)
							],

							local_extensions: [
								{ type: 0x39, data: quic_ext_data}
							],

							// ---- אלגוריתמי חתימה (TLS 1.2 → RSA-PKCS1, לא PSS) ----
							// 0x0401 = rsa_pkcs1_sha256, 0x0501 = rsa_pkcs1_sha384, 0x0601 = rsa_pkcs1_sha512
							local_signature_algorithms: [0x0401, 0x0501, 0x0601],
							// אופציונלי (לטובת חלק מהלקוחות): אותו דבר גם ל-signature_algorithms_cert
							local_signature_algorithms_cert: [0x0401, 0x0501, 0x0601],
							
							//local_cert_chain: [{ cert: new Uint8Array(cert.raw)}],
							//cert_private_key: new Uint8Array(private_key_der)
						});
                        
                    });

                    context.tls_session.on('secureConnect', function(){
						set_context({
							connection_status: 1,
							handshake_done: true
						});
                    });
                }

                for(var i in tls_messages){
                    context.tls_session.message(tls_messages[i]);
                }
            }

        }
        
    }


    function process_ack_frame(packet_type,frame){

        var acked_ranges=quic_acked_info_to_ranges(frame);
        
		if(packet_type=='initial'){

			if(flat_ranges.add(context.sending_init_pn_acked_ranges, acked_ranges)==true){
				//console.log(context.sending_init_pn_acked_ranges);
			}

		}else if(packet_type=='handshake'){

			if(flat_ranges.add(context.sending_handshake_pn_acked_ranges, acked_ranges)==true){
				//console.log(context.sending_handshake_pn_acked_ranges);
			}

		}else if(packet_type=='1rtt'){

			if('largest' in frame && 'delay' in frame){
				var largest_pn=frame.largest;

				if(context.sending_app_pn_in_flight.has(largest_pn)==true){
					var now = Math.floor(performance.timeOrigin + performance.now());
					var ack_delay_raw=frame.delay;
					var ack_delay_ms = Math.round((ack_delay_raw * Math.pow(2, 3)) / 1000);

					var pn_index = largest_pn - (context.sending_app_pn_base - context.sending_app_pn_history.length);

					if (pn_index >= 0 && pn_index < context.sending_app_pn_history.length) {
						/*
						console.log('pn_index: ',pn_index);
						console.log('sending_app_pn_history.length: ',context.sending_app_pn_history.length);
						console.log('largest_pn: ',largest_pn);
						console.log('sending_app_pn_base: ',context.sending_app_pn_base);
						*/

						var start_time=context.sending_app_pn_history[pn_index][0];
						

						var received_time_estimate = now - ack_delay_ms;

						var measured_rtt = now - start_time - ack_delay_ms;

						var sent_bytes_during = 0;
						var sent_packets_during = 0;

						for (var i2 = pn_index; i2 < context.sending_app_pn_history.length; i2++) {
							var [ts, size] = context.sending_app_pn_history[i2];
							if (received_time_estimate >= ts) {
								sent_bytes_during += size;
								sent_packets_during++;
							}
						}

						var received_bytes_during = 0;
						var received_packets_during = 0;

						for (var i2 = 0; i2 < context.receiving_app_pn_history.length; i2++) {
							var [pn_recv, ts_recv, size_recv] = context.receiving_app_pn_history[i2];
							if (ts_recv > received_time_estimate){
							break;

							}else if (ts_recv >= start_time) {
								received_bytes_during += size_recv;
								received_packets_during++;
							}
						}


						var last_rtt_record=null;
						if(context.rtt_history.length>0){
							last_rtt_record=context.rtt_history[context.rtt_history.length-1];
						}

						if(last_rtt_record==null || (last_rtt_record[0]!==start_time && last_rtt_record[1]!==received_time_estimate)){
							context.rtt_history.push([
							start_time,                // 0 - מתי נשלח
							received_time_estimate,    // 1 - מתי התקבל ACK
							sent_bytes_during,         // 2 - כמה נשלח בזמן הזה
							sent_packets_during,       // 3 - כמה פאקטים נשלחו
							received_bytes_during,     // 4 - כמה התקבל באותו זמן
							received_packets_during,   // 5 - כמה פאקטים התקבלו
							measured_rtt,              // 6 - RTT
							]);
						}
						

						//console.log(context);
					}

				}
			}

			for (var pn of context.sending_app_pn_in_flight) {
				var is_ack_in_ranges = false;
				for (var i2 = 0; i2 < acked_ranges.length; i2 += 2) {
					var from = acked_ranges[i2];
					var to = acked_ranges[i2 + 1];
					if (pn >= from && pn <= to) {
						is_ack_in_ranges = true;
						break;
					}
				}

				if(is_ack_in_ranges==true){
					context.sending_app_pn_in_flight.delete(pn);


					for(var stream_id in context.sending_streams){
					
						if('in_flight_ranges' in context.sending_streams[stream_id] && pn in context.sending_streams[stream_id].in_flight_ranges==true){

							if(flat_ranges.add(context.sending_streams[stream_id].acked_ranges, context.sending_streams[stream_id].in_flight_ranges[pn])==true){
							
							}

							delete context.sending_streams[stream_id].in_flight_ranges[pn];

							if(context.sending_streams[stream_id].acked_ranges.length==2 && typeof context.sending_streams[stream_id].total_size == 'number' && context.sending_streams[stream_id].total_size>0 && context.sending_streams[stream_id].acked_ranges[0]==0 && context.sending_streams[stream_id].acked_ranges[1]==context.sending_streams[stream_id].total_size){
							//we can delete it...
								delete context.sending_streams[stream_id];
							}

							//console.log(context.sending_streams[stream_id]);
						}
					}
					


				}
			}
		}
    }

    function process_decrypted_quic_packet(packet_type,packet_number,data){

        var ack_eliciting=false;


        var frames=parse_quic_frames(data);

        for(var i in frames){

            if(ack_eliciting==false && (frames[i].type=='stream' || frames[i].type=='crypto' || frames[i].type=='new_connection_id' || frames[i].type=='handshake_done' || frames[i].type=='path_challenge' || frames[i].type=='path_response' || frames[i].type=='ping')){
                ack_eliciting=true;
            }


            if(frames[i].type=='crypto'){

                process_crypto_frame(packet_type,frames[i].offset,frames[i].data);

            }else if(frames[i].type=='stream'){

                process_stream_frame(packet_type,frames[i].id,frames[i].offset,frames[i].data,frames[i].fin);

			}else if(frames[i].type=='reset_stream'){

				//process_reset_stream_frame(packet_type,frames[i].id, frames[i].finalSize, frames[i].error);

            }else if(frames[i].type=='stop_sending'){



            }else if(frames[i].type=='datagram'){

				ev.emit('datagram',frames[i].contextId,frames[i].data);

            }else if(frames[i].type=='ack'){

                process_ack_frame(packet_type,frames[i]);

            }else{



            }

        }
        
        if(ack_eliciting==true){
			var ack_frame_to_send = [];

			if(packet_type=='initial'){

				ack_frame_to_send.push(build_ack_info_from_ranges(context.receiving_init_pn_ranges, null, 0));

			}else if(packet_type=='handshake'){

				ack_frame_to_send.push(build_ack_info_from_ranges(context.receiving_handshake_pn_ranges, null, 0));
				
			}else if(packet_type=='1rtt'){

				flat_ranges.add(context.receiving_app_pn_pending_ack, [packet_number,packet_number]);

				prepare_and_send_quic_packet();
				
			}


			if(ack_frame_to_send.length>0){
				var encoded_frames=encode_quic_frames(ack_frame_to_send);
				send_quic_packet_frames(packet_type,encoded_frames);
			}
		}
        
    }


    function process_quic_packet(data){

        if('version' in data){
            if(context.version!==data.version){
                context.version=data.version;
            }
        }
            
        if('dcid' in data && data.dcid && data.dcid.byteLength>0){
            if(context.original_dcid==null || context.original_dcid.byteLength<=0 || arraybufferEqual(data.dcid.buffer,context.original_dcid.buffer)==false){
                context.original_dcid=data.dcid;
            }
        }

		if('scid' in data && data.scid && data.scid.byteLength>0){

			var is_scid_exist=false;
			for(var i in context.their_cids){
				if(arraybufferEqual(data.scid.buffer,context.their_cids[i].buffer)==true){
				is_scid_exist=true;
				break;
				}
			}

			if(is_scid_exist==false){
				context.their_cids.push(data.scid);
				//is_modified=true;
			}
		}

        var read_key=null;
        var read_iv=null;
        var read_hp=null;

        var largest_pn=-1;

        if(data['type']=='initial'){

          if(context.init_read_key!==null && context.init_read_iv!==null && context.init_read_hp!==null){
            read_key=context.init_read_key;
            read_iv=context.init_read_iv;
            read_hp=context.init_read_hp;

          }else{
            var d = quic_derive_init_secrets(context.original_dcid,context.version,'read');

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            context.init_read_key=d.key;
            context.init_read_iv=d.iv;
            context.init_read_hp=d.hp;
          }

          largest_pn=Number(context.receiving_init_pn_largest)+0;

        }else if(data['type']=='handshake'){

			if(context.tls_session!==null){
				if(context.handshake_read_key!==null && context.handshake_read_iv!==null && context.handshake_read_hp!==null){
					read_key=context.handshake_read_key;
					read_iv=context.handshake_read_iv;
					read_hp=context.handshake_read_hp;

				}else if(context.tls_session.context.client_handshake_traffic_secret!==null){
					var d = quic_derive_from_tls_secrets(context.tls_session.context.client_handshake_traffic_secret,TLS_CIPHER_SUITES[context.tls_session.context.selected_cipher_suite].hash);

					read_key=d.key;
					read_iv=d.iv;
					read_hp=d.hp;

					context.handshake_read_key=d.key;
					context.handshake_read_iv=d.iv;
					context.handshake_read_hp=d.hp;

				}

				largest_pn=Number(context.receiving_handshake_pn_largest)+0;
			}else{
				//console.log('tls still not start...');
			}

        }else if(data['type']=='1rtt'){
            
			if(context.tls_session!==null){

				if(context.app_read_key!==null && context.app_read_iv!==null && context.app_read_hp!==null){
					read_key=context.app_read_key;
					read_iv=context.app_read_iv;
					read_hp=context.app_read_hp;

				}else if(context.tls_session.context.client_app_traffic_secret!==null){

					var d = quic_derive_from_tls_secrets(context.tls_session.context.client_app_traffic_secret,TLS_CIPHER_SUITES[context.tls_session.context.selected_cipher_suite].hash);

					read_key=d.key;
					read_iv=d.iv;
					read_hp=d.hp;

					context.app_read_key=d.key;
					context.app_read_iv=d.iv;
					context.app_read_hp=d.hp;
					
					
				}

				largest_pn=Number(context.receiving_app_pn_largest)+0;
			}else{
				//console.log('tls still not start...');
			}

        }

        if(read_key!==null && read_iv!==null){

            var decrypted_packet = decrypt_quic_packet(data['raw'], read_key, read_iv, read_hp, context.original_dcid,largest_pn);

            if(decrypted_packet && decrypted_packet.plaintext!==null && decrypted_packet.plaintext.byteLength>0){

                var is_new_packet=false;

                if(data['type']=='initial'){

                    is_new_packet=flat_ranges.add(context.receiving_init_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

					if(is_new_packet && context.receiving_init_pn_largest<decrypted_packet.packet_number){
						context.receiving_init_pn_largest=decrypted_packet.packet_number;
					}

                }else if(data['type']=='handshake'){

                    is_new_packet=flat_ranges.add(context.receiving_handshake_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

					if(is_new_packet && context.receiving_handshake_pn_largest<decrypted_packet.packet_number){
						context.receiving_handshake_pn_largest=decrypted_packet.packet_number;
					}

                }else if(data['type']=='1rtt'){

                    is_new_packet=flat_ranges.add(context.receiving_app_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

					if(is_new_packet && context.receiving_app_pn_largest<decrypted_packet.packet_number){
						context.receiving_app_pn_largest=decrypted_packet.packet_number;
					}


					if(context.handshake_done_sent==false){
						context.handshake_done_sent=true;

						send_quic_packet_frames(data['type'],encode_quic_frames([{
							type: 'handshake_done'
						}]));
					}

                }
                    
                if(is_new_packet==true){

                    process_decrypted_quic_packet(data['type'],decrypted_packet.packet_number,decrypted_packet.plaintext);

                }
                

            }else{
				//console.log('decrypted fail...'+data['type']);
			}
        }else{
			//console.log('no read key...');
		}
    }



    // === API ציבורי (ללא חשיפת session) ===
    var api = {
        on: function(name, fn){ ev.on(name, fn); },

        packet: process_quic_packet,

		stream: stream_write,

        end: function(data){
            if (context.destroyed) return;
            if (typeof data !== 'undefined' && data !== null) api.write(data);
            try { context.transport && context.transport.end && context.transport.end(); } catch(e){}
        },

        destroy: function(){
            if (context.destroyed) return;
            context.destroyed = true;
            try { context.transport && context.transport.destroy && context.transport.destroy(); } catch(e){}
        }
    };

    for (var k in api) if (Object.prototype.hasOwnProperty.call(api,k)) this[k] = api[k];
    

    return this;
}

export default QUICSocket;