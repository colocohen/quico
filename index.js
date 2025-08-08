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

var process = require('process');
var dgram  = require('dgram');
var flat_ranges = require('flat-ranges');
var crypto = require('crypto');

var { sha256, sha384 } = require('@noble/hashes/sha2');

var {
  concatUint8Arrays,
  arraybufferEqual,
  quic_acked_info_to_ranges,
  build_ack_info_from_ranges,
  readVarInt,
  writeVarInt
} = require('./libs/utils');

var {
  get_cipher_info,
  build_certificate,
  decrypt_quic_packet,
  quic_derive_init_secrets,
  quic_derive_from_tls_secrets,
  parse_tls_message,
  parse_tls_client_hello,
  build_server_hello,
  tls_derive_handshake_secrets,
  build_quic_ext,
  build_encrypted_extensions,
  hkdf_expand_label,
  hmac,
  hash_transcript,
  handle_client_hello,
  build_certificate_verify,
  encode_quic_frames,
  encrypt_quic_packet,
  parse_quic_datagram,
  parse_quic_packet,
  parse_quic_frames,
  extract_tls_messages_from_chunks,
  build_alpn_ext,
  build_finished,
  tls_derive_app_secrets,
  parse_transport_parameters
} = require('./libs/crypto');

var {
  build_h3_frames,
  build_settings_frame,
  parse_h3_settings_frame,
  extract_qpack_encoder_instructions_from_chunks,
  extract_h3_frames_from_chunks,
  parse_qpack_header_block,
  build_http3_literal_headers_frame,
  parse_webtransport_datagram,
  qpack_static_table_entries
} = require('./libs/h3');

		
var new_quic_connection = {
  connection_status: 4,//0 - connecting... | 1 - connected | 2 - disconnected | ...

  from_ip: null,
  from_port: null,

  version: 1,

  my_cids: [],             // SCIDים שאתה נתת (כנראה אחד ראשוני ועוד future)
  their_cids: [],          // DCIDים שהצד השני השתמש בהם (כלומר שלך כשרת)
  original_dcid: null,     // ל־Initial ול־Retry

  //tls stuff...
  sni: null,

  tls_cipher_selected: null,
  tls_alpn_selected: null,

  tls_signature_algorithms: [],

  tls_handshake_secret: null,
  tls_shared_secret: null,
  tls_early_secret: null,

  tls_transcript: [],
  tls_handshake_step: 0,
  tls_finished_ok: false,
  
  tls_server_public_key: null,
  tls_server_private_key: null,

  tls_client_handshake_traffic_secret: null,
  tls_server_handshake_traffic_secret: null,

  tls_client_app_traffic_secret: null,
  tls_server_app_traffic_secret: null,


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


  receiving_streams: {},             // stream_id → stream object
  receiving_streams_next_check_timer: null,


  remote_ack_delay_exponent: 3,
  remote_max_udp_payload_size: 1000,

  h3_remote_control_stream_id: null,
  h3_remote_control_from_offset: 1,

  h3_remote_qpack_encoder_stream_id: null,
  h3_remote_qpack_encoder_from_offset: 1,

  h3_remote_qpack_decoder_stream_id: null,
  h3_remote_qpack_decoder_from_offset: 1,


  h3_http_request_streams: {},


  h3_remote_max_header_size: 0,//מתקבל ב settings - אחרי פיענוח
  h3_remote_qpack_max_table_capacity: 0,//מתקבל ב settings - גודל הטבלה המקסימלי
  h3_remote_datagram_support: null,

  h3_remote_qpack_table_base_index: 0,
  h3_remote_qpack_table_capacity: 0,
  h3_remote_qpack_dynamic_table: [],


  h3_wt_sessions: {}

// 🗺️ congestion control / flow control (אפשר להוסיף בהמשך)
};


function evict_qpack_remote_dynamic_table_if_needed(server, quic_connection_id){
  if(quic_connection_id in server.connections==true){

    var connection = server.connections[quic_connection_id];
    var entries = connection.h3_remote_qpack_dynamic_table;
    var capacity = connection.h3_remote_qpack_table_capacity;

    // חישוב גודל כולל של כל הערכים בטבלה
    var totalSize = 0;
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i][0];
      var value = entries[i][1];
      totalSize += name.length + value.length + 32;
    }

    // הדחה של ערכים ישנים עד שהטבלה בגבולות המותר
    while (totalSize > capacity && entries.length > 0) {
      var removed = entries.pop(); // מסיר את הערך האחרון
      var removedSize = removed[0].length + removed[1].length + 32;
      totalSize -= removedSize;
    }
    
  }
}

function insert_into_qpack_remote_encoder_dynamic_table(server, quic_connection_id, name, value){
  if(quic_connection_id in server.connections==true){
    var entry_size = name.length + value.length + 32;

    if (entry_size > server.connections[quic_connection_id].h3_remote_qpack_table_capacity) return false;

    server.connections[quic_connection_id].h3_remote_qpack_dynamic_table.unshift([name, value]);
    server.connections[quic_connection_id].h3_remote_qpack_table_base_index++;

    evict_qpack_remote_dynamic_table_if_needed(server, quic_connection_id);

    return true;

  }
}

function create_wt_session_object(server, quic_connection_id, stream_id, headers) {
  var wt = {
    id: stream_id,
    //quic_connection: conn_id,

    headers: {},

    send: function(data) {
      send_quic_frames_packet(server,quic_connection_id,'1rtt',[{
        type: 'datagram',
        data: concatUint8Arrays([writeVarInt(Number(stream_id)),data])
      }]);
    },

    close: function() {
      wt._internal.isOpen = false;
      // שלח CONTROL_FRAME של סוג close אם צריך
    },

    onmessage: null,
    onclose: null,
    onerror: null,
    onstream: null,

    _internal: {
      incoming_uni_streams: {},
      outgoing_uni_streams: {},
      control_stream_id: stream_id,
      isOpen: true
    }
  };

  return wt;
}


function build_response_object(server, quic_connection_id, stream_id) {
  return {

    statusCode: null,
    headersSent: false,
    socket: null,

    writeHead: function(statusCode, headers) {
      
      for(var header_name in headers){
        server.connections[quic_connection_id].h3_http_request_streams[stream_id].response_headers[header_name]=headers[header_name];
      }

      if(":status" in server.connections[quic_connection_id].h3_http_request_streams[stream_id].response_headers==false){
        server.connections[quic_connection_id].h3_http_request_streams[stream_id].response_headers[":status"]=statusCode;

        var headers_payload = build_http3_literal_headers_frame(server.connections[quic_connection_id].h3_http_request_streams[stream_id].response_headers);

        var http3_response=build_h3_frames([
          { frame_type: 1, payload: headers_payload }
        ]);

        quic_stream_write(server,quic_connection_id,Number(stream_id),http3_response,false);

      }
    },

    writeEarlyHints: function (hints){
      
    },

    write: function(chunk) {
      var http3_response=build_h3_frames([
        { frame_type: 0, payload: chunk }
      ]);

      quic_stream_write(server,quic_connection_id,Number(stream_id),http3_response,false);
    },

    end: function(chunk) {

      if(typeof chunk!=='undefined'){
        var http3_response=build_h3_frames([
          { frame_type: 0, payload: chunk }
        ]);

        quic_stream_write(server,quic_connection_id,Number(stream_id),http3_response,true);
      }else{
        quic_stream_write(server,quic_connection_id,Number(stream_id),new Uint8Array(0),true);
      }

      
      
    }
  };
}

function process_quic_receiving_streams(server,quic_connection_id){
  if(quic_connection_id in server.connections==true){

    for(var stream_id in server.connections[quic_connection_id].receiving_streams){
      if(server.connections[quic_connection_id].receiving_streams[stream_id].need_check==true){
        server.connections[quic_connection_id].receiving_streams[stream_id].need_check=false;

        var stream_type=null;

        if(server.connections[quic_connection_id].h3_remote_control_stream_id==Number(stream_id)){
          stream_type=0;
        }else if(server.connections[quic_connection_id].h3_remote_qpack_encoder_stream_id==Number(stream_id)){
          stream_type=2;
        }else if(server.connections[quic_connection_id].h3_remote_qpack_decoder_stream_id==Number(stream_id)){
          stream_type=3;
        }else{

        }

        if(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_ranges.length>=2){

          var is_unidirectional = (Number(stream_id) % 2 === 0) !== (Number(stream_id) % 4 === 0);
          if (is_unidirectional) {

            if(stream_type==null && '0' in server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks){

              var first_byte=server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks[0][0];

              switch (first_byte) {
                case 0x00:
                  //console.log("✅ Control Stream");
                  server.connections[quic_connection_id].h3_remote_control_stream_id=Number(stream_id);
                  stream_type=0;
                  break;
                case 0x01:
                  //console.log("✅ Push Stream");
                  //...
                  break;
                case 0x02:
                  //console.log("✅ QPACK Encoder Stream");
                  server.connections[quic_connection_id].h3_remote_qpack_encoder_stream_id=Number(stream_id);
                  stream_type=2;
                  break;
                case 0x03:
                  //console.log("✅ QPACK Decoder Stream");
                  server.connections[quic_connection_id].h3_remote_qpack_decoder_stream_id=Number(stream_id);
                  stream_type=3;
                  break;
                default:
                  //console.log("❓ Unknown Unidirectional Stream");
              }
            }

          } else {
            stream_type=4;

            //console.log("🔄 Bidirectional (HTTP Request/Response)");
            

            /*
            g_events.emit(['set_sending_quic_chunk',quic_connection_id,{
              type: '1rtt',
              stream_id: 0,
              fin: true,
              data: headersFrame
            }]);
            */
          }

          //console.log(server.connections[quic_connection_id]);

          //console.log("--------------------------------------------");

        }


        if(stream_type!==null){

          //console.log('h3_frames:::::::::::::::');
          
        }

        if(stream_type==0){

          //console.log('control stream from chunks:');
          //console.log(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks);

          //console.dir(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks, { maxArrayLength: null });


          //console.log('from offset: '+server.connections[quic_connection_id].h3_remote_control_from_offset);
          
          var ext=extract_h3_frames_from_chunks(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks,server.connections[quic_connection_id].h3_remote_control_from_offset);
          server.connections[quic_connection_id].h3_remote_control_from_offset=ext.new_from_offset;
          var h3_frames=ext.frames;

          if(h3_frames.length>0){
            //console.log('frames: ');
            //console.log(h3_frames);

            for(var i in h3_frames){
              if(h3_frames[i].frame_type==4){
                //console.log('parse_h3_settings_frame:');
                var control_settings=parse_h3_settings_frame(h3_frames[i].payload);
                //console.log(control_settings);

                if('SETTINGS_QPACK_MAX_TABLE_CAPACITY' in control_settings && control_settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY']>0){
                  server.connections[quic_connection_id].h3_remote_qpack_max_table_capacity=control_settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'];

                  evict_qpack_remote_dynamic_table_if_needed(server, quic_connection_id);
                }

                if('SETTINGS_MAX_FIELD_SECTION_SIZE' in control_settings && control_settings['SETTINGS_MAX_FIELD_SECTION_SIZE']>0){
                  server.connections[quic_connection_id].h3_remote_max_header_size=control_settings['SETTINGS_MAX_FIELD_SECTION_SIZE'];
                }

                if('SETTINGS_H3_DATAGRAM' in control_settings && control_settings['SETTINGS_H3_DATAGRAM']>0){
                  server.connections[quic_connection_id].h3_remote_datagram_support=Boolean(control_settings['SETTINGS_H3_DATAGRAM']);
                }

                

              }
            }
            
          }

        }else if(stream_type==2){//qpack encode stream...
          
          //console.log('qpack encode stream from chunks:');
          //console.log(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks);

          //console.dir(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks, { maxArrayLength: null });



          var ext=extract_qpack_encoder_instructions_from_chunks(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks,server.connections[quic_connection_id].h3_remote_qpack_encoder_from_offset);
          server.connections[quic_connection_id].h3_remote_qpack_encoder_from_offset=ext.new_from_offset;

          var arr_inserts=[];

          for(var i in ext.instructions){
            if(ext.instructions[i].type=='set_dynamic_table_capacity'){
              
              server.connections[quic_connection_id].h3_remote_qpack_table_capacity=ext.instructions[i].capacity;

            }else if(ext.instructions[i].type=='insert_with_name_ref' || ext.instructions[i].type=='insert_without_name_ref'){
              var name=null;
              var value=ext.instructions[i].value;

              if(ext.instructions[i].type=='insert_with_name_ref'){
                if(ext.instructions[i].from_static_table==true){
                  if(ext.instructions[i].name_index<qpack_static_table_entries.length){
                    name=qpack_static_table_entries[ext.instructions[i].name_index][0];
                  }else{
                    //error...
                  }
                }else{
                  //from dynamic...
                  var base_index = server.connections[quic_connection_id].h3_remote_qpack_table_base_index;
                  var name_index = ext.instructions[i].name_index;
                  var dynamic_index = base_index - 1 - name_index;
                  var dynamic_table = server.connections[quic_connection_id].h3_remote_qpack_dynamic_table;

                  if (dynamic_index >= 0 && dynamic_index < dynamic_table.length) {
                    name = dynamic_table[dynamic_index][0];
                  } else {
                    // Error: missing reference
                  }
                }
              }else{
                name=ext.instructions[i].name;
              }
              

              if(name!==null){
                arr_inserts.push([name,value]);
              }

            }
          }

          if(arr_inserts.length>0){
            for(var i in arr_inserts){
              insert_into_qpack_remote_encoder_dynamic_table(server,quic_connection_id,arr_inserts[i][0],arr_inserts[i][1]);
            }

            console.log(server.connections[quic_connection_id].h3_remote_qpack_dynamic_table);
            //then... build_qpack_known_received_count(arr_inserts.length);
          }

        }else if(stream_type==3){

        }else if(stream_type==4){//http3 request...
          

          if(stream_id in server.connections[quic_connection_id].h3_http_request_streams==false){
            server.connections[quic_connection_id].h3_http_request_streams[stream_id]={
              from_offset: 0,
              response_headers: {},
              header_sent: false,
              response_body: null,
              
            };
          }

          var ext=extract_h3_frames_from_chunks(server.connections[quic_connection_id].receiving_streams[stream_id].receiving_chunks,server.connections[quic_connection_id].h3_http_request_streams[stream_id].from_offset);

          server.connections[quic_connection_id].h3_http_request_streams[stream_id].from_offset=ext.new_from_offset;
          

          var h3_frames=ext.frames;

          if(h3_frames.length>0){
            //console.log('request frames: ');
            //console.log(h3_frames);

            for(var i in h3_frames){
              if(h3_frames[i].frame_type==1){//header request

                var headers={};

                var dynamic_table = server.connections[quic_connection_id].h3_remote_qpack_dynamic_table;
                var header_block = parse_qpack_header_block(h3_frames[i].payload);
                
                if(header_block.insert_count<=dynamic_table.length){
                  var used_dynamic_ref=false;


                  for(var i2 in header_block.headers){

                    if(header_block.headers[i2].type=='indexed'){
                      if(header_block.headers[i2].from_static_table==true){
                        if(header_block.headers[i2].index<qpack_static_table_entries.length){
                          
                          headers[qpack_static_table_entries[header_block.headers[i2].index][0]]=qpack_static_table_entries[header_block.headers[i2].index][1];

                        }else{
                          //error?
                        }
                      }else{
                        // from dynamic table
                        used_dynamic_ref=true;

                        var dynamic_index = header_block.base_index - 1 - header_block.headers[i2].index;
                        if (dynamic_index >= 0 && dynamic_index < dynamic_table.length) {
                          var [name, value] = dynamic_table[dynamic_index];
                          headers[name] = value;
                        }
                        
                      }
                    }else if(header_block.headers[i2].type=='literal_with_name_ref'){
                      if(header_block.headers[i2].from_static_table==true){
                        if(header_block.headers[i2].name_index<qpack_static_table_entries.length){
                          headers[qpack_static_table_entries[header_block.headers[i2].name_index][0]]=header_block.headers[i2].value;
                        }
                      }else{
                        //from dynamic table...
                        used_dynamic_ref=true;

                        var dynamic_index = header_block.base_index - 1 - header_block.headers[i2].name_index;
                        if (dynamic_index >= 0 && dynamic_index < dynamic_table.length) {
                          var [name] = dynamic_table[dynamic_index];
                          headers[name] = header_block.headers[i2].value;
                        }
                      }
                    }else if(header_block.headers[i2].type=='literal_with_literal_name'){
                      headers[header_block.headers[i2].name]=header_block.headers[i2].value;
                    }
                  }

                  if(used_dynamic_ref==true){
                    //build and send the: build_qpack_block_header_ack(stream_id)
                  }
                }

                //console.log(headers);

                if (headers[':protocol'] === 'webtransport') {
                  if (server._webtransport_handler) {
                    if(stream_id in server.connections[quic_connection_id].h3_wt_sessions==false){

                      var headers_payload = build_http3_literal_headers_frame([
                        { name: ":status", value: "200" },
                      ]);

                      var http3_response=build_h3_frames([
                        { frame_type: 1, payload: headers_payload }
                      ]);

                      set_sending_quic_chunk(server,quic_connection_id,{
                        type: '1rtt',
                        stream_id: Number(stream_id),
                        fin: false,
                        data: http3_response
                      });

                      var wt = create_wt_session_object(server, quic_connection_id, stream_id, headers);
                      server.connections[quic_connection_id].h3_wt_sessions[stream_id] = wt;
                      server._webtransport_handler(wt);
                    }
                  }
                }else{

                  //...
                  if(server._handler){
                    var req = {
                      method: headers[':method'],
                      path: headers[':path'],
                      headers: headers,
                      connection_id: quic_connection_id,
                      stream_id: stream_id
                    };

                    var res = build_response_object(server, quic_connection_id, stream_id);

                    server._handler(req, res);
                  }
                  
                }

              }else{//...

              }
            }
            
          }
          
        }


        



      }
    }

  }
}

function receiving_udp_quic_packet(server,from_ip,from_port,udp_packet_data){

  var quic_packets=parse_quic_datagram(udp_packet_data);

  if(quic_packets.length>0){
    for(var i in quic_packets){
      if(quic_packets[i]!==null){

        var quic_connection_id=null;

        var dcid_str=null;
        if('dcid' in quic_packets[i] && quic_packets[i].dcid && quic_packets[i].dcid.byteLength>0){
          dcid_str = quic_packets[i].dcid.toString('hex');
        }

        if(dcid_str!==null){
          if(dcid_str in server.connections==true){
            quic_connection_id=dcid_str;
          }
        }else{
          var address_str = from_ip + ':' + from_port;
          if(address_str in server.address_binds==true){
            if(server.address_binds[address_str] in server.connections==true){
              quic_connection_id=server.address_binds[address_str];
            }
          }
        }

        if(quic_connection_id==null){
          if(dcid_str!==null){
            quic_connection_id=dcid_str;
          }else{
            quic_connection_id=Math.floor(Math.random() * 9007199254740991);
          }
        }


        var build_params={};
        
        build_params['from_ip']=from_ip;
        build_params['from_port']=from_port;

        if('dcid' in quic_packets[i] && quic_packets[i].dcid && quic_packets[i].dcid.byteLength>0){
          build_params['dcid']=quic_packets[i].dcid;
        }

        if('scid' in quic_packets[i] && quic_packets[i].scid && quic_packets[i].scid.byteLength>0){
          build_params['scid']=quic_packets[i].scid;
        }

        if('version' in quic_packets[i] && quic_packets[i].version){
          build_params['version']=quic_packets[i].version;
        }


        if(quic_packets[i].type=='initial'){

          build_params['incoming_packet']={
            type: quic_packets[i].type,
            data: quic_packets[i].raw
          };

        }else if(quic_packets[i].type=='handshake'){

          build_params['incoming_packet']={
            type: quic_packets[i].type,
            data: quic_packets[i].raw
          };

        }else if(quic_packets[i].type=='1rtt'){

          
          build_params['incoming_packet']={
            type: quic_packets[i].type,
            data: quic_packets[i].raw
          };

        }else{
          //console.log(quic_packets[i]);
        }

        //console.log(build_params);

        set_quic_connection(server,quic_connection_id,build_params);


      }
    }
  }

}



function set_quic_connection(server,quic_connection_id,options){
  var is_modified=false;

  if(quic_connection_id in server.connections==false){
    server.connections[quic_connection_id]=structuredClone(new_quic_connection);

    is_modified=true;
  }

  var prev_params={
    connection_status: server.connections[quic_connection_id].connection_status,
    sni: server.connections[quic_connection_id].sni
  };

  if(typeof options=='object'){

    if('from_ip' in options){
      if(server.connections[quic_connection_id].from_ip!==options.from_ip){

        server.connections[quic_connection_id].from_ip=options.from_ip;
        is_modified=true;
      }
    }

    if('from_port' in options){
      if(server.connections[quic_connection_id].from_port!==options.from_port){

        server.connections[quic_connection_id].from_port=options.from_port;
        is_modified=true;
      }
    }

    if('version' in options){
      if(server.connections[quic_connection_id].version!==options.version){

        server.connections[quic_connection_id].version=options.version;
        is_modified=true;
      }
    }

    
    if('dcid' in options && options.dcid && options.dcid.byteLength>0){
      if(server.connections[quic_connection_id].original_dcid==null || server.connections[quic_connection_id].original_dcid.byteLength<=0 || arraybufferEqual(options.dcid.buffer,server.connections[quic_connection_id].original_dcid.buffer)==false){

        server.connections[quic_connection_id].original_dcid=options.dcid;
        is_modified=true;
        
      }
    }


    if('scid' in options && options.scid && options.scid.byteLength>0){

      var is_scid_exist=false;
      for(var i in server.connections[quic_connection_id].their_cids){
        if(arraybufferEqual(options.scid.buffer,server.connections[quic_connection_id].their_cids[i].buffer)==true){
          is_scid_exist=true;
          break;
        }
      }

      if(is_scid_exist==false){
        server.connections[quic_connection_id].their_cids.push(options.scid);
        is_modified=true;
      }
    }


    if('sni' in options){
      if(server.connections[quic_connection_id].sni!==options.sni){

        server.connections[quic_connection_id].sni=options.sni;
        is_modified=true;

      }
    }

    if('connection_status' in options){
      if(server.connections[quic_connection_id].connection_status!==options.connection_status){

        server.connections[quic_connection_id].connection_status=options.connection_status;
        is_modified=true;

        //clean up...
        if(server.connections[quic_connection_id].connection_status==1){
          server.connections[quic_connection_id].tls_transcript=[];
          server.connections[quic_connection_id].receiving_init_chunks={};
          server.connections[quic_connection_id].receiving_handshake_chunks={};
        }


      }
    }


  }


  if(is_modified==true){
    
    var address_str = server.connections[quic_connection_id].from_ip + ':' + server.connections[quic_connection_id].from_port;
    if(address_str in server.address_binds==false || server.address_binds[address_str]!==quic_connection_id){

      server.address_binds[address_str]=quic_connection_id;
    }


    quic_connection(server,quic_connection_id,{
      connection_status: server.connections[quic_connection_id].connection_status,
      sni: server.connections[quic_connection_id].sni
    },prev_params);

  }

  if(typeof options=='object'){

    

    if('cert' in options && 'key' in options){


      var cipher_info = get_cipher_info(server.connections[quic_connection_id].tls_cipher_selected);
      var hash_func = cipher_info.hash;





      var cert = new crypto.X509Certificate(options.cert);
      var cert_der = new Uint8Array(cert.raw);

      var certificate = build_certificate([{ cert: cert_der, extensions: new Uint8Array(0) }]);
      
      server.connections[quic_connection_id].tls_transcript.push(certificate);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: certificate
      });

      //////////////////////////////////


      
      var privateKeyObj = crypto.createPrivateKey(options.key);

      
      var label = new TextEncoder().encode("TLS 1.3, server CertificateVerify");
      var separator = new Uint8Array([0x00]);
      var handshake_hash = hash_transcript(server.connections[quic_connection_id].tls_transcript,hash_func); // SHA-256 over transcript

      // padding של 64 תווי רווח
      var padding = new Uint8Array(64).fill(0x20);

      // בניית signed_data לפי הפורמט
      var signed_data = new Uint8Array(
          padding.length + label.length + separator.length + handshake_hash.length
      );
      signed_data.set(padding, 0);
      signed_data.set(label, padding.length);
      signed_data.set(separator, padding.length + label.length);
      signed_data.set(handshake_hash, padding.length + label.length + separator.length);

      // מיפוי סוגי מפתח לאלגוריתמים תקניים
      var ALGO_BY_TYPE = {
          'rsa': 0x0804,       // rsa_pss_rsae_sha256
          'ec': 0x0403,        // ecdsa_secp256r1_sha256
          'ed25519': 0x0807    // ed25519
      };

      var keyType = privateKeyObj.asymmetricKeyType;
      var algo_candidate = ALGO_BY_TYPE[keyType];

      if (!algo_candidate) {
          throw new Error("Unsupported private key type for TLS 1.3 CertificateVerify: " + keyType);
      }

      if (!server.connections[quic_connection_id].tls_signature_algorithms.includes(algo_candidate)) {
          throw new Error(`Client did not offer compatible signature algorithm for key type ${keyType}`);
      }

      var signature=null;

      if (keyType === 'rsa') {
          signature = new Uint8Array(crypto.sign('sha256', Buffer.from(signed_data), 
              {
                  key: privateKeyObj,
                  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST // 32 bytes for SHA256
              }
          ));
      } else if (keyType === 'ec') {
          signature = new Uint8Array(crypto.sign('sha256', Buffer.from(signed_data), privateKeyObj));
      } else if (keyType === 'ed25519') {
          signature = new Uint8Array(crypto.sign(null, Buffer.from(signed_data), privateKeyObj));
      }

      var cert_verify = build_certificate_verify(algo_candidate, signature);
      
      server.connections[quic_connection_id].tls_transcript.push(cert_verify);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: cert_verify
      });

      /////////////////////////////////
      var finished_key = hkdf_expand_label(server.connections[quic_connection_id].tls_server_handshake_traffic_secret, 'finished', new Uint8Array(), hash_func.outputLen,hash_func);

      var verify_data = hmac(cipher_info.str, finished_key, hash_transcript(server.connections[quic_connection_id].tls_transcript,hash_func));

      var finished = build_finished(verify_data);
      server.connections[quic_connection_id].tls_transcript.push(finished);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: finished
      });
      //////////////////////////////


      var c = tls_derive_app_secrets(server.connections[quic_connection_id].tls_handshake_secret, server.connections[quic_connection_id].tls_transcript, hash_func);

      server.connections[quic_connection_id].tls_client_app_traffic_secret = c.client_application_traffic_secret;

      server.connections[quic_connection_id].tls_server_app_traffic_secret = c.server_application_traffic_secret;

    }

    

    if('incoming_packet' in options){

      if('type' in options['incoming_packet']){

        var read_key=null;
        var read_iv=null;
        var read_hp=null;

        var largest_pn=-1;

        if(options['incoming_packet']['type']=='initial'){

          if(server.connections[quic_connection_id].init_read_key!==null && server.connections[quic_connection_id].init_read_iv!==null && server.connections[quic_connection_id].init_read_hp!==null){
            read_key=server.connections[quic_connection_id].init_read_key;
            read_iv=server.connections[quic_connection_id].init_read_iv;
            read_hp=server.connections[quic_connection_id].init_read_hp;

          }else{
            var d = quic_derive_init_secrets(server.connections[quic_connection_id].original_dcid,server.connections[quic_connection_id].version,'read');

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            server.connections[quic_connection_id].init_read_key=d.key;
            server.connections[quic_connection_id].init_read_iv=d.iv;
            server.connections[quic_connection_id].init_read_hp=d.hp;
          }

          largest_pn=Number(server.connections[quic_connection_id].receiving_init_pn_largest)+0;

        }else if(options['incoming_packet']['type']=='handshake'){

          if(server.connections[quic_connection_id].handshake_read_key!==null && server.connections[quic_connection_id].handshake_read_iv!==null && server.connections[quic_connection_id].handshake_read_hp!==null){
            read_key=server.connections[quic_connection_id].handshake_read_key;
            read_iv=server.connections[quic_connection_id].handshake_read_iv;
            read_hp=server.connections[quic_connection_id].handshake_read_hp;

          }else if(server.connections[quic_connection_id].tls_client_handshake_traffic_secret!==null){
            var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_client_handshake_traffic_secret,sha256);

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            server.connections[quic_connection_id].handshake_read_key=d.key;
            server.connections[quic_connection_id].handshake_read_iv=d.iv;
            server.connections[quic_connection_id].handshake_read_hp=d.hp;

          }

          largest_pn=Number(server.connections[quic_connection_id].receiving_handshake_pn_largest)+0;

        }else if(options['incoming_packet']['type']=='1rtt'){

          
          if(server.connections[quic_connection_id].app_read_key!==null && server.connections[quic_connection_id].app_read_iv!==null && server.connections[quic_connection_id].app_read_hp!==null){
            read_key=server.connections[quic_connection_id].app_read_key;
            read_iv=server.connections[quic_connection_id].app_read_iv;
            read_hp=server.connections[quic_connection_id].app_read_hp;

          }else if(server.connections[quic_connection_id].tls_client_app_traffic_secret!==null){

            var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_client_app_traffic_secret,sha256);

            read_key=d.key;
            read_iv=d.iv;
            read_hp=d.hp;

            server.connections[quic_connection_id].app_read_key=d.key;
            server.connections[quic_connection_id].app_read_iv=d.iv;
            server.connections[quic_connection_id].app_read_hp=d.hp;
            

            
            
          }

          largest_pn=Number(server.connections[quic_connection_id].receiving_app_pn_largest)+0;
          
        }

        if(read_key!==null && read_iv!==null){

          var decrypted_packet = decrypt_quic_packet(options['incoming_packet']['data'], read_key, read_iv, read_hp,server.connections[quic_connection_id].original_dcid,largest_pn);

          if(decrypted_packet && decrypted_packet.plaintext!==null && decrypted_packet.plaintext.byteLength>0){

            /*
            if(server.connections[quic_connection_id].read_key_phase!==options['incoming_packet'].key_phase){
              console.log('changed key pashe!!!!!!!!!!!!!!!!!!! '+options['incoming_packet'].key_phase);
              server.connections[quic_connection_id].read_key_phase=options['incoming_packet'].key_phase;
            }
            */

            //console.log('key phase: ',decrypted_packet.key_phase);


            var need_check_tls_chunks=false;
            var is_new_packet=false;

            var need_check_receiving_streams=false;
            

            if(options['incoming_packet']['type']=='initial'){

              is_new_packet=flat_ranges.add(server.connections[quic_connection_id].receiving_init_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

              if(server.connections[quic_connection_id].receiving_init_pn_largest<decrypted_packet.packet_number){
                server.connections[quic_connection_id].receiving_init_pn_largest=decrypted_packet.packet_number;
              }

            }else if(options['incoming_packet']['type']=='handshake'){

              is_new_packet=flat_ranges.add(server.connections[quic_connection_id].receiving_handshake_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

              if(server.connections[quic_connection_id].receiving_handshake_pn_largest<decrypted_packet.packet_number){
                server.connections[quic_connection_id].receiving_handshake_pn_largest=decrypted_packet.packet_number;
              }

            }else if(options['incoming_packet']['type']=='1rtt'){

              is_new_packet=flat_ranges.add(server.connections[quic_connection_id].receiving_app_pn_ranges, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

              if(server.connections[quic_connection_id].receiving_app_pn_largest<decrypted_packet.packet_number){
                server.connections[quic_connection_id].receiving_app_pn_largest=decrypted_packet.packet_number;

                //console.log(server.connections[quic_connection_id].receiving_app_pn_ranges);
              }

              if(server.connections[quic_connection_id].connection_status!==1){
               

                set_quic_connection(server,quic_connection_id,{
                  connection_status: 1
                });
              }

            }
            
            if(is_new_packet==true){

              var ack_eliciting=false;

              var frames=parse_quic_frames(decrypted_packet.plaintext);

              for(var i in frames){
                
                if(ack_eliciting==false && (frames[i].type=='stream' || frames[i].type=='crypto' || frames[i].type=='new_connection_id' || frames[i].type=='handshake_done' || frames[i].type=='path_challenge' || frames[i].type=='path_response' || frames[i].type=='ping')){
                  ack_eliciting=true;
                }



                if(options['incoming_packet']['type']=='handshake'){
                  //console.log('handshake get! ..@@@@@@@@@@@@.');
                  //console.log(frames[i]);
                }else if(options['incoming_packet']['type']=='1rtt'){
                  //console.log('1rtt get! ..@@@@@@@@@@@@.');
                  //console.log(frames[i]);
                }
                

                if(frames[i].type=='crypto'){
                  if(options['incoming_packet']['type']=='initial'){

                    if(flat_ranges.add(server.connections[quic_connection_id].receiving_init_ranges, [frames[i].offset, frames[i].offset + frames[i].data.length])==true){

                      if(frames[i].offset in server.connections[quic_connection_id].receiving_init_chunks==false || server.connections[quic_connection_id].receiving_init_chunks[frames[i].offset].byteLength<frames[i].data.byteLength){
                        server.connections[quic_connection_id].receiving_init_chunks[frames[i].offset]=frames[i].data;
                      }
                      
                      need_check_tls_chunks=true;

                    }

                  }else if(options['incoming_packet']['type']=='handshake'){

                    if(flat_ranges.add(server.connections[quic_connection_id].receiving_handshake_ranges, [frames[i].offset, frames[i].offset + frames[i].data.length])==true){

                      

                      if(frames[i].offset in server.connections[quic_connection_id].receiving_handshake_chunks==false || server.connections[quic_connection_id].receiving_handshake_chunks[frames[i].offset].byteLength<frames[i].data.byteLength){
                        server.connections[quic_connection_id].receiving_handshake_chunks[frames[i].offset]=frames[i].data;
                      }
                      
                      need_check_tls_chunks=true;

                    }

                  }
                }else if(frames[i].type=='stream'){

                  if(frames[i].id in server.connections[quic_connection_id].receiving_streams==false){
                    server.connections[quic_connection_id].receiving_streams[frames[i].id]={
                      receiving_chunks: {},
                      total_size: 0,
                      receiving_ranges: [],
                      need_check: false
                    };
                  }

                  if(flat_ranges.add(server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_ranges, [frames[i].offset, frames[i].offset + frames[i].data.length])==true){
                    
                    if(frames[i].offset in server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_chunks==false || server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_chunks[frames[i].offset].byteLength<frames[i].data.byteLength){
                      server.connections[quic_connection_id].receiving_streams[frames[i].id].receiving_chunks[frames[i].offset]=frames[i].data;
                    }

                    if('fin' in frames[i] && frames[i].fin==true){
                      server.connections[quic_connection_id].receiving_streams[frames[i].id].total_size=frames[i].data.byteLength+frames[i].offset;
                    }

                    server.connections[quic_connection_id].receiving_streams[frames[i].id].need_check=true;

                    if(need_check_receiving_streams==false){
                      need_check_receiving_streams=true;
                    }

                  }

                }else if(frames[i].type=='stop_sending'){

                  //console.log(frames[i]);
                  //console.log('stop_sending!!!!!!!!!!!');

                }else if(frames[i].type=='datagram'){

                  var wt_datagram=parse_webtransport_datagram(frames[i].data);
                  if(wt_datagram.stream_id in server.connections[quic_connection_id].h3_wt_sessions){
                    var session = server.connections[quic_connection_id].h3_wt_sessions[wt_datagram.stream_id];
                    if (typeof session.ondatagram === 'function') {
                      session.ondatagram(wt_datagram.data); // מעביר רק את התוכן
                    }
                  }

                }else if(frames[i].type=='ack'){
                  

                  if(options['incoming_packet']['type']=='initial'){

                    var acked_ranges=quic_acked_info_to_ranges(frames[i]);

                    if(flat_ranges.add(server.connections[quic_connection_id].sending_init_pn_acked_ranges, acked_ranges)==true){
                      //console.log(server.connections[quic_connection_id].sending_init_pn_acked_ranges);
                    }

                  }else if(options['incoming_packet']['type']=='handshake'){

                    var acked_ranges=quic_acked_info_to_ranges(frames[i]);

                    if(flat_ranges.add(server.connections[quic_connection_id].sending_handshake_pn_acked_ranges, acked_ranges)==true){
                      //console.log(server.connections[quic_connection_id].sending_handshake_pn_acked_ranges);
                    }

                  }else if(options['incoming_packet']['type']=='1rtt'){

                    process_ack_frame(server,quic_connection_id,frames[i]);

                  }


                }else{
                  //console.log(frames[i]);
                }

                
              }

              //console.log('get frames:');
              //console.log(frames);


              if(options['incoming_packet']['type']=='1rtt'){
                //add to history
                var now=Math.floor(performance.timeOrigin + performance.now());
                server.connections[quic_connection_id].receiving_app_pn_history.push([decrypted_packet.packet_number,now,options['incoming_packet']['data'].byteLength]);
              }

              if(ack_eliciting==true){
                var ack_frame_to_send = [];

                if(options['incoming_packet']['type']=='initial'){
                  ack_frame_to_send.push(build_ack_info_from_ranges(server.connections[quic_connection_id].receiving_init_pn_ranges, null, 0));
                }else if(options['incoming_packet']['type']=='handshake'){
                  ack_frame_to_send.push(build_ack_info_from_ranges(server.connections[quic_connection_id].receiving_handshake_pn_ranges, null, 0));
                }else if(options['incoming_packet']['type']=='1rtt'){

                  flat_ranges.add(server.connections[quic_connection_id].receiving_app_pn_pending_ack, [decrypted_packet.packet_number,decrypted_packet.packet_number]);

                  prepare_and_send_quic_packet(server,quic_connection_id);
                  
                }


                if(ack_frame_to_send.length>0){
                  send_quic_frames_packet(server,quic_connection_id,options['incoming_packet']['type'],ack_frame_to_send);
                }
              }


              
              
            }


            var tls_messages=[];

            if(need_check_tls_chunks==true){
              if(options['incoming_packet']['type']=='initial'){
                
                var ext=extract_tls_messages_from_chunks(server.connections[quic_connection_id].receiving_init_chunks, server.connections[quic_connection_id].receiving_init_from_offset);
                
                tls_messages=ext.tls_messages;

                server.connections[quic_connection_id].receiving_init_from_offset=ext.new_from_offset;

              }else if(options['incoming_packet']['type']=='handshake'){

                var ext=extract_tls_messages_from_chunks(server.connections[quic_connection_id].receiving_handshake_chunks, server.connections[quic_connection_id].receiving_handshake_from_offset);
                
                tls_messages=ext.tls_messages;

                server.connections[quic_connection_id].receiving_handshake_from_offset=ext.new_from_offset;

              }
            }


            if(tls_messages.length>0){
              for(var i in tls_messages){
                process_quic_tls_message(server,quic_connection_id,tls_messages[i]);
              }
            }

            if(need_check_receiving_streams==true){
              
              if(server.connections[quic_connection_id].receiving_streams_next_check_timer==null){
                
                //run timer...
                server.connections[quic_connection_id].receiving_streams_next_check_timer=setTimeout(function(){
                  server.connections[quic_connection_id].receiving_streams_next_check_timer=null;
                  process_quic_receiving_streams(server,quic_connection_id);
                },5);

              }

            }


            

          }else{

            //console.log('decrtyped packet fail...');

          }
        }


        

      }

    }
  }
}

function process_ack_frame(server,quic_connection_id,frame){
  if(quic_connection_id in server.connections){

    var acked_ranges=quic_acked_info_to_ranges(frame);


    if('largest' in frame && 'delay' in frame){
      var largest_pn=frame.largest;

      if(server.connections[quic_connection_id].sending_app_pn_in_flight.has(largest_pn)==true){
        var now = Math.floor(performance.timeOrigin + performance.now());
        var ack_delay_raw=frame.delay;
        var ack_delay_ms = Math.round((ack_delay_raw * Math.pow(2, 3)) / 1000);

        var pn_index = largest_pn - (server.connections[quic_connection_id].sending_app_pn_base - server.connections[quic_connection_id].sending_app_pn_history.length);

        if (pn_index >= 0 && pn_index < server.connections[quic_connection_id].sending_app_pn_history.length) {
          /*
          console.log('pn_index: ',pn_index);
          console.log('sending_app_pn_history.length: ',server.connections[quic_connection_id].sending_app_pn_history.length);
          console.log('largest_pn: ',largest_pn);
          console.log('sending_app_pn_base: ',server.connections[quic_connection_id].sending_app_pn_base);
          */

          var start_time=server.connections[quic_connection_id].sending_app_pn_history[pn_index][0];
          

          var received_time_estimate = now - ack_delay_ms;

          var measured_rtt = now - start_time - ack_delay_ms;

          var sent_bytes_during = 0;
          var sent_packets_during = 0;

          for (var i2 = pn_index; i2 < server.connections[quic_connection_id].sending_app_pn_history.length; i2++) {
            var [ts, size] = server.connections[quic_connection_id].sending_app_pn_history[i2];
            if (received_time_estimate >= ts) {
              sent_bytes_during += size;
              sent_packets_during++;
            }
          }

          var received_bytes_during = 0;
          var received_packets_during = 0;

          for (var i2 = 0; i2 < server.connections[quic_connection_id].receiving_app_pn_history.length; i2++) {
            var [pn_recv, ts_recv, size_recv] = server.connections[quic_connection_id].receiving_app_pn_history[i2];
            if (ts_recv > received_time_estimate){
              break;

            }else if (ts_recv >= start_time) {
              received_bytes_during += size_recv;
              received_packets_during++;
            }
          }


          var last_rtt_record=null;
          if(server.connections[quic_connection_id].rtt_history.length>0){
            last_rtt_record=server.connections[quic_connection_id].rtt_history[server.connections[quic_connection_id].rtt_history.length-1];
          }

          if(last_rtt_record==null || (last_rtt_record[0]!==start_time && last_rtt_record[1]!==received_time_estimate)){
            server.connections[quic_connection_id].rtt_history.push([
              start_time,                // 0 - מתי נשלח
              received_time_estimate,    // 1 - מתי התקבל ACK
              sent_bytes_during,         // 2 - כמה נשלח בזמן הזה
              sent_packets_during,       // 3 - כמה פאקטים נשלחו
              received_bytes_during,     // 4 - כמה התקבל באותו זמן
              received_packets_during,   // 5 - כמה פאקטים התקבלו
              measured_rtt,              // 6 - RTT
            ]);
          }
          

          //console.log(server.connections[quic_connection_id]);
        }

      }
    }



    for (var pn of server.connections[quic_connection_id].sending_app_pn_in_flight) {
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
        server.connections[quic_connection_id].sending_app_pn_in_flight.delete(pn);


        for(var stream_id in server.connections[quic_connection_id].sending_streams){
          
          if('in_flight_ranges' in server.connections[quic_connection_id].sending_streams[stream_id] && pn in server.connections[quic_connection_id].sending_streams[stream_id].in_flight_ranges==true){

            if(flat_ranges.add(server.connections[quic_connection_id].sending_streams[stream_id].acked_ranges, server.connections[quic_connection_id].sending_streams[stream_id].in_flight_ranges[pn])==true){
              
            }

            delete server.connections[quic_connection_id].sending_streams[stream_id].in_flight_ranges[pn];

            if(server.connections[quic_connection_id].sending_streams[stream_id].acked_ranges.length==2 && server.connections[quic_connection_id].sending_streams[stream_id].total_size && server.connections[quic_connection_id].sending_streams[stream_id].total_size>0 && server.connections[quic_connection_id].sending_streams[stream_id].acked_ranges[0]==0 && server.connections[quic_connection_id].sending_streams[stream_id].acked_ranges[1]==server.connections[quic_connection_id].sending_streams[stream_id].total_size){
              //we can delete it...
              delete server.connections[quic_connection_id].sending_streams[stream_id];
            }

            //console.log(server.connections[quic_connection_id].sending_streams[stream_id]);
          }
        }

        


        
        


      }
    }

  }
}

function send_quic_frames_packet(server,quic_connection_id,type,frames){
  if(quic_connection_id in server.connections){

    var write_key=null;
    var write_iv=null;
    var write_hp=null;

    var packet_number=1;

    if(type=='initial'){

      if(server.connections[quic_connection_id].init_write_key!==null && server.connections[quic_connection_id].init_write_iv!==null && server.connections[quic_connection_id].init_write_hp!==null){
        write_key=server.connections[quic_connection_id].init_write_key;
        write_iv=server.connections[quic_connection_id].init_write_iv;
        write_hp=server.connections[quic_connection_id].init_write_hp;

      }else{
        var d = quic_derive_init_secrets(server.connections[quic_connection_id].original_dcid,server.connections[quic_connection_id].version,'write');

        write_key=d.key;
        write_iv=d.iv;
        write_hp=d.hp;

        server.connections[quic_connection_id].init_write_key=d.key;
        server.connections[quic_connection_id].init_write_iv=d.iv;
        server.connections[quic_connection_id].init_write_hp=d.hp;
      }


      packet_number=Number(server.connections[quic_connection_id].sending_init_pn_next)+0;

    }else if(type=='handshake'){

      if(server.connections[quic_connection_id].handshake_write_key!==null && server.connections[quic_connection_id].handshake_write_iv!==null && server.connections[quic_connection_id].handshake_write_hp!==null){
        write_key=server.connections[quic_connection_id].handshake_write_key;
        write_iv=server.connections[quic_connection_id].handshake_write_iv;
        write_hp=server.connections[quic_connection_id].handshake_write_hp;

      }else if(server.connections[quic_connection_id].tls_server_handshake_traffic_secret!==null){
        var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_server_handshake_traffic_secret,sha256);

        write_key=d.key;
        write_iv=d.iv;
        write_hp=d.hp;

        server.connections[quic_connection_id].handshake_write_key=d.key;
        server.connections[quic_connection_id].handshake_write_iv=d.iv;
        server.connections[quic_connection_id].handshake_write_hp=d.hp;
      }

      packet_number=Number(server.connections[quic_connection_id].sending_handshake_pn_next)+0;

    }else if(type=='1rtt'){
      
      if(server.connections[quic_connection_id].app_write_key!==null && server.connections[quic_connection_id].app_write_iv!==null && server.connections[quic_connection_id].app_write_hp!==null){
        write_key=server.connections[quic_connection_id].app_write_key;
        write_iv=server.connections[quic_connection_id].app_write_iv;
        write_hp=server.connections[quic_connection_id].app_write_hp;

      }else if(server.connections[quic_connection_id].tls_server_app_traffic_secret!==null){
        var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_server_app_traffic_secret,sha256);

        write_key=d.key;
        write_iv=d.iv;
        write_hp=d.hp;

        server.connections[quic_connection_id].app_write_key=d.key;
        server.connections[quic_connection_id].app_write_iv=d.iv;
        server.connections[quic_connection_id].app_write_hp=d.hp;
      }

      packet_number=Number(server.connections[quic_connection_id].sending_app_pn_base)+0;

    }

    //console.log('sending packet_number===');
    //console.log(packet_number);
    

    var dcid=new Uint8Array(0);

    if(server.connections[quic_connection_id].their_cids.length>0){
      dcid=server.connections[quic_connection_id].their_cids[0];
    }

    var encodedFrames = encode_quic_frames(frames);
    var encrypted_quic_packet=encrypt_quic_packet(type, encodedFrames, write_key, write_iv, write_hp, packet_number,dcid,server.connections[quic_connection_id].original_dcid, new Uint8Array(0));

    if(type=='initial'){
        server.connections[quic_connection_id].sending_init_pn_next++;
      }else if(type=='handshake'){
        server.connections[quic_connection_id].sending_handshake_pn_next++;
      }else if(type=='1rtt'){
        var now = Math.floor(performance.timeOrigin + performance.now());
        server.connections[quic_connection_id].sending_app_pn_history.push([now, encodedFrames.length]);
        server.connections[quic_connection_id].sending_app_pn_base++;
      }
    
    send_udp_packet(server,encrypted_quic_packet,server.connections[quic_connection_id].from_port,server.connections[quic_connection_id].from_ip,function(){

      

    });

    

  }
}

function send_udp_packet(server,data,port,ip,callback){
  if(ip.indexOf(':')>=0){
    server._udp6.send(data, port, ip, function(error){
      if (error) {
        callback(false);
      } else {
        callback(true);
      }
    });
  }else{
    server._udp4.send(data, port, ip, function(error){
      if (error) {
        callback(false);
      } else {
        callback(true);
      }
    });
  }
}


function send_quic_packet(server,quic_connection_id,type,encoded_frames,callback){
  if(quic_connection_id in server.connections){

    var write_key=null;
    var write_iv=null;
    var write_hp=null;

    var packet_number=1;

    if(type=='initial'){

      if(server.connections[quic_connection_id].init_write_key!==null && server.connections[quic_connection_id].init_write_iv!==null && server.connections[quic_connection_id].init_write_hp!==null){
        write_key=server.connections[quic_connection_id].init_write_key;
        write_iv=server.connections[quic_connection_id].init_write_iv;
        write_hp=server.connections[quic_connection_id].init_write_hp;

      }else{
        var d = quic_derive_init_secrets(server.connections[quic_connection_id].original_dcid,server.connections[quic_connection_id].version,'write');

        write_key=d.key;
        write_iv=d.iv;
        write_hp=d.hp;

        server.connections[quic_connection_id].init_write_key=d.key;
        server.connections[quic_connection_id].init_write_iv=d.iv;
        server.connections[quic_connection_id].init_write_hp=d.hp;
      }


      packet_number=Number(server.connections[quic_connection_id].sending_init_pn_next)+0;

    }else if(type=='handshake'){

      if(server.connections[quic_connection_id].handshake_write_key!==null && server.connections[quic_connection_id].handshake_write_iv!==null && server.connections[quic_connection_id].handshake_write_hp!==null){
        write_key=server.connections[quic_connection_id].handshake_write_key;
        write_iv=server.connections[quic_connection_id].handshake_write_iv;
        write_hp=server.connections[quic_connection_id].handshake_write_hp;

      }else if(server.connections[quic_connection_id].tls_server_handshake_traffic_secret!==null){
        var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_server_handshake_traffic_secret,sha256);

        write_key=d.key;
        write_iv=d.iv;
        write_hp=d.hp;

        server.connections[quic_connection_id].handshake_write_key=d.key;
        server.connections[quic_connection_id].handshake_write_iv=d.iv;
        server.connections[quic_connection_id].handshake_write_hp=d.hp;
      }

      packet_number=Number(server.connections[quic_connection_id].sending_handshake_pn_next)+0;

    }else if(type=='1rtt'){
      
      if(server.connections[quic_connection_id].app_write_key!==null && server.connections[quic_connection_id].app_write_iv!==null && server.connections[quic_connection_id].app_write_hp!==null){
        write_key=server.connections[quic_connection_id].app_write_key;
        write_iv=server.connections[quic_connection_id].app_write_iv;
        write_hp=server.connections[quic_connection_id].app_write_hp;

      }else if(server.connections[quic_connection_id].tls_server_app_traffic_secret!==null){
        var d = quic_derive_from_tls_secrets(server.connections[quic_connection_id].tls_server_app_traffic_secret,sha256);

        write_key=d.key;
        write_iv=d.iv;
        write_hp=d.hp;

        server.connections[quic_connection_id].app_write_key=d.key;
        server.connections[quic_connection_id].app_write_iv=d.iv;
        server.connections[quic_connection_id].app_write_hp=d.hp;
      }

      packet_number=Number(server.connections[quic_connection_id].sending_app_pn_base)+0;

    }

    //console.log('sending packet_number===');
    //console.log(packet_number);
    

    var dcid=new Uint8Array(0);

    if(server.connections[quic_connection_id].their_cids.length>0){
      dcid=server.connections[quic_connection_id].their_cids[0];
    }

    var encrypted_quic_packet=encrypt_quic_packet(type, encoded_frames, write_key, write_iv, write_hp, packet_number,dcid,server.connections[quic_connection_id].original_dcid, new Uint8Array(0));
    
    send_udp_packet(server,encrypted_quic_packet,server.connections[quic_connection_id].from_port,server.connections[quic_connection_id].from_ip,function(is_sent){

      if(typeof callback=='function'){
        callback(is_sent);
      }

    });

  }
}







function process_quic_tls_message(server,quic_connection_id,tls_message){
  if(quic_connection_id in server.connections==true){

    var hs = parse_tls_message(tls_message);
    if (hs.type === 0x01) {
      var parsed = parse_tls_client_hello(hs.body);
      
      server.connections[quic_connection_id].tls_signature_algorithms=parsed.signature_algorithms;
      server.connections[quic_connection_id].tls_transcript=[tls_message];

      var a=handle_client_hello(parsed);

      //console.log('handle_client_hello:');
      //console.log(parsed);

      var quic_transport_parameters=parse_transport_parameters(parsed.quic_transport_parameters_raw);
      //console.log('quic_transport_parameters:');
      //console.dir(quic_transport_parameters, { depth: null });

      if ('ack_delay_exponent' in quic_transport_parameters) {
        server.connections[quic_connection_id].remote_ack_delay_exponent=quic_transport_parameters['ack_delay_exponent'];
      }

      if ('max_udp_payload_size' in quic_transport_parameters) {
        server.connections[quic_connection_id].remote_max_udp_payload_size=quic_transport_parameters['max_udp_payload_size'];
      }

      

      server.connections[quic_connection_id].tls_cipher_selected=a.selected_cipher;

      var server_random = crypto.randomBytes(32);
      var server_hello = build_server_hello(server_random, a.server_public_key, parsed.session_id, server.connections[quic_connection_id].tls_cipher_selected, a.selected_group);

      
      server.connections[quic_connection_id].tls_transcript.push(server_hello);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'initial',
        data: server_hello
      });


      var cipher_info = get_cipher_info(server.connections[quic_connection_id].tls_cipher_selected);
      var hash_func = cipher_info.hash;

      var b = tls_derive_handshake_secrets(a.shared_secret, server.connections[quic_connection_id].tls_transcript, hash_func);

      server.connections[quic_connection_id].tls_handshake_secret=b.handshake_secret;


      server.connections[quic_connection_id].tls_client_handshake_traffic_secret=b.client_handshake_traffic_secret;

      server.connections[quic_connection_id].tls_server_handshake_traffic_secret=b.server_handshake_traffic_secret;

      var quic_ext_data=build_quic_ext({
        original_destination_connection_id: server.connections[quic_connection_id].original_dcid,
        initial_source_connection_id: server.connections[quic_connection_id].original_dcid,
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
          "*" // או הדומיין שלך
        ]
      });


      var supported_alpn = ['h3'];
      var selected_alpn=null;

      for(var i in supported_alpn){
        if(selected_alpn==null){
          for(var i2 in parsed.alpn){
            if(parsed.alpn[i2]==supported_alpn[i]){
              selected_alpn=parsed.alpn[i2];
              break;
            }
          }
        }
      }

      server.connections[quic_connection_id].tls_alpn_selected=selected_alpn;


      var enc_ext = build_encrypted_extensions([
          { type: 0x10, data: build_alpn_ext(selected_alpn) },
          { type: 0x39, data: quic_ext_data}
      ]);

      server.connections[quic_connection_id].tls_transcript.push(enc_ext);

      set_sending_quic_chunk(server,quic_connection_id,{
        type: 'handshake',
        data: enc_ext
      });

      set_quic_connection(server,quic_connection_id,{
        sni: parsed.sni
      });

      
    }else if (hs.type === 20) {

      
      //finished from client here...
      var cipher_info = get_cipher_info(server.connections[quic_connection_id].tls_cipher_selected);
      var hash_func = cipher_info.hash;


      var finished_key = hkdf_expand_label(server.connections[quic_connection_id].tls_client_handshake_traffic_secret, 'finished', new Uint8Array(), hash_func.outputLen,hash_func);

      var expected_client_finished = hmac(cipher_info.str, finished_key, hash_transcript(server.connections[quic_connection_id].tls_transcript,hash_func));

      if(arraybufferEqual(expected_client_finished.buffer,new Uint8Array(hs.body).buffer)==true){
        //finished ok!!!!!!

        //console.log('finished ok!!!!!!!');
        server.connections[quic_connection_id].tls_finished_ok=true;
      }


    }else{
      //console.log('tls other:');
      //console.log(hs);
    }
  }
}

function get_quic_stream_chunks_to_send(server, quic_connection_id, stream_id, allowed_bytes) {
  var conn = server.connections[quic_connection_id];
  if (!conn) return;

  var stream = conn.sending_streams[stream_id];
  if (!stream || !stream.pending_data) {
    return {
      chunks: [],
      send_offset_next: stream ? stream.send_offset_next : 0
    };
  }

    // הגודל הכולל של ה־stream
  var total_bytes = (typeof stream.total_size === 'number')
    ? stream.total_size
    : stream.write_offset_next;

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


function prepare_and_send_quic_packet(server, quic_connection_id) {
  var conn = server.connections[quic_connection_id];
  if (!conn) return;

  //console.log('prepare_and_send_quic_packet...............');

  if(conn.sending_quic_packet_now==false){
    conn.sending_quic_packet_now=true;

    if(conn.next_send_quic_packet_timer!==null){
      clearTimeout(conn.next_send_quic_packet_timer);
      conn.next_send_quic_packet_timer=null;
    }

    var now = Math.floor(performance.timeOrigin + performance.now());

    var total_bytes_last_1s = 0;
    var packet_count_last_1s = 0;

    var oldest_packet_time_bytes = null;
    var oldest_packet_time_packets = null;

    // סריקת ההיסטוריה
    for (var i in conn.sending_app_pn_history) {
      var [ts, size] = conn.sending_app_pn_history[i];

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

    var bytes_left = conn.max_sending_total_bytes_per_sec - total_bytes_last_1s;
    var packets_left = conn.max_sending_packets_per_sec - packet_count_last_1s;

    
    var in_flight_packet_count = conn.sending_app_pn_in_flight.size;
    var in_flight_total_bytes = 0;
    for (var pn of conn.sending_app_pn_in_flight) {
      var pn_index = Number(pn) - (conn.sending_app_pn_base - conn.sending_app_pn_history.length);
      if (pn_index >= 0 && pn_index < conn.sending_app_pn_history.length) {
        var info = conn.sending_app_pn_history[pn_index];
        if (info){
          in_flight_total_bytes=in_flight_total_bytes+info[1];//size
        }
      }
    }


    var in_flight_room = conn.max_sending_bytes_in_flight - in_flight_total_bytes;


    var allowed_packet_size = Math.min(bytes_left, conn.max_sending_packet_size, in_flight_room);


    if (
      packets_left > 0 &&
      allowed_packet_size >= conn.min_sending_packet_size &&
      in_flight_packet_count < conn.max_sending_packets_in_flight &&
      in_flight_total_bytes + allowed_packet_size <= conn.max_sending_bytes_in_flight
    ) {
    // מותר לשלוח *******************************
      

      var encoded_frames=[];
      var update_streams={};
      var remove_pending_ack=[];



      
      if(conn.receiving_app_pn_pending_ack.length>0 && 1==1){
        var ack_delay_ms = 0;
        var largest_pn = conn.receiving_app_pn_pending_ack[conn.receiving_app_pn_pending_ack.length - 1];
        for (var i2 = 0; i2 < conn.receiving_app_pn_history.length; i2++) {
          var [pn_recv, ts_recv, size_recv] = conn.receiving_app_pn_history[i2];
          if(pn_recv==largest_pn){
            ack_delay_ms = now - ts_recv;
            break;
          }
        }

        var delay_ns = ack_delay_ms * 1_000_000;
        var ack_delay_raw = Math.floor(delay_ns / (1 << conn.remote_ack_delay_exponent));
        
        var ack_frame = build_ack_info_from_ranges(conn.receiving_app_pn_pending_ack, null, ack_delay_raw);

        //var padding=new Uint8Array([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]);
        encoded_frames.push(encode_quic_frames([ack_frame]));

        /*
        
        console.log('ack frame sent:');

        console.log(ack_frame);

        console.log('ack for ranges:');

        console.log(conn.receiving_app_pn_pending_ack);

        console.log('raw:');
        console.log(encoded_frames);
        //allowed_packet_size=allowed_packet_size-encoded_frames[0].byteLength;

        */

        remove_pending_ack = conn.receiving_app_pn_pending_ack.slice();
      }



      var active_stream_count=0;
      for(var stream_id in server.connections[quic_connection_id].sending_streams){
        //צריך שיהיה בדיקה אם זה סטרים שעדיין לא נשלח במלואו...
        active_stream_count++;
      }
      var per_stream_bytes = Math.floor(allowed_packet_size / active_stream_count);


      for(var stream_id in server.connections[quic_connection_id].sending_streams){
        
        var chunks_ranges=[];

        var {chunks,send_offset_next}=get_quic_stream_chunks_to_send(server,quic_connection_id,Number(stream_id),per_stream_bytes);

        if(chunks.length>0){
          
          for(var i in chunks){

            var is_fin=false;

            if(chunks[i].offset+chunks[i].data.byteLength>=server.connections[quic_connection_id].sending_streams[stream_id].total_size){
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


      if(encoded_frames.length>0){

        
        /*
        console.log('allowed_packet_size::::::::::::');
        console.log(allowed_packet_size);

        console.log('update_streams::::::::::::');
        console.log(update_streams);

        console.log('frames::::::::::::');
        console.log(frames);

        console.log('encoded_frames::::::::::::');
        console.log(encoded_frames);
        */

        if(encoded_frames.length==1){
          var all_encoded_frames =  encoded_frames[0];
        }else if(encoded_frames.length>1){
          var all_encoded_frames = concatUint8Arrays(encoded_frames);
        }

        send_quic_packet(server,quic_connection_id,'1rtt',all_encoded_frames,function(is_sent){
          if(is_sent==true){
            now = Math.floor(performance.timeOrigin + performance.now());

            var packet_number=server.connections[quic_connection_id].sending_app_pn_base;
            conn.sending_app_pn_history.push([now, all_encoded_frames.length]);
            conn.sending_app_pn_in_flight.add(packet_number);

            for(var stream_id in update_streams){
              server.connections[quic_connection_id].sending_streams[stream_id].in_flight_ranges[packet_number]=update_streams[stream_id].chunks_ranges;
              server.connections[quic_connection_id].sending_streams[stream_id].send_offset_next=update_streams[stream_id].send_offset_next;
            }

            //console.log(server.connections[quic_connection_id].sending_streams);

            if(remove_pending_ack.length>0){
              flat_ranges.remove(conn.receiving_app_pn_pending_ack,remove_pending_ack);
            }


            server.connections[quic_connection_id].sending_app_pn_base++;
          }

          // אם שלחנו הרגע פאקט ואין עדיין מגבלות, נמתין את הזמן הזה כדי לפזר נכון
          //var interval_between_packets = Math.ceil(1000 / server.max_sending_packets_per_sec);
          
          
          
          

          
          //conn.next_send_quic_packet_timer=null;
          //prepare_and_send_quic_packet(server, quic_connection_id);

          
          conn.next_send_quic_packet_timer=setTimeout(function(){
            conn.sending_quic_packet_now=false;
            conn.next_send_quic_packet_timer=null;
            prepare_and_send_quic_packet(server, quic_connection_id);
          }, 0);
          
          
        });
        
       
      }else{

        conn.next_send_quic_packet_timer=null;
        conn.sending_quic_packet_now=false;

      }

    }else{

      // ✋ לא ניתן לשלוח כרגע — צריך לחשב מתי כן יהיה אפשר
      var wait_options = [];

      // זמן עד שיימחק פאקט שמפחית מגבלת פאקטים
      if (packets_left <= 0 && oldest_packet_time_packets !== null) {
        var wait_packets = Math.max(0, (oldest_packet_time_packets + 1000) - now);
        wait_options.push(wait_packets);
      }

      // זמן עד שיימחק מספיק בייטים
      if (bytes_left < conn.min_sending_packet_size && oldest_packet_time_bytes !== null) {
        var wait_bytes = Math.max(0, (oldest_packet_time_bytes + 1000) - now);
        wait_options.push(wait_bytes);
      }

      

      if (wait_options.length > 0) {
        conn.next_send_quic_packet_timer = setTimeout(function(){
          conn.next_send_quic_packet_timer=null;
          conn.sending_quic_packet_now=false;
          prepare_and_send_quic_packet(server, quic_connection_id);
        }, Math.max(...wait_options));

        //console.log('next_time: ',(Math.max(...wait_options)));
      }else{
        conn.sending_quic_packet_now=false;
      }

    }

  }
  
}



function quic_stream_write(server,quic_connection_id,stream_id,data,fin){
  if(quic_connection_id in server.connections==true){
    
    if(stream_id in server.connections[quic_connection_id].sending_streams==false){
      server.connections[quic_connection_id].sending_streams[stream_id]={
        pending_data: null,
        write_offset_next: 0,
        pending_offset_start: 0,
        send_offset_next: 0,
        total_size: 0,

        in_flight_ranges: {},
        acked_ranges: [],
      };
    }


    var stream = server.connections[quic_connection_id].sending_streams[stream_id];

    var start_offset = stream.write_offset_next;
    var end_offset = start_offset + data.byteLength;
    stream.write_offset_next = end_offset;
    //stream.total_size = end_offset;

    if (fin === true) {
      stream.total_size = end_offset;   // הגודל הסופי של הזרם
    }

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

    prepare_and_send_quic_packet(server, quic_connection_id);
  }
}

function set_sending_quic_chunk(server,quic_connection_id,options){
  if(quic_connection_id in server.connections==true){

    var type=null;
    var data=null;
    var stream_id=null;
    var fin=false;
    
    if(typeof options=='object'){
      if('type' in options){
        type=options.type;
      }

      if('data' in options){
        data=options.data;
      }

      if('stream_id' in options){
        stream_id=options.stream_id;
        type='1rtt';
      }

      if('fin' in options){
        fin=options.fin;
      }
    }


    if(type=='initial'){

      //server.connections[quic_connection_id].sending_init_chunks.push(data);

      send_quic_frames_packet(server,quic_connection_id,'initial',[{type: 'crypto', offset: server.connections[quic_connection_id].sending_init_offset_next, data: data}]);

      server.connections[quic_connection_id].sending_init_offset_next=server.connections[quic_connection_id].sending_init_offset_next+data.byteLength;

    }else if(type=='handshake'){

      //server.connections[quic_connection_id].sending_handshake_chunks.push(data);

      send_quic_frames_packet(server,quic_connection_id,'handshake',[{type: 'crypto', offset: server.connections[quic_connection_id].sending_handshake_offset_next, data: data}]);

      server.connections[quic_connection_id].sending_handshake_offset_next=server.connections[quic_connection_id].sending_handshake_offset_next+data.byteLength;

    }else if(type=='1rtt'){

      if(stream_id!==null){

        
        if(stream_id in server.connections[quic_connection_id].sending_streams==false){
          server.connections[quic_connection_id].sending_streams[stream_id]={
            offset_next: 0,
          };
        }

        send_quic_frames_packet(server,quic_connection_id,'1rtt',[{
          type: 'stream', 
          id: Number(stream_id),
          offset: server.connections[quic_connection_id].sending_streams[stream_id].offset_next,
          fin: fin,
          data: data
        }]);

        server.connections[quic_connection_id].sending_streams[stream_id].offset_next=server.connections[quic_connection_id].sending_streams[stream_id].offset_next+data.byteLength;

        
      }
      
      

    }


    


  }
}


function quic_connection(server,quic_connection_id,current_params,prev_params){
  if(current_params!==null){

    if(current_params.connection_status!==prev_params.connection_status){

      //console.log(server.connections[quic_connection_id]);

      if(current_params.connection_status==1){
        //איתות שיש לנו בצלחה פעם ראשונה
        
        
        send_quic_frames_packet(server,quic_connection_id,'1rtt',[{
          type: 'handshake_done'
        }]);
        
      }

      if(current_params.connection_status==1){


        var settings_frame=build_settings_frame({
          SETTINGS_QPACK_MAX_TABLE_CAPACITY: 65536,
          SETTINGS_MAX_FIELD_SECTION_SIZE: 65536,
          SETTINGS_ENABLE_WEBTRANSPORT: 1,
          SETTINGS_H3_DATAGRAM: 1,
          SETTINGS_ENABLE_CONNECT_PROTOCOL: 1,
          SETTINGS_WT_MAX_SESSIONS: 1
          //SETTINGS_NO_RFC9114_LEGACY_CODEPOINT: 1
        });

        var control_stream_frames=build_h3_frames([
          { frame_type: 0x04, payload: settings_frame },
        ]);
      
        quic_stream_write(server,quic_connection_id,3,concatUint8Arrays([new Uint8Array([0x00]),control_stream_frames]),false);


        /*
        set_sending_quic_chunk(server,quic_connection_id,{
          type: '1rtt',
          stream_id: 3,
          data: concatUint8Arrays([new Uint8Array([0x00]),control_stream_frames])
        });
        */

        quic_stream_write(server,quic_connection_id,7,new Uint8Array([0x02]),false);
        
        /*
        set_sending_quic_chunk(server,quic_connection_id,{
          type: '1rtt',
          stream_id: 7,
          data: new Uint8Array([0x02])
        });
        */

        quic_stream_write(server,quic_connection_id,11,new Uint8Array([0x03]),false);

        /*
        set_sending_quic_chunk(server,quic_connection_id,{
          type: '1rtt',
          stream_id: 11,
          data: new Uint8Array([0x03])
        });
        */
        
        

      }

    }

    if(current_params.sni!==prev_params.sni){

      server.SNICallback(current_params.sni, function (err, creds) {
        if (!err && creds) {
          set_quic_connection(server, quic_connection_id, {
            cert: creds.cert,
            key: creds.key
          });
        } else {
          //console.log('No TLS credentials for', current_params.sni);
        }
      });

    }

  }
}




function createServer(options, handler) {
  var server = {
    _udp4: null,
    _udp6: null,
    _port: null,
    _handler: handler || null,
    SNICallback: options.SNICallback || null,
    connections: {},
    address_binds: {},
    _timeout: null,

    listen: function(port, host, callback) {
      var self = this;

      // אם המשתמש לא סיפק host אלא רק callback
      if (typeof host === 'function') {
        callback = host;
        host = null;
      }

      self._port = port || 443;
      host = host || '::';

      // יצירת סוקט UDP4
      self._udp4 = dgram.createSocket('udp4');
      self._udp4.on('message', function(msg, rinfo) {
        receiving_udp_quic_packet(self, rinfo.address, rinfo.port, new Uint8Array(msg));
      });
      self._udp4.on('error', function(err) {
        //console.error('UDP4 error:', err);
      });

      if (host === '::' || host.indexOf('.') !== -1) {
        var host4 = host.indexOf('.') !== -1 ? host : '0.0.0.0';
        self._udp4.bind(self._port, host4);
      }

      // יצירת סוקט UDP6
      self._udp6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
      self._udp6.on('message', function(msg, rinfo) {
        receiving_udp_quic_packet(self, rinfo.address, rinfo.port, new Uint8Array(msg));
      });
      self._udp6.on('error', function(err) {
        //console.error('UDP6 error:', err);
      });

      var host6 = host.indexOf(':') !== -1 ? host : '::';
      self._udp6.bind(self._port, host6, function() {
        if (typeof callback === 'function') {
          callback();
        }
      });
    },


    on: function(event, cb) {
      if (event === 'request'){
         this._handler = cb;
      }else if(event === 'webtransport'){
        this._webtransport_handler = cb;

      }else if(event === 'OCSPRequest'){

      }else if(event === 'newSession'){

      }else if(event === 'resumeSession'){

      }
    },

    close: function() {
      if (this._udp4) this._udp4.close();
      if (this._udp6) this._udp6.close();
    },

    setTimeout: function(ms, cb) {
      this._timeout = setTimeout(cb, ms);
    }
  };

  return server;
}


module.exports = {
  createServer
};
