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

import {
  build_h3_frames,
  build_settings_frame,
  parse_h3_settings_frame,
  extract_qpack_encoder_instructions_from_chunks,
  extract_h3_frames_from_chunks,
  parse_qpack_header_block,
  build_close_webtransport,
  build_http3_literal_headers_frame,
  parse_webtransport_datagram,
  qpack_static_table_entries
} from './libs/h3.js';


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



// ==== H3Socket ====
function H3Socket(options){
  if (!(this instanceof H3Socket)) return new H3Socket(options);
    options = options || {};

    var ev = Emitter();

    var context = {
      isServer: true,

      local_max_header_size: 65536,
      local_qpack_max_table_capacity: 65536,
      local_datagram_support: true,

      remote_max_header_size: 0,//מתקבל ב settings - אחרי פיענוח
      remote_qpack_max_table_capacity: 0,//מתקבל ב settings - גודל הטבלה המקסימלי
      remote_datagram_support: null,

      remote_qpack_table_base_index: 0,
      remote_qpack_table_capacity: 0,
      remote_qpack_dynamic_table: [],

      receiving_streams: {},
    };


    function process_qpack_instructions(instructions){
      var arr_inserts=[];

      for(var i in instructions){
        if(instructions[i].type=='set_dynamic_table_capacity'){
          
          context.remote_qpack_table_capacity=instructions[i].capacity;

        }else if(instructions[i].type=='insert_with_name_ref' || instructions[i].type=='insert_without_name_ref'){
          var name=null;
          var value=instructions[i].value;

          if(instructions[i].type=='insert_with_name_ref'){
            if(instructions[i].from_static_table==true){
              if(instructions[i].name_index<qpack_static_table_entries.length){
                name=qpack_static_table_entries[instructions[i].name_index][0];
              }else{
                //error...
              }
            }else{
              //from dynamic...
              var base_index = context.remote_qpack_table_base_index;
              var name_index = instructions[i].name_index;
              var dynamic_index = base_index - 1 - name_index;
              var dynamic_table = context.remote_qpack_dynamic_table;

              if (dynamic_index >= 0 && dynamic_index < dynamic_table.length) {
                name = dynamic_table[dynamic_index][0];
              } else {
                // Error: missing reference
              }
            }
          }else{
            name=instructions[i].name;
          }
          

          if(name!==null){
            arr_inserts.push([name,value]);
          }

        }
      }

      if(arr_inserts.length>0){
        //console.log(arr_inserts);
        
        for(var i in arr_inserts){
          insert_into_qpack_remote_encoder_dynamic_table(arr_inserts[i][0],arr_inserts[i][1]);
        }

        //console.log(context.remote_qpack_dynamic_table);
        //then... build_qpack_known_received_count(arr_inserts.length);
      }
    }


    /*
    function close_wt(stream_id){
      var close_frame = build_h3_frames([
        { frame_type: 0x2843, payload: build_close_webtransport(0,'close...') }
      ]);

      ev.emit('stream',stream_id,close_frame);
    }
    */


    function http_header_write(stream_id,headers){

      var headers_payload = build_http3_literal_headers_frame(headers);

      var http3_response=build_h3_frames([
        { frame_type: 1, payload: headers_payload }
      ]);

      ev.emit('stream',stream_id,http3_response);
    }

    function http_body_write(stream_id,payload,fin){

      if(payload==null){
        ev.emit('stream',stream_id,null,true);
      }else{
        var http3_response=build_h3_frames([
          { frame_type: 0, payload: payload }
        ]);

        ev.emit('stream',stream_id,http3_response,fin);
      }
      
    }

    function process_http_frame(stream_id,frame_type,payload){

      if(frame_type==1){
        var headers={};

        var dynamic_table = context.remote_qpack_dynamic_table;
        var header_block = parse_qpack_header_block(payload);

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


        ev.emit('http_headers',Number(stream_id),headers);

      }else if(frame_type==0){

        ev.emit('http_body',Number(stream_id),payload);

      }

    }

    function evict_qpack_remote_dynamic_table_if_needed(){

      var entries = context.remote_qpack_dynamic_table;
      var capacity = context.remote_qpack_table_capacity;

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

    function insert_into_qpack_remote_encoder_dynamic_table(name, value){
      var entry_size = name.length + value.length + 32;

      if (entry_size > context.remote_qpack_table_capacity) return false;

      context.remote_qpack_dynamic_table.unshift([name, value]);
      context.remote_qpack_table_base_index++;

      evict_qpack_remote_dynamic_table_if_needed();

      return true;
    }

    function process_settings_frame(payload){
      var control_settings=parse_h3_settings_frame(payload);
      //console.log(control_settings);

      if('SETTINGS_QPACK_MAX_TABLE_CAPACITY' in control_settings && control_settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY']>0){
        context.remote_qpack_max_table_capacity=control_settings['SETTINGS_QPACK_MAX_TABLE_CAPACITY'];

        evict_qpack_remote_dynamic_table_if_needed();
      }

      if('SETTINGS_MAX_FIELD_SECTION_SIZE' in control_settings && control_settings['SETTINGS_MAX_FIELD_SECTION_SIZE']>0){
        context.remote_max_header_size=control_settings['SETTINGS_MAX_FIELD_SECTION_SIZE'];
      }

      if('SETTINGS_H3_DATAGRAM' in control_settings && control_settings['SETTINGS_H3_DATAGRAM']>0){
        context.remote_datagram_support=Boolean(control_settings['SETTINGS_H3_DATAGRAM']);
      }
    }


    function stream_write(stream_id,data,fin){
      
      //console.log('stream_id: '+stream_id);
      
      if(stream_id in context.receiving_streams==false){
        context.receiving_streams[stream_id]={
          data_chunks: [],
          next_offset: 0,
          total_size: 0,
          from_offset: 0,
          type: null,
        };
      }

      context.receiving_streams[stream_id].data_chunks.push(data);
      context.receiving_streams[stream_id].next_offset=context.receiving_streams[stream_id].next_offset+data.byteLength;

      if(context.receiving_streams[stream_id].total_size==0){
        if(typeof fin=='boolean' && fin==true){
          context.receiving_streams[stream_id].total_size=context.receiving_streams[stream_id].next_offset;
        }
      }

      if(context.receiving_streams[stream_id].type==null){
        
        var is_unidirectional = (Number(stream_id) & 0x2) !== 0;
        if (is_unidirectional) {

          if (context.receiving_streams[stream_id].data_chunks.length>0 && context.receiving_streams[stream_id].data_chunks[0].byteLength > 0) {
            
            var first_byte=context.receiving_streams[stream_id].data_chunks[0][0];

            if(first_byte==0x00){
              //console.log("✅ Control Stream");
              context.receiving_streams[stream_id].type=0;
              context.receiving_streams[stream_id].from_offset=1;
            }else if(first_byte==0x01){
              //console.log("✅ Push Stream");

            }else if(first_byte==0x02){
              //console.log("✅ QPACK Encoder Stream");
              context.receiving_streams[stream_id].type=2;
              context.receiving_streams[stream_id].from_offset=1;
            }else if(first_byte==0x03){
              //console.log("✅ QPACK Decoder Stream");
              context.receiving_streams[stream_id].type=3;
              context.receiving_streams[stream_id].from_offset=1;
            }else{
              //console.log("❓ Unknown Unidirectional Stream");
            }
          }
          
        } else {
          //console.log("🔄 Bidirectional (HTTP Request/Response)");
          context.receiving_streams[stream_id].type=4;
          context.receiving_streams[stream_id].from_offset=0;
        }


      }


      var ext=null;

      if(context.receiving_streams[stream_id].type==2 || context.receiving_streams[stream_id].type==3){
        ext = extract_qpack_encoder_instructions_from_chunks(context.receiving_streams[stream_id].data_chunks,context.receiving_streams[stream_id].from_offset);
      }else{
        ext = extract_h3_frames_from_chunks(context.receiving_streams[stream_id].data_chunks,context.receiving_streams[stream_id].from_offset);

      }

      //console.log('stream '+stream_id+': -----');
      //console.log(context.receiving_streams[stream_id]);

      if(ext && context.receiving_streams[stream_id].from_offset!==ext.new_from_offset){//
        context.receiving_streams[stream_id].from_offset=ext.new_from_offset;

        

        if(context.receiving_streams[stream_id].type==0){

          for(var i in ext.frames){

            //console.log('frame:');
            //console.log(ext.frames[i]);

            if(ext.frames[i].frame_type==0x04){
              //SETTINGS
              process_settings_frame(ext.frames[i].payload);

            }else if(ext.frames[i].frame_type==0x07){
              //GOAWAY

              //TODO...
            }
          }

        }else if(context.receiving_streams[stream_id].type==2){
          
          //console.log(ext);

          process_qpack_instructions(ext.instructions);

        }else if(context.receiving_streams[stream_id].type==3){

        }else if(context.receiving_streams[stream_id].type==4){
          for(var i in ext.frames){
            process_http_frame(Number(stream_id),ext.frames[i].frame_type,ext.frames[i].payload);
          }
        }

      }
      

    }


    

    function connect(){

      if(context.local_max_header_size>0){

      }
      var settings_frame=build_settings_frame({
        SETTINGS_QPACK_MAX_TABLE_CAPACITY: context.local_qpack_max_table_capacity,
        SETTINGS_MAX_FIELD_SECTION_SIZE: context.local_max_header_size,
        SETTINGS_ENABLE_WEBTRANSPORT: context.local_datagram_support,
        SETTINGS_H3_DATAGRAM: context.local_datagram_support,
        SETTINGS_ENABLE_CONNECT_PROTOCOL: context.local_datagram_support,
        SETTINGS_WT_MAX_SESSIONS: 1
        //SETTINGS_NO_RFC9114_LEGACY_CODEPOINT: 1
      });

      var control_stream_frames=build_h3_frames([
        { frame_type: 0x04, payload: settings_frame },
      ]);
    
      ev.emit('stream',3,new Uint8Array([0x00]));
      ev.emit('stream',3,control_stream_frames);

      ev.emit('stream',7,new Uint8Array([0x02]));

      ev.emit('stream',11,new Uint8Array([0x03]));

      //console.log('sending connect()............................');

    }


    setTimeout(connect,0);


    var api = {
        on: function(name, fn){ ev.on(name, fn); },

        stream: stream_write,

        //close_wt: close_wt,

        http_header: http_header_write,
        http_body: http_body_write,

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

export default H3Socket;