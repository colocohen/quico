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

import process from 'node:process';
import dgram from 'node:dgram';
import crypto from 'node:crypto';


import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const flat_ranges = require('flat-ranges');

// ---- local modules (ESM) ----
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

import QUICSocket from './quic_socket.js';
import H3Socket from './h3_socket.js';

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



function createServer(options, handler){
  options = options || {};

  var ev = Emitter();

  var context = {
		udp4: null,
		udp6: null,
		port: null,
		_handler: handler || null,
		SNICallback: options.SNICallback || null,
		connections: {},
		address_binds: {},
		timeout: null,
  };

  

  function set_http_stream(quic_connection_id,stream_id,params){

    var is_new=false;

    if(stream_id in context.connections[quic_connection_id].http_streams==false){

      var req={
        method: null,
        path: null,
        headers: {},
        stream_id: Number(stream_id)
      };

      var res={
        statusCode: null,
        headers: {},
        headersSent: false,

        /*
        close_wt: function(){
          context.connections[quic_connection_id].h3_socket.close_wt(stream_id);
        },
        */

        writeHead: function(statusCode, headers) {
          if(res.headersSent==false){
            res.statusCode=statusCode;
            res.headers[":status"]=String(statusCode);

            if(typeof headers=='object'){
              for(var field_name in headers){
                res.headers[field_name]=headers[field_name];
              }
            }
            

            //res.headersSent=true;
          }

          context.connections[quic_connection_id].h3_socket.http_header(stream_id,res.headers);
        },
        writeEarlyHints: function (hints){
          
        },
        write: function(chunk) {
          if(typeof chunk=='string'){
            var data=new TextEncoder().encode(chunk);
            context.connections[quic_connection_id].h3_socket.http_body(Number(stream_id),data);
          }else{
            context.connections[quic_connection_id].h3_socket.http_body(Number(stream_id),chunk);
          }
        },
        end: function(chunk) {
          if(typeof chunk!=='undefined'){
            if(typeof chunk=='string'){
              var data=new TextEncoder().encode(chunk);
              context.connections[quic_connection_id].h3_socket.http_body(Number(stream_id),data,true);
            }else{
              context.connections[quic_connection_id].h3_socket.http_body(Number(stream_id),chunk,true);
            }
          }else{
            context.connections[quic_connection_id].h3_socket.http_body(Number(stream_id),null);
          }

          
        }
      };


      context.connections[quic_connection_id].http_streams[stream_id]={
        req: req,
        res: res
      };

      is_new=true;
    }

    if(typeof params == "object"){

      if('request_headers' in params){
        for(var field_name in params['request_headers']){
          context.connections[quic_connection_id].http_streams[stream_id].req.headers[field_name]=params['request_headers'][field_name];
        }
      }

      if(context.connections[quic_connection_id].http_streams[stream_id].req.method==null && ":method" in context.connections[quic_connection_id].http_streams[stream_id].req.headers==true){
        context.connections[quic_connection_id].http_streams[stream_id].req.method=context.connections[quic_connection_id].http_streams[stream_id].req.headers[':method'];
      }

      if(context.connections[quic_connection_id].http_streams[stream_id].req.path==null && ":path" in context.connections[quic_connection_id].http_streams[stream_id].req.headers==true){
        context.connections[quic_connection_id].http_streams[stream_id].req.path=context.connections[quic_connection_id].http_streams[stream_id].req.headers[':path'];
      }


      //console.log(context.connections[quic_connection_id].http_streams[stream_id]);

    }


    if(is_new==true){
      context._handler(context.connections[quic_connection_id].http_streams[stream_id].req, context.connections[quic_connection_id].http_streams[stream_id].res);
    }
    
      

  }



  function receiving_quic_packet(from_ip,from_port,data){
    var quic_connection_id=null;

		var address_str = from_ip + ':' + from_port;

    var dcid_str=null;
    if('dcid' in data && data.dcid && data.dcid.byteLength>0){
        dcid_str = Array.from(data.dcid).join("");
    }

    if(dcid_str!==null){
			if(dcid_str in context.connections==true){
				quic_connection_id=dcid_str;
			}
    }else{
			if(address_str in context.address_binds==true){
				if(context.address_binds[address_str] in context.connections==true){
					quic_connection_id=context.address_binds[address_str];
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

		if(address_str in context.address_binds==false || context.address_binds[address_str]!==quic_connection_id){
			context.address_binds[address_str]=quic_connection_id;
		}
		

    if(quic_connection_id in context.connections==false){

      context.connections[quic_connection_id]={
        quic_socket: null,
				h3_socket: null,
        http_streams: {}
      };

    }



    

    if(context.connections[quic_connection_id].quic_socket==null){

      var quic_socket=new QUICSocket({
        isServer: true,
        SNICallback: context.SNICallback
      });

			context.connections[quic_connection_id].quic_socket=quic_socket;

			quic_socket.on('packet',function(data_to_send){
				send_udp_packet(from_ip,from_port,data_to_send);
			});

			quic_socket.on('connect',function(){

				//console.log('now connected:');

				var h3_socket=new H3Socket({
					isServer: true
				});

				context.connections[quic_connection_id].h3_socket=h3_socket;

				quic_socket.on('stream',function(stream_id,data,fin){
					h3_socket.stream(stream_id,data,fin);
				});

				h3_socket.on('stream',function(stream_id,data,fin){
					quic_socket.stream(stream_id,data,fin);
				});

        h3_socket.on('http_headers',function(stream_id,headers){
          set_http_stream(quic_connection_id,stream_id,{
            request_headers: headers
          });
				});

        h3_socket.on('http_body',function(stream_id,payload){
          set_http_stream(quic_connection_id,stream_id,{
            add_request_body_chunk: payload
          });
        });

        /*
				quic_socket.on('datagram',function(context_id,data){
          //console.log(data);
					//context.connections[quic_connection_id].h3_socket.datagram(context_id,data);
				});
        */

			});
      
    }

		
    context.connections[quic_connection_id].quic_socket.packet(data);


    //...
  }



  function receiving_udp_packet(from_ip,from_port,data){
      
    var quic_packets=parse_quic_datagram(data);

    if(quic_packets.length>0){
      for(var i in quic_packets){
        if(quic_packets[i]!==null){

          receiving_quic_packet(from_ip,from_port,quic_packets[i]);

        }
      }
    }

  }

  function send_udp_packet(to_ip,to_port,data,callback){
    if(to_ip.indexOf(':')>=0){
      context.udp6.send(data, to_port, to_ip, function(error){
        if (error) {
          if(typeof callback=='function'){
						callback(false);
					}
        } else {
          if(typeof callback=='function'){
						callback(true);
					}
        }
      });
    }else{
      context.udp4.send(data, to_port, to_ip, function(error){
        if (error) {
          if(typeof callback=='function'){
						callback(false);
					}
        } else {
          if(typeof callback=='function'){
						callback(true);
					}
        }
      });
    }
  }

  function listen(port, host, callback){
    if (typeof host === 'function') {
      callback = host;
      host = null;
    }

    context.port = port || 443;
    host = host || '::';




    // יצירת סוקט UDP4
    context.udp4 = dgram.createSocket('udp4');

    context.udp4.on('message', function(message, rinfo) {
      receiving_udp_packet(rinfo.address, rinfo.port, new Uint8Array(message));
    });
    context.udp4.on('error', function(error) {
      //console.error('UDP4 error:', err);
    });

    if (host === '::' || host.indexOf('.') !== -1) {
      var host4 = host.indexOf('.') !== -1 ? host : '0.0.0.0';
      context.udp4.bind(context.port, host4);
    }




    // יצירת סוקט UDP6
    context.udp6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });

    context.udp6.on('message', function(message, rinfo) {
      receiving_udp_packet(rinfo.address, rinfo.port, new Uint8Array(message));
    });
    context.udp6.on('error', function(error) {
      //console.error('UDP6 error:', err);
    });

    var host6 = host.indexOf(':') !== -1 ? host : '::';
    context.udp6.bind(context.port, host6, function() {
      if (typeof callback === 'function') {
        callback();
      }
    });
  }

  function close(){
      
  }

  var api={
    context: context,

    on: function(name, fn){ ev.on(name, fn); },

    listen: listen,

    close: close,

    setTimeout: function(){

    },
  };

  for (var k in api) if (Object.prototype.hasOwnProperty.call(api,k)) this[k] = api[k];
  return this;
}

export { createServer };