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

var nobleHashes={
  hmac: require("@noble/hashes/hmac.js")['hmac'],
  hkdf: require("@noble/hashes/hkdf.js")['hkdf'],
  hkdf_extract: require("@noble/hashes/hkdf.js")['extract'],
  hkdf_expand: require("@noble/hashes/hkdf.js")['expand'],
  sha256: require("@noble/hashes/sha2.js")['sha256'],
};

var { p256 } = require('@noble/curves/p256');
var { x25519 } = require('@noble/curves/ed25519');
var { sha256, sha384 } = require('@noble/hashes/sha2');

var crypto = require('crypto');

var { AES } = require('@stablelib/aes');
var { GCM } = require('@stablelib/gcm');

var x509 = require('@peculiar/x509');

var {
  concatUint8Arrays,
  writeVarInt,
  readVarInt
} = require('./utils');





function get_cipher_info(cipher_suite) {
  switch (cipher_suite) {
    case 0x1301: // TLS_AES_128_GCM_SHA256
      return { keylen: 16, ivlen: 12, hash: sha256,str: 'sha256' };
    case 0x1302: // TLS_AES_256_GCM_SHA384
      return { keylen: 32, ivlen: 12, hash: sha384,str: 'sha384' };
    case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
      return { keylen: 32, ivlen: 12, hash: sha256,str: 'sha256' };
    default:
      throw new Error("Unsupported cipher suite: 0x" + cipher_suite.toString(16));
  }
}




function build_server_hello(server_random, public_key, session_id, cipher_suite, group) {
    var legacy_version = [0x03, 0x03];
    var random = Array.from(server_random);
    var session_id_bytes = Array.from(session_id);
    var session_id_length = session_id_bytes.length & 0xff;

    var cipher_suite_bytes = [(cipher_suite >> 8) & 0xff, cipher_suite & 0xff];
    var compression_method = [0x00];

    var key = Array.from(public_key);
    var key_length = [(key.length >> 8) & 0xff, key.length & 0xff];
    var group_bytes = [(group >> 8) & 0xff, group & 0xff];
    var key_exchange = [...group_bytes, ...key_length, ...key];
    var key_share_extension = (() => {
        var extension_type = [0x00, 0x33];
        var extension_length = [(key_exchange.length >> 8) & 0xff, key_exchange.length & 0xff];
        return [...extension_type, ...extension_length, ...key_exchange];
    })();

    var supported_versions_extension = [
        0x00, 0x2b,
        0x00, 0x02,
        0x03, 0x04
    ];

    var params_bytes = [
      0x00, 0x01,  0x00, 0x04,  0x00, 0x00, 0x10, 0x00, // initial_max_data = 4096
      0x00, 0x03,  0x00, 0x04,  0x00, 0x00, 0x08, 0x00  // max_packet_size = 2048
    ];

    

    var extensions = [
      ...supported_versions_extension,
      ...key_share_extension
    ];
    var extensions_length = [(extensions.length >> 8) & 0xff, extensions.length & 0xff];

    var handshake_body = [
        ...legacy_version,
        ...random,
        session_id_length,
        ...session_id_bytes,
        ...cipher_suite_bytes,
        ...compression_method,
        ...extensions_length,
        ...extensions
    ];

    var body_length = handshake_body.length;
    var handshake = [
        0x02, // handshake type: ServerHello
        (body_length >> 16) & 0xff,
        (body_length >> 8) & 0xff,
        body_length & 0xff,
        ...handshake_body
    ];

    return Uint8Array.from(handshake); // ✔️ מחזיר רק Handshake Message
}




function build_quic_ext(params) {
  var out = [];

  function addParam(id, value) {
    var id_bytes = writeVarInt(id);
    var length_bytes, value_bytes;

    if (typeof value === 'number') {
      value_bytes = writeVarInt(value);
    } else if (value instanceof Uint8Array) {
      value_bytes = Array.from(value);
    } else if (value === true) {
      value_bytes = []; // for disable_active_migration
    } else {
      throw new Error('Unsupported value type for parameter ' + id);
    }

    length_bytes = writeVarInt(value_bytes.length);
    out.push(...id_bytes, ...length_bytes, ...value_bytes);
  }

  if (params.original_destination_connection_id)
    addParam(0x00, params.original_destination_connection_id);
  if (params.max_idle_timeout)
    addParam(0x01, params.max_idle_timeout);
  if (params.stateless_reset_token)
    addParam(0x02, params.stateless_reset_token);
  if (params.max_udp_payload_size)
    addParam(0x03, params.max_udp_payload_size);
  if (params.initial_max_data)
    addParam(0x04, params.initial_max_data);
  if (params.initial_max_stream_data_bidi_local)
    addParam(0x05, params.initial_max_stream_data_bidi_local);
  if (params.initial_max_stream_data_bidi_remote)
    addParam(0x06, params.initial_max_stream_data_bidi_remote);
  if (params.initial_max_stream_data_uni)
    addParam(0x07, params.initial_max_stream_data_uni);
  if (params.initial_max_streams_bidi)
    addParam(0x08, params.initial_max_streams_bidi);
  if (params.initial_max_streams_uni)
    addParam(0x09, params.initial_max_streams_uni);
  if (params.ack_delay_exponent !== undefined)
    addParam(0x0a, params.ack_delay_exponent);
  if (params.max_ack_delay !== undefined)
    addParam(0x0b, params.max_ack_delay);
  if (params.disable_active_migration)
    addParam(0x0c, true);
  if (params.active_connection_id_limit)
    addParam(0x0e, params.active_connection_id_limit);
  if (params.initial_source_connection_id)
    addParam(0x0f, params.initial_source_connection_id);
  if (params.retry_source_connection_id)
    addParam(0x10, params.retry_source_connection_id);
  if (params.max_datagram_frame_size)
    addParam(0x20, params.max_datagram_frame_size); // אין ערך – presence בלבד
  if (params.web_accepted_origins) {
    for (var i = 0; i < params.web_accepted_origins.length; i++) {
      var origin = params.web_accepted_origins[i];
      var origin_bytes = new TextEncoder().encode(origin);
      addParam(0x2b603742, origin_bytes);
    }
  }

  return new Uint8Array(out);
}





function build_alpn_ext(protocol) {
    var proto_bytes = new TextEncoder().encode(protocol);
    var ext = new Uint8Array(2 + 1 + proto_bytes.length);
    ext[0] = 0x00;
    ext[1] = proto_bytes.length + 1;
    ext[2] = proto_bytes.length;
    ext.set(proto_bytes, 3);
    return ext;
}

function build_encrypted_extensions(extensions) {
    var ext_bytes = [];
    for (var ext of extensions) {
        ext_bytes.push((ext.type >> 8) & 0xff, ext.type & 0xff);
        ext_bytes.push((ext.data.length >> 8) & 0xff, ext.data.length & 0xff);
        ext_bytes.push(...ext.data);
    }
    var ext_len = ext_bytes.length;
    var ext_len_bytes = [(ext_len >> 8) & 0xff, ext_len & 0xff];
    var body = [...ext_len_bytes, ...ext_bytes];
    var hs_len = body.length;
    var header = [0x08, (hs_len >> 16) & 0xff, (hs_len >> 8) & 0xff, hs_len & 0xff];
    return Uint8Array.from([...header, ...body]);
}

function build_certificate(certificates) {
    var context = [0x00];
    var cert_list = [];
    for (var cert of certificates) {
        var extensions = cert.extensions instanceof Uint8Array ? cert.extensions : new Uint8Array(0);
        cert_list.push((cert.cert.length >> 16) & 0xff, (cert.cert.length >> 8) & 0xff, cert.cert.length & 0xff);
        cert_list.push(...cert.cert);
        cert_list.push((extensions.length >> 8) & 0xff, extensions.length & 0xff);
        cert_list.push(...extensions);
    }
    var total_len = cert_list.length;
    var list_len = [(total_len >> 16) & 0xff, (total_len >> 8) & 0xff, total_len & 0xff];
    var body = [...context, ...list_len, ...cert_list];
    var hs_len = body.length;
    var header = [0x0b, (hs_len >> 16) & 0xff, (hs_len >> 8) & 0xff, hs_len & 0xff];
    return Uint8Array.from([...header, ...body]);
}



function build_certificate_verify(algorithm, signature) {
    var sig_len = signature.length;
    var total_len = 4 + sig_len;
    var header = [
        0x0f,
        (total_len >> 16) & 0xff,
        (total_len >> 8) & 0xff,
        total_len & 0xff,
        (algorithm >> 8) & 0xff, algorithm & 0xff,
        (sig_len >> 8) & 0xff, sig_len & 0xff
    ];
    return Uint8Array.from([...header, ...signature]);
}

function build_finished(verify_data) {
    var length = verify_data.length;
    var header = [0x14, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff];
    return Uint8Array.from([...header, ...verify_data]);
}



function handle_client_hello(parsed) {

  
  var supported_groups = [0x001d, 0x0017]; // X25519, secp256r1
  var supported_cipher_suites = [0x1301, 0x1302];//0x1303, 

  var selected_alpn=null;
  var selected_group=null;
  var selected_cipher=null;

  var client_public_key=null;

  var server_private_key=null;
  var server_public_key=null;
  var shared_secret=null;

  for(var i in supported_cipher_suites){
    if(parsed.cipher_suites.includes(supported_cipher_suites[i])==true){
      selected_cipher=supported_cipher_suites[i];
      break;
    }
  }

  for(var i in supported_groups){
    if(selected_group==null){
      for(var i2 in parsed.key_shares){
        if(parsed.key_shares[i2].group==supported_groups[i]){
          selected_group=parsed.key_shares[i2].group;
          client_public_key=parsed.key_shares[i2].pubkey;
          break;
        }
      }
    }
  }

  

  if(selected_group!==null){

    if (selected_group === 0x001d) { // X25519
      server_private_key = crypto.randomBytes(32);
      server_public_key = x25519.getPublicKey(server_private_key);
      shared_secret = x25519.getSharedSecret(server_private_key, client_public_key);
    } else if (selected_group === 0x0017) { // secp256r1 (P-256)
      server_private_key = p256.utils.randomPrivateKey();
      server_public_key = p256.getPublicKey(server_private_key, false);
      var client_point = p256.ProjectivePoint.fromHex(client_public_key);
      var shared_point = client_point.multiply(
          BigInt('0x' + Buffer.from(server_private_key).toString('hex'))
      );
      shared_secret = shared_point.toRawBytes().slice(0, 32);
    }

  }


  return {
    selected_cipher: selected_cipher,
    selected_group: selected_group,
    client_public_key: client_public_key,
    server_private_key: new Uint8Array(server_private_key),
    server_public_key: server_public_key,
    shared_secret: shared_secret
  }


}





function parse_transport_parameters(buf, start) {
  if (!(buf instanceof Uint8Array)) throw new Error("Expect Uint8Array");
  var offset = start || 0;
  var end    = buf.length;
  var out    = {
    web_accepted_origins: []
  };

  while (offset < end) {
    // ---- מזהה הפרמטר ----
    var idVar = readVarInt(buf, offset);
    if (!idVar) throw new Error("Bad varint (id) at " + offset);
    offset += idVar.byteLength;
    var id = idVar.value;

    // ---- אורך הערך ----
    var lenVar = readVarInt(buf, offset);
    if (!lenVar) throw new Error("Bad varint (len) at " + offset);
    offset += lenVar.byteLength;
    var length = lenVar.value;

    if (offset + length > end) throw new Error("Truncated value for id " + id);
    var valueBytes = buf.slice(offset, offset + length);
    offset += length;

    // ---- פענוח לפי ID ----
    switch (id) {
      case 0x00:
        out.original_destination_connection_id = valueBytes;
        break;
      case 0x01:
        out.max_idle_timeout = readVarInt(valueBytes, 0).value;
        break;
      case 0x02:
        if (valueBytes.length !== 16) throw new Error("stateless_reset_token len≠16");
        out.stateless_reset_token = valueBytes;
        break;
      case 0x03:
        out.max_udp_payload_size = readVarInt(valueBytes, 0).value;
        break;
      case 0x04:
        out.initial_max_data = readVarInt(valueBytes, 0).value;
        break;
      case 0x05:
        out.initial_max_stream_data_bidi_local = readVarInt(valueBytes, 0).value;
        break;
      case 0x06:
        out.initial_max_stream_data_bidi_remote = readVarInt(valueBytes, 0).value;
        break;
      case 0x07:
        out.initial_max_stream_data_uni = readVarInt(valueBytes, 0).value;
        break;
      case 0x08:
        out.initial_max_streams_bidi = readVarInt(valueBytes, 0).value;
        break;
      case 0x09:
        out.initial_max_streams_uni = readVarInt(valueBytes, 0).value;
        break;
      case 0x0a:
        out.ack_delay_exponent = readVarInt(valueBytes, 0).value;
        break;
      case 0x0b:
        out.max_ack_delay = readVarInt(valueBytes, 0).value;
        break;
      case 0x0c:
        if (length !== 0) throw new Error("disable_active_migration must be zero-length");
        out.disable_active_migration = true;
        break;
      case 0x0e:
        out.active_connection_id_limit = readVarInt(valueBytes, 0).value;
        break;
      case 0x0f:
        out.initial_source_connection_id = valueBytes;
        break;
      case 0x10:
        out.retry_source_connection_id = valueBytes;
        break;
      case 0x20:
        out.max_datagram_frame_size = readVarInt(valueBytes, 0).value;
        break;
      case 0x11:
        out.server_certificate_hash = valueBytes;
        break;
      case 0x2b603742:
        var origin = new TextDecoder().decode(valueBytes);
        out.web_accepted_origins.push(origin);
        break;
      default:
        if (!out.unknown) out.unknown = [];
        out.unknown.push({ id: id, bytes: valueBytes });
    }
  }

  return out;
}




function parse_tls_message(data) {
    var view = new Uint8Array(data);
    var type = view[0];
    var length = (view[1] << 16) | (view[2] << 8) | view[3];
    var body = new Uint8Array(view.buffer, view.byteOffset + 4, length);
    return { type, length, body };
}
function parse_tls_client_hello2(body) {
  var view = new Uint8Array(body);
  var ptr = 0;

  var legacy_version = (view[ptr++] << 8) | view[ptr++];
  var random = view.slice(ptr, ptr + 32); ptr += 32;
  var session_id_len = view[ptr++];
  var session_id = view.slice(ptr, ptr + session_id_len); ptr += session_id_len;

  var cipher_suites_len = (view[ptr++] << 8) | view[ptr++];
  var cipher_suites = [];
  for (var i = 0; i < cipher_suites_len; i += 2) {
    var code = (view[ptr++] << 8) | view[ptr++];
    cipher_suites.push(code);
  }

  var compression_methods_len = view[ptr++];
  var compression_methods = view.slice(ptr, ptr + compression_methods_len); ptr += compression_methods_len;

  var extensions_len = (view[ptr++] << 8) | view[ptr++];
  var extensions = [];
  var ext_end = ptr + extensions_len;
  while (ptr < ext_end) {
    var ext_type = (view[ptr++] << 8) | view[ptr++];
    var ext_len = (view[ptr++] << 8) | view[ptr++];
    var ext_data = view.slice(ptr, ptr + ext_len); ptr += ext_len;
    extensions.push({ type: ext_type, data: ext_data });
  }

  var sni = null;
  var key_shares = [];
  var supported_versions = [];
  var supported_groups = [];
  var signature_algorithms = [];
  var alpn = [];
  var max_fragment_length = null;
  var padding = null;
  var cookie = null;
  var psk_key_exchange_modes = [];
  var pre_shared_key = null;
  var renegotiation_info = null;
  var quic_transport_parameters = {
    original: {},
    initial_max_stream_data_bidi_local: undefined,
    initial_max_data: undefined,
    initial_max_streams_bidi: undefined,
    idle_timeout: undefined,
    max_packet_size: undefined,
    ack_delay_exponent: undefined,
    max_datagram_frame_size: undefined,
    web_accepted_origins: undefined
  };

  for (var ext of extensions) {
    var ext_view = new Uint8Array(ext.data);
    if (ext.type === 0x00) {
      var name_len = (ext_view[3] << 8) | ext_view[4];
      sni = new TextDecoder().decode(ext_view.slice(5, 5 + name_len));
    }
    if (ext.type === 0x33) {
      var ptr2 = 0;
      var list_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
      var end = ptr2 + list_len;
      while (ptr2 < end) {
        var group = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
        var key_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
        var pubkey = ext_view.slice(ptr2, ptr2 + key_len);
        ptr2 += key_len;
        key_shares.push({ group, pubkey });
      }
    }
    if (ext.type === 0x2b) {
      var len = ext_view[0];
      for (var i = 1; i < 1 + len; i += 2) {
        supported_versions.push((ext_view[i] << 8) | ext_view[i + 1]);
      }
    }
    if (ext.type === 0x0a) {
      var len = (ext_view[0] << 8) | ext_view[1];
      for (var i = 2; i < 2 + len; i += 2) {
        supported_groups.push((ext_view[i] << 8) | ext_view[i + 1]);
      }
    }
    if (ext.type === 0x0d) {
      var len = (ext_view[0] << 8) | ext_view[1];
      for (var i = 2; i < 2 + len; i += 2) {
        signature_algorithms.push((ext_view[i] << 8) | ext_view[i + 1]);
      }
    }
    if (ext.type === 0x10) {
      var list_len = (ext_view[0] << 8) | ext_view[1];
      var i = 2;
      while (i < 2 + list_len) {
        var name_len = ext_view[i++];
        var proto = new TextDecoder().decode(ext_view.slice(i, i + name_len));
        alpn.push(proto);
        i += name_len;
      }
    }
    if (ext.type === 0x39) {
      var ext_data = ext.data;
      var ptr2 = 0;
      while (ptr2 < ext_data.length) {
        var idRes = readVarInt(ext_data, ptr2);
        if (!idRes) break;
        var id = idRes.value;
        ptr2 += idRes.byteLength;

        var lenRes = readVarInt(ext_data, ptr2);
        if (!lenRes) break;
        var len = lenRes.value;
        ptr2 += lenRes.byteLength;

        var value = ext_data.slice(ptr2, ptr2 + len);
        ptr2 += len;

        quic_transport_parameters.original[id] = value;

        function toNumber(bytes) {
          var n = 0;
          for (var i = 0; i < bytes.length; i++) {
            n = (n << 8) | bytes[i];
          }
          return n;
        }

        if (id === 0x00) quic_transport_parameters.original_destination_connection_id = value;
        if (id === 0x01) quic_transport_parameters.max_idle_timeout = toNumber(value);
        if (id === 0x03) quic_transport_parameters.max_packet_size = toNumber(value);
        if (id === 0x04) quic_transport_parameters.initial_max_data = toNumber(value);
        if (id === 0x05) quic_transport_parameters.initial_max_stream_data_bidi_local = toNumber(value);
        if (id === 0x08) quic_transport_parameters.initial_max_streams_bidi = toNumber(value);
        if (id === 0x0a) quic_transport_parameters.ack_delay_exponent = toNumber(value);
        if (id === 0x20) quic_transport_parameters.max_datagram_frame_size = toNumber(value);
        if (id === 0x2b603742) {
          try {
            quic_transport_parameters.web_accepted_origins = new TextDecoder().decode(value);
          } catch (e) {}
        }
      }
    }
    if (ext.type === 0x01) max_fragment_length = ext_view[0];
    if (ext.type === 0x15) padding = ext_view;
    if (ext.type === 0x002a) {
      var len = (ext_view[0] << 8) | ext_view[1];
      cookie = ext_view.slice(2, 2 + len);
    }
    if (ext.type === 0x2d) {
      var len = ext_view[0];
      for (var i = 1; i <= len; i++) {
        psk_key_exchange_modes.push(ext_view[i]);
      }
    }
    if (ext.type === 0x29) pre_shared_key = ext_view;
    if (ext.type === 0xff01) renegotiation_info = ext_view;
  }

  return {
    type: 'client_hello',
    legacy_version,
    random,
    session_id,
    cipher_suites,
    compression_methods,
    extensions,
    sni,
    key_shares,
    supported_versions,
    supported_groups,
    signature_algorithms,
    alpn,
    max_fragment_length,
    padding,
    cookie,
    psk_key_exchange_modes,
    pre_shared_key,
    renegotiation_info,
    quic_transport_parameters
  };
}



function parse_tls_client_hello(body) {
    var view = new Uint8Array(body);
    var ptr = 0;

    var legacy_version = (view[ptr++] << 8) | view[ptr++];
    var random = view.slice(ptr, ptr + 32); ptr += 32;
    var session_id_len = view[ptr++];
    var session_id = view.slice(ptr, ptr + session_id_len); ptr += session_id_len;

    var cipher_suites_len = (view[ptr++] << 8) | view[ptr++];
    var cipher_suites = [];
    for (var i = 0; i < cipher_suites_len; i += 2) {
        var code = (view[ptr++] << 8) | view[ptr++];
        cipher_suites.push(code);
    }

    var compression_methods_len = view[ptr++];
    var compression_methods = view.slice(ptr, ptr + compression_methods_len); ptr += compression_methods_len;

    var extensions_len = (view[ptr++] << 8) | view[ptr++];
    var extensions = [];
    var ext_end = ptr + extensions_len;
    while (ptr < ext_end) {
        var ext_type = (view[ptr++] << 8) | view[ptr++];
        var ext_len = (view[ptr++] << 8) | view[ptr++];
        var ext_data = view.slice(ptr, ptr + ext_len); ptr += ext_len;
        extensions.push({ type: ext_type, data: ext_data });
    }

    var sni = null;
    var key_shares = [];
    var supported_versions = [];
    var supported_groups = [];
    var signature_algorithms = [];
    var alpn = [];
    var max_fragment_length = null;
    var padding = null;
    var cookie = null;
    var psk_key_exchange_modes = [];
    var pre_shared_key = null;
    var renegotiation_info = null;
    var quic_transport_parameters_raw = null;

    for (var ext of extensions) {
      var ext_view = new Uint8Array(ext.data);
      if (ext.type === 0x00) { // SNI
          var list_len = (ext_view[0] << 8) | ext_view[1];
          var name_type = ext_view[2];
          var name_len = (ext_view[3] << 8) | ext_view[4];
          var name = new TextDecoder().decode(ext_view.slice(5, 5 + name_len));
          sni = name;
      }
      if (ext.type === 0x33) {
          var ptr2 = 0;
          var list_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
          var end = ptr2 + list_len;
          while (ptr2 < end) {
              var group = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
              var key_len = (ext_view[ptr2++] << 8) | ext_view[ptr2++];
              var pubkey = ext_view.slice(ptr2, ptr2 + key_len);
              ptr2 += key_len;
              key_shares.push({ group, pubkey });
          }
      
      }
      if (ext.type === 0x2b) { // supported_versions
          var len = ext_view[0];
          for (var i = 1; i < 1 + len; i += 2) {
              var ver = (ext_view[i] << 8) | ext_view[i + 1];
              supported_versions.push(ver);
          }
      }
      if (ext.type === 0x0a) { // supported_groups
          var len = (ext_view[0] << 8) | ext_view[1];
          for (var i = 2; i < 2 + len; i += 2) {
              supported_groups.push((ext_view[i] << 8) | ext_view[i + 1]);
          }
      }
      if (ext.type === 0x0d) { // signature_algorithms
          var len = (ext_view[0] << 8) | ext_view[1];
          for (var i = 2; i < 2 + len; i += 2) {
              signature_algorithms.push((ext_view[i] << 8) | ext_view[i + 1]);
          }
      }
      if (ext.type === 0x10) { // ALPN
          var list_len = (ext_view[0] << 8) | ext_view[1];
          var i = 2;
          while (i < 2 + list_len) {
              var name_len = ext_view[i++];
              var proto = new TextDecoder().decode(ext_view.slice(i, i + name_len));
              alpn.push(proto);
              i += name_len;
          }
      }
      if (ext.type === 0x39) { // quic_transport_parameters
        quic_transport_parameters_raw = ext.data;
      }
      if (ext.type === 0x01) { // Max Fragment Length
          max_fragment_length = ext_view[0];
      }
      if (ext.type === 0x15) { // Padding
          padding = ext_view;
      }
      if (ext.type === 0x002a) { // Cookie
          var len = (ext_view[0] << 8) | ext_view[1];
          cookie = ext_view.slice(2, 2 + len);
      }
      if (ext.type === 0x2d) { // PSK Key Exchange Modes
          var len = ext_view[0];
          for (var i = 1; i <= len; i++) {
              psk_key_exchange_modes.push(ext_view[i]);
          }
      }
      if (ext.type === 0x29) { // PreSharedKey (placeholder)
          pre_shared_key = ext_view;
      }
      if (ext.type === 0xff01) { // Renegotiation Info
          renegotiation_info = ext_view;
      }
    }

    return {
        type: 'client_hello',
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
        sni,
        key_shares,
        supported_versions,
        supported_groups,
        signature_algorithms,
        alpn,
        max_fragment_length,
        padding,
        cookie,
        psk_key_exchange_modes,
        pre_shared_key,
        renegotiation_info,
        quic_transport_parameters_raw
    };
}

////////////////////////////////
		
function hmac(hash, key, data) {
    return new Uint8Array(crypto.createHmac(hash, key).update(data).digest());
}
function hkdf_extract(salt, ikm, hash_func) {
  return nobleHashes.hkdf_extract(hash_func, ikm, salt);
}


function hkdf_expand(prk, info, length, hash_func) {
  return nobleHashes.hkdf_expand(hash_func, prk, info, length);
}



function build_hkdf_label(label, context, length) {
  const prefix = "tls13 ";
  const full = new TextEncoder().encode(prefix + label);

  const info = new Uint8Array(
      2 + 1 + full.length + 1 + context.length);

  // length (2-bytes, BE)
  info[0] = (length >> 8) & 0xff;
  info[1] =  length       & 0xff;

  // label length + bytes
  info[2] = full.length;
  info.set(full, 3);

  // context length + bytes
  const ctxOfs = 3 + full.length;
  info[ctxOfs] = context.length;
  info.set(context, ctxOfs + 1);

  return info;
}

function hkdf_expand_label(secret, label, context, length, hash_func) {
  const info = build_hkdf_label(label, context, length);
  return hkdf_expand(secret, info, length, hash_func);   // hash = sha384/sha256
}


function hash_transcript(messages,hash_func) {
    var total_len = messages.reduce((sum, m) => sum + m.length, 0);
    var total = new Uint8Array(total_len);
    var offset = 0;
    for (var m of messages) {
        total.set(m, offset);
        offset += m.length;
    }
    return hash_func(total);
}

function tls_derive_app_secrets(handshake_secret, transcript, hash_func) {
  const hashLen = hash_func.outputLen;
  const empty = new Uint8Array(0);
  var zero = new Uint8Array(hash_func.outputLen);

  var derived_secret = hkdf_expand_label(handshake_secret, "derived", hash_func(empty), hash_func.outputLen, hash_func);
  var master_secret = hkdf_extract(derived_secret, zero, hash_func);

  // שלב 3: חישוב hash של ה־transcript עד server Finished
  const transcript_hash = hash_transcript(transcript, hash_func);

  // שלב 4: גזירת סודות התעבורה
  const client_app = hkdf_expand_label(master_secret, 'c ap traffic', transcript_hash, hashLen, hash_func);
  const server_app = hkdf_expand_label(master_secret, 's ap traffic', transcript_hash, hashLen, hash_func);

  return {
    client_application_traffic_secret: client_app,
    server_application_traffic_secret: server_app
  };
}


function tls_derive_handshake_secrets(shared_secret, transcript, hash_func) {
  var zero = new Uint8Array(hash_func.outputLen);
  var empty = new Uint8Array();

  var early_secret = hkdf_extract(empty, zero, hash_func); // salt, ikm
  var derived_secret = hkdf_expand_label(early_secret, "derived", hash_func(empty), hash_func.outputLen, hash_func);
  var handshake_secret = hkdf_extract(derived_secret, shared_secret, hash_func);

  var transcript_hash = hash_transcript(transcript, hash_func);

  var client_hts = hkdf_expand_label(handshake_secret, "c hs traffic", transcript_hash, hash_func.outputLen, hash_func);
  var server_hts = hkdf_expand_label(handshake_secret, "s hs traffic", transcript_hash, hash_func.outputLen, hash_func);

  return {
    handshake_secret,
    client_handshake_traffic_secret: client_hts,
    server_handshake_traffic_secret: server_hts,
    transcript_hash
  };
}

function aead_decrypt(key, iv, packetNumber, ciphertextWithTag, aad, callback) {
  try {
    // יצירת nonce לפי QUIC (IV XOR packetNumber)
    var nonce = new Uint8Array(iv.length);
    for (var i = 0; i < iv.length; i++) {
      var pnIndex = iv.length - 1 - i;
      var pnByte = (packetNumber >>> (8 * i)) & 0xff;
      nonce[pnIndex] = iv[pnIndex] ^ pnByte;
    }

    var tag = ciphertextWithTag.slice(-16);
    var ciphertext = ciphertextWithTag.slice(0, -16);

    var algo = key.length === 32 ? 'aes-256-gcm' :
               key.length === 16 ? 'aes-128-gcm' :
               (() => { throw new Error("Unsupported key length: " + key.length); })();

    const decipher = crypto.createDecipheriv(algo, key, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(aad);

    const decrypted = decipher.update(ciphertext);
    decipher.final();

    callback(null, decrypted);
  } catch (e) {
    callback(e);
  }
}
		
function aes_gcm_decrypt(ciphertext, tag, key, nonce, aad) {
  try {
    var algo = key.length === 32 ? 'aes-256-gcm' :
                key.length === 16 ? 'aes-128-gcm' :
                (() => { throw new Error("Unsupported key length: " + key.length); })();

    var decipher = crypto.createDecipheriv(
      algo,
      Buffer.from(key),
      Buffer.from(nonce)
    );

    decipher.setAuthTag(Buffer.from(tag));
    decipher.setAAD(Buffer.from(aad));

    var decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertext)),
      decipher.final()
    ]);

    //console.log("✅ Decryption success!");
    return new Uint8Array(decrypted);
  } catch (e) {
      return null;
  }
}

const INITIAL_SALTS = {
    // QUIC v1 (RFC 9001)
    0x00000001: new Uint8Array([
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
    ]),

    // QUIC draft-29 (HTTP/3 version h3-29)
    0xff00001d: new Uint8Array([
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
    0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99
    ]),

    // QUIC draft-32 (h3-32)
    0xff000020: new Uint8Array([
    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0x77,
    0x7b, 0xe3, 0x0e, 0xbd, 0x5f, 0xa5, 0x15, 0x87,
    0x3d, 0x8d, 0x6e, 0x67
    ]),

    // Google QUIC v50 ("Q050") — נדיר יותר אבל נתמך בדפדפנים מסוימים
    0x51303530: new Uint8Array([
    0x69, 0x45, 0x6f, 0xbe, 0xf1, 0x6e, 0xd7, 0xdc,
    0x48, 0x15, 0x9d, 0x98, 0xd0, 0x7f, 0x5c, 0x3c,
    0x3d, 0x5a, 0xa7, 0x0a
    ])
};

function quic_derive_init_secrets(client_dcid, version, direction) {
    const hash_func = sha256;
    //console.log(version);
    const salt = INITIAL_SALTS[version] || null;
    if (!salt) throw new Error("Unsupported QUIC version: 0x" + version.toString(16));

    const label = direction === 'read' ? 'client in' : 'server in';
    const initial_secret = hkdf_extract(salt, client_dcid, hash_func);

    const initial_secret2 = hkdf_expand_label(
        initial_secret,
        label,
        new Uint8Array(0),
        32,
        hash_func
    );

    const key = hkdf_expand_label(initial_secret2, 'quic key', new Uint8Array(0), 16, hash_func);  // AES-128-GCM
    const iv  = hkdf_expand_label(initial_secret2, 'quic iv', new Uint8Array(0), 12, hash_func);
    const hp  = hkdf_expand_label(initial_secret2, 'quic hp', new Uint8Array(0), 16, hash_func);

    return { key, iv, hp };
}


function quic_derive_from_tls_secrets(traffic_secret, hash_func = sha256) {
    if(traffic_secret){
    const key = hkdf_expand_label(traffic_secret, 'quic key', new Uint8Array(0), 16, hash_func);
    const iv  = hkdf_expand_label(traffic_secret, 'quic iv', new Uint8Array(0), 12, hash_func);
    const hp  = hkdf_expand_label(traffic_secret, 'quic hp', new Uint8Array(0), 16, hash_func);

    return { key, iv, hp };
    }
}



function compute_nonce(iv, packetNumber) {
    const nonce = new Uint8Array(iv); // עותק של ה־IV המקורי (12 בתים)
    const pnBuffer = new Uint8Array(12); // 12 בתים, מיושר לימין

    // הכנס את packetNumber לימין של pnBuffer
    let n = packetNumber;
    for (let i = 11; n > 0 && i >= 0; i--) {
        pnBuffer[i] = n & 0xff;
        n >>= 8;
    }

    // בצע XOR בין ה־IV לבין pnBuffer
    for (let i = 0; i < 12; i++) {
        nonce[i] ^= pnBuffer[i];
    }

    return nonce;
}


function aes_ecb_encrypt(keyBytes, plaintext) {
  if (keyBytes.length !== 16 && keyBytes.length !== 24 && keyBytes.length !== 32) {
    throw new Error("Invalid AES key size");
  }

  if (plaintext.length % 16 !== 0) {
    throw new Error("Plaintext must be a multiple of 16 bytes");
  }

  const cipher = crypto.createCipheriv('aes-' + (keyBytes.length * 8) + '-ecb', keyBytes, null);
  cipher.setAutoPadding(false);

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return new Uint8Array(encrypted);
}


function aead_encrypt(key, iv, packetNumber, plaintext, aad) {
  try {
    const algo = key.length === 32 ? 'aes-256-gcm' :
                 key.length === 16 ? 'aes-128-gcm' :
                 (() => { throw new Error("Unsupported key length: " + key.length); })();

    const nonce = compute_nonce(iv, packetNumber);

    const cipher = crypto.createCipheriv(algo, Buffer.from(key), Buffer.from(nonce));
    cipher.setAAD(Buffer.from(aad));

    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(plaintext)),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    const result = new Uint8Array(encrypted.length + tag.length);
    result.set(encrypted, 0);
    result.set(tag, encrypted.length);

    return result;

  } catch (e) {
    return null;
  }
}




function apply_header_protection(packet, pnOffset, hpKey, pnLength) {
  var sample = packet.slice(pnOffset + 4, pnOffset + 4 + 16);
  if (sample.length < 16) throw new Error("Not enough bytes for header protection sample");

  var maskFull = aes_ecb_encrypt(hpKey, sample);
  var mask = maskFull.slice(0, 5);

  var firstByte = packet[0];
  var isLongHeader = (firstByte & 0x80) !== 0;

  if (isLongHeader) {
    packet[0] ^= (mask[0] & 0x0f); // רק 4 ביטים אחרונים
  } else {
    packet[0] ^= (mask[0] & 0x1f); // ל־Short Header
  }

  for (var i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }

  return packet;
}




function aes128ecb(sample,hpKey) {
    const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(hpKey), null);
    cipher.setAutoPadding(false);
    const input = Buffer.from(sample);
    return new Uint8Array(Buffer.concat([cipher.update(input), cipher.final()]));
}

function expandPacketNumber(truncated, pnLen, largestReceived) {
  var pnWin  = 1 << (pnLen * 8);
  var pnHalf = pnWin >>> 1;
  var expected = largestReceived + 1;
  return truncated + pnWin * Math.floor((expected - truncated + pnHalf) / pnWin);
}

function decode_packet_number(array, offset, pnLength) {
  let value = 0;
  for (let i = 0; i < pnLength; i++) {
    value = (value << 8) | array[offset + i];
  }
  return value;
}

function decode_and_expand_packet_number(array, offset, pnLength, largestReceived) {
  var truncated = decode_packet_number(array, offset, pnLength);
  return expandPacketNumber(truncated, pnLength, largestReceived);
}

function remove_header_protection(array, pnOffset, hpKey, isShort) {
  // Step 1: קח sample של 16 בתים מתוך ה־payload אחרי pnOffset + 4
  var sampleOffset = pnOffset + 4;
  var sample = array.slice(sampleOffset, sampleOffset + 16);

  var mask = aes128ecb(sample, hpKey).slice(0, 5); // ECB with no IV

  // Step 2: הסר הגנה מה־first byte
  var firstByte = array[0];

  if (isShort) {
    // Short Header: רק 5 הביטים הנמוכים מוצפנים
    array[0] ^= mask[0] & 0x1f;
  } else {
    // Long Header: רק 4 הביטים הנמוכים מוצפנים
    array[0] ^= mask[0] & 0x0f;
  }

  // Step 3: הסר הגנה מה־packet number (pnLength נקבע מתוך הביטים עכשיו)
  var pnLength = (array[0] & 0x03) + 1;

  for (var i = 0; i < pnLength; i++) {
    array[pnOffset + i] ^= mask[1 + i];
  }

  return pnLength;
}


function decrypt_quic_packet(array, read_key, read_iv, read_hp, dcid, largest_pn) {
  if (!(array instanceof Uint8Array)) throw new Error("Invalid input");

  const firstByte = array[0];
  const isShort = (firstByte & 0x80) === 0;
  const isLong = !isShort;

  let keyPhase = false;
  let pnOffset = 0;
  let pnLength = 0;
  let aad = null;
  let ciphertext = null;
  let tag = null;
  let packetNumber = null;
  let nonce = null;

  if (isLong) {
    // ---------- ניתוח Long Header ----------
    const view = new DataView(array.buffer, array.byteOffset, array.byteLength);
    const version = view.getUint32(1);
    const dcidLen = array[5];

    let offset = 6;
    const parsed_dcid = array.slice(offset, offset + dcidLen);
    offset += dcidLen;

    const scidLen = array[offset++];
    const scid = array.slice(offset, offset + scidLen);
    offset += scidLen;

    const typeBits = (firstByte & 0x30) >> 4;
    const typeMap = ['initial', '0rtt', 'handshake', 'retry'];
    const packetType = typeMap[typeBits];

    if (packetType === 'initial') {
      const tokenLen = readVarInt(array, offset);
      offset += tokenLen.byteLength + tokenLen.value;
    }

    const len = readVarInt(array, offset);
    offset += len.byteLength;

    pnOffset = offset;

    // הסרת הגנת כותרת
    pnLength = remove_header_protection(array, pnOffset, read_hp, false);

    if(pnLength!==null){
      packetNumber = decode_and_expand_packet_number(array, pnOffset, pnLength, largest_pn);
      nonce = compute_nonce(read_iv, packetNumber);

      const payloadStart = pnOffset + pnLength;
      const payloadLength = len.value - pnLength;
      const payloadEnd = payloadStart + payloadLength;

      if (payloadEnd > array.length) throw new Error("Truncated long header packet");

      const payload = array.slice(payloadStart, payloadEnd);
      if (payload.length < 16) throw new Error("Encrypted payload too short");

      ciphertext = payload.slice(0, payload.length - 16);
      tag = payload.slice(payload.length - 16);
      aad = array.slice(0, pnOffset + pnLength);
    }else{
      return null;
    }

  } else {
    // ---------- ניתוח Short Header ----------
    // פורמט: 1 byte header + DCID + Packet Number + Payload

    const dcidLen = dcid.length;
    pnOffset = 1 + dcidLen;

    // הסרת הגנת כותרת
    pnLength = remove_header_protection(array, pnOffset, read_hp, true);

    if(pnLength!==null){
      keyPhase = Boolean((array[0] & 0x04) >>> 2);

      packetNumber = decode_and_expand_packet_number(array, pnOffset, pnLength, largest_pn);
      nonce = compute_nonce(read_iv, packetNumber);

      const payloadStart = pnOffset + pnLength;
      const payload = array.slice(payloadStart);
      if (payload.length < 16) throw new Error("Encrypted payload too short");

      ciphertext = payload.slice(0, payload.length - 16);
      tag = payload.slice(payload.length - 16);
      aad = array.slice(0, pnOffset + pnLength);
    }else{
      return null;
    }
    
  }

  const plaintext = aes_gcm_decrypt(ciphertext, tag, read_key, nonce, aad);

  return {
    packet_number: packetNumber,
    key_phase: keyPhase,
    plaintext
  };
}



function extract_tls_messages_from_chunks(chunks, from_offset) {
  var offset = from_offset;
  var buffers = [];

  // מאחדים רצף שלם של chunks מה־offset הנוכחי
  while (chunks[offset]) {
    buffers.push(chunks[offset]);
    offset += chunks[offset].length;
  }

  // אם לא קיבלנו שום דבר – נחזיר ריק
  if (buffers.length === 0) return [];

  var combined = concatUint8Arrays(buffers);
  var tls_messages = [];
  var i = 0;

  while (i + 4 <= combined.length) {
    var msgType = combined[i];
    var length = (combined[i + 1] << 16) | (combined[i + 2] << 8) | combined[i + 3];

    if (i + 4 + length > combined.length) break; // הודעה לא שלמה – עוצרים

    var msg = combined.slice(i, i + 4 + length);
    tls_messages.push(msg);
    i += 4 + length;
  }

  // עדכון offset רק עד איפה שעברנו בפועל
  if (i > 0) {
    // מוחקים את החלקים המאוחדים מתוך chunks
    var cleanupOffset = from_offset;
    while (cleanupOffset < from_offset + i) {
      var chunk = chunks[cleanupOffset];
      delete chunks[cleanupOffset];
      cleanupOffset += chunk.length;
    }

    // השארית – אם קיימת – נחזיר אותה כ־chunk חדש
    if (i < combined.length) {
      var leftover = combined.slice(i);
      chunks[cleanupOffset] = leftover;
    }

    // נעדכן את currentOffset
    from_offset += i;
  }

  return {tls_messages,new_from_offset: from_offset};
}



function encode_version(version) {
  return new Uint8Array([
    (version >>> 24) & 0xff,
    (version >>> 16) & 0xff,
    (version >>> 8) & 0xff,
    version & 0xff
  ]);
}

function build_quic_header(packetType, dcid, scid, token, lengthField, pnLen) {
  var hdr = [];
  var firstByte;

  // שלב 1: הגדרת הביט הראשון לפי סוג הפאקט
  if (packetType === 'initial') {
    firstByte = 0xC0 | ((pnLen - 1) & 0x03);  // Long Header, Initial
  } else if (packetType === 'handshake') {
    firstByte = 0xE0 | ((pnLen - 1) & 0x03);  // Long Header, Handshake
  } else if (packetType === '0rtt') {
    firstByte = 0xD0 | ((pnLen - 1) & 0x03);  // Long Header, 0-RTT
  } else if (packetType === '1rtt') {
    firstByte = 0x40 | ((pnLen - 1) & 0x03);  // Short Header
    hdr.push(Uint8Array.of(firstByte));
    hdr.push(dcid); // ב־short header, זהו ה־Destination CID בלבד
    return {
      header: concatUint8Arrays(hdr),
      packetNumberOffset: hdr.reduce((sum, u8) => sum + u8.length, 0)
    };
  } else {
    throw new Error('Unsupported packet type: ' + packetType);
  }

  // שלב 2: Header בסיסי לכל long header
  hdr.push(Uint8Array.of(firstByte));
  hdr.push(encode_version(0x00000001)); // גרסה (4 בייטים)
  hdr.push(writeVarInt(dcid.length), dcid);
  hdr.push(writeVarInt(scid.length), scid);

  // שלב 3: רק ל־Initial מוסיפים טוקן
  if (packetType === 'initial') {
    if (!token) token = new Uint8Array(0);
    hdr.push(writeVarInt(token.length), token);
  }

  // שלב 4: שדה אורך (Length), חובה
  hdr.push(lengthField);

  // שלב 5: חישוב נקודת התחלה של packet number (מופיע מיד לאחר header)
  var header = concatUint8Arrays(hdr);
  return {
    header: header,
    packetNumberOffset: header.length
  };
}



function encrypt_quic_packet(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token) {
  var pnLength;
  if (packetNumber <= 0xff) pnLength = 1;
  else if (packetNumber <= 0xffff) pnLength = 2;
  else if (packetNumber <= 0xffffff) pnLength = 3;
  else pnLength = 4;

  var pnFull = new Uint8Array(4);
  pnFull[0] = (packetNumber >>> 24) & 0xff;
  pnFull[1] = (packetNumber >>> 16) & 0xff;
  pnFull[2] = (packetNumber >>> 8) & 0xff;
  pnFull[3] = packetNumber & 0xff;
  var packetNumberField = pnFull.slice(4 - pnLength);

  var unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
  var lengthField = writeVarInt(unprotectedPayloadLength);
  var headerInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength);

  var header = headerInfo.header;
  var packetNumberOffset = headerInfo.packetNumberOffset;

  // בונים AAD
  var fullHeader = concatUint8Arrays([header, packetNumberField]);

  // ✨ הוספת padding אם צריך כדי לאפשר sample
  var minSampleLength = 32; // או 32 ל־ChaCha20
  var minTotalLength = packetNumberOffset + pnLength + minSampleLength;
  var fullLength = header.length + pnLength + encodedFrames.length + 16; // 16 = GCM tag

  if (fullLength < minTotalLength) {
    var extraPadding = minTotalLength - (header.length + pnLength + encodedFrames.length);
    var padded = new Uint8Array(encodedFrames.length + extraPadding);
    padded.set(encodedFrames, 0);
    encodedFrames = padded;
    // חשוב! גם unprotectedPayloadLength צריך להתעדכן
    unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
    lengthField = writeVarInt(unprotectedPayloadLength);
    headerInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength);
    header = headerInfo.header;
    packetNumberOffset = headerInfo.packetNumberOffset;
    fullHeader = concatUint8Arrays([header, packetNumberField]);
  }

  var ciphertext = aead_encrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);
  if (ciphertext == null) return null;

  var fullPacket = concatUint8Arrays([
    header,
    packetNumberField,
    ciphertext
  ]);

  return apply_header_protection(fullPacket, packetNumberOffset, writeHp, pnLength);
}

function encrypt_quic_packet2(packetType, encodedFrames, writeKey, writeIv, writeHp, packetNumber, dcid, scid, token) {

  // 2. קביעת אורך packet number
  var pnLength;
  if (packetNumber <= 0xff) pnLength = 1;
  else if (packetNumber <= 0xffff) pnLength = 2;
  else if (packetNumber <= 0xffffff) pnLength = 3;
  else pnLength = 4;

  // 3. חיתוך שדה ה־packet number לבתים
  var pnFull = new Uint8Array(4);
  pnFull[0] = (packetNumber >>> 24) & 0xff;
  pnFull[1] = (packetNumber >>> 16) & 0xff;
  pnFull[2] = (packetNumber >>> 8) & 0xff;
  pnFull[3] = packetNumber & 0xff;
  var packetNumberField = pnFull.slice(4 - pnLength);

  // 4. נבנה header בלי packet number

	var unprotectedPayloadLength = encodedFrames.length + pnLength + 16;
	var lengthField = writeVarInt(unprotectedPayloadLength);
	var headerInfo = build_quic_header(packetType, dcid, scid, token, lengthField, pnLength);

  var header = headerInfo.header; // עד לפני packet number
  var packetNumberOffset = headerInfo.packetNumberOffset;

  // 5. AAD כולל את header + packet number (לפני ההצפנה)
  var fullHeader = concatUint8Arrays([header, packetNumberField]);

  // 6. הצפנת המטען
  var ciphertext = aead_encrypt(writeKey, writeIv, packetNumber, encodedFrames, fullHeader);
  if (ciphertext == null) return null;

  // 7. בניית הפקט המלא לפני header protection
  var fullPacket = concatUint8Arrays([
    header,
    packetNumberField,
    ciphertext
  ]);

  // 8. החלת הגנת כותרת (XOR)
  return apply_header_protection(fullPacket, packetNumberOffset, writeHp, pnLength);
}




function encode_quic_frames(frames) {
  var parts = [];
  var i;

  for (i = 0; i < frames.length; i++) {
    var frame = frames[i];

    if (frame.type === 'padding') {
      var pad = new Uint8Array(frame.length);
      for (var j = 0; j < pad.length; j++) pad[j] = 0x00;
      parts.push(pad);

    } else if (frame.type === 'ping') {
      parts.push(new Uint8Array([0x01]));

    } else if (frame.type === 'ack') {
      var hasECN = frame.ecn !== null && frame.ecn !== undefined;
      var typeByte = hasECN ? 0x03 : 0x02;

      var b1 = writeVarInt(frame.largest);           // Largest Acknowledged
      var b2 = writeVarInt(frame.delay);             // ACK Delay
      var b3 = writeVarInt(frame.ranges.length); // ACK Range Count
      var b4 = writeVarInt(frame.firstRange != null ? frame.firstRange : 0);

      var temp = [new Uint8Array([typeByte]), b1, b2, b3, b4];

      
      for (j = 0; j < frame.ranges.length; j++) {
        var gap = writeVarInt(frame.ranges[j].gap);     // Gap to next range
        var len = writeVarInt(frame.ranges[j].length);  // Length of next range
        temp.push(gap, len);
      }

      if (hasECN) {
        temp.push(
        writeVarInt(frame.ecn.ect0),
        writeVarInt(frame.ecn.ect1),
        writeVarInt(frame.ecn.ce)
        );
      }

      parts.push(concatUint8Arrays(temp));

    } else if (frame.type === 'reset_stream') {
      var id = writeVarInt(frame.id);
      var err = new Uint8Array([frame.error >> 8, frame.error & 0xff]);
      var size = writeVarInt(frame.finalSize);
      parts.push(concatUint8Arrays([
        new Uint8Array([0x04]), id, err, size
      ]));

    } else if (frame.type === 'stop_sending') {
      var id = writeVarInt(frame.id);
      var err = new Uint8Array([frame.error >> 8, frame.error & 0xff]);
      parts.push(concatUint8Arrays([
        new Uint8Array([0x05]), id, err
      ]));

    } else if (frame.type === 'crypto') {
      var off = writeVarInt(frame.offset);
      var len = writeVarInt(frame.data.length);
      parts.push(concatUint8Arrays([
        new Uint8Array([0x06]), off, len, frame.data
      ]));

    } else if (frame.type === 'new_token') {
      var len = writeVarInt(frame.token.length);
      parts.push(concatUint8Arrays([
        new Uint8Array([0x07]), len, frame.token
      ]));

    } else if (frame.type === 'stream') {

      var typeByte = 0x08;

      var hasOffset = (frame.offset != null);
      var hasLen = (frame.data && frame.data.length > 0);
      var hasFin = !!frame.fin;

      if (hasOffset) typeByte |= 0x04;
      if (hasLen) typeByte |= 0x02;
      if (hasFin) typeByte |= 0x01;

      var id  = writeVarInt(frame.id);
      var off = hasOffset ? writeVarInt(frame.offset) : new Uint8Array(0);
      var len = hasLen ? writeVarInt(frame.data.length) : new Uint8Array(0);

      parts.push(concatUint8Arrays([
        new Uint8Array([typeByte]), id, off, len, frame.data
      ]));

    } else if (frame.type === 'max_data') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x09]), writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'max_stream_data') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x0a]), writeVarInt(frame.id), writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'max_streams_bidi' || frame.type === 'max_streams_uni') {
      var code = frame.type === 'max_streams_bidi' ? 0x0b : 0x0c;
      parts.push(concatUint8Arrays([
        new Uint8Array([code]), writeVarInt(frame.max)
      ]));

    } else if (frame.type === 'data_blocked') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x0d]), writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'stream_data_blocked') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x0e]), writeVarInt(frame.id), writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'streams_blocked_bidi') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x0f]), writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'streams_blocked_uni') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x10]), writeVarInt(frame.limit)
      ]));

    } else if (frame.type === 'new_connection_id') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x11]),
        writeVarInt(frame.seq),
        writeVarInt(frame.retire),
        new Uint8Array([frame.connId.length]),
        frame.connId,
        frame.token
      ]));

    } else if (frame.type === 'retire_connection_id') {
      parts.push(concatUint8Arrays([
        new Uint8Array([0x12]),
        writeVarInt(frame.seq)
      ]));

    } else if (frame.type === 'path_challenge' || frame.type === 'path_response') {
      var code = frame.type === 'path_challenge' ? 0x13 : 0x14;
      parts.push(concatUint8Arrays([
        new Uint8Array([code]), frame.data
      ]));

    } else if (frame.type === 'connection_close') {
      var code = frame.application ? 0x1d : 0x1c;
      var err = new Uint8Array([frame.error >> 8, frame.error & 0xff]);
      var ft = frame.application ? new Uint8Array(0) : writeVarInt(frame.frameType);
      var reason = new TextEncoder().encode(frame.reason || "");
      var reasonLen = writeVarInt(reason.length);
      parts.push(concatUint8Arrays([
        new Uint8Array([code]), err, ft, reasonLen, reason
      ]));

    } else if (frame.type === 'handshake_done') {
      parts.push(new Uint8Array([0x1e]));

    } else if (frame.type === 'datagram') {
      var firstByte;
      var prefixBytes;
      var payload = frame.data;

      if (frame.contextId != null) {
        // אם יש contextId — משתמשים ב־0x31 לפי תקן QUIC
        firstByte = 0x31;
        var contextBytes = writeVarInt(frame.contextId);
        prefixBytes = concatUint8Arrays([
          new Uint8Array([firstByte]),
          contextBytes
        ]);
      } else {
        // אם אין contextId — שולחים כ־0x30 לפי תקן QUIC
        firstByte = 0x30;
        prefixBytes = new Uint8Array([firstByte]);
        // payload נשאר כמו שהוא — לא מוסיפים streamId!
      }

      parts.push(concatUint8Arrays([
        prefixBytes,
        payload
      ]));
    } else {
      // פריים לא ידוע – נתעלם או אפשר להתריע בלוג
      //console.warn('Unsupported frame type:', frame.type);
    }
  }

  if(parts.length==1){
    return parts[0];
  }else{
    return concatUint8Arrays(parts);
  }
  
}





function parse_quic_frames(buf) {
  let offset = 0;
  const frames = [];
  const textDecoder = new TextDecoder();

  function safeReadVarInt() {
    if (offset >= buf.length) return null;
    const res = readVarInt(buf, offset);
    if (!res || typeof res.byteLength !== 'number') return null;
    offset += res.byteLength;
    return res;
  }

  while (offset < buf.length) {
    const start = offset;
    let type = buf[offset++];

    if (type >= 0x80) {
      offset--; // backtrack and read full varint
      const t = safeReadVarInt();
      if (!t) break;
      type = t.value;
    }

    if (type === 0x00) {
      // padding

    } else if (type === 0x01) {
      frames.push({ type: 'ping' });

    } else if ((type & 0xfe) === 0x02) {
      const hasECN = (type & 0x01) === 0x01;
      const largest = safeReadVarInt(); if (!largest) break;
      const delay = safeReadVarInt(); if (!delay) break;
      const rangeCount = safeReadVarInt(); if (!rangeCount) break;
      const firstRange = safeReadVarInt(); if (!firstRange) break;

      const ranges = [];
      for (let i = 0; i < rangeCount.value; i++) {
        const gap = safeReadVarInt(); if (!gap) break;
        const len = safeReadVarInt(); if (!len) break;
        ranges.push({ gap: gap.value, length: len.value });
      }

      let ecn = null;
      if (hasECN) {
        const ect0 = safeReadVarInt(); if (!ect0) break;
        const ect1 = safeReadVarInt(); if (!ect1) break;
        const ce = safeReadVarInt(); if (!ce) break;
        ecn = { ect0: ect0.value, ect1: ect1.value, ce: ce.value };
      }

      frames.push({ type: 'ack', largest: largest.value, delay: delay.value, firstRange: firstRange.value, ranges, ecn });

    } else if (type === 0x04) {
      const id = safeReadVarInt(); if (!id) break;
      if (offset + 2 > buf.length) break;
      const error = buf[offset++] << 8 | buf[offset++];
      const finalSize = safeReadVarInt(); if (!finalSize) break;
      frames.push({ type: 'reset_stream', id: id.value, error, finalSize: finalSize.value });

    } else if (type === 0x05) {
      const id = safeReadVarInt(); if (!id) break;
      if (offset + 2 > buf.length) break;
      const error = buf[offset++] << 8 | buf[offset++];
      frames.push({ type: 'stop_sending', id: id.value, error });

    } else if (type === 0x06) {
      const off = safeReadVarInt(); if (!off) break;
      const len = safeReadVarInt(); if (!len) break;
      if (offset + len.value > buf.length) break;
      const data = buf.slice(offset, offset + len.value); offset += len.value;
      frames.push({ type: 'crypto', offset: off.value, data });

    } else if (type === 0x07) {
      const len = safeReadVarInt(); if (!len) break;
      if (offset + len.value > buf.length) break;
      const token = buf.slice(offset, offset + len.value); offset += len.value;
      frames.push({ type: 'new_token', token });

    } else if ((type & 0xe0) === 0x00) {
      const fin  = !!(type & 0x01);
      const lenb = !!(type & 0x02);
      const offb = !!(type & 0x04);

      const stream_id = safeReadVarInt(); if (!stream_id) break;
      const offset_val = offb ? safeReadVarInt() : { value: 0 }; if (!offset_val) break;
      const length_val = lenb ? safeReadVarInt() : { value: buf.length - offset }; if (!length_val) break;

      if (offset + length_val.value > buf.length) break;

      const data = buf.slice(offset, offset + length_val.value); offset += length_val.value;

      frames.push({
        type: 'stream',
        id: stream_id.value,
        offset: offset_val.value,
        fin,
        data
      });
    } else if (type === 0x09) {
      const max = safeReadVarInt(); if (!max) break;
      frames.push({ type: 'max_data', max: max.value });

    } else if (type === 0x0a) {
      const id = safeReadVarInt(); if (!id) break;
      const max = safeReadVarInt(); if (!max) break;
      frames.push({ type: 'max_stream_data', id: id.value, max: max.value });

    } else if (type === 0x12 || type === 0x13) {
      const max = safeReadVarInt(); if (!max) break;
      frames.push({ type: type === 0x12 ? 'max_streams_bidi' : 'max_streams_uni', max: max.value });

    } else if (type === 0x14) {
      const max = safeReadVarInt(); if (!max) break;
      frames.push({ type: 'data_blocked', max: max.value });

    } else if (type === 0x15) {
      const id = safeReadVarInt(); if (!id) break;
      frames.push({ type: 'stream_data_blocked', id: id.value });

    } else if (type === 0x16 || type === 0x17) {
      const max = safeReadVarInt(); if (!max) break;
      frames.push({ type: type === 0x16 ? 'streams_blocked_bidi' : 'streams_blocked_uni', max: max.value });

    } else if (type === 0x18) {
      const seq = safeReadVarInt(); if (!seq) break;
      const retire = safeReadVarInt(); if (!retire) break;
      if (offset >= buf.length) break;
      const len = buf[offset++];
      if (offset + len + 16 > buf.length) break;
      const connId = buf.slice(offset, offset + len); offset += len;
      const token = buf.slice(offset, offset + 16); offset += 16;
      frames.push({ type: 'new_connection_id', seq: seq.value, retire: retire.value, connId, token });

    } else if (type === 0x19) {
      const seq = safeReadVarInt(); if (!seq) break;
      frames.push({ type: 'retire_connection_id', seq: seq.value });

    } else if (type === 0x1a || type === 0x1b) {
      if (offset + 8 > buf.length) break;
      const data = buf.slice(offset, offset + 8); offset += 8;
      frames.push({ type: type === 0x1a ? 'path_challenge' : 'path_response', data });

    } else if (type === 0x1c || type === 0x1d) {
      if (offset + 2 > buf.length) break;
      const error = buf[offset++] << 8 | buf[offset++];
      let frameType = null;
      if (type === 0x1c) {
        const ft = safeReadVarInt(); if (!ft) break;
        frameType = ft.value;
      }
      const reasonLen = safeReadVarInt(); if (!reasonLen) break;
      if (offset + reasonLen.value > buf.length) break;
      const reason = textDecoder.decode(buf.slice(offset, offset + reasonLen.value)); offset += reasonLen.value;
      frames.push({ type: 'connection_close', application: type === 0x1d, error, frameType, reason });

    } else if (type === 0x1e) {
      frames.push({ type: 'handshake_done' });

    } else if (type === 0x1f) {
      frames.push({ type: 'immediate_ack' });

    } else if (type === 0x30 || type === 0x31) {
      let contextId = null;
      let len = null;

      if (type === 0x31) {
        // קורא את context ID
        var cid = safeReadVarInt(buf, offset);
        if (!cid) break;
        contextId = cid.value;
        offset = cid.nextOffset;
      }

      // החישוב של len מבוסס על מה שנשאר בפאקט אחרי הקריאה של contextId
      len = { value: buf.length - offset };

      if (offset + len.value > buf.length) break;

      const data = buf.slice(offset, offset + len.value);
      offset += len.value;

      frames.push({
        type: 'datagram',
        contextId: contextId,
        data: data
      });

    } else if (type === 0xaf) {
      const seq = safeReadVarInt(); if (!seq) break;
      const packetTolerance = safeReadVarInt(); if (!packetTolerance) break;
      if (offset >= buf.length) break;
      const ackDelayExponent = buf[offset++];
      const maxAckDelay = safeReadVarInt(); if (!maxAckDelay) break;
      frames.push({
        type: 'ack_frequency',
        seq: seq.value,
        packetTolerance: packetTolerance.value,
        ackDelayExponent,
        maxAckDelay: maxAckDelay.value
      });

    } else if (type >= 0x15228c00 && type <= 0x15228cff) {
      frames.push({ type: 'multipath_extension', frameType: type });

    } else {
      frames.push({ type: 'unknown', frameType: type, offset: start });
      break;
    }
  }

  return frames;
}






function parse_quic_packet(array, offset0 = 0) {
  if (!(array instanceof Uint8Array)) return null;
  if (offset0 >= array.length) return null;

  const firstByte = array[offset0];
  const isLongHeader = (firstByte & 0x80) !== 0;

  if (isLongHeader) {
    if (offset0 + 6 > array.length) return null;

    const version = ((array[offset0+1] << 24) | (array[offset0+2] << 16) | (array[offset0+3] << 8) | array[offset0+4]) >>> 0;

    const dcidLen = array[offset0+5];
    let offset = offset0 + 6;

    if (offset + dcidLen + 1 > array.length) return null;
    const dcid = array.slice(offset, offset + dcidLen);
    offset += dcidLen;

    const scidLen = array[offset++];
    if (offset + scidLen > array.length) return null;
    const scid = array.slice(offset, offset + scidLen);
    offset += scidLen;

    // Version negotiation
    if (version === 0) {
      const supportedVersions = [];
      while (offset + 4 <= array.length) {
        const v = (array[offset] << 24) | (array[offset+1] << 16) | (array[offset+2] << 8) | array[offset+3];
        supportedVersions.push(v);
        offset += 4;
      }
      return {
        form: 'long',
        type: 'version_negotiation',
        version,
        dcid,
        scid,
        supportedVersions,
        totalLength: offset - offset0
      };
    }

    const packetTypeBits = (firstByte & 0x30) >> 4;
    const typeMap = ['initial', '0rtt', 'handshake', 'retry'];
    const packetType = typeMap[packetTypeBits] || 'unknown';

    if (packetType === 'retry') {
      const odcid = array.slice(offset);
      return {
        form: 'long',
        type: 'retry',
        version,
        dcid,
        scid,
        originalDestinationConnectionId: odcid,
        totalLength: array.length - offset0 // כל השאר
      };
    }

    // === קריאה של Token אם זה Initial ===
    let token = null;
    if (packetType === 'initial') {
      try {
        const tokenLen = readVarInt(array, offset);
        offset += tokenLen.byteLength;
        if (offset + tokenLen.value > array.length) return null;
        token = array.slice(offset, offset + tokenLen.value);
        offset += tokenLen.value;
      } catch (e) {
        return null;
      }
    }

    // === כאן בא השלב הקריטי: לקרוא את Length ===
    try {
      const lengthInfo = readVarInt(array, offset);
      offset += lengthInfo.byteLength;

      const payloadLength = lengthInfo.value;
      const totalLength = offset - offset0 + payloadLength;

      if (offset0 + totalLength > array.length) return null;

      return {
        form: 'long',
        type: packetType,
        version,
        dcid,
        scid,
        token,
        totalLength
      };
    } catch (e) {
      return null;
    }
  } else {
    const totalLength = array.length - offset0; // לא ניתן לדעת בדיוק, אז נניח שזה האחרון
    return {
      form: 'short',
      type: '1rtt',
      totalLength
    };
  }
}

function parse_quic_datagram(array) {
  var packets = [];
  var offset = 0;

  while (offset < array.length) {
    var pkt = parse_quic_packet(array, offset);
    if (!pkt || !pkt.totalLength) break;

    const start = offset;
    const end = offset + pkt.totalLength;

    // slice רק אם חייב
    pkt.raw = (start === 0 && end === array.length)
      ? array
      : array.slice(start, end);

    packets.push(pkt);
    offset = end;
  }

  return packets;
}


function build_new_session_ticket(session_id_bytes, options) {
  var ticket_lifetime = options.lifetime || 86400;
  var ticket_age_add = Math.floor(Math.random() * 0xffffffff);
  var ticket_nonce = crypto.getRandomValues(new Uint8Array(8));
  var ticket = session_id_bytes;

  var extensions = [];
  if (options.early_data_max_size != null) {
    var ed = new Uint8Array(8);
    ed[0] = 0x00; ed[1] = 0x2a; // early_data extension type
    ed[2] = 0x00; ed[3] = 0x04; // extension length
    ed[4] = (options.early_data_max_size >>> 24) & 0xff;
    ed[5] = (options.early_data_max_size >>> 16) & 0xff;
    ed[6] = (options.early_data_max_size >>> 8) & 0xff;
    ed[7] = (options.early_data_max_size) & 0xff;
    extensions.push(ed);
  }

  var ext_len = 0;
  for (var i = 0; i < extensions.length; i++) ext_len += extensions[i].length;
  var extensions_block = new Uint8Array(ext_len);
  for (var i = 0, offset = 0; i < extensions.length; i++) {
    extensions_block.set(extensions[i], offset);
    offset += extensions[i].length;
  }

  var total_len =
    4 + // ticket_lifetime
    4 + // ticket_age_add
    1 + ticket_nonce.length +
    2 + ticket.length +
    2 + extensions_block.length;

  var result = new Uint8Array(total_len);
  var p = 0;

  result[p++] = (ticket_lifetime >>> 24) & 0xff;
  result[p++] = (ticket_lifetime >>> 16) & 0xff;
  result[p++] = (ticket_lifetime >>> 8) & 0xff;
  result[p++] = (ticket_lifetime) & 0xff;

  result[p++] = (ticket_age_add >>> 24) & 0xff;
  result[p++] = (ticket_age_add >>> 16) & 0xff;
  result[p++] = (ticket_age_add >>> 8) & 0xff;
  result[p++] = (ticket_age_add) & 0xff;

  result[p++] = ticket_nonce.length;
  result.set(ticket_nonce, p);
  p += ticket_nonce.length;

  result[p++] = (ticket.length >>> 8) & 0xff;
  result[p++] = (ticket.length) & 0xff;
  result.set(ticket, p);
  p += ticket.length;

  result[p++] = (extensions_block.length >>> 8) & 0xff;
  result[p++] = (extensions_block.length) & 0xff;
  result.set(extensions_block, p);

  return result;
}


module.exports = {
  extract_tls_messages_from_chunks,
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
  build_alpn_ext,
  build_finished,
  tls_derive_app_secrets,
  parse_transport_parameters
};