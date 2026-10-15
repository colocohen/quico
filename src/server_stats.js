// ============================================================
//  The server's counters — server.getStats()
// ============================================================
//
// What an operator watches a server by: how many connections came, over what,
// how many handshakes failed, how connections ended and with what code, what
// 0-RTT did, how often the anti-amplification limit held the server back,
// how many internal errors were caught. Counts only: no addresses, no names,
// no headers, no payloads — nothing here identifies a client.
//
// One object per server, made by createServer and handed to each layer
// (quic_server, quic_connection, h3_server, tcp_listener, h2_server / h2.js,
// h1_server) in its options as `stats`; each counts where the thing happens,
// with a plain increment. A layer used on its own (createQuicServer, an
// H2Connection) has none and counts nothing.
//
// Codes are the protocol's, as hex strings ('0x0', '0x12f'): a map from code
// to count, only for codes seen.

function ServerStats() {
  this.since = Date.now();
  // Connections taken: QUIC, a first Initial that began a handshake; TCP, a
  // socket accepted (before TLS).
  this.connections = { quic: 0, tcp: 0 };
  // TLS handshakes, as they ended: completed (the client's Finished
  // verified) or failed (an alert either way, a timeout, the connection
  // closed first). resumed: completed with a session ticket.
  this.handshakes = { quic: { completed: 0, failed: 0 }, tcp: { completed: 0, failed: 0 }, resumed: 0 };
  // Connections by the protocol they went on to speak (the ALPN agreed; over
  // cleartext TCP, the preface read) — other: an ALPN name of the
  // application's.
  this.protocols = { h3: 0, h2: 0, 'http/1.1': 0, other: 0 };
  // 0-RTT offered by the client: taken, or refused (the ticket's, the replay
  // check, a HelloRetryRequest); tooEarly, requests answered 425 (RFC 8470).
  this.earlyData = { accepted: 0, rejected: 0, tooEarly: 0 };
  // How connections ended, by code:
  //   quic   CONNECTION_CLOSE of the transport (RFC 9000 §20.1; 0x100 + a TLS
  //          alert, RFC 9001 §4.8) — sent by us, received from the client;
  //          silent: ended with none either way (the idle timeout, a
  //          stateless reset, a handshake abandoned)
  //   h3     CONNECTION_CLOSE of the application (RFC 9114 §8.1)
  //   h2     GOAWAY (RFC 9113 §7)
  //   http1  requests refused before the application saw them, by status
  //          (400 a malformed request, 431 headers too large, ...)
  this.closes = {
    quic: { sent: {}, received: {}, silent: 0 },
    h3: { sent: {}, received: {} },
    h2: { sent: {}, received: {} },
    http1: { sent: {} }
  };
  // Streams reset, by code: RESET_STREAM (HTTP/3) and RST_STREAM (HTTP/2),
  // sent and received.
  this.streamResets = { h3: { sent: {}, received: {} }, h2: { sent: {}, received: {} } };
  // Datagrams the server held because the client's address was not yet
  // validated and it had sent three times what it received (RFC 9000 §8.1).
  this.amplificationBlocked = 0;
  // Exceptions caught inside the QUIC and HTTP/3 layers: a bug of ours,
  // never the client's (the packet dropped, or H3_INTERNAL_ERROR).
  this.internalErrors = 0;
}

/** One more of a protocol error `code` in `map`, by its hex. */
ServerStats.prototype.code = function (map, code) {
  // Up to 62 bits (a QUIC varint — WebTransport's codes are past 2^32): by
  // its value, not cut to 32 bits.
  var k = '0x' + (typeof code === 'bigint' ? code : Number(code)).toString(16);
  map[k] = (map[k] || 0) + 1;
};

/** One more of an HTTP status in `map`. */
ServerStats.prototype.status = function (map, status) {
  map[status] = (map[status] || 0) + 1;
};

/** A TLS handshake ended ('quic' or 'tcp'): completed or not, resumed. */
ServerStats.prototype.handshake = function (transport, ok, resumed) {
  this.handshakes[transport][ok ? 'completed' : 'failed']++;
  if (ok && resumed) this.handshakes.resumed++;
};

/** A connection handed to the protocol it speaks. */
ServerStats.prototype.protocol = function (name) {
  this.protocols[name === 'h3' || name === 'h2' || name === 'http/1.1' ? name : 'other']++;
};

/** A copy, for the caller to keep or change. */
ServerStats.prototype.snapshot = function () {
  var copy = JSON.parse(JSON.stringify(this));
  copy.uptime = Date.now() - this.since;
  return copy;
};

export { ServerStats };
