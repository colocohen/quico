/*
 * quico — QUIC Interop Runner harness
 *
 * Written against quico's ACTUAL API:
 *   createQuicServer({ alpn, key, cert })  ->  .on('connection', (quic, peer))
 *   quic.on('stream', (sid, data, fin))    ->  incoming stream data
 *   quic.sendStream(sid, data, fin)        ->  outgoing stream data
 *   quic.on('connect'|'close'|'error')
 *   quic.close(errorCode, reason)
 *
 * HTTP/0.9 (ALPN "hq-interop") is used by every test case except `http3`.
 *   request:  client opens a bidi stream, sends "GET /path\r\n", FIN
 *   response: server sends raw file bytes, FIN
 *
 * Contract (quic-interop-runner/quic.md):
 *   server   — serves /www on port 443; key /certs/priv.key, chain /certs/cert.pem
 *   client   — downloads $REQUESTS (space separated) into /downloads
 *   exit 0   — success;  exit 1 — error;  exit 127 — TESTCASE not supported
 *   logs     — /logs;  SSLKEYLOGFILE — NSS key log;  QLOGDIR — qlog
 */

import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';

import { createQuicServer, createQuicClientSocket } from 'quico';

const ROLE      = process.argv[2];
const TESTCASE  = process.env.TESTCASE || '';
const REQUESTS  = (process.env.REQUESTS || '').trim().split(/\s+/).filter(Boolean);
const KEYLOG    = process.env.SSLKEYLOGFILE;

// Directory layout. The interop runner bind-mounts /www, /downloads and
// /certs into the container, so those are the defaults and the only paths
// used in production. The env overrides exist so the endpoint can also be run
// straight from a checkout — useful for reproducing an interop failure against
// another implementation without the runner in the way.
const WWW       = process.env.WWW_DIR      || '/www';
const DOWNLOADS = process.env.DOWNLOAD_DIR || '/downloads';
const CERTS     = process.env.CERTS_DIR    || '/certs';
const CERT      = path.join(CERTS, 'cert.pem');
const KEY       = path.join(CERTS, 'priv.key');

// Test-case support is decided in run_endpoint.sh (allow-list + exit 127),
// before this file is reached — matching how quicly, picoquic and nginx do it.
// It has to happen there rather than here because the runner probes an
// endpoint by starting it with a randomly generated TESTCASE and expecting it
// to decline; anything that instead starts listening hangs the whole run.

// ALPN: HTTP/0.9 for everything except the http3 test case.
const ALPN = TESTCASE === 'http3' ? ['h3'] : ['hq-interop'];

// Absolute, normalised — the containment checks below compare prefixes, and a
// relative WWW_DIR would make them pass for paths outside the directory.
const WWW_ABS = path.resolve(WWW);

const log  = (...a) => console.log('[interop]', ...a);
const fail = (e) => { console.error('[interop] FATAL:', (e && e.stack) || e); process.exit(1); };

// ---------------------------------------------------------------------------
// NSS key log. quico doesn't emit these yet — see PATCHES.md item 4.
// ---------------------------------------------------------------------------
function installKeylog(quic) {
  if (!KEYLOG) return;

  // lemon-tls emits a Buffer, already newline-terminated. An earlier version
  // of this called line.endsWith() on it, which throws on a Buffer — and the
  // throw was swallowed by a bare catch, so the file stayed empty while
  // everything looked fine. Six test cases would have silently reported
  // UNSUPPORTED. Normalise explicitly and let real errors be seen.
  quic.on('keylog', (line) => {
    try {
      let text = Buffer.isBuffer(line) ? line.toString('ascii') : String(line);
      if (!text.endsWith('\n')) text += '\n';
      fs.appendFileSync(KEYLOG, text);
    } catch (e) {
      // Not fatal to the transfer, but never silent: a missing key log turns
      // six interop test cases into UNSUPPORTED with no explanation.
      console.error('[interop] keylog write failed:', e.message);
    }
  });
}

// ---------------------------------------------------------------------------
// HTTP/0.9 server side.
// Streams arrive as (sid, data, fin). Buffer per stream until the newline,
// then stream the file back and FIN.
// ---------------------------------------------------------------------------
function serveH09(quic) {
  const pending = new Map();   // sid -> accumulated request bytes

  quic.on('stream', (sid, data, fin) => {
    // Only client-initiated bidirectional streams carry requests.
    // Client bidi ids are 0,4,8,... => (sid & 0x3) === 0
    if ((sid & 0x3) !== 0) return;

    let buf = pending.get(sid) || new Uint8Array(0);
    if (data && data.byteLength) {
      const merged = new Uint8Array(buf.byteLength + data.byteLength);
      merged.set(buf, 0);
      merged.set(data, buf.byteLength);
      buf = merged;
    }

    const nl = buf.indexOf(0x0a);
    if (nl === -1) {
      if (!fin) { pending.set(sid, buf); return; }
      pending.delete(sid);
      quic.sendStream(sid, new Uint8Array(0), true);
      return;
    }
    pending.delete(sid);

    const line = Buffer.from(buf.subarray(0, nl)).toString('ascii').trim();
    const m = /^GET\s+(\S+)$/.exec(line);
    if (!m) { quic.sendStream(sid, new Uint8Array(0), true); return; }

    // Keep the resolved path inside /www.
    const rel  = decodeURIComponent(m[1]).replace(/^\/+/, '');
    const file = path.resolve(WWW_ABS, rel);
    if (!file.startsWith(WWW_ABS + path.sep)) {
      quic.sendStream(sid, new Uint8Array(0), true);
      return;
    }

    let body;
    try { body = fs.readFileSync(file); }
    catch (e) { quic.sendStream(sid, new Uint8Array(0), true); return; }

    // sendStream buffers into the burst scheduler, so one call for a 5 MB file
    // is fine — the scheduler paces it out under BBR + flow control.
    quic.sendStream(sid, new Uint8Array(body.buffer, body.byteOffset, body.byteLength), true);
  });
}

// ---------------------------------------------------------------------------
// HTTP/0.9 client side.
// ---------------------------------------------------------------------------
function requestH09(quic, sid, urlPath) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let done = false;

    const onStream = (gotSid, data, fin) => {
      if (gotSid !== sid || done) return;
      if (data && data.byteLength) parts.push(Buffer.from(data));
      if (fin) {
        done = true;
        quic.off('stream', onStream);
        resolve(Buffer.concat(parts));
      }
    };
    quic.on('stream', onStream);

    const req = new TextEncoder().encode(`GET ${urlPath}\r\n`);
    quic.sendStream(sid, req, true);

    setTimeout(() => {
      if (!done) { done = true; quic.off('stream', onStream); reject(new Error('timeout on ' + urlPath)); }
    }, 120000).unref?.();
  });
}

// ---------------------------------------------------------------------------
// Raw QUIC client connection (no HTTP/3 layer), via quico's public API.
//
// Deliberately NOT a hand-rolled dgram + QUICConnection setup: package.json
// exports keep src/ private, and duplicating the socket wiring here would
// silently drift from the real client (buffer sizing, ALPN normalisation,
// close handling) the moment either changes.
// ---------------------------------------------------------------------------
function connectQuic(host, port) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, (err, ip) => {
      if (err) return reject(err);

      let settled = false;

      const sock = createQuicClientSocket({
        remoteIp: ip,
        remotePort: port,
        hostname: host,
        alpn: ALPN,

        // The runner generates its own CA and addresses the server as
        // server4 / server6, which no certificate we are given will match.
        // Every implementation in the runner disables verification here; it is
        // part of the harness contract, not a shortcut.
        rejectUnauthorized: false,

        // Fires before connect(), which is the only point where a keylog
        // listener still catches the handshake secrets.
        onSocket: (quic) => { installKeylog(quic); },

        onConnect: (quic, socket) => {
          if (settled) return;
          settled = true;
          resolve({ quic, sock: socket });
        },

        onError: (e) => {
          if (settled) return;
          settled = true;
          reject(e);
        },
      });

      // createQuicClientSocket resolves nothing itself; guard against a
      // handshake that never completes so the client exits 1 instead of
      // hanging until the runner's timeout.
      setTimeout(() => {
        if (!settled) {
          settled = true;
          try { sock.close(); } catch (e) {}
          reject(new Error('handshake timeout to ' + host + ':' + port));
        }
      }, 30000).unref?.();
    });
  });
}

function downloadPath(urlStr) {
  const u = new URL(urlStr);
  return path.resolve(DOWNLOADS, u.pathname.replace(/^\/+/, ''));
}

function saveDownload(urlStr, body) {
  const dest = downloadPath(urlStr);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, body);
}

// The runner treats exit 0 as "the transfer completed" and only then compares
// files. Reporting success while /downloads is short a file turns a real
// transport bug into a confusing "missing files" line with no error attached,
// so verify before claiming success.
function verifyDownloads(urls) {
  const missing = [];
  for (const url of urls) {
    const dest = downloadPath(url);
    let ok = false;
    try { ok = fs.statSync(dest).size > 0; } catch (e) { ok = false; }
    if (!ok) missing.push(dest);
  }
  return missing;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
function runServer() {
  const opts = {
    alpn: ALPN,
    key:  fs.readFileSync(KEY),
    cert: fs.readFileSync(CERT),
  };

  if (TESTCASE === 'http3') {
    // The one case that uses HTTP/3 — quico's native path.
    //
    // NOTE: no key log on this path. createServer() owns its QUIC connections
    // and doesn't surface them, so there is nowhere to attach the 'keylog'
    // listener; the same is true of request() on the client side. The http3
    // test case is judged on downloaded files and handshake count, neither of
    // which needs decryption, so this costs debuggability rather than results.
    // Fixing it properly means a small quico API addition (re-emit
    // 'connection' from createServer, accept a keylog hook in request()).
    import('quico').then(({ createServer }) => {
      const server = createServer(opts, (req, res) => {
        const rel  = decodeURIComponent(req.url).replace(/^\/+/, '');
        const file = path.resolve(WWW_ABS, rel);
        if (!file.startsWith(WWW_ABS + path.sep) || !fs.existsSync(file)) {
          res.writeHead(404); res.end(); return;
        }
        const body = fs.readFileSync(file);
        res.writeHead(200, { 'content-length': String(body.length) });
        res.end(body);
      });
      server.listen(443, () => log('HTTP/3 server on :443'));
    }).catch(fail);
    return;
  }

  const qserver = createQuicServer(opts);
  qserver.on('error', (e) => log('server error:', e.message));
  qserver.on('connection', (quic, peer) => {
    log('connection from', peer.address + ':' + peer.port);
    installKeylog(quic);
    serveH09(quic);
  });
  qserver.listen(443, () => log('HTTP/0.9 server on :443, alpn=' + ALPN.join(',')));
  // The runner kills the server container; never exit on our own.
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
async function downloadAll(urls) {
  const first = new URL(urls[0]);
  const { quic, sock } = await connectQuic(first.hostname, Number(first.port) || 443);

  // Client-initiated bidi stream ids: 0, 4, 8, ...
  let nextSid = 0;
  const results = await Promise.all(urls.map((url) => {
    const sid = nextSid; nextSid += 4;
    return requestH09(quic, sid, new URL(url).pathname).then((body) => saveDownload(url, body));
  }));

  await new Promise((r) => {
    quic.on('close', r);
    quic.close(0, 'done');
    setTimeout(r, 2000).unref?.();
  });
  try { sock.close(); } catch (e) {}
  return results;
}

async function runClient() {
  if (REQUESTS.length === 0) { log('no REQUESTS'); return; }

  if (TESTCASE === 'http3') {
    const { request } = await import('quico');
    await Promise.all(REQUESTS.map((url) => new Promise((resolve, reject) => {
      request(url, { rejectUnauthorized: false }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => { saveDownload(url, Buffer.concat(chunks)); resolve(); });
      }).on('error', reject).end();
    })));
    return;
  }

  if (TESTCASE === 'multiconnect') {
    // One connection per file. Sequential — far easier to reason about at
    // 30% packet loss, and the runner allows it.
    for (const url of REQUESTS) await downloadAll([url]);
    return;
  }

  // handshake / transfer / chacha20 / retry / v2:
  // one connection, all files in parallel on separate streams.
  await downloadAll(REQUESTS);
}

// ---------------------------------------------------------------------------
(async () => {
  try {
    if (ROLE === 'server') {
      runServer();
      return;                       // the runner stops the container
    }
    if (ROLE !== 'client') {
      console.error('usage: interop.js server|client');
      process.exit(1);
    }

    await runClient();

    const missing = verifyDownloads(REQUESTS);
    if (missing.length) {
      console.error('[interop] FAILED — ' + missing.length + ' file(s) not downloaded:');
      for (const m of missing) console.error('  ' + m);
      process.exit(1);
    }

    log('done — ' + REQUESTS.length + ' file(s)');
    process.exit(0);
  } catch (e) { fail(e); }
})();

process.on('unhandledRejection', fail);
process.on('uncaughtException', fail);
