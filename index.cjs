/*
 * quico — CommonJS entry point
 *
 * Since quico is ESM-only internally, CommonJS users
 * must await .ready before calling any API:
 *
 *   const quico = require('quico');
 *   await quico.ready;
 *   const server = quico.createServer({ ... }, handler);
 *
 * Or in one step:
 *
 *   const quico = await require('quico').ready;
 *   const server = quico.createServer({ ... }, handler);
 */

let _mod;

const proxy = new Proxy({}, {
  get(target, key) {
    // .ready must be accessible before module loads
    if (key === 'ready') return target.ready;
    // Prevent Promise auto-unwrapping when proxy is returned from async
    if (key === 'then') return undefined;
    if (!_mod) throw new Error(
      'quico: module not loaded yet. Use "const quico = await require(\'quico\').ready" first.'
    );
    return _mod[key];
  }
});

// Kick off async ESM import — sets .ready on proxy target
proxy.ready = import('./index.js').then(function (m) {
  // Merge default export (createServer, request, etc.)
  // with named exports (WebTransport, etc.)
  _mod = Object.assign({}, m.default);
  for (var key in m) {
    if (key !== 'default' && key !== '__esModule') {
      _mod[key] = m[key];
    }
  }
  return proxy;
});

module.exports = proxy;
