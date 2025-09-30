# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-08-07
### Added
- Basic QUIC server with 1-RTT support
- TLS 1.3 handshake (fully JS)
- HTTP/3 request/response over control streams
- Static & dynamic QPACK decoding
- Basic `createServer()` API
- Quick start example in README

### In progress
- WebTransport streams (uni & bidi)
- 0-RTT support
- Integration with Node.js `https`-style API
- Connection teardown, keep-alive, congestion control

### Notes
- This is a pre-release version under heavy development.
- API may change without notice.


## [0.1.1] - 2025-09-30
- Extracted the TLS implementation into a separate library: **lemon-tls**, for easier maintenance and reuse.
- Refactored the project’s file structure for clearer organization and improved modularity.
- Migrated the codebase from CommonJS (`require`) to **ESM** (`import/export`) for modern compatibility.