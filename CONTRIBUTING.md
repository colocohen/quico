# Contributing to Quico

First off — thank you for taking the time to contribute!  
Quico is an open-source implementation of **QUIC + HTTP/3 for Node.js**, and it grows stronger with every contribution.



## 🧭 Getting started

1. **Fork** this repository.
2. **Clone** your fork:
   ```bash
   git clone https://github.com/colocohen/quico.git
   cd quico
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Run tests:**
   ```bash
   npm test
   ```
   Make sure all tests pass before submitting changes.



## 💡 Ways to contribute

- Report bugs or issues
- Suggest new features or improvements
- Improve documentation or examples
- Help review Pull Requests
- Write or improve test coverage

No contribution is too small — even fixing typos helps!



## 🔧 Development guidelines

- Keep your changes **focused and small** — one purpose per PR.
- Use **clear commit messages**, e.g.:
  ```
  fix(h3): correct header parsing in request stream
  ```
- Follow existing code style:
  - Use `var` for variable declarations
  - Avoid arrow functions and ES6+ shortcuts
  - Prefer `Uint8Array` over `Buffer`
  - Keep line length under 100 chars



## 🧪 Running QUIC / HTTP3 examples

To test QUIC or HTTP/3 locally:
```bash
node test/quic_server.js
curl --http3 -v https://localhost:4433 --insecure
```

If you modify TLS or transport logic, make sure to test both:
- Client handshake (using `curl --http3`)
- Server behavior with multiple streams



## 📤 Submitting a Pull Request

1. Create a new branch for your change:
   ```bash
   git checkout -b fix-connection-timeout
   ```
2. Commit your changes and push to your fork.
3. Open a Pull Request to the `main` branch.
4. Add a clear description of what your PR does and why.

Your PR will be reviewed — we might ask for clarifications or adjustments.



## 📜 Code of Conduct

By participating in this project, you agree to follow our [Code of Conduct](./CODE_OF_CONDUCT.md).



## ❤️ Thanks

Every contribution matters — from fixing small typos to improving the protocol stack.  
Together we’re building the next generation of networking for Node.js.
