# Pull Request


### 🔹 Summary
Briefly describe what this PR changes or fixes.

### 🔹 Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] API / developer-facing change
- [ ] Refactor / cleanup
- [ ] Documentation / tests only

### 🔹 Related issues
Link to any related issues (e.g. #42).

### 🔹 Details
Which layer(s) are affected?
- QUIC / HTTP3 / WebTransport / TLS / Other

If it affects API design, please show before/after example:
```js
// Before
conn.createStream()
// After
conn.openStream({ uni: true })
```

### 🔹 Tests
- [ ] Added or updated tests
- [ ] Verified locally with `curl --http3`
- [ ] Verified both server and client behavior
- [ ] No new tests needed (non-functional change)

### 🔹 Compatibility
- [ ] No breaking changes
- [ ] May break older usage (explain below)
  
Explain any potential backward incompatibility:


> Thank you for contributing to **Quico**!  
> Your attention to detail keeps the protocol stack stable and elegant.
