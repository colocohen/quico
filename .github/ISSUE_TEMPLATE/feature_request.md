---
name: Feature request
about: Suggest a new feature, protocol improvement, or API design idea for QUICO
title: "[Feature] "
labels: enhancement
assignees: ''

---

### 🔹 Summary
Briefly describe what you’d like to see added or improved.

### 🔹 Layer or scope
Which part of QUICO does this relate to?
- QUIC core / transport
- HTTP/3
- WebTransport
- TLS
- Developer API / Debug / Other

### 🔹 Motivation
What problem or limitation does this feature solve?  
(e.g. better congestion control, new ALPN option, improved event handling, etc.)

### 🔹 Proposed solution
Describe your idea.  
If it’s an **API design or developer interface**, show an example of how you imagine it:
```js
var conn = quico.connect({ alpn: "h3" })
conn.on('stream', s => s.write('Hello world'))
```

### 🔹 Alternatives
Any other ways you thought of solving this?

### 🔹 Additional context
Links, references, RFCs, or examples from other stacks (e.g. QUICHE, aioquic, Node core).
