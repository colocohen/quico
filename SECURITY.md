# Security Policy

Thank you for helping keep **QUICO** secure.



## Supported Versions
Only the latest release of Quico (main branch) receives security updates.

| Version | Supported |
|----------|------------|
| main (latest) | ✅ |
| older releases | ❌ |


## Reporting a Vulnerability
If you discover a security issue in Quico, **do not open a public issue**.

Please report it privately to:  
**security@quicojs.dev**

Include:
- Steps to reproduce or proof of concept  
- Affected version / commit  
- Expected vs actual behavior  
- Any logs or packet captures (if relevant)

We will acknowledge receipt within **72 hours** and provide a fix or response within **7–14 days**, depending on severity.



## Disclosure Process
Once a fix is available:
- We’ll coordinate disclosure with the reporter.  
- A public advisory will be posted in the **Security Advisories** section on GitHub.  
- CVE identifiers may be requested if applicable.



## Scope
This policy covers:
- QUIC / HTTP3 / WebTransport layers  
- TLS (via LemonTLS integration)  
- Developer APIs and debug tools that could expose sensitive data  
