# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately to: security@skaldlab.dev

We will acknowledge receipt within 48 hours and aim to release
a fix within 7 days for critical issues.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |

## Scope

Muninn is a security scanner — we take vulnerabilities in our
own tooling seriously. In-scope issues include:

- Scanner bypass techniques (making Muninn miss real findings)
- False negative patterns across any of the 8 scanners
- Supply chain attacks against Muninn's own dependencies
- Remote code execution via malicious scan targets
- Information disclosure via scan output

## Recognition

We maintain a hall of fame for responsible disclosures.
Researchers who report valid vulnerabilities will be credited
in our release notes (with permission).

---
*Skald Lab — [skaldlab.dev](https://skaldlab.dev)*
