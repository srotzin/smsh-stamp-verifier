# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through GitHub Issues.**

If you discover a security vulnerability in `@hivecivilization/smsh-stamp-verifier`, please disclose it responsibly by emailing:

**steve@thehiveryiq.com**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Any suggested mitigations if known

You can expect an acknowledgment within **48 hours** and a resolution timeline within **7 business days** for critical issues.

## Scope

This library performs cryptographic verification of SMSH-Stamp v1 receipts. Issues of particular interest include:

- Signature verification bypass
- Canonicalization (JCS) inconsistencies that could allow a receipt to verify under a different canonical form
- Clock-skew or timestamp validation bypasses
- Type confusion or schema validation bypasses

## Out of Scope

- Vulnerabilities in the Ed25519 algorithm itself (report to `@noble/ed25519`)
- Node.js runtime vulnerabilities
