# Changelog

All notable changes to `@hivecivilization/smsh-stamp-verifier` are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 — 2026-05-02

### Added

- Initial release of the SMSH-Stamp v1 verifier library.
- `verify()` — core Ed25519 signature verification with schema validation, clock skew enforcement, and expiry support.
- `parseReceipt()` — robust parser accepting string or plain object input.
- `canonicalize()` — RFC 8785 JCS (JSON Canonicalization Scheme) implementation.
- `DEFAULT_VERIFIER_PUBKEY_B64U` — embedded default trust anchor (Ed25519 public key).
- Full TypeScript types: `SmshReceipt`, `VerifyOpts`, `VerifyResult`, `VerifyError`.
- CLI binary `smsh-verify` — reads receipt from file or stdin, exits 0 on valid, 1 on invalid.
- Zero network calls, zero telemetry, zero phone-home — fully auditable offline verifier.
- Comprehensive test suite (vitest) with JCS test vectors from RFC 8785 appendix.
