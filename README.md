# @hivecivilization/smsh-stamp-verifier

> **Layer C — Reference Primitive.** This is a public reference implementation. The wire format (see `SPEC.md` where present) is normative; this code is illustrative. Production-grade implementations of these specs run on the closed-source Hive Civilization platform with HSM-backed key custody, immutable transparency-log audit, multi-region sovereign federation, and SOC 2 / ISO 27001 / FedRAMP-track controls. Fork freely; conform to the spec.


<div align="center">

<img src="https://img.shields.io/npm/v/@hivecivilization/smsh-stamp-verifier?style=flat-square&color=FFB800" alt="npm version" />
<img src="https://img.shields.io/badge/license-Apache--2.0-FFB800?style=flat-square" alt="Apache 2.0 License" />
<img src="https://img.shields.io/github/actions/workflow/status/srotzin/smsh-stamp-verifier/ci.yml?style=flat-square&color=FFB800" alt="CI Status" />

</div>

Regulator-friendly cryptographic verification for **SMSH-Stamp v1** receipts — the provenance format for AI agent operations. Verify that any LLM call, tool invocation, or agent step was genuinely stamped by the Hive Civilization council, with no Hive runtime required. Pure **Ed25519** signatures, **SHA-256** fingerprinting, and **RFC 8785 JCS** canonicalization. Drop it into any compliance pipeline, audit tool, or regulatory submission workflow.

## Why it matters

- **Provenance for every LLM call.** Each SMSH-Stamp receipt cryptographically binds a model call's inputs and outputs to a signed timestamp — you can prove what was asked, what was answered, and when, without trusting any third party.
- **Recursive lineage.** Receipts carry a `lineage` chain so you can trace a multi-step agent workflow back to its root, detecting any tampering at any depth.
- **Regulator-readable.** The [SMSH-Stamp v1 Spec](https://github.com/srotzin/smsh-stamp-spec) is a plain JSON schema. The verification algorithm is ~100 lines. Any auditor can review this library in a single PR.

## Install

```bash
npm install @hivecivilization/smsh-stamp-verifier
```

No native binaries. No runtime dependencies beyond `@noble/ed25519` and `@noble/hashes` — both are widely audited, pure-JavaScript cryptographic libraries.

## Quick start

```typescript
import { verify } from "@hivecivilization/smsh-stamp-verifier";

const result = await verify(receiptJson);

if (result.valid) {
  console.log("✓ Valid  |  fingerprint:", result.fingerprint);
} else {
  console.error("✗ Invalid:", result.error.reason, "—", result.error.message);
}
```

## Receipt schema

A SMSH-Stamp v1 receipt is a JSON object with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | `"smsh-stamp/1"` | ✓ | Protocol version. Must be exactly `"smsh-stamp/1"`. |
| `alg` | `"ed25519"` | ✓ | Signature algorithm. Must be `"ed25519"`. |
| `kid` | `string` | ✓ | Key identifier (base64url). Used for key rotation lookups. |
| `stamped_at` | RFC 3339 UTC string | ✓ | When the stamp was issued. Validated for clock skew (±5 min max future drift). |
| `subject.kind` | enum | ✓ | One of: `llm-call`, `tool-call`, `data-emit`, `model-output`, `agent-step`. |
| `subject.model` | `string` | — | Model identifier (e.g. `gpt-4o`, `claude-3-opus`). |
| `subject.input_hash` | base64url string | ✓ | SHA-256 of the canonicalized input. |
| `subject.output_hash` | base64url string | ✓ | SHA-256 of the canonicalized output. |
| `subject.context_hashes` | `string[]` | — | Additional SHA-256 hashes of context documents. |
| `council` | object \| `null` | ✓ | Council consensus metadata, or `null`. |
| `council.round` | `"R3"` \| `"R4"` \| `"R5"` \| `"R6"` \| `"ad-hoc"` | ✓ (if council present) | Council round identifier. |
| `council.score` | `number` | ✓ (if council present) | Score received from the council. |
| `council.of` | `number` | ✓ (if council present) | Maximum possible score. |
| `lineage` | object \| `null` | ✓ | Lineage chain, or `null` for root receipts. |
| `lineage.parent_receipts` | `string[]` | ✓ (if lineage present) | Base64url IDs of parent receipts. |
| `lineage.depth` | `number` | ✓ (if lineage present) | Depth in the lineage chain (`0` = root). |
| `sig` | base64url string | ✓ | Ed25519 signature over the JCS-canonicalized receipt, **excluding** this field. |

## Verification semantics

A receipt is **valid** when all of the following hold:

1. **Schema** — The receipt matches the SMSH-Stamp v1 schema exactly (no unknown top-level keys, correct types on all fields).
2. **Version** — `v === "smsh-stamp/1"`.
3. **Algorithm** — `alg === "ed25519"`.
4. **Timestamp** — `stamped_at` is a parseable RFC 3339 UTC date, is not more than 5 minutes in the future, and (if `maxAgeSeconds` is set) is not older than that limit.
5. **Signature** — The Ed25519 signature in `sig` verifies against the JCS-canonicalized receipt body (all fields **except** `sig`), using the trust-anchor public key.

A successful `VerifyResult` carries:
- `valid: true`
- `receipt` — the fully typed, validated `SmshReceipt`
- `fingerprint` — a hex-encoded SHA-256 of the canonical bytes that were signed (useful for audit logs and correlation)

## Trust anchor

By default, verification uses the embedded Hive Civilization SMSH-Stamp v1 public key:

```typescript
import { DEFAULT_VERIFIER_PUBKEY_B64U } from "@hivecivilization/smsh-stamp-verifier";

console.log(DEFAULT_VERIFIER_PUBKEY_B64U);
// → "8DBPaWbs1uBGOVPEK-ktrTbtR5sz3ST5pKLe8te9Bq4"
```

### Override the trust anchor

Pass a different base64url-encoded Ed25519 public key (32 bytes) via `opts.pubkeyB64u`:

```typescript
import { verify } from "@hivecivilization/smsh-stamp-verifier";

const result = await verify(receipt, {
  pubkeyB64u: "YOUR_PUBKEY_B64U_HERE",
});
```

### Pin multiple keys (multi-tenant)

For multi-signer environments, verify against each key and accept if any succeeds:

```typescript
import { verify } from "@hivecivilization/smsh-stamp-verifier";

async function verifyAny(receipt, pubkeys) {
  for (const pubkeyB64u of pubkeys) {
    const result = await verify(receipt, { pubkeyB64u });
    if (result.valid) return result;
  }
  return { valid: false, error: { reason: "key_unknown", message: "No matching key" } };
}
```

### Enforce a maximum receipt age

```typescript
const result = await verify(receipt, {
  maxAgeSeconds: 3600, // reject receipts older than 1 hour
});
```

## CLI

```bash
# Verify a receipt file (exits 0 on valid, 1 on invalid)
smsh-verify receipt.json

# Pipe from stdin
cat receipt.json | smsh-verify

# Override trust anchor via env var
SMSH_PUBKEY="YOUR_PUBKEY_B64U" smsh-verify receipt.json

# Enforce max age
SMSH_MAX_AGE_SECONDS=3600 smsh-verify receipt.json
```

Example output (valid receipt):

```json
{
  "valid": true,
  "fingerprint": "3a4b5c...",
  "kid": "hive-key-001",
  "stamped_at": "2026-05-02T12:00:00.000Z",
  "subject_kind": "llm-call"
}
```

Example output (invalid receipt, stderr):

```json
{
  "valid": false,
  "reason": "signature_invalid",
  "message": "Ed25519 signature does not match the canonicalized receipt payload"
}
```

## API reference

### `verify(receipt, opts?): Promise<VerifyResult>`

Core verification function. Never throws. Returns a discriminated union:

```typescript
type VerifyResult =
  | { valid: true; receipt: SmshReceipt; fingerprint: string }
  | { valid: false; error: VerifyError };

type VerifyErrorReason =
  | "parse_error"       // Input could not be parsed as JSON
  | "schema_invalid"    // Missing/extra/wrong-type fields
  | "version_mismatch"  // v !== "smsh-stamp/1"
  | "alg_mismatch"      // alg !== "ed25519"
  | "expired"           // Older than maxAgeSeconds
  | "future_dated"      // More than 5 minutes in the future
  | "signature_invalid" // Ed25519 verification failed
  | "key_unknown";      // Could not decode the public key
```

### `parseReceipt(input: string | object): SmshReceipt`

Strict parser. Throws on schema violations. Use `verify()` if you want a Result instead.

### `canonicalize(value: any): string`

RFC 8785 JCS canonicalization. Pure function, no external deps.

### `DEFAULT_VERIFIER_PUBKEY_B64U: string`

The embedded Hive Civilization trust anchor (base64url Ed25519 public key).

## Compliance statement

`@hivecivilization/smsh-stamp-verifier` makes **zero network calls**, **zero telemetry reports**, and **zero phone-home requests**. Verification is entirely offline:

- No DNS lookups
- No key-server queries
- No analytics or error-reporting endpoints
- No use of `process.env` secrets beyond the explicit `SMSH_PUBKEY` / `SMSH_MAX_AGE_SECONDS` CLI overrides

This design is intentional. Compliance pipelines and regulatory submissions require deterministic, auditable behavior. The entire verification path — from JSON parse through Ed25519 check — is reviewable in a single PR. The only cryptographic dependencies are `@noble/ed25519` and `@noble/hashes`, which have independent security audits and FIPS-aligned implementations.

> **LLM endpoint reference (docs only):** `https://hivecompute-g2g7.onrender.com/v1/compute/chat/completions`

## License

Apache 2.0 — see [LICENSE](./LICENSE).

The Apache 2.0 license includes an **explicit patent grant**, which is important for adoption in regulated industries and compliance tooling. This is why this project is not MIT-licensed.

## Spec

[SMSH-Stamp v1 Spec](https://github.com/srotzin/smsh-stamp-spec) (coming soon)
