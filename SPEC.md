# SMSH-Stamp Receipt Verifier — Normative Specification

**Patent reference:** USPTO Provisional 64/055,601, claims C8 and C12
**Status:** Layer C reference. Wire format normative; production-grade hardening is Layer B.
**Author:** Stephen A. Rotzin, pro se
**Date:** 2026-05-02

---

## 1. Purpose

The SMSH-Stamp is a cryptographic receipt format used throughout the HiveAttest
ecosystem to assert that a specific agent performed a specific action over a
specific content hash at a specific time. An SMSH-Stamp receipt is compact,
self-contained, and verifiable offline given only the receipt and the issuer's
public key.

However, recipients of SMSH-Stamp receipts face two practical problems:

1. **Offline verification is non-trivial.** Implementing Ed25519 verification
   with RFC 8785 JCS canonicalization correctly requires crypto and
   canonicalization libraries. Not every consumer has these readily available.

2. **Age and format checks.** A receipt may be syntactically valid but stale
   (too old to be trusted) or issued against an unknown key. A verifier must
   check expiry windows and key binding without additional infrastructure.

The SMSH-Stamp Receipt Verifier (hereafter "Verifier") solves both problems by
exposing a single HTTP endpoint. The caller submits a receipt object plus an
optional public key (if they have it out of band) and an optional maximum age
window. The Verifier returns a structured verdict: `valid: true` or
`valid: false` plus a list of reasons for any failures. A `receipt_fingerprint`
is also returned for deduplication and audit logging.

Claims C8 and C12 cover, respectively, the SMSH-Stamp receipt format itself and
the stamp-verification protocol as a distinct attestable operation.

---

## 2. Conformance Terms

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in RFC 2119.

- An **SMSH-Stamp v1 receipt** is the canonical receipt object defined in
  Section 3.2. A receipt that omits any required field is malformed and MUST
  produce `valid: false` with reason `MALFORMED_RECEIPT`.
- A **verifier** is this HiveAttest service endpoint.
- A **relying party** is any system that calls this endpoint and acts on the
  verdict.
- The verifier MUST NOT return `valid: true` if any of the failure conditions
  in Section 3.4 apply.

---

## 3. Wire Format

### 3.1 Verify Request

`POST /v1/attest/smsh/verify`

```json
{
  "receipt":          "<SMSH-Stamp v1 receipt object, required>",
  "pubkey_b64url":    "<base64url-no-pad 32-byte Ed25519 public key, optional>",
  "max_age_seconds":  "<positive integer, optional>"
}
```

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `receipt` | object | REQUIRED | The SMSH-Stamp v1 receipt to verify. See Section 3.2. |
| `pubkey_b64url` | string | OPTIONAL | base64url-encoded (no padding) 32-byte Ed25519 public key to verify the signature against. If omitted, the verifier uses the `key_id` in the receipt to look up its own known keys. If provided, it MUST match the `key_id` in the receipt. |
| `max_age_seconds` | integer | OPTIONAL | If provided and positive, the verifier rejects receipts older than `max_age_seconds` seconds relative to the current server time. |

### 3.2 SMSH-Stamp v1 Receipt Shape

```json
{
  "version":      1,
  "action_id":    "<string, required>",
  "agent_did":    "<string, required>",
  "content_hash": "<hex SHA-256 of the attested content, required>",
  "issued_at":    "<ISO-8601 UTC string, required>",
  "signing": {
    "algorithm": "EdDSA",
    "curve":     "Ed25519",
    "key_id":    "<base64url-no-pad SHA-256 of issuer public key, required>",
    "signature": "<base64url-no-pad Ed25519 signature, required>"
  }
}
```

| Field | Type | Semantics |
|-------|------|-----------|
| `version` | integer | MUST be `1` at this revision. |
| `action_id` | string | The unique identifier of the action this stamp covers. |
| `agent_did` | string | DID of the agent who performed the attested action. |
| `content_hash` | string | Lowercase hex SHA-256 of the content being attested. The verifier checks format but does not re-hash the content (the caller controls what was hashed). |
| `issued_at` | string | ISO-8601 UTC. Time of stamp issuance. Used for `max_age_seconds` checks. |
| `signing.algorithm` | string | MUST be `"EdDSA"`. |
| `signing.curve` | string | MUST be `"Ed25519"`. |
| `signing.key_id` | string | base64url-no-pad SHA-256 of the 32-byte issuer public key. |
| `signing.signature` | string | base64url-no-pad Ed25519 signature over the JCS-canonical signed body. |

### 3.3 Verify Response

```json
{
  "valid":               true,
  "reasons":             [],
  "receipt_fingerprint": "<hex SHA-256 of JCS(receipt)>",
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/smsh-stamp-verifier/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C8/C12"
  }
}
```

| Field | Type | Semantics |
|-------|------|-----------|
| `valid` | boolean | `true` if and only if all verification checks passed. |
| `reasons` | array of strings | Empty if `valid == true`. Otherwise contains one or more reason codes from Section 3.4. |
| `receipt_fingerprint` | string | Lowercase hex SHA-256 of the JCS-canonical form of the submitted `receipt` object. Suitable for use as a deduplication key or audit log entry. |

### 3.4 Failure Reason Codes

| Code | Meaning |
|------|---------|
| `MALFORMED_RECEIPT` | The receipt is missing a required field or has a field of the wrong type. |
| `UNSUPPORTED_VERSION` | `receipt.version` is not `1`. |
| `UNSUPPORTED_ALGORITHM` | `receipt.signing.algorithm` is not `"EdDSA"` or `receipt.signing.curve` is not `"Ed25519"`. |
| `UNKNOWN_KEY` | `pubkey_b64url` was not provided and the `key_id` is not in the verifier's known-key set. |
| `KEY_ID_MISMATCH` | `pubkey_b64url` was provided but `SHA-256(decode(pubkey_b64url))` does not match `receipt.signing.key_id`. |
| `INVALID_SIGNATURE` | The Ed25519 signature does not verify against the reconstructed signed body and the provided or looked-up public key. |
| `RECEIPT_EXPIRED` | `max_age_seconds` was provided and `now - issued_at > max_age_seconds`. |
| `INVALID_ISSUED_AT` | `issued_at` is not a parseable ISO-8601 UTC timestamp or is in the future beyond clock skew tolerance (30 seconds). |
| `INVALID_CONTENT_HASH` | `content_hash` is not a 64-character lowercase hex string. |

Multiple reason codes MAY be returned in a single response. The verifier SHOULD
accumulate all applicable failures rather than stopping at the first.

---

## 4. Cryptography

### 4.1 Algorithms

| Primitive | Algorithm | Reference |
|-----------|-----------|-----------|
| Signature verification | Ed25519 (EdDSA) | RFC 8032 |
| Canonicalization | JSON Canonicalization Scheme (JCS) | RFC 8785 |
| Hashing | SHA-256 | FIPS 180-4 |
| Key identifier | base64url-no-pad SHA-256 of public key bytes | — |

### 4.2 Signed Body Reconstruction

To verify the signature in a receipt, the verifier reconstructs the signed body
as the following object and JCS-canonicalizes it:

```json
{
  "action_id":    "<string>",
  "agent_did":    "<string>",
  "content_hash": "<string>",
  "issued_at":    "<string>",
  "version":      1
}
```

Note: the `signing` field is NOT included in the signed body.

```
bodyBytes = UTF-8( JCS( signedBody ) )
sigBytes  = base64url_no_pad_decode( receipt.signing.signature )
valid     = Ed25519Verify( publicKey32Bytes, bodyBytes, sigBytes )
```

### 4.3 Key Binding Check

```
expected_key_id = base64url_no_pad( SHA-256( publicKey32Bytes ) )
assert expected_key_id == receipt.signing.key_id
```

If `pubkey_b64url` is provided:
```
publicKey32Bytes = base64url_no_pad_decode( pubkey_b64url )
assert length(publicKey32Bytes) == 32
```

### 4.4 Receipt Fingerprint

```
receipt_fingerprint = lowercase_hex( SHA-256( UTF-8( JCS( receipt ) ) ) )
```

The fingerprint covers the entire submitted receipt object, including the
`signing` field. It is a stable, deterministic identifier for the receipt.

### 4.5 Age Check

```
age_seconds = (now_utc() - parse_iso8601(receipt.issued_at)).total_seconds()
assert age_seconds <= max_age_seconds
```

The server MUST use its own UTC clock for `now_utc()`. Callers MUST NOT assume
the server clock matches their own.

---

## 5. Endpoints (HTTP)

Base URL: `https://hivemorph.onrender.com`

### 5.1 Verify a Receipt

```
POST /v1/attest/smsh/verify
Content-Type: application/json
```

**Example request (with public key and age limit):**

```json
{
  "receipt": {
    "version":      1,
    "action_id":    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "agent_did":    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "content_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "issued_at":    "2026-05-02T14:00:00.000Z",
    "signing": {
      "algorithm": "EdDSA",
      "curve":     "Ed25519",
      "key_id":    "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
      "signature": "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz01"
    }
  },
  "pubkey_b64url":   "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
  "max_age_seconds": 3600
}
```

**Example response (HTTP 200, valid):**

```json
{
  "valid":               true,
  "reasons":             [],
  "receipt_fingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/smsh-stamp-verifier/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C8/C12"
  }
}
```

**Example response (HTTP 200, invalid — bad signature + expired):**

```json
{
  "valid":               false,
  "reasons":             ["INVALID_SIGNATURE", "RECEIPT_EXPIRED"],
  "receipt_fingerprint": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
  "_meta": {
    "layer":            "C",
    "production_grade": false,
    "spec_url":         "https://raw.githubusercontent.com/srotzin/smsh-stamp-verifier/main/SPEC.md",
    "patent":           "USPTO 64/055,601",
    "claim":            "C8/C12"
  }
}
```

**Error responses:**

| HTTP Status | Condition |
|-------------|-----------|
| 400 | `receipt` field is missing or not a JSON object |
| 422 | `pubkey_b64url` decodes to other than 32 bytes |

Note: a malformed receipt that is syntactically parseable returns HTTP 200 with
`valid: false` and reason `MALFORMED_RECEIPT`. HTTP 4xx is reserved for requests
where the top-level envelope is malformed.

---

## 6. Layer C Honesty Contract

Every response from this endpoint MUST carry:

- **HTTP header:** `X-Hive-Layer: C-Reference`
- **Body field `_meta.layer`:** `"C"`
- **Body field `_meta.production_grade`:** `false`
- **Body field `_meta.spec_url`:** `"https://raw.githubusercontent.com/srotzin/smsh-stamp-verifier/main/SPEC.md"`
- **Body field `_meta.patent`:** `"USPTO 64/055,601"`
- **Body field `_meta.claim`:** `"C8/C12"`

---

## 7. Receipts and Verifiability

The Verifier itself produces no new signed artifact. The `receipt_fingerprint`
is an unsigned hash and is not a receipt in the sense of claims C15–C18.
Its purpose is deduplication and audit-log keying.

A third party that wants to verify a receipt WITHOUT calling this endpoint
MUST:

1. Reconstruct `signedBody` per Section 4.2.
2. Compute `bodyBytes = UTF-8( JCS( signedBody ) )`.
3. Obtain the 32-byte Ed25519 public key (either from `pubkey_b64url` or from
   a trusted key directory keyed by `receipt.signing.key_id`).
4. Verify `Ed25519Verify( publicKey, bodyBytes, sigBytes ) == true`.
5. Verify `base64url_no_pad( SHA-256( publicKey ) ) == receipt.signing.key_id`.
6. If freshness matters, verify `issued_at` is within the required time window.

All of these steps require only standard crypto primitives and produce no
network traffic.

The Verifier endpoint is a convenience for callers who cannot or do not wish to
implement Steps 1–6 themselves. It does not add trust; it delegates verification
to the HiveAttest service, which introduces a network trust assumption. Where
possible, callers SHOULD perform offline verification.

---

## 8. Security Considerations

1. **Verification is a convenience, not a trust anchor.** Calling this endpoint
   and receiving `valid: true` means the HiveAttest server verified the receipt.
   If the server is compromised, it could return `valid: true` for a forged
   receipt. Callers with strong security requirements SHOULD perform offline
   verification (Section 7) rather than relying solely on this endpoint.

2. **Unknown-key lookups are server-trust-dependent.** When `pubkey_b64url` is
   omitted, the verifier looks up the key by `key_id` from its own key store.
   If the issuer of the receipt is not the same server, or if the server's key
   store is stale, the lookup may fail or use the wrong key.

3. **No replay prevention.** This endpoint does not record which receipts it has
   verified. A receipt that is valid once will return `valid: true` on every
   call until it expires (if `max_age_seconds` is used). Callers who need
   replay detection MUST maintain their own `receipt_fingerprint` log.

4. **Clock skew.** The `INVALID_ISSUED_AT` check accepts a 30-second future
   tolerance. Receipts from clocks more than 30 seconds ahead of the server will
   be rejected. This is not configurable at Layer C.

5. **Content hash is caller-controlled.** The `content_hash` field is stored in
   the receipt as provided by the original issuer. The verifier confirms that the
   signature over it is valid; it does NOT re-hash the underlying content.
   Verifying that `content_hash` actually corresponds to the content in question
   is the caller's responsibility.

6. **No transparency log.** Verification events are not logged to an external
   auditable store. The issuer cannot prove to a third party that a verification
   was requested or what verdict was returned.

7. **In-process key storage (for known-key lookups).** The server's own Ed25519
   public keys are stored in process memory. There is no HSM, no key vault, and
   no hardware-backed key store.

8. **Accumulation of reasons is best-effort.** The verifier SHOULD return all
   applicable failure reasons. However, some checks are short-circuited (e.g.,
   a `MALFORMED_RECEIPT` may prevent subsequent checks). Callers MUST NOT assume
   that a response with fewer reason codes means fewer problems; fix all listed
   reasons and re-submit.

---

## 9. References

- USPTO Provisional Application No. 64/055,601 — HiveAttest patent family,
  claims C8 (SMSH-Stamp receipt format) and C12 (stamp-verification protocol)
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- FIPS 180-4 — Secure Hash Standard (SHA-256)

---

## Appendix A. Test Vectors

### A.1 Deterministic Fields

The SHA-256 of the string `"hello"` (UTF-8) is:
```
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```
This value MAY be used as `content_hash` in test receipts.

### A.2 Malformed Receipt — Missing Field

```
POST https://hivemorph.onrender.com/v1/attest/smsh/verify
Content-Type: application/json

{
  "receipt": {
    "version":   1,
    "action_id": "00000000-0000-0000-0000-000000000005"
  }
}
```

Expected: HTTP 200, `{ "valid": false, "reasons": ["MALFORMED_RECEIPT"], ... }`.

### A.3 Wrong Version

```json
{
  "receipt": {
    "version":      99,
    "action_id":    "00000000-0000-0000-0000-000000000006",
    "agent_did":    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuias8siQmFe2BCM7",
    "content_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "issued_at":    "2026-05-02T14:00:00.000Z",
    "signing": {
      "algorithm": "EdDSA", "curve": "Ed25519",
      "key_id": "ZoRSOrFzpuqyLbCgJLRkpCRB2iSjT7tMmrNV9xWfBQA",
      "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
  }
}
```

Expected: HTTP 200, `{ "valid": false, "reasons": ["UNSUPPORTED_VERSION"], ... }`.

### A.4 Age Exceeded

Submit a syntactically valid receipt with `issued_at` set to `2020-01-01T00:00:00.000Z`
and `max_age_seconds: 60`.

Expected: HTTP 200, `{ "valid": false, "reasons": ["RECEIPT_EXPIRED", ...], ... }`.

### A.5 Live Round-Trip

To obtain a fresh, valid receipt to test against this endpoint, first call
`POST /v1/attest/passport/issue` (claim C15) with a `ttl_seconds` of `300`.
The response includes a `manifest.signing` block with a valid Ed25519 signature.
Construct an SMSH-Stamp v1 receipt using the same `signing` block and fields,
then submit it here. The server's public key is consistent across endpoints.
