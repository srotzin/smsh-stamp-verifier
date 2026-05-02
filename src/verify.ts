/**
 * SMSH-Stamp v1 receipt verification.
 *
 * This module is the core of the verifier. It performs:
 *   1. Schema validation (strict, no unknown top-level keys)
 *   2. Version and algorithm checks
 *   3. Timestamp validation (clock skew + optional max age)
 *   4. JCS canonicalization of the receipt minus the `sig` field
 *   5. SHA-256 fingerprint computation
 *   6. Ed25519 signature verification via @noble/ed25519
 *
 * It NEVER throws — all failures are returned as VerifyResultErr values.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { canonicalize } from "./canonicalize.js";
import type {
  SmshReceipt,
  SmshCouncil,
  SmshLineage,
  SmshSubject,
  VerifyError,
  VerifyErrorReason,
  VerifyOpts,
  VerifyResult,
} from "./types.js";

// Enable synchronous Ed25519 operations by wiring in @noble/hashes sha512.
// This is required by @noble/ed25519 v2's optional sync API.
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Default trust anchor
// ---------------------------------------------------------------------------

/**
 * Default Ed25519 public key (base64url, 32 bytes) embedded as a trust
 * anchor. This is the Hive Civilization SMSH-Stamp v1 verifier key.
 *
 * Consumers may override this via `VerifyOpts.pubkeyB64u`.
 */
export const DEFAULT_VERIFIER_PUBKEY_B64U =
  "8DBPaWbs1uBGOVPEK-ktrTbtR5sz3ST5pKLe8te9Bq4";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum clock skew in seconds: receipts may not be more than 5 min in the future. */
const MAX_FUTURE_SKEW_SECONDS = 5 * 60;

/** The only supported protocol version. */
const SUPPORTED_VERSION = "smsh-stamp/1";

/** The only supported signature algorithm. */
const SUPPORTED_ALG = "ed25519";

/** All valid top-level keys for an SmshReceipt. */
const VALID_TOP_LEVEL_KEYS = new Set([
  "v",
  "alg",
  "kid",
  "stamped_at",
  "subject",
  "council",
  "lineage",
  "sig",
]);

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/** Decode a base64url string to Uint8Array. */
function b64uDecode(input: string): Uint8Array {
  // Replace base64url characters with standard base64 characters.
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  // Pad to a multiple of 4.
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Encode a Uint8Array to lowercase hex. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Build a VerifyResultErr from a reason and message. */
function fail(reason: VerifyErrorReason, message: string): VerifyResult {
  return { valid: false, error: { reason, message } satisfies VerifyError };
}

// ---------------------------------------------------------------------------
// Schema validators
// ---------------------------------------------------------------------------

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

/** Validate that `obj` is a non-null plain object. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validate the `subject` sub-object. */
function validateSubject(
  s: unknown
): { ok: true; value: SmshSubject } | { ok: false; error: string } {
  if (!isPlainObject(s)) {
    return { ok: false, error: '"subject" must be an object' };
  }

  const VALID_KINDS = new Set([
    "llm-call",
    "tool-call",
    "data-emit",
    "model-output",
    "agent-step",
  ]);
  if (!isNonEmptyString(s["kind"]) || !VALID_KINDS.has(s["kind"])) {
    return {
      ok: false,
      error: `"subject.kind" must be one of: ${[...VALID_KINDS].join(", ")}`,
    };
  }
  if (!isNonEmptyString(s["input_hash"])) {
    return { ok: false, error: '"subject.input_hash" must be a non-empty string' };
  }
  if (!isNonEmptyString(s["output_hash"])) {
    return {
      ok: false,
      error: '"subject.output_hash" must be a non-empty string',
    };
  }
  if (s["model"] !== undefined && typeof s["model"] !== "string") {
    return { ok: false, error: '"subject.model" must be a string if present' };
  }
  if (s["context_hashes"] !== undefined) {
    if (
      !Array.isArray(s["context_hashes"]) ||
      !(s["context_hashes"] as unknown[]).every((h) => typeof h === "string")
    ) {
      return {
        ok: false,
        error: '"subject.context_hashes" must be an array of strings if present',
      };
    }
  }

  const result: SmshSubject = {
    kind: s["kind"] as SmshSubject["kind"],
    input_hash: s["input_hash"] as string,
    output_hash: s["output_hash"] as string,
  };
  if (typeof s["model"] === "string") result.model = s["model"];
  if (Array.isArray(s["context_hashes"]))
    result.context_hashes = s["context_hashes"] as string[];

  return { ok: true, value: result };
}

/** Validate the `council` sub-object (nullable). */
function validateCouncil(
  c: unknown
): { ok: true; value: SmshCouncil | null } | { ok: false; error: string } {
  if (c === null) return { ok: true, value: null };
  if (!isPlainObject(c)) {
    return { ok: false, error: '"council" must be an object or null' };
  }
  const VALID_ROUNDS = new Set(["R3", "R4", "R5", "R6", "ad-hoc"]);
  if (!isNonEmptyString(c["round"]) || !VALID_ROUNDS.has(c["round"])) {
    return {
      ok: false,
      error: `"council.round" must be one of: ${[...VALID_ROUNDS].join(", ")}`,
    };
  }
  if (!isFiniteNumber(c["score"])) {
    return { ok: false, error: '"council.score" must be a finite number' };
  }
  if (!isFiniteNumber(c["of"])) {
    return { ok: false, error: '"council.of" must be a finite number' };
  }
  return {
    ok: true,
    value: {
      round: c["round"] as SmshCouncil["round"],
      score: c["score"] as number,
      of: c["of"] as number,
    },
  };
}

/** Validate the `lineage` sub-object (nullable). */
function validateLineage(
  l: unknown
): { ok: true; value: SmshLineage | null } | { ok: false; error: string } {
  if (l === null) return { ok: true, value: null };
  if (!isPlainObject(l)) {
    return { ok: false, error: '"lineage" must be an object or null' };
  }
  if (
    !Array.isArray(l["parent_receipts"]) ||
    !(l["parent_receipts"] as unknown[]).every((r) => typeof r === "string")
  ) {
    return {
      ok: false,
      error: '"lineage.parent_receipts" must be an array of strings',
    };
  }
  if (!isFiniteNumber(l["depth"]) || !Number.isInteger(l["depth"]) || (l["depth"] as number) < 0) {
    return {
      ok: false,
      error: '"lineage.depth" must be a non-negative integer',
    };
  }
  return {
    ok: true,
    value: {
      parent_receipts: l["parent_receipts"] as string[],
      depth: l["depth"] as number,
    },
  };
}

/**
 * Strictly validate a plain object as a SmshReceipt.
 *
 * Returns a typed SmshReceipt on success, or an error message on failure.
 */
function validateSchema(
  obj: Record<string, unknown>
): { ok: true; receipt: SmshReceipt } | { ok: false; error: string } {
  // Reject unknown top-level keys.
  for (const key of Object.keys(obj)) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) {
      return { ok: false, error: `Unknown top-level key: "${key}"` };
    }
  }

  // Required top-level fields.
  if (!isNonEmptyString(obj["v"])) {
    return { ok: false, error: '"v" must be a non-empty string' };
  }
  if (!isNonEmptyString(obj["alg"])) {
    return { ok: false, error: '"alg" must be a non-empty string' };
  }
  if (!isNonEmptyString(obj["kid"])) {
    return { ok: false, error: '"kid" must be a non-empty string' };
  }
  if (!isNonEmptyString(obj["stamped_at"])) {
    return { ok: false, error: '"stamped_at" must be a non-empty string' };
  }
  if (!isNonEmptyString(obj["sig"])) {
    return { ok: false, error: '"sig" must be a non-empty string' };
  }

  // subject
  const subjectResult = validateSubject(obj["subject"]);
  if (!subjectResult.ok) return { ok: false, error: subjectResult.error };

  // council (must exist even if null)
  if (!("council" in obj)) {
    return { ok: false, error: '"council" field is required (may be null)' };
  }
  const councilResult = validateCouncil(obj["council"]);
  if (!councilResult.ok) return { ok: false, error: councilResult.error };

  // lineage (must exist even if null)
  if (!("lineage" in obj)) {
    return { ok: false, error: '"lineage" field is required (may be null)' };
  }
  const lineageResult = validateLineage(obj["lineage"]);
  if (!lineageResult.ok) return { ok: false, error: lineageResult.error };

  const receipt: SmshReceipt = {
    v: obj["v"] as "smsh-stamp/1",
    alg: obj["alg"] as "ed25519",
    kid: obj["kid"] as string,
    stamped_at: obj["stamped_at"] as string,
    subject: subjectResult.value,
    council: councilResult.value,
    lineage: lineageResult.value,
    sig: obj["sig"] as string,
  };

  return { ok: true, receipt };
}

// ---------------------------------------------------------------------------
// parseReceipt
// ---------------------------------------------------------------------------

/**
 * Parse a SMSH-Stamp v1 receipt from a JSON string or a plain object.
 *
 * @throws {Error} on parse failure (use verify() if you want a Result instead).
 */
export function parseReceipt(input: string | object): SmshReceipt {
  let obj: unknown;
  if (typeof input === "string") {
    try {
      obj = JSON.parse(input);
    } catch (e) {
      throw new Error(
        `parseReceipt: invalid JSON — ${e instanceof Error ? e.message : String(e)}`
      );
    }
  } else {
    obj = input;
  }

  if (!isPlainObject(obj)) {
    throw new Error("parseReceipt: input must be a JSON object");
  }

  const result = validateSchema(obj);
  if (!result.ok) {
    throw new Error(`parseReceipt: schema error — ${result.error}`);
  }
  return result.receipt;
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/**
 * Verify a SMSH-Stamp v1 receipt.
 *
 * This function never throws. All failure modes are captured in the returned
 * VerifyResult discriminated union.
 *
 * @param receipt - The receipt to verify (already-parsed SmshReceipt or a
 *                  raw object/string — will be parsed internally).
 * @param opts    - Optional verification options.
 */
export async function verify(
  receipt: SmshReceipt | Record<string, unknown> | string,
  opts: VerifyOpts = {}
): Promise<VerifyResult> {
  // -----------------------------------------------------------------------
  // Step 1: Parse / schema-validate
  // -----------------------------------------------------------------------
  let parsed: SmshReceipt;
  try {
    if (typeof receipt === "string" || !("v" in (receipt as object))) {
      // Treat as raw input
      parsed = parseReceipt(receipt as string | object);
    } else {
      // Already looks like a typed receipt — re-validate for safety
      if (!isPlainObject(receipt)) {
        return fail("parse_error", "Receipt must be a JSON object");
      }
      const schemaResult = validateSchema(receipt as Record<string, unknown>);
      if (!schemaResult.ok) {
        return fail("schema_invalid", schemaResult.error);
      }
      parsed = schemaResult.receipt;
    }
  } catch (e) {
    return fail(
      "parse_error",
      `Failed to parse receipt: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  // -----------------------------------------------------------------------
  // Step 2: Version check
  // -----------------------------------------------------------------------
  if (parsed.v !== SUPPORTED_VERSION) {
    return fail(
      "version_mismatch",
      `Unsupported receipt version "${parsed.v}" — expected "${SUPPORTED_VERSION}"`
    );
  }

  // -----------------------------------------------------------------------
  // Step 3: Algorithm check
  // -----------------------------------------------------------------------
  if (parsed.alg !== SUPPORTED_ALG) {
    return fail(
      "alg_mismatch",
      `Unsupported algorithm "${parsed.alg}" — expected "${SUPPORTED_ALG}"`
    );
  }

  // -----------------------------------------------------------------------
  // Step 4: Timestamp validation
  // -----------------------------------------------------------------------
  let stampedAt: Date;
  try {
    stampedAt = new Date(parsed.stamped_at);
    if (isNaN(stampedAt.getTime())) {
      throw new Error("Invalid date");
    }
  } catch {
    return fail(
      "schema_invalid",
      `"stamped_at" is not a valid RFC 3339 date: "${parsed.stamped_at}"`
    );
  }

  const nowMs = Date.now();
  const stampedAtMs = stampedAt.getTime();

  // Reject future-dated receipts (beyond clock skew tolerance)
  if (stampedAtMs > nowMs + MAX_FUTURE_SKEW_SECONDS * 1000) {
    return fail(
      "future_dated",
      `Receipt is dated ${Math.round(
        (stampedAtMs - nowMs) / 1000
      )} seconds in the future (tolerance: ${MAX_FUTURE_SKEW_SECONDS}s)`
    );
  }

  // Reject expired receipts (if maxAgeSeconds is set)
  if (opts.maxAgeSeconds !== undefined) {
    const ageSeconds = (nowMs - stampedAtMs) / 1000;
    if (ageSeconds > opts.maxAgeSeconds) {
      return fail(
        "expired",
        `Receipt is ${Math.round(ageSeconds)}s old, which exceeds the maximum age of ${opts.maxAgeSeconds}s`
      );
    }
  }

  // -----------------------------------------------------------------------
  // Step 5: Build canonical payload (receipt minus `sig`)
  // -----------------------------------------------------------------------
  // Construct a copy of the receipt object without the `sig` field and
  // canonicalize it per RFC 8785.
  const payloadObj: Record<string, unknown> = {
    v: parsed.v,
    alg: parsed.alg,
    kid: parsed.kid,
    stamped_at: parsed.stamped_at,
    subject: parsed.subject as unknown as Record<string, unknown>,
    council: parsed.council,
    lineage: parsed.lineage,
  };

  let canonicalStr: string;
  try {
    canonicalStr = canonicalize(payloadObj);
  } catch (e) {
    return fail(
      "schema_invalid",
      `Failed to canonicalize receipt: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  const canonicalBytes = new TextEncoder().encode(canonicalStr);

  // -----------------------------------------------------------------------
  // Step 6: SHA-256 fingerprint
  // -----------------------------------------------------------------------
  const fingerprintBytes = sha256(canonicalBytes);
  const fingerprint = bytesToHex(fingerprintBytes);

  // -----------------------------------------------------------------------
  // Step 7: Decode public key and signature
  // -----------------------------------------------------------------------
  const pubkeyB64u = opts.pubkeyB64u ?? DEFAULT_VERIFIER_PUBKEY_B64U;

  let pubKeyBytes: Uint8Array;
  try {
    pubKeyBytes = b64uDecode(pubkeyB64u);
    if (pubKeyBytes.length !== 32) {
      throw new Error(`Expected 32 bytes, got ${pubKeyBytes.length}`);
    }
  } catch (e) {
    return fail(
      "key_unknown",
      `Failed to decode public key: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = b64uDecode(parsed.sig);
    if (sigBytes.length !== 64) {
      throw new Error(`Expected 64 bytes, got ${sigBytes.length}`);
    }
  } catch (e) {
    return fail(
      "signature_invalid",
      `Failed to decode signature: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  // -----------------------------------------------------------------------
  // Step 8: Ed25519 signature verification
  // -----------------------------------------------------------------------
  // Note: @noble/ed25519 verifyAsync(signature, message, publicKey)
  // The message passed to Ed25519 is the raw canonical bytes (not the hash —
  // Ed25519 hashes internally via SHA-512 as per RFC 8032).
  let isValid: boolean;
  try {
    isValid = await ed.verifyAsync(sigBytes, canonicalBytes, pubKeyBytes);
  } catch (e) {
    return fail(
      "signature_invalid",
      `Signature verification threw: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  if (!isValid) {
    return fail(
      "signature_invalid",
      "Ed25519 signature does not match the canonicalized receipt payload"
    );
  }

  // -----------------------------------------------------------------------
  // Success
  // -----------------------------------------------------------------------
  return { valid: true, receipt: parsed, fingerprint };
}
