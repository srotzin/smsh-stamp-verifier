/**
 * SMSH-Stamp v1 receipt types.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

// ---------------------------------------------------------------------------
// Receipt schema
// ---------------------------------------------------------------------------

/** Subject kind values for SMSH-Stamp v1 receipts. */
export type SubjectKind =
  | "llm-call"
  | "tool-call"
  | "data-emit"
  | "model-output"
  | "agent-step";

/** The subject of a stamped operation. */
export interface SmshSubject {
  /** What kind of operation was stamped. */
  kind: SubjectKind;
  /** Model identifier (optional). */
  model?: string;
  /** SHA-256 base64url of the canonicalized input. */
  input_hash: string;
  /** SHA-256 base64url of the canonicalized output. */
  output_hash: string;
  /** Additional context hashes (optional). */
  context_hashes?: string[];
}

/** Council consensus metadata (optional). */
export interface SmshCouncil {
  /** Council round identifier. */
  round: "R3" | "R4" | "R5" | "R6" | "ad-hoc";
  /** Score received. */
  score: number;
  /** Maximum possible score. */
  of: number;
}

/** Lineage chain metadata (optional). */
export interface SmshLineage {
  /** Base64url-encoded identifiers of parent receipts. */
  parent_receipts: string[];
  /** Depth in the lineage chain (0 = root). */
  depth: number;
}

/** A complete SMSH-Stamp v1 receipt. */
export interface SmshReceipt {
  /** Protocol version string. Must be "smsh-stamp/1". */
  v: "smsh-stamp/1";
  /** Signature algorithm. Must be "ed25519". */
  alg: "ed25519";
  /** Key identifier (base64url). */
  kid: string;
  /** ISO 8601 / RFC 3339 UTC timestamp of when the stamp was issued. */
  stamped_at: string;
  /** The subject operation that was stamped. */
  subject: SmshSubject;
  /** Council consensus info, or null if no council vote. */
  council: SmshCouncil | null;
  /** Lineage chain info, or null if this is a root receipt. */
  lineage: SmshLineage | null;
  /** Base64url Ed25519 signature over the canonicalized receipt (excluding this field). */
  sig: string;
}

// ---------------------------------------------------------------------------
// Verifier types
// ---------------------------------------------------------------------------

/** Options passed to the verify() function. */
export interface VerifyOpts {
  /**
   * Override the default trust anchor with a different Ed25519 public key
   * (base64url-encoded, 32 bytes).
   */
  pubkeyB64u?: string;
  /**
   * Reject receipts older than this many seconds (measured from `stamped_at`
   * to now). When omitted, no maximum age is enforced.
   */
  maxAgeSeconds?: number;
}

/** Discriminated union of error reasons returned on verification failure. */
export type VerifyErrorReason =
  | "parse_error"
  | "schema_invalid"
  | "version_mismatch"
  | "alg_mismatch"
  | "expired"
  | "future_dated"
  | "signature_invalid"
  | "key_unknown";

/** Error detail returned in a failed VerifyResult. */
export interface VerifyError {
  /** Machine-readable reason code. */
  reason: VerifyErrorReason;
  /** Human-readable description of what went wrong. */
  message: string;
}

/** Successful verification result. */
export interface VerifyResultOk {
  valid: true;
  /** The parsed and validated receipt. */
  receipt: SmshReceipt;
  /**
   * Hex-encoded SHA-256 of the canonical bytes that were signed.
   * Useful for audit logs.
   */
  fingerprint: string;
}

/** Failed verification result. */
export interface VerifyResultErr {
  valid: false;
  /** Structured error details. */
  error: VerifyError;
}

/** Union of success and failure results. */
export type VerifyResult = VerifyResultOk | VerifyResultErr;
