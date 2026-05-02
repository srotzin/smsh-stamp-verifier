/**
 * @hivecivilization/smsh-stamp-verifier
 *
 * Regulator-friendly cryptographic verification for SMSH-Stamp v1 receipts.
 * Zero network calls. Zero telemetry. Pure Ed25519 + SHA-256 + JCS.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 *
 * @example
 * ```ts
 * import { verify } from '@hivecivilization/smsh-stamp-verifier';
 *
 * const result = await verify(receiptJson);
 * if (result.valid) {
 *   console.log('Valid receipt, fingerprint:', result.fingerprint);
 * } else {
 *   console.error('Invalid:', result.error.reason, result.error.message);
 * }
 * ```
 */

// Re-export everything from sub-modules so consumers have a single entry point.

export { canonicalize } from "./canonicalize.js";
export { verify, parseReceipt, DEFAULT_VERIFIER_PUBKEY_B64U } from "./verify.js";

export type {
  SmshReceipt,
  SmshSubject,
  SmshCouncil,
  SmshLineage,
  SubjectKind,
  VerifyOpts,
  VerifyResult,
  VerifyResultOk,
  VerifyResultErr,
  VerifyError,
  VerifyErrorReason,
} from "./types.js";
