/**
 * Example: Verify a SMSH-Stamp v1 receipt from a file.
 *
 * Usage (after building):
 *   node --loader ts-node/esm examples/verify-from-file.ts path/to/receipt.json
 *
 * Or compile first:
 *   npx tsc && node dist/examples/verify-from-file.js path/to/receipt.json
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

import { readFileSync } from "node:fs";
import {
  verify,
  DEFAULT_VERIFIER_PUBKEY_B64U,
} from "@hivecivilization/smsh-stamp-verifier";

async function main(): Promise<void> {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error("Usage: verify-from-file.ts <receipt.json>");
    process.exit(1);
  }

  // Read the receipt from disk
  const raw = readFileSync(filePath, "utf-8");
  const receiptObj = JSON.parse(raw) as object;

  console.log(`Verifying receipt using default trust anchor...`);
  console.log(`Public key: ${DEFAULT_VERIFIER_PUBKEY_B64U}\n`);

  // Verify using the default trust anchor
  const result = await verify(receiptObj);

  if (result.valid) {
    console.log("✓ VALID RECEIPT");
    console.log(`  Fingerprint : ${result.fingerprint}`);
    console.log(`  Version     : ${result.receipt.v}`);
    console.log(`  Algorithm   : ${result.receipt.alg}`);
    console.log(`  Key ID      : ${result.receipt.kid}`);
    console.log(`  Stamped at  : ${result.receipt.stamped_at}`);
    console.log(`  Subject kind: ${result.receipt.subject.kind}`);
    if (result.receipt.council) {
      console.log(
        `  Council     : round=${result.receipt.council.round} score=${result.receipt.council.score}/${result.receipt.council.of}`
      );
    }
    if (result.receipt.lineage) {
      console.log(`  Lineage depth: ${result.receipt.lineage.depth}`);
      console.log(
        `  Parent receipts: ${result.receipt.lineage.parent_receipts.length}`
      );
    }
  } else {
    console.error("✗ INVALID RECEIPT");
    console.error(`  Reason  : ${result.error.reason}`);
    console.error(`  Message : ${result.error.message}`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
