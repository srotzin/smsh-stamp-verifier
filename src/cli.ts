#!/usr/bin/env node
/**
 * smsh-verify CLI
 *
 * Usage:
 *   smsh-verify <receipt-file.json>
 *   cat receipt.json | smsh-verify
 *
 * Exits with code 0 on valid receipt, 1 on invalid or error.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

import { readFileSync } from "node:fs";
import { verify } from "./verify.js";
import type { SmshReceipt } from "./types.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let raw: string;

  if (args.length > 0 && args[0] !== "-") {
    // Read from file
    const filePath = args[0];
    try {
      raw = readFileSync(filePath, "utf-8");
    } catch (e) {
      console.error(
        `smsh-verify: Cannot read file "${filePath}": ${
          e instanceof Error ? e.message : String(e)
        }`
      );
      process.exit(1);
    }
  } else {
    // Read from stdin
    raw = await readStdin();
  }

  // Parse opts from env / flags (minimal: pubkey override and maxAge)
  const pubkeyB64u = process.env["SMSH_PUBKEY"] ?? undefined;
  const maxAgeEnv = process.env["SMSH_MAX_AGE_SECONDS"];
  const maxAgeSeconds = maxAgeEnv ? parseInt(maxAgeEnv, 10) : undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    console.error(
      `smsh-verify: Invalid JSON — ${e instanceof Error ? e.message : String(e)}`
    );
    process.exit(1);
  }

  const result = await verify(parsed as SmshReceipt, {
    pubkeyB64u,
    maxAgeSeconds,
  });

  if (result.valid) {
    console.log(
      JSON.stringify(
        {
          valid: true,
          fingerprint: result.fingerprint,
          kid: result.receipt.kid,
          stamped_at: result.receipt.stamped_at,
          subject_kind: result.receipt.subject.kind,
        },
        null,
        2
      )
    );
    process.exit(0);
  } else {
    console.error(
      JSON.stringify(
        {
          valid: false,
          reason: result.error.reason,
          message: result.error.message,
        },
        null,
        2
      )
    );
    process.exit(1);
  }
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk: string) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

main().catch((err) => {
  console.error("smsh-verify: Unexpected error:", err);
  process.exit(1);
});
