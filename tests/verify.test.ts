/**
 * Tests for verify() — SMSH-Stamp v1 receipt verification.
 *
 * NOTE: These are real tests using a real Ed25519 keypair generated
 * dynamically. No mocks. No stubs.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

import { describe, it, expect, beforeAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { verify, parseReceipt, DEFAULT_VERIFIER_PUBKEY_B64U } from "../src/verify.js";
import { canonicalize } from "../src/canonicalize.js";
import type { SmshReceipt } from "../src/types.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

// Enable @noble/ed25519 sync API
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64uEncode(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function b64uDecode(input: string): Uint8Array {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "fixtures");

function loadFixture(name: string): SmshReceipt {
  const raw = readFileSync(join(fixturesDir, name), "utf-8");
  return JSON.parse(raw) as SmshReceipt;
}

/** Build and sign a receipt payload using a test private key. */
function signReceipt(
  payload: Omit<SmshReceipt, "sig">,
  privKey: Uint8Array
): SmshReceipt {
  const canonical = canonicalize(payload as unknown as Record<string, unknown>);
  const bytes = new TextEncoder().encode(canonical);
  const sig = ed.sign(bytes, privKey);
  return { ...payload, sig: b64uEncode(sig) };
}

// ---------------------------------------------------------------------------
// Test keypair — generated fresh for each test run
// ---------------------------------------------------------------------------

let testPrivKey: Uint8Array;
let testPubKeyB64u: string;

beforeAll(() => {
  testPrivKey = ed.utils.randomPrivateKey();
  const pubKey = ed.getPublicKey(testPrivKey);
  testPubKeyB64u = b64uEncode(pubKey);
});

/** A known-good receipt payload (no sig). */
function makePayload(overrides: Partial<SmshReceipt> = {}): Omit<SmshReceipt, "sig"> {
  return {
    v: "smsh-stamp/1",
    alg: "ed25519",
    kid: "test-key-001",
    stamped_at: new Date().toISOString(),
    subject: {
      kind: "llm-call",
      model: "gpt-4o",
      input_hash: "aGVsbG8gd29ybGQ",
      output_hash: "d29ybGQgaGVsbG8",
    },
    council: null,
    lineage: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Valid receipt tests
// ---------------------------------------------------------------------------

describe("verify — valid receipts", () => {
  it("verifies a freshly signed receipt", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(result.receipt.v).toBe("smsh-stamp/1");
    }
  });

  it("verifies fixture: valid_llm_call.json (pre-signed with test keypair)", async () => {
    // Load the fixture keypair used during fixture generation
    const keypair = JSON.parse(
      readFileSync(join(fixturesDir, "test_keypair.json"), "utf-8")
    ) as { pubKeyB64u: string };
    const fixture = loadFixture("valid_llm_call.json");
    const result = await verify(fixture, { pubkeyB64u: keypair.pubKeyB64u });
    expect(result.valid).toBe(true);
  });

  it("verifies fixture: valid_tool_call_with_council.json", async () => {
    const keypair = JSON.parse(
      readFileSync(join(fixturesDir, "test_keypair.json"), "utf-8")
    ) as { pubKeyB64u: string };
    const fixture = loadFixture("valid_tool_call_with_council.json");
    const result = await verify(fixture, { pubkeyB64u: keypair.pubKeyB64u });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.receipt.council?.round).toBe("R4");
      expect(result.receipt.subject.kind).toBe("tool-call");
    }
  });

  it("verifies fixture: valid_lineage_depth3.json", async () => {
    const keypair = JSON.parse(
      readFileSync(join(fixturesDir, "test_keypair.json"), "utf-8")
    ) as { pubKeyB64u: string };
    const fixture = loadFixture("valid_lineage_depth3.json");
    const result = await verify(fixture, { pubkeyB64u: keypair.pubKeyB64u });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.receipt.lineage?.depth).toBe(3);
      expect(result.receipt.lineage?.parent_receipts).toHaveLength(3);
    }
  });

  it("accepts receipt with optional subject.model and context_hashes", async () => {
    const payload = makePayload({
      subject: {
        kind: "model-output",
        model: "llama-3-70b",
        input_hash: "aGVsbG8",
        output_hash: "d29ybGQ",
        context_hashes: ["Y29udGV4dA", "bW9yZQ"],
      },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
  });

  it("accepts receipt as a JSON string", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(JSON.stringify(receipt), {
      pubkeyB64u: testPubKeyB64u,
    });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tampered receipt tests
// ---------------------------------------------------------------------------

describe("verify — tampered receipts fail", () => {
  it("fails when output_hash is mutated", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const tampered = {
      ...receipt,
      subject: { ...receipt.subject, output_hash: "dGFtcGVyZWQ" },
    };
    const result = await verify(tampered, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });

  it("fails when stamped_at is mutated", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const tampered = { ...receipt, stamped_at: "2020-01-01T00:00:00Z" };
    const result = await verify(tampered, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });

  it("fails when council.score is mutated", async () => {
    const payload = makePayload({
      council: { round: "R4", score: 8, of: 10 },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const tampered = {
      ...receipt,
      council: { ...receipt.council!, score: 10 },
    };
    const result = await verify(tampered, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });

  it("fails when sig is zeroed out", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const tampered = { ...receipt, sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
    const result = await verify(tampered, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });
});

// ---------------------------------------------------------------------------
// Version / algorithm mismatch
// ---------------------------------------------------------------------------

describe("verify — version and algorithm checks", () => {
  it("fails when v is wrong version", async () => {
    const payload = makePayload({ v: "smsh-stamp/2" as "smsh-stamp/1" });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("version_mismatch");
  });

  it("fails when alg is not ed25519", async () => {
    const payload = makePayload({ alg: "ecdsa" as "ed25519" });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("alg_mismatch");
  });
});

// ---------------------------------------------------------------------------
// Expiry and clock skew
// ---------------------------------------------------------------------------

describe("verify — expiry and clock skew", () => {
  it("fails when receipt is older than maxAgeSeconds", async () => {
    const oldDate = new Date(Date.now() - 7200 * 1000).toISOString(); // 2h ago
    const payload = makePayload({ stamped_at: oldDate });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, {
      pubkeyB64u: testPubKeyB64u,
      maxAgeSeconds: 3600, // 1 hour
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("expired");
  });

  it("passes when receipt is within maxAgeSeconds", async () => {
    const recentDate = new Date(Date.now() - 60 * 1000).toISOString(); // 1 min ago
    const payload = makePayload({ stamped_at: recentDate });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, {
      pubkeyB64u: testPubKeyB64u,
      maxAgeSeconds: 3600,
    });
    expect(result.valid).toBe(true);
  });

  it("passes when no maxAgeSeconds is set (old receipt is fine)", async () => {
    const oldDate = "2020-01-01T00:00:00Z";
    const payload = makePayload({ stamped_at: oldDate });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
  });

  it("fails when stamped_at is more than 5 minutes in the future", async () => {
    const futureDate = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min from now
    const payload = makePayload({ stamped_at: futureDate });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("future_dated");
  });

  it("accepts stamps within 5-minute future skew tolerance", async () => {
    const nearFuture = new Date(Date.now() + 2 * 60 * 1000).toISOString(); // 2 min from now
    const payload = makePayload({ stamped_at: nearFuture });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Wrong pubkey
// ---------------------------------------------------------------------------

describe("verify — wrong public key", () => {
  it("fails when verified against a different public key", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);

    // Generate a second, unrelated keypair
    const otherPrivKey = ed.utils.randomPrivateKey();
    const otherPubKey = ed.getPublicKey(otherPrivKey);
    const otherPubKeyB64u = b64uEncode(otherPubKey);

    const result = await verify(receipt, { pubkeyB64u: otherPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });

  it("reports key_unknown when pubkey is malformed", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: "!!!notvalidbase64url" });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("key_unknown");
  });

  it("uses DEFAULT_VERIFIER_PUBKEY_B64U when opts.pubkeyB64u not set", async () => {
    // The default key is a real key; we just test that a receipt NOT signed
    // with it fails cleanly.
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt); // No opts — uses default key
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });
});

// ---------------------------------------------------------------------------
// Schema fuzz
// ---------------------------------------------------------------------------

describe("verify — schema validation", () => {
  it("fails on unknown top-level key", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, unknownKey: "boom" } as unknown as SmshReceipt,
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails on missing required field (kid)", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const { kid: _kid, ...noKid } = receipt;
    const result = await verify(noKid as unknown as SmshReceipt, {
      pubkeyB64u: testPubKeyB64u,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails on missing required field (sig)", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const { sig: _sig, ...noSig } = receipt;
    const result = await verify(noSig as unknown as SmshReceipt, {
      pubkeyB64u: testPubKeyB64u,
    });
    expect(result.valid).toBe(false);
  });

  it("fails on wrong type for council.score (string instead of number)", async () => {
    const payload = makePayload({
      council: { round: "R4", score: "eight" as unknown as number, of: 10 },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt as unknown as SmshReceipt, {
      pubkeyB64u: testPubKeyB64u,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails on invalid subject.kind", async () => {
    const payload = makePayload({
      subject: {
        kind: "database-query" as "llm-call",
        input_hash: "x",
        output_hash: "y",
      },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails on invalid JSON string", async () => {
    const result = await verify("{ this is not json }", {
      pubkeyB64u: testPubKeyB64u,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("parse_error");
  });

  it("fails when subject is not an object", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, subject: "not-an-object" } as unknown as SmshReceipt,
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when council is missing entirely (not null)", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const { council: _c, ...noCouncil } = receipt;
    const result = await verify(noCouncil as unknown as SmshReceipt, {
      pubkeyB64u: testPubKeyB64u,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("does NOT fail when maxAgeSeconds is not set and receipt is old", async () => {
    const oldDate = "2019-01-01T00:00:00Z";
    const payload = makePayload({ stamped_at: oldDate });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    // Should pass — old receipts are valid when no expiry is set
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// parseReceipt
// ---------------------------------------------------------------------------

describe("parseReceipt", () => {
  it("parses a valid JSON string", () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const parsed = parseReceipt(JSON.stringify(receipt));
    expect(parsed.v).toBe("smsh-stamp/1");
    expect(parsed.alg).toBe("ed25519");
  });

  it("parses a plain object", () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const parsed = parseReceipt(receipt);
    expect(parsed.sig).toBe(receipt.sig);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseReceipt("not json")).toThrow();
  });

  it("throws on schema violation", () => {
    expect(() => parseReceipt({ v: "smsh-stamp/1", alg: "ed25519" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Canonicalization stability
// ---------------------------------------------------------------------------

describe("verify — canonicalization stability", () => {
  it("produces the same fingerprint for identical receipts", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const r1 = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    const r2 = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(r1.valid && r2.valid).toBe(true);
    if (r1.valid && r2.valid) {
      expect(r1.fingerprint).toBe(r2.fingerprint);
    }
  });

  it("different key order in an object does not affect verification", async () => {
    // Build a receipt, then reconstruct with keys in a different order
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);

    // Manually reorder keys in subject
    const reordered = {
      ...receipt,
      subject: {
        output_hash: receipt.subject.output_hash,
        input_hash: receipt.subject.input_hash,
        kind: receipt.subject.kind,
        model: receipt.subject.model,
      },
    };

    const result = await verify(reordered, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Additional branch coverage
// ---------------------------------------------------------------------------

describe("verify — additional schema branches", () => {
  it("fails when v is not a string", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, v: 1 as unknown as "smsh-stamp/1" },
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when alg is not a string", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, alg: null as unknown as "ed25519" },
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when stamped_at is not a string", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, stamped_at: 12345 as unknown as string },
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when sig is not a string", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, sig: null as unknown as string },
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when council.round is invalid", async () => {
    const payload = makePayload({
      council: { round: "R99" as "R3", score: 5, of: 10 },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when council.of is not a number", async () => {
    const payload = makePayload({
      council: { round: "R4", score: 5, of: "ten" as unknown as number },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when lineage is not null and not an object", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(
      { ...receipt, lineage: "root" as unknown as null },
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when lineage.parent_receipts contains non-strings", async () => {
    const payload = makePayload({
      lineage: {
        parent_receipts: [123, 456] as unknown as string[],
        depth: 2,
      },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when lineage.depth is negative", async () => {
    const payload = makePayload({
      lineage: { parent_receipts: ["abc"], depth: -1 },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("fails when pubkey has wrong byte length (not 32 bytes)", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    // A valid b64u string that decodes to more than 32 bytes
    const wrongLengthKey = b64uEncode(new Uint8Array(16)); // only 16 bytes
    const result = await verify(receipt, { pubkeyB64u: wrongLengthKey });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("key_unknown");
  });

  it("fails when sig has wrong byte length (not 64 bytes)", async () => {
    const payload = makePayload();
    const receipt = signReceipt(payload, testPrivKey);
    // Replace sig with a short one
    const shortSig = b64uEncode(new Uint8Array(32)); // only 32 bytes
    const result = await verify(
      { ...receipt, sig: shortSig },
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("signature_invalid");
  });

  it("fails on input that is not an object (array)", async () => {
    const result = await verify(
      [] as unknown as SmshReceipt,
      { pubkeyB64u: testPubKeyB64u }
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("parse_error");
  });

  it("fails when stamped_at is a non-parseable date string", async () => {
    const payload = makePayload({ stamped_at: "not-a-date" });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error.reason).toBe("schema_invalid");
  });

  it("accepts ad-hoc council round", async () => {
    const payload = makePayload({
      council: { round: "ad-hoc", score: 1, of: 1 },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
  });

  it("accepts all valid subject kinds", async () => {
    const kinds: Array<"llm-call" | "tool-call" | "data-emit" | "model-output" | "agent-step"> = [
      "llm-call",
      "tool-call",
      "data-emit",
      "model-output",
      "agent-step",
    ];
    for (const kind of kinds) {
      const payload = makePayload({ subject: { kind, input_hash: "a", output_hash: "b" } });
      const receipt = signReceipt(payload, testPrivKey);
      const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
      expect(result.valid).toBe(true);
    }
  });

  it("passes verify with subject.model undefined (no model field)", async () => {
    const payload = makePayload({
      subject: {
        kind: "data-emit",
        input_hash: "inp",
        output_hash: "out",
        // no model, no context_hashes
      },
    });
    const receipt = signReceipt(payload, testPrivKey);
    const result = await verify(receipt, { pubkeyB64u: testPubKeyB64u });
    expect(result.valid).toBe(true);
  });
});
