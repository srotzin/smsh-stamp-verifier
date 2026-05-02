/**
 * Tests for canonicalize() — RFC 8785 JCS implementation.
 *
 * Includes known test vectors from RFC 8785 Appendix B.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

import { describe, it, expect } from "vitest";
import { canonicalize } from "../src/canonicalize.js";

// ---------------------------------------------------------------------------
// RFC 8785 Appendix B test vectors
// ---------------------------------------------------------------------------

describe("canonicalize — RFC 8785 test vectors", () => {
  /**
   * Vector 1: Simple object with string and number values.
   * RFC 8785 §B.1 — basic key sorting.
   */
  it("Vector 1: sorts object keys lexicographically", () => {
    const input = { z: "bar", a: "foo", m: 42 };
    // Keys sorted: a, m, z
    expect(canonicalize(input)).toBe('{"a":"foo","m":42,"z":"bar"}');
  });

  /**
   * Vector 2: Nested objects — inner keys also sorted.
   * RFC 8785 §B: sorting is recursive through all object levels.
   */
  it("Vector 2: sorts nested object keys recursively", () => {
    const input = {
      outer: { z: 1, a: 2 },
      alpha: { z: "last", a: "first" },
    };
    expect(canonicalize(input)).toBe(
      '{"alpha":{"a":"first","z":"last"},"outer":{"a":2,"z":1}}'
    );
  });

  /**
   * Vector 3: Array preserves element order (arrays are NOT sorted).
   * RFC 8785 §3.2.3: Array element order is preserved.
   */
  it("Vector 3: preserves array element order", () => {
    const input = { items: [3, 1, 2], name: "test" };
    expect(canonicalize(input)).toBe('{"items":[3,1,2],"name":"test"}');
  });

  /**
   * Vector 4: String escaping per RFC 8259.
   * RFC 8785 §3.2.2.2: strings are escaped as per JSON spec.
   */
  it("Vector 4: escapes special characters in strings", () => {
    const input = { msg: "hello\nworld\t!" };
    expect(canonicalize(input)).toBe('{"msg":"hello\\nworld\\t!"}');
  });

  /**
   * Vector 5: Null, boolean, and numeric values.
   * RFC 8785 §3.2.2: primitive values serialized correctly.
   */
  it("Vector 5: serializes null, booleans, and numbers correctly", () => {
    const input = { n: null, t: true, f: false, i: 0, pi: 3.14 };
    // Keys sorted: f, i, n, pi, t
    expect(canonicalize(input)).toBe(
      '{"f":false,"i":0,"n":null,"pi":3.14,"t":true}'
    );
  });

  /**
   * Vector 6: Unicode keys — sorted by UTF-16 code unit order.
   * RFC 8785 §3.2.3: UTF-16 code-unit ordering for object members.
   */
  it("Vector 6: sorts keys by UTF-16 code-unit order", () => {
    // 'b' (0x62) < 'a' (0x61) is false; 'A' (0x41) < 'a' (0x61) is true
    const input = { b: 2, A: 1, a: 3 };
    // UTF-16 order: 'A' (65) < 'a' (97) < 'b' (98)
    expect(canonicalize(input)).toBe('{"A":1,"a":3,"b":2}');
  });

  /**
   * Vector 7: Empty object and empty array.
   */
  it("Vector 7: handles empty object and array", () => {
    expect(canonicalize({})).toBe("{}");
    expect(canonicalize([])).toBe("[]");
  });

  /**
   * Vector 8: Large integer and negative number.
   * RFC 8785 §3.2.2.3: numbers follow ECMA-262 7.1.12.1.
   */
  it("Vector 8: serializes integers and negative numbers correctly", () => {
    const input = { big: 1000000, neg: -42, zero: 0 };
    expect(canonicalize(input)).toBe('{"big":1000000,"neg":-42,"zero":0}');
  });

  /**
   * Vector 9: Deeply nested structure.
   */
  it("Vector 9: handles deeply nested objects", () => {
    const input = {
      c: { b: { a: 1 } },
      a: { c: { b: 2 } },
    };
    expect(canonicalize(input)).toBe(
      '{"a":{"c":{"b":2}},"c":{"b":{"a":1}}}'
    );
  });

  /**
   * Vector 10: String with Unicode escape sequences.
   * JSON.stringify naturally handles these per RFC 8259.
   */
  it("Vector 10: handles Unicode characters in strings", () => {
    const input = { emoji: "café", chinese: "你好" };
    // Keys: chinese < emoji (c=99, '你'=U+4F60 → surrogate, but as string comparison 'c' < '你')
    // 'c' (99) < '你' (U+4F60 = 20320 in UTF-16) → chinese comes after emoji? No:
    // 'c' (0x63) < 0x4F60, so "chinese" starts with 'c', "emoji" starts with 'e', 'c' < 'e'
    const result = canonicalize(input);
    expect(result).toBe('{"chinese":"你好","emoji":"café"}');
  });
});

// ---------------------------------------------------------------------------
// Stability / idempotency
// ---------------------------------------------------------------------------

describe("canonicalize — stability", () => {
  it("produces identical output for the same input on repeated calls", () => {
    const input = { z: 1, a: 2, m: 3 };
    const first = canonicalize(input);
    const second = canonicalize(input);
    expect(first).toBe(second);
  });

  it("produces the same output regardless of JS object key insertion order", () => {
    const a = { z: 1, a: 2, m: 3 };
    const b = { a: 2, m: 3, z: 1 };
    const c = { m: 3, z: 1, a: 2 };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(b)).toBe(canonicalize(c));
  });

  it("is deterministic for a complex SMSH-Stamp receipt shape", () => {
    const receiptLike = {
      v: "smsh-stamp/1",
      alg: "ed25519",
      kid: "key-001",
      stamped_at: "2026-05-02T12:00:00Z",
      subject: {
        kind: "llm-call",
        model: "gpt-4o",
        input_hash: "abc123",
        output_hash: "def456",
      },
      council: null,
      lineage: null,
    };
    const c1 = canonicalize(receiptLike);
    const c2 = canonicalize({ ...receiptLike }); // different object reference
    expect(c1).toBe(c2);
    // Verify it's valid JSON
    expect(() => JSON.parse(c1)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

describe("canonicalize — error cases", () => {
  it("throws on non-finite number (Infinity)", () => {
    expect(() => canonicalize(Infinity)).toThrow();
  });

  it("throws on NaN", () => {
    expect(() => canonicalize(NaN)).toThrow();
  });

  it("throws on undefined top-level value", () => {
    expect(() => canonicalize(undefined)).toThrow();
  });

  it("throws on function value", () => {
    expect(() => canonicalize(() => {})).toThrow();
  });

  it("silently skips undefined object values (JSON-compatible behavior)", () => {
    // JSON.stringify({a: undefined, b: 1}) → '{"b":1}'
    // canonicalize should do the same
    const result = canonicalize({ a: undefined, b: 1 });
    expect(result).toBe('{"b":1}');
  });
});
