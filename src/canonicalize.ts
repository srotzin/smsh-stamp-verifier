/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) implementation.
 *
 * Produces a deterministic UTF-8 encoding of a JSON value with:
 *   - Object keys sorted in UTF-16 code-unit order (lexicographic)
 *   - Numbers serialized per ECMA-262 7.1.12.1 (same as JSON.stringify)
 *   - Strings escaped per RFC 8259
 *   - No insignificant whitespace
 *
 * This is a pure function with no external dependencies.
 *
 * @license Apache-2.0
 * @copyright Copyright 2026 Hive Civilization
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Canonicalize any JSON-serializable value according to RFC 8785 (JCS).
 *
 * @param value - Any JSON-serializable value (object, array, string, number,
 *                boolean, or null). `undefined` and non-finite numbers will
 *                throw a TypeError, matching JSON.stringify behavior.
 * @returns The canonical JSON string.
 */
export function canonicalize(value: unknown): string {
  return serializeValue(value);
}

// ---------------------------------------------------------------------------
// Internal serialization
// ---------------------------------------------------------------------------

function serializeValue(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return serializeNumber(value);
  }
  if (typeof value === "string") {
    return serializeString(value);
  }
  if (Array.isArray(value)) {
    return serializeArray(value);
  }
  if (typeof value === "object") {
    return serializeObject(value as Record<string, unknown>);
  }
  // undefined, function, symbol — these are not JSON-serializable
  throw new TypeError(
    `canonicalize: non-serializable value of type ${typeof value}`
  );
}

/**
 * Serialize a number per ECMA-262 7.1.12.1 / RFC 8785 §3.2.2.3.
 * - Integers in the safe range are serialized without decimal point.
 * - Non-finite numbers are rejected.
 */
function serializeNumber(n: number): string {
  if (!isFinite(n)) {
    throw new TypeError(
      `canonicalize: non-finite number ${n} is not allowed in JCS`
    );
  }
  // JSON.stringify already implements the correct ECMA-262 number serialization.
  // For integers it emits no decimal point; for floats it uses the shortest
  // round-trip representation — exactly what RFC 8785 §3.2.2.3 requires.
  const result = JSON.stringify(n);
  if (result === undefined) {
    throw new TypeError(`canonicalize: could not serialize number ${n}`);
  }
  return result;
}

/**
 * Escape a string per RFC 8259 §7 (same as JSON.stringify).
 * RFC 8785 §3.2.2.2 specifies the exact same escaping rules.
 */
function serializeString(s: string): string {
  // JSON.stringify with a string value produces the correctly escaped,
  // double-quoted form required by both RFC 8259 and RFC 8785.
  return JSON.stringify(s);
}

/**
 * Serialize an array. Elements maintain their original order (RFC 8785 §3.2.3).
 */
function serializeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (const item of arr) {
    parts.push(serializeValue(item));
  }
  return `[${parts.join(",")}]`;
}

/**
 * Serialize an object with keys sorted in UTF-16 code-unit order (RFC 8785 §3.2.3).
 *
 * UTF-16 code-unit order is equivalent to Unicode code-point order for
 * characters in the BMP (U+0000–U+FFFF). For supplementary characters
 * (U+10000+) represented as surrogate pairs, the first surrogate (U+D800–
 * U+DBFF) sorts before the second (U+DC00–U+DFFF), which matches the
 * lexicographic comparison that String.prototype.localeCompare and the < / >
 * operators use on JavaScript strings.
 *
 * We use the built-in < operator which compares strings by UTF-16 code units,
 * exactly as specified in RFC 8785 §3.2.3.
 */
function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj);

  // Sort by UTF-16 code-unit order.  The default JS string comparison with
  // Array.prototype.sort uses the < / > operators which compare UTF-16 code
  // units — this is exactly the order RFC 8785 requires.
  keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const parts: string[] = [];
  for (const key of keys) {
    const val = obj[key];
    // Skip undefined values (same as JSON.stringify behavior)
    if (val === undefined) {
      continue;
    }
    parts.push(`${serializeString(key)}:${serializeValue(val)}`);
  }
  return `{${parts.join(",")}}`;
}
