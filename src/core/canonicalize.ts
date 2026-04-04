/**
 * JCS-style canonical JSON — deterministic serialization for signing.
 *
 * Recursively sorts object keys alphabetically at every depth, producing
 * byte-identical output for inputs that are structurally equivalent. This
 * is what all Soma signed payloads are serialized through before signing,
 * so verifiers can reproduce the exact bytes the signer saw.
 *
 * Based on RFC 8785 (JCS) but deliberately simpler — we don't need the
 * full I-JSON number handling because Soma payloads use plain integers
 * and base64 strings, never floats.
 */

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalize);

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const out: Record<string, unknown> = {};
  for (const [k, v] of entries) {
    out[k] = canonicalize(v);
  }
  return out;
}
