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

/**
 * Produce signing bytes with a domain tag prepended to the canonical JSON.
 *
 * Every Soma signing primitive that calls this uses a unique domain string
 * (e.g. `soma/delegation/v1`, `soma/revocation/v1`, `soma/lineage/v1`). The
 * domain is part of the signed bytes, so a signature made over one credential
 * type cannot be reinterpreted as a signature over another even if the
 * payload shapes happen to overlap. This is defense-in-depth against
 * cross-protocol signature replay.
 *
 * Format: `${domain}\n${canonicalJson(payload)}` as UTF-8 bytes. The newline
 * separator is safe because canonical JSON never contains unescaped newlines
 * at the top level, so parsing is unambiguous if a verifier ever needs to
 * reconstruct the boundary.
 */
export function domainSigningInput(domain: string, payload: unknown): Uint8Array {
  if (!domain || domain.length === 0) {
    throw new Error('domainSigningInput: domain must be a non-empty string');
  }
  return new TextEncoder().encode(`${domain}\n${canonicalJson(payload)}`);
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
