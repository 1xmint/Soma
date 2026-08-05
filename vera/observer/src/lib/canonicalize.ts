/**
 * RFC 8785 (JCS) canonicalization, with Soma's strictness.
 *
 * Ported from js/src/canonicalize.mjs in hey-vera/soma, which is normative
 * where this and it disagree.
 *
 * This is deliberately duplicated between observer/ and host/ rather than
 * shared. Per SIGNING-SPEC.md, implementations prove agreement against shared
 * conformance vectors instead of sharing code: two implementations that agree
 * on vectors is a stronger guarantee than one library that cannot be caught
 * being wrong because it only ever runs once. The vectors are what keep these
 * two copies honest.
 *
 * Strictness matters more than completeness here. Ambiguous input is rejected,
 * never repaired, because a canonicalizer that silently normalizes turns a
 * detectable encoding bug into an undetectable signature mismatch.
 */

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

function assertUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalizationError('lone high surrogate');
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new CanonicalizationError('lone low surrogate');
    }
  }
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null';

  if (typeof value === 'string') {
    assertUnicode(value);
    // JSON.stringify already emits JCS-mandated escaping: only ", \\ and
    // control characters below 0x20, with the short forms where they exist.
    return JSON.stringify(value);
  }

  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalizationError('non-finite number');
    // -0 and 0 serialize identically but are distinguishable values. Rejecting
    // is safer than picking one, because either choice silently rewrites data.
    if (Object.is(value, -0)) throw new CanonicalizationError('negative zero');
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new CanonicalizationError(
        'unsafe integer; encode exact quantities as decimal strings',
      );
    }
    // ECMAScript Number::toString, which is what JCS mandates.
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalize(entry)).join(',')}]`;
  }

  if (typeof value === 'object') {
    // Default sort is UTF-16 code-unit order, which is what JCS requires.
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys
      .map((key) => {
        assertUnicode(key);
        if (record[key] === undefined) {
          throw new CanonicalizationError('undefined object member');
        }
        return `${JSON.stringify(key)}:${canonicalize(record[key])}`;
      })
      .join(',')}}`;
  }

  throw new CanonicalizationError(`unsupported JSON value: ${typeof value}`);
}
