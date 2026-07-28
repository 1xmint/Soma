import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { canonicalize, CanonicalizationError } from '../lib/canonicalize.js';

/**
 * Both observer/ and host/ carry their own canonicalizer and both run this
 * suite against the same vector file. That file is the contract; these two
 * implementations are merely two things currently bound by it. A Rust observer
 * must pass the identical vectors.
 *
 * Resolved from cwd because each package's tests run with its own directory as
 * the working directory.
 */
const vectors = JSON.parse(
  readFileSync('../conformance/canonicalization-vectors.json', 'utf8'),
) as {
  accept: { name: string; input: unknown; canonical: string; catches: string }[];
  reject: { name: string; reason: string }[];
};

test('canonicalization vectors: accepted forms', () => {
  for (const vector of vectors.accept) {
    assert.equal(
      canonicalize(vector.input),
      vector.canonical,
      `${vector.name} — catches: ${vector.catches}`,
    );
  }
});

test('canonicalization is idempotent over the vector corpus', () => {
  for (const vector of vectors.accept) {
    const once = canonicalize(vector.input);
    const twice = canonicalize(JSON.parse(once));
    assert.equal(twice, once, `${vector.name} did not survive a round trip`);
  }
});

// The reject cases cannot all be expressed in a JSON file: -0, NaN, Infinity,
// unsafe integers and undefined have no JSON representation, and lone
// surrogates only survive as escapes. They are constructed here and matched to
// the vector file by name so the two cannot drift apart silently.
const rejectCases: Record<string, () => unknown> = {
  'lone high surrogate': () => ({ s: JSON.parse('"\\ud800"') }),
  'lone low surrogate': () => ({ s: JSON.parse('"\\udc00"') }),
  'negative zero': () => ({ n: -0 }),
  'integer beyond the safe range': () => ({ n: 9007199254740993 }),
  'non-finite: Infinity': () => ({ n: Infinity }),
  'non-finite: NaN': () => ({ n: NaN }),
  'undefined object member': () => ({ a: undefined }),
  'large magnitude is unreachable, not exponential': () => ({ n: 1e21 }),
  'large magnitude below the JCS exponential threshold is also unreachable': () => ({ n: 1e20 }),
};

test('canonicalization vectors: rejected forms', () => {
  for (const vector of vectors.reject) {
    const build = rejectCases[vector.name];
    assert.ok(build, `no constructor for reject vector "${vector.name}"`);
    assert.throws(
      () => canonicalize(build()),
      CanonicalizationError,
      `${vector.name} was accepted but must be rejected`,
    );
  }
});

test('every reject vector has a constructor and vice versa', () => {
  const declared = new Set(vectors.reject.map((v) => v.name));
  const built = new Set(Object.keys(rejectCases));
  assert.deepEqual(
    [...declared].sort(),
    [...built].sort(),
    'the vector file and the test constructors have drifted apart',
  );
});
