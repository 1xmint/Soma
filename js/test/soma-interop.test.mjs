import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEd25519 } from "../src/crypto.mjs";

/**
 * Interop with Vera, against the same fixed vectors.
 *
 * Soma and Vera implement base58btc, multicodec tagging and Ed25519
 * verification separately. This file and its counterpart in hey-vera/vera check
 * identical frozen bytes, so a change to either codec breaks a test instead of
 * silently breaking the ability of a Soma agent and a Vera observer to be the
 * same identity.
 *
 * The values are fixed, not generated here. A test that produces its own input
 * on both sides proves only that one implementation agrees with itself.
 */
const vectors = JSON.parse(
  readFileSync(path.join(fileURLToPath(new URL("../conformance/", import.meta.url)), "soma-identity-vectors.json"), "utf8")
);

test("a did:key carries the multibase key it commits to", () => {
  for (const vector of vectors.vectors) {
    assert.equal(
      vector.did,
      `did:key:${vector.public_key_multibase}`,
      `${vector.name}: the identifier must be the key, not a reference to it`
    );
  }
});

test("soma verifies the frozen signature under the key its DID commits to", () => {
  for (const vector of vectors.vectors) {
    const message = Buffer.from(vector.message_utf8, "utf8");
    assert.ok(
      verifyEd25519(vector.public_key_multibase, message, vector.signature_base64),
      `${vector.name}: the frozen signature did not verify`
    );
  }
});

test("a tampered message does not verify", () => {
  for (const vector of vectors.vectors) {
    const tampered = Buffer.from(`${vector.message_utf8}x`, "utf8");
    assert.ok(!verifyEd25519(vector.public_key_multibase, tampered, vector.signature_base64));
  }
});

test("a different key does not verify the signature", () => {
  const vector = vectors.vectors[0];
  const other = vectors.reject.find((entry) => entry.did.startsWith("did:key:"));
  if (!other) return;
  assert.ok(
    !verifyEd25519(other.did.slice("did:key:".length), Buffer.from(vector.message_utf8, "utf8"), vector.signature_base64)
  );
});
