/**
 * Attack #12 — Selective-disclosure field swap.
 *
 * Scenario:
 *   Issuer signs a disclosable document about Alice: {name, dob, country,
 *   kyc-tier}. Alice presents to a verifier that only cares about kyc-tier.
 *   Eve wants to show a verifier a FAKE claim: "my kyc-tier is 5" when the
 *   issuer actually signed "kyc-tier = 1".
 *
 *   Variants:
 *     - Swap commitment positions: claim the country commitment is actually
 *       the kyc-tier commitment.
 *     - Substitute disclosed value: claim `value=5` with the legitimate salt
 *       for field `kyc-tier` but a different value.
 *     - Omit a field entirely (fewer commitments than the issuer signed).
 *
 * Defense: commitments are salted AND bind the field NAME. Root computation
 * sorts by field name — any omission, swap, or value mutation changes the
 * root, which the issuer's signature is over.
 *
 * Primitives composed:
 *   selective-disclosure · commitment root · salted field binding
 */

import { describe, it, expect } from "vitest";
import {
  createDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
} from "../../src/heart/selective-disclosure.js";
import { makeIdentity, failedWith } from "./_harness.js";

function makeDoc() {
  const issuer = makeIdentity();
  const subject = makeIdentity();
  const doc = createDisclosableDocument({
    issuerDid: issuer.did,
    issuerPublicKey: issuer.publicKey,
    issuerSigningKey: issuer.signingKey,
    subjectDid: subject.did,
    claims: {
      name: "Alice",
      dob: "1990-01-01",
      country: "US",
      "kyc-tier": 1,
    },
  });
  return { issuer, subject, doc };
}

describe("Attack #12: selective-disclosure field swap", () => {
  it("substituting a disclosed value with the wrong salt breaks the root", () => {
    const { doc } = makeDoc();
    const proof = createDisclosureProof(doc, ["kyc-tier"]);

    // Eve changes the disclosed value to 5 (claiming tier 5).
    const tampered = {
      ...proof,
      disclosed: {
        "kyc-tier": {
          value: 5, // was 1
          salt: proof.disclosed["kyc-tier"].salt,
        },
      },
    };
    const result = verifyDisclosureProof(tampered);
    expect(result.valid).toBe(false);
    expect(failedWith(result, "root mismatch")).toBe(true);
  });

  it("using country's salt with kyc-tier's name fails field binding", () => {
    const { doc } = makeDoc();
    const proof = createDisclosureProof(doc, ["kyc-tier", "country"]);

    // Eve tries to use country's salt as if it were kyc-tier's.
    const tampered = {
      ...proof,
      disclosed: {
        "kyc-tier": {
          value: 5,
          salt: proof.disclosed["country"].salt,
        },
        country: proof.disclosed["country"],
      },
    };
    const result = verifyDisclosureProof(tampered);
    expect(result.valid).toBe(false);
  });

  it("dropping a field from undisclosedCommitments breaks the root", () => {
    const { doc } = makeDoc();
    const proof = createDisclosureProof(doc, ["kyc-tier"]);

    // Eve omits a withheld-field commitment hoping to shrink the root.
    const tampered = {
      ...proof,
      undisclosedCommitments: Object.fromEntries(
        Object.entries(proof.undisclosedCommitments).slice(0, -1),
      ),
    };
    const result = verifyDisclosureProof(tampered);
    expect(result.valid).toBe(false);
  });

  it("adding an UNSIGNED extra field to disclosed breaks the root", () => {
    const { doc } = makeDoc();
    const proof = createDisclosureProof(doc, ["kyc-tier"]);

    // Eve appends a fake field the issuer never signed.
    const tampered = {
      ...proof,
      disclosed: {
        ...proof.disclosed,
        secret_access_level: { value: "admin", salt: "aaaa" },
      },
    };
    const result = verifyDisclosureProof(tampered);
    expect(result.valid).toBe(false);
  });

  it("field in both disclosed and undisclosed fails", () => {
    const { doc } = makeDoc();
    const proof = createDisclosureProof(doc, ["kyc-tier"]);
    // Eve also leaves kyc-tier's commitment in the undisclosed bucket.
    const tampered = {
      ...proof,
      undisclosedCommitments: {
        ...proof.undisclosedCommitments,
        "kyc-tier": "xxx",
      },
    };
    const result = verifyDisclosureProof(tampered);
    expect(result.valid).toBe(false);
  });

  it("legitimate reveal of one field verifies", () => {
    const { doc } = makeDoc();
    const proof = createDisclosureProof(doc, ["kyc-tier"]);
    const result = verifyDisclosureProof(proof, { requiredFields: ["kyc-tier"] });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.disclosed["kyc-tier"]).toBe(1);
    }
  });
});
