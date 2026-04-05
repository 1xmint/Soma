/**
 * Selective disclosure benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  createDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
  type DisclosableDocument,
  type DisclosureProof,
} from "../src/heart/selective-disclosure.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

function setupDoc() {
  const issuer = crypto.signing.generateKeyPair();
  const subject = crypto.signing.generateKeyPair();
  const doc = createDisclosableDocument({
    issuerDid: publicKeyToDid(issuer.publicKey),
    issuerPublicKey: crypto.encoding.encodeBase64(issuer.publicKey),
    issuerSigningKey: issuer.secretKey,
    subjectDid: publicKeyToDid(subject.publicKey),
    claims: {
      name: "Alice",
      dob: "1990-01-01",
      country: "SG",
      "kyc-tier": 3,
    },
  });
  return { doc };
}

export function selectiveDisclosureBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "createDocument (4 fields)",
      setup: () => {
        const issuer = crypto.signing.generateKeyPair();
        const subject = crypto.signing.generateKeyPair();
        return {
          did: publicKeyToDid(issuer.publicKey),
          pk: crypto.encoding.encodeBase64(issuer.publicKey),
          sk: issuer.secretKey,
          subjectDid: publicKeyToDid(subject.publicKey),
        };
      },
      body: (ctx) => {
        const c = ctx as { did: string; pk: string; sk: Uint8Array; subjectDid: string };
        createDisclosableDocument({
          issuerDid: c.did,
          issuerPublicKey: c.pk,
          issuerSigningKey: c.sk,
          subjectDid: c.subjectDid,
          claims: {
            name: "Alice",
            dob: "1990-01-01",
            country: "SG",
            "kyc-tier": 3,
          },
        });
      },
    },
    {
      name: "createDisclosureProof (2 of 4)",
      setup: () => setupDoc(),
      body: (ctx) => {
        const c = ctx as { doc: DisclosableDocument };
        createDisclosureProof(c.doc, ["country", "kyc-tier"]);
      },
    },
    {
      name: "verifyDisclosureProof (2 of 4)",
      setup: () => {
        const { doc } = setupDoc();
        const proof = createDisclosureProof(doc, ["country", "kyc-tier"]);
        return { proof };
      },
      body: (ctx) => {
        verifyDisclosureProof((ctx as { proof: DisclosureProof }).proof);
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
