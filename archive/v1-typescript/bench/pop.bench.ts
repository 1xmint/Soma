/**
 * Proof-of-possession benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import { createDelegation, type Delegation } from "../src/heart/delegation.js";
import {
  issueChallenge,
  proveChallenge,
  verifyProof,
  type Challenge,
  type PossessionProof,
} from "../src/heart/proof-of-possession.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

function setupDelegation() {
  const aliceKp = crypto.signing.generateKeyPair();
  const bobKp = crypto.signing.generateKeyPair();
  const d = createDelegation({
    issuerDid: publicKeyToDid(aliceKp.publicKey),
    issuerPublicKey: crypto.encoding.encodeBase64(aliceKp.publicKey),
    issuerSigningKey: aliceKp.secretKey,
    subjectDid: publicKeyToDid(bobKp.publicKey),
    capabilities: ["api:read"],
  });
  return { d, bobSigningKey: bobKp.secretKey };
}

export function popBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "issueChallenge",
      setup: () => {
        const { d } = setupDelegation();
        return { d };
      },
      body: (ctx) => {
        issueChallenge((ctx as { d: Delegation }).d);
      },
    },
    {
      name: "proveChallenge",
      setup: () => {
        const { d, bobSigningKey } = setupDelegation();
        const ch = issueChallenge(d);
        return { ch, bobSigningKey };
      },
      body: (ctx) => {
        const c = ctx as { ch: Challenge; bobSigningKey: Uint8Array };
        proveChallenge(c.ch, c.bobSigningKey);
      },
    },
    {
      name: "verifyProof",
      setup: () => {
        const { d, bobSigningKey } = setupDelegation();
        const ch = issueChallenge(d);
        const proof = proveChallenge(ch, bobSigningKey);
        return { ch, proof, d };
      },
      body: (ctx) => {
        const c = ctx as {
          ch: Challenge;
          proof: PossessionProof;
          d: Delegation;
        };
        verifyProof(c.ch, c.proof, c.d);
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
