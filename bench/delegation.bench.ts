/**
 * Delegation + attenuation + verification benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  createDelegation,
  attenuateDelegation,
  verifyDelegation,
  type Delegation,
} from "../src/heart/delegation.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

interface Ident {
  did: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
  signingKey: Uint8Array;
}

function ident(): Ident {
  const kp = crypto.signing.generateKeyPair();
  return {
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    publicKeyBytes: kp.publicKey,
    signingKey: kp.secretKey,
  };
}

export function delegationBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "createDelegation",
      setup: () => {
        const a = ident();
        const b = ident();
        return { a, b };
      },
      body: (ctx) => {
        const c = ctx as { a: Ident; b: Ident };
        createDelegation({
          issuerDid: c.a.did,
          issuerPublicKey: c.a.publicKey,
          issuerSigningKey: c.a.signingKey,
          subjectDid: c.b.did,
          capabilities: ["api:read"],
        });
      },
    },
    {
      name: "createDelegation (5 caps, 3 caveats)",
      setup: () => {
        const a = ident();
        const b = ident();
        return { a, b };
      },
      body: (ctx) => {
        const c = ctx as { a: Ident; b: Ident };
        createDelegation({
          issuerDid: c.a.did,
          issuerPublicKey: c.a.publicKey,
          issuerSigningKey: c.a.signingKey,
          subjectDid: c.b.did,
          capabilities: ["api:read", "api:write", "api:admin", "tool:db", "tool:fs"],
          caveats: [
            { kind: "expires-at", timestamp: Date.now() + 3_600_000 },
            { kind: "budget", credits: 1000 },
            { kind: "max-invocations", count: 100 },
          ],
        });
      },
    },
    {
      name: "verifyDelegation",
      setup: () => {
        const a = ident();
        const b = ident();
        const d = createDelegation({
          issuerDid: a.did,
          issuerPublicKey: a.publicKey,
          issuerSigningKey: a.signingKey,
          subjectDid: b.did,
          capabilities: ["api:read"],
        });
        return { d, bDid: b.did };
      },
      body: (ctx) => {
        const c = ctx as { d: Delegation; bDid: string };
        verifyDelegation(c.d, { invokerDid: c.bDid, capability: "api:read" });
      },
    },
    {
      name: "attenuateDelegation",
      setup: () => {
        const a = ident();
        const b = ident();
        const carol = ident();
        const d = createDelegation({
          issuerDid: a.did,
          issuerPublicKey: a.publicKey,
          issuerSigningKey: a.signingKey,
          subjectDid: b.did,
          capabilities: ["api:read", "api:write"],
        });
        return { d, b, carol };
      },
      body: (ctx) => {
        const c = ctx as { d: Delegation; b: Ident; carol: Ident };
        attenuateDelegation({
          parent: c.d,
          newSubjectDid: c.carol.did,
          newSubjectSigningKey: c.b.signingKey,
          newSubjectPublicKey: c.b.publicKey,
          narrowedCapabilities: ["api:read"],
          additionalCaveats: [{ kind: "budget", credits: 100 }],
        });
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
