/**
 * Attack #14 — Lineage certificate grafting.
 *
 * Scenario:
 *   A root heart R spawns child A, which spawns grandchild B. The chain
 *   [R→A, A→B] is carried by B as its lineage. Eve wants to claim that her
 *   heart E descends from R (inheriting R's reputation / delegations)
 *   without R ever signing for her.
 *
 *   Variants:
 *     - Eve builds a cert {parent: R, child: E} signed by HER own key. The
 *       signature is real but the parentPublicKey belongs to Eve, not R.
 *     - Eve takes A's legitimate cert and swaps the childDid for her own E.
 *     - Eve grafts onto the middle of a real chain by forging a new B→E link.
 *     - Eve removes a link (R→A→B becomes R→B) to shorten ancestry.
 *
 * Defense: `verifyLineageChain` checks signature + parentDid/pubKey binding +
 * chain linkage (parent[i] matches child[i-1]). Any tamper breaks exactly one
 * of these.
 *
 * Primitives composed:
 *   lineage · parent-child chain walk · DID/key binding
 */

import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { createGenome, commitGenome } from '../../src/core/genome.js';
import {
  createLineageCertificate,
  verifyLineageCertificate,
  verifyLineageChain,
  type HeartLineage,
} from '../../src/heart/lineage.js';

const crypto = getCryptoProvider();

function makeCommitment() {
  const kp = crypto.signing.generateKeyPair();
  const genome = createGenome({
    modelProvider: 'test',
    modelId: 't',
    modelVersion: '1',
    systemPrompt: 'p',
    toolManifest: '[]',
    runtimeId: 'r',
  });
  return { kp, commitment: commitGenome(genome, kp) };
}

describe('Attack #14: lineage certificate grafting', () => {
  it("cert signed by wrong key but claiming R's parentDid fails", () => {
    const R = makeCommitment();
    const E = makeCommitment();

    // Eve builds a cert claiming R as parent, signed with HER own key.
    // parentPublicKey must match parentDid, so Eve has to either:
    // (a) set parentPublicKey to her own and lose R's identity claim, or
    // (b) set parentPublicKey to R's real pk — but then the signature
    //     won't verify because she signed with Eve's sk.
    //
    // Here we construct (b): present R's pk but signature from Eve.
    const forged = createLineageCertificate({
      parent: { ...R.commitment, publicKey: R.commitment.publicKey },
      parentSigningKey: E.kp.secretKey, // signed by Eve
      child: E.commitment,
    });
    // The cert stores parentPublicKey = R's pub key (via R.commitment).
    expect(forged.parentPublicKey).toBe(R.commitment.publicKey);
    // But the signature was computed with Eve's secret → won't verify.
    const result = verifyLineageCertificate(forged);
    expect(result.valid).toBe(false);
  });

  it('swapping childDid after signing breaks the signature', () => {
    const R = makeCommitment();
    const A = makeCommitment();
    const E = makeCommitment();

    const legit = createLineageCertificate({
      parent: R.commitment,
      parentSigningKey: R.kp.secretKey,
      child: A.commitment,
    });
    // Eve rewrites the childDid to point to herself.
    const tampered = { ...legit, childDid: E.commitment.did };
    expect(verifyLineageCertificate(tampered).valid).toBe(false);
  });

  it('grafting a forged link into the middle of a valid chain fails chain walk', () => {
    const R = makeCommitment();
    const A = makeCommitment();
    const E = makeCommitment();

    // Legit R→A.
    const R2A = createLineageCertificate({
      parent: R.commitment,
      parentSigningKey: R.kp.secretKey,
      child: A.commitment,
    });
    // Eve forges a link A→E signed by HERSELF (she doesn't have A's sk).
    const forgedA2E = createLineageCertificate({
      parent: A.commitment, // claims A is parent
      parentSigningKey: E.kp.secretKey, // signed by E
      child: E.commitment,
    });
    const lineage: HeartLineage = {
      did: E.commitment.did,
      rootDid: R.commitment.did,
      chain: [R2A, forgedA2E],
    };
    const result = verifyLineageChain(lineage);
    expect(result.valid).toBe(false);
  });

  it('chain with broken parent→previous-child linkage fails', () => {
    const R = makeCommitment();
    const A = makeCommitment();
    const B = makeCommitment();
    const C = makeCommitment();

    // R→A legit. Then R→B legit. But we try to claim chain [R→A, R→B]
    // as a path to B. The second cert's parent is R, not A, so chain
    // walker rejects: cert[1].parentDid != cert[0].childDid.
    const R2A = createLineageCertificate({
      parent: R.commitment,
      parentSigningKey: R.kp.secretKey,
      child: A.commitment,
    });
    const R2B = createLineageCertificate({
      parent: R.commitment,
      parentSigningKey: R.kp.secretKey,
      child: B.commitment,
    });
    // Abuse: claim [R→A, R→B] as the chain from R to B.
    const lineage: HeartLineage = {
      did: B.commitment.did,
      rootDid: R.commitment.did,
      chain: [R2A, R2B],
    };
    const result = verifyLineageChain(lineage);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toMatch(/previous child/);
  });

  it('legitimate two-link chain verifies', () => {
    const R = makeCommitment();
    const A = makeCommitment();
    const B = makeCommitment();

    const R2A = createLineageCertificate({
      parent: R.commitment,
      parentSigningKey: R.kp.secretKey,
      child: A.commitment,
    });
    const A2B = createLineageCertificate({
      parent: A.commitment,
      parentSigningKey: A.kp.secretKey,
      child: B.commitment,
    });
    const lineage: HeartLineage = {
      did: B.commitment.did,
      rootDid: R.commitment.did,
      chain: [R2A, A2B],
    };
    expect(verifyLineageChain(lineage).valid).toBe(true);
  });

  it('expired cert fails verification', async () => {
    const R = makeCommitment();
    const A = makeCommitment();
    const expired = createLineageCertificate({
      parent: R.commitment,
      parentSigningKey: R.kp.secretKey,
      child: A.commitment,
      ttl: 1, // expires in 1ms
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const result = verifyLineageCertificate(expired);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toMatch(/expired/);
  });
});
