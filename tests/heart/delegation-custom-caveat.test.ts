import { describe, it, expect } from 'vitest';
import { getCryptoProvider } from '../../src/core/crypto-provider.js';
import { publicKeyToDid } from '../../src/core/genome.js';
import {
  createDelegation,
  checkCaveats,
  verifyDelegation,
  type Caveat,
  type CustomCaveatEvaluator,
} from '../../src/heart/delegation.js';

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

function makeDelegation(caveats: Caveat[]) {
  const issuer = makeIdentity();
  const subject = makeIdentity();
  return {
    subject,
    d: createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ['tool:search'],
      caveats,
    }),
  };
}

describe('Caveat: custom — fail-closed behavior', () => {
  it('fails closed when no evaluator is provided', () => {
    const { subject, d } = makeDelegation([
      { kind: 'custom', key: 'acme:region', value: 'us-east-1' },
    ]);
    const check = checkCaveats(d, { invokerDid: subject.did, capability: 'tool:search' });
    expect(check.valid).toBe(false);
    if (!check.valid) {
      expect(check.reason).toMatch(/fail-closed/);
      expect(check.reason).toContain('acme:region');
    }
  });

  it('passes when the evaluator accepts the caveat', () => {
    const { subject, d } = makeDelegation([
      { kind: 'custom', key: 'acme:region', value: 'us-east-1' },
    ]);
    const evaluator: CustomCaveatEvaluator = (cav) => {
      if (cav.key === 'acme:region' && cav.value === 'us-east-1') return { valid: true };
      return { valid: false, reason: `unknown region: ${cav.value}` };
    };
    const check = checkCaveats(d, { invokerDid: subject.did, capability: 'tool:search' }, evaluator);
    expect(check.valid).toBe(true);
  });

  it('propagates rejection from the evaluator', () => {
    const { subject, d } = makeDelegation([
      { kind: 'custom', key: 'acme:region', value: 'eu-west-1' },
    ]);
    const evaluator: CustomCaveatEvaluator = (cav) => ({
      valid: false,
      reason: `region ${cav.value} not permitted by this verifier`,
    });
    const check = checkCaveats(d, { invokerDid: subject.did, capability: 'tool:search' }, evaluator);
    expect(check.valid).toBe(false);
    if (!check.valid) expect(check.reason).toContain('eu-west-1');
  });

  it('evaluator receives the full caveat and context', () => {
    const { subject, d } = makeDelegation([
      { kind: 'custom', key: 'test:key', value: 'test-value' },
    ]);
    let capturedCav: { key: string; value: string } | null = null;
    let capturedCtxDid: string | null = null;
    const evaluator: CustomCaveatEvaluator = (cav, ctx) => {
      capturedCav = { key: cav.key, value: cav.value };
      capturedCtxDid = ctx.invokerDid;
      return { valid: true };
    };
    checkCaveats(d, { invokerDid: subject.did, capability: 'tool:search' }, evaluator);
    expect(capturedCav?.key).toBe('test:key');
    expect(capturedCav?.value).toBe('test-value');
    expect(capturedCtxDid).toBe(subject.did);
  });

  it('each custom caveat in a chain is evaluated', () => {
    const { subject, d } = makeDelegation([
      { kind: 'custom', key: 'x', value: '1' },
      { kind: 'custom', key: 'y', value: '2' },
    ]);
    const seen: string[] = [];
    const evaluator: CustomCaveatEvaluator = (cav) => {
      seen.push(cav.key);
      return { valid: true };
    };
    const check = checkCaveats(d, { invokerDid: subject.did, capability: 'tool:search' }, evaluator);
    expect(check.valid).toBe(true);
    expect(seen).toEqual(['x', 'y']);
  });

  it('verifyDelegation also threads the evaluator through', () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const d = createDelegation({
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      subjectDid: subject.did,
      capabilities: ['tool:search'],
      caveats: [{ kind: 'custom', key: 'scope', value: 'read-only' }],
    });

    // Without evaluator — fail closed
    const noEval = verifyDelegation(d, { invokerDid: subject.did, capability: 'tool:search' });
    expect(noEval.valid).toBe(false);
    if (!noEval.valid) expect(noEval.reason).toMatch(/fail-closed/);

    // With evaluator — passes
    const withEval = verifyDelegation(
      d,
      { invokerDid: subject.did, capability: 'tool:search' },
      undefined,
      undefined,
      undefined,
      () => ({ valid: true }),
    );
    expect(withEval.valid).toBe(true);
  });
});
