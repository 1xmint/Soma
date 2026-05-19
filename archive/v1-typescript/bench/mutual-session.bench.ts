/**
 * Mutual-session handshake benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  initiateSession,
  acceptSession,
  confirmSession,
  verifyMutualSession,
  type SessionInit,
  type SessionAccept,
  type SessionConfirm,
} from "../src/heart/mutual-session.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

interface Ident {
  did: string;
  publicKey: string;
  signingKey: Uint8Array;
}

function ident(): Ident {
  const kp = crypto.signing.generateKeyPair();
  return {
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    signingKey: kp.secretKey,
  };
}

export function mutualSessionBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "initiateSession",
      setup: () => ({ alice: ident() }),
      body: (ctx) => {
        const c = ctx as { alice: Ident };
        initiateSession({
          initiatorDid: c.alice.did,
          initiatorPublicKey: c.alice.publicKey,
          purpose: "bench",
        });
      },
    },
    {
      name: "acceptSession",
      setup: () => {
        const alice = ident();
        const bob = ident();
        const init = initiateSession({
          initiatorDid: alice.did,
          initiatorPublicKey: alice.publicKey,
          purpose: "bench",
        });
        return { init, bob };
      },
      body: (ctx) => {
        const c = ctx as { init: SessionInit; bob: Ident };
        acceptSession({
          init: c.init,
          responderDid: c.bob.did,
          responderPublicKey: c.bob.publicKey,
          responderSigningKey: c.bob.signingKey,
        });
      },
    },
    {
      name: "confirmSession",
      setup: () => {
        const alice = ident();
        const bob = ident();
        const init = initiateSession({
          initiatorDid: alice.did,
          initiatorPublicKey: alice.publicKey,
          purpose: "bench",
        });
        const accept = acceptSession({
          init,
          responderDid: bob.did,
          responderPublicKey: bob.publicKey,
          responderSigningKey: bob.signingKey,
        });
        return { init, accept, alice };
      },
      body: (ctx) => {
        const c = ctx as {
          init: SessionInit;
          accept: SessionAccept;
          alice: Ident;
        };
        confirmSession({
          init: c.init,
          accept: c.accept,
          initiatorSigningKey: c.alice.signingKey,
        });
      },
    },
    {
      name: "verifyMutualSession",
      setup: () => {
        const alice = ident();
        const bob = ident();
        const init = initiateSession({
          initiatorDid: alice.did,
          initiatorPublicKey: alice.publicKey,
          purpose: "bench",
        });
        const accept = acceptSession({
          init,
          responderDid: bob.did,
          responderPublicKey: bob.publicKey,
          responderSigningKey: bob.signingKey,
        });
        const confirm = confirmSession({
          init,
          accept,
          initiatorSigningKey: alice.signingKey,
        });
        return { init, accept, confirm };
      },
      body: (ctx) => {
        const c = ctx as {
          init: SessionInit;
          accept: SessionAccept;
          confirm: SessionConfirm;
        };
        verifyMutualSession({ init: c.init, accept: c.accept, confirm: c.confirm });
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
