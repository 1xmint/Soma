/**
 * Key rotation (KERI pre-rotation) benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import {
  KeyHistory,
  type RotationEvent,
} from "../src/heart/key-rotation.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

export function keyRotationBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "KeyHistory.incept",
      setup: () => {
        const k0 = crypto.signing.generateKeyPair();
        const k1 = crypto.signing.generateKeyPair();
        return { k0, k1 };
      },
      body: (ctx) => {
        const c = ctx as {
          k0: { publicKey: Uint8Array; secretKey: Uint8Array };
          k1: { publicKey: Uint8Array; secretKey: Uint8Array };
        };
        KeyHistory.incept({
          inceptionSecretKey: c.k0.secretKey,
          inceptionPublicKey: c.k0.publicKey,
          nextPublicKey: c.k1.publicKey,
        });
      },
    },
    {
      name: "history.rotate",
      setup: () => {
        const k0 = crypto.signing.generateKeyPair();
        const k1 = crypto.signing.generateKeyPair();
        const k2 = crypto.signing.generateKeyPair();
        KeyHistory.incept({
          inceptionSecretKey: k0.secretKey,
          inceptionPublicKey: k0.publicKey,
          nextPublicKey: k1.publicKey,
        });
        // Use a fresh history per rotation so the digest chain remains valid.
        return { k1, k2 };
      },
      body: (ctx) => {
        const c = ctx as {
          k1: { publicKey: Uint8Array; secretKey: Uint8Array };
          k2: { publicKey: Uint8Array; secretKey: Uint8Array };
        };
        // Each rotation appends one event; we have to rebuild a history to
        // avoid chaining pre-rotation misses. Build minimal history inline.
        const k0 = crypto.signing.generateKeyPair();
        const { history } = KeyHistory.incept({
          inceptionSecretKey: k0.secretKey,
          inceptionPublicKey: k0.publicKey,
          nextPublicKey: c.k1.publicKey,
        });
        history.rotate({
          currentSecretKey: c.k1.secretKey,
          currentPublicKey: c.k1.publicKey,
          nextPublicKey: c.k2.publicKey,
        });
      },
    },
    {
      name: "verifyChain (3 events)",
      setup: () => {
        const k0 = crypto.signing.generateKeyPair();
        const k1 = crypto.signing.generateKeyPair();
        const k2 = crypto.signing.generateKeyPair();
        const k3 = crypto.signing.generateKeyPair();
        const { history } = KeyHistory.incept({
          inceptionSecretKey: k0.secretKey,
          inceptionPublicKey: k0.publicKey,
          nextPublicKey: k1.publicKey,
        });
        history.rotate({
          currentSecretKey: k1.secretKey,
          currentPublicKey: k1.publicKey,
          nextPublicKey: k2.publicKey,
        });
        history.rotate({
          currentSecretKey: k2.secretKey,
          currentPublicKey: k2.publicKey,
          nextPublicKey: k3.publicKey,
        });
        return {
          events: history.getEvents() as readonly RotationEvent[],
          id: history.identity,
        };
      },
      body: (ctx) => {
        const c = ctx as { events: readonly RotationEvent[]; id: string };
        KeyHistory.verifyChain(c.events, c.id);
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
