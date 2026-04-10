/**
 * Step-Up Oracle — pluggable delivery channel for step-up challenges.
 *
 * The oracle is the transport between the heart (which mints challenges)
 * and whatever device the human uses to approve. It is intentionally
 * orthogonal to the cryptographic step-up flow in `stepup.ts` — the heart
 * doesn't care whether a challenge reaches its subject via web push, an
 * email magic link, a native mobile app, a terminal prompt, or a carrier
 * pigeon with a QR code. All the oracle must do is:
 *
 *   1. Accept a `StepUpChallenge` and deliver it to the subject.
 *   2. Surface the `FactorAssertion` the subject produces back to the
 *      heart so it can be submitted to `StepUpService.submitAttestation`.
 *
 * Because the oracle sits outside the crypto boundary, an oracle that
 * fails to deliver a challenge (lost push, down mail server, offline
 * device) is a LIVENESS failure, not a SAFETY failure. The worst thing a
 * malicious oracle can do is drop challenges or stall them — it cannot
 * forge an approval, because factor assertions are still signed by
 * keys the oracle never touches.
 *
 * Reference implementations:
 *   - `CliPromptOracle` in this file (for tests and dev workflows).
 *   - `WebPushOracle`, `EmailMagicLinkOracle`, `TelegramOracle`, etc.
 *     live in separate packages so this module has no transport
 *     dependencies.
 */

import type { FactorAssertion, StepUpChallenge } from './stepup.js';

// ─── Interface ──────────────────────────────────────────────────────────────

/**
 * Result of delivering a challenge.
 *
 * `pending` means the challenge has been dispatched but the human has
 * not yet responded. Oracles should return this immediately and surface
 * the eventual assertion via `listen()` or a callback.
 *
 * `unsupported` means the oracle knows it cannot reach this subject at
 * all (e.g., no push subscription, no email on file). Callers should
 * fall back to another oracle.
 *
 * `failed` is a transient delivery failure — retry may succeed.
 */
export type DeliveryResult =
  | { status: 'pending'; deliveryId: string }
  | { status: 'delivered'; deliveryId: string }
  | { status: 'unsupported'; reason: string }
  | { status: 'failed'; reason: string };

/**
 * A callback the oracle invokes when the human produces a factor
 * assertion. The assertion MUST still be verified by the heart's
 * `StepUpService.submitAttestation` — the oracle is not a trust root.
 */
export type AssertionCallback = (
  assertion: FactorAssertion,
) => void | Promise<void>;

/**
 * Pluggable delivery channel for step-up challenges.
 *
 * Implementations are free to be synchronous (CLI prompt, blocking call)
 * or asynchronous (web push + webhook). Asynchronous implementations
 * should return `pending` from `deliver` immediately and later emit via
 * `on('assertion', ...)`.
 */
export interface StepUpOracle {
  /** Human-readable oracle name, used in logs and UIs. */
  readonly name: string;

  /**
   * Attempt to deliver a challenge to the subject. MUST not block on
   * human input for more than ~1 second; async oracles return `pending`
   * and surface the assertion later via `on('assertion', ...)`.
   */
  deliver(challenge: StepUpChallenge): Promise<DeliveryResult>;

  /**
   * Register an assertion callback. The oracle invokes it for every
   * assertion it receives, regardless of which challenge it answers.
   * Multiple callbacks may be registered; order is not guaranteed.
   */
  onAssertion(callback: AssertionCallback): void;

  /**
   * Optional teardown. Release sockets, webhook routes, timers.
   */
  close?(): Promise<void>;
}

// ─── Base class with callback plumbing ──────────────────────────────────────

/**
 * Small base class that implements `onAssertion` / `emitAssertion` so
 * concrete oracles only have to implement `deliver`.
 */
export abstract class BaseStepUpOracle implements StepUpOracle {
  abstract readonly name: string;
  private readonly callbacks: AssertionCallback[] = [];

  abstract deliver(challenge: StepUpChallenge): Promise<DeliveryResult>;

  onAssertion(callback: AssertionCallback): void {
    this.callbacks.push(callback);
  }

  protected async emitAssertion(assertion: FactorAssertion): Promise<void> {
    for (const cb of this.callbacks) {
      await cb(assertion);
    }
  }
}

// ─── Reference: CLI Prompt Oracle ───────────────────────────────────────────

/**
 * Synchronous test/dev oracle. Writes challenge details to a provided
 * output stream and reads a pre-seeded or interactively supplied
 * assertion. Never use in production.
 *
 * Typical use in tests:
 *   const oracle = new CliPromptOracle({
 *     autoAssertion: (challenge) => ({ ... }),
 *   });
 *
 * The `autoAssertion` callback lets a test inject a canned assertion
 * for every challenge without any real I/O.
 */
export class CliPromptOracle extends BaseStepUpOracle {
  readonly name = 'cli-prompt';
  private readonly opts: {
    autoAssertion?: (challenge: StepUpChallenge) => FactorAssertion | null;
    log?: (line: string) => void;
  };

  constructor(opts: {
    autoAssertion?: (challenge: StepUpChallenge) => FactorAssertion | null;
    log?: (line: string) => void;
  } = {}) {
    super();
    this.opts = opts;
  }

  async deliver(challenge: StepUpChallenge): Promise<DeliveryResult> {
    const log = this.opts.log ?? ((line: string) => {
      // Default: silent. Tests inject their own logger.
      void line;
    });

    log(`[cli-prompt] step-up required`);
    log(`  challengeId: ${challenge.id}`);
    log(`  subjectDid:  ${challenge.subjectDid}`);
    log(`  minTier:     ${challenge.minTier}`);
    log(`  actionDigest: ${challenge.actionDigest}`);
    log(`  expiresAt:   ${new Date(challenge.expiresAt).toISOString()}`);

    if (this.opts.autoAssertion) {
      const assertion = this.opts.autoAssertion(challenge);
      if (assertion) {
        // Emit asynchronously so the caller can `await deliver()` first
        // and see the resulting callback on the next microtask.
        queueMicrotask(() => {
          void this.emitAssertion(assertion);
        });
        return { status: 'pending', deliveryId: challenge.id };
      }
      return { status: 'failed', reason: 'autoAssertion returned null' };
    }

    return { status: 'pending', deliveryId: challenge.id };
  }

  /**
   * Manually inject an assertion. Useful in tests that want to
   * simulate a delayed human approval.
   */
  async injectAssertion(assertion: FactorAssertion): Promise<void> {
    await this.emitAssertion(assertion);
  }
}

// ─── Oracle Chain ───────────────────────────────────────────────────────────

/**
 * Try oracles in order; return the first non-`unsupported` result. Useful
 * when a deployment wants web push as primary and email as fallback.
 */
export class OracleChain extends BaseStepUpOracle {
  readonly name: string;

  constructor(private readonly oracles: StepUpOracle[]) {
    super();
    this.name = `chain(${oracles.map((o) => o.name).join(',')})`;
    // Fan assertions from every child oracle out to our own listeners.
    for (const child of oracles) {
      child.onAssertion((assertion) => this.emitAssertion(assertion));
    }
  }

  async deliver(challenge: StepUpChallenge): Promise<DeliveryResult> {
    let lastReason = 'no oracles available';
    for (const oracle of this.oracles) {
      const result = await oracle.deliver(challenge);
      if (result.status === 'unsupported') {
        lastReason = `${oracle.name}: ${result.reason}`;
        continue;
      }
      return result;
    }
    return { status: 'unsupported', reason: lastReason };
  }

  async close(): Promise<void> {
    for (const oracle of this.oracles) {
      await oracle.close?.();
    }
  }
}
