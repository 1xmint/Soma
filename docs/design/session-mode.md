# Session Mode — Human Consent Ceremony

**Status:** design — PR-A + PR-B shipped (primitives), PR-B.5 runtime
integration pending.
**Modules:** `src/heart/human-delegation.ts`,
`src/heart/ceremony-policy.ts`, `src/heart/human-session.ts`

---

## §1 Economic reality — why session mode exists

The naive "agent" mental model assumes autonomous programs with their own
durable identities. That is almost never what happens in practice today:

- Running an LLM API for every signed operation is cost-prohibitive for
  most dev-tier users.
- Harness platforms (Claude Code, Codex CLI, Cursor, etc.) gate model
  access behind a *human's* paid account. The human is the paying
  customer; the model is a rented tool.
- Real-world usage: **human prompts an LLM → LLM (in a harness) acts on
  the human's behalf → signs things using delegated authority → may sign
  out before the next prompt → signs back in**.
- The durable, liability-bearing identity is the **human** (or their
  hardware key-holder). The agent is ephemeral: it holds a delegated
  session with a ceiling on budget, actions, time, and scope.

Session mode inverts the primitive. Instead of:

> agent.durableDid signs everything

Soma provides:

> human.durableDid delegates a bounded session to agent.ephemeralDid;
> heart records the delegation handshake + every action in the session
> under both identities; sense-observer replays the chain and can pin
> liability on either side depending on whether the action stayed
> inside the envelope.

## §2 The session primitive

A **session** is conceptually:

```
Session {
  sessionId: string                 // UUID, logged everywhere
  humanDid: string                  // durable, registered during onboarding
  agentEphemeralDid: string         // fresh keypair per session
  capabilityEnvelope: Caveat[]      // reuses delegation caveat system
  humanDelegation: HumanDelegation  // signed consent payload — §7
  startedAt: number
  expiresAt: number                 // hard TTL
}
```

Key design choices:

- **Ephemeral session keypair** — generated in-harness, private key never
  touches disk outside the harness's sealed area. On session end, key is
  discarded.
- **Capability envelope reuses `soma/delegation/v1`** — Soma already has
  `expires-at`, `budget`, `max-invocations`, `host-allowlist`,
  `command-allowlist`, `requires-stepup`, `time-window` caveats. Session
  mode is a *bundling* of these, not a new caveat language.
- **HumanDelegation** binds the agent ephemeral DID to the human durable
  DID via a signature from the human's hardware authenticator. §7 details
  the struct.
- **Workflow container** (optional, deferred) lets one human consent
  ceremony cover multiple short sessions that constitute a single
  logical unit of work.

## §3 End-to-end ceremony walkthrough

Concrete flow for "human asks a coding agent to deploy a change":

1. Human opens a harness and asks the agent to do work.
2. Harness asks the local/remote Soma heart to begin a session with:
   - humanDid (from the human's existing Soma identity)
   - requested capabilityEnvelope (what actions the agent will need)
   - requested TTL + budget
3. Heart emits a **`consent_required`** heartbeat event and returns a
   challenge:
   - sessionId (pre-committed so it's the same across the handshake)
   - agentEphemeralPubkey (freshly generated)
   - a hash of (envelope || TTL || sessionId || agentEphemeralPubkey)
   - a deep link + QR code for the human's authenticator
4. Human picks up their authenticator (phone, hardware key, laptop
   platform WebAuthn), the link opens the consent app:
   - Displays *human-readable summary* of the envelope
   - Prompts `navigator.credentials.get({ userVerification: 'required' })`
     or equivalent
   - Authenticator asks for Face ID / Touch ID / iris / hardware key
   - On success, signs the challenge hash
5. Authenticator posts signed challenge back to the heart.
6. Heart:
   - Verifies the signature via an injected `AttestationVerifier`
   - Constructs the signed `HumanDelegation`
   - Emits a **`consent_granted`** heartbeat event
   - Returns a session handle to the harness
7. Harness now acts using the session handle. Every action hits the
   heart's `HumanSessionRegistry`, which checks the envelope and logs to
   the sense-observer stream.
8. Session ends by TTL, explicit sign-out, or a mid-session escalation.

## §4 Ceremony tiers

| Tier | Hardware                          | Use case                                    |
|------|-----------------------------------|---------------------------------------------|
| L0   | Password / bearer token           | Read-only, observational calls              |
| L1   | Platform WebAuthn (Touch ID)      | Normal dev work, ≤ small budget             |
| L2   | Hardware WebAuthn + biometric     | Production deploys, money movement          |
| L3   | L2 + hardware SSH + biometric witness | Key rotation, admin ops, high-risk moves |

WebAuthn is the primitive that makes L1/L2 actually usable — it's built
into every modern phone and browser and does not require custom
hardware. L3 is the "extremist" case: iris + hardware SSH + face scan +
whatever else. It exists so the policy engine can refuse to grant
certain delegations without it, not because it's expected on every
call.

**Soma does not implement any of these verifiers.** It accepts an
`AttestationVerifier` function and trusts whatever verdict the caller
returns. This preserves protocol purity: Soma has zero browser crypto
dependencies, no platform-specific code paths, and no coupling to any
single vendor's authenticator stack.

## §5 Sense-observer as session verifier

Sense (and downstream observers like Nova in the ClawNet ecosystem) is
the natural home for session verification because:

- It already holds the receipt archive and replay pipeline.
- A session is a *sequence of heart events* — exactly what sense is
  built for.
- It can produce a "session transcript" proof: the full ordered chain
  from `consent_granted` → every in-session action → session end, with
  the envelope attached, signed as a single artifact.

The observer does **not** issue the delegation — that's the heart's
job. It **verifies** after the fact and produces replayable receipts.
This matches Soma's separation: heart = runtime, sense = observer.

## §6 Composition with the rotation controller

Session mode and credential rotation are orthogonal:

- The **human** holds a durable Soma identity whose credentials rotate
  on the Class A/B/C schedule under `CredentialRotationController`.
- The **agent ephemeral session key** does not rotate — it is born and
  dies within one session. Rotation semantics don't apply.
- The **HumanDelegation** payload names the *current* human credential
  at the moment of consent. If the human's credential rotates
  mid-session, the delegation remains valid against the lineage chain;
  the controller already supports this via the DID + credential-id
  binding.

Mid-session escalation: if the envelope forbids an action and the agent
needs it, the harness can request a new ceremony bound to the existing
sessionId. The human approves (or doesn't) through the same consent
app. This is how we avoid forcing humans to pre-authorize the full
blast radius up-front.

## §7 Primitives shipped

### 7.1 `HumanDelegation` (PR-A — `src/heart/human-delegation.ts`)

```typescript
export interface HumanDelegation {
  version: 'soma/human-delegation/v1';
  sessionId: string;
  humanDid: string;
  humanCredentialId: string;
  humanPublicKey: string;
  agentEphemeralDid: string;
  agentEphemeralPublicKey: string;
  envelope: Caveat[];
  issuedAt: number;
  expiresAt: number;
  ceremonyTier: 'L0' | 'L1' | 'L2' | 'L3';
  attestation: HumanAttestation;
  signature: string;
}
```

Functions: `createHumanDelegation`, `verifyHumanDelegation`,
`computeChallengeHash`. Canonical signing under
`soma/human-delegation/v1` domain via `domainSigningInput`. The
`AttestationVerifier` is injected — Soma stays agnostic.

### 7.2 Heartbeat event types (PR-A — `src/heart/heartbeat.ts`)

```typescript
| "consent_required"    // heart asked for human approval
| "consent_granted";    // human returned a signed HumanDelegation
```

Flow through the existing heartbeat chain so observers see them with no
new plumbing.

### 7.3 `CeremonyPolicy` (PR-B — `src/heart/ceremony-policy.ts`)

Pure lookup: action class → required ceremony tier. Fail-safe defaults:

| Class     | Default tier |
|-----------|--------------|
| `read`    | L0           |
| `write`   | L1           |
| `spend`   | L2           |
| `deploy`  | L2           |
| `admin`   | L3           |
| unknown   | L2           |

Callers tighten, loosen, or extend the map via `PolicyOverrides`. No
crypto, no I/O — trivially unit-testable.

### 7.4 `HumanSessionRegistry` (PR-B — `src/heart/human-session.ts`)

Runtime handle that wraps a verified `HumanDelegation` with mutable
budget / invocation counters. Verifies on `open`, enforces envelope +
policy on every `invoke`. Terminal states: `expired`, `revoked`,
`budget-exhausted`, `invocations-exhausted`. Idempotent by sessionId.

### 7.5 `HeartRuntime.createHumanSession` (PR-B.5 — pending)

Thin wrapper that composes `HumanSessionRegistry` with
`HeartRuntime.heartbeatChain` so consent events land in the same chain
as model calls and tool events. Deferred until a real consumer surfaces
the exact API shape needed — the standalone primitives are usable
today.

### 7.6 Workflow container (deferred)

Only build this after a real consumer shows the UX tension of "every 1h
session needs re-consent." Container would hold a cross-session budget
and let the human authorize a whole workflow at a higher ceremony tier
once. Do not design speculatively.

## §8 Consumer wiring

Soma ships the primitives; consumers wire them. A typical consumer
(e.g. ClawNet) needs to provide:

- **HTTP/IPC surface** — routes like `session-begin`, `session-confirm`,
  `session-escalate`, `session-end`. Soma doesn't ship a web server.
- **Attestation verifier** — a function that parses whatever
  authenticator payload the consumer accepts (WebAuthn, Apple
  DeviceCheck, hardware SSH keys, mock for tests) and returns a
  `CeremonyTier` verdict.
- **DID registry** — if the human uses `did:web` or `did:pkh`, the
  consumer supplies the resolver. Soma includes `did:key` out of the
  box.
- **Enrollment flow** — how humans register their authenticators and
  durable DIDs. Entirely a consumer concern.
- **Session transcript delivery** — where the `consent_granted` → action
  chain goes for observer replay. Sense provides the archive format;
  the consumer picks the transport.

## §9 Open questions

- **Revocation of in-flight sessions** — a rotation that burns the
  human credential mid-session should probably kill the session. The
  controller already supports revocation; needs a session-revoke path
  wired through `HumanSessionRegistry`.
- **Offline consent** — for air-gapped scenarios where the
  authenticator can't reach the heart during the ceremony. Defer until
  a real user asks for it.
- **Multi-human consent** — does a HumanDelegation ever need multiple
  co-signers (e.g. 2-of-3 for L3 actions)? Currently single-signer.
  Add only if a consumer needs it.
