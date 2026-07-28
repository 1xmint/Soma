# Ordinary Soma Controller-Key Rotation

Status: **implemented offline ordinary rotation; not compromise recovery and not independently rollback-resistant**

This slice implements the closed `somavera.soma-controller-key-rotation.v1`
contract from Somavera Origin commit `b64d7794ad368f5e690596e50dd0c11ef2f73072` and capsule root
`48e45cb82cf27e0b3ad94d492c92cb6249ed7dc69734171e86c34ea424aed243`.

## Commands

```text
soma identity status --home ABSOLUTE_HOME
soma identity controller-rotate-preview --reason TEXT --home ABSOLUTE_HOME
soma identity controller-rotate-confirm --proposal-id HASH --expect-successor-key-hash HASH --confirm-controller-rotation --home ABSOLUTE_HOME
```

All commands are offline. They create no recovery, connection, consent,
disclosure, send, token, wallet, or governance authority.

## Ceremony and cryptographic boundary

Preview creates a fresh Ed25519 successor and stores its private material only
in a DPAPI-protected pending blob. Its public proposal commits the stable
controller DID, exact sequence and predecessor, prior key and validity start,
successor key and raw-key SHA-256, preparation time, reason, key-disposition
rule, rollback limitation, and every authority exclusion. The proposal expires
after 900 seconds and has no effect by itself.

Confirmation requires the exact proposal ID, exact successor raw-key SHA-256,
and the explicit confirmation flag. Only then does Soma choose the effect time,
derive the final rotation ID, sign it in distinct domains with both the live
prior key and the fresh successor, and begin the state transaction. The stable
controller DID does not change.

The former public key remains in identity history with its exact validity
interval. Historical signatures remain verifiable only before the transition
boundary. The successor is the sole active controller key afterward. The live
keystore contains only the successor controller private key; the old private
record is removed. Ordinary filesystem replacement does not promise forensic
erasure from storage media, snapshots, paging, or backups.

## Atomicity and recovery

The transaction durably prepares:

- the dual-signed event;
- exact prior and successor public identity;
- exact prior and successor public-key history; and
- a protected successor keystore whose controller private key is re-derived
  and matched to the signed successor before installation; and
- a short-lived DPAPI-protected copy of the prior bundle used only to prove that
  the root-store, agent, observer, and reply keys are byte-identical across
  recovery. It is deleted on rollback or completed finalization.

Replacing `identity/identity.json` is the single logical commit point. A restart
before it removes the incomplete transaction and leaves the prior identity plus
the still-inert proposal. A restart after it verifies the complete transaction,
finishes the exact history and keystore, publishes the event, and removes the
proposal. Any third identity, missing successor material, malformed event,
competing history, changed key, or ambiguous file set fails closed.

Identical confirmations are idempotent. Competing successor commitments
conflict. The test suite fault-injects each boundary and races one hundred
identical confirmations against one competitor under a zero-egress sentinel.

## Honest limitations

- This is safe only when the current controller key is still believed
  uncompromised. A thief holding it can co-sign an attacker-chosen successor.
  Suspected compromise requires a separately precommitted recovery authority,
  which remains unimplemented.
- Signed local history proves internal continuity, not that the device has not
  been rolled back. Independent rollback assurance requires exact history or a
  compatible capsule preserved outside the candidate device.
- `soma-host-trust-capsule.v2` exports and verifies the complete dual-signed
  controller chain from an independently expected initial key. A separately
  preserved earlier capsule is still required for independent rollback/fork
  comparison; the local chain alone is not an external anchor.
- This profile rotates only `controller_signing`. Agent, observer, reply
  encryption, revocation, and identity-recovery lifecycles need separate
  ratified profiles.
- DPAPI is the only production keystore backend in this reference slice.
