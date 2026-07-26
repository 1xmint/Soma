# Offline Vera Host Succession

Status: **implemented controller-confirmed inert local transition; connection, consent, disclosure, send, and emergency recovery are absent**

This slice imports the ordinary Vera Host descriptor-succession and controller-confirmation contracts from Somavera Origin commit `cabc10eb889def42c395735bf701b16c18105628` and capsule root `4ef5a42ab4b330678f8c52a822d90c105b267751da6227c31c54a50c67bf67e0`. It verifies a successor against an existing controller-signed host pin, stores one controller-signed pending candidate, and can replace that inert pin only after an exact controller confirmation. Every operation is local and performs zero network actions.

## Commands

```text
soma host succession-preview --successor ABSOLUTE_DESCRIPTOR.json --proof ABSOLUTE_PROOF.json --home ABSOLUTE_HOME
soma host succession-confirm --candidate-id HASH --subject HASH --expect-successor-descriptor HASH --confirm-inert-pin-replacement --home ABSOLUTE_HOME
```

All inputs are local. Neither command fetches a descriptor, follows a redirect, contacts a host, registers consent, creates a session, retries work, or places work in a queue. Confirmation requires the literal replacement flag and all three exact identifiers; there is no broad yes flag or inferred candidate.

## Required continuity proof

The preview verifier requires exact sequence and predecessor continuity; immutable host, network, context, transport, release, policy, capability, disclosure, region, subprocessor, retention, and limit fields; bounded prior precommitment of every newly active key; coherent key retirement and lifecycle history; recomputed descriptor and proof identifiers; distinct role-separated prior and successor signatures; an exact no-authority statement; and a live proof window of at most 900 seconds within both descriptors.

Revocation smuggling, an uncommitted key, multiple active keys, key-role reuse, expired overlap, immutable-field change, signature replay, or excess descriptor lifetime fails closed. Ordinary succession cannot authorize emergency recovery after total compromise.

## Candidate and confirmation bindings

One candidate per host is stored under `hosts/candidates/`. Its controller signature binds the current pin, complete successor descriptor and proof, succession and change-scope identifiers, successor active-key commitment, controller DID, creation time, and the authority `offline_candidate_only_no_pin_replacement_no_connection_no_consent_no_send`. Preview is idempotent for identical bytes and conflicts on a different candidate.

The confirmation subject is recomputed from the live candidate and binds the candidate ID, prior pin and descriptor IDs, successor descriptor and active keys, succession proof and change scope, host DID, exact origin, network lineage, execution context, proof expiry, and inert replacement authority. The controller-confirmation receipt binds that subject, the expected successor descriptor, the exact decision `replace_inert_pin_only`, and explicit false values for connection, consent, disclosure, send, and emergency recovery. Receipt creation and commit must both occur while the proof is live.

## Atomic transition and recovery

The implementation writes a complete controller-signed prepared transaction, synchronizes a successor-pin temporary file, rechecks the current pin and proof window, and atomically renames the successor over the current pin. That rename is the sole commit point. It then consumes the exact candidate and publishes the prepared transaction as immutable local history.

Startup, `doctor`, and `status` deterministically recover interruptions:

- if the prior pin is current, preparation is rolled back and the candidate remains;
- if the exact successor is current, candidate consumption and history publication are completed;
- any unrelated current state, invalid signature, fork, gap, or mismatched history fails closed.

Identical repeated confirmations are idempotent. A per-host exclusive lock serializes local contenders. The adversarial suite faults every durable boundary and races 100 identical confirmations plus a competing candidate.

The resulting version-2 pin remains `offline_pin_only_no_connection_no_consent_no_send`. It is not routing, session, consent, disclosure, contribution, payment, or emergency-recovery authority.

## Security limits

- Dual signatures establish controlled continuity, not host honesty, confidentiality, or safety.
- Compromise of both the prior key and its precommitted successor can authorize a malicious ordinary transition; immutable fields and controller confirmation reduce but cannot eliminate that risk.
- Controller signatures and local history do not defeat rollback when an attacker controls both the filesystem and controller key. `HOST-TRUST-CAPSULE-PROFILE.md` provides complete portable bytes and comparison against a separately preserved capsule, but external publication/anchor receipts remain unimplemented.
- Validity depends on local system time; authenticated time is absent.
- Atomic rename and file synchronization inherit the actual operating system, filesystem, storage-controller, and hardware durability guarantees. Power-loss behavior beyond those guarantees cannot be proven by this implementation.
- Ordinary controller-key rotation is implemented. Historical pin and transition signatures verify against authenticated key-validity intervals, and portable capsule v2 carries the complete dual-signed controller chain.
- Emergency compromise recovery remains unsupported.
