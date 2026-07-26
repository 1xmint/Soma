# CONFORMANCE VECTORS

These vectors pin consensus-critical primitives before independent implementations exist.

- canonicalization-v1.json covers a small RFC 8785/I-JSON subset used by the included checker;
- ed25519-rfc8032-v1.json reproduces the first RFC 8032 Ed25519 test vector;
- future releases must add full RFC canonicalization edge cases, domain-separated event signatures, Merkle construction, every state transition, negative cases, and cross-language outputs.

Run `npm ci` before `npm run check`; the pinned Ajv dependency is part of the
reproducible validation path. The included JavaScript remains neither the
required independent second implementation nor a security certification.

`wire-invalid-v1.json` mutates the valid-shape wire examples and pins mandatory rejection of discovery-path substitution, signing/encryption key-role reuse, circular fields, clear plaintext fingerprints, outer/header mismatches, chunk-count mismatch, return-key substitution, contradictory acknowledgement decisions, signing-key mismatch, invalid delegation, and missing citation sources.

`controller-key-rotation-v1.json` pins the stable Soma controller identity, exact old/new key lifecycle, event canonical bytes/ID, and distinct prior/successor signatures. Its invalid companion covers sequence, predecessor, key/hash/window, time, status, disposition, rollback-claim, authority, ID, and signature attacks; the profile is ordinary live-key rotation only, never compromise recovery.

`host-descriptor-succession-v1.json` pins deterministic prior and successor descriptor canonical bytes, IDs, descriptor signatures, proof bytes/ID, and distinct prior/successor proof-signature domains. `host-descriptor-succession-invalid-v1.json` pins rejection of sequence/predecessor substitution, immutable changes, uncommitted keys, scope and time expansion, signature replay/corruption, historic-key deletion, revocation smuggling, overlap expansion, and authority escalation. This closes only ordinary continuity; controller confirmation and a separately ratified emergency-recovery authority remain required.

`host-trust-capsule-v1.json` preserves the original pre-controller-rotation portable format for verification compatibility. `host-trust-capsule-v2.json` adds the complete ordered dual-signed controller-rotation chain, an independently expected initial-key anchor, historical key-window verification, active-key capsule signing, and distinct v2 roots. Its invalid companion covers initial-key substitution, missing/reordered rotation history, either rotation signature, head/count/root substitution, active-key substitution, claim widening, and capsule-signature corruption.

The checker performs standards-complete Draft 2020-12 schema meta-validation,
positive example validation, generated structural-negative validation, the
legacy defensive schema-subset checks, and explicit token, recovery, and wire
semantic/adversarial checks. These checks are necessary but not sufficient
cryptographic conformance. Before the wire profile can leave `freeze_blocking_draft`, independent implementations must publish positive and negative vectors for:

- RFC 9180 setup and key wrap;
- AES-256-GCM chunk AAD, nonces, ciphertext hashes, and Merkle roots;
- every identifier and Ed25519 signature domain; and
- wrong-recipient, lifecycle, replay, truncation, reordering, and outer/inner mismatch cases.

