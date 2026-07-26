# EXAMPLES

These files demonstrate shape and field meaning. Repeated hashes, keys, signatures, identities, organizations, jurisdictions, and URLs are test-only placeholders. They are not a genesis, checkpoint, consent grant, token activation, or recovery vote.

Never copy example keys or signatures into a network. A ratified artifact must have correctly derived identifiers, real proof-of-possession, exact document hashes, independent participants, and valid threshold signatures.


The shared Soma/Vera wire examples cover:

- exact Vera host discovery, release/policy binding, and disjoint signing/ingestion-key lifecycle;
- a request-bound Soma return-encryption descriptor;
- the signed clear application envelope and encrypted request stream;
- the signed-and-encrypted private response container;
- accepted/narrowed contribution acknowledgement semantics;
- explicit controller-to-Soma query delegation; and
- a signed answer/source bundle with query authority, citations, provenance, rights, uncertainty, and abstention fields.

`profile_status: freeze_blocking_draft` is intentional. The examples have placeholder identifiers, ciphertext, keys, and signatures and demonstrate strict shape only. They are not successful cryptographic vectors and MUST NOT be sent to a host. Raw plaintext hashes are intentionally absent from clear private request/response containers to prevent dictionary fingerprinting of low-entropy content.

The normative noncircular projections and remaining ratification blockers are in `../ID-DERIVATION.md`.
