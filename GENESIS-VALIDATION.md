# SOMAVERA GENESIS VALIDATION BOUNDARY

Status: **partial implementation boundary; Genesis activation remains blocked**

JSON Schema validity is not Genesis validity. The bundled
`network-genesis.example.json` contains obvious placeholder hashes, keys, and
signatures and is suitable only for structural documentation. It must never be
accepted as a network Genesis.

## Implemented now

The conformance suite exercises a deterministic Genesis identity/tokenless
validator that:

- projects the exact Genesis core defined in `ID-DERIVATION.md`;
- recomputes `genesis_core_hash`, `network_lineage_id`, and the epoch-zero
  `execution_context_id`;
- requires the initial token to be inactive, supply zero, and asset lineage null;
- rejects duplicate validator IDs and public keys;
- rejects non-positive or unsafe aggregate voting power;
- requires at least four validators and prevents any one validator from holding
  one third or more voting power in the pilot profile;
- rejects duplicate external anchors and missing chamber roles.

Positive and adversarial fixtures are synthetic and generated in memory from the
structural example. Passing them proves only these named semantics.

## Still activation-blocking

A production Genesis validator must additionally:

1. resolve the exact governance, chamber-seat, recovery-authority, death-policy,
   build, release, and substrate manifests committed by the core;
2. recompute every manifest and document hash;
3. verify key purpose, proof of possession, lifecycle, controller,
   organization, jurisdiction, common control, threshold, term, and expiry;
4. verify every Genesis ratification signature over the exact domain bytes;
5. require signer independence under the committed bootstrap policy;
6. verify validator consensus keys and map them exactly into the selected
   substrate Genesis;
7. reproduce the initial application state and application hash in two
   independent implementations;
8. verify release signatures, reproducible builds, SBOMs, dependency archives,
   and externally witnessed authenticity anchors;
9. produce a signed ceremony transcript and independent verification report;
10. reject placeholder, example, development, expired, revoked, or self-elevating
    authority.

No CLI may expose `genesis activate`, public validator startup, or valuable state
until every item is implemented and adversarially tested. A schema pass, core
hash pass, or locally green test suite is not ratification.
