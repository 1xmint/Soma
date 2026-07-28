# CONTRIBUTING

Contributions are welcome during the draft phase.

Normative changes must:

1. identify the affected invariant, schema, state transition, or recovery behavior;
2. include machine-readable changes and test vectors where applicable;
3. state compatibility, privacy, security, economic, governance, and recovery effects;
4. avoid copying private legacy notes or secrets;
5. distinguish evidence from assertion and technical class from legal conclusion;
6. preserve a clean build and capsule verification.

Before proposing a valuable mainnet release, run:

    npm run check
    npm run manifest
    npm run verify

Generated manifests are reviewed with the source changes. Consensus-critical behavior requires a second independent implementation before ratification.

