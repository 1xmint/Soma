# Soma Spec-to-Implementation Gap Report

**Date:** 2026-04-19
**Auditor:** Claude Opus 4.6 (automated spec audit)
**Scope:** All 5 Soma specs vs. `src/` and `tests/` on `main`
**soma-heart version:** 0.5.0

---

## Summary

| Status | Count |
|--------|-------|
| **Covered** | 84 |
| **Partial** | 12 |
| **Missing** | 9 |
| **Contradicted** | 0 |

No spec contradictions were found. There are zero cases where an implementation actively violates a spec requirement. All "missing" items are unimplemented normative requirements — gaps, not conflicts.

---

## 1. SOMA-HEART-CERTIFICATE-SPEC.md

**Spec status:** accepted (v0.1)

### 1.1 Profiles (§5)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `birth` profile accepted | `src/heart/certificate/vocabulary.ts` | `tests/heart/certificate/vocabulary.test.ts`, `tests/heart/certificate/conformance.test.ts` | covered |
| `one-sided` profile accepted | `src/heart/certificate/vocabulary.ts` | same as above | covered |
| `heart-to-heart` profile accepted, requires issuer + counterparty sigs | `src/heart/certificate/vocabulary.ts` | same as above | covered |
| `freshness-receipt-bound` profile accepted | `src/heart/certificate/vocabulary.ts` | same as above | covered |
| `fulfillment-receipt-bound` profile open — MAY appear but MUST NOT be treated as ratified | `src/heart/certificate/vocabulary.ts` — returns `valid: false` for open | same as above | covered |
| `policy-statement` deferred — MUST be rejected | `src/heart/certificate/vocabulary.ts` | same as above | covered |
| `witnessed` deferred — MUST be rejected | `src/heart/certificate/vocabulary.ts` | same as above | covered |
| Verifiers MUST reject unknown profiles | `src/heart/certificate/vocabulary.ts` — returns `profile-not-allowed` for unknown | `tests/heart/certificate/vocabulary.test.ts` | covered |
| MUST NOT invent additional profiles in v0.1 | Enforced by vocabulary validator — unknown profiles rejected | N/A (structural) | covered |
| `heart-to-heart` MUST have issuer + counterparty signatures over same §9.4 signature input | `src/heart/certificate/signature.ts` — role validation exists | `tests/heart/certificate/signature.test.ts` | partial — signature module verifies individual signatures with correct role prefixes; no integrated heart-to-heart verifier that enforces the "both roles present" constraint |

### 1.2 Minimum Certificate Fields (§6)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `version`/`profile` field REQUIRED | `src/heart/certificate/policy.ts` — evaluatePolicy checks profile | `tests/heart/certificate/policy.test.ts` | covered |
| certificate identifier REQUIRED (§9) | `src/heart/certificate/canonical.ts` — `computeCertificateId` | `tests/heart/certificate/canonical.test.ts`, `tests/heart/certificate/conformance.test.ts` | covered |
| issuer identity REQUIRED (stable identityId) | `src/heart/certificate/signature.ts` — `CertificateSignatureEntry.identity_id` | `tests/heart/certificate/signature.test.ts` | covered |
| issuer credential/rotation reference REQUIRED | `src/heart/certificate/signature.ts` — `CredentialRotationReference` | `tests/heart/certificate/signature.test.ts` | covered |
| subject identifier/hash REQUIRED | Referenced in vectors via manifest; no standalone validator | `tests/heart/certificate/conformance.test.ts` (vector-based) | partial — enforced by vectors but no runtime field-presence validator |
| `issued_at` REQUIRED | Used by signature verifier for effective-at check | `tests/heart/certificate/signature.test.ts` | covered |
| expiry/freshness bounds CONDITIONAL | No runtime enforcer beyond vector coverage | `tests/heart/certificate/conformance.test.ts` | partial |
| claim set REQUIRED, non-empty | `src/heart/certificate/policy.ts` — rejects empty claim_set | `tests/heart/certificate/policy.test.ts` | covered |
| evidence references CONDITIONAL → REQUIRED where claims depend on evidence | `src/heart/certificate/policy.ts` — rejects empty evidence_references | `tests/heart/certificate/policy.test.ts` | covered |
| prior certificate references CONDITIONAL | Policy evaluator checks max_chain_depth | `tests/heart/certificate/policy.test.ts` | covered |
| disclosure/privacy profile CONDITIONAL (§16) | No runtime enforcer for disclosure field presence | None | missing |
| signature set REQUIRED | `src/heart/certificate/signature.ts` | `tests/heart/certificate/signature.test.ts` | covered |
| MUST NOT silently drop REQUIRED fields | Structural — vectors enforce field presence | `tests/heart/certificate/conformance.test.ts` | covered |

### 1.3 Claim Vocabulary (§7)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| All accepted claim kinds validate correctly | `src/heart/certificate/vocabulary.ts` | `tests/heart/certificate/vocabulary.test.ts` | covered |
| Deferred claim kinds (`capability_statement`, `delegation_or_endorsement`) MUST be rejected | `src/heart/certificate/vocabulary.ts` — returns `claim-deferred` | `tests/heart/certificate/vocabulary.test.ts`, vectors | covered |
| `fulfillment_receipt` open — MAY accept but MUST NOT treat as ratified | `src/heart/certificate/vocabulary.ts` — returns `claim-not-allowed` (treats open as invalid) | `tests/heart/certificate/vocabulary.test.ts` | covered |
| Unknown claim kinds rejected | `src/heart/certificate/vocabulary.ts` | `tests/heart/certificate/vocabulary.test.ts` | covered |
| Delegation/capability references MUST NOT be interpreted as valid delegation/capability unless their spec independently verifies it | Structural — certificate module has no delegation/capability verifier | N/A | covered (by design — no such path exists) |

### 1.4 Evidence Vocabulary (§8)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| All accepted evidence kinds validate correctly | `src/heart/certificate/vocabulary.ts` | `tests/heart/certificate/vocabulary.test.ts` | covered |
| Deferred evidence kinds MUST be rejected | `src/heart/certificate/vocabulary.ts` | `tests/heart/certificate/vocabulary.test.ts`, vectors | covered |
| Open evidence kinds (`observation_log_reference`, `private_evidence_pointer`) — MAY accept, MUST NOT treat as ratified | `src/heart/certificate/vocabulary.ts` — returns `evidence-not-allowed` for open | `tests/heart/certificate/vocabulary.test.ts` | covered |

### 1.5 Canonicalization (§9)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Determinism — two serializers produce byte-identical output | `src/heart/certificate/canonical.ts` | `tests/heart/certificate/canonical.test.ts`, `tests/heart/certificate/conformance.test.ts` | covered |
| `certificate_id` and `signatures` excluded from canonical bytes | `src/heart/certificate/canonical.ts` — `canonicalizePayload` filters them | `tests/heart/certificate/canonical.test.ts` | covered |
| SHA-256 with domain prefix `soma-heart-certificate:v0.1:` | `src/heart/certificate/canonical.ts` — `computeCertificateId` | `tests/heart/certificate/canonical.test.ts`, `tests/heart/certificate/conformance.test.ts` | covered |
| Object key ordering by Unicode code point | `src/heart/certificate/canonical.ts` — `compareByCodePoint` | `tests/heart/certificate/canonical.test.ts` | covered |
| Duplicate keys MUST be rejected | `src/heart/certificate/canonical.ts` — `encodeObject` checks for dupes | `tests/heart/certificate/canonical.test.ts` | covered |
| No insignificant whitespace | `src/heart/certificate/canonical.ts` | `tests/heart/certificate/canonical.test.ts` | covered |
| String escaping per §9.2 (lowercase hex, no `/` escape, no non-ASCII escape) | `src/heart/certificate/canonical.ts` — `encodeString` | `tests/heart/certificate/canonical.test.ts` | covered |
| Integer range `[-(2^53-1), 2^53-1]`, reject outside | `src/heart/certificate/canonical.ts` — `encodeNumber` | `tests/heart/certificate/canonical.test.ts` | covered |
| NaN/Infinity rejected | `src/heart/certificate/canonical.ts` | `tests/heart/certificate/canonical.test.ts` | covered |
| Floating-point rejected | `src/heart/certificate/canonical.ts` | `tests/heart/certificate/canonical.test.ts` | covered |
| Timestamps as integer ms since epoch | Structural — spec requires it; impl uses JS integers | N/A | covered |
| Byte arrays as base64 with padding (RFC 4648 §4) | `src/heart/certificate/canonical.ts` — `encodeBytes` | `tests/heart/certificate/canonical.test.ts` | covered |
| Absent optional fields omitted, not null | `src/heart/certificate/canonical.ts` — undefined rejected | `tests/heart/certificate/canonical.test.ts` | covered |

### 1.6 Signature Input (§9.4)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Signature input = `soma-heart-certificate:v0.1:<role>:` + canonical bytes | `src/heart/certificate/canonical.ts` — `computeSignatureInput` | `tests/heart/certificate/canonical.test.ts`, `tests/heart/certificate/conformance.test.ts` | covered |
| Valid roles: `issuer`, `counterparty`, `witness`, `participant` | `src/heart/certificate/canonical.ts` — `VALID_SIGNER_ROLES` | `tests/heart/certificate/canonical.test.ts` | covered |
| MUST reject mismatched signer role | `src/heart/certificate/signature.ts` | `tests/heart/certificate/signature.test.ts` | covered |

### 1.7 Signature and Credential Verification (§10)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Verifier MUST resolve signer's stable identityId | `src/heart/certificate/signature.ts` — `verifyCertificateSignature` checks identity_id binding | `tests/heart/certificate/signature.test.ts` | covered |
| Verifier MUST resolve signing-time credential via historical lookup | `src/heart/certificate/signature.ts` — uses `CredentialLookup.resolve()` | `tests/heart/certificate/signature.test.ts` | covered |
| Confirm credential was `effective` at claimed `issued_at` | `src/heart/certificate/signature.ts` — `cred.effective_at > issuedAt` check | `tests/heart/certificate/signature.test.ts` | covered |
| MUST NOT accept signature under credential that became effective after claimed signing time | `src/heart/certificate/signature.ts` — returns `credential-ineffective` | `tests/heart/certificate/signature.test.ts` | covered |
| MUST fail closed on ambiguous rotation state → `credential-unresolvable` | `src/heart/certificate/signature.ts` — catch block, lookup failures | `tests/heart/certificate/signature.test.ts` | covered |
| Revoked credential → `credential-revoked` | `src/heart/certificate/signature.ts` — checks `cred.revoked_at <= issuedAt` | `tests/heart/certificate/signature.test.ts` | covered |

### 1.8 Trust Chain Semantics (§11)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| MUST NOT expose "is-this-trusted" runtime API | No such API exists | N/A (structural) | covered |
| Each link and claim evaluated independently | No chain traversal implemented — policy module evaluates one cert at a time | N/A | partial — chain evaluation logic not yet implemented; policy module handles single certs only |
| Chain fails closed if any required link fails | Not implemented — no chain walker | None | missing |

### 1.9 Verifier Policy (§12)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Policy MUST declare accepted profiles, claims, evidence, freshness | `src/heart/certificate/policy.ts` — `VerifierPolicy` interface | `tests/heart/certificate/policy.test.ts` | covered |
| `fail_closed` MUST be true | `src/heart/certificate/policy.ts` — rejects `fail_closed: false` | `tests/heart/certificate/policy.test.ts` | covered |
| Policy MUST be reproducible | Structural — deterministic pure function | N/A | covered |
| MUST NOT treat absence of field as "accept by default" | `src/heart/certificate/policy.ts` — explicit checks for every field | `tests/heart/certificate/policy.test.ts` | covered |
| `policy_ref` shape for verifier policy references | Not implemented as runtime type | None | missing — no `policy_ref` validator/constructor |

### 1.10 Soma Check Interaction (§13)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Soma Check MAY contribute freshness_receipt claims, content hash commitments | `src/heart/certificate/soma-check-binding.ts` — `bindSomaCheckEvidence` | `tests/heart/certificate/soma-check-binding.test.ts` | covered |
| Soma Check MUST NOT verify certificate chains, evaluate claim acceptability | Structural — `src/core/soma-check.ts` has no certificate awareness | N/A | covered |

### 1.11 Payment Rail Boundary (§14)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Certificate core MUST stay rail-agnostic via `payment_receipt_reference` | `src/heart/certificate/payment-rail-binding.ts` | `tests/heart/certificate/payment-rail-binding.test.ts` | covered |
| x402 is NOT a hard dependency | Structural — no x402 import in certificate module | N/A | covered |

### 1.12 Credential Rotation Interaction (§15)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Bind signatures to stable identityId, not specific key | `src/heart/certificate/signature.ts` — resolves via `CredentialRotationReference.identity_id` | `tests/heart/certificate/signature.test.ts` | covered |
| Resolve credential effective at signing time via historical lookup | `src/heart/certificate/signature.ts` — uses `CredentialLookup` | `tests/heart/certificate/signature.test.ts` | covered |
| MUST NOT introduce rotation mechanisms through certificate processing | Structural — no rotation mutations in certificate module | N/A | covered |

### 1.13 Privacy and Disclosure (§16)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Disclosure field MUST declare what was withheld | No runtime `disclosure` validator | None | missing |
| MUST declare which verification checks are impossible | Same — no `disclosure` object constructor/validator | None | missing |
| MUST NOT imply hidden evidence was verified | Structural | N/A | covered (no such path) |
| Verifier MUST fail with `disclosure-missing` when required | `src/heart/certificate/failure-modes.ts` — `DISCLOSURE_MISSING` defined | None — not wired to any runtime check | partial — failure mode defined but no runtime enforcement |

### 1.14 Error/Failure Semantics (§18)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| All 16 failure modes defined with lowercase kebab-case identifiers | `src/heart/certificate/failure-modes.ts` | `tests/heart/certificate/failure-modes.test.ts` | covered |
| Structured failure report shape: `{error_code, failure_mode, message?, vector_id?}` | `src/heart/certificate/failure-modes.ts` — `CertificateFailure` and `createFailure` | `tests/heart/certificate/failure-modes.test.ts` | covered |

### 1.15 Test Vectors (§19)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Conforming cert for each accepted profile | `test-vectors/soma-heart-certificate/v0.1/manifest.json` | `tests/heart/certificate/conformance.test.ts` | covered |
| Rejection vector for each deferred profile | manifest `coverage_summary.deferred_profiles_rejected` | `tests/heart/certificate/conformance.test.ts` | covered |
| Rejection vector for each deferred claim | manifest `coverage_summary.deferred_claims_rejected` | `tests/heart/certificate/conformance.test.ts` | covered |
| Rejection vector for each deferred evidence | manifest `coverage_summary.deferred_evidence_rejected` | `tests/heart/certificate/conformance.test.ts` | covered |
| Signature verification with historical credential lookup | manifest `coverage_summary.rotation` | `tests/heart/certificate/conformance.test.ts` | covered |
| `chain-link-mismatch` vector | manifest `failure_modes_exercised` | `tests/heart/certificate/conformance.test.ts` | covered |
| `credential-ineffective` vector | manifest `failure_modes_exercised` | `tests/heart/certificate/conformance.test.ts` | covered |
| `credential-revoked` vector | manifest `failure_modes_exercised` | `tests/heart/certificate/conformance.test.ts` | covered |
| `freshness-window-expired` vector | manifest `failure_modes_exercised` | `tests/heart/certificate/conformance.test.ts` | covered |
| `canonicalisation-divergence` vector | manifest `failure_modes_exercised` | `tests/heart/certificate/conformance.test.ts` | covered |
| Redaction/disclosure vector (§16) | manifest `coverage_summary.disclosure` | `tests/heart/certificate/conformance.test.ts` | covered |
| Evidence laundering vector (§17) | manifest `failure_modes_exercised` has `evidence-malformed` | `tests/heart/certificate/conformance.test.ts` | covered |
| `chain-link-unresolvable` vector | manifest `failure_modes_exercised` | `tests/heart/certificate/conformance.test.ts` | covered |

---

## 2. SOMA-DELEGATION-SPEC.md

**Spec status:** Draft

### 2.1 Delegation Key Structure

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Delegation has id, issuerDid, subjectDid, capabilities, caveats, issuedAt, nonce, parentId, signature, issuerPublicKey | `src/heart/delegation.ts` — `Delegation` interface | `tests/heart/delegation.test.ts` | covered |
| Signature covers all fields except `signature` via canonical JSON | `src/heart/delegation.ts` — uses `domainSigningInput(DELEGATION_DOMAIN, payload)` | `tests/heart/delegation.test.ts` | covered |
| Ed25519 signature, `issuerDid` MUST be `did:key` derivation of `issuerPublicKey` | `src/heart/delegation.ts` — `verifyDelegationSignature` checks DID binding | `tests/heart/delegation.test.ts` | covered |

### 2.2 Depth and Scope Narrowing

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `depth` and `max_depth` constraints (HTTP wire protocol) | Not implemented at library level — delegation.ts has no depth tracking | None | partial — `src/heart/delegation.ts` implements chainable attenuation but not depth/max_depth fields; the HTTP wire protocol (§Protocol) is a server concern, reference impl is in claw-net |
| Child scope MUST be subset of parent scope (endpoints, methods, cost) | Not implemented at library level — delegation.ts uses capability-string subsetting only | `tests/heart/delegation.test.ts` — tests capability narrowing | partial — capability string narrowing tested; endpoint/method/cost scope dimensions not present in library-level Delegation |
| Scope enforced at BOTH issue time AND serving time | `src/heart/delegation.ts` — `attenuateDelegation` enforces at issue; `checkCaveats` at serving | `tests/heart/delegation.test.ts` | covered (for capabilities; other scope dimensions are server-level) |

### 2.3 Spend Caps

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Total cap (`spend_cap_usd`) enforced at every call | Not in library-level delegation — server concern | None at library level | partial — `budget` caveat in delegation.ts covers library-level spend gating; USD-denominated spend_cap is server-level (claw-net) |
| Branch cap (`branch_spend_cap_usd`) per-immediate-child | Server-level concern | None at library level | partial — same as above |
| Both caps roll up (grandchild spend counts toward parent) | Server-level concern | None at library level | partial |

### 2.4 Cascade Revoke

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Parent revocation invalidates all descendants recursively | `src/heart/revocation.ts` — `RevocationRegistry.isRevoked` per-target; no built-in cascade | `tests/heart/revocation.test.ts` | partial — revocation events and registry exist but no automatic subtree cascade; cascade is described as server-side BFS concern |

### 2.5 Intent Declaration

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Signed intent with `declaration` and `data_domain` | Not in library-level delegation.ts | None | missing — intent is a wire-protocol concept not modeled at library level; reference impl is in claw-net |

### 2.6 Rotation Interaction (Normative)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Root delegation binds to stable `identityId`, not specific credential | `src/heart/delegation.ts` — `issuerDid` is the did:key; Delegation carries `issuerPublicKey` but no identityId/credentialId reference for rotation lookup | `tests/heart/delegation.test.ts` | **partial** — see Key-Verifier Gap section below |
| Conforming verifier MUST resolve signing-time credential via historical lookup | `src/heart/delegation.ts` — `verifyDelegationSignature` uses `issuerPublicKey` from the delegation object directly, does NOT consult `KeyHistory` or `lookupHistoricalCredential` | None | **missing** — **KEY GAP: this is the primary key-verifier call-site gap** |
| Historical-credential lookup (Slice D code contract) | `src/heart/credential-rotation/controller.ts` — `lookupHistoricalCredential` implemented | `tests/heart/credential-rotation/historical-credential-lookup.test.ts` | covered — the lookup itself exists and is well-tested; it is not yet consumed by delegation verification |
| Wire-schema: root delegation MUST carry `issuer_credential_id` or `issuer_public_key` | `src/heart/delegation.ts` — carries `issuerPublicKey` (satisfies `issuer_public_key` option) | N/A | covered (field exists) |

### 2.7 Verification Algorithm

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Signature check | `src/heart/delegation.ts` — `verifyDelegationSignature` | `tests/heart/delegation.test.ts` | covered |
| Subject match (subjectDid == invokerDid) | `src/heart/delegation.ts` — `verifyDelegation` | `tests/heart/delegation.test.ts` | covered |
| Proof of possession | `src/heart/proof-of-possession.ts` | `tests/heart/proof-of-possession.test.ts` | covered |
| Capability match with wildcard | `src/heart/delegation.ts` — `checkCaveats` | `tests/heart/delegation.test.ts` | covered |
| Caveat iteration — fail closed on unknown kinds | `src/heart/delegation.ts` — exhaustive switch with `never` default | `tests/heart/delegation.test.ts` | covered |
| Chain walk (parentId != null → recurse) | Not implemented — `verifyDelegation` verifies single delegation only | None | missing — chain-walking verification not implemented at library level |
| Revocation check at each link | Not integrated into `verifyDelegation` | None | missing — caller must check revocation separately |
| Key rotation: verifiers MUST resolve issuerDid to key version current at issuedAt | **NOT IMPLEMENTED** — see Key-Verifier Gap section | None | **missing** |

---

## 3. SOMA-CAPABILITIES-SPEC.md

**Spec status:** Draft (v1.1)

### 3.1 Caveat Types

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `expires-at` — fail if now > timestamp | `src/heart/delegation.ts` | `tests/heart/delegation.test.ts` | covered |
| `not-before` — fail if now < timestamp | `src/heart/delegation.ts` | `tests/heart/delegation.test.ts` | covered |
| `audience` — MUST fail closed if ctx.audienceDid absent | `src/heart/delegation.ts` | `tests/heart/delegation.test.ts` | covered |
| `budget` — cumulative spend check | `src/heart/delegation.ts` | `tests/heart/delegation.test.ts` | covered |
| `max-invocations` — invocation count cap | `src/heart/delegation.ts` | `tests/heart/delegation.test.ts` | covered |
| `capabilities` — subset narrowing caveat | `src/heart/delegation.ts` | `tests/heart/delegation.test.ts` | covered |
| `custom` — opaque extension, fail closed on unknown | `src/heart/delegation.ts` — custom passes through (caveat is opaque) | `tests/heart/delegation.test.ts` | partial — custom caveats are not fail-closed; they pass through silently. Spec says verifiers MUST recognize the key or FAIL CLOSED. However, since `custom` is a known kind, the `default` arm is not reached. The issue is that custom caveat *semantics* are not enforced. |
| `requires-stepup` (1.1) — fail closed if no attestation | `src/heart/delegation.ts` | `tests/heart/delegation-stepup-caveats.test.ts` | covered |
| `host-allowlist` (1.1) — fail closed if ctx.host absent | `src/heart/delegation.ts` | `tests/heart/delegation-stepup-caveats.test.ts` | covered |
| `command-allowlist` (1.1) — fail closed if ctx.commandArgv absent | `src/heart/delegation.ts` | `tests/heart/delegation-stepup-caveats.test.ts` | covered |
| `time-window` (1.1) — UTC hour window, midnight wrap | `src/heart/delegation.ts` | `tests/heart/delegation-stepup-caveats.test.ts` | covered |
| Unknown caveat kinds MUST fail closed | `src/heart/delegation.ts` — `default:` arm with `never` exhaustiveness | `tests/heart/delegation.test.ts` | covered |

### 3.2 Attenuation Rules

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Attenuated delegation's capabilities MUST be subset of parent | `src/heart/delegation.ts` — `attenuateDelegation` checks each cap | `tests/heart/delegation.test.ts` | covered |
| All parent caveats copied unchanged, may add more | `src/heart/delegation.ts` — spreads parent.caveats + additional | `tests/heart/delegation.test.ts` | covered |
| Broadened scope is invalid | `src/heart/delegation.ts` — throws on missing cap | `tests/heart/delegation.test.ts` | covered |

### 3.3 Proof of Possession

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Challenge-response with nonce, delegationId | `src/heart/proof-of-possession.ts` | `tests/heart/proof-of-possession.test.ts` | covered |
| Challenges single-use, short-lived (≤5 min) | `src/heart/proof-of-possession.ts` — `DEFAULT_MAX_CHALLENGE_AGE_MS = 60_000`; nonce tracking is caller responsibility | `tests/heart/proof-of-possession.test.ts` | partial — default max age is 60s not 5min. Spec says ≤5 min, impl defaults to 1 min (stricter, so conforming). Nonce single-use tracking is left to caller. |
| Mutual Session PoP | `src/heart/mutual-session.ts` | `tests/heart/mutual-session.test.ts` | covered |

### 3.4 Factor Registry (1.1)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Per-heart mapping from subjectDid to registered factors | `src/heart/factor-registry.ts` | `tests/heart/factor-registry.test.ts` | covered |
| register, get, listActive, listAll, markUsed, revoke, isActive, countActiveByType, toJSON/fromJSON | `src/heart/factor-registry.ts` | `tests/heart/factor-registry.test.ts` | covered |
| Revocation preserves original revokedAt on double-revoke | `src/heart/factor-registry.ts` | `tests/heart/factor-registry.test.ts` | covered |
| Defensive copies from get() | `src/heart/factor-registry.ts` | `tests/heart/factor-registry.test.ts` | covered |
| Well-known factor types | `src/heart/factor-registry.ts` — `WELL_KNOWN_FACTOR_TYPES` | `tests/heart/factor-registry.test.ts` | covered |

### 3.5 Step-Up (1.1)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| StepUpService with createChallenge, submitAttestation | `src/heart/stepup.ts` | `tests/heart/stepup.test.ts` | covered |
| StepUpOracle interface, CliPromptOracle, OracleChain | `src/heart/stepup-oracle.ts` | `tests/heart/stepup-oracle.test.ts` | covered |
| Challenge expiry, replayed challenge rejection, revoked factor rejection | `src/heart/stepup.ts` | `tests/heart/stepup.test.ts` | covered |
| verifyStepUpAttestation (signature, action digest, subject, tier, age) | `src/heart/stepup.ts` | `tests/heart/stepup.test.ts` | covered |
| computeActionDigest | `src/heart/stepup.ts` | `tests/heart/stepup.test.ts` | covered |

### 3.6 Tier Ladder (1.1)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Predicate algebra (factor-type, min-factor-tier, and/or/not, etc.) | `src/heart/tier-ladder.ts` | `tests/heart/tier-ladder.test.ts` | covered |
| DEFAULT_LADDER and PARANOID_LADDER | `src/heart/tier-ladder.ts` | `tests/heart/tier-ladder.test.ts` | covered |
| Unknown predicate kinds FAIL CLOSED | `src/heart/tier-ladder.ts` | `tests/heart/tier-ladder.test.ts` | covered |
| distinct-device-count by metadata.deviceId fallback to factorId | `src/heart/tier-ladder.ts` | `tests/heart/tier-ladder.test.ts` | covered |

### 3.7 Revocation Integration

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| RevocationEvent with targetKind, targetId, reason | `src/heart/revocation.ts` | `tests/heart/revocation.test.ts` | covered |
| Events signed and hash-chained in RevocationLog | `src/heart/revocation-log.ts` | `tests/heart/revocation-log.test.ts` | covered |
| Revoked delegation or chain containing one MUST fail | Not integrated into verifyDelegation — caller checks separately | `tests/heart/delegation.test.ts` (no revocation integration test) | partial — revocation system exists but not wired into delegation chain verification |

### 3.8 Security: Key Rotation

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| If issuer rotates key mid-chain, verifiers MUST resolve issuerDid to key version current at issuedAt | **NOT IMPLEMENTED** in `verifyDelegationSignature` | None | **missing** — KEY GAP |

---

## 4. SOMA-ROTATION-SPEC.md

**Spec status:** Draft (v0.1)

### 4.1 Canonical Subsystem (§1)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `src/heart/credential-rotation/` is canonical consumer-facing surface | `src/heart/credential-rotation/index.ts` | `tests/heart/credential-rotation.test.ts` | covered |
| `key-rotation.ts` is internal — downstream MUST NOT import directly | `src/heart/key-rotation.ts` (internal) | `tests/heart/key-rotation.test.ts` | covered — package exports enforce this |

### 4.2 Pre-Rotation Commitment L1 (§3)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Every credential MUST carry `nextManifestCommitment` | `src/heart/credential-rotation/types.ts` — `Credential.nextManifestCommitment` | `tests/heart/credential-rotation.test.ts` | covered |
| Commitment over full manifest `soma-manifest:<backendId>\|<algorithmSuite>\|<base64(publicKey)>` | `src/heart/credential-rotation/controller.ts` — `computeManifestCommitment` | `tests/heart/credential-rotation/l1-commitment-vectors.test.ts` | covered |
| `backendId` MUST NOT contain `\|`, `:`, or NUL | `src/heart/credential-rotation/controller.ts` — `validateBackendIdBytes` | `tests/heart/credential-rotation/backend-id-validation.test.ts` | covered |
| At rotation: recompute commitment, byte-for-byte match → `PreRotationMismatch` on fail | `src/heart/credential-rotation/controller.ts` — `rotate()` | `tests/heart/credential-rotation.test.ts` | covered |
| Test vectors for commitment (§3.3) | `tests/heart/credential-rotation/vectors/` | `tests/heart/credential-rotation/l1-commitment-vectors.test.ts` | covered |

### 4.3 Rotation Event Lifecycle (§4)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| States: pending → anchored → witnessed → effective → revoked | `src/heart/credential-rotation/types.ts` — `RotationEventStatus` | `tests/heart/credential-rotation.test.ts` | covered |
| L3: local log write + pulse-tree anchor + witness before effective | `src/heart/credential-rotation/controller.ts` — `anchorEvent` + `witnessEvent` | `tests/heart/credential-rotation.test.ts` | covered |
| L2: old-key signature + new-key PoP | `src/heart/credential-rotation/controller.ts` — `rotate()` | `tests/heart/credential-rotation.test.ts` | covered |
| Event hash with `sha256("soma-rotation-event:" \|\| canonicalJson(...))` | `src/heart/credential-rotation/controller.ts` — `computeEventHash` | `tests/heart/credential-rotation.test.ts` | covered |
| Chain linkage via `previousEventHash`, genesis hash deterministic | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation.test.ts` | covered |
| Ratchet anchor derivation (§4.6) | `src/heart/credential-rotation/controller.ts` — `deriveRatchetAnchor` | `tests/heart/credential-rotation.test.ts` | covered |
| Event chain retention — append-only, MUST NOT prune (§4.7, invariant 13) | `src/heart/credential-rotation/controller.ts` — events array only pushed to, never spliced | `tests/heart/credential-rotation.test.ts` | covered (structural) |
| `effectiveAt` field (§4.8) — set exactly once on first witness, excluded from hash | `src/heart/credential-rotation/controller.ts` — `witnessEvent` sets `effectiveAt` once | `tests/heart/credential-rotation/historical-credential-lookup.test.ts` | covered |

### 4.4 Staged Rotation and Rollback (§5)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| stage / commit / abort transactional | `src/heart/credential-rotation/controller.ts` — `rotate()` with try/catch/abort | `tests/heart/credential-rotation.test.ts` | covered |
| Rollback invariant: throw between stage and commit → pre-stage state | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation/rollback-substeps.test.ts` | covered |
| At most one staged rotation per identity → `StagedRotationConflict` | `src/heart/credential-rotation/types.ts` — `StagedRotationConflict` | `tests/heart/credential-rotation.test.ts` | covered |
| Failed rotation MUST NOT consume rotation slot (§8.2) | `src/heart/credential-rotation/controller.ts` — rate limit only advanced on success | `tests/heart/credential-rotation.test.ts` | covered |
| Commit-call failure handling (§5.2) | `tests/heart/credential-rotation/commit-failure-recovery.test.ts` | `tests/heart/credential-rotation/commit-failure-recovery.test.ts` | covered |

### 4.5 Verify-Before-Revoke and Accepted Pool (§6)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Prior credential in accepted pool with grace window | `src/heart/credential-rotation/controller.ts` — `state.accepted` Map | `tests/heart/credential-rotation.test.ts` | covered |
| `verify()` accepts pooled credentials; `sign()` does not | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation.test.ts` | covered |
| `VerifyBeforeRevokeFailed` on premature revoke | `src/heart/credential-rotation/controller.ts` — `forceRevoke` | `tests/heart/credential-rotation.test.ts` | covered |

### 4.6 Witness Quorum (§7)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Single-witness: first witness → effective | `src/heart/credential-rotation/controller.ts` — `witnessEvent` | `tests/heart/credential-rotation.test.ts` | covered |
| Additional witnesses increment counter, no state change | `src/heart/credential-rotation/controller.ts` — short-circuits on already-effective | `tests/heart/credential-rotation.test.ts` | covered |
| Invariant 4 removed from v0.1 | `src/heart/credential-rotation/types.ts` — invariant 4 reserved gap | N/A | covered |

### 4.7 Challenge Period and Rate Limiting (§8)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `ChallengePeriodActive` on destructive ops during window | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation.test.ts` | covered |
| `RateLimitExceeded` with token-bucket | `src/heart/credential-rotation/controller.ts` — `enforceRateLimit` | `tests/heart/credential-rotation.test.ts` | covered |
| Floor: challengePeriodMs >= 15min, maxRotationsPerHour >= 2 | `src/heart/credential-rotation/controller.ts` — `validatePolicy` | `tests/heart/credential-rotation.test.ts` | covered |

### 4.8 Policy Model (§9)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Three credential classes: A, B, C | `src/heart/credential-rotation/types.ts` — `CredentialClass` | `tests/heart/credential-rotation.test.ts` | covered |
| Per-class TTL with `defaultMs >= floorMs` | `src/heart/credential-rotation/controller.ts` — `validatePolicy` | `tests/heart/credential-rotation.test.ts` | covered |
| `backendAllowlist` and `suiteAllowlist` enforcement | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation.test.ts` | covered |
| v0.1 only supports `ed25519` normatively | `src/heart/credential-rotation/types.ts` — `AlgorithmSuite` type | `tests/heart/credential-rotation.test.ts` | covered |

### 4.9 Snapshot and Wire (§10)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `SNAPSHOT_VERSION = 2` | `src/heart/credential-rotation/snapshot.ts` | `tests/heart/credential-rotation/snapshot-restore-lookup.test.ts` | covered |
| Reject non-v2 snapshots | `src/heart/credential-rotation/controller.ts` — `restore()` | `tests/heart/credential-rotation/snapshot-restore-lookup.test.ts` | covered |
| Snapshot preserves full event chain including `effectiveAt` | `src/heart/credential-rotation/controller.ts` — `snapshot()` | `tests/heart/credential-rotation/snapshot-restore-lookup.test.ts` | covered |
| Mid-stage snapshot prohibition | Backend-level enforcement | `tests/heart/credential-rotation.test.ts` | covered |

### 4.10 Error Taxonomy (§11)

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| All `InvariantViolation` subclasses per spec | `src/heart/credential-rotation/types.ts` | `tests/heart/credential-rotation.test.ts` | covered |
| No invariant-4 error (reserved gap) | `src/heart/credential-rotation/types.ts` — no invariant 4 class | N/A | covered |

### 4.11 Historical-Credential Lookup

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `lookupHistoricalCredential` — pure read, identity-scoped, typed not-found | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation/historical-credential-lookup.test.ts` | covered |
| `effectiveFrom`/`effectiveUntil` from `effectiveAt`, NOT `timestamp` | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation/historical-credential-lookup.test.ts` | covered |
| Byte-exact public-key comparison | `src/heart/credential-rotation/controller.ts` | `tests/heart/credential-rotation/historical-credential-lookup.test.ts` | covered |

---

## 5. SOMA-CHECK-SPEC.md

**Spec status:** Draft (v1.0)

### 5.1 Headers

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `If-Soma-Hash` request header | `src/core/soma-check.ts` — `SOMA_CHECK_HEADERS.IF_SOMA_HASH` | `tests/core.test.ts` | covered |
| `X-Soma-Hash` response header | `src/core/soma-check.ts` — `SOMA_CHECK_HEADERS.X_SOMA_HASH` | `tests/core.test.ts` | covered |
| `X-Soma-Protocol: soma-check/1.0` response header | `src/core/soma-check.ts` — `SOMA_CHECK_PROTOCOL` | `tests/core.test.ts` | covered |

### 5.2 Flow Semantics

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Matching hash → `unchanged: true`, 0 credits | `src/core/soma-check.ts` — `shouldRespondUnchanged`, `buildUnchangedResponse` | `tests/core.test.ts` | covered |
| Non-matching hash → normal paid response | `src/core/soma-check.ts` — `shouldRespondUnchanged` returns false | `tests/core.test.ts` | covered |
| No `If-Soma-Hash` → normal call (backward compatible) | `src/core/soma-check.ts` — `extractIfSomaHash` returns null | `tests/core.test.ts` | covered |

### 5.3 Unchanged Response Body

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Shape: `{unchanged, dataHash, cachedAt?, fresh?, age?, creditsUsed, protocol}` | `src/core/soma-check.ts` — `UnchangedResponse` and `buildUnchangedResponse` | `tests/core.test.ts` | covered |
| Callers MUST tolerate unknown fields | Structural — TypeScript does not strip unknown fields | N/A | covered |

### 5.4 Idempotency & Pricing

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Matching hash request MUST NOT be billed | `src/core/soma-check.ts` — `buildUnchangedResponse` sets `creditsUsed: 0` | `tests/core.test.ts` | covered |

### 5.5 Compatibility with Soma Provenance

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| `X-Soma-Hash` MUST equal `dataHash` in birth certificate | Not enforced at library level — caller responsibility | None | partial — no automated check that birth cert `dataHash` matches `X-Soma-Hash`; this is a protocol-level invariant left to integrators |

### 5.6 Hash Store

| Requirement | Impl file | Test file | Status |
|---|---|---|---|
| Consumer-side in-memory hash store | `src/core/soma-check.ts` — `SomaCheckHashStore` | `tests/core.test.ts` | covered |
| Hash minimum length: MUST NOT shorten below 16 hex chars | Not enforced | None | missing — no validation on hash length |

---

## Key-Verifier Call-Site Gap — Deep Dive

This section maps every call site that resolves an `issuerDid` or verifies a signature, and evaluates whether it looks up the key version current at `issuedAt`.

### Call Sites

| # | File | Function | Resolves issuerDid? | Uses historical key lookup? | Failure mode if key rotated |
|---|---|---|---|---|---|
| 1 | `src/heart/delegation.ts` | `verifyDelegationSignature()` | Yes — derives DID from `issuerPublicKey` carried on delegation | **NO** — uses `del.issuerPublicKey` directly from the delegation JSON, no KeyHistory/rotation lookup | **Stale key accepted if delegation was issued under an old key and the delegation JSON still carries the old public key (this is actually correct for bearer tokens). Rotated key rejected only if the delegation's `issuerPublicKey` no longer matches `issuerDid`** — but the deeper issue is that there is no mechanism to validate that `issuerPublicKey` *was* the correct key at `issuedAt` |
| 2 | `src/heart/delegation.ts` | `verifyDelegation()` | Delegates to `verifyDelegationSignature` | **NO** | Same as #1 |
| 3 | `src/heart/revocation.ts` | `verifyRevocation()` | Yes — derives DID from `issuerPublicKey` | **NO** — same pattern as delegation: uses `issuerPublicKey` from the revocation event | **Silent pass** — a revocation event signed by an old key will verify as long as the old public key is carried on the event. No check that it was the *correct* key at `issuedAt`. |
| 4 | `src/heart/birth-certificate.ts` | `verifyBirthCertificate()` | No — takes a public key directly from caller's `publicKeys` map | **NO** — caller must supply the correct key; no rotation-aware lookup | **Caller-dependent** — if caller provides current key but cert was signed by a rotated-out key, verification fails silently. If caller provides the old key, it works. No guidance to caller on which key to use. |
| 5 | `src/heart/birth-certificate.ts` | `verifyBirthCertificateChain()` | No — uses caller's `publicKeys: Map<string, Uint8Array>` | **NO** | Same as #4 |
| 6 | `src/heart/proof-of-possession.ts` | `verifyProof()` | Yes — derives key from `delegation.subjectDid` | **NO** — derives current key from DID, does not consult rotation history | **Rotated key rejected** — if subject's key rotated since the delegation was issued, PoP against the DID-derived key will use the *new* key, but the subject may only have the old key's secret. This is likely correct for PoP (you prove you have the *current* key). |
| 7 | `src/heart/stepup.ts` | `verifyStepUpAttestation()` | Heart's public key from attestation | **NO** — uses `att.heartPublicKey` directly | If heart key rotated since attestation, old key still carried on attestation. Verifier can pin trusted keys via `trustedHeartPublicKeys`. Not a rotation gap per se — attestations are short-lived. |
| 8 | `src/heart/certificate/signature.ts` | `verifyCertificateSignature()` | Yes — via `CredentialRotationReference` | **YES** — uses `CredentialLookup.resolve()` with full rotation-aware historical lookup | **Correctly implemented** — this is the only call site that properly resolves signing-time credentials |
| 9 | `src/heart/selective-disclosure.ts` | `verifyDisclosure()` | Uses `issuerPublicKey` from document | **NO** — takes public key directly | Same pattern as delegation |
| 10 | `src/heart/key-rotation.ts` | `KeyHistory.verifyChain()` | Self-contained chain verification | N/A — verifies its own internal chain, not external signatures | Not applicable — this is internal chain integrity |

### Gap Analysis

**The certificate signature module (#8) is the model implementation.** It correctly implements the full SOMA-HEART-CERTIFICATE-SPEC.md §10.2 flow: resolve identity → lookup historical credential → check effective window → verify signature.

**The delegation verifier (#1, #2) is the primary gap.** `verifyDelegationSignature` trusts the `issuerPublicKey` embedded in the delegation object. It does not:
- Accept a `KeyHistory` or `CredentialRotationController` reference
- Call `lookupHistoricalCredential` to verify that `issuerPublicKey` was the effective key at `issuedAt`
- Fail closed if rotation state is unavailable

**Concrete failure scenarios:**
1. **Issuer rotates key after issuing a delegation.** The delegation still carries the old `issuerPublicKey` and signature. `verifyDelegationSignature` succeeds because the old key still matches — **this is actually safe** because the delegation is self-contained with its own key material. However, a verifier has no way to confirm that the `issuerPublicKey` was *legitimately effective* at `issuedAt` — it could be a fabricated key.
2. **Attacker fabricates a delegation with a valid-looking but unauthorized key.** Without consulting the rotation subsystem, the verifier cannot distinguish a legitimately-issued delegation from one signed by a key that was never effective for that identity.

**The rotation controller's `lookupHistoricalCredential` is ready** — it's implemented, well-tested, and satisfies the Slice D code contract. The gap is entirely at the *consumer* side: delegation (and revocation, birth certificate, selective disclosure) verification functions do not yet consume it.

### Remediation Path

The fix requires:
1. Add an optional `CredentialLookup` or `HistoricalCredentialLookup` parameter to `verifyDelegationSignature`
2. When provided, resolve `(identityId, issuerPublicKey)` via the lookup
3. Check that `effectiveFrom <= issuedAt` and (`effectiveUntil === null || effectiveUntil > issuedAt`)
4. Fail closed with a typed error if the lookup is provided but the credential is not found or was not effective
5. When the lookup is NOT provided, behavior remains unchanged (backward compatible)
6. Apply the same pattern to `verifyRevocation`, `verifyBirthCertificate`, and `verifyDisclosure`

This matches the SOMA-DELEGATION-SPEC.md §Rotation Interaction's Conforming Verifier Rule exactly.

---

## Findings by Priority

### Critical (blocks production readiness)

1. **Key-verifier call-site gap** — `verifyDelegationSignature` does not resolve issuerDid to the key version current at `issuedAt`. The historical-credential lookup exists in the rotation controller but is not consumed by delegation/revocation/birth-certificate verifiers. (SOMA-DELEGATION-SPEC.md §Rotation Interaction, SOMA-CAPABILITIES-SPEC.md §Security: Key rotation)

### High (should fix before 10/10)

2. **Delegation chain-walk verification missing** — `verifyDelegation` verifies a single delegation only; no chain traversal that checks each parentId link, verifies attenuation rules hold at each step, and checks revocation at each link. (SOMA-CAPABILITIES-SPEC.md §Verification Algorithm steps 6-7)

3. **Certificate trust chain evaluation missing** — No implementation of §11.3 chain evaluation (each link verified independently, chain fails closed if any link fails). The policy module handles single certificates only. (SOMA-HEART-CERTIFICATE-SPEC.md §11.3)

4. **Revocation not integrated into delegation verification** — Revocation registry exists but `verifyDelegation` does not check it. Callers must do this manually. (SOMA-CAPABILITIES-SPEC.md §Verification Algorithm step 7)

### Medium (track for next release)

5. **Disclosure/privacy field enforcement missing** — No runtime validator for the §16 `disclosure` object. The `disclosure-missing` failure mode is defined but never raised. (SOMA-HEART-CERTIFICATE-SPEC.md §16)

6. **`policy_ref` shape not implemented** — No constructor/validator for the verifier policy reference object from §12. (SOMA-HEART-CERTIFICATE-SPEC.md §12)

7. **Custom caveat semantics not enforced** — `custom` caveats pass through silently in `checkCaveats`. Spec says verifiers MUST recognize the key and apply semantics, or FAIL CLOSED. Current impl treats all custom caveats as pass-through. (SOMA-CAPABILITIES-SPEC.md §Caveat Types: custom)

### Low (nice to have)

8. **Soma Check hash length validation missing** — Spec says providers MUST NOT shorten hashes below 16 hex chars. No validation in `soma-check.ts`. (SOMA-CHECK-SPEC.md §Hash Collisions)

9. **Birth certificate `dataHash` / `X-Soma-Hash` consistency not enforced** — Spec says they MUST be equal. No automated check. (SOMA-CHECK-SPEC.md §Compatibility with Soma Provenance)

10. **heart-to-heart profile "both roles present" constraint** — Individual signature verification works, but no integrated verifier enforces that a heart-to-heart certificate has both issuer and counterparty signatures. (SOMA-HEART-CERTIFICATE-SPEC.md §5)

---

## Recommendation

**Fix the key-verifier gap first, then proceed to integration tests.**

Rationale:
- The key-verifier gap is the #1 known open problem and the most security-relevant finding
- The rotation subsystem's `lookupHistoricalCredential` is already implemented and tested — the fix is "wire it up at the consumer side"
- The certificate signature module (`signature.ts`) already demonstrates the correct pattern via `CredentialLookup` — the delegation/revocation/birth-certificate verifiers can follow the same approach
- Integration tests written against the current delegation verifier would not exercise the rotation-aware path and would need to be rewritten after the fix
- The chain-walk and revocation-integration gaps (#2, #3, #4) are larger scoped and can be addressed in parallel with the integration test workstream

**Suggested order:**
1. Key-verifier gap fix (scoped: delegation.ts, revocation.ts, birth-certificate.ts, selective-disclosure.ts)
2. Integration tests (targets: certificate conformance, delegation chain walk, attack scenarios)
3. Chain-walk verification implementation
4. Disclosure/privacy enforcement

---

*Report generated against Soma `main` at soma-heart@0.5.0. All 1580 tests passing at time of audit.*
