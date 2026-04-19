# Packages

Status: canonical

## Published Packages

### `soma-heart`

- Source-of-truth package
- Contains the execution runtime and `soma-heart/sense`
- Canonical install target for full agent/runtime usage

#### Subpath exports

| Subpath | Entry | Description |
|---|---|---|
| `.` | `dist/heart/index.js` | Execution heart runtime |
| `./core` | `dist/core/genome.js` | Core genome primitives |
| `./credential-rotation` | `dist/heart/credential-rotation/index.js` | Credential rotation lifecycle |
| `./crypto-provider` | `dist/core/crypto-provider.js` | Cryptographic provider abstraction |
| `./sense` | `dist/sensorium/index.js` | Sensorium (temporal fingerprinting, behavioral landscape) |
| `./senses` | `dist/sensorium/senses/index.js` | Individual sense modules |
| `./atlas` | `dist/sensorium/atlas.js` | Phenotype atlas |
| `./mcp` | `dist/mcp/index.js` | MCP middleware |
| `./certificate` | `dist/heart/certificate/public.js` | Certificate module (Gate 6 public surface) |
| `./signals` | `dist/experiment/signals.js` | Experimental signal helpers |

#### Top-level exports added in 0.7.0

**Delegation chain** (PR #76):

- `verifyDelegationChain` — walks a delegation chain leaf-to-root,
  verifying signatures, subject-issuer linkage, monotonic capability
  attenuation, monotonic caveat accumulation, and revocation at each link.
- Types: `ChainVerificationResult`, `ChainVerificationSuccess`,
  `ChainVerificationFailure`, `ChainVerificationOptions`.

**Custom caveat evaluator** (PR #78):

- `CustomCaveatEvaluator` — type for a callback passed to `checkCaveats()`
  and `verifyDelegation()`. Unhandled `custom` caveats fail closed without it.

**Soma Check hardening** (PR #78):

- `SOMA_CHECK_MIN_HASH_LENGTH` — constant (16 hex chars) for minimum
  acceptable hash length.
- `verifyDataHashConsistency` — compares a birth-certificate `dataHash`
  against an `X-Soma-Hash` header value.

#### Top-level exports added in 0.6.0

The following exports are available from the main `soma-heart` entry
point (`.`) as of 0.6.0. They do not introduce new subpath exports.

**Reception receipts** (accountability primitive for capability
verification):

- `signReceipt`, `verifyReceipt`, `receiptCanonical` — sign, verify,
  and canonically serialize a `ReceiptPayload` attesting a verifier's
  evaluation outcome (pass / fail / inconclusive) against a heart's
  capability class.
- `EVIDENCE_SUMMARY_MAX` — constant (512 chars) for evidence summary
  length cap.
- Types: `ReceiptPayload`, `SignedReceipt`, `ReceiptOutcome`.

**Historical key lookup** (rotation-aware key validity for verifiers):

- `checkKeyEffective` — checks whether a public key was effective at a
  given timestamp, bridging verifiers and the rotation subsystem.
- Types: `HistoricalKeyLookup`, `HistoricalKeyLookupHit`,
  `HistoricalKeyLookupMiss`, `HistoricalKeyLookupResult`.

#### `soma-heart/certificate` public surface

The `./certificate` subpath exports the Gate 6 accepted public surface
via `public.ts`. Internal rotation lookup, credential resolution, and
signature verification primitives are NOT exported through this subpath;
they remain available only via the internal barrel (`index.ts`) for
in-repo use.

**Exported areas:**

- **Areas 1-3** - Canonicalization helpers: `canonicalizePayload`,
  `computeCertificateId`, `computeSignatureInput`,
  `computeSignatureInputHash`, `CanonicalisationError`, `SignerRole`
- **Area 4** - Vector loading and conformance: `loadManifest`,
  `VectorLoadError`, `Manifest`, `Vector`, `VectorSignatureInput`,
  `VectorVerifierPolicy`, `RotationFixtureIdentity`
- **Areas 5-7** - Vocabulary validators: `validateProfile`,
  `validateClaimKind`, `validateEvidenceKind`, `Disposition`,
  `VocabularyResult`
- **Area 8** - Verifier-policy evaluator (full install only):
  `evaluatePolicy`, `VerifierPolicy`, `PolicyCertificateInput`,
  `PolicyViolation`, `PolicyEvalResult`, `PolicyEvalOk`, `PolicyEvalFail`
- **Area 10** - Soma Check binding helper: `bindSomaCheckEvidence`,
  `SomaCheckReceiptInput`, `FreshnessClaimBinding`,
  `EvidenceReferenceBinding`, `SomaCheckBindingResult`,
  `SomaCheckBindingOk`, `SomaCheckBindingFail`
- **Area 11** - Payment rail binding interface:
  `bindPaymentRailEvidence`, `PaymentRailReceiptInput`,
  `PaymentClaimBinding`, `PaymentEvidenceBinding`,
  `PaymentRailBindingResult`, `PaymentRailBindingOk`,
  `PaymentRailBindingFail`
- **Area 12** - Failure modes: `FAILURE_MODES`, `isFailureMode`,
  `createFailure`, `FailureMode`, `CertificateFailure`

- **§12** - policy_ref shape validator: `validatePolicyRef`, `PolicyRef`,
  `PolicyRefValidResult`, `PolicyRefValidOk`, `PolicyRefValidFail`
- **§11.3** - Certificate chain evaluator: `evaluateChain`,
  `CertificateChainLink`, `CertificateChainInput`, `CertificateChainResult`,
  `ChainEvalOk`, `ChainEvalFail`
- **§16** - Disclosure / privacy enforcement: `validateDisclosure`,
  `DisclosureField`, `DisclosureCertificateInput`, `DisclosureValidResult`,
  `DisclosureValidOk`, `DisclosureValidFail`
- **§5** - Heart-to-heart integrated verifier: `verifyHeartToHeartSignatures`,
  `HeartToHeartCertificateInput`, `HeartToHeartResult`, `HeartToHeartOk`,
  `HeartToHeartFail`

**Not exported (internal-only):**

- Area 9 - Rotation lookup adapter (`CredentialLookup` and related types)
- Signature verification (`verifyCertificateSignature` and related types)

### `soma-sense`

- Thin compatibility re-export
- Intended for observer-only installs
- **Not currently published.** Deprecated at `0.1.0` on npm; the publish
  workflow covers `soma-heart` only. The in-repo package is maintained
  for local development and surface tests.

#### Subpath exports

| Subpath | Entry | Description |
|---|---|---|
| `.` | `index.js` | Sensorium re-export |
| `./certificate` | `certificate.js` | Observer-safe certificate helpers |

#### `soma-sense/certificate` observer-safe surface

The `./certificate` subpath re-exports an observer-safe subset of
`soma-heart/certificate`. It uses selective named exports (never
`export *`) and imports only from `soma-heart/certificate`.

**Exported areas (observer-safe):**

- **Areas 1-3** - Canonicalization helpers: `canonicalizePayload`,
  `computeCertificateId`, `computeSignatureInput`,
  `computeSignatureInputHash`, `CanonicalisationError`, `SignerRole`
- **Area 4** - Vector loading and conformance: `loadManifest`,
  `VectorLoadError`, `Manifest`, `Vector`, `VectorSignatureInput`,
  `VectorVerifierPolicy`, `RotationFixtureIdentity`
- **Areas 5-7** - Vocabulary validators: `validateProfile`,
  `validateClaimKind`, `validateEvidenceKind`, `Disposition`,
  `VocabularyResult`
- **Area 12** - Failure modes: `FAILURE_MODES`, `isFailureMode`,
  `createFailure`, `FailureMode`, `CertificateFailure`

**Not exported (full-install-only):**

- Area 8 - Verifier-policy evaluator (`evaluatePolicy` and related types)
- Area 10 - Soma Check binding helper (`bindSomaCheckEvidence` and related types)
- Area 11 - Payment rail binding interface (`bindPaymentRailEvidence` and related types)

**Not exported (internal-only):**

- Rotation lookup adapter and signature verification (same as soma-heart exclusions)

**Dependency requirement:** `soma-heart >= 0.5.0` (the `./certificate`
subpath ships in 0.5.0; the published 0.4.0 tag predates it).

## Packaging Rule

If behavior is normative to the protocol or package surface, it should be documented here or in a linked spec, not in downstream application repos.
