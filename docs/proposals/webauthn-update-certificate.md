# Proposal: WebAuthn + UpdateCertificate — Securing Soma Releases Through ClawNet Heart

**Status:** proposed → ready for implementation  
**Author:** Claude (research synthesis), decisions by Josh  
**Date:** April 20, 2026  
**Depends on:** UpdateCertificate (PR #75, shipped), api-key-rotation.ts, rotation-backend.ts  
**Repos:** soma (`src/supply-chain/update-certificate.ts`), claw-net (`src/core/soma-heart.ts`)

---

## 1. Executive Summary

This proposal designs a WebAuthn-gated signing ceremony for Soma releases, where the founder's biometric authentication through the ClawNet heart is the sole authority for approving UpdateCertificates. The founder authenticates via Apple passkey (primary, synced via iCloud Keychain) or Google passkey (backup, synced via Google account), with an offline Ed25519 recovery seed as catastrophic backup. CI publishes to npm first, then the founder completes a WebAuthn ceremony at their convenience — no pipeline blocking. Signed certificates are distributed at `/.well-known/soma-updates.json` on claw-net.org (authoritative) and as a convenience copy in the npm package. Both a dashboard UI and a CLI ship from day one as production paths.

---

## 2. Research Findings

### 2.1 WebAuthn/FIDO2 State of the Art (2025–2026)

WebAuthn is a W3C standard supported across all major browsers (Chrome, Firefox, Edge, Safari) and platforms (Windows, macOS, Android, iOS). The core flow is well-established: registration generates a public-private keypair where the private key never leaves the authenticator, and authentication requires proving possession of that private key by signing a server-generated challenge. Domain binding provides phishing resistance by cryptographically tying credentials to the origin that created them.

**SimpleWebAuthn** (`@simplewebauthn/server` v13.x, `@simplewebauthn/browser` v13.x) is the leading Node.js/TypeScript library for WebAuthn integration. It is actively maintained, supports Node LTS 20+, runs on Deno and Cloudflare Workers, covers all attestation formats (Packed, TPM, Android Key, Apple, FIDO U2F, None), and has ~3M weekly downloads on npm. Its API surface is clean: `generateRegistrationOptions()` / `verifyRegistrationResponse()` for enrollment, `generateAuthenticationOptions()` / `verifyAuthenticationResponse()` for authentication. This is the implementation choice for ClawNet.

### 2.2 Passkey Ecosystems for Signing Ceremonies

The founder's decision to use synced passkeys (Apple iCloud Keychain as primary, Google Password Manager as backup) trades hardware-bound non-exportability for practical resilience across devices. This is a deliberate and informed choice.

**What synced passkeys provide:** The private key is stored in the platform's secure enclave and synced end-to-end encrypted across all devices in the ecosystem. If the founder's MacBook is destroyed, the passkey survives on their iPhone and vice versa. Cross-ecosystem coverage (Apple + Google) means the founder is not locked into a single vendor's availability.

**What synced passkeys do not provide:** NIST SP 800-63B-4 AAL3 compliance (which requires non-exportable keys) and device attestation (which requires a hardware-bound manufacturer certificate chain). For Soma's threat model, AAL3 is not a regulatory requirement, and the practical resilience of multi-device sync outweighs the theoretical purity of hardware-bound keys.

**Security posture:** Compromise requires access to the founder's Apple ID or Google account AND their device biometrics. Both ecosystems require biometric or PIN verification before releasing a passkey for use. The WebAuthn ceremony always sets `userVerification: 'required'`, ensuring the authenticator confirms the founder's identity before signing.

### 2.3 Recovery Patterns in Production Systems

**GitHub's model:** Multiple authentication methods (passkeys, security keys, TOTP, SMS, recovery codes). If all 2FA credentials and recovery codes are lost, account recovery requires identity verification via SSH key, personal access token, or previously verified device — with a 3–5 business day review period. GitHub explicitly states that Support may not be able to restore access if all recovery methods are lost.

**Coinbase's model:** Recovery codes saved at setup. Without them, identity verification via government-issued photo ID and video selfie. The process is deliberately slow (days) to prevent social engineering.

**Crypto wallet recovery (Shamir's Secret Sharing):** Trezor (SLIP-0039) and Ledger Recover (Pedersen's Verifiable Secret Sharing) split master secrets into N shares with threshold K. In a 2-of-3 scheme, any two shares reconstruct the secret. The mathematical guarantee is information-theoretic security — knowledge below threshold provides zero advantage.

**Key takeaway for Soma:** No production system relies on a single authenticator without a recovery path. The founder's layered approach (two passkey ecosystems + offline seed) mirrors industry best practice without distributing authority to other parties.

### 2.4 npm Supply Chain Signing (Sigstore)

npm integrates Sigstore for package provenance attestations via `sigstore-js`. Provenance establishes *where* a package was built and *which CI identity* published it, but does not establish *human authorization*. The Soma ceremony system fills this exact gap. They are complementary: Sigstore proves CI-to-tarball integrity, UpdateCertificate proves human-to-CI authorization.

---

## 3. Design Decisions (Founder-Specified)

| # | Decision | Rationale |
|---|---|---|
| 1 | Dashboard + CLI ship together in Phase 1 | Both are production paths. CLI opens dashboard URL and polls for completion. |
| 2 | Certificates are permanent. Ceremony *requests* expire after 72 hours. | Certificates attest historical facts. Requests have a window because uncompleted ceremonies shouldn't linger. |
| 3 | Apple passkey primary. Google passkey backup. Offline Ed25519 recovery seed with 72h time-lock. No hardware key vault. | Multi-ecosystem passkey resilience. Recovery seed is catastrophic backup only. |
| 4 | CI publishes first, ceremony request follows. No pipeline blocking. | Decoupled flow. Founder authenticates when convenient. |
| 5 | `.well-known/soma-updates.json` on claw-net.org is authoritative. npm package metadata is convenience copy. `.well-known` wins on disagreement. | Single source of truth with offline-verifiable convenience copy. |

---

## 4. Ceremony Flow Design

### 4.1 Phase A: WebAuthn Enrollment

The founder registers their passkey credentials with the ClawNet heart. Two enrollments are required: Apple passkey (primary) and Google passkey (backup).

**Flow:**

1. Founder authenticates to ClawNet dashboard via existing Clerk auth.
2. Founder navigates to "Soma Signing Authority" settings panel.
3. ClawNet server calls `generateRegistrationOptions()` with:
   - `rpName: 'ClawNet Soma Signing'`
   - `rpID: 'claw-net.org'`
   - `userName: founder's Clerk user ID`
   - `authenticatorSelection: { residentKey: 'required', userVerification: 'required' }`
   - `supportedAlgorithmIDs: [-7, -257]` (ES256, RS256)
   - `attestationType: 'none'` (synced passkeys cannot provide meaningful attestation)
4. Browser calls `startRegistration()` — system passkey prompt appears (Touch ID / Face ID / Google prompt).
5. ClawNet server calls `verifyRegistrationResponse()`, extracts public key and credential ID.
6. Server stores in `webauthn_credentials` table:
   - `credential_id` (base64url)
   - `public_key` (base64url-encoded COSE key)
   - `counter` (signature counter for replay detection)
   - `transports` (internal, hybrid — for authentication hints)
   - `aaguid` (authenticator model identifier)
   - `created_at`, `last_used_at`
   - `ecosystem` ('apple' | 'google' — labeled by founder during enrollment)
   - `is_primary` (boolean — Apple enrollment is primary)
7. Founder repeats enrollment for Google passkey (different browser/device signed into Google account).
8. Server generates the **offline recovery seed** (256-bit random), derives an Ed25519 keypair, stores only the recovery public key. The seed is displayed once and never stored.

**CLI enrollment path:** `npx soma-sign enroll` opens `https://claw-net.org/ceremony/enroll` in the default browser. The same WebAuthn flow runs in the browser. The CLI polls `GET /api/ceremony/enroll/status` until enrollment completes.

### 4.2 Phase B: Update Signing Ceremony

**Flow:**

1. **CI publishes to npm.** GitHub Action runs `npm publish --provenance`. Tarball is live on npm with Sigstore attestation.

2. **CI sends ceremony request.** After successful publish, the action POSTs to `https://claw-net.org/api/ceremony/request`:
   ```json
   {
     "package": "soma-heart",
     "targetVersion": "0.9.0",
     "tarballSha256": "<64-char hex>",
     "gitCommit": "<sha>",
     "releaseLogSequence": 42,
     "releaseLogEntryHash": "<hash>",
     "oidcToken": "<github-actions-jwt>"
   }
   ```

3. **ClawNet validates and creates pending ceremony.** The server:
   - Validates the OIDC token against GitHub's JWKS
   - Verifies the source repo matches expected (`josh/soma`)
   - Creates a `pending_ceremonies` record: status `awaiting_webauthn`, `expires_at = now + 72h`
   - Sends notifications (email, Slack webhook)

4. **Founder authenticates.** Two production paths:

   **Dashboard path:** Founder visits `https://claw-net.org/ceremony/<ceremony-id>`. Reviews release details (package, version, tarball hash, git commit). Clicks "Authorize Release." WebAuthn challenge is presented. Founder authenticates with Apple passkey (or Google backup).

   **CLI path:** Founder runs `npx soma-sign authorize`. The CLI:
   - Fetches pending ceremonies from `GET /api/ceremony/pending`
   - Displays ceremony details in terminal
   - Opens `https://claw-net.org/ceremony/<id>` in default browser for WebAuthn authentication
   - Polls `GET /api/ceremony/<id>/status` every 2 seconds
   - Prints success/failure when ceremony completes

5. **WebAuthn verification.** ClawNet server:
   - Calls `generateAuthenticationOptions()` with `rpID: 'claw-net.org'`, `userVerification: 'required'`, founder's registered credential IDs
   - The challenge encodes the SHA-256 of the ceremony payload
   - Calls `verifyAuthenticationResponse()` — validates signature, checks counter
   - Verifies challenge matches pending ceremony

6. **ClawNet heart co-signs.** On successful WebAuthn verification:
   - Maintainer's authorization is created via `createUpdateCertificate()` with `role: 'maintainer'`, `ceremonyTier: 'L2'`
   - ClawNet heart calls `addAuthorization()` with its own Ed25519 keypair, `role: 'consumer-heart'`
   - Certificate has `threshold: 2`, `expiresAt: null` (permanent)
   - The `delegationHash` field on the maintainer authorization links to the WebAuthn ceremony record for audit trail

7. **Certificate is distributed:**
   - Written to `/.well-known/soma-updates.json` on claw-net.org (authoritative)
   - Published as a convenience copy in the next npm package version's `package.json` metadata (or as a sidecar file)
   - Ceremony status updated to `completed`
   - Optionally anchored on-chain via EAS

8. **Request expiry.** If the founder does not complete WebAuthn within 72 hours:
   - `pending_ceremonies` record status → `expired`
   - No certificate is issued
   - A new `npm publish` cycle is required to create a fresh ceremony request

### 4.3 Phase C: Verification by Downstream Consumers

Consumers verify using the existing `verifyPackageProvenance()` function (shipped, 571 LOC):

1. Fetch the UpdateCertificate from `https://claw-net.org/.well-known/soma-updates.json` (authoritative) or from the npm package metadata (convenience copy).
2. If both sources are available and disagree, `.well-known` wins.
3. Call `verifyPackageProvenance()` with:
   - `trustedMaintainers: [founderDid]`
   - `trustedConsumerHearts: [clawNetHeartDid]`
4. No new verification code needed.

### 4.4 `.well-known/soma-updates.json` Schema

```json
{
  "version": "1",
  "packages": {
    "soma-heart": {
      "0.9.0": {
        "certificate": { /* full UpdateCertificate object */ },
        "ceremonyCompletedAt": "2026-04-20T14:30:00Z",
        "sigstoreBundle": "<optional link to Rekor entry>"
      }
    }
  },
  "signingAuthority": {
    "maintainerDid": "did:key:z...",
    "consumerHeartDid": "did:key:z..."
  }
}
```

---

## 5. Recovery Mechanism

### 5.1 Three-Layer Recovery Architecture

| Layer | Authenticator | Failure it handles | Standing backdoor? |
|---|---|---|---|
| **Primary** | Apple passkey (iCloud Keychain) | Device loss/damage — passkey syncs across all Apple devices | No — only founder's Apple ID + biometrics |
| **Backup** | Google passkey (Google Password Manager) | Apple ecosystem outage, Apple ID lockout | No — only founder's Google account + biometrics |
| **Catastrophic** | Offline Ed25519 recovery seed (paper/steel, never on a server) | Both passkey ecosystems compromised/lost, VPS destroyed | No — seed is never stored; 72h time-lock provides detection window |
