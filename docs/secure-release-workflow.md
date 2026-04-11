# Soma Secure Release Workflow

Soma should not use the same production deployment workflow as ClawNet or Pulse.

Soma is the open-source upstream. The clean professional model here is:

- protected default branch
- required CI and CodeQL before merge
- weekly Dependabot updates
- package publishing from GitHub Actions using npm trusted publishing
- no long-lived npm automation tokens
- public npm releases with provenance

## Why Soma Is Different

ClawNet and Pulse are private production applications.

Soma is a public source repo with one publishable package:

- `soma-heart` — unified Soma trust machine (runner + sensorium + MCP middleware). The former `soma-sense` package is deprecated; its contents are subpath exports of `soma-heart` (`./sense`, `./senses`, `./atlas`, `./mcp`, `./signals`).

That means the security focus is:

- source integrity
- release integrity
- package provenance
- predictable semver consumption by downstream apps

## GitHub Settings To Enable

1. Protect the default branch.
2. Require pull requests before merge.
3. Require at least 1 approving review.
4. Require status checks to pass before merge.
5. Block force-pushes.
6. Create an `npm-release` environment with required reviewers.

Required status checks:

- `validate`
- `analyze`

## npm Trusted Publishing

Use npm trusted publishing instead of npm tokens.

Official docs:

- [Trusted publishing for npm packages](https://docs.npmjs.com/trusted-publishers/)

Recommended configuration:

1. Configure `soma-heart` on npm as a trusted publisher for this GitHub repo (workflow: `.github/workflows/publish-packages.yml`, environment: `npm-release`).
2. In npm package settings, require two-factor authentication and disallow tokens after trusted publishing is working.
3. Deprecate `soma-sense` on npm once `soma-heart@0.3.0` is live: `npm deprecate soma-sense@"*" "Merged into soma-heart@>=0.3.0. Install soma-heart and import from soma-heart/sense."`
4. Use the `Publish Packages` GitHub Actions workflow for releases.

## Release Flow

Two paths. Tag-push is preferred because it is automated, version-guarded,
and leaves a visible git tag as the canonical release marker.

### Preferred: tag-push release

1. Open a PR that bumps `packages/soma-heart/package.json` and adds a
   `CHANGELOG.md` entry.
2. Wait for CI and CodeQL to pass.
3. Review and merge to the protected default branch.
4. From the merged `main`, tag the release with the exact format
   `soma-heart-v<version>`:

   ```bash
   git tag soma-heart-v0.3.0
   git push origin soma-heart-v0.3.0
   ```

5. The `Publish Packages` workflow triggers on the tag push. It re-runs
   the full CI suite (lint, format, typecheck, test, build), then asserts
   that the tag version matches the `package.json` version, then calls
   `npm publish`. Provenance attestations are generated automatically
   because `soma-heart` has `publishConfig.provenance = true`.
6. Approve the `npm-release` environment gate.
7. Verify the new version on npm with a provenance badge attached to
   the release.

### Fallback: manual dispatch

Use this only to republish a broken release or ship from a non-tag
commit in an incident. There is no version guard on this path.

1. Actions → `Publish Packages` → Run workflow.
2. Approve the `npm-release` environment.
3. Verify the new version on npm.

## Downstream Consumption

ClawNet and Pulse should consume released package versions, not local tarballs and not floating branch code.

Recommended policy:

- pin exact versions during initial rollout
- move to controlled semver ranges only after the release cadence is stable
- upgrade Soma in ClawNet first
- then upgrade Soma in Pulse after the same version proves stable

## Next Step After This

The next maturity jump is to connect the existing Soma supply-chain log to published releases, so every `soma-heart` publish also appends a verifiable signed release entry.
