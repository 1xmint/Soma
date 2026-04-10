# Soma Ops And Secret Hygiene

Soma is primarily a package, experiment, and verification workspace rather than a long-lived VPS service. The operational goal here is to keep credentials, generated artifacts, and research output from leaking into git or getting mixed into releaseable package code.

## What To Keep Out Of Git

- provider API keys
- `.env` variants beyond [.env.example](C:\Users\Josh\Desktop\GitHub\Soma\.env.example)
- experiment logs in `results/*.log`
- generated package tarballs in `packages/**/*.tgz`
- ad hoc secret folders such as `secrets/` or `.secrets/`

## Recommended Local Workflow

1. Keep provider keys only in a local `.env`
2. Run experiments and analyses locally
3. Review `git status` before commits so results and package artifacts do not get mixed in
4. Build packages intentionally with `scripts/build-packages.sh`
5. Publish or copy package artifacts only from a clean working tree

## Release Hygiene

- treat `packages/soma-heart` and `packages/soma-sense` as publishable artifacts
- avoid committing generated tarballs unless you intentionally want release artifacts in git
- run lint and tests before packaging
- if a provider key is ever exposed, rotate it first and then clean history if needed

## If Soma Is Used On A VPS

If another project hosts Soma-backed code on a VPS, keep the deployment-specific secrets in that host project, not in this repo. In other words:

- `claw-net` or another service repo owns the VPS env file
- `Soma` stays focused on packages, experiments, and verification logic
