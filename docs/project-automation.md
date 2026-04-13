# ClawNet Project Automation

Status: operational

Soma is public and intentionally separate from the private `claw-net` org repos.

Do not auto-add every Soma issue or PR to the private execution board. Add only cross-repo work that needs ClawNet/Pulse coordination.

## Rule

Add the `claw-net-project` label to a Soma issue or PR when it should appear in the `Soma + ClawNet + Pulse` project:

<https://github.com/orgs/claw-net/projects/1>

## Secret

The workflow `.github/workflows/add-to-claw-net-project.yml` requires a repository secret named `ADD_TO_PROJECT_PAT`.

The token needs:

- access to read Soma issues and PRs
- organization Projects read/write access for the `claw-net` org

If a fine-grained token cannot span both owners cleanly, use a deliberately scoped classic token as a fallback and revisit with a GitHub App later.
