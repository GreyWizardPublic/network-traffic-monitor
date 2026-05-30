# network-traffic-monitor

This project uses a multi-agent collaborative workflow. Three Claude Code
sessions on different operating systems work in parallel on the same repo,
each on its own feature branch.

## Required reading at session start (in order)

Every agent MUST read both files below before starting any new work:

1. **[docs/agent-framework.md](docs/agent-framework.md)** — generic
   multi-agent collaboration rules: branch hygiene, cross-agent handoff
   protocol, versioning scheme, protocol-governance principles,
   production-push policy, per-OS shell conventions. Reusable across
   projects.

2. **[docs/project-rules.md](docs/project-rules.md)** — concrete facts
   for this project: agent role detection, owned paths, module list,
   protocol versions, build & push commands, Apple Distribution cert
   reference.

The framework defines the *how*; project rules define the *what*. If they
ever conflict, **project rules win** — the framework is intentionally
generic and is overridden by anything specific in `docs/project-rules.md`.

## Session start checklist (summary — full version in `docs/agent-framework.md §3`)

1. Detect your agent role (see `docs/project-rules.md §2`).
2. `git fetch --prune` and audit your own stale branches.
3. Check open PRs and GitHub Issues addressed to your agent.
4. Address any handoff PRs targeting your prefix; delete handoff branches
   you closed.
