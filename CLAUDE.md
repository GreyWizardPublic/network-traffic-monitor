# network-traffic-monitor

This project uses a multi-agent collaborative workflow. Three Claude Code
sessions on different operating systems work in parallel on the same repo,
each on its own feature branch.

## Required reading at session start (in order)

Every agent MUST read both files below before starting any new work:

1. **[docs/agent-framework.md](docs/agent-framework.md)** — generic
   multi-agent collaboration rules, and **the single source of truth for agent
   communication**: the hub-and-spoke hierarchy (§0), branch hygiene and the
   Architect-only merge gate (§3), the request/dispatch protocol (§4),
   versioning scheme, protocol-governance principles, production-push policy
   and human-escalation routing (§7), per-OS shell conventions, and Architect
   operating discipline (§12). Reusable across projects.

2. **[docs/project-rules.md](docs/project-rules.md)** — concrete facts
   for this project: agent role detection, owned paths, module list,
   protocol versions, build & push commands, Apple Distribution cert
   reference.

The framework defines the *how*; project rules define the *what*. If they
ever conflict, **project rules win** — the framework is intentionally
generic and is overridden by anything specific in `docs/project-rules.md`.

## How work reaches you (non-normative summary — the rule is `docs/agent-framework.md`)

Three agents work hub-and-spoke. The **Fedora Linux Agent is the Architect**
(the hub) and also owns the C++/Linux domain; the Swift and Windows Agents are
spokes. Work flows **agent → Architect → agent**, never spoke to spoke.

- **Only the Architect creates work orders** (`[<RECIPIENT>] [<KIND>]` Issues)
  and **only the Architect merges PRs into `main`** (framework §3.5, §4.0a).
- A spoke that needs something outside its domain files an **`[ARCHITECT]`
  request** and stops.
- **Only the Architect talks to the maintainer** (framework §7.0, §7.2).
- **GitHub is the system of record; a peer message is only a doorbell**
  (framework §4.0b). If a fact exists only in a peer message, it does not exist.
- **End every turn with an explicit state token** — `IDLE — awaiting X`,
  `BLOCKED — need X`, or `CONTINUING IN THIS TURN`. Never a future-tense promise
  (framework §4.0c).

## Session start checklist (summary — full version in `docs/agent-framework.md §3.7`)

1. Detect your agent role (see `docs/project-rules.md §2`).
2. Check **your own inbox only** — Issues whose title starts with your recipient
   tag (`docs/project-rules.md §2.2`), plus your own open PRs. Sweeping the whole
   board is the Architect's job and nobody else's.
3. `git fetch --prune`, confirm `git rev-list --count HEAD..origin/main` is 0,
   and audit your own stale branches.
4. Address any dispatch addressed to you: acknowledge on the thread, apply
   `acked`, and ring the doorbell — in the same turn.
