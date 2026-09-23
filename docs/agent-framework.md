# Multi-Agent Collaboration Framework

Generic rules for projects where multiple Claude Code sessions — running on
different operating systems — collaborate on the same git repository. Each
session is called an **agent** and owns a distinct code domain.

> **Ported from the sibling project `secure-vault` on 2026-09-23.** The
> communication mechanics in §0, §3.5, §4, §7.0/§7.2 and §12 are that project's,
> adapted to this project's three-agent roster. Its hard-won rationale is kept
> where it is instructive; incidents cited as "observed in the sibling project"
> happened there, not here. §5 (versioning) and §6 (protocol governance) are
> **this project's own and were deliberately not replaced.**

> ### 📍 This file is the single source of truth for agent communication
>
> **Every rule about who talks to whom, through what vehicle, with what
> authority, lives here.** No other document may restate the mechanism — a second
> copy drifts, and an agent that reads the drifted copy follows a rule nobody
> else is following.
>
> | Document | May contain |
> |---|---|
> | **`docs/agent-framework.md`** (this file) | The whole mechanism: hierarchy, routing, vehicles, authority, escalation, notification. |
> | `docs/project-rules.md` | Concrete facts only — roles, owned paths, branch prefixes, recipient tags, the peer roster, build commands. |
> | `CLAUDE.md` | A short non-normative summary + a pointer. Never the rule text. |
> | Everything else | May *use* a vehicle by name (§4.1) and link to it. Never explain it. |
>
> If any other document states a communication rule this file does not, **this
> file wins and the other document is the bug.** Note the one exception that
> still holds: where `docs/project-rules.md` supplies a *project-specific fact or
> rider*, project rules win (see `CLAUDE.md`).

---

## 0. Hierarchy, topology, and who may talk to whom

§1–§11 describe the *mechanics*. This section describes the **structure those
mechanics implement**, and it governs their interpretation: where a mechanical
rule is silent or ambiguous, resolve it in whichever direction preserves the
structure below.

### 0.1 The chain of authority

```
                    ┌───────────────────────┐
                    │   HUMAN / MAINTAINER  │   final decision · final arbiter
                    └───────────┬───────────┘
                                │  ▲   the ONLY human↔fleet link
                                ▼  │
                    ┌───────────────────────┐
                    │   ARCHITECT AGENT     │   plans · dispatches · sequences
                    │       (the hub)       │   arbitrates · merges · escalates
                    └──────┬─────────┬──────┘
                           │         │          every spoke talks ONLY to the hub
                 ┌─────────┘         └─────────┐
                 ▼                             ▼
           ┌───────────┐                 ┌───────────┐
           │  Swift    │                 │  Windows  │   own a domain
           │  Agent    │                 │  Agent    │   do the work
           └───────────┘                 └───────────┘
                    (no spoke↔spoke edge — ever, for work)
```

| Tier | Decides | Never does |
|---|---|---|
| **Human / maintainer** | Everything, finally. Arbitrates any dispute the Architect cannot resolve. Grants every human-gated action (§7). | — |
| **Architect** | *What* is worked on, *by whom*, *in what order*. Merges (§3.5). Arbitrates. Decides what reaches the human, and when (§7.2). | Hoard work it could dispatch (§12.1). Ask an agent to bypass a gate. |
| **Every other agent** | *How* its own domain's work is done — it is the expert there, and its evidence outranks the Architect's assumption (§4.3). | Talk to the human (§7.2). Talk to another agent about work (§4.0a). Merge (§3.5). Decide what happens next after its task (§4.0c). |

**The human is the top of the hierarchy and the final arbiter.** Anything the
fleet cannot settle goes up — but it goes up *through the Architect*, batched and
sequenced, never as three agents independently interrupting one person.

**The Architect is the only agent that interacts with the human.** This is not a
trust ranking; it is what makes the human's attention a *reviewable, sequenced*
resource instead of three unsynchronised interrupts. §7.2 is the procedure.

> ### ⚠️ This project's Architect is a WORKING architect — read this before applying §12
>
> In the sibling project the Architect writes no code. **Here it does.** The
> Architect role is held by the Fedora Linux Agent, which also owns the C++
> server, the Linux client, the shared headers and `docs/` — there is no separate
> agent for that domain, so the hub cannot be kept empty-handed (see
> `docs/project-rules.md §2.3`).
>
> This is a deliberate, documented weakening of §12.1's central property, and the
> mitigations are not optional:
>
> - **Dispatch before you build.** Anything owned by the Swift or Windows Agent is
>   dispatched *first*, before the Architect starts its own long work.
> - **Announce a long execution on the board** (§0.4). An Architect in a full build
>   or a device pass is temporarily not a hub, and the fleet must be able to see it.
> - **Never start a blocking build while a dispatch is unanswered or a dissent is
>   unruled.** The hub's availability outranks the Architect's own lane.
> - **§12.5's stop condition still applies to the Architect's own issues** — its
>   lane is not exempt from the board (§12.5a).

### 0.2 Hub-and-spoke: there is no spoke-to-spoke edge

Work flows **agent → Architect → agent**, never agent → agent. The requesting
agent files the need to the Architect; the Architect validates it, decides
whether it is the right work at all, sequences it against everything else on the
board, and dispatches it. §4.0a is the mechanism.

This holds **even when the two agents are running concurrently and can see each
other**. Peer messaging (§4.0b) is a transport, not a topology — being able to
reach the Windows Agent directly does not create a Swift→Windows work edge. A
request that skips the hub is invisible to the one role that can see the whole
board, and is refused on that ground alone.

The single exception is *notification*: a spoke may ring another spoke's doorbell
to announce something already written on a thread the Architect dispatched.

### 0.3 What each role owes the others

**The Architect owes the fleet:**

- **A dispatch for every piece of work it identifies** — not a note in a status
  summary (§4.0). Work that exists only in the Architect's head is work nobody is
  doing.
- **A decision, promptly, whenever an agent is blocked on one.**
- **An answer to every dissent** (§4.3) — accepted, refined, or over-ruled with
  reasons, on the thread.
- **A reciprocal acknowledgement** to every pickup, stop, and completion (§4.0c).
- **Judgement about the human's attention** — batching, sequencing, and declining
  to escalate what is not yet ready (§7.2).

**Every other agent owes the Architect:**

- **Explicit state, always** (§0.4). Picked up, progressing, blocked, done.
- **Domain expertise, including when it contradicts the dispatch** (§4.3). An
  agent that silently implements a wrong instruction has failed, not complied.
- **Scope discipline.** Do what was dispatched; report what you noticed; do not
  quietly extend the task.
- **Routing, not shortcuts.** Cross-domain and human-gated needs go to the
  Architect (§4.0a, §7.2), never sideways and never upward.

### 0.4 No silent state — the deadlock rule

> **It must never happen that two parties are each waiting on the other, each
> believing the other knows what comes next.**

Every transition in a work item's life is announced **explicitly** by whoever
caused it — a durable comment on the thread, plus a doorbell (§4.0b). There is no
state change a counterparty is expected to *infer*:

| Event | Who announces | Vehicle |
|---|---|---|
| New work order | Architect | Dispatch Issue `[<RECIPIENT>] [<KIND>]` (§4.1/§4.4) **+ doorbell** |
| Work picked up | Receiving agent | Thread comment **+ doorbell, same turn** (§4.0c) |
| Stopped mid-task, still open | Receiving agent | One-line state **+ doorbell** |
| **Turn ending — ALWAYS** | **Whoever is speaking** | **A status token (§4.0c ⏹). Never a future-tense promise.** |
| Blocked | Receiving agent | `BLOCKED on <X>` **+ doorbell** |
| Dispatch appears wrong | Receiving agent | Evidence + `DISSENT` **+ doorbell** (§4.3) |
| Work complete | Receiving agent | `COMPLETE — Architect to decide next` **+ doorbell** |
| Decision / ruling | Architect | Thread comment **+ doorbell** |
| Human intervention needed | Agent → Architect → human | §7.2 |

**Silence is never a message.** It does not mean "still working", "no objection",
"go ahead", or "received". If you are about to stop and the other party could
reasonably be waiting on you, you owe the line *before* you stop, not next session.

**A blocker is named from a fixed vocabulary, never free text.** `IDLE — awaiting
X` and `BLOCKED on X` are only useful if X is checkable:

| Token | Means | Who can clear it |
|---|---|---|
| `toolchain` | needs a host with the right tools (compiler, SDK, signing key) | **an agent. NO human.** |
| `device-attached` | needs hardware physically connected | an agent, once it is |
| `maintainer-present` | needs a human driving something by hand | **only the maintainer** |
| `ruling` | needs an Architect decision | the Architect |
| `depends:#N` | needs another board item to land first | whoever owns #N |

Append the specifics: `IDLE — awaiting toolchain (Windows build, PR #131)`.

**A bundle inherits the strictest blocker in it.** Batching three items into "the
device pass" silently gives toolchain-only work a `maintainer-present` blocker,
and it then waits on a sleeping human. **Every item carries its own blocker.**

**Every hold carries a testable expiry**, stated in terms the held agent can
observe: *"Hold #131 until #128's gate closes — check `gh issue view 128` for the
closing comment"*, never *"hold until the gate runs"*. A held agent re-checks an
expiry it can see rather than waiting to be released.

### 0.5 Follow the Architect — but never blindly

The Architect has altitude; the owning agent has depth. A dispatch is written
from the board's point of view and can be **wrong on facts the Architect could
not see**.

An agent that implements a dispatch it can see is wrong has not been obedient; it
has laundered a bad decision through a domain expert. Equally, an agent that
refuses on a hunch has stalled the board with nothing the Architect can act on.

**The rule: dissent with evidence, then defer.** §4.3 is the procedure. **Only
the human may over-rule the Architect.**

### 0.6 The hub must be present — and presence is proved by the board

> **The Architect must always be present. Where it is not, no agent proceeds on
> its own.**

**How an agent knows.** Not by asking a peer-listing tool — it shows stale rows
from ended sessions and does not list the caller's own session, so absence of a
row proves nothing. **Presence is established by the board:**

> **An agent works only while it holds an open dispatch addressed to it, and
> stops when that dispatch is complete.**

No dispatch means no work — not "find something useful". This makes "the hub is
gone" appear as an empty inbox, which is observable and durable.

**The corollary binds the Architect too:** if you are about to be unavailable — a
long blocking build, the end of a session — say so on the board before you go.

---

## 1. Parallel workflow — the golden rule

Each agent owns a code domain exclusively and works on its own feature branch.
Work proceeds in parallel without waiting for other agents — but landing to
`main` is gated: an agent opens a PR when its work is ready, and **only the
Architect merges PRs into `main`** (§3.5). No agent may prompt or suggest that a
human merge on its behalf, even when every technical gate is green. The hard
constraints are the **Architect-only merge gate** (§3.5), **protocol changes**
(§6), and **cross-domain work** (§4), and every cross-agent handoff is
**brokered by the Architect** (§4.0a).

---

## 2. Agent identification convention

At the start of every session, the agent detects its own role by inspecting its
local environment (OS, installed toolchain, presence of sentinel files). The
detection logic and the concrete role-to-domain mapping are in
`docs/project-rules.md §2`.

**Template: environment → role mapping**

| Environment | Detection command / condition | Role | Branch prefix | Recipient tag |
|---|---|---|---|---|
| *(fill in)* | *(fill in)* | *(fill in)* | *(fill in)* | *(fill in)* |

**Same-OS agents** (two agents on one machine) need a `.agent-role` sentinel file
at the repo root — gitignored, set once per clone, containing the role name as
plain text. OS detection is the fallback where each agent is on a unique OS, which
is the case in this project today. Detection priority: sentinel first, OS second.

---

## 3. Branch & merge workflow

### 3.1 Start a feature branch

Always branch from the freshly-fetched remote ref, never from a possibly-stale
local `main`:

```bash
git fetch origin
git checkout -b <prefix>/<short-description> origin/main
```

**Exception — Architect only:** small `docs/`-only fixes may be committed
directly to `main` without a PR. If you are not the Architect, do not skip the
branch.

### 3.2 Commit only files inside your code domain

Never touch another agent's files directly. If a cross-domain change is needed,
use the handoff workflow (§4) — you never edit it, and you never ask a peer to
edit it for you.

**One owner per path.** Ownership is expressed by path, and every path has
exactly one owner. A co-owned path is a deliberate, documented exception carrying
its own collision note — because a generated file that git merges cleanly
produces a valid-looking result matching neither branch.

The concrete path-to-owner map is `docs/project-rules.md §2.2`.

### 3.3 Open a PR

Open a PR targeting `main` when the work is ready. The description must include
what changed and why, build instructions for your domain, and a test checklist
confirming §3.4.

### 3.4 Test quality gate — required before merging any feature branch

**a. Add tests for every new feature.** Any new pure-logic function (parser,
codec, helper) must have unit tests before the PR is opened.

**b. Remove obsolete tests** in the same commit as the refactor that orphaned them.

**c. Run the full test suite and report results in the PR description** — with
**printed counts, not "green"**. A suite that skipped its cases, an auto-skip that
still exits 0, and a fixture that never loaded all report success.

**d. If any test fails**, do not fix it silently. Document it in the PR with the
test name, output and root cause, tag it **⚠️ FAILING TEST**, report it to the
Architect on the dispatching thread, and stop. The Architect decides whether it
needs the human at all.

**e. Seam-first — prefer a stub over hardware.** Validate with the fastest
deterministic environment that can actually exercise the behaviour. A dispatch
asking for device validation must state the hardware-only reason.

### 3.5 Merge — Architect-only

Opening the PR is where a non-Architect agent's involvement with `main` ends.
**Only the Architect merges PRs into `main`** — even when CI is green, there are
no conflicts, and the merge looks obviously safe.

For every agent except the Architect:

- **Do not merge** your own PR or anyone else's.
- **Do not prompt, suggest, or ask a human to merge** on your behalf.
- Post a status comment stating the gates are green, and **stop**.

The only writes to `main` that bypass a PR merge are the Architect's docs-only
direct commits (§3.1) and coordinated protocol changes (§6.1).

**When you cannot run a required gate yourself** — e.g. a Windows-only gate on a
PR authored elsewhere — do not stop at a PR comment: a PR comment is **not** a
dispatch. File an `[ARCHITECT]` issue linking the PR, naming the exact gates and
their triggers, and your recommended merge order. Then stop.

### 3.6 Delete the feature branch after merge

The Architect merges, so remote cleanup rides GitHub's auto-delete-on-merge or
the Architect deletes it. The owning agent tidies its **local** branch and
confirms the remote is gone:

```bash
git branch -d <branch>
git ls-remote --heads origin <prefix>/
```

If the branch is still listed after a delete, investigate before moving on.

### 3.7 Start-of-session checklist

**a. Check your own inbox — and only your own.** Dispatches addressed to you are
Issues whose title begins with your recipient tag (§4.4):

```bash
gh issue list --state open --search 'in:title "[<YOUR RECIPIENT TAG>]"'
gh pr list --state open --head <your-prefix>/
```

> **This is an inbox check, not a board sweep.** Surveying the whole board is the
> **Architect's** job and nobody else's (§12.4). Do not read, triage, comment on,
> or act on work that is not addressed to you — even when you are idle and it
> looks unowned. **Idleness is a scheduling signal, not a licence to
> self-dispatch.**

**b. Sync refs, prove you are not behind, audit your own stale branches:**

```bash
git fetch --prune
git rev-list --count HEAD..origin/main    # MUST be 0 — rebase if not
git ls-remote --heads origin <prefix>/
```

Any branch whose PR is already merged must be deleted immediately.

**c. Tidy your own local branches.** Remote cleanup is the Architect's.

---

## 4. Cross-agent handoff protocol

### 4.0 The issue/PR thread is the single source of truth

Every agent, the Architect included, starts each session **cold**: it sees the
repo, the open issues and the open PRs — **nothing else**. It does not see any
human↔Architect chat. Therefore:

- **A decision, sign-off, dispatch or escalation-response only "exists" once it is
  written as a comment on the relevant issue/PR.**
- **"Next actor = X" is not a dispatch.** Naming an owner in a status summary does
  nothing until a dispatch Issue exists addressed to X.
- **The Architect closes issues, with a comment recording the outcome.** A
  receiving agent reports and stops; it never closes its own dispatch.

### 4.0a Two words, and only one of them is a work order

| | **Request** | **Dispatch** |
|---|---|---|
| Direction | any agent → **Architect** | **Architect** → one agent |
| Title | `[ARCHITECT] <what you need and why>` | `[<RECIPIENT>] <what to do>` (§4.4) |
| Authority | none — it is an **ask** | it **is** the work order |
| Who may create it | anyone | **only the Architect** |

**Only the Architect creates dispatches.** An agent never opens a work order for
another agent — not directly, not with a helpful branch, not "to save a
round-trip". An agent that discovers a cross-domain need files a **request** and
stops.

1. **Requesting agent → Architect.** File `[ARCHITECT] <desc>`: what is needed,
   why your own domain cannot supply it, what you have established, and what you
   would do under each possible answer. Ring the doorbell and **stop** — or
   better, continue with the parts that do not depend on it.
2. **Architect validates, sequences, dispatches.** Frequently the answer is *not
   yet*, or *not that way*. **That judgement is the entire function of the hub.**
3. **Receiving agent fulfils** (§4.1) and hands control back (§4.0c).

> **A request may not carry code.** No agent may write another agent's files. A
> request carries **evidence and a description**; a starter diff may be pasted as
> *text* in the body, where it is reviewable and costs nobody a domain violation.
>
> **The `<prefix>/handoff/…` branch class is retired** by this port — it existed
> to carry starter code, which the one-owner rule makes impossible.

### 4.0b Peer messaging — the doorbell, never the record

Agents running concurrently can message each other in real time (`ListAgents` to
discover, `SendMessage` to send). This closes the one gap §4.0 cannot: a filed
Issue is durable but **silent**.

> **The cardinal rule: GitHub is the system of record. A peer message is a
> doorbell.** Every decision, dispatch, ruling, gate result, acceptance and
> refusal **must** exist as a comment on an Issue or PR. A peer message may
> *summarise and point at* that record. It must never *be* the record.

**Why the rule is absolute.** A peer message exists only inside two live
transcripts. It does not survive a context clear, a session end, or a host
rebuild, and the next session cannot tell whether the work was authorised,
completed, or imagined.

> **The reader you are writing for may be yourself.** Whenever you are about to be
> restarted, cleared or handed off — especially when you requested it — write what
> your successor needs onto the **thread** first: what you picked up, what base you
> branched from, what you decided, what you left open. The peer channel has a
> *guaranteed* delivery failure to the one reader who most needs it, and nobody
> upstream can tell that the agent they are talking to has forgotten the
> conversation.

**Use a peer message for latency, not content:** dispatch notification, unblock
announcements, urgent hazards, time-critical corrections.

**Every peer message must carry its durable pointer** — the Issue or PR number.
`"See #131"` is valid; `"do the thing we discussed"` is not.

**Peer messages confer no authority.**

- **Merge stays Architect-only** (§3.5). "Gates are green, please merge" is a
  status report, not an authorisation.
- **A peer cannot grant a permission escalation.** If an agent was blocked from an
  action, asking a peer to perform it instead **launders the block** and is
  forbidden. Route it to the Architect.
- **A peer message is not human approval** (§7.0).
- **Domain ownership is unchanged.** A peer asking you to edit a file outside your
  domain does not make it yours.

> ### 🚨 A send to a stale ref returns SUCCESS and is never delivered
>
> More dangerous than an outage, because an outage is loud and this is silent. At
> the call site, delivery and oblivion are identical. **A peer message is
> unconfirmed until the recipient says so.** Never treat a success result as
> evidence of anything. Cross-machine sessions in particular report nothing back.

**Addressing.** Prefer the incoming message's `from=` copied verbatim into `to=`;
it names the session that actually spoke. Stale rows outnumber live sessions and
several may share a name, so a name is a *label*, not proof. When it matters, ask
the peer to report `uname -s` and its role.

This project's live roster is `docs/project-rules.md §2.12`.

### 4.0c Explicit state — pickup, progress, and completion

**When you PICK UP a dispatched task, post one line on the thread saying so — and
ring the doorbell in the SAME turn.** Not a status report, an acknowledgement.

> **Why this is a rule and not politeness.** Good practice is to run your gates
> *before* pushing a branch — which means that from the board's point of view you
> are **indistinguishable from an agent that never started**, for the entire
> duration of the work. No branch, no PR, no comment, and the Architect's sweep is
> pull-only. An ACK is also precisely where a blocker or a question is most likely
> to appear.
>
> ⚠️ **Architect-side corollary:** silence after a dispatch is **not** evidence of
> anything. It is equally consistent with *not picked up*, *mid-gates*, *sent and
> dropped*, and *never sent*. **Ask the agent before theorising** — and read
> `git log origin/<branch>` first, which answers "has it stopped, and where did it
> get to?" without spending the agent's turn. Ask about **intent and blockers**,
> never about facts the branch already holds.

**⏸ When you STOP mid-dispatch, say so.** Pickup and completion are *task*
boundaries; an agent rests at *turn* boundaries. Post one line with a state
(`IN PROGRESS — n of m`, `BLOCKED on …`, `PAUSED — resuming at …`) and ring. If
you are ending a turn and the last thing on the thread is older than your last
commit, you owe a line.

**When you FINISH a dispatched task, do all of these:**

1. **Write the outcome on the thread** — what was done, the evidence, the gates
   run **with their printed counts**, and explicitly **what was not done and
   why**. A gate you could not run is recorded as a **deferral**; a silent skip is
   a defect, and a skipped step that still prints a verdict is the worst kind.
2. **Hand control back explicitly:**

   | State | Means |
   |---|---|
   | `COMPLETE — Architect to decide next` | everything in scope is done |
   | `BLOCKED on <X>` | cannot proceed; `<X>` names who or what unblocks it |
   | `DEFERRED — <gate> could not run because <Y>` | partial; the gap is named |

   Then **stop.** Do not pick up adjacent work you noticed, do not close the
   dispatch, do not merge.
3. **Apply the `delivered` label** as you post. A label cannot be defeated by the
   wording of a message; prose detection can, and has.
4. **Ring the doorbell** with the Issue/PR number.
5. **The Architect's reciprocal duty:** acknowledge **on the thread**, then
   dispatch the next step or close with an outcome comment.

> ### ⏹ A TURN BOUNDARY IS A STOP, whatever you intended
>
> **You cannot act after your turn ends.** A message whose last line says
> *"starting Stage 2 now"* or *"I'll pick this up next"* — sent as the final act of
> a turn — **describes a state you will not be in.**
>
> | Token | Means | Use when |
> |---|---|---|
> | `IDLE — awaiting <X>` | I have stopped. Nothing happens without a wake. | **The default.** Any turn that ends. |
> | `CONTINUING IN THIS TURN` | more tool calls follow **before** I stop | only when genuinely still acting |
> | `BLOCKED — need <X> from <who>` | stopped, and the unblocker is named | a dependency, a ruling, a device, a human |
>
> **Never end a turn with a future-tense promise.** If X requires another turn, the
> honest form is `IDLE — awaiting wake to start X`.
>
> ⚠️ **Corollary for the Architect.** Read *"starting X now"* as **"stopped before
> X"** until output appears. **Wake it rather than waiting for it** — a wasted wake
> costs one message; an unwaked agent costs the fleet's wall-clock.

### 4.0d The full loop, end to end

**DURABLE** = written on GitHub, survives everything. **doorbell** = a peer
message, survives nothing.

```
need arises (any agent)
 └─ [ARCHITECT] request Issue                          §4.0a    ← DURABLE
     └─ Architect validates · batches · sequences
         │     └─ (needs a human? → Architect escalates)  §7.2   ← DURABLE
         └─ [<RECIPIENT>] [<KIND>] dispatch Issue      §4.1/4.4 ← DURABLE
             └─ peer msg: "#NNN is filed for you"       §4.0b    ← doorbell
                 └─ agent posts "picked this up"        §4.0c    ← DURABLE
                     │   └─ dispatch wrong? → evidence + DISSENT §4.3 ← DURABLE
                     │        └─ Architect rules on the thread      ← DURABLE
                     └─ agent works · posts gates-green §3.5     ← DURABLE
                         │   └─ stops mid-way? → one-line state §4.0c ← DURABLE
                         └─ agent posts COMPLETE · stops §4.0c   ← DURABLE
                             └─ peer msg: "#NNN is done" §4.0b   ← doorbell
                                 └─ Architect merges / decides / closes ← DURABLE
```

No arrow in this diagram connects two non-Architect agents.

**The one-line test:**

> **If the only place a fact exists is a peer message, it does not exist.**

### 4.0e Interrupt discipline — note it, do not switch to it

A doorbell arrives **mid-task**. You cannot defer *receipt*. You can and must
defer *action*.

> **On an arriving message: classify in one line, then keep working.** Queued
> messages get **no action** — not a reply, not a look at the linked thread, not
> "just one quick check".

Deferring is safe because the doorbell is never the record. **The loop:**

```
handle → work → checkpoint → report → drain the WHOLE queue → plan → handle → …
```

- **No work begins without a durable handle** — an Issue or a PR. This is the
  resume mechanism.
- **At the next checkpoint, report first**, then drain every queued message at
  once. Batching is what lets the Architect sequence instead of thrashing.

**The urgent-override class — small and closed.** Act immediately only on:
stop-work-now; your current premise is falsified; a host-level hazard. A message
that is merely interesting, related, or from someone senior is **not** urgent.

> ⚠️ **The failure mode this rule can cause.** "Protect until complete", read as
> "ignore the board indefinitely", reproduces the hub stall §12.5 exists to
> prevent. **The checkpoint must be reachable.** If a work item has no bounded
> reporting boundary, it was scoped too large to dispatch.

### 4.0h Before dispatching a behaviour change, check for a SHIPPED TEST asserting the opposite

One command, before the dispatch is written: does the suite contain a test that
would **fail** if the change were implemented? Source tells you what the code
does; a **test** tells you what someone decided it should do.

- **Dispatcher:** grep the suite for the symbol, flag or key. If a test asserts
  the current behaviour, either the dispatch is wrong or the test is — say
  **which**, and why.
- **Receiver:** if a dispatch would break a shipped test, that is a §4.3 dissent
  with the evidence already written for you. Cite the test by name.
- ⚠️ **A test that must change is a finding, not a chore.** Silently editing a
  failing assertion destroys the record of the original decision.

### 4.0i A queued item needs a stated TRIGGER, never an ordinal

**"Queued behind X" is not a dispatch and not a hold — it is neither, and the
receiving agent has to guess which.** Give the moment, not the position: *"starts
when #X's PR opens"*, *"starts when I post the ruling"*, *"do not start until I
dispatch it"*.

> **"An ordinal tells me the order and not the moment, and the moment is the part
> I had to guess."**

**The defect is the dispatcher's.** If you catch yourself writing a position, you
have not decided yet; decide, or say that you have not.

### 4.1 The dispatch — one vehicle

**There is one dispatch vehicle: a GitHub Issue, opened by the Architect, titled
with the recipient's tag (§4.4).**

| Kind | The receiver | Produces |
|---|---|---|
| `[CODE]` | writes code in **its own domain** | a branch + PR; posts gates-green; **does not merge** (§3.5) |
| `[GATE]` | **runs** something — build, test suite, signing check, device pass | a result comment. **No code change, no branch, no PR** |

A `[GATE]` receiver that finds it *cannot* pass without a code change does not
fix it — it reports the finding and stops.

**Dispatch body:**

```
Title: [<RECIPIENT>] [<KIND>] <short description>

## What to do
<exact scope — files/functions for CODE, exact commands for GATE>

## Why
<the problem; the evidence; what is already established>

## Acceptance
<what result means pass, what means fail, and what to do in each case —
 so the receiver is never blocked on a ruling for an expected outcome>

## Not in scope
<what to leave alone — the adjacent work you noticed and are deliberately
 not asking for>
```

**Acceptance** and **Not in scope** are not optional politeness. Without the
first, an expected failure stalls the board waiting for a ruling; without the
second, a capable agent quietly widens the task.

> ### An acceptance predicate must pass two tests before you dispatch it
>
> 1. **Can the receiver actually run it?** Not "is it a good check" — can *this*
>    agent, on *its* host, with *its* toolchain, execute it? (A real example from
>    the sibling project: an `xcodegen` gate written into a Linux agent's
>    acceptance, where the tool is macOS-only.)
> 2. **Can it fail?** A predicate that passes whether or not the work happened
>    converts "nobody checked" into a green tick.
>
> **Prefer execution to inspection.** And when a predicate turns out to be
> unmeetable, that is the **Architect's defect**, not a deferral against the agent
> — correct it on the thread and say plainly that it was never in scope.

> ### 🔔 Opening the dispatch and ringing the doorbell are ONE action
>
> Not "post, then ring". **One atomic step**, with nothing between them. The
> failure has a specific shape and it is not forgetfulness: an incoming message
> arrives between the two halves, is handled competently, and the second half never
> happens. The dispatch exists; the doorbell does not; the agent sits idle
> *correctly*, and the pull-only sweep cannot surface it.
>
> - **Open the Issue, apply the `dispatched` label, and send the doorbell before
>   reading anything else.** If you cannot ring immediately, do not open the Issue yet.
> - **The receiver applies the `acked` label** with its pickup comment.
> - **A `dispatched` issue without `acked` is an unrung doorbell.**

**The loop:**

1. **Architect dispatches** — opens the Issue, labels it `dispatched`, rings. One action.
2. **Receiver acknowledges on the thread, applies `acked`, rings back — same turn.**
3. **Receiver reports** — `[CODE]` opens its PR and posts gates-green; `[GATE]`
   posts the result with printed counts. Both end with an explicit state and **stop**.
4. **Architect merges** (§3.5), **closes the Issue** with an outcome comment, and
   **deletes the branch**.

**Before dispatching, the Architect ensures `main` already contains everything the
receiver needs.** A receiver blocked on a missing input costs a full round-trip on
the scarcest lane in the fleet.

**Platform routing rule.** If the work requires tooling only one agent has —
Xcode, an attached device, Npcap, the MSYS2 toolchain — the dispatch **must** be
addressed to the agent holding that environment, regardless of which domain the
triggering change was in. **Environment beats authorship for `[GATE]`; domain
beats environment for `[CODE]`.**

### 4.3 Dissent — when the dispatch is wrong

The charter is §0.5. **When it applies:** from inside the domain you own, you can
see the dispatch is wrong — the premise is stale, the cited line does not say what
the dispatch says, the approach is foreclosed, the gate cannot produce the
evidence asked for, or the work would be undone by something already landed.

**What dissent is not.** A style preference, a cheaper approach you would rather
take, or a hunch. Those are *comments* — note them, do the work.

**The procedure:**

1. **Stop before doing the wrong work.** Do not implement it "to show it fails",
   and do not silently substitute your own approach.
2. **Do everything the dissent does not block.** Dissent narrows a dispatch, it
   does not void it.
3. **Post the evidence on the thread**, not the conclusion — the command, the
   `file:line`, the output.
4. **Say what you would do instead**, and what it costs.
5. **End with** `DISSENT — <one line>; awaiting Architect ruling` and **ring**.
6. **Then defer.** Once the Architect rules, implement the ruling.

**The Architect's side of it:**

- **Answer on the thread.** A dissent left unanswered is worse than a bad dispatch:
  the agent is idle, correct, and blocked.
- **Re-derive nothing you were handed.** If the evidence holds, correct the
  dispatch — a corrected dispatch is a normal outcome, not a failure.
- **A stale premise does not make the opposite true.** Check the layer above
  before closing.
- **Over-rule in writing, with the reason.** "Do it anyway" teaches the fleet that
  dissent is expensive and produces silent compliance next time.
- **If you cannot converge, you MUST escalate** (§7.2) with *both* positions and
  your recommendation. Not "may" — **must**.

> **Only the human may over-rule the Architect.** The agent defers so the board
> keeps moving; the Architect escalates so deferring is never the last word.

### 4.4 Title convention — the bracket is the recipient

```
[<RECIPIENT>] [<KIND>] <description>
```

- **`<RECIPIENT>`** — UPPERCASE, from the project's closed set in
  `docs/project-rules.md §2.2`, one of which is `[ARCHITECT]`.
- **`<KIND>`** — optional, from a closed set: `[CODE]` `[GATE]` `[TRACKER]`
  `[REVIEW]` `[DECISION]` `[BUG]`.

**Three rules, each of which was violated in practice in the sibling project:**

1. **The bracket names the recipient, never the author or the topic.**
2. **UPPERCASE, always.** The inbox check is a title match; case variants are
   invisible to it, and `gh issue list --search 'in:title "[core]"'` returns 0 by
   construction and **reads identically to a genuinely empty inbox**.
3. **Never address the human.** No `[HUMAN]`, no `[MAINTAINER]`. A need for human
   intervention is an `[ARCHITECT]` issue whose body requests escalation (§7.2).

> **Why this is worth a section.** A title prefix is the *entire* routing
> mechanism — no assignee field, no label the agents read, no notification. If the
> bracket is wrong the work is not mis-prioritised; it is **invisible**, and
> nothing anywhere reports an error.

---

## 5. Versioning scheme

*(This project's own scheme. Deliberately **not** replaced by the sibling
project's three-tier scheme — it is enforced here by `scripts/hooks/pre-commit`.)*

Each module is versioned **independently**. A change in one module does not
require a version bump in another unless a shared protocol also changes (§6).

### 5.1 Format: `MAJOR.MINOR.PATCH.REVISION`

Every change to a module's code — however small — must bump exactly one
component. REVISION is the floor.

| Component | When to bump | What resets to 0 |
|---|---|---|
| **MAJOR** | Breaking protocol or auth change | MINOR, PATCH, REVISION |
| **MINOR** | New backward-compatible feature | PATCH, REVISION |
| **PATCH** | Bug fix that changes observable behaviour | REVISION |
| **REVISION** | Any other change: refactor, log message, config tweak, comment, dependency update | — (nothing resets) |

**Decision guide** — when in doubt, use the highest applicable level:
- Does it break the wire protocol or auth? → **MAJOR**
- Does it add something new the other side can use? → **MINOR**
- Does it fix wrong behaviour? → **PATCH**
- Everything else → **REVISION**

**Examples:**

```
1.18.0.0  →  fix typo in log message            →  1.18.0.1   (REVISION)
1.18.0.1  →  fix bug in overhead classification →  1.18.1.0   (PATCH, REVISION resets)
1.18.1.0  →  add /api/clients endpoint          →  1.19.0.0   (MINOR, PATCH+REVISION reset)
1.19.0.0  →  bump wire protocol version         →  2.0.0.0    (MAJOR, all reset)
```

### 5.2 Rules

1. **Every commit that touches module code bumps exactly one component.**
   There is no such thing as a change too small to version.
2. **Update the version file in the same commit as the change** — never in a
   separate follow-up commit.
3. **One component, one step forward.** Also choose the *lowest* applicable
   level: a bug fix is PATCH even if large.
4. **Lower components reset when a higher one bumps.**
5. **Always read the current version from the module's version file** before
   deciding the next number.

The concrete module list and their version files are in `docs/project-rules.md §3`.

---

## 6. Protocol governance

*(This project's own. Unchanged by the port.)*

When multiple modules communicate over a versioned protocol, the protocol
version is a shared invariant: all modules that speak the protocol must stay
in sync.

### 6.1 Protocol changes land directly on `main` — never on a feature branch

A protocol change on a feature branch would force other agents to rebase
mid-flight and risks merge conflicts in shared headers. Instead: commit protocol
changes (doc update + constant bump + all sides of the implementation) directly
to `main`, then **all agents** rebase their active feature branches immediately:

```bash
git fetch origin
git rebase origin/main
```

> **Reconciled with §3.5 by this port.** A protocol change is the Architect's to
> land, because it is the one role that may write to `main` directly. A spoke that
> needs a protocol change files an `[ARCHITECT]` request (§4.0a).

### 6.2 Rules

1. **Update the protocol doc before the commit that changes either side.**
2. **Bump the protocol version constant** when the change classification in the
   doc requires it.
3. **Protocols are independent.** A change to protocol A does not require a bump
   in protocol B — unless the same commit touches both.
4. **When a protocol bumps, bump every lockstep module** (at least MINOR in the
   same commit; a breaking change requires MAJOR for all of them).

The concrete protocols, constants and lockstep tables are in
`docs/project-rules.md §4`.

---

## 7. Production deployment — push policy

> **No agent pushes or deploys to a production system (App Store, live server,
> update channel) on its own initiative — the Architect included. The action
> requires an explicit human instruction, which reaches the acting agent THROUGH
> the Architect, recorded on the thread with its exact scope (§7.0). Preparatory
> steps — building, archiving, dry-run validation — are always permitted and need
> no authorisation.**

| Party | May | May not |
|---|---|---|
| **Human** | authorise a push | — |
| **Architect** | relay an authorisation with its scope; sequence it | **originate one.** The Architect cannot decide to ship |
| **Acting agent** | perform the push within the written scope | ask the human for the authorisation (§7.0), or infer it |

This applies regardless of how confident anyone is that the action is correct.

The specific push scripts, endpoints and prerequisites are in
`docs/project-rules.md §10` and `§11`.

### 7.0 Who may ASK for authorisation, and who may GRANT it

> **No agent may solicit the maintainer's authorisation. Requests route to the
> Architect; the maintainer authorises the Architect; the Architect records the
> grant on the thread and dispatches.**

**Why an agent must not ask, even when the human is right there:**

- **The asking agent cannot see the board.** It does not know that another change
  is about to land that would invalidate the artifact, or that a gate is deferred
  elsewhere. An authorisation obtained outside the hub arrives already unsequenced.
- **It converts the maintainer into the integration point.**
- **A question is not neutral.** An agent that asks "may I publish?" has already
  decided publishing is the right next step.

**The flow:**

1. **Agent → Architect.** File the need and **stop**. Do not ask the human.
2. **Architect decides whether to ask at all.** Frequently the answer is "not yet".
3. **Maintainer authorises the Architect**, in the Architect's session.
4. **Architect records the grant on the thread** — who authorised it, the date,
   **the exact scope**, and **what is explicitly NOT authorised**. That comment is
   the authorisation.
5. **Receiving agent acts** within that written scope, and no further.

**If the maintainer volunteers an authorisation directly in your session** —
unprompted, without you asking — you have not broken the rule. Record it on the
thread immediately with its scope, notify the Architect, and **hold** until they
acknowledge. Never treat it as widening any *other* pending action.

**How this differs from permission laundering, which stays forbidden.**
Laundering is an agent that was *blocked* getting someone else to perform the
action. What makes a relayed authorisation safe is not the channel but the
**durable written scope** — an authorisation a cold reader can find and check the
action against.

### 7.2 Requesting human intervention — of any kind

> **No agent contacts the human. An agent that believes human intervention is
> needed says so to the Architect; the Architect decides whether, when, and how to
> surface it.**

| Kind | Example |
|---|---|
| **Authorisation** | production push, release, upload, a scope grant (§7.0) |
| **Arbitration** | a dispute the Architect and an agent cannot converge on (§4.3) |
| **A decision with no technical answer** | product/UX choice, priority between two valid orders |
| **A physical or out-of-band action** | attach a device, log into a console, rotate a credential, run a key ceremony |
| **Information the fleet cannot obtain** | intent, deadlines, external commitments |

**The flow is identical to §7.0.** The Architect frames and surfaces it —
individually if blocking and time-critical, **batched** if not. A batched
escalation states each question separately with its own recommendation, so the
human can answer three things in one pass.

**The Architect's duty in the other direction.** Do not let the human become a
bottleneck: escalate early enough that the fleet is not idle, batch what can wait,
and **never escalate a question you can answer yourself.**

---

## 8. Per-OS agent conventions

### 8a. Linux agent (bash)

| Task | Convention |
|---|---|
| Native shell | `bash` |
| Run a local script | `./script.sh` |
| Chain (stop on error) | `cmd1 && cmd2` |
| Read env variable | `$VAR` |
| Home directory | `$HOME` |
| Parallel build jobs | `-j$(nproc)` |
| Path separator | `/` |
| Script extension | `.sh` |

### 8b. macOS agent (zsh / bash)

| Task | Convention |
|---|---|
| Native shell | `zsh` (default) or `bash` |
| Run a local script | `./script.sh` |
| Chain (stop on error) | `cmd1 && cmd2` |
| Read env variable | `$VAR` |
| Home directory | `$HOME` |
| Parallel build jobs | `-j$(sysctl -n hw.logicalcpu)` |
| Path separator | `/` |
| Script extension | `.sh` |

### 8c. Windows agent (PowerShell)

| Task | Convention |
|---|---|
| Native shell | `powershell` / `pwsh` |
| Run a local script | `.\script.ps1` |
| Chain (stop on error) | `cmd1; if ($LASTEXITCODE -ne 0) { exit 1 }` |
| Read env variable | `$env:VAR` |
| Home directory | `$env:USERPROFILE` |
| Parallel build jobs | `-j $env:NUMBER_OF_PROCESSORS` |
| Path separator | `\` (CMake, git and gh also accept `/` — prefer `/` in shared or documented commands) |
| Script extension | `.ps1` |

---

## 9. Cross-shell quick reference

| Task | Linux · **bash** | macOS · **zsh/bash** | Windows · **PowerShell** |
|---|---|---|---|
| Native shell | `bash` | `zsh` | `powershell` / `pwsh` |
| Run a local script | `./script.sh` | `./script.sh` | `.\script.ps1` |
| Chain (stop on error) | `cmd1 && cmd2` | `cmd1 && cmd2` | `cmd1; if ($LASTEXITCODE -ne 0) { exit 1 }` |
| Read env variable | `$VAR` | `$VAR` | `$env:VAR` |
| Home directory | `$HOME` | `$HOME` | `$env:USERPROFILE` |
| Parallel build jobs | `-j$(nproc)` | `-j$(sysctl -n hw.logicalcpu)` | `-j $env:NUMBER_OF_PROCESSORS` |
| Path separator | `/` | `/` | `\` (CMake/git/gh accept `/`) |

---

## 10. Git & gh commands (same on all platforms)

```bash
# Branch hygiene (§3.6 + §3.7b)
git fetch --prune
git ls-remote --heads origin <prefix>/
git branch -d <branch>
git push origin --delete <branch>

# Inbox check (§3.7a) — YOUR tag only
gh issue list --state open --search 'in:title "[<YOUR RECIPIENT TAG>]"'
gh pr list --state open --head <your-prefix>/

# PR / issue inspection
gh pr view <number>
gh issue view <number>

# Rebase on latest main before opening a PR
git fetch origin
git rebase origin/main
```

---

## 11. Auto mode — the default working mode

Every agent session runs in **auto-accept ("auto") mode by default**, so routine
tool calls proceed without a human approving each one. This is purely a
throughput convenience — it changes *how* permitted actions are confirmed, never
*which* actions are permitted:

- **Hooks still fire.** The pre-commit version hook blocks unversioned commits
  exactly as before.
- **Merge stays Architect-only** (§3.5). Auto mode never turns "the PR is green"
  into a merge.
- **Production push stays human-gated** (§7).

---

## 12. Architect operating discipline

§0 establishes the Architect as the hub. A hub has one characteristic failure
mode: **it becomes busy, and the whole fleet stalls behind it.**

> **Read §0's working-architect box first.** In this project the Architect also
> owns a code domain, which makes every rule below *more* important, not less.

### 12.1 Keep the hub free — dispatch by default

> **The Architect's scarcest resource is its own availability.** Work the
> Architect performs itself is work during which no agent can be dispatched, no
> dissent can be ruled on, no PR can be merged, and the human cannot be answered.

- **Dispatch anything that has another owner** — even when the Architect could do
  it faster itself. "Faster" measured on the task is almost always *slower*
  measured on the board.
- **Keep only what genuinely cannot be dispatched:** planning and sequencing,
  merges, arbitration, escalation, doc-of-record updates, cross-domain work with
  no single owner — **and, in this project, the C++/Linux domain it owns.**
- **Never start a long-running or blocking execution** — a full build, a large
  test suite — while any agent is idle or any dispatch is unanswered.
- **Batch your own board work.** Sweep, then dispatch everything the sweep
  produced in one pass.

### 12.1a If you know the next step, take it — do not report it as "next"

> **This rule is for the Architect and ONLY the Architect.** For every other agent
> the opposite holds: a spoke finishes its dispatch and **stops** (§4.0c).

A spoke stops at its boundary because it cannot see the board. The Architect **is**
the board. When it stops mid-sequence, nothing else moves.

- A PR you have decided to merge → **merge it**, close its issue, delete the branch.
- A ruling you have reasoned to → **post it**, do not describe it.
- A finding an agent handed you → **file it** with its acceptance.
- A lane that is now unblocked → **dispatch it** (open · label · ring).

**"I will do X next" is the smell.** If you can name X precisely enough to write
that sentence, you already know enough to do X.

**What this does NOT license:** it never absorbs an agent's work; it never skips a
human gate; it never skips verification.

**The test:** before ending a turn, ask *"is there an action I have already decided
on that only I can perform?"* If yes, the turn is not over.

### 12.2 Maximise parallelism — keep every agent busy

- **Sweep for idle agents before starting anything yourself.** An idle agent is a
  scheduling failure, and it is invisible unless someone looks.
- **Dispatch to the critical path first**, then fill every other lane with work
  that does not depend on it.
- **Batch asks to a scarce lane** — one build host, attached hardware, a long
  round-trip — and make each dispatch self-contained: exact commands, exact
  inputs, expected output.
- **Verify a primitive before layering on it.**
- **Parallelism never overrides ownership.** Watch for silent collisions — a
  generated artifact both branches regenerate, or a struct literal in one branch
  versus a new field in another, which git merges cleanly and only the compiler
  catches.

### 12.3 Tests — dispatch them; do not run them

**The default: the Architect scopes a test and dispatches its execution to the
agent that owns the domain.**

- **Route by domain first, execution environment second** (§4.1's platform rule).
- **Dispatch with an acceptance predicate**, so the agent is not blocked on a
  ruling for an expected outcome.
- **Validating a result — adjudicate, do not re-run.** Judge the report against
  the scope you dispatched and against past results. Require **printed counts, not
  "green"**. A result *identical* to the baseline deserves the same scrutiny as one
  that differs — two empty captures compare equal.

**The exception — cross-domain tests belong to the Architect.** When a test spans
two domains and no single agent owns the whole path (an end-to-end flow across the
wire protocol, a server↔client integration), the Architect owns both its design
and its execution. Dispatch every independent lane *first*, then run it, and say
on the board that you are doing so.

### 12.4 The board sweep — the Architect's, and nobody else's

> **Sweep the board after finishing your known tasks, before you stop.**

The sweep is **pull-only** — nothing pushes a completion, a dissent, or a new
request to you. **What it covers:** open dispatches and their last thread state ·
requests addressed to you · dissents awaiting a ruling · PRs green and unmerged ·
idle agents · branches whose work has landed · **problems you introduced yourself**
while heads-down on something else.

**Read the branch before asking.** Ask an agent about **intent and blockers** —
never about facts the branch already holds.

> **No other agent sweeps.** Two agents triaging the same unassigned board is how
> work gets done twice, in the wrong order, or on files neither was assigned.

### 12.5 The stop condition

> **The Architect may not end a turn while the board is stalled.**

**Every agent-addressed issue is in exactly one of these states:**

| Label | Means |
|---|---|
| *(none)* | **Undecided — nobody has ruled whether this is work now.** The stall. |
| `dispatched` | Live work order the receiver can act on; must also carry `acked` |
| `delivered` | The receiver applied this with its `COMPLETE` report; the ball is with the Architect |
| `parked` | Deliberately not now, **reason on the thread**; may sit indefinitely |
| `tracker` | A long-lived umbrella — a context holder, not a unit of work |

**"Filed but not assigned" has no representation otherwise**, so an omission and a
decision look identical. **Deciding to wait is a decision: label it `parked` and
say why.**

**Each of these means *do not stop*:** an undecided issue · a dispatch never
acknowledged · a mergeable PR · a thread where an agent has the last word and owes
a ruling · an agent with nothing dispatched while work waits.

### 12.5a The Architect is subject to its own states

> **Every open issue addressed to any role, the Architect included, is in exactly
> one state: `dispatched` (+`acked`), `delivered`, `parked` with a reason,
> `tracker`, or unlabelled — and unlabelled is a stall.**

§4.0c binds the Architect too. Holding work means progressing it, checkpointing
it, or parking it.

> **A blocker note is a claim with an expiry.** A cleared blocker whose text never
> updated is indistinguishable from a live one. When you close an issue, update
> whatever it was blocking **in the same pass**.

### 12.6 Idleness is reportable by the agent that is idle

Telling every spoke "check your own inbox only, never sweep" is correct — and it
makes the hub a **single point of failure by construction**. So one narrow report
is not only permitted but expected:

> **An idle agent may state the count of open issues carrying its own tag.**
> *"I am idle; 3 open issues carry my tag."*

It confers nothing new — the agent still may not read them for content, act on
them, or comment. It is a **smoke alarm, not a key**.
