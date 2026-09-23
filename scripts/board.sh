#!/usr/bin/env bash
# board.sh — the Architect's stop condition. "May I end this turn?"
#
# docs/agent-framework.md §12.5. Run it before ending ANY turn. Silent when the
# board is clear; every line it prints is an action §12.1a says to take now.
#
# WHY THIS EXISTS. §12.1a ("if you know the next step, take it") and §12.4
# ("sweep before stopping") both already forbid the failure this catches, and in
# the sibling project both failed — the Architect ended turns with agents idle,
# dispatchable issues undispatched and its own lane unstarted. The rules were not
# missing; nothing FIRED at the moment of stopping.
#
# STATE MODEL — every agent-addressed issue is in exactly one state:
#   (no label)  undecided — nobody has ruled whether this is work now. THE STALL.
#   dispatched  live work order THE RECEIVER CAN ACT ON; must also carry `acked`.
#               The moment the ball returns to the Architect or the maintainer,
#               the issue is `parked` with a reason, or closed. Leaving it
#               `dispatched` counts the agent as BUSY while its console sits idle,
#               which is the precise condition the capacity line exists to reveal.
#   delivered   receiver posted COMPLETE; the ball is with the Architect.
#   parked      deliberately not now, reason on the thread; may sit indefinitely.
#   tracker     a long-lived umbrella: a context holder, not a unit of work.
#
# "Filed but not assigned" has no representation otherwise, so an omission is
# indistinguishable from a decision. Deciding to wait is a decision — label it.
#
# PORTING NOTE. Adapted from secure-vault's docs/scripts/board.sh (2026-09-23).
# Two changes beyond the roster: the per-row python one-liners are replaced by a
# single gh --jq TSV query (the sibling's inline python had a quoting bug that
# `2>/dev/null` swallowed, so a whole check silently emitted nothing for weeks),
# and the `wip` / fleet-stall-check sections are dropped because neither the
# label nor that script exists here.
#
# Exit 0 always. This informs; it does not block. If it ever misses a stall the
# Architect then walks past, make it blocking (exit 2) rather than louder.

set -uo pipefail

# Recipient tags from docs/project-rules.md §2.2 — the closed set, minus ARCHITECT
# (handled separately in check 6). Update BOTH lists when the roster changes.
SPOKES=("SWIFT AGENT" "WINDOWS AGENT")

STALLS=0
say() { printf '%s\n' "$*"; STALLS=$((STALLS+1)); }

command -v gh >/dev/null 2>&1 || {
    echo "board.sh: gh unavailable — CANNOT AUDIT, do not treat silence as clear" >&2
    exit 0
}

# One query, reused by checks 1/2/4/5. Tabs separate; newlines in the last comment
# are flattened so one issue is always exactly one line.
ISSUES=$(gh issue list --state open --limit 100 \
    --json number,title,labels,comments \
    --jq '.[] | [
            (.number|tostring),
            (.title[0:58]),
            ([.labels[].name]|join(",")),
            ((.comments|last|.body) // "" | gsub("[\n\r\t]"; " ") | .[0:200])
          ] | @tsv') || {
    echo "board.sh: gh query failed — CANNOT AUDIT, do not treat silence as clear" >&2
    exit 0
}

TAG_RE="^\[($(IFS='|'; echo "${SPOKES[*]}")|ARCHITECT)\]"

# ── 1. Undecided · 2. Dispatched but never acked · 4. Agent has the last word ──
# The Architect's own tag is INCLUDED deliberately. In the sibling project this
# filter skipped [ARCHITECT] before any check ran, so nine of the Architect's own
# issues sat open, six entirely unlabelled, and not one ever produced a stall
# line — while a comment sixty lines below asserted the lane was not exempt.
# The comment was aspiration; the filter was behaviour.
while IFS=$'\t' read -r n title labels last; do
    [ -z "${n:-}" ] && continue
    printf '%s' "$title" | grep -qE "$TAG_RE" || continue

    case ",$labels," in
        *,dispatched,*)
            case ",$labels," in
                *,delivered,*)
                    say "STALL  #$n  DELIVERED — you owe a merge, a ruling, or a close"
                    say "       $title"
                    ;;
                *,acked,*)
                    # Prose fallback, deliberately secondary and NOT reliable: in the
                    # sibling project the signature test was defeated by §4.0c's own
                    # mandated closing line, "COMPLETE — Architect to decide next",
                    # which contains the very string used to detect the Architect's
                    # own comments. A correct completion therefore read as the
                    # Architect's reply and raised no stall — three times. The
                    # `delivered` label above is the fix; this stays as a net.
                    if printf '%s' "$last" | grep -qE 'COMPLETE|BLOCKED on|DISSENT|DEFERRED' \
                       && ! printf '%s' "$last" | grep -qE '— Architect$'; then
                        say "STALL  #$n  agent may have the last word — check; you may owe a ruling"
                        say "       $title"
                    fi
                    ;;
                *)
                    say "STALL  #$n  dispatched but never acked — doorbell not rung (§4.0c)"
                    say "       $title"
                    ;;
            esac ;;
        *,parked,*|*,tracker,*) : ;;   # decided: not-now, or a long-lived umbrella
        *)
            say "STALL  #$n  UNDECIDED — dispatch it, or label it 'parked' with a reason"
            say "       $title"
            ;;
    esac
done <<< "$ISSUES"

# ── 3. A merge you owe ────────────────────────────────────────────────────────
# Use gh's own --jq rather than piping into an inline interpreter: no nested
# quoting, and a query error is loud instead of silently empty.
PRS=$(gh pr list --state open --limit 30 --json number,title,mergeable \
      --jq '.[] | select(.mergeable == "MERGEABLE") | "\(.number)\t\(.title[0:58])"') || {
    say "STALL  cannot query PRs — gh pr list failed; this is NOT 'no merges owed'"
    PRS=""
}
while IFS=$'\t' read -r num title; do
    [ -z "${num:-}" ] && continue
    say "STALL  PR#$num mergeable — merge it, or say on the thread why not"
    say "       $title"
done <<< "$PRS"

# ── 5. Idle capacity: ANY spoke with nothing dispatched ───────────────────────
# §12.2: "an idle agent is a scheduling failure" — full stop, not "…while work
# waits". Requiring waiting work would make an agent with an EMPTY tagged queue
# invisible, which is the commonest form of under-parallelisation: nobody thought
# to create work for it, and the check would reward that blindness.
BUSY=0
TOTAL=${#SPOKES[@]}
for a in "${SPOKES[@]}"; do
    # Delivered work is NOT live capacity: the receiver is done and waiting on the
    # Architect. Counting it as busy is what hid three idle agents in the sibling.
    disp=$(gh issue list --state open --label dispatched --limit 50 --json title,labels \
           --jq "[.[] | select(.title | startswith(\"[$a]\")) | select((.labels|map(.name)|index(\"delivered\")) == null)] | length" 2>/dev/null || echo 0)
    wait=$(gh issue list --state open --limit 50 --json title,labels \
           --jq "[.[] | select(.title | startswith(\"[$a]\")) | select((.labels|map(.name)|index(\"dispatched\")) == null) | select((.labels|map(.name)|index(\"parked\")) == null) | select((.labels|map(.name)|index(\"tracker\")) == null)] | length" 2>/dev/null || echo 0)
    if [ "${disp:-0}" -gt 0 ]; then
        BUSY=$((BUSY+1))
    elif [ "${wait:-0}" -gt 0 ]; then
        say "IDLE   $a — nothing dispatched, $wait undecided issue(s) waiting → dispatch"
    else
        say "IDLE   $a — nothing dispatched AND nothing tagged. Deliberate?"
        say "       If there is genuinely no work, say so; otherwise this lane is"
        say "       unscheduled, not finished (§12.2)."
    fi
done
echo
echo "capacity: $BUSY/$TOTAL spokes hold a live dispatch"

# ── 6. The Architect's OWN lane ───────────────────────────────────────────────
# THE ARCHITECT'S LANE IS NOT EXEMPT FROM THE BOARD (§12.5a). In this project the
# Architect also owns a code domain (§0's working-architect box), so its own lane
# is likelier to be occupied here than in the sibling — which makes the hub more
# likely, not less, to be the thing everyone is waiting on.
MINE=$(gh issue list --state open --label dispatched --limit 50 --json title \
       --jq '[.[] | select(.title | startswith("[ARCHITECT]"))] | length' 2>/dev/null || echo 0)
if [ "${MINE:-0}" -gt 0 ]; then
    echo "your own lane: $MINE issue(s) you have taken — progress them or hand them back"
fi

echo
if [ "$STALLS" -eq 0 ]; then
    echo "BOARD CLEAR — nothing owed. Safe to stop."
else
    echo "⛔ $STALLS stall line(s). §12.5: do not end the turn while the board is stalled."
    echo "   Every line above is an action you already know how to take (§12.1a)."
fi
exit 0
