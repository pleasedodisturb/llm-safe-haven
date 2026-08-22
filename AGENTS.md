# AGENTS.md

## What this file is (and isn't)

This is the cross-agent working contract for llm-safe-haven, plus a short current-state block
refreshed at ship time. Several AI coding tools — not just Claude Code — read a file named
`AGENTS.md` at the repository root by convention before touching a project, including cloud and
containerized runs that see nothing but the output of `git clone`.

It does **not** restate the full coding contract — the coding rules, the TDD contract, the project
shape, or the writing style for docs. All of that lives in `CLAUDE.md`, cross-referenced below —
this file only carries what `CLAUDE.md` cannot: state that changes every release, and the minimum
working agreements an agent needs before its first commit (a few of which, like the hook syntax
check, deliberately repeat a `CLAUDE.md` rule so a non-Claude agent sees them without reading it).

### Why this shape (D-08)

Three options were weighed for making project state reachable from a bare clone:

- **A contract with no current-state block.** Rejected — a static contract that never states where
  the project actually is rots exactly the way the version references in `CLAUDE.md` once did:
  nothing forces it to stay current, and the drift goes undetected until an agent trusts a stale
  line.
- **Un-ignoring the local session-handoff log wholesale.** Rejected — that log is a verbose local
  working record that today carries absolute local paths, a machine name, and internal-tooling
  field names. Publishing it as-is would leak that content into a public repository, and every
  future regeneration would need re-sanitising, forever, to stay safe to publish.
- **This file: a tracked contract plus a short, guard-enforced current-state block.** Chosen. It
  duplicates nothing from `CLAUDE.md`, and the one thing that must not silently go stale — the
  version line below — is graded by the documentation-drift guard's existing version check, not
  left to memory or convention alone.

No `.claude/rules/` directory exists in this repository, and none is created by this change.
Nothing belongs there that `CLAUDE.md` does not already hold; adding an empty scaffold to satisfy
a convention would itself be the kind of drift-prone duplication this file exists to avoid.

## Working agreements

- Branch per ticket. Never commit directly to the repository's default branch.
- Prefix every commit title with the ticket it serves (for example, `G-1565: ...`).
- Review every change before merge — no self-merging on a summary alone.
- Never push a bare short-form version tag. The publish workflow fires on any pushed tag matching
  the `v*` pattern, so a stray short tag would trigger a real npm release.
- The planning directory and the session-handoff log directory are both local-only. Neither is
  ever staged or committed, and neither exists in a fresh clone of this repository.
- Every hook must pass a syntax check (`node -c`) before it ships.

For the full coding contract — the TDD requirement, the zero-runtime-dependency rule, the
agent-module interface, and the writing style for `docs/` — see `CLAUDE.md`. It is not repeated
here.

## Current state

- Shipped: llm-safe-haven@0.7.0
- Milestone: v0.8 "Doc Integrity" — Phase 22 (Content Fixes) complete: the documentation-drift
  guard reports zero findings and runs as a blocking CI check
- Next: ship v0.8.0 (bump `package.json` and this block together; the guard enforces it)
- Long-form local state lives in the session-handoff log this repository keeps local-only and
  fully ignored — not reachable from a clone, and not duplicated here.

This version line is bumped together with `package.json`'s own version, and the
documentation-drift guard enforces that agreement: it fails any build where this line and
`package.json` disagree. The guard's own test suite already proves this with a planted defect —
see `tests/docs-verify/version.test.js`, which is cited here rather than duplicated. This block
itself is refreshed at ship time, as part of the release change.
