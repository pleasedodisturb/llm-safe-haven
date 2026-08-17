# LLM Safe Haven

## What This Is

Security toolkit and reference for solo developers running autonomous AI coding agents.
`npx llm-safe-haven` installs hooks and hardens your setup in 60 seconds.

This file does not restate global rules — read `~/.claude/CLAUDE.md` first.

## Project Structure

bin/                         — CLI entry point (npx llm-safe-haven)
lib/                         — CLI logic (detect, install, audit, scan)
lib/agents/                  — Modular agent plugins (one file per agent)
hooks/                       — PreToolUse/PostToolUse hooks (the product)
manifests/                   — Secret manifest format
docs/                        — Reference documentation (threat model, hardening guides)
docs/hardening/              — Per-agent hardening guides (6 agents)
docs/guides/                 — Quick start, tutorials

## TDD — Non-Negotiable (adopted 2026-08-17)

**Every behaviour change starts with a failing test.** Not "tests alongside". Not "tests before the
PR". The test is written first, it is run, it FAILS, and that failure is recorded — then the code is
written.

### The contract

1. **RED first.** Write the test. Run it. It must fail *for the reason you intend* — a test that
   fails with `TypeError: x is not a function` proves nothing; it must fail on the assertion.
2. **Commit the RED separately**, prefixed `test(G-NNNN):`, before the implementation commit. On a
   squash-merged repo this branch history is the only surviving evidence the order was honoured.
3. **Paste the verbatim RED output** into the implementation commit message. "Tests added" is not
   evidence; the failure text is.
4. **GREEN.** Implement. The named test now passes and nothing else broke.

### Clear pass/fail criteria — what "proper test" means here

A test that cannot fail is worse than no test, because it ships confidence. Before writing one, state
in a comment what would make it fail. Then:

- **Assert behaviour, never the implementation restated.** If the expected value is computed by
  re-implementing the function under test, the test cannot detect a wrong implementation — it agrees
  with whatever ships. Compare against the canonical source (e.g. `computeExit()`), a fixture, or a
  hand-written literal.
- **Every "must fail" case needs a "must still pass" twin.** A guard with no paired control is
  satisfied by deleting the feature.
- **Derive cases from the construct's grammar, not from the last bug.** Cases copied from a bug
  report test yesterday's adversary. If a fix is "add another literal to the list", the check is at
  the wrong layer.
- **Non-vacuity guard for any test that loops over a set.** Assert the set is non-empty first, or an
  empty/unreadable set makes the loop iterate nothing and pass silently.
- **A negative result needs a tool that can produce a positive.** `grep` here is ugrep `-I`: it
  silently skips NUL-bearing files and exits 1, identical to "no match". Never let a bare `grep`
  exiting 1 be the proof behind an assertion.

### Break-proof stays, and is NOT the same thing

RED-first proves the test *can* fail before the code exists. The break-proof (revert one bit, confirm
the named test fails, record verbatim) proves it *still* can afterwards. Both are required. The
break-proof has repeatedly caught what RED-first would not — a test that was meaningful when written
and became vacuous later.

### Scope

Applies to `lib/**`, `hooks/**`, `bin/**`, `scripts/**`. Docs-only, comment-only, and pure-rename
commits are exempt — say so in the commit message rather than inventing a test.

`scripts/**` is **excluded from the coverage denominator**, so nothing catches a missing test there
by arithmetic. Explicit behavioural tests are its only guarantee.

## Code Rules

- Zero runtime dependencies. Only Node.js built-ins (fs, path, os, crypto, child_process).
- Node.js >= 18.
- No lifecycle scripts in package.json (postinstall, prepare, etc.).
- All hooks must pass `node -c` syntax check.
- Every agent module exports: { name, id, tier, detect, harden, audit }.
- Hooks export functions via module.exports for testing.

## Adding a New Agent Module

1. Create `lib/agents/your-agent.js` implementing the interface in `lib/agents/base.js`
2. Export: name, id, tier (1/2/3), detect(), harden(projectDir, flags), audit()
3. The registry auto-discovers — no registration needed
4. Each module is try/catch wrapped — a broken module never crashes the CLI

## Self-Security Rules

- No secrets in code, config, or docs
- npm publish with --provenance (Sigstore attestation)
- Hook integrity verification via SHA256 checksums
- Recommend pinned versions (npx llm-safe-haven@x.y.z)
- No network access during install or audit
- All file writes are to user-specified paths only (~/.claude/hooks/, project ignore files)
- settings.json merge is non-destructive (append-only, backup before write)

## Writing Style (for docs/)

- Practical, not academic. Every recommendation has a concrete action.
- Code examples are complete and runnable.
- Cite real incidents and CVEs, not hypotheticals.
- Audience: solo developers who use AI coding agents daily.
- Tone: direct, opinionated, no corporate fluff.

## Linear Ticket

Parent epic: G-507

## Conventions

- All hook code is Node.js
- Links to external repos use full GitHub URLs
- Anthropic issue references use anthropics/claude-code#NNNNN format
