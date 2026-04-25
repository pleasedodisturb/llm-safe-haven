# LLM Safe Haven

## What This Is

Security toolkit and reference for solo developers running autonomous AI coding agents.
`npx llm-safe-haven` installs hooks and hardens your setup in 60 seconds.

## Project Structure

bin/                         — CLI entry point (npx llm-safe-haven)
lib/                         — CLI logic (detect, install, audit, scan)
lib/agents/                  — Modular agent plugins (one file per agent)
hooks/                       — PreToolUse/PostToolUse hooks (the product)
manifests/                   — Secret manifest format
docs/                        — Reference documentation (threat model, hardening guides)
docs/hardening/              — Per-agent hardening guides (6 agents)
docs/guides/                 — Quick start, tutorials

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
