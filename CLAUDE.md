# LLM Safe Haven

## What This Is

Security toolkit and reference for solo developers running autonomous AI coding agents.
`npx llm-safe-haven` installs hooks and hardens your setup in 60 seconds.

## Project Structure

```
bin/                         — CLI entry point (npx llm-safe-haven)
lib/                         — CLI logic (detect, install, audit, scan)
hooks/                       — Working PreToolUse/PostToolUse hooks
manifests/                   — Secret manifest format
docs/
  threat-model.md            — OWASP Agentic Top 10 mapped to solo dev setups
  credential-management.md   — Why env vars fail, credential proxy architecture
  testing.md                 — Canary tokens, honeypots, audit log analysis
  references.md              — 64+ curated repos, papers, tools
  guides/
    quick-start.md           — Under 30 min to basic hardening
  hardening/
    claude-code.md           — Claude Code hardening guide
    cursor.md                — Cursor hardening guide
    windsurf.md              — Windsurf hardening guide
    devin.md                 — Devin hardening guide
    github-copilot.md        — GitHub Copilot hardening guide
    aider.md                 — Aider hardening guide
```

## Writing Style

- Practical, not academic. Every recommendation has a concrete action.
- Code examples are complete and runnable, not pseudocode.
- Threat model entries cite real incidents and CVEs, not hypotheticals.
- Audience: solo developers who use AI coding agents daily and want to harden their setup.
- Tone: direct, opinionated, no corporate fluff.

## Linear Ticket

Parent epic: G-507

## Conventions

- All code examples use Node.js (hooks) or shell (scripts)
- Links to external repos use full GitHub URLs
- Anthropic issue references use `anthropics/claude-code#NNNNN` format
