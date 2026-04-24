# LLM Safe Haven

## What This Is

Open-source security guide for solo developers running autonomous AI coding agents.
Covers threat models, hardening guides, credential management, and working code examples.

## Project Structure

```
docs/
  threat-model.md          — OWASP Agentic Top 10 mapped to solo dev setups
  credential-management.md — Why env vars fail, credential proxy architecture
  references.md            — Curated collection of 23+ repos, papers, tools
  guides/
    quick-start.md         — Under 30 min to basic hardening
  hardening/
    claude-code.md         — Claude Code hardening guide
    cursor.md              — Cursor hardening guide
    windsurf.md            — Windsurf hardening guide
examples/
  hooks/                   — Working PreToolUse/PostToolUse hook examples
  manifests/               — Secret manifest format examples
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
