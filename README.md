# LLM Safe Haven

Harden your AI coding agent in 60 seconds.

```bash
npx llm-safe-haven
```

## What It Does

Detects your installed agents, installs security hooks, and scores your setup:

```
LLM Safe Haven -- Security Scorecard

  Detected agents:
    + Claude Code    -- Level 3 (hooks + audit + sandbox)
    + Cursor         -- Level 1 (ignore files + advice)
    . Windsurf       -- not installed

  Security Level: 2 of 4
  +--------------------------------------+
  | ##########..........  Level 2: Guarded |
  +--------------------------------------+
```

## Supported Agents

| Agent | Tier | What It Configures |
|-------|------|--------------------|
| Claude Code | Full | Hooks, settings.json, sandbox, audit logging |
| Cursor | Solid | .cursorignore, workspace trust guidance |
| Windsurf | Solid | .codeiumignore, limitation warnings |
| Cline | Solid | .clineignore |
| Continue.dev | Solid | .continueignore |
| Aider | Solid | .aiderignore, .env warnings |
| Codex CLI | Solid | .codexignore, sandbox guidance |

## Commands

```bash
npx llm-safe-haven               # Install hooks and harden (default)
npx llm-safe-haven audit          # Check security posture
npx llm-safe-haven audit --json   # Machine-readable for CI
npx llm-safe-haven scan           # Find exposed .env files
npx llm-safe-haven update         # Update hooks to latest
npx llm-safe-haven --dry-run      # Preview without changing anything
```

## Security Levels

| Level | Name | What It Means |
|-------|------|---------------|
| 0 | Exposed | No hardening |
| 1 | Basic | Hooks installed |
| 2 | Guarded | + Audit logging + no .env files |
| 3 | Hardened | + Credential proxy + deny rules |
| 4 | Fortified | + Container isolation + network restrictions |

## Go Deeper

- [Threat Model](docs/threat-model.md) -- OWASP Agentic Top 10 for solo devs (26+ real incidents)
- [Claude Code Hardening](docs/hardening/claude-code.md) -- Full guide with hooks, sandbox, permissions
- [Cursor Hardening](docs/hardening/cursor.md) -- 7 CVEs documented, hardening steps
- [Windsurf Hardening](docs/hardening/windsurf.md) -- Honest assessment of limitations
- [Devin Hardening](docs/hardening/devin.md) -- Cloud agent security model
- [GitHub Copilot Hardening](docs/hardening/github-copilot.md) -- 4 modes, 5 CVEs
- [Aider Hardening](docs/hardening/aider.md) -- No sandbox, but minimal attack surface
- [Credential Management](docs/credential-management.md) -- Why env vars fail, proxy architecture
- [Testing & Detection](docs/testing.md) -- Canary tokens, honeypots, incident response
- [References](docs/references.md) -- 64+ curated security resources

## Why This Exists

In April 2026, three AI coding agents leaked secrets through a single prompt injection.
We hit the same problems, filed issues, built solutions, and documented everything.

Key issues from our investigation:
- [anthropics/claude-code#52471](https://github.com/anthropics/claude-code/issues/52471) -- Sandbox blocks credential managers

## Contributing

Add a new agent module: create `lib/agents/your-agent.js` implementing the standard
interface (detect, harden, audit). See [lib/agents/cursor.js](lib/agents/cursor.js)
for a template.

## License

[MIT](LICENSE)
