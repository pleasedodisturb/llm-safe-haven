# LLM Safe Haven

**The missing security guide for solo developers running autonomous AI coding agents.**

No comprehensive, practical guide exists for solo developers running autonomous AI coding agents securely. The space is fragmented across enterprise frameworks, narrow tools, and academic papers. This project fills that gap.

## Why This Exists

In April 2026, three AI coding agents (Claude Code, Gemini CLI, Copilot) were [demonstrated leaking secrets through a single prompt injection](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026). The fundamental problem: **any secret an agent can read is a secret that prompt injection can exfiltrate.**

We hit this ourselves while building with Claude Code — the Seatbelt sandbox blocks Unix socket IPC, breaking credential managers like `rbw` and `1Password CLI`. The workarounds (env vars, file caching) are all insecure. We filed issues ([anthropics/claude-code#52471](https://github.com/anthropics/claude-code/issues/52471)), researched 23+ repos, and built the hardening setup documented here.

This guide is the result: threat models, hardening guides, working code, and a curated reference collection — all from real experience, not theory.

## What's Inside

### Threat Model

- [OWASP Agentic Top 10 for Solo Devs](docs/threat-model.md) — attack vectors mapped to your actual setup, with real incidents and evidence

### Hardening Guides

- [Claude Code](docs/hardening/claude-code.md) — hooks, sandbox, permissions, secret isolation
- [Cursor](docs/hardening/cursor.md) — sandbox limitations, CVE history, hardening steps
- [Windsurf](docs/hardening/windsurf.md) — weak defaults, what to lock down

### Credential Management

- [Why Env Vars Fail](docs/credential-management.md) — the fundamental problem and what to do instead
- [rbw-proxy](https://github.com/pleasedodisturb/rbw-proxy) — credential proxy for sandboxed agents *(separate project)*

### Quick Start

- [30-Minute Hardening Guide](docs/guides/quick-start.md) — do this right now, before your next agent session

### Working Examples

- [`examples/hooks/`](examples/hooks/) — bash firewall, secret detection, exfil blocking, audit logging
- [`examples/manifests/`](examples/manifests/) — per-project secret manifest format

### Reference Collection

- [Curated Security Resources](docs/references.md) — 23+ repos, papers, and tools organized by category

## Quick Start

**Time needed:** ~30 minutes for basic hardening.

```bash
# 1. Clone this repo
git clone https://github.com/pleasedodisturb/llm-safe-haven.git
cd llm-safe-haven

# 2. Follow the quick start guide
# See docs/guides/quick-start.md for step-by-step instructions
```

Or jump straight to the [Quick Start Guide](docs/guides/quick-start.md).

## Origin Story

This project grew out of real security research during the [terminal-craft](https://github.com/pleasedodisturb/terminal-craft) project, where we discovered that Claude Code's Seatbelt sandbox blocks Unix socket IPC — breaking every credential manager that uses socket-based communication (rbw, 1Password CLI, etc.).

Key Anthropic issues from our investigation:
- [anthropics/claude-code#52471](https://github.com/anthropics/claude-code/issues/52471) — Sandbox blocks Unix domain socket IPC with credential managers
- References: [#40209](https://github.com/anthropics/claude-code/issues/40209), [#41817](https://github.com/anthropics/claude-code/issues/41817), [#50165](https://github.com/anthropics/claude-code/issues/50165), [#31551](https://github.com/anthropics/claude-code/issues/31551), [#16076](https://github.com/anthropics/claude-code/issues/16076), [#29533](https://github.com/anthropics/claude-code/issues/29533), [#44195](https://github.com/anthropics/claude-code/issues/44195), [#23642](https://github.com/anthropics/claude-code/issues/23642)

## Contributing

Contributions welcome. If you've hardened your own agent setup, found a new attack vector, or built a useful tool — open a PR.

## License

[MIT](LICENSE)
