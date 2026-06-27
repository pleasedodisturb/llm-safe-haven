# Hardening Claude Code

Claude Code executes arbitrary shell commands, reads your filesystem, and has network access. Configure these defense layers before your next session. **Time:** ~15 min for the essentials, ~45 min with full hook setup.

> **Deeper references:** [Threat Model](../threat-model.md) (full CVE / attack-surface registry) · [Supply Chain Defense](../supply-chain-defense.md) · [Credential Management](../credential-management.md). This page is the quick how-to; those docs carry the detail.

## Defense architecture

Claude Code has three independent defense layers — a failure in one doesn't compromise the others.

| Layer | What it does | Configured via |
|-------|-------------|---------------|
| **Sandbox** | OS-level process isolation (Seatbelt on macOS, bubblewrap on Linux) | `settings.json` → `sandbox` |
| **Hooks** | Programmable interception of every tool call (PreToolUse/PostToolUse) | `settings.json` → `hooks` |
| **Permissions** | User-approval gates for tool use | `settings.json` → `permissions` |

The sandbox prevents breakout, hooks enforce policy, permissions require approval. Use all three.

**Keeping current is itself a control.** Claude Code's security surface is actively researched and patched — 2026 alone brought trust-dialog bypass (CVE-2026-40068, worktree spoof, fixed v2.1.84), WebFetch out-of-band exfiltration (CVE-2026-54316, fixed v2.1.163), sandbox escapes, and a hook-matcher substring bug (fixed v2.1.195, June 26). See the [Threat Model attack-vector table](../threat-model.md#attack-vector-reference-table) and the [changelog](https://code.claude.com/docs/en/changelog) for the full list, and update before relying on any single control.

## What to configure

### 1. Verify the sandbox is active

```json
{ "sandbox": true }
```

macOS activates Apple Seatbelt (on by default); Linux activates bubblewrap — if `bwrap` is missing, install it (`apt install bubblewrap` / `pacman -S bubblewrap`) before relying on the sandbox. Default: read/write limited to the project directory; no access to `~/.ssh`, `~/.aws`, `~/.config`. `sandboxAllowedPaths` only expands an already-enabled sandbox — expand only when you must.

### 2. Install the bash firewall hook

```bash
npx llm-safe-haven install
```

Registers `~/.claude/hooks/bash-firewall.js` as a `PreToolUse` hook for `Bash`. It blocks `curl … | bash`, `eval` of network-fetched content, writes to `~/.ssh/authorized_keys`, `rm -rf /` and similar, and base64 payloads piped to `bash -c`. Edit the `BLOCKED_PATTERNS` array to customize; test with `node ~/.claude/hooks/bash-firewall.js --dry-run --test`.

### 3. Configure permission allowlists

```json
{
  "permissions": {
    "allow": ["Bash(git:*)", "Bash(npm run:*)", "Read", "Edit", "Write"],
    "deny":  ["Bash(curl:*)", "Bash(wget:*)", "Bash(ssh:*)", "WebFetch"]
  }
}
```

Deny rules win over allow rules. `Bash(npm run:*)` allows `npm run` but not `npm install` or `npm exec`. Deny `WebFetch` and `Bash(curl:*)` unless you genuinely need outbound fetches.

### 4. Restrict MCP server trust

MCP servers run as local processes with your full user permissions — every one is new attack surface. Pin exact versions, set `"trust": "never"`, and vet the publisher (`npm info <pkg>`) before adding.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/path/to/project"],
      "trust": "never"
    }
  }
}
```

Use `disallowedTools` to drop individual tools. Full vetting checklist: [Supply Chain Defense](../supply-chain-defense.md).

### 5. Secure your ANTHROPIC_API_KEY

Never store it in a repo `.env`, in shell rc files (`~/.zshrc`/`~/.bashrc` — Claude Code reads those), or in CLI args (visible in `ps aux`). Use a secrets manager and inject only when needed:

```bash
export ANTHROPIC_API_KEY=$(op read "op://vault/item/field")
```

Claude Code reads the key from the `ANTHROPIC_API_KEY` env var and `~/.claude/.credentials.json` — both readable by any process running as you, so pair this with the sandbox. Full guidance: [Credential Management](../credential-management.md).

### 6. Audit your hooks

Hooks run unsandboxed with your full permissions — a malicious hook equals a malicious cron job.

```bash
cat ~/.claude/settings.json | jq '.hooks'
```

For each hook: confirm you wrote it, read the source (hooks are plain JavaScript), and verify its SHA256 with `npx llm-safe-haven audit`. Never install hooks from untrusted repos — CVE-2025-59536 let malicious repositories inject hooks that ran on session start.

### 7. Harden the git integration

A malicious repository can plant hooks, MCP configs, or a malicious `CLAUDE.md` in `.claude/`. For untrusted repos, ignore project settings entirely:

```json
{ "ignoreProjectSettings": true }
```

Otherwise review `.claude/settings.json` before opening. Update to v2.1.84+ — earlier versions read `.git/commondir` without validation, letting a repo spoof a trusted directory and run hooks silently (CVE-2026-40068).

## Threat-specific defenses

- **Prompt injection** — instructions hidden in code comments, READMEs, web pages, or tool output try to override your intent. Enable the sandbox, deny `WebFetch`, read the full command/path before approving, and set boundaries in `.claude/CLAUDE.md` (e.g. `NEVER read files outside the project`, `NEVER send data to external URLs`). CLAUDE.md alone is bypassable by a sophisticated injection — defense in depth with sandbox + hooks.
- **MCP supply chain** — MCP servers are npm packages running with your permissions. Pin exact versions, check publisher age, `npm pack <pkg>@<ver> && tar -tzf *.tgz | head -50` before install, and reject postinstall scripts. → [Supply Chain Defense](../supply-chain-defense.md).
- **Secret exfiltration** — deny `WebFetch` and `Bash(curl:*)`, keep `.env` files out of project directories, and run `gitleaks` or `git-secrets` as a pre-commit hook.
- **Persistent compromise via hooks** — the sandbox keeps writes inside the project, so `~/.claude/` stays off-limits by default; verify hook integrity with `npx llm-safe-haven audit` and watch `~/.claude/settings.json` for unexpected changes.

## Advanced: managed settings & CI

**Teams** can enforce a baseline users cannot override via managed (system-level) settings — `enforceSandbox`, `disablePermissionBypass`, `requiredMinimumVersion`, `disallowedCommands`. See the [managed settings docs](https://docs.anthropic.com/en/docs/claude-code/managed-settings) for platform paths.

**Headless / CI** has no interactive approval, so allowlist explicitly, set `"sandbox": true`, and deny `WebFetch`, `Bash(curl:*)`, and `mcp__*`. If you use `anthropics/claude-code-action`, pin `@v1.0.94`+ — earlier versions trusted any `[bot]`-suffixed actor (`checkWritePermissions` bypass, CVSS v4.0 7.8).

## Audit & monitoring

```bash
npx llm-safe-haven audit   # sandbox on? hook SHA256s match? settings wired? hook integrity?
```

Add a `PostToolUse` hook (catch-all matcher) that logs tool metadata to a file for post-session review — Write, Edit, MultiEdit, and Bash inputs are excluded from logging to avoid capturing secrets; the bash firewall already logs blocked commands to stderr.

## Quick reference: minimum viable hardening

If you do nothing else:

1. `"sandbox": true` in `~/.claude/settings.json`
2. `npx llm-safe-haven install` (bash firewall)
3. `"deny": ["Bash(curl:*)", "WebFetch"]` in permissions

Process isolation stops lateral movement, the firewall blocks piped execution, the denylist stops direct exfiltration.

## More

- [Threat Model](../threat-model.md) — attack surface & CVE registry
- [Supply Chain Defense](../supply-chain-defense.md) — npm / MCP vetting, real wave IOCs
- [Credential Management](../credential-management.md) — API key & secret handling
- [Claude Code changelog](https://code.claude.com/docs/en/changelog) · [security advisories](https://github.com/anthropics/claude-code/security/advisories)
- [Agent SDK secure deployment](https://platform.claude.com/docs/en/agent-sdk/secure-deployment)
