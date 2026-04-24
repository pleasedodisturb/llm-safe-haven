# Cursor Hardening Guide

Cursor is a VS Code fork with integrated AI agent capabilities. It has a real sandbox,
a growing CVE history, and defaults that prioritize convenience over security.
This guide covers what to lock down and why.

## Security Model Overview

Cursor implements platform-native sandboxing for its agent subprocess tree:

- **macOS:** Seatbelt profiles restrict read/write at the syscall level. The policy is
  generated dynamically from workspace settings, admin settings, and `.cursorignore`.
- **Linux:** Landlock + seccomp. Seccomp blocks unsafe syscalls; Landlock enforces
  filesystem restrictions. Ignored files are overwritten with inaccessible copies.
- **Windows:** The Linux sandbox runs inside WSL2.

The sandbox writable scope covers `~/` (the entire home directory), not just the workspace.
This is a significant design choice -- any sandbox escape grants home-directory-wide access.

Cursor ships with **Workspace Trust disabled by default**. This means opening a malicious
repository can trigger automatic code execution via `.vscode/tasks.json` with no prompt.

## Known Vulnerabilities

Cursor has accumulated a significant CVE history. This is not speculation -- these are
documented, assigned vulnerabilities with real exploit paths.

### CVE-2025-54135 -- CurXecute (August 2025, CVSS 8.6)

Indirect prompt injection could create and execute MCP server configurations without user
confirmation. A crafted Slack message processed by an MCP server could modify `mcp.json`
globally. Cursor would execute the new configuration immediately. Patched in Cursor 1.3
(July 2025) -- MCP config changes now require explicit re-approval.

### CVE-2025-54136 -- MCPoison (August 2025)

Once an MCP server is approved, Cursor binds trust to the MCP *name*, not its contents.
An attacker who modifies the underlying `mcp.json` can inject malicious commands that
execute silently without re-approval. Also patched in Cursor 1.3.

### CVE-2025-59944 -- Case-Sensitivity Bypass (CVSS 8.0)

On case-insensitive filesystems (macOS, Windows), attackers could bypass file protections
by using alternate casing (e.g., `.Cursorrules` instead of `.cursorrules`). The OS treats
them as the same file; Cursor's protection matched case-sensitively and missed it.
Patched in Cursor 1.7 with path normalization.

### CVE-2025-4609 -- Chromium Sandbox Escape

A critical Chromium sandbox escape affecting both Cursor and Windsurf due to outdated
Chromium builds. OX Security researchers identified 94+ known CVEs from unpached Chromium
components and successfully weaponized CVE-2025-7656 against the latest versions.
As of October 2025 disclosure, both editors lagged months behind Chromium security patches.

### CVE-2026-22708 -- Shell Builtin Allowlist Bypass (January 2026)

Pillar Security discovered that shell built-in commands (`export`, `cd`, etc.) bypass
Cursor's Auto-Run Mode allowlist entirely. An attacker can poison environment variables
via prompt injection, influencing trusted commands to achieve RCE -- even with an empty
allowlist. Patched in Cursor 2.3.

### CVE-2026-26268 -- Git Hook Sandbox Escape

Malicious agents could write Git hooks (e.g., `pre-commit`) to achieve RCE through
improper protection of `.git` settings. Patched in Cursor 2.5.

### NomShub -- Full Attack Chain (April 2026)

Straiker demonstrated a complete attack chain: open a malicious repo, indirect prompt
injection in README.md triggers sandbox escape via shell builtins, writes a tunnel
exploitation script, and gives attackers persistent shell access through Cursor's remote
tunnel feature. All traffic routes through Microsoft Azure, making network detection
nearly impossible. Rated Critical severity. Patched in Cursor 3.0 (April 2026).

## Hardening Steps

### 1. Enable Workspace Trust

Cursor disables this by default. Without it, `.vscode/tasks.json` in any cloned repo
can auto-execute arbitrary code when you open the folder.

```json
// In Cursor settings (settings.json)
{
  "security.workspace.trust.enabled": true
}
```

### 2. Configure .cursorignore

Create a `.cursorignore` at your project root. Files listed here are fully blocked --
not indexed, not read, not referenced by the AI.

```gitignore
# .cursorignore
.env
.env.*
*.pem
*.key
**/credentials.json
**/secrets.yaml
**/.secret
**/service-account*.json
```

This is your primary defense against secret leakage into AI context. `.cursorindexingignore`
only blocks indexing -- the AI can still read those files when prompted. Use `.cursorignore`
for anything sensitive.

### 3. Lock Down Auto-Run Mode

If you use Auto-Run Mode, configure the allowlist explicitly. Do not rely on defaults
after CVE-2026-22708 showed that shell builtins bypass the allowlist.

- Keep the allowlist minimal: only commands you actually need
- Review what runs after each agent session
- Consider disabling Auto-Run entirely for untrusted repositories

### 4. Audit MCP Server Configurations

After CVE-2025-54135 and CVE-2025-54136:

- Review `~/.cursor/mcp.json` and project-level `.cursor/mcp.json` regularly
- Remove MCP servers you don't actively use
- Verify MCP configurations haven't been silently modified
- After updating Cursor, re-verify MCP approvals

### 5. Update Aggressively

Cursor's CVE cadence is roughly one critical vulnerability every 2-3 months. Check for
updates weekly. Do not defer updates -- each CVE listed above was actively exploitable
before its patch.

### 6. Don't Open Untrusted Repos Directly

NomShub demonstrated that merely opening a repository is enough to trigger a full attack
chain. For untrusted code:

- Review the repo on GitHub first (check README for suspicious content)
- Clone into an isolated directory outside your home folder if possible
- Open with Workspace Trust enabled (see step 1)

### 7. Limit Extension Installations

Cursor inherits the VS Code extension marketplace. Extensions run with full process
privileges. Only install extensions from verified publishers, and regularly audit your
installed extensions.

## Security Comparison: Cursor vs Claude Code

| Feature | Claude Code | Cursor |
|---------|------------|--------|
| Sandbox | Seatbelt (macOS) / bubblewrap (Linux) | Seatbelt (macOS) / Landlock+seccomp (Linux) |
| Sandbox Scope | Workspace-scoped | Home-directory-wide (`~/`) |
| Tool Hooks | PreToolUse / PostToolUse (user-defined) | None -- no hook system |
| Permission Model | Per-tool approval with allowlists | Workspace trust (disabled by default) |
| MCP Security | User approval per server | Name-bound trust (was exploitable) |
| Secret Management | Env var scrubbing (limited) | `.cursorignore` (best-effort) |
| Audit Logging | Via hooks (custom) | None native |
| CVE History (2025-2026) | None assigned | 7+ assigned CVEs |
| Auto-Execution | Explicit opt-in per tool | Default-on for trusted commands |
| Chromium Dependency | None (terminal-based) | Yes -- inherits Chromium vulns |

## Bottom Line

Cursor has a real sandbox and has invested in security improvements after each disclosure.
But the CVE cadence is high, defaults are permissive, and the Chromium dependency surface
is large. If you use Cursor:

1. Enable Workspace Trust immediately
2. Maintain `.cursorignore` for every project
3. Update the moment patches drop
4. Don't open repositories you haven't reviewed
5. Treat Auto-Run Mode as a privilege escalation vector

Cursor is usable with hardening. But you're maintaining a larger attack surface than a
terminal-based agent, and you need to stay on top of updates to keep it that way.
