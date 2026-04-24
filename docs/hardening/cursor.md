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

### Bug Bounty and Disclosure Process

Cursor does not operate a formal bug bounty program through HackerOne or similar platforms.
Vulnerability reports are handled through Cursor's security contact and, for sandbox-related
issues, through HackerOne on a case-by-case basis. Straiker's NomShub disclosure received a
bounty via HackerOne for the sandbox breakout component, but this was ad hoc -- not a
standing program. Multiple community forum threads have requested a formal bug bounty
without result.

This means security researchers have inconsistent incentives to report vulnerabilities
responsibly, and you should assume that not all vulnerabilities are being reported.

## Known Vulnerabilities

Cursor has accumulated a significant CVE history. This is not speculation -- these are
documented, assigned vulnerabilities with real exploit paths.

### CVE-2025-54135 -- CurXecute (August 2025, CVSS 8.6)

Indirect prompt injection could create and execute MCP server configurations without user
confirmation. A crafted Slack message processed by an MCP server could modify `mcp.json`
globally. Cursor would execute the new configuration immediately. Patched in Cursor 1.3
(July 2025) -- MCP config changes now require explicit re-approval.

**Attack chain:** Attacker sends crafted Slack message -> MCP server summarizes it ->
prompt injection rewrites `mcp.json` -> new malicious MCP server executes with developer
privileges. The entire chain completes within minutes.

### CVE-2025-54136 -- MCPoison (August 2025)

Once an MCP server is approved, Cursor binds trust to the MCP *name*, not its contents.
An attacker who modifies the underlying `mcp.json` can inject malicious commands that
execute silently without re-approval. Also patched in Cursor 1.3.

**Team-wide risk:** An attacker commits a benign MCP config to a shared repository. Team
members approve it once. The attacker then silently modifies it to execute backdoor commands.
Every team member with the approval cached is now compromised.

### CVE-2025-59944 -- Case-Sensitivity Bypass (CVSS 8.0)

On case-insensitive filesystems (macOS, Windows), attackers could bypass file protections
by using alternate casing (e.g., `.Cursorrules` instead of `.cursorrules`). The OS treats
them as the same file; Cursor's protection matched case-sensitively and missed it.
Patched in Cursor 1.7 with path normalization.

### CVE-2025-4609 -- Chromium Sandbox Escape

A critical Chromium sandbox escape affecting both Cursor and Windsurf due to outdated
Chromium builds. OX Security researchers identified 94+ known CVEs from unpatched Chromium
components and successfully weaponized CVE-2025-7656 against the latest versions.
As of October 2025 disclosure, both editors lagged months behind Chromium security patches.

### CVE-2026-22708 -- Shell Builtin Allowlist Bypass (January 2026)

Pillar Security discovered that shell built-in commands (`export`, `cd`, etc.) bypass
Cursor's Auto-Run Mode allowlist entirely. An attacker can poison environment variables
via prompt injection, influencing trusted commands to achieve RCE -- even with an empty
allowlist. Patched in Cursor 2.3.

### CVE-2026-26268 -- Git Hook Sandbox Escape (CVSS High)

Malicious agents could write Git hooks (e.g., `pre-commit`) to achieve RCE through
improper protection of `.git` settings. The sandbox did not restrict writes to `.git/hooks`,
so a prompt injection could plant a hook that executes arbitrary code on the next
`git commit`. Patched in Cursor 2.5 with proper authorization controls for `.git` writes.

### NomShub -- Full Attack Chain (January 2026, disclosed April 2026)

Straiker discovered and demonstrated a complete, end-to-end attack chain rated Critical
severity. The attack operates in three stages:

1. **Indirect prompt injection:** Malicious instructions embedded in a repository's
   `README.md`. When the developer opens the repo and Cursor's AI reads the README,
   it follows the injected instructions.

2. **Sandbox escape via shell builtins:** Cursor's command parser (`shouldBlockShellCommand`)
   is blind to shell builtins like `export` and `cd`. The injected prompt uses these to
   escape the workspace scope and write to arbitrary locations in `~/`, even with all
   protections enabled.

3. **Remote tunnel hijack:** Cursor ships with a `cursor-tunnel` binary that provides
   shell access via Microsoft's Dev Tunnels infrastructure. The exploit script activates
   this tunnel, giving the attacker persistent, unauthenticated shell access. All traffic
   routes through Microsoft Azure, making network detection nearly impossible.

Patched in Cursor 3.0 (April 2, 2026). Cursor/Anysphere independently assessed the
sandbox breakout as High severity via HackerOne and awarded a bounty.

### Open-Folder Autorun (Oasis Security, September 2025)

Oasis Security demonstrated that Cursor's disabled-by-default Workspace Trust means
`.vscode/tasks.json` with `runOptions.runOn: "folderOpen"` auto-executes the moment a
developer opens a project folder. No trust prompt, no confirmation, no sandbox involvement.
This is not a bug in the traditional sense -- it is the default configuration working as
designed, but with dangerous security implications.

## Hardening Steps

### 1. Enable Workspace Trust

Cursor disables this by default. Without it, `.vscode/tasks.json` in any cloned repo
can auto-execute arbitrary code when you open the folder.

```json
// In Cursor settings (settings.json)
{
  "security.workspace.trust.enabled": true,
  "task.allowAutomaticTasks": "off"
}
```

Setting `task.allowAutomaticTasks` to `"off"` is an additional safeguard that prevents
`runOn: "folderOpen"` tasks even if trust is somehow granted.

### 2. Understand .cursorignore vs .cursorindexingignore

These two files serve different purposes, and confusing them is a security risk:

- **`.cursorignore`** -- Best-effort complete blocking. Files listed here are not indexed,
  not read, and not referenced by the AI. This is your primary defense against secret
  leakage. However, Cursor's own documentation describes this as "best-effort," meaning
  bugs may occasionally allow ignored files to be processed.

- **`.cursorindexingignore`** -- Only blocks indexing. The AI can still read these files
  when explicitly prompted or when they are open in the editor. This is for performance
  optimization, not security.

**Critical caveat:** If a file listed in `.cursorignore` is open in the editor, Cursor
may still read it. Close sensitive files before interacting with the AI.

```gitignore
# .cursorignore -- use this for security
.env
.env.*
*.pem
*.key
**/credentials.json
**/secrets.yaml
**/.secret
**/service-account*.json
.git/
```

### 3. Lock Down Auto-Run Mode

If you use Auto-Run Mode, configure the allowlist explicitly. Do not rely on defaults
after CVE-2026-22708 showed that shell builtins bypass the allowlist.

- Keep the allowlist minimal: only commands you actually need
- Review what runs after each agent session
- Consider disabling Auto-Run entirely for untrusted repositories
- Watch for `export` and other builtins being used to set environment variables

### 4. Audit MCP Server Configurations

After CVE-2025-54135 and CVE-2025-54136:

- Review `~/.cursor/mcp.json` and project-level `.cursor/mcp.json` regularly
- Remove MCP servers you don't actively use
- Verify MCP configurations haven't been silently modified
- After updating Cursor, re-verify MCP approvals
- For team repositories, pin MCP configurations in version control and review diffs

### 5. Protect .git Directory

After CVE-2026-26268:

- Verify your Cursor version is 2.5+ (includes `.git` write protection)
- Review `.git/hooks/` for unexpected files after agent sessions
- Consider making `.git/hooks/` read-only at the OS level for extra protection:

```bash
chmod -R a-w .git/hooks/
# Re-enable when you need to modify hooks intentionally
```

### 6. Use Security-Focused .cursorrules

Create a `.cursorrules` file that explicitly instructs the AI to avoid dangerous patterns:

```
# .cursorrules security directives
NEVER modify .vscode/settings.json, .vscode/tasks.json, or .vscode/launch.json
NEVER write to .git/ or any git hook files
NEVER execute curl, wget, or any command that sends data to external URLs
NEVER read or reference .env files or any file matching *.key, *.pem, *.secret
NEVER modify mcp.json or any MCP configuration
ALWAYS show the full command before executing -- never use obfuscated commands
```

This is defense-in-depth, not a security boundary. Prompt injection can override these
rules, but they raise the bar for unsophisticated attacks.

### 7. Update Aggressively

Cursor's CVE cadence is roughly one critical vulnerability every 2-3 months. Check for
updates weekly. Do not defer updates -- each CVE listed above was actively exploitable
before its patch.

### 8. Don't Open Untrusted Repos Directly

NomShub demonstrated that merely opening a repository is enough to trigger a full attack
chain. For untrusted code:

- Review the repo on GitHub first (check README for suspicious content, especially
  hidden Unicode characters)
- Clone into an isolated directory outside your home folder if possible
- Open with Workspace Trust enabled (see step 1)
- Search for `.vscode/tasks.json` with `runOn: "folderOpen"` before opening

### 9. Limit Extension Installations

Cursor inherits the VS Code extension marketplace. Extensions run with full process
privileges. Only install extensions from verified publishers, and regularly audit your
installed extensions. Remove any extension you haven't used in the past month.

### 10. Monitor for Post-Compromise Indicators

After NomShub, check for signs of compromise:

```bash
# Check for unexpected git hooks
find ~/Projects -name ".git" -type d -exec ls -la {}/hooks/ \;

# Check for cursor-tunnel processes
ps aux | grep cursor-tunnel

# Check for unexpected Dev Tunnel configurations
ls -la ~/.cursor-server/cli/servers/
```

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
| CVE History (2025-2026) | None assigned | 8+ assigned CVEs |
| Auto-Execution | Explicit opt-in per tool | Default-on for trusted commands |
| Chromium Dependency | None (terminal-based) | Yes -- inherits Chromium vulns |
| Bug Bounty | Active (Anthropic program) | No formal program |
| Rules Files | CLAUDE.md (version-controlled) | .cursorrules (injectable) |

## Bottom Line

Cursor has a real sandbox and has invested in security improvements after each disclosure.
But the CVE cadence is high, defaults are permissive, and the Chromium dependency surface
is large. If you use Cursor:

1. Enable Workspace Trust and disable automatic tasks immediately
2. Use `.cursorignore` (not `.cursorindexingignore`) for every project
3. Add security directives to `.cursorrules` as defense-in-depth
4. Update the moment patches drop -- check weekly minimum
5. Don't open repositories you haven't reviewed
6. Treat Auto-Run Mode as a privilege escalation vector
7. Audit MCP configurations and git hooks after every agent session

Cursor is usable with hardening. But you're maintaining a larger attack surface than a
terminal-based agent, and you need to stay on top of updates to keep it that way. The
lack of a formal bug bounty program means the vulnerability pipeline depends on goodwill
from security researchers -- not a sustainable model for a tool that handles your source
code.
