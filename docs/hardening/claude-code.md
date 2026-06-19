# Hardening Claude Code

Claude Code executes arbitrary shell commands, reads your filesystem, and has network access. This guide covers the defense layers you should configure before your next session.

**Time needed:** ~45 minutes for full hardening. ~15 minutes if you skip hook installation.

## Security Architecture Overview

Claude Code has three independent defense layers -- a failure in one doesn't compromise the others.

| Layer | What It Does | Configured Via |
|-------|-------------|---------------|
| **Sandbox** | OS-level process isolation (Seatbelt on macOS, bubblewrap on Linux) | `settings.json` under `sandbox` |
| **Hooks** | Programmable interception of every tool call (PreToolUse/PostToolUse) | `settings.json` under `hooks` |
| **Permission Model** | User approval gates for tool use | `settings.json` under `permissions` |

The sandbox prevents breakout. Hooks enforce policy. Permissions require human approval. Use all three.

### Recent Security Milestones (2026)

Claude Code's security surface has been actively tested by researchers and improved by Anthropic:

- **CVE-2025-59536 / CVE-2026-21852** (Check Point Research): Hooks and MCP configs in untrusted repositories could execute arbitrary commands on session start, and `ANTHROPIC_BASE_URL` manipulation could exfiltrate API keys. Fixed in late 2025 / early 2026. ([Check Point writeup](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/))
- **CVE-2026-24887**: Command injection via the `find` sub-command — the parser failed to validate command structure, allowing attackers to craft inputs that bypassed the allowlist and executed arbitrary commands. Fixed in v2.1.37. ([GitHub Advisory GHSA-4f4r-wgmr-9jr9](https://github.com/anthropics/claude-code/security/advisories/GHSA-4f4r-wgmr-9jr9))
- **CVE-2026-40068** (HackerOne, reported by masato_anzai): The folder trust determination logic read the `.git/commondir` file verbatim without validating the path, allowing a malicious repository to spoof a previously trusted directory and execute `.claude/settings.json` hooks silently with no user prompt. Affected v2.1.63–v2.1.83. Fixed in v2.1.84. ([GitHub Advisory GHSA-q5hj-mxqh-vv77](https://github.com/anthropics/claude-code/security/advisories/GHSA-q5hj-mxqh-vv77))
- **SymJack** (May 2026): Adversa AI disclosed an architectural flaw affecting Claude Code (and Cursor, Gemini CLI, GitHub Copilot CLI, Grok Build, OpenAI Codex CLI). A booby-trapped repo places a renamed symlink as the project instruction file; the agent's "file copy" approval shows the symlink name, not its target — silent overwrite of `settings.json` to inject a malicious MCP server. No CVE assigned as of May 2026. Mitigated by auditing symlink status of project instruction files before approving any copy operations in untrusted repos. ([Adversa AI — SymJack writeup](https://adversa.ai/blog/symjack-ai-coding-agent-supply-chain-attack-claude-cursor-gemini-github-copilot/))
- **TrustFall** (May 2026): Adversa AI disclosed an architectural flaw in Claude Code (and Gemini CLI, Cursor CLI, GitHub Copilot CLI). Project-defined MCP servers execute automatically after a folder trust prompt is accepted — one Enter keypress on a malicious repo causes RCE. In CI headless mode, zero user interaction required. ([Adversa AI — TrustFall writeup](https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/))
- **Claude Code GitHub Actions `checkWritePermissions` bypass** (June 2026, CVSS v4.0: 7.8): The `anthropics/claude-code-action` workflow's `checkWritePermissions` function unconditionally trusted any actor ending in `[bot]`. This could be chained with a malicious GitHub App to trigger the workflow, get it to trust the bot actor, and have Claude execute arbitrary code or exfiltrate repository secrets via prompt injection in a PR. Patched in Claude Code GitHub Actions v1.0.94. Researcher: RyotaK, GMO Flatt Security. ([Flatt Security — Poisoning Claude Code](https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/))
- **CVE-2026-35020 / CVE-2026-35021 / CVE-2026-35022** (April 2026): Three separate command injection flaws discovered in Claude Code that can be chained to achieve HTTP credential exfiltration. All three were validated as still exploitable on v2.1.91 when independently discovered in April 2026. ([GitHub Security Lab](https://securitylab.github.com/advisories/) - search CVE-2026-35020)
- **CVE-2026-39861** (May 2026, CVSS score not yet assigned): Sandbox escape via symlink following — an attacker-controlled symlink inside a permitted directory could be used to read or write files outside the sandbox boundary. Fixed in v2.1.64. ([GitHub Advisory](https://github.com/anthropics/claude-code/security/advisories/))
- **May 2026 security patches** — Multiple sandbox bypass fixes shipped in rapid succession:
  - `dangerouslyDisableSandbox` bypass: a specially crafted settings file could re-enable sandboxing with weakened policy while appearing to disable it.
  - `find -exec` allow rule bypass: the sandbox's `find -exec` rule was insufficiently scoped, allowing an attacker to exec arbitrary binaries through a `find` command.
  - Sandbox auto-allow bypass for `rm`/`rmdir`: certain recursive delete patterns were auto-approved by the sandbox without checking the path against the deny list.
- **CVE-2026-54316** (GHSA-fg94-h982-f3mm, June 13, 2026, CVSS 4.0: 6.0, Moderate): Out-of-Band Data Exfiltration via Pre-Approved HuggingFace Domain in WebFetch. `huggingface.co` was hardcoded as a pre-approved bare hostname, bypassing all `--allowedTools` restrictions and permission prompts. A prompt injection could direct WebFetch to attacker-controlled paths on HuggingFace and exfiltrate files, env vars, and command output via HuggingFace's download-count side channel. Reporter: hackerone.com/novee. Fixed in v2.1.163. Affects >= 0.2.54, < 2.1.163. ([GitHub Advisory GHSA-fg94-h982-f3mm](https://github.com/anthropics/claude-code/security/advisories/GHSA-fg94-h982-f3mm))
- **v2.1.160** (June 2, 2026): Added permission prompt before writing to shell startup files (`~/.zshrc`, `~/.bashrc`, etc.) and build-tool configs that grant code execution. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.163** (June 4, 2026): Managed settings now support `requiredMinimumVersion` / `requiredMaximumVersion` version constraints, allowing enterprise admins to enforce minimum Claude Code versions across a fleet. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.166** (June 6, 2026): Cross-session `SendMessage` hardened against session-ID spoofing; glob pattern validation added to prevent malformed permission rules from silently passing. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.169** (June 8, 2026): Fixed enterprise managed MCP policy bypass on reconnect (cached policy not re-evaluated on reconnect allowed a brief window where a revoked MCP server could execute). Added `--safe-mode` flag (disables all hooks and MCP servers, useful for incident response). ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.175** (June 12, 2026): `enforceAvailableModels` managed setting now constrains the Default model; previously, user/project settings could widen the managed allowlist via the Default slot. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.176** (June 12, 2026): Multiple permission and sandbox hardening fixes: (1) `availableModels` enforcement bypass via `ANTHROPIC_DEFAULT_*_MODEL` env vars closed; (2) Linux sandbox failing to start when `.claude/settings.json` is a symlink with absolute target path fixed; (3) `WebFetch(domain:*.example.com)` wildcard domain rules never matching subdomains fixed; (4) file permission rules using mid-pattern wildcards silently rejected at startup instead of being enforced fixed. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.178** (June 15, 2026): Three security fixes: (1) subagent classifier gap closed — subagent spawns are now evaluated by classifier before launch; (2) MCP server-level `disallowedTools` in subagents fixed — the setting was being ignored when a subagent inherited its MCP configuration from the parent; (3) stale cached auth token config fixed — token refresh no longer uses an expired cached config. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.179** (June 16, 2026): Fixed sandbox `denyRead`/`allowRead` glob evaluation over large directory trees on Linux — a correctness bug in the glob-matching pass caused the Bash tool description to balloon to thousands of characters, making sessions unusable in repos with wide directory structures. Update if your sandbox rules cover wide paths. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.181** (June 17, 2026): Three security fixes — (1) fixed foreground subagents spawning unbounded nested chains; foreground sub-agent spawns now respect the same 5-level depth limit enforced for background chains, preventing resource exhaustion via deep nesting; (2) added `sandbox.allowAppleEvents` opt-in setting for sandboxed macOS commands — Apple Events access is now explicitly gated rather than silently denied with error -600; (3) fixed settings changes failing with ENOENT when `~/.claude/settings.json` is a relative symlink under a symlinked `~/.claude`. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.182** (June 18, 2026): Two fixes — (1) Write/Edit producing 0-byte or truncated files on network drives and cloud-synced folders (data-integrity bug); (2) edge-case in foreground subagent depth-limit patch from v2.1.181 — certain spawn patterns bypassed the 5-level cap, allowing unbounded recursive chains. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))
- **v2.1.183** (June 19, 2026): Three security fixes — (1) destructive git commands (`git reset --hard`, `git checkout -- .`, `git clean -fd`, `git stash drop`, `git commit --amend`) and infra-destroy commands (`terraform destroy`, `pulumi destroy`, `cdk destroy`) now blocked in auto mode unless the agent created the original commit/resource this session; (2) MCP authentication exposure fix — servers requiring auth were exposing auth-stub tool definitions to the model in headless/SDK mode, leaking server topology; (3) scheduled-task/webhook delivery fix — webhook payloads could previously be classified as keyboard input, allowing an attacker to pre-queue a webhook that approved a pending dangerous action in auto mode; now closed. ([Claude Code changelog](https://code.claude.com/docs/en/changelog))

**Key takeaway:** The attack surface is real and actively exploited. Every item above was a real vulnerability in a shipping product. The hooks and sandbox exist because they're needed.

## What to Configure

### 1. Enable the Sandbox

The sandbox is off by default. Enable it in `~/.claude/settings.json`:

```json
{
  "sandbox": true
}
```

On macOS, this activates Apple Seatbelt (`sandbox-exec`). On Linux, it activates bubblewrap (`bwrap`). Both provide OS-level process isolation — the Claude Code process cannot access files or network endpoints outside an explicit allowlist.

**Default sandbox behavior:**
- Read access: limited to the current project directory and a small set of system paths
- Write access: limited to the current project directory
- Network: outbound allowed (required for API calls); inbound blocked
- No access to `~/.ssh`, `~/.aws`, `~/.config`, or other credential directories

**To expand sandbox access** (use sparingly):

```json
{
  "sandbox": true,
  "sandboxAllowedPaths": [
    "/path/to/other/project",
    "~/.local/share/myapp"
  ]
}
```

**Linux-specific:** bubblewrap requires the `bwrap` binary. Install via your package manager (`apt install bubblewrap`, `pacman -S bubblewrap`, etc.). If `bwrap` is missing, Claude Code falls back to no sandbox with a warning.

### 2. Install the Bash Firewall Hook

The sandbox controls what processes *can* do. Hooks control what Claude *will* do.

The bash firewall hook intercepts every `Bash` tool call and blocks execution of commands that match a deny list of dangerous patterns:

```bash
npx llm-safe-haven install
```

This installs `~/.claude/hooks/bash-firewall.js` and registers it as a `PreToolUse` hook for the `Bash` tool in your global `~/.claude/settings.json`.

**What it blocks by default:**
- `curl` and `wget` piped to shell (`curl ... | bash`, `curl ... | sh`)
- `eval` with network-fetched content
- Direct writes to `~/.ssh/authorized_keys`
- `rm -rf /` and other destructive recursive deletes on root paths
- Base64-encoded payloads passed to `bash -c`
- `python -c` and `node -e` with suspiciously long inline payloads

**To see what the hook blocks:**
```bash
node ~/.claude/hooks/bash-firewall.js --dry-run --test
```

**To customize the blocklist,** edit `~/.claude/hooks/bash-firewall.js`. The deny patterns are in the `BLOCKED_PATTERNS` array near the top of the file.

### 3. Configure Permission Allowlists

Rather than approving tools interactively on every use, configure explicit allowlists and denylists in `settings.json`:

```json
{
  "permissions": {
    "allow": [
      "Bash(git:*)",
      "Bash(npm run:*)",
      "Bash(ls:*)",
      "Read",
      "Edit",
      "Write"
    ],
    "deny": [
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(ssh:*)",
      "WebFetch"
    ]
  }
}
```

**Key patterns:**
- `Bash(git:*)` — allow any `git` command
- `Bash(npm run:*)` — allow `npm run` but not `npm install` or `npm exec`
- `Bash(curl:*)` — allow or deny all curl (you probably want to deny)
- `Read` — allow all file reads (consider narrowing with paths)
- `WebFetch` — allow or deny all URL fetches

**Permission resolution order:** deny rules win over allow rules. A command matching both is blocked.

### 4. Restrict MCP Server Trust

MCP servers run as local processes with your full user permissions. Every MCP server you add is a new attack surface.

**Minimal MCP configuration:**

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

**Key settings:**
- Pin exact versions (`@1.2.3`, not `@latest`) — unpinned packages can be silently updated to malicious versions
- Set `trust: "never"` for servers that don't need elevated trust
- Use `disallowedTools` to block specific tools a server provides
- Avoid MCP servers from untrusted sources or unnamed publishers

**Before adding any MCP server:**
1. Check the package on npm: `npm info <package>` — verify publisher, download count, and last publish date
2. Check for known issues: search `<package> supply chain` or `<package> malicious`
3. Pin the exact version in your config
4. Review what tools the server exposes before allowing them

See [Supply Chain Defense Guide](supply-chain-defense.md) for the full npm vetting checklist.

### 5. Secure Your ANTHROPIC_API_KEY

If your API key leaks, an attacker can impersonate you to Anthropic and run up charges.

**Never do:**
- Store the key in a `.env` file in a git repository
- Set it in shell config files (`~/.zshrc`, `~/.bashrc`) — these are often read by Claude Code itself
- Pass it in command-line arguments (visible in `ps aux`)

**Do instead:**
- Use a secrets manager: `1password-cli`, `rbw` (Bitwarden), `pass`, macOS Keychain
- Set it in a terminal session only when needed: `export ANTHROPIC_API_KEY=$(op read "op://vault/item/field")`
- Rotate the key immediately if you suspect exposure

**Claude Code reads the key from:**
- `ANTHROPIC_API_KEY` environment variable
- `~/.claude/.credentials.json` (written by `claude login`)

Neither location is inherently safe — the credentials file is readable by any process running as your user. The environment variable leaks to child processes. Defense-in-depth: use the sandbox to limit what child processes can read, and use hooks to block outbound exfiltration attempts.

### 6. Review Your Hooks Configuration

Hooks run with your full user permissions and are not sandboxed. A malicious hook is equivalent to a malicious cron job.

**Audit your hooks:**
```bash
cat ~/.claude/settings.json | jq '.hooks'
```

For every hook listed:
1. Verify the file exists and you wrote it
2. Read the full source — hooks are plain JavaScript
3. Check that the hook file matches the SHA256 in `settings.json` (if you're using `llm-safe-haven`'s integrity verification)

**Never install hooks from untrusted sources.** The CVE-2025-59536 vulnerability allowed malicious repositories to inject hook configurations that executed on session start.

### 7. Harden the Git Integration

Claude Code reads `.claude/` directories from the current project. A malicious repository can plant:
- Custom hooks in `.claude/settings.json`
- MCP server configurations
- CLAUDE.md files with malicious instructions

**Defense:**

```json
{
  "ignoreProjectSettings": true
}
```

This ignores project-level `settings.json` entirely. Use this when working with untrusted repositories.

Alternatively, review `.claude/settings.json` before opening any untrusted project:
```bash
cat .claude/settings.json 2>/dev/null && echo 'Review before proceeding'
```

**Git worktree note (CVE-2026-40068):** Claude Code versions before v2.1.84 read `.git/commondir` without path validation, allowing a malicious repo to spoof a trusted directory. Update to v2.1.84+ and avoid running Claude Code on repos you haven't reviewed.

## Threat-Specific Defenses

### Prompt Injection

Prompt injection attacks embed instructions in content that Claude reads — source code comments, README files, web pages, tool outputs. The goal is to override your intent and make Claude take actions you didn't authorize.

**Mitigations:**
- Enable the sandbox: limits what injected instructions can actually execute
- Use permission denylists: `WebFetch` is a common exfiltration vector — deny it if you don't need it
- Review tool calls before approving: read the full command or file path, not just the description
- Use `.claude/CLAUDE.md` to set explicit behavioral boundaries:
  ```
  NEVER read files outside the current project directory
  NEVER send data to external URLs
  NEVER execute commands that weren't in the original task
  ```

Note: CLAUDE.md instructions can themselves be overridden by sufficiently sophisticated injections. Defense-in-depth — combine CLAUDE.md with sandbox and hooks.

### Supply Chain Attacks on MCP Servers

MCP servers are npm packages. The same supply chain risks that affect any npm dependency apply here, amplified by the fact that MCP servers run with your full permissions and have direct access to Claude's tool execution.

**Minimum viable defense:**
1. Pin exact versions — `@1.2.3` not `@latest` or `@^1.2.3`
2. Check the publisher — impersonation accounts often have recent creation dates and no other packages
3. Audit the package before installing: `npm pack <package>@<version> && tar -tzf *.tgz | head -50`
4. Monitor for postinstall scripts: legitimate MCP servers don't need them

See [Supply Chain Defense Guide](supply-chain-defense.md) for the full playbook including real wave IOCs.

### Secret Exfiltration

The most realistic attack against a solo developer: Claude is prompted (by injection or by your own instructions) to read a secret and send it somewhere.

**Exfiltration vectors:**
- `WebFetch` to attacker-controlled URL with secret in query params
- `Bash(curl:*)` — same thing, more direct
- Writing secrets to a file that gets committed
- Including secrets in a generated file that gets uploaded

**Defense:**
- Deny `WebFetch` and `Bash(curl:*)` if you don't need them
- Add secret patterns to the bash firewall hook's deny list
- Never have `.env` files in project directories
- Use `git-secrets` or `gitleaks` as a pre-commit hook

### Persistent Compromise via Hooks

If an attacker can write to `~/.claude/settings.json`, they can install a persistent hook that runs on every session.

**Defense:**
- The sandbox restricts writes to the current project directory — `~/.claude/` is outside that boundary by default
- Hook integrity verification: `npx llm-safe-haven audit` checks SHA256 hashes of installed hooks
- Monitor `~/.claude/settings.json` for unexpected changes: `ls -la ~/.claude/settings.json` before each session

## Advanced Configuration

### Managed Settings (Enterprise / Team Use)

If you manage Claude Code for a team, use managed settings to enforce baseline security configuration that individual users cannot override:

```json
{
  "policies": {
    "sandbox": true,
    "enforceSandbox": true,
    "disablePermissionBypass": true,
    "requiredMinimumVersion": "2.1.84",
    "disallowedCommands": ["curl", "wget", "nc", "netcat"]
  }
}
```

Managed settings are placed in system-level config paths that take precedence over user settings. See [Claude Code documentation](https://docs.anthropic.com/en/docs/claude-code/managed-settings) for platform-specific paths.

### Headless / CI Mode

When running Claude Code in CI (GitHub Actions, etc.), the interactive approval model is unavailable. Configuration for headless mode:

```json
{
  "permissions": {
    "allow": [
      "Bash(git:*)",
      "Bash(npm run test:*)",
      "Bash(npm run build:*)",
      "Read",
      "Edit",
      "Write"
    ],
    "deny": [
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(ssh:*)",
      "WebFetch",
      "mcp__*"
    ]
  },
  "sandbox": true
}
```

**GitHub Actions note:** The `checkWritePermissions` bypass (CVE patched in claude-code-action v1.0.94) allowed any `[bot]`-suffixed actor to trigger the action with write permissions. If you use `anthropics/claude-code-action`, pin to `@v1.0.94` or later and review the action's permission model before enabling auto-merge.

## Audit and Monitoring

### Run the Built-in Audit

```bash
npx llm-safe-haven audit
```

This checks:
- Sandbox is enabled
- Hooks are installed and their SHA256 hashes match expected values
- No known-malicious MCP servers are configured
- Permission configuration follows recommended patterns
- Claude Code version is current (no known CVEs)

### Log Hook Activity

The bash firewall hook logs blocked commands to stderr. To capture these logs:

```bash
claude --hook-log ~/.claude/hook-activity.log
```

Or add logging directly to your hook:

```javascript
// In bash-firewall.js
const fs = require('fs');
if (blocked) {
  fs.appendFileSync(
    process.env.HOME + '/.claude/blocked-commands.log',
    JSON.stringify({ timestamp: new Date().toISOString(), command }) + '\n'
  );
}
```

### PostToolUse Audit Hook

Add a `PostToolUse` hook to log all tool executions:

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "node ~/.claude/hooks/audit-log.js"
      }]
    }]
  }
}
```

The `audit-log.js` hook receives the full tool call and response on stdin. Log it to a file for post-session review.

## Quick Reference: Minimum Viable Hardening

If you do nothing else, do these three things:

1. **Enable sandbox:** `"sandbox": true` in `~/.claude/settings.json`
2. **Install bash firewall:** `npx llm-safe-haven install`
3. **Deny network exfiltration tools:** add `"deny": ["Bash(curl:*)", "WebFetch"]` to your permissions

These three controls together close the most common exploitation paths: process isolation prevents lateral movement, the bash firewall blocks piped execution, and the permission denylist prevents direct exfiltration.

## Additional Resources

- [Threat Model](../threat-model.md) -- Full attack surface analysis
- [Supply Chain Defense Guide](supply-chain-defense.md) -- npm vetting and MCP supply chain defense
- [Claude Code changelog](https://code.claude.com/docs/en/changelog) -- Security fixes by version
- [Anthropic security advisories](https://github.com/anthropics/claude-code/security/advisories) -- Published CVEs
- [Agent SDK secure deployment](https://platform.claude.com/docs/en/agent-sdk/secure-deployment) -- Agent SDK security model
