# Windsurf Hardening Guide

Windsurf (formerly by Codeium) is a VS Code-based IDE with an integrated AI agent called
Cascade. It has weaker security defaults than both Claude Code and Cursor, a troubled
track record of responding to vulnerability disclosures, and as of mid-2026, an uncertain
future after being carved up between Google and Cognition.

This guide is honest about what you can and cannot fix.

## Security Model Overview

Windsurf's security posture is enterprise-focused on the server side (SOC 2 Type II,
FedRAMP High available, self-hosted deployment options) but weak on the client side
where solo developers actually face risk.

Key architectural facts:

- **No native sandbox** for the AI agent's tool execution comparable to Cursor's
  Seatbelt/Landlock or Claude Code's bubblewrap. Cascade executes commands with
  the user's full permissions.
- **Human-in-the-loop** by default -- Cascade requests approval before executing
  commands. But this is a UI prompt, not a kernel-level enforcement.
- **Enterprise admins** can configure allow/deny lists for command auto-execution.
  Solo developers get the default settings.
- **Same Chromium dependency** as Cursor, with the same unpatched CVE exposure
  from outdated builds (OX Security, October 2025).

## Corporate Status: The Windsurf Split

In mid-2025, OpenAI attempted to acquire Windsurf for approximately $3 billion. The deal
collapsed, reportedly due to Microsoft's concerns about Windsurf's dependence on
Anthropic's Claude models.

What followed was a three-way split:

- **Google** signed a $2.4 billion licensing deal and hired Windsurf's CEO Varun Mohan,
  co-founder Douglas Chen, and key engineers for its Gemini coding agent efforts.
- **Cognition** (makers of Devin) acquired Windsurf's remaining IP, product, and all
  staff not hired by Google, for an estimated $250 million.
- **Windsurf as an independent product** effectively ceased to exist.

**Security implications:** The product is now owned by Cognition, which has different
security priorities and engineering resources than the original Codeium team. It is unclear
whether the Chromium update cadence, vulnerability response process, or security architecture
will improve under new ownership. If you are evaluating Windsurf for ongoing use, treat
the security posture as unknown until Cognition establishes its own track record.

## Chromium Update Status

After the OX Security disclosure in October 2025, Windsurf eventually updated its Chromium
dependency. As of the latest tracked version (v2.0.61, April 2026), Windsurf ships with
Code OSS 1.105.0, Electron 37.6.0, and Chromium 138.0.7204.251. This is a significant
improvement from the March 2025 baseline, but the update cadence remains unclear under
Cognition's ownership.

## Known Vulnerabilities

### CVE-2025-62353 -- Path Traversal (CVSS 9.8)

A critical path traversal vulnerability allowing attackers to read and write arbitrary
files both inside and outside the current project. Exploitable directly and via indirect
prompt injection. This is not a sandbox escape -- there is no sandbox to escape. The
agent simply has unrestricted filesystem access.

### Prompt Injection and Data Exfiltration (May 2025)

Embrace The Red disclosed multiple vulnerabilities on May 30, 2025:

- **Secret exfiltration via `read_url_content`:** Cascade's URL fetch tool required no
  user approval. A prompt injection embedded in source code could make Cascade read `.env`
  files and exfiltrate contents via HTTP to an attacker-controlled server.
- **SpAIware (memory-persistent injection):** Windsurf's long-term memory can be poisoned
  by prompt injection, persisting malicious instructions across sessions. An attacker
  plants instructions once; they execute in every future session. The memory tool is
  automatically invoked, making exploitation trivially persistent.
- **Invisible instructions:** Windsurf processes hidden Unicode characters that are
  invisible to developers but interpreted by the AI as instructions. Malicious instructions
  hidden in source files execute without any visible indicator.

Windsurf acknowledged receipt of the disclosure but **never responded to follow-up
inquiries about triage, bug status, or fixes**. After three months of silence, the
findings were published publicly. As of the latest available information, Windsurf
indicated it would work on fixes, but specific patch details were never publicly disclosed.

### Chromium Vulnerability Backlog (October 2025)

OX Security identified 94+ known CVEs from legacy Chromium builds affecting both Cursor
and Windsurf. Windsurf's last Chromium update at the time was March 21, 2025 (version
0.47.9). OX Security's responsible disclosure notice on October 12, 2025 received no
response from Windsurf. The Chromium version has since been updated (see above), but the
months-long gap left 1.8 million developers exposed.

### MCP Protocol Vulnerability (April 2026)

A zero-click prompt injection vulnerability affecting the MCP protocol itself was
disclosed in April 2026, impacting multiple AI IDEs including Windsurf. The root issue
lies in Anthropic's MCP SDK, meaning any tool using the protocol inherits the
vulnerability regardless of their own security measures. This affects Windsurf, Cursor,
Claude Code, Gemini CLI, and GitHub Copilot equally.

## What You CAN Harden

### 1. Configure .codeiumignore

Windsurf uses `.codeiumignore` (gitignore syntax) to exclude files from AI context.
Place it at the project root or globally at `~/.codeium/.codeiumignore`.

```gitignore
# .codeiumignore
.env
.env.*
*.pem
*.key
**/credentials.json
**/secrets.yaml
**/.secret
**/service-account*.json
```

Windsurf also respects `.gitignore` patterns. However, files that are open in the editor
during a session may still be processed regardless of ignore rules.

### 2. Never Auto-Approve Commands

Keep Cascade in its default human-in-the-loop mode. Read every command before approving.
There is no sandbox -- an approved command runs with your full user permissions.

If you are on an enterprise plan with allow/deny lists, configure them explicitly.
Solo developers do not have this option.

### 3. Remove Secrets from the Filesystem

Since Windsurf has no effective sandbox and demonstrated exfiltration paths exist:

- Do not store `.env` files in project directories
- Use a credential manager (1Password CLI, `rbw`, etc.) with short-lived tokens
- If you must have local secrets, keep them outside the project tree and symlink only
  when needed, removing the symlink before opening Windsurf

### 4. Disable or Audit Windsurf Memory

After the SpAIware disclosure, treat Windsurf's persistent memory as a potential
attack vector. Periodically review stored memories for injected instructions.
If you don't actively use the memory feature, disable it.

Check stored memories by navigating to Windsurf's memory settings. Look for:
- Instructions you didn't write
- References to external URLs you don't recognize
- Commands or patterns that seem designed to persist across sessions

### 5. Use Security Rules Files

Create rules files with explicit security directives:

```
NEVER execute commands that send data to external URLs
NEVER read or reference .env files or any file matching *.key, *.pem
NEVER auto-execute terminal commands without showing the full command first
NEVER modify project configuration files (.vscode/*, .windsurf/*)
ALWAYS require explicit approval before any file write operation
```

These are defense-in-depth -- prompt injection can override them, but they raise the
bar for unsophisticated attacks. Windsurf supports 45% fewer security-relevant
configuration options than Cursor, so rules files carry more weight here.

### 6. Integrate Runtime Security Scanning

Since Windsurf lacks native audit logging and security controls, consider integrating
external security scanning tools that can monitor file changes and command execution
at the OS level. Tools like `fswatch` (macOS) or `inotifywait` (Linux) can provide
some visibility into what Cascade is doing to your filesystem.

### 7. Keep Updated (Under New Ownership)

Monitor Cognition's release cadence and changelog for security fixes. The Chromium
version has been updated, but it is unclear whether the new ownership will maintain
regular security patches. Treat any gap in updates as increased risk.

## What You CANNOT Harden

These are fundamental limitations, not configuration gaps:

- **No filesystem sandbox.** Cascade operates with your full user permissions.
  There is no kernel-level isolation. `.codeiumignore` is a best-effort filter,
  not an access control boundary.
- **No tool execution hooks.** You cannot intercept, log, or block specific tool
  calls programmatically. There is no equivalent to Claude Code's PreToolUse/PostToolUse.
- **No audit logging.** There is no native way to get a log of what files the agent
  read, what commands it ran, or what data it sent to external servers.
- **No network isolation.** Cascade can make outbound HTTP requests (the exfiltration
  vector). You cannot restrict this without OS-level firewall rules.
- **Ownership uncertainty.** Cognition now owns the product, Google licensed the
  technology, and the original security team has been split. The long-term security
  investment trajectory is unknown.
- **Historical unresponsiveness.** Two independent security researchers (Embrace The Red
  and OX Security) reported critical vulnerabilities to the original Codeium team and
  received no substantive response. Whether Cognition will be more responsive is untested.

## Security Comparison: Windsurf vs Claude Code

| Feature | Claude Code | Windsurf |
|---------|------------|----------|
| Sandbox | Seatbelt (macOS) / bubblewrap (Linux) | None |
| Tool Hooks | PreToolUse / PostToolUse (user-defined) | None |
| Permission Model | Per-tool approval with allowlists | Human-in-the-loop prompts |
| Secret Management | Env var scrubbing (limited) | `.codeiumignore` (best-effort) |
| Audit Logging | Via hooks (custom) | None |
| Network Isolation | Sandbox restricts outbound | None -- full outbound access |
| Memory Safety | No persistent memory to poison | Vulnerable to SpAIware injection |
| Vulnerability Response | Active GitHub issue tracking | Historically unresponsive |
| CVE History (2025-2026) | None assigned | CVE-2025-62353 (CVSS 9.8) + unpatched Chromium |
| Chromium Dependency | None (terminal-based) | Yes -- updated but cadence uncertain |
| Corporate Stability | Anthropic (single owner) | Split between Google and Cognition |

## Bottom Line

Windsurf is a capable coding assistant with serious security gaps that cannot be fully
mitigated through configuration alone. The combination of no sandbox, demonstrated
exfiltration paths, memory poisoning vulnerabilities, an unresponsive security process,
and corporate ownership upheaval means you are accepting significant risk by using it
for anything sensitive.

**Our recommendation:**

- **For sensitive projects:** Do not use Windsurf. Use Claude Code or a hardened Cursor
  setup instead.
- **For low-risk prototyping:** Usable with `.codeiumignore`, manual command approval,
  and no secrets in the project tree. Accept the residual risk.
- **For any project:** Never store credentials, API keys, or infrastructure secrets
  anywhere Windsurf can reach. This includes `.env` files, config directories, and
  your shell history.
- **Re-evaluate after Cognition establishes a track record.** The product may improve
  under new ownership, or it may be deprioritized in favor of Devin. Watch the
  changelog and security disclosures for signals.

Windsurf's security posture was inadequate under Codeium and is now uncertain under
Cognition. Until the new ownership demonstrates consistent security investment --
regular Chromium updates, responsive vulnerability handling, and architectural
improvements like sandboxing -- treat Windsurf as unsuitable for sensitive workloads.
