# Windsurf Hardening Guide

Windsurf (by Codeium, formerly Windsurf AI) is a VS Code-based IDE with an integrated
AI agent called Cascade. It has weaker security defaults than both Claude Code and
Cursor, a poor track record of responding to vulnerability disclosures, and fundamental
architectural issues that limit how much hardening is possible.

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
- **Same Chromium dependency** as Cursor, with the same 94+ unpatched CVE exposure
  from outdated builds (OX Security, October 2025).

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
  plants instructions once; they execute in every future session.
- **Invisible instructions:** Windsurf processes hidden Unicode characters that are
  invisible to developers but interpreted by the AI as instructions. Malicious instructions
  hidden in source files execute without any visible indicator.

Windsurf acknowledged receipt of the disclosure but **never responded to follow-up
inquiries about triage, bug status, or fixes**. After three months of silence, the
findings were published publicly.

### Chromium Vulnerability Backlog (October 2025)

Same as Cursor: 94+ known CVEs from legacy Chromium builds. Windsurf's last Chromium
update was March 21, 2025 (version 0.47.9). OX Security's responsible disclosure notice
on October 12, 2025 received no response from Windsurf.

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

### 5. Keep Chromium Updated (When Possible)

Check Windsurf's changelog for Chromium version bumps. Given the 94+ CVE backlog,
this is a significant ongoing risk. There is nothing you can do about this except
update Windsurf when new versions ship and pressure Codeium to maintain their
Chromium fork.

### 6. Don't Use Windsurf for Sensitive Projects

This is the honest recommendation. If your project handles credentials, payment
processing, PII, or infrastructure secrets, Windsurf's security posture is not
adequate. Use it for prototyping, learning, or projects where a compromise has
limited blast radius.

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
- **Unresponsive security team.** Two independent security researchers (Embrace The Red
  and OX Security) reported critical vulnerabilities and received no substantive response.
  This is a process failure that affects your ability to trust future patches.

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
| Vulnerability Response | Active GitHub issue tracking | Unresponsive to disclosures |
| CVE History (2025-2026) | None assigned | CVE-2025-62353 (CVSS 9.8) + unpatched Chromium |
| Chromium Dependency | None (terminal-based) | Yes -- 94+ unpatched CVEs |

## Bottom Line

Windsurf is a capable coding assistant with serious security gaps that cannot be fully
mitigated through configuration alone. The combination of no sandbox, demonstrated
exfiltration paths, memory poisoning vulnerabilities, and an unresponsive security
process means you are accepting significant risk by using it for anything sensitive.

**Our recommendation:**

- **For sensitive projects:** Do not use Windsurf. Use Claude Code or a hardened Cursor
  setup instead.
- **For low-risk prototyping:** Usable with `.codeiumignore`, manual command approval,
  and no secrets in the project tree. Accept the residual risk.
- **For any project:** Never store credentials, API keys, or infrastructure secrets
  anywhere Windsurf can reach. This includes `.env` files, config directories, and
  your shell history.

Windsurf may improve its security posture over time. But as of April 2026, the
architecture and disclosure response pattern do not support trusting it with sensitive
workloads.
