# Aider Hardening Guide

Aider is an open-source (Apache 2.0), terminal-based AI pair programming tool. It connects
to multiple LLM providers (OpenAI, Anthropic, local models via Ollama), edits files
directly on your filesystem, and auto-commits changes to git. It has no sandbox, no
permission system, and no tool hooks -- but it is transparent, local, and under your
full control.

This guide covers what risks Aider introduces and what you can realistically do about them.

## Security Model Overview

Aider's security model is simple: there isn't one. This is not a criticism -- it is a
design choice consistent with Aider's philosophy as a lightweight pair programmer that
trusts the developer to manage their own environment.

Key architectural facts:

- **No sandbox.** Aider operates directly on your filesystem with your full user
  permissions. There is no kernel-level isolation, no container, no restricted process
  tree.
- **No permission system.** Aider does not ask for approval before reading files, writing
  files, or executing commands. If you add a file to the chat, Aider can edit it.
- **No tool hooks.** There is no PreToolUse/PostToolUse equivalent. You cannot
  programmatically intercept, log, or block Aider's actions.
- **No network isolation.** Aider sends your code context to whichever LLM provider you
  configure. There is no outbound filtering beyond what the OS provides.
- **Git-centric workflow.** Every edit Aider makes is auto-committed to git with a
  descriptive message. This is Aider's primary safety mechanism -- you can `/undo` any
  change instantly.
- **Multi-provider.** Aider works with OpenAI, Anthropic, Google, Azure, local models
  (Ollama, llama.cpp), and dozens of other providers. Your code goes wherever you point it.

### What Aider Does NOT Do

Unlike IDE-based agents (Cursor, Windsurf, Copilot), Aider does not:

- Execute arbitrary shell commands autonomously (it edits files and commits)
- Run MCP servers or external tool integrations
- Maintain persistent memory across sessions (no SpAIware vector)
- Process hidden UI elements or invisible Unicode in a GUI context
- Ship with a Chromium dependency (terminal-only)

This significantly reduces the attack surface compared to IDE-based tools. The primary
risks are code context leakage to LLM providers and secrets exposure through file access.

## Known Vulnerabilities

Aider has no assigned CVEs as of April 2026. This reflects both its smaller attack surface
and its smaller install base compared to Cursor or Copilot. However, the absence of CVEs
does not mean the absence of risk.

### Prompt Injection via Repository Content

Aider is susceptible to the same indirect prompt injection risks as any tool that feeds
repository content to an LLM. Academic research reports attack success rates exceeding 85%
against state-of-the-art defenses when adaptive attack strategies are applied. A malicious
file added to the chat context could instruct the LLM to:

- Write malicious code into other files
- Exfiltrate secrets by encoding them into file contents or commit messages
- Modify `.aider.conf.yml` or `.env` to change Aider's own configuration

Aider has no defense against this beyond the LLM's own instruction-following boundaries.

### .env File Exposure

Aider loads API keys and configuration from `.env` files in a specific precedence:

1. Home directory (`~/.env`)
2. Git repository root (`.env`)
3. Current directory (`.env`)
4. Custom path via `--env-file`

Files loaded later take priority. This means:

- **Your API keys are stored in plaintext** in `.env` files on disk
- If Aider's LLM reads the `.env` file (e.g., you add it to chat context, or a prompt
  injection instructs the model to read it), your provider API keys are exposed
- The `.env` in your repo root is at particular risk -- it is adjacent to the code
  Aider processes

Aider's documentation recommends adding `.env` to `.gitignore`, but this only prevents
git commits -- it does not prevent Aider's LLM from reading the file if instructed.

### Provider Trust Surface

Every LLM provider you configure receives your code context:

- **Commercial APIs (OpenAI, Anthropic, Google):** Your code is transmitted over HTTPS
  to their servers. Each has its own data retention and training policies.
- **Azure/AWS deployments:** Your code goes to your cloud tenant, but you are still
  trusting the provider's infrastructure.
- **Local models (Ollama, llama.cpp):** No external transmission. This is the strongest
  data sovereignty option.
- **Together.ai, Groq, etc.:** Third-party inference providers with varying security
  postures and data policies.

Unlike Claude Code (which only talks to Anthropic) or Copilot (which only talks to
GitHub/Microsoft), Aider's multi-provider nature means you need to evaluate the trust
posture of whichever provider you choose.

## Hardening Steps

### 1. Use Local Models for Sensitive Code

If your code contains trade secrets, proprietary algorithms, or references to
infrastructure:

```bash
# Run Aider with a local model via Ollama
aider --model ollama/deepseek-coder-v2
```

Local models keep all code on your machine. The quality tradeoff is real -- local models
are less capable than GPT-4o or Claude Sonnet -- but for security-critical work, the
data sovereignty is worth it.

### 2. Protect .env Files

```bash
# Ensure .env is in .gitignore
echo ".env" >> .gitignore

# Move API keys out of the project directory
# Use a home directory .env instead
echo "OPENAI_API_KEY=sk-..." >> ~/.env

# Or better: use environment variables directly
export OPENAI_API_KEY=$(rbw get "OpenAI API Key")
```

Never store `.env` files in the project root where Aider operates. Use a credential
manager with short-lived tokens when possible.

### 3. Use --no-auto-commits for Untrusted Contexts

If you are working with code from an untrusted source:

```bash
aider --no-auto-commits
```

This disables Aider's automatic git commits, giving you the chance to review every
change before it becomes part of your git history. The tradeoff is losing `/undo`
functionality, since undo depends on auto-commits.

### 4. Limit Chat Context

Only add files to the chat that Aider needs to edit. Aider cannot read files you haven't
added (unlike IDE-based tools that index your entire workspace):

```bash
# Good: add only the files being modified
aider src/auth.py src/routes.py

# Bad: add everything
aider $(find . -name "*.py")
```

Fewer files in context means less code sent to the LLM provider and less surface for
prompt injection from repository content.

### 5. Review Auto-Commits Before Pushing

Aider's auto-commits are your audit trail. Review them before pushing:

```bash
# See what Aider changed
git log --oneline --author="aider" -10
git diff HEAD~3..HEAD

# Undo the last Aider change if it looks wrong
aider
> /undo
```

### 6. Use .aiderignore

Aider respects a `.aiderignore` file (gitignore syntax) that prevents files from being
added to the chat context:

```gitignore
# .aiderignore
.env
.env.*
*.pem
*.key
**/credentials.json
**/secrets.yaml
**/service-account*.json
```

This is a best-effort defense -- it prevents accidental inclusion, not a determined
prompt injection attack.

### 7. Scope API Keys Narrowly

Since Aider stores API keys in plaintext `.env` files or environment variables:

- Use API keys with the narrowest possible scope and permissions
- Set spending limits on your LLM provider accounts
- Rotate keys regularly (monthly minimum)
- Use separate API keys for Aider vs. production workloads

### 8. Run in a Container for Maximum Isolation

For sensitive work, run Aider in Docker:

```bash
docker run --rm -it \
  -v $(pwd):/app \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  paulgauthier/aider \
  --model gpt-4o
```

This provides filesystem isolation (Aider can only access `/app`), network isolation
(configurable via Docker networking), and process isolation. It is the closest thing
to a sandbox that Aider supports.

### 9. Air-Gap for Maximum Security

Aider supports fully air-gapped deployments with local models:

```bash
# No external API calls at all
ollama serve &
aider --model ollama/codestral --no-analytics
```

This eliminates all external data transmission. Useful for classified, regulated, or
extremely sensitive codebases.

## Security Comparison: Aider vs Claude Code

| Feature | Claude Code | Aider |
|---------|------------|-------|
| Sandbox | Seatbelt (macOS) / bubblewrap (Linux) | None |
| Tool Hooks | PreToolUse / PostToolUse (user-defined) | None |
| Permission Model | Per-tool approval with allowlists | None -- full filesystem access |
| Secret Management | Env var scrubbing (limited) | `.aiderignore` (best-effort) |
| Audit Logging | Via hooks (custom) | Git auto-commits (every change) |
| Network Isolation | Sandbox restricts outbound | None (OS-level only) |
| Memory Safety | No persistent memory | No persistent memory |
| LLM Provider | Anthropic only | Any provider (including local) |
| Data Sovereignty | Code goes to Anthropic | Your choice (local possible) |
| CVE History (2025-2026) | None assigned | None assigned |
| Chromium Dependency | None (terminal-based) | None (terminal-based) |
| MCP/Extension Surface | MCP servers (user-approved) | None |
| Open Source | No (CLI is closed-source) | Yes (Apache 2.0) |
| Command Execution | Shell commands with approval | File edits only (no shell) |

## Bottom Line

Aider occupies a unique position in the AI coding tool landscape: it has the weakest
built-in security controls but also the smallest attack surface. No sandbox, no
permissions, no hooks -- but also no Chromium vulnerabilities, no MCP server exploits,
no persistent memory poisoning, and no autonomous command execution.

**Strengths:**
- Open source and auditable (Apache 2.0)
- Terminal-based with no GUI attack surface
- Multi-provider with local model support (true air-gap possible)
- Git-centric workflow provides natural audit trail and instant undo
- No persistent memory or state between sessions
- No autonomous command execution -- edits files only
- Smallest dependency footprint of any major AI coding tool

**Weaknesses:**
- No sandbox of any kind -- full filesystem access with user permissions
- API keys stored in plaintext `.env` files
- No tool hooks for interception or logging
- No permission system -- cannot restrict what files Aider accesses
- Prompt injection defenses rely entirely on the LLM provider
- No native `.env` file protection (can be read if added to context)

**Our recommendation:** Aider is a reasonable choice for developers who want transparency
and control over their AI coding tool. Its security model is "trust the developer" rather
than "restrict the agent," which works if you:

1. Use local models or trusted providers only
2. Keep secrets out of the project directory
3. Review auto-commits before pushing
4. Run in Docker for sensitive work
5. Maintain `.aiderignore` for every project

For developers who need enforced security boundaries (sandboxing, permission systems,
audit hooks), Claude Code provides stronger guarantees. For developers who prioritize
data sovereignty and transparency, Aider with local models is the most private option
available.

Aider is honest about what it is: a power tool with no safety guards. Use it accordingly.
