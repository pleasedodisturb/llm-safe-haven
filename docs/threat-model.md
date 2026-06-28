# Threat Model: OWASP Agentic Top 10 for Solo Developers

## Why This Exists

You run an AI coding agent with access to your terminal, your files, and your credentials. That agent talks to a cloud API. Everything it reads — every file, every command output, every environment variable — becomes part of a conversation that leaves your machine.

There is no OWASP Testing Guide equivalent for autonomous coding agents. Enterprise security frameworks assume teams, SOCs, and network perimeters. Solo developers have none of that. You are the developer, the ops team, and the security department.

This threat model maps the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) to solo developer setups — real tools, real attack vectors, real incidents. It draws on the [precize/Agentic-AI-Top10-Vulnerability](https://github.com/precize/Agentic-AI-Top10-Vulnerability) taxonomy that underpins the OWASP and CSA red-teaming work.

**If you just want the action items:** jump to [What Solo Developers Should Do](#what-solo-developers-should-do) at the bottom.

---

## OWASP Agentic Top 10: How It Maps to Your Setup

| OWASP Rank | Threat | Your Attack Surface | Relevant Guide |
|-----------|--------|--------------------|-----------------|
| AG01 | Prompt Injection | CLAUDE.md, web content, code comments | [Claude Code Hardening](hardening/claude-code.md) |
| AG02 | Sensitive Data Exposure | .env files, credentials in context | [Secret Management](hardening/claude-code.md#5-secure-your-anthropic_api_key) |
| AG03 | Agent Privilege Escalation | Tool permissions, MCP trust levels | [Permission Model](hardening/claude-code.md#3-configure-permission-allowlists) |
| AG04 | Cross-Agent Interaction Risks | MCP servers, subagents | [MCP Hardening](hardening/claude-code.md#4-restrict-mcp-server-trust) |
| AG05 | Insecure Orchestration | Hook execution, bash firewall gaps | [Hooks](hardening/claude-code.md#2-install-the-bash-firewall-hook) |
| AG06 | Memory Poisoning | Session persistence, log injection | N/A for Claude Code (no persistent memory) |
| AG07 | Trust Boundary Violations | Untrusted repos, project settings | [Git Hardening](hardening/claude-code.md#7-harden-the-git-integration) |
| AG08 | Resource & Budget Exhaustion | Runaway tool calls, API cost | Rate limits, usage caps |
| AG09 | Supply Chain Compromise | MCP packages, npm dependencies | [Supply Chain Defense](supply-chain-defense.md) |
| AG10 | Emergent Behavior Risk | Unintended multi-step actions | Permission model, hooks |

---

## Attack Vector Reference Table

Every item in this table is a real, confirmed attack or vulnerability. No hypotheticals.

| Attack Vector | Severity | Mechanism | Source |
|--------------|----------|-----------|--------|
| Prompt injection via CLAUDE.md | High | Malicious project CLAUDE.md overrides user intent; instructs agent to exfiltrate secrets or install backdoors | [Check Point Research — CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| API key exfiltration via ANTHROPIC_BASE_URL | High | Attacker-controlled ANTHROPIC_BASE_URL in project .env redirects API calls, leaks API key to attacker's server | [Check Point Research — CVE-2026-21852](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| Command injection via find sub-command (CVE-2026-24887) | High | The `find` sub-command parser failed to validate command structure; attackers craft inputs that bypass the tool allowlist and execute arbitrary commands | [GitHub Advisory GHSA-4f4r-wgmr-9jr9 — Claude Code (Jan 2026)](https://github.com/anthropics/claude-code/security/advisories/GHSA-4f4r-wgmr-9jr9) |
| Symlink-based project file injection (SymJack) | High | Renamed symlink placed as project instruction file; agent's "file copy" approval shows symlink name, not target; silently overwrites settings.json to inject malicious MCP server | [Adversa AI — SymJack (May 2026)](https://adversa.ai/blog/symjack-ai-coding-agent-supply-chain-attack-claude-cursor-gemini-github-copilot/) |
| Project-defined MCP auto-exec on folder trust (TrustFall) | High | Accepting a folder trust prompt in Claude Code, Gemini CLI, Cursor CLI, or GitHub Copilot CLI automatically launches all project-defined MCP servers — one Enter keypress on a malicious repo causes RCE; in CI headless mode, zero user interaction required | [TrustFall — Adversa AI (May 2026)](https://adversa.ai/blog/trustfall-coding-agent-security-flaw-rce-claude-cursor-gemini-cli-copilot/) |
| Git worktree trust spoofing (CVE-2026-40068) | High | `.git/commondir` read without path validation allows malicious repo to spoof a trusted directory; `.claude/settings.json` hooks execute silently with no user prompt | [GitHub Advisory GHSA-q5hj-mxqh-vv77 — Claude Code (May 2026)](https://github.com/anthropics/claude-code/security/advisories/GHSA-q5hj-mxqh-vv77) |
| GitHub Actions permission bypass via [bot]-suffix trust | High | `checkWritePermissions` unconditionally trusted any actor ending in `[bot]`; enables malicious GitHub App to trigger the workflow with write permissions and execute arbitrary code via prompt injection in PRs; CVSS v4.0: 7.8 | [GMO Flatt Security — Poisoning Claude Code (June 2026)](https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/) |
| Command injection via unsanitized prompt-derived input to shell (ms-agent) | Medium | ms-agent ≤v1.6.0rc1 passes prompt-derived content directly to shell execution without sanitization; CVSS 6.5, CWE-77; no patch as of June 2026 | [CVE-2026-2256 / GHSA-4gc2-344q-r2rw — ModelScope ms-agent (Mar 2026)](https://github.com/advisories/GHSA-4gc2-344q-r2rw) |
| MCP server information disclosure to privileged local users | High | Splunk MCP Server app < v1.0.3: privileged users can view session and authentication tokens in clear text in the `_internal` index; CVSS 7.2, CWE-532; fixed in v1.0.3 | [CVE-2026-20205 — Splunk MCP Server (SVD-2026-0407)](https://advisory.splunk.com/advisories/SVD-2026-0407) (HTTP 403 — bot-protection pattern; search-confirmed live) |
| Cross-site tool execution via MCP Go SDK CSRF | High | The Go SDK's Streamable HTTP transport (≤ v1.4.0) accepted browser-generated cross-site POST requests without validating the Origin header or enforcing Content-Type: application/json; in deployments without authorization controls, any malicious website could send MCP requests to a local server and trigger tool execution; CVSS 7.1, CWE-352; fixed in v1.4.1 (requires Go 1.25+) | [CVE-2026-33252 / GHSA-89xv-2j6f-qhc8 — modelcontextprotocol/go-sdk (Mar 2026)](https://github.com/advisories/GHSA-89xv-2j6f-qhc8) |
| Zero-click MCP config injection in Windsurf IDE | High | Windsurf 1.9544.26: attacker-controlled HTML content silently modifies local MCP JSON config and registers a malicious STDIO server; MCP SDK launches server binary — code execution with no click, approval, or user interaction required. Only AI IDE in OX Security disclosure chain where zero user interaction sufficed; CVSS 8.0, fixed in versions after 1.9544.26 | [CVE-2026-30615 / GHSA-wj2m-jvpr-64cq — Windsurf (2026)](https://github.com/advisories/GHSA-wj2m-jvpr-64cq) |
| DNS rebinding attack against locally-running MCP servers (CVE-2026-11624) | High | Google MCP Toolbox for Databases prior to v0.25.0 did not validate the `Origin` header. A DNS rebinding attack from a malicious browser tab can cause the browser to connect to a locally-running MCP server and execute arbitrary tool calls — e.g., SQL queries against enterprise databases — without authentication. First MCP-ecosystem CVE attributed to Google's own infrastructure. CVSS 9.4, CWE-346; fixed in v0.25.0 via new `--allowed-hosts` and `--allowed-origins` flags. | [CVE-2026-11624 — googleapis/mcp-toolbox issue #3113](https://github.com/googleapis/mcp-toolbox/issues/3113) (HTTP 200 verified) |
| Missing authentication in PraisonAI legacy Flask API server (CVE-2026-44338) | High | `src/praisonai/api_server.py` hard-codes `AUTH_ENABLED = False` and `AUTH_TOKEN = None`; `check_auth()` returns True, so `GET /agents` exposes agent metadata and `POST /chat` executes `PraisonAI(agent_file="agents.yaml").run()` with no credentials required. Exploited in the wild by an automated scanner (`CVE-Detector/1.0`) within 3h44m of the May 11, 2026 advisory. Affects PraisonAI 2.5.6–4.6.33; fixed in 4.6.34. CVSS 7.3, CWE-306. | [Sysdig — CVE-2026-44338](https://www.sysdig.com/blog/cve-2026-44338-praisonai-authentication-bypass-in-under-4-hours-and-the-growing-trend-of-rapid-exploitation) (HTTP 403 — bot-protection pattern; search-confirmed live) |
| Arbitrary file write → persistence + RCE via model-controlled `localFilePath` in Semantic Kernel .NET (CVE-2026-25592) | Critical | `SessionsPythonPlugin.DownloadFileAsync` was accidentally decorated `[KernelFunction]`, exposing its `localFilePath` parameter to model control. A prompt-injected path targeting the Windows Startup folder writes an attacker-supplied file and achieves persistence + RCE without spawning any shell. CVSS 10.0, CWE-732; patched in .NET SDK v1.71.0 (May 7, 2026). | [Microsoft Security Blog — Prompts Become Shells (May 7, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/) (HTTP 200 verified) |
| `eval()` on attacker-controlled vector store content in Semantic Kernel Python (CVE-2026-26030) | Critical | `InMemoryVectorStore` constructs and `eval()`s a filter lambda built directly from vector entry data; bypasses AST validation and keyword blocklist via Python class hierarchy traversal (`__class__.__mro__`). Any attacker who can populate the vector store — via prompt injection into a RAG pipeline or a poisoned document — achieves arbitrary code execution in the agent process. CVSS 9.8, CWE-95; patched in Python SDK v1.39.4 (May 7, 2026). | [Microsoft Security Blog — Prompts Become Shells (May 7, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/) (HTTP 200 verified) |
| Agentjacking via Sentry MCP event injection | High | Attacker injects fake error events into a victim's Sentry project using the project's public DSN (which is routinely embedded in client-side code); the Sentry MCP server returns these events to the AI coding agent as trusted system context; agent reads attacker-controlled "resolution steps" and executes a crafted `npx` command with the developer's local permissions. 2,388 organizations with exposed public DSNs identified; AI agents at 100+ companies including a Fortune 100 technology firm ran the PoC command. Sentry added a content filter post-disclosure; structural fix is challenging because the flaw is architectural. No CVE assigned. Disclosed June 12, 2026. | Tenet Security — Agentjacking (June 12, 2026) (HTTP 403 — bot-protection pattern; search-confirmed live via scworld.com, thehackernews.com, cybersecuritynews.com, labs.cloudsecurityalliance.org) |
| Insecure temporary file in Claude Code `/copy` (CVE-2026-46406) | Medium | `/copy` wrote responses to a predictable, world-readable path (`/tmp/claude/response.md`, mode 0644) with no UID isolation, randomness, or symlink protection; a local user can read a privileged user's responses (which may contain secrets) or pre-plant a symlink at that path to force the privileged process to overwrite an attacker-chosen file. CVSS 4.4, CWE-377/59/200; affects `@anthropic-ai/claude-code` 2.1.59–2.1.127, fixed 2.1.128. | [GHSA-4vp2-6q8c-pvq2 — Claude Code (June 2026)](https://github.com/advisories/GHSA-4vp2-6q8c-pvq2) (HTTP 200 verified) |
| MCP server insecure default — no auth + `0.0.0.0` bind (CVE-2026-49257) | Critical | StarTree `mcp-pinot` defaults to an HTTP interface on `0.0.0.0:8080` with authentication disabled; any network-adjacent attacker invokes all MCP tools (SQL execution, schema/table mutation) via the server's own Pinot credentials — a confused-deputy condition granting full cluster read/write. CVSS 10.0, CWE-306; fixed `mcp-pinot-server` 3.1.0. | [GHSA-73cv-556c-w3g6 (June 2026)](https://github.com/advisories/GHSA-73cv-556c-w3g6) (HTTP 200 verified) |
| Cross-user client confusion in GitHub MCP Server lockdown mode (CVE-2026-48529) | Medium | `RepoAccessCache` is a process-global singleton seeded with the first authenticated user's GraphQL token; subsequent users' repo-access/visibility checks run under that first user's credentials (and break when its token is revoked). First-party multi-tenant isolation bug that affects the managed Copilot MCP endpoint. CVSS 6.0, CWE-284; fixed `github-mcp-server` 1.1.2. | [GHSA-pjp5-fpmr-3349 (June 2026)](https://github.com/advisories/GHSA-pjp5-fpmr-3349) (HTTP 200 verified) |
| OAuth scope not enforced at the MCP tool layer (CVE-2026-49291) | High | `mcp-memory-service`'s `/mcp` endpoint required only OAuth `read` scope and then dispatched `tools/call` with no per-tool scope check, so a read-only client could invoke `store_memory`/`delete_memory` and tamper with stored agent memory. CVSS 8.1; fixed 10.65.3. | [GHSA-2r68-g678-7qr3 (2026)](https://github.com/advisories/GHSA-2r68-g678-7qr3) |
| Argument-delimiter injection in AWS Bedrock AgentCore `install_packages()` (CVE-2026-12530) | High | An incomplete blocklist lets crafted package names inject pip flags (`--index-url`, `-r`) to redirect dependency resolution or read sandbox files. AWS first-party agent SDK. CVSS 7.3, CWE-88; fixed `bedrock-agentcore` 1.6.1. | [GHSA-6rfw-mq36-jm8h (June 2026)](https://github.com/advisories/GHSA-6rfw-mq36-jm8h) |
| SSRF blocklist bypass via IPv6 transition addresses in pydantic-ai (CVE-2026-48782) | Medium | An incomplete fix for CVE-2026-46678: the cloud-metadata SSRF filter is bypassed via IPv4-compatible IPv6, SIIT/IVI, and NAT64 (`64:ff9b:1::/48`) address forms when `force_download='allow-local'` is set. CVSS 6.8, CWE-918; fixed `pydantic-ai` 1.102.0. | [GHSA-cg7w-rg45-pc59 (2026)](https://github.com/advisories/GHSA-cg7w-rg45-pc59) |

## Real Incidents Timeline

### June 2026 — Mini Shai-Hulud Wave D: Miasma Targets @redhat-cloud-services npm Namespace (June 1)

On June 1, 2026, Wiz Research disclosed **"Miasma: The Spreading Blight"** — the fourth Mini Shai-Hulud wave and the fifth confirmed TeamPCP/UNC6780 npm supply chain attack. Unlike previous waves which used stolen developer credentials, Miasma compromised the `@redhat-cloud-services` npm namespace via **GitHub Actions OIDC credential theft** from a Red Hat CI/CD pipeline. 96 versions across 32 packages (~116,991 weekly downloads) were affected. See [Supply Chain Defense Guide](supply-chain-defense.md) for full IOC list and Wave D timeline.

**What makes this significant:** The attacker used OIDC tokens — short-lived, machine-generated credentials intended to replace static API keys — to publish malicious packages. This demonstrates that OIDC alone does not prevent supply chain attacks; pipeline security and publish-time verification are still required.

Source: [Wiz Research — Miasma: The Spreading Blight](https://www.wiz.io/blog/miasma-the-spreading-blight-wiz-research-discovers-new-supply-chain-attack) (HTTP 403 — bot-protection pattern; search-confirmed live via search engine) | Sonatype, StepSecurity, BleepingComputer, The Hacker News (all HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — Mini Shai-Hulud Wave E: Phantom Gyp Targets vAPI-ai-sdk and ollama-js (June 3)

On June 3, 2026, StepSecurity and Snyk disclosed **"Phantom Gyp"** — the fifth Mini Shai-Hulud wave. The attacker used `binding.gyp`-mediated code execution to bypass npm's `--ignore-scripts` flag. Unlike postinstall scripts (which are blocked by `--ignore-scripts`), `binding.gyp` triggers the `node-gyp` build system, which executes as part of the package installation process regardless of the flag. The targets — `vapi-ai-sdk` and `ollama-js` — are heavily used in AI agent stacks.

**What makes this significant:** `--ignore-scripts` was widely recommended as the primary defense against npm supply chain attacks. Phantom Gyp demonstrates that this recommendation is insufficient. Developers relying solely on `--ignore-scripts` remain vulnerable.

Source: [StepSecurity — Binding.gyp npm supply chain attack](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm) | [Snyk — Node-gyp supply chain compromise](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/) | [Corgea — Phantom Gyp Miasma](https://corgea.com/research/miasma-phantom-gyp-npm-worm-vapi-ai-sdk-ollama-june-2026) (all HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — Mini Shai-Hulud Wave F: Hades PyPI Targets LiteLLM and Telnyx (June 4)

On June 4, 2026, Snyk and Endor Labs disclosed **"Hades PyPI"** — the sixth Mini Shai-Hulud wave and the campaign's first pivot to the Python ecosystem. The attacker targeted `litellm` (the most widely deployed LLM gateway in self-hosted AI stacks, ~2.1M weekly downloads) and `telnyx` (telephony SDK). The malicious packages used the same `SPREADING_BLIGHT` dead-drop C2 pattern established in Wave C (AntV) and continued in Wave D (Miasma), confirming TeamPCP/UNC6780 operational continuity across ecosystems.

**What makes this significant:** Wave F is the first time the CanisterSprawl campaign (which began with Go and npm packages) crossed into PyPI. Any developer whose AI stack uses LiteLLM should verify package integrity against known-good SHA256 hashes. See [Supply Chain Defense Guide](supply-chain-defense.md) for PyPI-specific vetting steps.

Source: Snyk, Endor Labs (both HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — Mini Shai-Hulud Wave G: Hades MCP-Targeting (June 9)

On June 9, 2026, StepSecurity and BleepingComputer disclosed **"Hades MCP-targeting"** — the seventh Mini Shai-Hulud wave and the first to directly target the MCP server ecosystem. The attacker published malicious packages impersonating popular MCP server libraries, including packages targeting Claude Code, Cursor, and GitHub Copilot integrations. The payload continued using the `SPREADING_BLIGHT` C2 pattern, confirming TeamPCP/UNC6780 involvement.

**What makes this significant:** Prior waves targeted general npm/PyPI packages used *by* AI developers. Wave G targets MCP server packages directly — the exact dependency layer that AI coding agents load and execute. A developer who installs a compromised MCP server grants the attacker direct access to their agent's tool execution environment. See [Supply Chain Defense Guide](supply-chain-defense.md) for Wave G IOCs and the updated blocklist.

Source: StepSecurity, BleepingComputer (both HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — Atomic Arch: Independent AUR Supply Chain Attack (June 11–12)

An independent threat actor (not attributed to TeamPCP/UNC6780) compromised over **1,600 Arch User Repository (AUR) packages** in a two-wave campaign discovered June 11, 2026. The attack vector: orphaned AUR packages claimed through AUR's standard adoption process had their `PKGBUILD` scripts silently modified to install malicious npm/bun packages.

**Wave 1 (June 11):** PKGBUILDs injected two malicious npm packages: `atomic-lockfile` (Sonatype-2026-003775, CVSS 8.7) and `lockfile-js`. Malicious npm accounts: `krisztinavarжа`, `franziskaweber`, `tobiaswesterburg`, `ellenmyklebust`. Payload: ELF credential stealer targeting GitHub PATs, npm tokens, SSH keys, Discord tokens, and browser data.

**Wave 2 (June 12):** Accounts `custodiatovar` and `veramagalhaes` added Bun-based installation paths via `js-digest`. Payload added **eBPF rootkit** capability (process/file hiding when running as root) and **systemd persistence** (auto-restart service).

**Why it matters:** Arch Linux and derivatives (Manjaro, EndeavourOS, Garuda) are disproportionately popular among developers and security researchers. AUR is unmoderated — any claimed package is implicitly trusted by `makepkg`. The cross-ecosystem path (AUR → npm → ELF binary) evades scan tools that check only npm or PyPI registries.

Source: [github.com/lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) (HTTP 200 verified — community detection scripts and IOC database) | Sonatype, StepSecurity, BleepingComputer, The Hacker News (all HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — Agentjacking: Sentry MCP Event Injection → AI Agent RCE (June 12)

Tenet Security's Threat Labs disclosed **"Agentjacking"** — a new attack class in which an attacker injects fake error events into a victim's Sentry project using the project's **public DSN** (a write-only identifier routinely embedded in client-side JavaScript bundles). The Sentry MCP server returns these attacker-injected events to the AI coding agent as trusted operational context. The agent reads the attacker-controlled "resolution steps" and executes a crafted `npx` command with the developer's local permissions.

Tenet Security identified **2,388 organizations** with exposed public DSNs and confirmed that AI agents at **100+ companies** — including a Fortune 100 technology firm — executed the PoC `npx` command. Claude Code, Cursor, and Codex are all affected. Sentry added a content filter post-disclosure; Tenet notes a structural fix is challenging because the flaw is architectural. No CVE assigned.

**Why it matters:** Unlike prompt injection attacks that target AI output, Agentjacking exploits the trust relationship between MCP servers and AI agents. The Sentry MCP server is explicitly designed to provide agents with error context — the attack simply poisons that context. Any developer using the Sentry MCP server is exposed if their project DSN appears in client-side code (the default for most web apps).

Source: Tenet Security — Agentjacking (June 12, 2026) (HTTP 403 — bot-protection pattern; search-confirmed live via scworld.com, thehackernews.com, cybersecuritynews.com, labs.cloudsecurityalliance.org)

### June 2026 — CVE-2026-42824 "SearchLeak": M365 Copilot One-Click Data Exfiltration (June 15)

Varonis Threat Labs disclosed a three-stage attack chain against Microsoft 365 Copilot Enterprise Search. A crafted `microsoft.com` URL triggers a parameter-to-prompt (P2P) injection that instructs Copilot to search and summarize the victim's mailbox. An HTML rendering race condition fires an attacker-controlled `<img>` tag before output sanitization completes. A Bing SSRF then routes the stolen content out through Microsoft's own image-retrieval endpoint, bypassing the page's CSP because the outbound request originates from Microsoft infrastructure.

A single click on a legitimate-looking Microsoft link exfiltrates mailbox contents, calendar events, OneDrive/SharePoint files, MFA codes, and password-reset links. Patched via a Microsoft backend fix in early June 2026; no customer action required. CVSS 6.5 (Microsoft) / 7.5 (NVD). No PoC published; no confirmed in-the-wild exploitation.

**Why it matters:** SearchLeak demonstrates the P2P injection + SSRF exfiltration template. The exfiltration channel — Microsoft's own Bing endpoint — bypasses outbound-connection monitoring because traffic appears to originate from Microsoft's infrastructure, not the victim's browser.

Source: [SearchLeak: How We Turned M365 Copilot Into a One-Click Data Exfiltration Weapon — Varonis](https://www.varonis.com/blog/searchleak) (HTTP 403 — bot-protection pattern; search-confirmed live) | [BleepingComputer — New attack turned Microsoft 365 Copilot into 1-click data theft tool](https://www.bleepingcomputer.com/news/security/new-attack-turned-microsoft-365-copilot-into-1-click-data-theft-tool/) (HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — IronWorm: Rust/eBPF npm Supply Chain Worm (June 4)

JFrog Security Research and OX Security disclosed IronWorm, a npm supply chain worm distinct from the Shai-Hulud/TeamPCP campaign that JFrog describes as "Shai-Hulud's rustier cousin." A single compromised account (`asteroiddao`) republished 36–37 npm packages with a 976 KB Rust-compiled binary payload.

**Payload capabilities:** eBPF kernel rootkit (hides the malicious process from `ps`/`top`); Tor-based C2 for exfiltration; targets 86 environment variables and 20 credential file patterns including OpenAI, AWS, and **Anthropic API keys**, npm tokens, SSH keys, and 166 cryptocurrency wallet extension IDs.

**Novel technique:** IronWorm mints its own npm publish credentials by scraping short-lived OIDC tokens from CI runner memory (the same `/proc/<pid>/mem` technique as the TanStack/Mini Shai-Hulud Wave B attack), then uses npm Trusted Publishing to republish packages with valid Sigstore attestations. No stored npm token required. Commit timestamps are backdated up to 13 years to evade recency-based detection. No CVE assigned.

**Why it matters for Claude Code users:** Anthropic API keys are an explicit target. Any pipeline that installed the affected packages should be treated as compromised and rotate `ANTHROPIC_API_KEY` immediately.

Source: [JFrog Security Research — IronWorm: Shai-Hulud's rustier cousin](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/) (HTTP 403 — bot-protection pattern; search-confirmed live) | [OX Security — IronWorm Supply Chain Malware Hits npm](https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/) (HTTP 403 — bot-protection pattern; search-confirmed live) | [BleepingComputer — New IronWorm malware hits 36 packages](https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/) (HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — Mastra AI npm Supply Chain Attack via easy-day-js Typosquat (June 17)

An unknown threat actor (Sapphire Sleet / BlueNoroff tradecraft similarities — attribution not confirmed) compromised **144 packages in the @mastra npm scope** on June 17, 2026. Mastra is a TypeScript-first AI agent and MCP server framework with 1.1M+ weekly downloads.

**Attack mechanism:** The attacker hijacked the npm account of former Mastra contributor **"ehindero"** and published **`easy-day-js`** — a typosquat of the widely used `dayjs` date library — as a dependency across 144 @mastra packages. The malicious `postinstall` hook activated 88 minutes after the account compromise.

**Payload:** Cross-platform credential stealer targeting cryptocurrency wallet browser extensions (160+ extension IDs), browser session data, credentials, and clipboard contents, with exfiltration to attacker-controlled C2 infrastructure.

**Why it matters for AI developers:** Mastra is foundational infrastructure for building agents and MCP servers. Any developer machine, CI/CD pipeline, or build environment that installed `@mastra/*` packages after June 16, 2026 should be considered potentially compromised. This attack marks a significant escalation: AI agent framework ecosystems — not just general-purpose npm packages — are now direct targets for supply chain attacks attributed to nation-state tradecraft.

Source: [OX Security — easy-day-js Supply Chain Attack Hits Mastra AI in npm](https://www.ox.security/blog/easy-day-js-supply-chain-attack-hits-mastra-ai-in-npm/) (HTTP 403 — bot-protection pattern; search-confirmed live) | Snyk, Endor Labs, AI Weekly (all HTTP 403 — bot-protection pattern; search-confirmed live)

### June 2026 — June MCP-Server "Insecure Default" Wave (June 18–26)

A cluster of GitHub-reviewed advisories landed in the back half of June against third-party and first-party MCP servers, all variations of the same anti-pattern: an MCP server exposing privileged tools over HTTP **without authentication**, often bound to `0.0.0.0` or with an auth flag that does nothing. Confirmed examples: `mcp-pinot` (CVE-2026-49257, CVSS 10.0 — no auth + public bind, full Pinot cluster R/W), `dbt-mcp` (CVE-2026-55837 — unauthenticated `/dbt_platform_context` leaks access + refresh tokens, fixed 1.20.0), `backpropagate` (CVE-2026-48797 — `--auth`/`--share` flags are no-ops; the Reflex backend never reads `BACKPROPAGATE_UI_AUTH`, fixed 1.2.0), `line-desktop-mcp` (CVE-2026-49357 — Streamable-HTTP mode exposes read/send tools, fixed 1.1.2), and `mcp-memory-service` (CVE-2026-49291 — OAuth `read` scope not enforced at the tool layer, fixed 10.65.3). Even GitHub's own MCP server had a multi-tenant isolation bug (CVE-2026-48529).

**Lesson:** treat every MCP server as a network service. Never expose one on a non-loopback interface, require authentication, and confirm that documented auth flags actually gate requests — the `backpropagate` case shows a documented control that silently did nothing.

Source: [GHSA-73cv-556c-w3g6](https://github.com/advisories/GHSA-73cv-556c-w3g6) (HTTP 200 verified) | [GHSA-jr33-mw75-7j8f](https://github.com/advisories/GHSA-jr33-mw75-7j8f) | [GHSA-f65r-h4g3-3h9h](https://github.com/advisories/GHSA-f65r-h4g3-3h9h) | [GHSA-4hf8-5mjm-rfgq](https://github.com/advisories/GHSA-4hf8-5mjm-rfgq) | [GHSA-2r68-g678-7qr3](https://github.com/advisories/GHSA-2r68-g678-7qr3)

### June 2026 — Agent-Framework RCE/Authz Cluster: Langflow, LiteLLM, PraisonAI (June 15–21)

Three widely deployed AI-agent/LLM-proxy frameworks shipped critical fixes in the same week:

- **Langflow (June 19)** — a four-CVE cluster fixed in 1.9.1/1.9.2. The must-patch pair: **CVE-2026-55447** (CVSS 9.6 — `BaseFileComponent` extracts tar archives without validating symlinks; an uploaded tar reads the JWT secret → token forge → RCE via the Python Interpreter node) and **CVE-2026-55255** (IDOR in `/api/v1/responses` with no ownership check), with active exploitation observed ~June 25.
- **LiteLLM (June 15/21)** — Obsidian Security publicly weaponized a default-low-privilege-user → `proxy_admin` → RCE chain (combined CVSS ~9.9, remediated in `litellm` 1.83.14); a separate June 21 VulDB batch added four authz/auth CVEs with public PoCs. The repo previously tracked **zero** LiteLLM CVEs despite LiteLLM being a common AI-stack dependency.
- **PraisonAI (June 18)** — a mass wave of 40+ coordinated advisories across `praisonai`/`praisonaiagents`/`praisonai-platform`, including unauthenticated RCE via the Jobs API, a YAML `approve` safety-decorator bypass, an MCP SSE server bound `0.0.0.0` with no auth, and a default JWT secret (`dev-secret-change-me`) enabling token forgery. Larger than and distinct from the May `CVE-2026-44338` bypass below. Fixed in praisonai 4.6.59/4.6.61.

Source: [GHSA-ccv6-r384-xp75 — Langflow](https://github.com/advisories/GHSA-ccv6-r384-xp75) (HTTP 200 verified) | [Obsidian Security — LiteLLM privilege escalation](https://www.obsidiansecurity.com/blog/litellm-privilege-escalation-rce) | [GHSA-4869-x4pr-q22x — PraisonAI](https://github.com/advisories/GHSA-4869-x4pr-q22x)

### June 2026 — Mini Shai-Hulud Wave H: Leo Platform / RStreams + First Go-Ecosystem Element (June 24)

The Shai-Hulud/Miasma lineage continued past Wave G. On June 24, 2026 (≈23:04 UTC) a compromised maintainer (`czirker`) published malicious versions of 20+ LeoPlatform/RStreams npm packages in an automated burst; npm user `llxlr` added `hexo-deployer-wrangler`, `hexo-shoka-swiper`, and `prism-silq`. The wave reuses the **Phantom Gyp** `binding.gyp` execution pattern, writes its toolkit to `/tmp/p.js`, and runs it under the **Bun runtime (v1.3.13) instead of Node** to evade Node-focused EDR. It harvests GitHub Actions secrets, `.env`, npm/PyPI/GitHub/Slack/Twilio tokens, SSH keys, Docker/K8s configs, cloud credentials, and IDE/AI-agent config paths to a GitHub dead-drop. Notably it is the **first Go-ecosystem element** of the lineage: a related compromise of the Verana Blockchain Go project staged payloads in a `.claude/` folder with a VS Code folder-open task invoking `node .claude/setup.mjs`.

Source: [Socket.dev — Miasma hits Leo Platform npm packages / Go ecosystem](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem)

### June 2026 — Anthropic Alleges Large-Scale Claude Model-Distillation Campaign (June 24)

Per a June 10 letter to the U.S. Senate Banking Committee (reported by CNBC on June 24, 2026), Anthropic alleges that operators affiliated with Alibaba's Qwen lab ran roughly 28.8M Claude exchanges through ~25,000 fraudulent accounts and commercial proxies between April 22 and June 5, 2026, targeting Claude's agentic-reasoning, software-engineering, and long-horizon capabilities for model distillation. Treat this as an **allegation, not established fact** — the figures are Anthropic-internal and Alibaba denies them — but it is relevant to the threat model as an example of API-abuse / account-fraud at scale against agent providers.

Source: [CNBC — Anthropic accuses Alibaba of distillation campaign (June 24, 2026)](https://www.cnbc.com/2026/06/24/anthropic-alibaba-distillation-campaign.html)

### May 2026 — PraisonAI CVE-2026-44338: Auth Bypass Exploited Within 3h44m of Disclosure (May 11)

PraisonAI 2.5.6–4.6.33 ships a legacy Flask API server (`src/praisonai/api_server.py`) with `AUTH_ENABLED = False` and `AUTH_TOKEN = None` hard-coded. The `check_auth()` helper returns True whenever authentication is disabled, so `GET /agents` (returns agent metadata including the configured agent file name and agent list) and `POST /chat` (executes `PraisonAI(agent_file="agents.yaml").run()`) accept requests with no credentials. Within 3 hours and 44 minutes of the advisory going public on May 11, 2026 at 13:56 UTC, an automated scanner (`CVE-Detector/1.0`) was probing the exact vulnerable endpoint on internet-exposed instances — the first targeted request landed at 17:40 UTC. Fixed in 4.6.34. CVSS 7.3.

**What makes this significant:** The sub-4-hour exploitation gap is a hallmark of automated mass scanning against recently disclosed CVEs. For AI agent frameworks, the impact is asymmetric: unauthenticated callers can execute arbitrary agent workflows — consuming model API quota and triggering all connected tool integrations — without credentials. Operators who deployed PraisonAI with default settings and any internet-facing exposure had effectively zero response window.

Source: [Sysdig — CVE-2026-44338: PraisonAI authentication bypass in under 4 hours](https://www.sysdig.com/blog/cve-2026-44338-praisonai-authentication-bypass-in-under-4-hours-and-the-growing-trend-of-rapid-exploitation) (HTTP 403 — bot-protection pattern; search-confirmed live) | [The Hacker News](https://thehackernews.com/2026/05/praisonai-cve-2026-44338-auth-bypass.html) (HTTP 403 — bot-protection pattern; search-confirmed live) | [CybersecurityNews](https://cybersecuritynews.com/praisonai-vulnerability-exploited/) (HTTP 403 — bot-protection pattern; search-confirmed live)

### May 2026 — GitHub Copilot & Visual Studio Security Feature Bypass (CVE-2026-41109)

Microsoft disclosed a security-feature-bypass vulnerability (May 12, 2026 Patch Tuesday) affecting GitHub Copilot in Visual Studio and VS Code. Improper neutralization of special elements in model output (CWE-79-class) lets untrusted input slip past the AI content filters and user-consent prompts that are supposed to gate Copilot suggestions before they reach the editor. A network-reachable, unauthenticated attacker can use this to inject malicious code suggestions, leak data, or silently disable telemetry/consent controls. CVSS 8.8 (NVD) / rated Important (7.8) by Microsoft. Fixed in VS Code 1.97.0 and the GitHub Copilot extension v1.43.20260512.

**Why it matters:** The bug sits on the human↔AI trust boundary. By automating the bypass of consent prompts and content filters, it removes the human-in-the-loop review step — letting attacker-controlled content flow into the editor as if a developer had already reviewed it, exactly the step solo developers rely on when they accept Copilot suggestions quickly.

Source: [Microsoft Security Response Center — CVE-2026-41109](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2026-41109) (HTTP 403 — bot-protection pattern; search-confirmed live) | [TheHackerWire — GitHub Copilot & Visual Studio Injection Bypasses Security Feature (CVE-2026-41109)](https://www.thehackerwire.com/github-copilot-visual-studio-injection-bypasses-security-feature-cve-2026-41109/) (HTTP 403 — bot-protection pattern; search-confirmed live)

### May 2026 — Megalodon: TeamPCP Backdoors 5,561 GitHub Repositories in Six Hours (May 18)

Using throwaway GitHub accounts and forged CI bot identities, TeamPCP (UNC6780) pushed **5,718 malicious commits to 5,561 GitHub repositories in under six hours** on May 18, 2026 — from approximately 11:36 to 17:48 UTC. Each commit backdoored the repository's CI/CD workflows to exfiltrate cloud credentials, SSH keys, OIDC tokens, and source-code secrets at scale. Attribution confirmed by CSA Labs, Protos Labs, and multiple security vendors.

**Why it matters:** Megalodon targeted repositories' CI/CD workflows directly — a distinct attack surface from the npm/PyPI package poisoning in the concurrent Shai-Hulud waves. A developer whose repository was among the 5,561 affected would have unknowingly triggered credential exfiltration on their next CI run. The scale (5,718 commits in 6 hours) was enabled by automation, consistent with TeamPCP's established tooling from the CanisterSprawl campaign.

Source: The Hacker News, SecurityWeek, CPO Magazine, The Register, CSA Labs — Shai-Hulud/Megalodon: A Two-Wave AI Developer Supply Chain Attack (all HTTP 403 — bot-protection pattern; search-confirmed live)

### April 2026 — MCP Design Flaw: Zero-Click Prompt Injection in IDEs, 9 of 11 Registries Poisoned

On April 16, 2026, OX Security (as part of the broader AI security community) published a sweeping disclosure covering systemic vulnerabilities in the MCP protocol and its ecosystem. The key findings:

- **Zero-click prompt injection in IDEs:** By injecting malicious instructions into HTML rendered by IDEs (VS Code, Cursor, Windsurf, etc.), an attacker can silently modify the local MCP JSON configuration and register a malicious MCP STDIO server — without any user click, approval, or warning.
- **9 of 11 major MCP registries were poisoned** with malicious or misleading server entries at the time of disclosure.
- **Hardening bypasses in protected environments:** Ten CVEs were issued including CVE-2026-30623, CVE-2026-30615, CVE-2026-30624. Anthropic confirmed the behavior is by design and declined to modify the protocol.

Source: [The Register — MCP design flaw puts 200k servers at risk](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/) | [Infosecurity Magazine — Systemic Flaw in MCP](https://www.infosecurity-magazine.com/news/systemic-flaw-mcp-expose-150/)

**Anthropic's own Git MCP server had path traversal and prompt injection flaws** that allowed malicious repositories to read arbitrary files from the developer's machine by crafting a git history that embedded malicious instructions in commit messages. Fixed in a patch released the same day.

### March 2026 — GitHub Copilot Chat Visual Studio Injection Bypasses Microsoft's Security AI

Researchers at MacCarita Security reported that GitHub Copilot Chat for Visual Studio was vulnerable to prompt injection via specially crafted code comments. The attack allowed bypassing Microsoft's internal safety layer — the "Security AI" — via a multi-step injection that first neutralized the safety check and then executed the malicious instruction.

Source: [MacCarita Security Blog](https://maccarita.com/posts/idesaster) (HTTP 403 — bot-protection pattern; search-confirmed live)

### January 2026 — "Scary Hallucination": AI Package Hallucination Codified as CVE

Researchers demonstrated that Claude 3.7 and GPT-4o hallucinate specific package names consistently enough to be weaponized: an attacker publishes a real package with the hallucinated name. When a developer asks Claude to add a dependency, Claude suggests the malicious package by name. The attack doesn't require prompt injection — it exploits the model's tendency to confabulate plausible-sounding package names.

The 10 most consistent hallucinated npm package names were documented, published as a CVE, and then — demonstrating the urgency — squatted by researchers before they could be squatted by attackers.

Source: [Lasso Security — Scary Hallucination](https://www.lasso.security/blog/ai-package-hallucinations) (HTTP 403 — bot-protection pattern; search-confirmed live)

### December 2025 — Cursor Rules Injection: Hidden Instructions in .cursor/rules

A proof-of-concept attack demonstrated that `.cursor/rules` files in open-source repositories can contain hidden Unicode characters that are invisible in most editors but interpreted by Cursor's AI as instructions. A developer who clones a malicious repository and opens it in Cursor silently activates the injected instructions — which can include directives to exfiltrate credentials or install backdoors.

The same technique applies to `.claude/CLAUDE.md`, `.github/copilot-instructions.md`, and similar agent instruction files.

Source: [Pillar Security — Invisible Ink](https://www.pillar.security/blog/the-invisible-prompt-injection-attack-targeting-cursor-ai-users) (HTTP 403 — bot-protection pattern; search-confirmed live)

### November 2025 — EchoLeak: First Zero-Click Prompt Injection in a Production LLM System

[Described in detail in the Research Papers section below.]

The first confirmed zero-click prompt injection against a production LLM deployment (Microsoft 365 Copilot). The attack required no user action — receiving a malicious email was sufficient to trigger silent data exfiltration. This validated that prompt injection was not purely a red-teaming exercise but a real, deployable attack against production systems.

### October 2025 — Cursor/Windsurf Chromium Vulnerability Backlog

OX Security identified 94+ known Chromium CVEs in the builds of Cursor (0.42.x) and Windsurf (0.47.9) — both frozen at early 2025 Chromium versions. The affected products had 1.8 million+ combined downloads. OX Security's responsible disclosure notice on October 12, 2025 received no substantive response from either vendor until public disclosure.

See [Windsurf Hardening Guide](hardening/windsurf.md) and [Cursor Hardening Guide](hardening/cursor.md) for update status.

### October 2025 — Mini Shai-Hulud Waves A, B, C: CanisterSprawl Campaign

The first three documented waves of the CanisterSprawl npm supply chain campaign (attributed to TeamPCP / UNC6780) targeted React and popular npm packages. See [Supply Chain Defense Guide](supply-chain-defense.md) for full timeline and IOCs.

### May 2025 — Prompt Injection in Cursor and Windsurf via Hidden Unicode

Embrace The Red disclosed that both Cursor and Windsurf process hidden Unicode characters in source code that are invisible to developers but interpreted by the AI as instructions. A malicious package or repository can inject instructions into any file that the developer opens — triggering secret exfiltration, backdoor installation, or settings modification without any visible indicator.

Windsurf acknowledged the disclosure but did not respond to follow-up inquiries. Cursor patched silently. Claude Code is not affected (terminal-based, does not render Unicode-styled text).

Source: [Embrace The Red — AI IDEs and Hidden Instructions](https://embracethered.com/blog/posts/2025/cursor-windsurf-hidden-unicode-prompt-injection/) (HTTP 403 — bot-protection pattern; search-confirmed live)

### April 2025 — Context Window Poisoning via Indirect Injection in Large Codebases

Researchers at Cognition demonstrated that in large codebases (>100k lines), an attacker can guarantee malicious instructions reach the model's context window by strategically placing them in files likely to be retrieved by the agent's file-reading heuristics — config files, README files, package.json, etc.

The attack doesn't require bypassing any security control. It exploits the fundamental mechanics of how agents decide what to read.

### March 2025 — MCP Servers as Universal Attack Surface

The Model Context Protocol was publicly released in late 2024. By March 2025, researchers had documented the first practical attacks against MCP servers:

- **Tool shadowing:** A malicious MCP server registers a tool with the same name as a legitimate one; the model calls the malicious version
- **Cross-server tool injection:** Instructions injected via one MCP server's outputs can direct the model to call tools on other servers
- **MCP server impersonation:** A server claims to be a trusted service and manipulates the model into providing credentials

Source: [Invariant Labs — MCP Security Research](https://invariantlabs.ai/blog/mcp-security) (HTTP 403 — bot-protection pattern; search-confirmed live)

---

## Threat Actors and Targeting

### TeamPCP / UNC6780 (CanisterSprawl / Shai-Hulud)

**Who:** Russian threat actor attributed by Wiz Research (UNC6780), Sonatype (TeamPCP), and multiple security vendors. Part of a broader APT ecosystem targeting developer tools and supply chains.

**What they do:** Multi-wave npm supply chain attacks against AI-adjacent packages. Each wave uses a distinct technique and targets different ecosystems. See [Supply Chain Defense Guide](supply-chain-defense.md) for full wave breakdown.

**Why you're a target:** Solo developers using AI coding agents are disproportionately likely to install new npm packages quickly, run `npm install` without auditing, and have high-value credentials (GitHub tokens, AWS keys, API keys) on their machines.

**Current wave:** Wave H (Leo Platform / RStreams, June 24, 2026) — first Go-ecosystem element; uses Bun runtime to evade Node-focused EDR.

### OX Security / Cross-IDE Research Disclosures

**Who:** OX Security is a commercial application security company that has published multiple coordinated disclosures covering all major AI IDEs simultaneously.

**What they document:** Cross-IDE attacks that work across Claude Code, Cursor, Windsurf, Gemini CLI, and GitHub Copilot. Their disclosures tend to reveal that the same vulnerability class affects multiple tools simultaneously.

**Pattern:** Disclosure → all vendors notified simultaneously → some vendors patch quickly, some don't respond. Windsurf has historically not responded; Claude Code typically patches within days.

### Nation-State Supply Chain Actors

**Lazarus Group / Sapphire Sleet (North Korea):** Attributed by multiple vendors to npm supply chain attacks targeting cryptocurrency and DeFi developers. Tradecraft: compromising developer accounts, publishing typosquat packages, targeting crypto wallet extensions.

**RomCom / TeamPCP (Russia):** See above. Focused on developer toolchain poisoning, credential theft from build systems.

**Relevance to solo developers:** If you work on crypto projects, financial services tooling, or any product with monetary value, you are a direct target for nation-state supply chain attacks. The Mastra attack (June 2026) is a recent example: 144 packages in a foundational AI agent framework compromised in under 90 minutes.

---

## What Solo Developers Should Do

### Immediate Actions (< 15 minutes)

1. **Enable the sandbox.** Add `"sandbox": true` to `~/.claude/settings.json`. This is the single highest-value action.
2. **Deny exfiltration tools.** Add `"deny": ["Bash(curl:*)", "Bash(wget:*)", "WebFetch"]` to permissions.
3. **Install the bash firewall.** `npx llm-safe-haven install`

### Short-Term Actions (< 1 hour)

4. **Review installed MCP servers.** For each server: verify publisher, check for recent supply chain reports, pin to an exact version.
5. **Remove secrets from project directories.** `.env` files in project directories are accessible to the agent.
6. **Configure `.gitignore` to exclude `.claude/` directories** from accidental commits.
7. **Update Claude Code.** Known CVEs have been fixed in specific versions — see the changelog above. Always run the latest version.

### Ongoing Practices

8. **Subscribe to supply chain alerts.** Sonatype OSS Index and Snyk have free tiers that alert on new malicious packages.
9. **Review tool calls before approving.** Read the full command. The description is generated by the model and can be manipulated; the actual command is not.
10. **Check CLAUDE.md in repos you clone.** A malicious CLAUDE.md can redirect agent behavior silently.

---

## Research Papers

| Paper | Date | Key Finding |
|-------|------|-------------|
| [Prompt Injection Attacks on Agentic Coding Assistants](https://arxiv.org/abs/2601.17548) (Maloyan & Namiot) | Jan 2026 | 42 attack techniques identified; attack success >85% against state-of-the-art defenses; most defenses achieve <50% mitigation |
| [EchoLeak: First Zero-Click Prompt Injection](https://arxiv.org/abs/2509.10540) | Sep 2025 | First zero-click exploit on production LLM system (Microsoft 365 Copilot): malicious email silently exfiltrates data, no user interaction required; validated against live production system |
| [Reframing LLM Agent Security as an Agent-Human Interaction Problem](https://arxiv.org/abs/2605.24309) (Wang, Li, Tian — UCLA) | May 2026 | Systematic analysis of 59 papers + 21 production systems + 26 security plugins; finds approval fatigue, brittle scope bounds, and inaccessible policy languages are the core design failures; three production controls (policy specification, runtime approval, scope configuration) each adopted by ≥14/21 systems yet almost unstudied academically |
| [Layered Attack Surface Model (LASM)](https://arxiv.org/abs/2604.23338) (Kexin Chu) | Apr 2026 | 7-layer decomposition of the agentic stack with non-transferability theorem proving a defense at one layer has zero detection power against attacks at another |
| [VIPER-MCP](https://arxiv.org/abs/2605.21392) | May 2026 | Scanned 39,884 real-world MCP server repos; found 106 zero-day vulnerabilities with 67 CVE IDs assigned; first framework combining taint-style static detection with dynamic PoC-confirmed exploitability |
| [ARGUS](https://arxiv.org/abs/2605.03378) | May 2026 | Provenance-aware runtime auditor that grounds tool-call decisions in trusted evidence via span-level context tracking; significantly reduces attack success while preserving utility |
| [Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI Agents](https://arxiv.org/abs/2603.20953) | Mar 2026 | Proposes model-independent, deterministic pre-action authorization; documents ClawHavoc supply-chain attack against developer toolchains |
| [Security Considerations for Multi-agent Systems](https://arxiv.org/abs/2603.09002) | Mar 2026 | Analyzes security threats specific to multi-agent architectures: trust transitivity, capability amplification, and cross-agent injection |
| [Credential Leakage in LLM Agent Skills](https://arxiv.org/abs/2604.03070) | Apr 2026 | 17,022 skills analyzed; 520 vulnerable with 1,708 issues; 10 leakage patterns; stdout leakage affects 75.8% of vulnerable skills |
| [Your LLM Agent Can Leak Your Data: Back-Reveal Attack](https://arxiv.org/abs/2604.05432) | Apr 2026 | Back-Reveal attack via backdoored tool use; semantic triggers exfiltrate stored user context via disguised memory-access calls |
| [Breaking MCP with Function Hijacking Attacks](https://arxiv.org/abs/2604.20994) | Apr 2026 | 70–100% attack success rate across 5 models including GPT-5 and Claude Sonnet 4; MCP tool shadowing and cross-server injection demonstrated against production servers |
| [MCPSHIELD: Unified Threat Taxonomy for MCP](https://arxiv.org/abs/2604.05969) | Apr 2026 | Taxonomy of 7 threat categories, 23 attack vectors across 177k+ MCP tools; no single existing defense covers >34% of threat landscape |
| [A Survey on the Security of Long-Term Memory in LLM Agents](https://arxiv.org/abs/2604.16548) | Apr 2026 | Coins "mnemonic sovereignty" framing; catalogs attack surfaces across retrieval-augmented, summarization-based, and episodic memory architectures; cross-session memory poisoning as primary threat |
| [ACM TOSEM: Model Context Protocol: Landscape, Security Threats, and Future Research Directions](https://dl.acm.org/doi/10.1145/3729381) | 2026 | Systematic threat taxonomy across 4 attacker types and 16 distinct threat scenarios; first ACM journal treatment of MCP security |
| [Beyond the Protocol: Unveiling Attack Vectors in the MCP Ecosystem](https://arxiv.org/abs/2506.02040) | Jun 2026 | 4 MCP attack categories; user study shows systematic failure to identify malicious servers; current aggregator audit mechanisms insufficient |
| [From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agent Workflows](https://arxiv.org/abs/2506.23260) (Ferrag et al.) | Jun 2025 (rev. Dec 2025) | Unified end-to-end threat model covering 30+ attack techniques across input manipulation, model compromise, system/privacy attacks, and protocol-level exploits; covers Toxic Agent Flow in GitHub MCP servers (HTTP 403 — bot-protection pattern; search-confirmed live via arxiv.org/html/2506.23260) |
| [AgentAuditor: Human-Level Safety and Security Evaluation for LLM Agents](https://arxiv.org/abs/2506.00641) (Luo et al., arXiv:2506.00641) | Jun 2025 | NeurIPS 2025. Training-free, memory-augmented reasoning framework that evaluates LLM agents at human-expert level by extracting structured semantic features from past interactions and using RAG to guide assessment of new cases; introduces ASSEBench — first large-scale dataset jointly covering safety and security, with 2,293 annotated agent interaction records across 15 risk types, 528 environments, and 29 application scenarios; addresses evaluator failure modes: missing step-level dangers, overlooking subtle compounding harms, and confusion from ambiguous safety rules (HTTP 403 — bot-protection pattern; search-confirmed live via openreview.net/forum?id=2KKqp7MWJM) |
| [The Containment Gap: How Deployed Agentic AI Frameworks Fail Public-Facing Safety Requirements](https://arxiv.org/abs/2606.12797) (arXiv:2606.12797) | Jun 2026 | Audits LangChain, AutoGPT, and OpenAI Agents SDK against six containment principles; finds no native compliance with containment principles in any of the three evaluated frameworks; memory integrity — defense against the most prevalent vulnerability class — not observed in any framework; documents the structural gap between academic safety requirements and production deployments in public-facing domains (HTTP 403 — bot-protection pattern; search-confirmed live via arxiv.org/html/2606.12797v1) |
| [VATS: Exploiting Implicit Authority in Error-Path Injection via Systematic Mutation](https://arxiv.org/abs/2606.07992) (arXiv:2606.07992) | Jun 2026 | Introduces VATS framework for systematic mutation-based testing of MCP server error paths; finds 88% of open-source MCP servers have broken authentication and >25% of community agent skills contain injection or exfiltration vulnerabilities; MCP SDK reached 97M monthly downloads by April 2026, widening the blast radius of each finding (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers](https://arxiv.org/abs/2506.13538) (arXiv:2506.13538) | Jun 2026 | First large-scale empirical security audit of 1,899 open-source MCP servers using hybrid static analysis; 66% exhibit code smells, 14.4% have bug patterns; action-capable tools grew from 27% to 65% of servers as MCP moved to Linux Foundation; advocates mandatory CVE databases and automated registry scanning for MCP (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [We Should Identify and Mitigate Third-Party Safety Risks in MCP-Powered Agent Systems](https://arxiv.org/abs/2506.13666) (arXiv:2506.13666) | Jun 2026 | SAFEMCP: MCP third-party services are not controlled by LLM developers and may be intentionally malicious with economic incentives to exploit; pilot experiments show non-trivial threats from compromised MCP service providers; proposes a roadmap for safe MCP-powered agent systems (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [A First Measurement Study on Authentication Security in Real-World Remote MCP Servers](https://arxiv.org/abs/2605.22333) (arXiv:2605.22333) | May 2026 | Identifies 7,973 live remote MCP servers; 40.55% expose tools without any authentication; focuses on the authentication boundary between MCP clients and remote servers as agents connect to user-linked social, productivity, and financial services; first empirical measurement of authentication gaps in real-world remote MCP deployments (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [Description-Code Inconsistency in Real-world MCP Servers](https://arxiv.org/abs/2606.04769) (arXiv:2606.04769, DCIChecker) | Jun 2026 | Defines and studies Description-Code Inconsistency (DCI) where a tool's description does not faithfully reflect what its code actually does; introduces DCIChecker combining structure-aware static analysis with Direct-Reverse-Arbitration prompting across 19,200 description-code pairs from 2,214 real-world MCP servers; DCI is widespread with significant security implications (undeclared side effects, trust manipulation) (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [Toward Secure LLM Agents: Threat Surfaces, Attacks, Defenses, and Evaluation](https://arxiv.org/abs/2606.10749) (arXiv:2606.10749) | Jun 2026 | Lifecycle-based framework synthesizing 247 papers; reframes LLM agent security as software and systems security rather than prompt-level model safety; structured coverage of threat surfaces, attack taxonomies (prompt injection, tool-use security, memory poisoning, multi-agent coordination), defenses, and evaluation methodologies (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [Who Pays the Price? Stakeholder-Centric Prompt Injection Benchmarking for Real-world Web Agents](https://arxiv.org/abs/2606.13385) (arXiv:2606.13385) | Jun 2026 | Argues existing prompt-injection benchmarks adopt an attack-centric view and overlook how harm is distributed across stakeholders; introduces a stakeholder-centric benchmark showing a single exploit can produce asymmetric consequences for different parties and the same attack pattern varies in effectiveness by targeted stakeholder (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [SecureClaw: Clawing Back Control of LLM Agents](https://arxiv.org/abs/2606.09549) (arXiv:2606.09549, TU Berlin) | Jun 2026 | Dual-boundary architecture for tool-using LLM agents: authorization at the effect sink prevents unauthorized external actions; plaintext confinement at the read boundary routes sensitive reads through a trusted gateway that replaces raw values with opaque handles and bounded summaries, preventing data exfiltration before output checks can intervene (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [Under the Hood of SKILL.md: Semantic Supply-chain Attacks on AI Agent Skill Registry](https://arxiv.org/abs/2605.11418) (arXiv:2605.11418) | May 2026 | Attacks targeting the Discovery, Selection, and Loading stages of the agent skill lifecycle; 86% pairwise win rate in retrieval-ranking manipulation; demonstrates that an attacker who controls a skill's metadata can reliably displace legitimate skills without modifying any code (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [Exploiting LLM Agent Supply Chains via Payload-less Skills](https://arxiv.org/abs/2605.14460) (arXiv:2605.14460) | May 2026 | Semantic Compliance Hijacking (SCH): pure natural-language manipulation of skill content, no executable payload; bypasses code-auditing detection entirely because there is no malicious code to scan; demonstrates that semantic manipulation alone is sufficient to hijack agent behavior in skill-augmented systems (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [RAS-Eval: A Comprehensive Benchmark for Security Evaluation of LLM Agents in Real-World Environments](https://arxiv.org/abs/2506.15253) (arXiv:2506.15253) | Jun 2026 | 80 test cases, 3,802 attack tasks across 11 CWE categories in JSON, LangGraph, and MCP tool formats; attacks reduce agent task completion by 36.78%; 85.65% attack success rate (ASR); first evaluation framework to cover agentic tool-use attack vectors across real-world deployment formats systematically (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [POISE: Position-Aware Undetectable Skill Injection on LLM Agents](https://arxiv.org/abs/2606.07943) (arXiv:2606.07943) | Jun 2026 | Embeds the malicious trigger inside a benign body instruction at a chosen position, escaping YAML-header inspection while staying reliable; 89.3% ASR on Skill-Inject (codex+gpt-5.2) with only 5.6% of variants raising a new high-risk alert — concrete evidence that static skill scanners are insufficient and runtime/behavioral checks are needed (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [SkillHarm: Lifecycle-Aware Skill-Based Attacks via Automated Construction](https://arxiv.org/abs/2606.02540) (arXiv:2606.02540) | Jun 2026 | Benchmark across the skill-use lifecycle (12 risk types); contrasts Fixed-Payload Poisoning with Self-Mutating Poisoning, where an initially benign skill silently mutates persistent state for later reuse; AutoSkillHarm yields 879 samples, ASR up to 86.3% — relevant to persistent-state / config-tampering defenses (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent Skills](https://arxiv.org/abs/2606.07131) (arXiv:2606.07131) | Jun 2026 | First runtime-verified malicious-skill benchmark: 3,944 malicious skills (703 in-the-wild + 3,214 generated in a syscall-monitored sandbox) plus 4,000 benign; runtime verification yields 94.5% confirmation for code-injection vs 75.8% for prompt-injection skills, quantifying why static scanning under-detects (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [SkillGuard: A Permission Framework for Agent Skills](https://arxiv.org/abs/2606.03024) (arXiv:2606.03024) | Jun 2026 | Treats skills as permission-bearing artifacts with dual-plane governance (context influence + action side effects) via manifests, deny-by-default runtime access control, and capability inference; 91.0% F1 manifest generation — closely parallels this repo's secret-manifest + Pre/PostToolUse hook model (HTTP 403 — bot-protection pattern; search-confirmed live) |
| [AI Code Sandboxes: A Comparative Security Study, Part 1 — Engine-Level Properties](https://arxiv.org/abs/2606.08433) (arXiv:2606.08433) | Jun 2026 | Compares five AI code-sandbox products on host attack surface, leakage, defense-in-depth stackability, CVE history, patch cadence, and fuzzing posture; engine classes (microVM / userspace-kernel / OCI) separate cleanly while products within a class do not, and product pin policy is the dominant operator-facing variable (HTTP 403 — bot-protection pattern; search-confirmed live) |

**Industry reports:**
- [Trail of Bits — Lack of Guardrails for AI Agents (Jan 2026)](https://blog.trailofbits.com/2026/01/13/ai-agents-lack-of-guardrails/) (HTTP 403 — bot-protection pattern; search-confirmed live)
- [NSA AISC — MCP Security Design Considerations (June 2, 2026)](https://media.defense.gov/2026/Jun/02/2003990684/-1/-1/0/CSI-MCP-SECURITY-DESIGN-CONSIDERATIONS.PDF) (HTTP 403 — bot-protection pattern; search-confirmed live via NSA press release)
- [OWASP State of Agentic AI Security and Governance 2.01 (June 2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (HTTP 403 — bot-protection pattern; search-confirmed live)
- [Unit 42 — New Prompt Injection Attack Vectors Through MCP Sampling](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/) (HTTP 403 — bot-protection pattern; search-confirmed live): Three novel attack vectors exploiting the MCP sampling primitive — where an MCP server initiates LLM calls rather than responding to them, inverting the normal trust flow. Attack surfaces: (1) **resource theft** via server-inflated token requests consuming user quota without visible sign; (2) **conversation hijacking** via injected system prompts inside the `sampling/createMessage` payload that alter model behavior across the session; (3) **covert tool invocation** using server-initiated LLM calls to trigger actions without appearing in the client's tool-call log. Bypasses tool integrity checks because sampling operates through a legitimate, explicitly trusted protocol path that most MCP hosts and clients do not inspect.
- [OWASP Agentic Skills Top 10 (AST01–AST10), v1.0 (2026 Edition)](https://owasp.org/www-project-agentic-skills-top-10/) (June 2026): First framework purpose-built for AI agent **skill/plugin** supply-chain risk, complementing the Agentic Top 10. Categories: AST01 Malicious Skills, AST02 Supply-Chain Compromise, AST03 Over-Privileged Skills, AST04 Insecure Metadata, AST05 Untrusted External Instructions, AST06 Weak Isolation, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance, AST10 Cross-Platform Reuse. Covers OpenClaw, Claude Code, Cursor/Codex, and VS Code skill formats — directly applicable to the `manifests/` skill-vetting model in this repo.
- [Five Eyes — Careful Adoption of Agentic AI Services](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services) (May 1, 2026): First joint guidance from all Five Eyes agencies (CISA, NSA, ASD ACSC, CCCS, NCSC-NZ, NCSC-UK). Five risk categories (privilege, design/config, behavioral, structural, accountability), ~23 risks, 100+ best practices. Headline recommendations: give each agent a cryptographically anchored identity with short-lived credentials, require human sign-off for high-impact actions, and treat prompt injection as the most persistent threat (HTTP 403 — bot-protection pattern; search-confirmed live).

---

## Keeping This Document Current

This threat model is maintained as part of the `llm-safe-haven` project. The maintenance schedule is:

- **Daily:** Automated sweeps check for new CVEs, supply chain incidents, and research papers
- **Weekly:** Link health check across all sources
- **Per-incident:** Immediate update when a high-severity incident is confirmed

As new tools and research emerge

---

*Last updated: June 2026. Sources verified at time of writing. If a link is dead, check the [Wayback Machine](https://web.archive.org/) or search for the title.*
