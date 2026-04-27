# Agent Security Resources

> Last verified: April 2026

Curated collection of frameworks, tools, guides, and incident reports for securing AI coding agents. Focused on what's useful for solo developers — enterprise-only tools are noted but not prioritized.

---

## Security Frameworks & Standards

| Resource | Stars | Description |
|----------|-------|-------------|
| [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) | ~1.2K | Policy enforcement, zero-trust identity, and execution sandboxing for AI agents. Covers 10/10 OWASP Agentic Top 10. MIT licensed, multi-language (Python, TS, .NET, Rust, Go). |
| [precize/Agentic-AI-Top10-Vulnerability](https://github.com/precize/Agentic-AI-Top10-Vulnerability) | — | OWASP-style top 10 for agentic AI. Detailed attack descriptions, examples, and mitigations for each category. |
| [slowmist/slowmist-agent-security](https://github.com/slowmist/slowmist-agent-security) | — | Security review framework for AI agents in adversarial environments. Includes GitHub repo audit, URL/document analysis, and on-chain address review. |
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) | — | Foundation taxonomy for LLM risks. 2025 edition adds system prompt leakage and vector/embedding weaknesses. |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | — | Purpose-built for agentic AI. Covers agent goal hijack, tool misuse, identity/privilege abuse, supply chain poisoning, memory poisoning, and rogue agents. Developed by 100+ industry experts. |
| [requie/LLMSecurityGuide](https://github.com/requie/LLMSecurityGuide) | — | Comprehensive guide to offensive and defensive LLM security. Updated Feb 2026 with OWASP Top 10 for LLMs 2025 and Agentic Applications 2026. |

## Scanning & Detection

| Resource | Stars | Description |
|----------|-------|-------------|
| [snyk/agent-scan](https://github.com/snyk/agent-scan) | ~2.2K | Security scanner for AI agents, MCP servers, and agent skills. Auto-discovers local agent configs (Claude, Cursor, Windsurf, Gemini CLI). Scans for prompt injection, tool poisoning, toxic flows, and 15+ risks. Originally MCP-Scan by Invariant Labs (acquired by Snyk June 2025). |
| [avast/sage](https://github.com/avast/sage) | ~182 | Lightweight Agent Detection & Response (ADR) layer. Intercepts every tool call before it hits the OS. URL reputation, YAML heuristics, package supply-chain checks. Works with Claude Code, Cursor, VS Code. March 2026. |
| [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | ~900 | Scans MCP servers for malicious code and hidden threats. Three scanning engines: YARA rules, LLM-as-judge, and Cisco AI Defense inspect API. |
| [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | ~1.8K | Detects risk patterns in agent skills. Combines signature-based detection, LLM-based semantic analysis, behavioral dataflow analysis, and configurable rule packs. |
| [garagon/aguara](https://github.com/garagon/aguara) | — | Static security scanner for AI agent skills and MCP servers. 189 detection rules across 14 categories. 4-layer analysis: pattern matching, NLP, taint tracking, rug-pull detection. Single binary, offline, no LLM required. |
| [HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit) | — | Static security scanner for LLM agent *code* — the complementary layer to MCP server scanning. 49 rules mapped to all 10 OWASP Agentic Top 10 categories. AST-based dataflow analysis, credential detection, taint tracking, MCP config auditing. Works with LangChain, CrewAI, AutoGen. CI/CD integration via GitHub Actions. 94.6% recall. `pip install agent-audit`. February 2026. |
| [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | ~4.3K | Pre-commit secret detection with plugin architecture. 27 built-in detectors, scans git diffs (not full repos) — efficient for monorepos. |
| [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | ~25.7K | Find, verify, and analyze leaked credentials across git repos, S3 buckets, filesystems, and more. Verification reduces false positives. |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | ~26.2K | Fast git secret scanner. Pre-commit hooks and CI integration. Good complement to TruffleHog for different detection patterns. |
| [GitGuardian/ggshield](https://github.com/GitGuardian/ggshield) | ~1.9K | CLI secret scanner with 550+ secret types. Now scans prompts, tool calls, and agent actions in real-time. Free tier available. 700K+ developers on GitHub Marketplace. |

## Credential Management

| Resource | Stars | Description |
|----------|-------|-------------|
| [Infisical/agent-vault](https://github.com/Infisical/agent-vault) | — | TLS-intercepting, credential-injecting forward proxy for AI agents. Agents route requests through the proxy which injects credentials at the network layer — agents never see plaintext secrets. Officially launched April 22, 2026. |
| [DemiPass](https://www.demipass.com/) | — | MCP-native secrets management using 30-second, single-use cryptographic nonces. Agents get use-tokens, never raw credentials. Injects credentials into HTTP headers, request bodies, or SSH commands server-side. Commercial. |
| [1Password/agent-hooks](https://github.com/1Password/agent-hooks) | — | PreToolUse hooks for AI agents (Claude Code, Cursor, Copilot, Windsurf). Validates mounted .env files against 1Password vault. |
| [hashicorp/vault-mcp-server](https://github.com/hashicorp/vault-mcp-server) | — | Official HashiCorp Vault MCP server. Vault-backed secret management for AI agents via MCP protocol. Beta. |
| [joelhooks/agent-secrets](https://github.com/joelhooks/agent-secrets) | — | Portable credential management for AI agents. Age encryption, session-scoped leases with custom TTLs, killswitch to revoke all active leases. Daemon communicates via Unix socket. |
| [pleasedodisturb/rbw-proxy](https://github.com/pleasedodisturb/rbw-proxy) | — | Bitwarden CLI credential proxy for sandboxed agents. Works around sandbox Unix socket restrictions. *(Forthcoming)* |

## Sandboxing & Isolation

| Resource | Stars | Description |
|----------|-------|-------------|
| [Anthropic: Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) | — | Engineering blog post on Seatbelt (macOS) / Bubblewrap (Linux) sandboxing. Reduces permission prompts by 84% while maintaining OS-level filesystem and network isolation. |
| [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) | — | Open-source lightweight sandboxing tool. Enforces filesystem and network restrictions at the OS level without containers. Research preview. |
| [stacklok/brood-box](https://github.com/stacklok/brood-box) | — | CLI tool for running AI coding agents (Claude Code, Codex, OpenCode) inside hardware-isolated microVMs. COW snapshot isolation, DNS-aware egress policies, Cedar-based MCP authorization. Reviews diffs before flush-back. Apache-2.0. |
| [dagger/container-use](https://github.com/dagger/container-use) | — | MCP server giving each agent a fresh container in its own git branch. Run multiple agents without conflicts. Early development. |
| [trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) | — | Security-hardened devcontainer for running Claude Code in bypass mode safely. Built for security audits and untrusted code review. Includes `devc` CLI. |
| [e2b-dev/E2B](https://github.com/e2b-dev/E2B) | ~11.5K | Open-source cloud sandbox for AI agents. Isolated Firecracker microVM environments with a single API call. 24-hour session limit. |
| [superradcompany/microsandbox](https://github.com/superradcompany/microsandbox) | ~5K | Lightweight VMs that spin up in milliseconds from SDKs. Local-first, no server, no daemon, rootless. Embedded microVM runtime. |
| [superhq-ai/shuru](https://github.com/superhq-ai/shuru) | — | Local-first microVM sandbox for macOS (Virtualization.framework) and Linux (KVM). Ships as an agent skill so AI agents can use it automatically. |
| [abshkbh/arrakis](https://github.com/abshkbh/arrakis) | — | Self-hosted sandboxing for AI agent code execution. Backtracking support, REST API, Python SDK, automatic port forwarding, MicroVM isolation. |
| [firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker) | ~30K | AWS-built microVM monitor for serverless workloads. Hardware-level isolation via KVM. The engine behind E2B and many agent sandboxes. Not agent-specific, but the foundation most agent isolation tools build on. |
| [google/gvisor](https://github.com/google/gvisor) | ~18K | Application kernel that intercepts syscalls in user space. Stronger than containers, lighter than VMs. Used by Modal and Northflank for agent isolation. |
| [google/nsjail](https://github.com/google/nsjail) | ~3.2K | Process isolation tool using Linux namespaces and seccomp-bpf. Lightweight, used in production by Google. Good for isolating individual agent processes. |

## Prompt Injection Detection & Prevention

| Resource | Stars | Description |
|----------|-------|-------------|
| [protectai/rebuff](https://github.com/protectai/rebuff) | ~1.4K | Multi-layered prompt injection detector. Heuristics, LLM-based detection, vector database of previous attacks, and canary tokens. Python SDK and API. |
| [protectai/llm-guard](https://github.com/protectai/llm-guard) | ~2.5K | Security toolkit for LLM interactions. Sanitization, harmful language detection, data leakage prevention, prompt injection resistance. Input and output scanners. |
| [Lakera Guard](https://www.lakera.ai/lakera-guard) | — | AI security API with 98%+ prompt injection detection, sub-50ms latency, 100+ language support. PII detection/redaction, secrets detection. Trained on 80M+ adversarial prompts from Gandalf game. Acquired by Check Point (Sep 2025). Commercial. |
| [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) | ~678 | Catalog of practical and proposed defenses against prompt injection. Covers instructional defense, guardrails, firewalls, canaries, and research proposals. |

## LLM Guardrails & Firewalls

| Resource | Stars | Description |
|----------|-------|-------------|
| [NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | ~6K | Programmable guardrails for LLM-based systems. Input/output/dialog/retrieval/execution rails. Jailbreak and injection detection, hallucination checking, topic safety. Integrates with LangChain, LlamaIndex. GPU-accelerated. |
| [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) | ~6.7K | Validation framework for LLM outputs. Define guardrails in RAIL spec, validate structured output, retry on failure. Hub of community validators. |
| [luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock) | — | Firewall for AI agents. DLP scanning (48 patterns), SSRF protection, bidirectional MCP scanning, tool poisoning detection (SHA-256 fingerprinting), prompt injection blocking (25 patterns). Capability separation: agent has secrets but no network; Pipelock has network but no secrets. Apache-2.0 core. |

## Red Teaming & Pentesting

| Resource | Stars | Description |
|----------|-------|-------------|
| [NVIDIA/garak](https://github.com/NVIDIA/garak) | ~7K | LLM vulnerability scanner. Probes for hallucination, data leakage, prompt injection, misinformation, toxicity, jailbreaks. ~100 attack vectors, up to 20K prompts per run. AVID integration for community vulnerability sharing. Apache-2.0. |
| [microsoft/PyRIT](https://github.com/microsoft/PyRIT) | ~3.4K | Python Risk Identification Tool for generative AI. Multi-turn adversarial testing across text, image, audio, video. Orchestrators, converters, scorers, and memory system. Built from experience red-teaming Bing Chat and Copilot. |
| [praetorian-inc/augustus](https://github.com/praetorian-inc/augustus) | — | LLM vulnerability scanner. 210+ adversarial attack probes, 28 LLM providers, single Go binary. Production-oriented: concurrent scanning, rate limiting, retries, timeouts. Go-native reimplementation inspired by garak. Apache-2.0. |
| [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) | ~20K | CLI for evaluating and red-teaming LLM apps. 50+ vulnerability types, CI/CD integration via GitHub Actions. Used by OpenAI and Anthropic. Acquired by OpenAI (Mar 2026). MIT licensed. |
| [utkusen/promptmap](https://github.com/utkusen/promptmap) | — | Automated prompt injection scanner. White-box testing (provide system prompts) and black-box testing (point at HTTP endpoint). Controller LLM judges attack success. |

## Agent Monitoring & Observability

| Resource | Stars | Description |
|----------|-------|-------------|
| [langfuse/langfuse](https://github.com/langfuse/langfuse) | ~25K | Open-source LLM engineering platform. Traces, metrics, evals, prompt management. Framework-agnostic, built on OpenTelemetry. Self-hosted option available. Acquired by ClickHouse. |
| [LangSmith](https://www.langchain.com/langsmith/observability) | — | AI agent observability platform by LangChain. Near-zero overhead async tracing. If LangSmith goes down, your agent keeps running. Commercial with free tier. |

## CI/CD Runtime Hardening

| Resource | Stars | Description |
|----------|-------|-------------|
| [step-security/harden-runner](https://github.com/step-security/harden-runner) | ~1K | GitHub Actions runner hardening. Runtime egress filtering with allowlists, file integrity monitoring, anomaly detection. Maintains a Global Block List of IOC domains updated 24/7 from active supply chain attacks. Drop-in workflow step. Kubernetes ARC + third-party runner support (Depot, Blacksmith, Namespace, WarpBuild). Would have prevented Shai-Hulud egress in block mode. |

## Agent Orchestration

| Resource | Stars | Description |
|----------|-------|-------------|
| [smtg-ai/claude-squad](https://github.com/smtg-ai/claude-squad) | ~6.9K | TUI for managing multiple Claude Code / Codex / Amp sessions. Each agent gets its own git worktree. Spawn, monitor, pause, resume, merge. |
| [anthropics/claude-agent-sdk-python](https://github.com/anthropics/claude-agent-sdk-python) | — | Official Python SDK for Claude Agent. Claude Code CLI bundled — no separate install. |
| [anthropics/claude-agent-sdk-demos](https://github.com/anthropics/claude-agent-sdk-demos) | — | Reference implementations demonstrating Claude Agent SDK patterns. |

## Standards & Compliance

| Resource | Link | Description |
|----------|------|-------------|
| NIST AI Risk Management Framework | [nist.gov/ai-risk-management-framework](https://www.nist.gov/itl/ai-risk-management-framework) | Voluntary framework for identifying, assessing, and mitigating AI risks. Flexible, risk-based guidance. April 2026 concept note released for AI RMF Profile on Trustworthy AI in Critical Infrastructure. |
| ISO/IEC 42001 | [iso.org](https://www.iso.org/standard/81230.html) | First global standard for an AI Management System (AIMS). Certifiable. Published Dec 2023. Provides the auditable management system that NIST AI RMF's risk methodology feeds into. |
| EU AI Act | [artificialintelligenceact.eu](https://artificialintelligenceact.eu/) | Legal compliance framework. August 2026 deadline for high-risk AI system requirements, transparency obligations, and enforcement powers. Requires human oversight for all autonomous agents and traceable action logging. Multi-agent systems are especially complex. |
| CSA AI Safety Initiative / CSAI Foundation | [cloudsecurityalliance.org/ai-safety-initiative](https://cloudsecurityalliance.org/ai-safety-initiative) | Cloud Security Alliance's AI safety program. 2026 mission: "Securing the Agentic Control Plane." Includes AI Risk Observatory for continuous monitoring and agentic best practices. TAISE certification for AI safety professionals. |

## Awesome Lists & Meta-Resources

| Resource | Stars | Description |
|----------|-------|-------------|
| [ProjectRecon/awesome-ai-agents-security](https://github.com/ProjectRecon/awesome-ai-agents-security) | — | Living map of the AI agent security ecosystem. Organized by security lifecycle: red teaming, runtime protection, sandboxing, governance. |
| [bureado/awesome-agent-runtime-security](https://github.com/bureado/awesome-agent-runtime-security) | — | Curated list focused on runtime security for AI agents. Covers sandboxing, process isolation, credential management, and monitoring. |
| [corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) | — | Broad curation of LLM security tools, documents, and projects. Good starting point for exploring the space. |
| [restyler/awesome-sandbox](https://github.com/restyler/awesome-sandbox) | — | Curated list of code sandboxing solutions for AI agents. Covers microVMs, containers, gVisor, WASM, and cloud platforms. |
| [pleasedodisturb/awesome-llm-token-optimization](https://github.com/pleasedodisturb/awesome-llm-token-optimization) | — | Curated strategies, tools, papers for reducing LLM token costs 80-99%. Covers prompt caching, batch APIs, model routing, compression, KV cache. Companion to this repo — cost overruns from retries are a security-adjacent concern. |

## Community Guides

| Resource | Stars | Description |
|----------|-------|-------------|
| [affaan-m/everything-claude-code](https://github.com/affaan-m/everything-claude-code) | ~158K | Comprehensive Claude Code optimization system. 28 agents, 119 skills, 60 slash commands. Started at Cerebral Valley x Anthropic hackathon (Feb 2026). |

## Newsletters & Feeds

| Resource | Link | Description |
|----------|------|-------------|
| tl;dr sec | [tldrsec.com](https://tldrsec.com/) | Free weekly cybersecurity newsletter by Clint Gibler. 90K+ readers. Heavy AI agent security coverage in 2026 including MCP security, sandboxing, prompt injection. The single best newsletter for staying current on agent security. |
| GitGuardian State of Secrets Sprawl | [gitguardian.com/state-of-secrets-sprawl-report-2026](https://www.gitguardian.com/state-of-secrets-sprawl-report-2026) | Annual report. 2026 edition: Claude Code-assisted commits leak secrets at 3.2% vs 1.5% baseline. 29M leaked secrets found on public GitHub in 2025. AI-service leaks surged 81%. |
| PipeLab State of MCP Security | [pipelab.org/blog/state-of-mcp-security-2026](https://pipelab.org/blog/state-of-mcp-security-2026/) | Comprehensive analysis of MCP security incidents, attack patterns, and defense coverage in 2026. Includes scanner comparison. |

## Blog Posts & Incident Reports

These are the posts and reports that informed our threat model. Read them to understand the real-world attacks, not hypotheticals.

| Resource | Published | Summary |
|----------|-----------|---------|
| [Knostic: "Claude Code Automatically Loads .env Secrets"](https://www.knostic.ai/blog/claude-loads-secrets-without-permission) | 2026 | Claude Code silently ingests `.env` files at session start. Any secrets in those files enter the context window. |
| [Knostic: "From .env to Leakage"](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage) | 2026 | Demonstrates `.env` secret leakage across Claude Code, Cursor, and other coding agents. |
| [Martin Paul Eve: "Claude Code .env File Compromise"](https://eve.gd/2026/04/19/claude-code-can-consume-transmit-and-compromise-your-env-files-even-if-you-tell-it-not-to/) | Apr 2026 | Even explicit instructions to ignore `.env` files don't prevent reading. Secrets may be transmitted to Anthropic servers. |
| [VentureBeat: "Three AI Agents Leaked Secrets"](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026) | Apr 2026 | Claude Code, Gemini CLI, and Copilot demonstrated leaking secrets through a single prompt injection. One vendor's system card predicted it. |
| [Snyk: "ToxicSkills: Malicious AI Agent Skills"](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) | Feb 2026 | 13.4% of scanned agent skills contain critical security issues. 36% contain prompt-injection techniques. 76 confirmed malicious payloads. |
| [Snyk: "Clinejection — Cline Supply Chain Attack"](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/) | 2026 | Researcher disclosed prompt injection vulnerability in Cline. 8 days later, exploited to publish unauthorized npm version that installed OpenClaw on developer machines during an 8-hour window. |
| [Anthropic: "Claude Code Sandboxing"](https://www.anthropic.com/engineering/claude-code-sandboxing) | 2025 | Engineering blog on OS-level sandboxing via Seatbelt/Bubblewrap. Reduces permission prompts by 84%. |
| [GitGuardian: State of Secrets Sprawl 2026](https://www.helpnetsecurity.com/2026/04/14/gitguardian-ai-agents-credentials-leak/) | Apr 2026 | Claude Code-assisted commits leak secrets at 3.2% vs 1.5% baseline across all public GitHub commits. 29 million leaked secrets found in 2025. |
| [CrowdStrike: "Agentic Tool Chain Attacks"](https://www.crowdstrike.com/en-us/blog/how-agentic-tool-chain-attacks-threaten-ai-agent-security/) | 2026 | Analysis of how agents autonomously chaining tools creates cascading attack surfaces. Tool poisoning enables credential theft via hidden instructions in tool metadata. |
| [Simon Roses: "AI Agent Skill Poisoning"](https://simonroses.com/2026/02/ai-agent-skill-poisoning-the-supply-chain-attack-you-havent-heard-of/) | Feb 2026 | Deep dive into supply chain attacks via poisoned agent skills. 1,184 malicious skills confirmed on ClawHub marketplace. |

## Anthropic Issues (From Our Investigation)

These are the GitHub issues we filed or tracked while building [rbw-proxy](https://github.com/pleasedodisturb/rbw-proxy) and discovering that the Seatbelt sandbox breaks credential manager IPC.

| Issue | Topic |
|-------|-------|
| [anthropics/claude-code#52471](https://github.com/anthropics/claude-code/issues/52471) | Sandbox blocks Unix domain socket IPC with credential managers |
| [#40209](https://github.com/anthropics/claude-code/issues/40209) | Related sandbox restriction |
| [#41817](https://github.com/anthropics/claude-code/issues/41817) | Path-scoped Unix socket creation (bind) support in sandbox |
| [#50165](https://github.com/anthropics/claude-code/issues/50165) | Related sandbox restriction |
| [#31551](https://github.com/anthropics/claude-code/issues/31551) | Related sandbox restriction |
| [#16076](https://github.com/anthropics/claude-code/issues/16076) | Related sandbox restriction |
| [#29533](https://github.com/anthropics/claude-code/issues/29533) | Related sandbox restriction |
| [#44195](https://github.com/anthropics/claude-code/issues/44195) | Related sandbox restriction |
| [#23642](https://github.com/anthropics/claude-code/issues/23642) | Related sandbox restriction |
