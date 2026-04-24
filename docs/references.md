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

## Scanning & Detection

| Resource | Stars | Description |
|----------|-------|-------------|
| [snyk/agent-scan](https://github.com/snyk/agent-scan) | ~2.2K | Security scanner for AI agents, MCP servers, and agent skills. Auto-discovers local agent configs (Claude, Cursor, Windsurf, Gemini CLI). Scans for prompt injection, tool poisoning, toxic flows, and 15+ risks. |
| [avast/sage](https://github.com/avast/sage) | ~182 | Lightweight Agent Detection & Response (ADR) layer for AI agents. Intercepts every tool call — Bash commands, URL fetches, file writes — before it hits the OS. Checks against URL reputation (cloud-based malware/phishing detection), local YAML-based heuristics, and package supply-chain data (npm/PyPI). Works with Claude Code, Cursor, VS Code, OpenClaw. File content and commands stay local; only URL/package hashes are sent to Gen Digital reputation APIs. March 2026. |
| [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | ~4.3K | Pre-commit secret detection with plugin architecture. 27 built-in detectors, scans git diffs (not full repos) — efficient for monorepos. |
| [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | ~25.7K | Find, verify, and analyze leaked credentials across git repos, S3 buckets, filesystems, and more. Verification reduces false positives. |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | ~26.2K | Fast git secret scanner. Pre-commit hooks and CI integration. Good complement to TruffleHog for different detection patterns. |

## Credential Management

| Resource | Stars | Description |
|----------|-------|-------------|
| [Infisical/agent-vault](https://github.com/Infisical/agent-vault) | — | HTTP credential proxy for AI agents. Agents route requests through a local proxy that injects credentials at the network layer — agents never see plaintext secrets. Officially launched April 22, 2026. |
| [DemiPass](https://www.demipass.com/) | — | MCP-native secrets management using 30-second, single-use cryptographic nonces. Agents get use-tokens, never raw credentials. Commercial. |
| [1Password/agent-hooks](https://github.com/1Password/agent-hooks) | — | PreToolUse hooks for AI agents (Claude Code, Cursor, Copilot, Windsurf). Validates mounted .env files against 1Password vault. |
| [hashicorp/vault-mcp-server](https://github.com/hashicorp/vault-mcp-server) | — | Official HashiCorp Vault MCP server. Vault-backed secret management for AI agents via MCP protocol. Beta. |
| [pleasedodisturb/rbw-proxy](https://github.com/pleasedodisturb/rbw-proxy) | — | Bitwarden CLI credential proxy for sandboxed agents. Works around sandbox Unix socket restrictions. *(Forthcoming)* |

## Sandboxing & Isolation

| Resource | Stars | Description |
|----------|-------|-------------|
| [Anthropic: Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) | — | Engineering blog post on Seatbelt (macOS) / Bubblewrap (Linux) sandboxing. Reduces permission prompts by 84% while maintaining OS-level filesystem and network isolation. |
| [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) | — | Open-source lightweight sandboxing tool. Enforces filesystem and network restrictions at the OS level without containers. Research preview. |
| [dagger/container-use](https://github.com/dagger/container-use) | — | MCP server giving each agent a fresh container in its own git branch. Run multiple agents without conflicts. Early development. |
| [trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) | — | Security-hardened devcontainer for running Claude Code in bypass mode safely. Built for security audits and untrusted code review. Includes `devc` CLI. |
| [e2b-dev/E2B](https://github.com/e2b-dev/E2B) | ~11.5K | Open-source cloud sandbox for AI agents. Isolated environments with a single API call. |

## Agent Orchestration

| Resource | Stars | Description |
|----------|-------|-------------|
| [smtg-ai/claude-squad](https://github.com/smtg-ai/claude-squad) | ~6.9K | TUI for managing multiple Claude Code / Codex / Amp sessions. Each agent gets its own git worktree. Spawn, monitor, pause, resume, merge. |
| [anthropics/claude-agent-sdk-python](https://github.com/anthropics/claude-agent-sdk-python) | — | Official Python SDK for Claude Agent. Claude Code CLI bundled — no separate install. |
| [anthropics/claude-agent-sdk-demos](https://github.com/anthropics/claude-agent-sdk-demos) | — | Reference implementations demonstrating Claude Agent SDK patterns. |

## Community Guides

| Resource | Stars | Description |
|----------|-------|-------------|
| [affaan-m/everything-claude-code](https://github.com/affaan-m/everything-claude-code) | ~158K | Comprehensive Claude Code optimization system. 28 agents, 119 skills, 60 slash commands. Started at Cerebral Valley x Anthropic hackathon (Feb 2026). |
| [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) | ~678 | Catalog of practical and proposed defenses against prompt injection. Covers instructional defense, guardrails, firewalls, canaries, and research proposals. |

## Blog Posts & Incident Reports

These are the posts and reports that informed our threat model. Read them to understand the real-world attacks, not hypotheticals.

| Resource | Published | Summary |
|----------|-----------|---------|
| [Knostic: "Claude Code Automatically Loads .env Secrets"](https://www.knostic.ai/blog/claude-loads-secrets-without-permission) | 2026 | Claude Code silently ingests `.env` files at session start. Any secrets in those files enter the context window. |
| [Knostic: "From .env to Leakage"](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage) | 2026 | Demonstrates `.env` secret leakage across Claude Code, Cursor, and other coding agents. |
| [Martin Paul Eve: "Claude Code .env File Compromise"](https://eve.gd/2026/04/19/claude-code-can-consume-transmit-and-compromise-your-env-files-even-if-you-tell-it-not-to/) | Apr 2026 | Even explicit instructions to ignore `.env` files don't prevent reading. Secrets may be transmitted to Anthropic servers. |
| [VentureBeat: "Three AI Agents Leaked Secrets"](https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026) | Apr 2026 | Claude Code, Gemini CLI, and Copilot demonstrated leaking secrets through a single prompt injection. One vendor's system card predicted it. |
| [Snyk: "ToxicSkills: Malicious AI Agent Skills"](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) | Feb 2026 | 13.4% of scanned agent skills contain critical security issues. 36% contain prompt-injection techniques. 76 confirmed malicious payloads. |
| [Anthropic: "Claude Code Sandboxing"](https://www.anthropic.com/engineering/claude-code-sandboxing) | 2025 | Engineering blog on OS-level sandboxing via Seatbelt/Bubblewrap. Reduces permission prompts by 84%. |
| [GitGuardian: State of Secrets Sprawl 2026](https://www.helpnetsecurity.com/2026/04/14/gitguardian-ai-agents-credentials-leak/) | Apr 2026 | Claude Code-assisted commits leak secrets at 3.2% vs 1.5% baseline across all public GitHub commits. 29 million leaked secrets found in 2025. |

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
