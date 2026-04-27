# Supply Chain Defense for AI Agent Developers

Your npm dependencies, GitHub Actions, and credential managers are all attack surfaces. This guide covers what happened, what you can do about it, and how we protect our own supply chain.

---

## Case Study: Shai-Hulud — Bitwarden CLI Supply Chain Attack (April 2026)

On April 22, 2026, the official Bitwarden CLI (`@bitwarden/cli@2026.4.0`) was trojanized for 93 minutes. The malicious package specifically targeted AI tool API keys — the first known supply chain attack to do so.

This is not hypothetical. It happened to one of the most trusted credential managers in the ecosystem.

### The Attack Chain

The Shai-Hulud campaign traces back to **February 27, 2026**, when threat actor **TeamPCP** stole initial credentials from Aqua Security's Trivy via a misconfigured CI workflow. The campaign then compromised Checkmarx KICS and LiteLLM before pivoting to exploit Checkmarx's own GitHub Actions to reach Bitwarden.

The name "Shai-Hulud: The Third Coming" was embedded in the payload — a deliberate campaign marker indicating at least two prior attack waves.

**Step-by-step attack flow:**

1. **Compromised GitHub Action** — TeamPCP gained control of a GitHub Action in Checkmarx's ecosystem (the security vendor, ironically).
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
- **Dead-drop C2 via GitHub**: the payload queried GitHub's public commit search API for `LongLiveTheResistanceAgainstMachines`, using RSA/SHA-256 signed commits matching `/beautifulcastle/` as the command channel. Traffic to `github.com` is rarely flagged by security tools.

**Supply chain worm:**
The payload contained a self-propagation mechanism: it used stolen npm tokens to identify packages the victim had publish access to, injected malicious preinstall hooks into those packages, and re-uploaded them to npm — creating worm-style supply chain spread.

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

### Sources

- [The Hacker News — Bitwarden CLI Compromised in Ongoing Shai-Hulud Attack](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html)
- [OX Security — Shai-Hulud: Bitwarden CLI Supply Chain Attack](https://www.ox.security/blog/shai-hulud-bitwarden-cli-supply-chain-attack/)
- [Endor Labs — Shai-Hulud: The Third Coming](https://www.endorlabs.com/learn/shai-hulud-the-third-coming----inside-the-bitwarden-cli-2026-4-0-supply-chain-attack)
- [Socket.dev — Bitwarden CLI Compromised](https://socket.dev/blog/bitwarden-cli-compromised)
- [Bitwarden Community — Statement on Checkmarx Supply Chain Incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- [Hacking Passion — Bitwarden CLI Supply Chain Attack](https://hackingpassion.com/bitwarden-cli-supply-chain-attack/)

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

### 4. Run npm audit signatures

```bash
npm audit signatures
```

Verifies that every installed package's tarball matches the cryptographic signature published by the registry. Each package version includes an ECDSA P-256 signature computed over `${name}@${version}:${integrity}`. If the signature doesn't match, the bytes you installed were not what the publisher signed.

Also verifies Sigstore provenance attestations when available — linking the package to its exact source commit and CI build.

**Protects against:** Tarball tampering (man-in-the-middle, registry mirror poisoning, CDN corruption).
**Does not protect against:** Compromised publisher accounts (attacker publishes a new legitimately-signed version) or malicious code that was always in the package.

**Important:** The npm CLI bundled with Node is frequently too old for provenance verification. Run `npm install -g npm@latest` before using this in CI.

### 5. Use Socket.dev for behavioral analysis

[Socket.dev](https://socket.dev) does deep static analysis on packages and their dependency trees, detecting 60+ compromise indicators including install scripts, network access, obfuscated code, environment variable reads, and shell access.

Unlike `npm audit` which checks a CVE database, Socket catches zero-day attacks — packages with no CVE yet.

**GitHub App (recommended):** Install from socket.dev. Monitors every PR that modifies `package.json` or `package-lock.json`. Posts blocking comments with risk breakdown before changes merge.

**CLI:**

```bash
npx @socketsecurity/safe npm install   # drop-in replacement, blocks high-risk
```

**Free for public repos.** Private repos require a paid plan.

### 6. Validate lockfiles

[lockfile-lint](https://github.com/lirantal/lockfile-lint) ensures packages are only fetched from approved registries over HTTPS:

```bash
npx lockfile-lint --path package-lock.json --type npm \
  --allowed-hosts npm \
  --validate-https
```

**Protects against:** Lockfile injection attacks — a malicious contributor modifies `package-lock.json` to redirect a legitimate package name to `https://evil.example.com/malware.tgz`. Without lockfile-lint, no CI check catches this.

### 7. Run npm audit for known vulnerabilities

```bash
npm audit                    # check for known CVEs
npm audit --audit-level=high # fail only on high/critical
```

This checks the npm advisory database. It catches *known* vulnerabilities but not zero-day supply chain attacks (use Socket.dev for those).

### 8. Use Snyk or GitHub Dependabot for continuous monitoring

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
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4
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
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5  # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'
      - run: npm publish --provenance --access public
        # No NODE_AUTH_TOKEN — OIDC handles auth
```

**Protects against:** Stolen long-lived npm tokens. Each OIDC token is scoped to one workflow run, tied to a specific repo+workflow, and expires immediately.

**Gotcha:** All registration fields on npmjs.com are case-sensitive and not validated at setup time — errors only surface during publish.

### 4. Restrict GITHUB_TOKEN permissions

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

### 5. Verify after publish

Add a post-publish verification step:

```yaml
- run: |
    sleep 30  # wait for registry propagation
    npm audit signatures
```

This confirms the published package has valid signatures and provenance attestations.

### 6. No lifecycle scripts in package.json

Don't include `preinstall`, `postinstall`, or `prepare` scripts in your published package. llm-safe-haven follows this rule already.

Lifecycle scripts are the primary vector for install-time attacks. Every security scanner flags packages that have them. By not including them, you:
- Reduce your package's risk score on Socket.dev
- Make it safe to install with `--ignore-scripts`
- Signal to consumers that your package doesn't run code at install time

### 7. Monitor for unauthorized publishes

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
git ls-remote https://github.com/actions/checkout.git refs/tags/v4

# Current SHAs (verified April 2026):
actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5      # v4
actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020     # v4
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

If you installed `@bitwarden/cli@2026.4.0` during the 93-minute window, or any compromised package:

### Immediate (within 1 hour)

1. **Rotate ALL credentials** — GitHub tokens, npm tokens, AWS/GCP/Azure credentials, SSH keys. Assume everything is compromised.
2. **Check for persistence** — inspect `~/.bashrc` and `~/.zshrc` for injected heredoc blocks. Check `/tmp/tmp.987654321.lock` (Shai-Hulud's lock file).
3. **Audit GitHub repos** — check for unauthorized repository creation, unexpected workflow files, and suspicious workflow runs.
4. **Check npm publishes** — verify your packages haven't been re-published with malicious payloads.

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

*Last updated: April 2026. Sources verified at time of writing. If a link is dead, check the [Wayback Machine](https://web.archive.org/) or search for the title.*
