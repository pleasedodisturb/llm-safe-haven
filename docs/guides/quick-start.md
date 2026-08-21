# Harden Your AI Agent Setup

**Time estimate:** ~15 minutes (1 min with the CLI, the rest is follow-up) — or ~30 minutes if you install everything by hand, see the appendix | **Prerequisites:** macOS or Linux, Claude Code installed

> Cursor and Windsurf users: most concepts apply, but hook syntax differs. See [docs/hardening/cursor.md](../hardening/cursor.md) and [docs/hardening/windsurf.md](../hardening/windsurf.md) for agent-specific steps.

---

## Step 1: Run It (~1 min)

`npx llm-safe-haven` is the product. The primary path is three invocations — preview, install, audit — shown below with their real captured output, run against a scratch `$HOME` (never a real `~/.claude`) so nothing here reflects the machine that captured it. Output below is trimmed for length (marked `[...]`), never edited.

### 1. Preview — nothing is written yet

```bash
npx llm-safe-haven --dry-run
```

```
  🔒 LLM Safe Haven — Security Scorecard

  Detected agents:
    ✓ Claude Code 2.1.239 (Claude Code)
    ✓ Cursor
    [... 4 more detected, 10 "not installed" — see the README's Supported Agents table for all 16 ...]

  Hardening:

  ✓ Claude Code 2.1.239 (Claude Code) (Full support)
    ✓ [dry-run] Would copy hooks to /var/folders/v4/j7fwh_rj5r716k59_6cqs7xc0000gn/T/lsh-qs-KiK7ix/.claude/hooks
    ✓ [dry-run] Would merge hook config into /var/folders/v4/j7fwh_rj5r716k59_6cqs7xc0000gn/T/lsh-qs-KiK7ix/.claude/settings.json
    ✓ Sandbox — Seatbelt sandbox is on by default since Claude Code v1.0
    ✗ bash firewall — Not installed
    ✗ secret guard — Not installed
    ✗ config guard — Not installed
    ✗ audit logger — Not installed
    ✗ Settings hooks — No hooks in settings.json
    [... 4 more ✗ lines: per-hook integrity + Audit logging, same "not installed yet" shape ...]

  [... trimmed: each other detected agent prints its own advisory block ...]

  Security Level: 1 of 4
  ┌──────────────────────────────────────┐
  │ █████░░░░░░░░░░░░░░░  Level 1: Basic │
  └──────────────────────────────────────┘
```

*(`$HOME` above is a throwaway `mktemp -d` scratch directory used to capture this output — never a real `~/.claude`. On your machine the `[dry-run]` paths will be under your actual home directory, and `Detected agents:` will reflect what's on your own PATH.)*

### 2. Install — hooks copied, `settings.json` merged non-destructively

```bash
npx llm-safe-haven
```

```
  Hardening:

  ✓ Claude Code 2.1.239 (Claude Code) (Full support)
    ✓ bash-firewall.js — installed
    ✓ secret-guard.js — installed
    ✓ config-guard.js — installed
    ✓ audit-logger.js — installed
    ✓ settings.json — hooks config merged
    ✓ Sandbox — Seatbelt sandbox is on by default since Claude Code v1.0
    ✓ bash firewall — Installed and valid
    [... 8 more ✓ lines: secret/config/audit-logger valid, settings wired, four SHA256 integrity checks ...]
    ✗ Audit logging — No recent audit logs

  [... trimmed: Detected agents list (same as preview) and the other agents' own hardening output ...]

  Security Level: 3 of 4
  ┌─────────────────────────────────────────┐
  │ ███████████████░░░░░  Level 3: Hardened │
  └─────────────────────────────────────────┘
```

Four hooks copied to `~/.claude/hooks/`, `settings.json` merged (not replaced). `✗ Audit logging` stays red until a Claude Code session actually runs and writes a log — expected on a fresh install.

### 3. Audit — check the posture any time, in CI or locally

```bash
npx llm-safe-haven audit
```

```
  Auditing security posture...

  ✓ Claude Code 2.1.239 (Claude Code) (Full support)
    ✓ Sandbox — Seatbelt sandbox is on by default since Claude Code v1.0
    ✓ bash firewall — Installed and valid
    [... 8 more ✓ lines, same shape as install above ...]
    ✗ Audit logging — No recent audit logs

  [... trimmed: other agents' audit output ...]

  Security Level: 3 of 4
  ┌─────────────────────────────────────────┐
  │ ███████████████░░░░░  Level 3: Hardened │
  └─────────────────────────────────────────┘
```

`audit`'s exit code is the same three-valued contract every scanning command uses: **`0`** means Level 2 ("Guarded") or higher, **`1`** means below Level 2, **`2`** means the MCP or `.env` scan didn't finish — fail closed, never reported as clean. A fresh scratch home before install exits `1` (Level 1, as above); after install it's `0`. `npx llm-safe-haven audit --json` gives the same result machine-readable, for CI.

The steps below are what the CLI does **not** yet do for you — still part of getting hardened, not optional extras.

---

## Step 2: Verify Your Sandbox (~2 min)

Claude Code's Seatbelt (macOS) / Bubblewrap (Linux) sandbox is **on by default** since late 2025. Verify it's active:

```bash
# Start a Claude Code session and check for the sandbox indicator
claude --version
# In-session, run:
/sandbox
```

You should see sandbox status confirming filesystem and network isolation are active. If sandbox is off, enable it:

```json
// ~/.claude/settings.json
{
  "permissions": {
    "sandbox": true
  }
}
```

**Verify it works:** In a Claude Code session, ask the agent to read `/etc/passwd`. It should be blocked by filesystem isolation.

**Cursor/Windsurf:** Check Settings > Security for sandbox toggles. Neither offers OS-level sandboxing equivalent to Claude Code's — container isolation (Step 1 of the hardening guides) is recommended.

---

## Step 3: Audit Your Secrets (~10 min)

`npx llm-safe-haven scan` (and the project scan folded into `install`/`audit` above) already tells you whether `.env` files exist under your default scan roots. This step is the actual remediation — move secrets out, gitignore them, and check history for leaks. Every `.env` file in your projects is readable by your agent.

1. **Find all .env files:**

```bash
find ~/Projects -name ".env" -not -path "*/node_modules/*" -not -path "*/.git/*"
```

2. **For each .env file:**
   - Move secrets to a credential manager (`rbw`, `1password`, `op`, `infisical`, etc.)
   - Replace the `.env` with a `.env.example` containing placeholder values:
     ```
     # .env.example — copy to .env and fill in real values
     DATABASE_URL=<your-database-url-here>
     API_KEY=<your-api-key-here>
     ```
   - Delete or encrypt the original `.env`

3. **Verify .env is gitignored:**

```bash
# In each project root
grep -q "\.env" .gitignore && echo "OK: .env in .gitignore" || echo "WARNING: add .env to .gitignore"
```

4. **Scan for leaked secrets in git history:**

```bash
# Using trufflehog (install: brew install trufflehog)
trufflehog git file://. --only-verified

# Or using gitleaks (install: brew install gitleaks)
gitleaks detect --source .
```

---

## Step 4: Create a Secret Manifest (~3 min)

A secret manifest declares which secrets a project needs, where they come from, and how to inject them — without containing the secrets themselves.

1. Copy the template:

```bash
cp manifests/secrets.manifest.yaml ./secrets.manifest.yaml
```

2. Customize for your project (example):

```yaml
# secrets.manifest.yaml — checked into git
project: my-app
secrets:
  - name: DATABASE_URL
    source: rbw
    key: "my-app/database-url"
    required: true
  - name: STRIPE_SECRET_KEY
    source: 1password
    vault: Development
    item: "Stripe API Key"
    required: true
  - name: SENTRY_DSN
    source: env
    required: false
```

3. Check it into git:

```bash
git add secrets.manifest.yaml
git commit -m "add secret manifest"
```

---

## What You Just Secured

| Before | After |
|--------|-------|
| Agents could run any command | Destructive commands blocked by bash firewall |
| Secrets could be written into code | API keys detected and blocked before file write |
| Config files could be turned into execution implants | `binding.gyp`, CI workflows, VS Code tasks, and `settings.json` writes blocked by config guard |
| No audit trail | Every tool call logged to JSONL |
| .env files readable by agents | Secrets moved to credential manager |
| No record of what secrets exist | Secret manifest checked into git |

---

## Verify Your Full Setup

The three invocations in Step 1 already prove the install worked — that's what `audit`'s exit code is for. Run `npx llm-safe-haven audit` again any time. For per-hook checks — the exact syntax, export, and live block-decision tests used to prove each hook actually works — see [hooks/README.md § Testing](../../hooks/README.md#testing) rather than a second, separately-maintained script here.

---

## Appendix: Install By Hand (~15 min)

Everything `npx llm-safe-haven` did in Step 1, as four manual copy/merge steps — shown so you can read exactly what the tool writes to your machine before you ever run it.

### Copy the hooks

```bash
mkdir -p ~/.claude/hooks
cp hooks/bash-firewall.js ~/.claude/hooks/
cp hooks/secret-guard.js ~/.claude/hooks/
cp hooks/config-guard.js ~/.claude/hooks/
cp hooks/audit-logger.js ~/.claude/hooks/
chmod 755 ~/.claude/hooks
chmod 644 ~/.claude/hooks/*.js
```

**bash-firewall.js** (PreToolUse — Bash) blocks destructive commands before they execute — `rm -rf /`, `curl | sh`, force-push to a protected branch, `git reset --hard`. **secret-guard.js** (PreToolUse — Write/Edit/MultiEdit) scans every file write and edit for hardcoded secrets before the content reaches disk. **config-guard.js** (PreToolUse — Write/Edit/MultiEdit) blocks the agent from writing supply-chain execution implants into config files that auto-run code (`binding.gyp`, `.github/workflows/*.yml`, `.vscode/tasks.json`, `.claude/settings.json` itself). **audit-logger.js** (PostToolUse — all tools) logs every tool call to a JSONL file for forensic review, redacting file/command content, never just the path.

### Wire them into settings.json

Add to `~/.claude/settings.json` — merge with any existing `hooks` key, don't replace it:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/bash-firewall.js", "timeout": 5 }]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/secret-guard.js", "timeout": 5 }]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/config-guard.js", "timeout": 5 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [{ "type": "command", "command": "node ~/.claude/hooks/audit-logger.js", "timeout": 10 }]
      }
    ]
  }
}
```

**Verify it works:** ask Claude to run `rm -rf ~/` — the hook should block it before execution. Ask it to write a file containing a string matching the AWS access-key pattern (`AKIA` followed by 16 alphanumeric characters) — secret-guard should catch it and block the write.

### What you give up doing it this way

`install` performs the same two writes above, plus four things a manual copy/paste does not: it **merges** `settings.json` non-destructively instead of requiring a hand-edit of the `hooks` array, takes a **timestamped backup** of your existing `settings.json` before writing anything (keeps the 3 most recent), ships **SHA256 checksums** so `npx llm-safe-haven audit` can later tell you if a hook file was tampered with after install, and gives you `npx llm-safe-haven update` to pull hook updates without repeating any of the above by hand.

---

## Troubleshooting

### Hooks Not Firing

**Symptom:** You installed hooks but they don't block anything.

**Check 1: Is the settings.json in the right location?**

Claude Code reads settings from multiple locations with this priority:

```
1. Project-level:  .claude/settings.json  (in repo root)
2. User-level:     ~/.claude/settings.json
3. Enterprise:     /etc/claude/settings.json  (managed installs)
```

If a project-level `settings.json` exists and doesn't include your hooks, it may shadow your user-level config. Verify which file is active:

```bash
# Check if any project overrides exist
find . -path "*/.claude/settings.json" -maxdepth 2 2>/dev/null

# Check user-level settings
cat ~/.claude/settings.json | python3 -m json.tool
```

**Check 2: Is the hook file executable and syntactically valid?**

```bash
# Syntax check
node --check ~/.claude/hooks/bash-firewall.js

# Permissions check — file needs to be readable
ls -la ~/.claude/hooks/
```

**Check 3: Does the matcher regex match the tool name?**

The `matcher` field is a regex. Common mistakes:
- `"Bash"` matches the Bash tool (correct)
- `"bash"` does NOT match (case-sensitive)
- `"Write|Edit|MultiEdit"` matches all three (correct)
- `"Write|Edit"` misses `MultiEdit` (wrong for Claude Code versions that use it)

**Check 4: Is the timeout too low?**

If a hook takes longer than the `timeout` (in seconds), Claude Code skips it silently. Set to at least 5 seconds for file-based hooks. If your hook shells out to external tools (e.g., gitleaks), increase to 10-15.

### Wrong settings.json Location

**macOS:** `~/.claude/settings.json` (expands to `/Users/<you>/.claude/settings.json`)

**Linux:** `~/.claude/settings.json` (expands to `/home/<you>/.claude/settings.json`)

**Common mistake:** Editing `~/.config/claude/settings.json` or `~/.claude/config.json` — these are not read by Claude Code.

Verify the correct path:

```bash
# This should show your hooks configuration
cat ~/.claude/settings.json
```

### Permissions Issues

**Hook returns "Permission denied":**

```bash
# The hook script itself doesn't need execute permission (node runs it),
# but the directory must be readable
chmod 755 ~/.claude/hooks/
chmod 644 ~/.claude/hooks/*.js
```

**Audit log directory not writable:**

```bash
mkdir -p ~/.claude/audit
chmod 755 ~/.claude/audit
```

**Sandbox blocks hook from reading files:**

If the hook needs to read files outside the project directory (e.g., a global blocklist), the sandbox may block it. Options:
1. Place the file inside `~/.claude/` (which is always readable)
2. Inline the data in the hook script itself
3. Add a sandbox exception (last resort — weakens isolation)

### Hook Crashes Silently

Claude Code swallows hook errors by default. To debug:

```bash
# Run the hook manually with test input
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | \
  node ~/.claude/hooks/bash-firewall.js

# Check exit code
echo $?
# 0 = allow, non-zero = block
```

If the hook throws an uncaught exception, Claude Code treats it as "allow" (fail-open). Always wrap your hook logic in try/catch with a default-deny:

```javascript
try {
  // ... hook logic ...
} catch (err) {
  // Fail closed: block on error
  console.error(JSON.stringify({ error: err.message }));
  process.exit(2);
}
```

---

## Edge Cases

### Multiple Claude Code Profiles

If you use multiple Claude Code profiles (e.g., personal vs. work), each profile can have its own settings:

```
~/.claude/settings.json              # Default profile
~/.claude/profiles/work/settings.json  # Work profile (if supported)
```

However, hooks are currently loaded from the user-level `settings.json` regardless of profile. To ensure hooks are active across all profiles:

1. Keep all security hooks in `~/.claude/settings.json` (the global user config)
2. Use project-level `.claude/settings.json` only for project-specific permissions — not to override security hooks
3. Verify hooks are active at the start of each session: ask Claude "what hooks are loaded?" or check `/hooks`

### Project-Level vs. Global settings.json

There is a hierarchy:

| Level | Path | Use Case |
|-------|------|----------|
| Enterprise | `/etc/claude/settings.json` | Org-wide policy (managed installs) |
| User (global) | `~/.claude/settings.json` | Your security hooks, sandbox config |
| Project | `.claude/settings.json` (in repo root) | Project-specific permissions, allowed tools |

**Key behavior:** Project settings can add permissions but should not remove security hooks defined at the user level. However, if a project `settings.json` redefines the `hooks` key entirely, it may shadow your global hooks.

**Best practice:** Define all security hooks (bash firewall, secret guard, audit logger) at the user level. Only use project-level settings for permission allowlists.

**Verify no project override is hiding your hooks:**

```bash
# From your project root
if [[ -f .claude/settings.json ]]; then
  echo "Project settings found:"
  cat .claude/settings.json
  echo ""
  echo "Check if 'hooks' key exists — if so, it may shadow global hooks"
  grep -l "hooks" .claude/settings.json && echo "WARNING: project overrides hooks"
else
  echo "No project settings — global settings apply"
fi
```

### macOS vs. Linux Differences

| Feature | macOS | Linux |
|---------|-------|-------|
| Sandbox engine | Seatbelt (App Sandbox) | Bubblewrap (bwrap) |
| Config path | `~/.claude/settings.json` | `~/.claude/settings.json` |
| Hook execution | Node.js via PATH | Node.js via PATH |
| Unix sockets | Blocked by Seatbelt | May work depending on bwrap config |
| Credential managers | Keychain, `rbw`, `op` | `gnome-keyring`, `rbw`, `pass`, `op` |
| Filesystem isolation | Profile-based sandboxing | Namespace-based sandboxing |

**macOS-specific gotcha:** Seatbelt blocks Unix domain socket IPC. If your credential manager (rbw, 1Password CLI) communicates via Unix socket, the sandbox will break it. See [credential-management.md](../credential-management.md) for workarounds.

**Linux-specific gotcha:** Bubblewrap requires user namespaces. Some hardened kernels disable them (`sysctl kernel.unprivileged_userns_clone=0`). Check:

```bash
# Linux only
sysctl kernel.unprivileged_userns_clone 2>/dev/null || echo "Setting not found (likely enabled)"
```

### Corporate Proxy / VPN

If you're behind a corporate proxy:

**1. Claude Code itself:** Set proxy environment variables before launching:

```bash
export HTTP_PROXY=http://proxy.corp.example.com:8080
export HTTPS_PROXY=http://proxy.corp.example.com:8080
export NO_PROXY=localhost,127.0.0.1,.corp.example.com
```

**2. Hooks that make network calls:** If any hook fetches external data (e.g., checking a blocklist API), it needs proxy-aware HTTP. Node.js does not respect `HTTP_PROXY` by default. Use `global-agent` or pass proxy config explicitly.

**3. Secret scanners:** TruffleHog and Gitleaks scan local repos and don't need network access. But if using `trufflehog --only-verified` (which checks if credentials are live), it needs outbound HTTPS.

**4. Sandbox + proxy conflict:** The sandbox may block outbound connections to the proxy itself. If Claude Code can't reach its API through your proxy, you may need to adjust sandbox network rules or run Claude Code outside the sandbox with compensating controls (hooks + audit logging).

---

## Monthly Security Audit Checklist

Run this checklist once a month to catch drift, new exposures, and configuration rot.

### Audit Logs

- [ ] Review audit logs for suspicious patterns — commands you didn't expect, unusual file paths, network requests to unknown hosts:

```bash
# Show the 20 most recent tool calls with their commands
tail -100 ~/.claude/audit/*.jsonl | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        tool = e.get('tool_name', '?')
        cmd = e.get('tool_input', {}).get('command', e.get('tool_input', {}).get('file_path', ''))
        ts = e.get('timestamp', '?')
        print(f'{ts}  {tool:12s}  {cmd[:80]}')
    except: pass
" | tail -20
```

- [ ] Check for any `curl`, `wget`, or `nc` calls in audit logs — these are the most common exfiltration vectors:

```bash
grep -i '"curl\|"wget\|"nc ' ~/.claude/audit/*.jsonl 2>/dev/null | head -20
```

### Secret Exposure

- [ ] Re-scan for .env files (new projects may have added them):

```bash
find ~/Projects -name ".env" -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/.venv/*" 2>/dev/null
```

- [ ] Run a secret scanner on active repos:

```bash
# Quick scan of your most active project
cd ~/Projects/your-project
gitleaks detect --source . --no-banner
```

- [ ] Verify all .env files are still gitignored:

```bash
for dir in ~/Projects/*/; do
  if [[ -f "$dir/.env" ]] && ! grep -q "\.env" "$dir/.gitignore" 2>/dev/null; then
    echo "WARNING: $dir has .env but no .gitignore entry"
  fi
done
```

### Hook Health

- [ ] Verify hooks are still installed and pass syntax check:

```bash
for hook in bash-firewall.js secret-guard.js audit-logger.js; do
  if node --check ~/.claude/hooks/$hook 2>/dev/null; then
    echo "OK: $hook"
  else
    echo "BROKEN: $hook"
  fi
done
```

- [ ] Confirm no project-level settings.json is shadowing your hooks:

```bash
find ~/Projects -path "*/.claude/settings.json" -exec grep -l "hooks" {} \; 2>/dev/null
```

- [ ] Test that the bash firewall actually blocks a destructive command (run in a Claude session)

### Agent & Tool Updates

- [ ] Check for new security advisories on Claude Code:

```bash
# Check Claude Code version
claude --version

# Check for known issues
gh issue list --repo anthropics/claude-code --label security --state open 2>/dev/null | head -10
```

- [ ] Review changelogs for recent Claude Code updates — new features may change security assumptions

- [ ] If using MCP servers, scan them for vulnerabilities:

```bash
# Using Snyk agent-scan (install: npm install -g @snyk/agent-scan)
npx @snyk/agent-scan scan --static
```

### Credential Rotation

- [ ] Rotate any secrets older than 90 days
- [ ] Revoke any API keys that are no longer in use
- [ ] Check credential manager for stale entries
- [ ] Update secret manifests if credential sources changed

### Canary Tokens (If Deployed)

- [ ] Check canary token dashboard for any triggers
- [ ] Verify canary tokens are still in place (haven't been deleted by agent cleanup)
- [ ] Rotate canary token values (prevents attackers from learning to avoid them)

---

## What's Next

You've covered the basics. For deeper hardening:

- **[Full Threat Model](../threat-model.md)** — OWASP Agentic Top 10 mapped to solo dev setups, with real incidents
- **[Claude Code Deep Dive](../hardening/claude-code.md)** — advanced hook patterns, sandbox configuration, permission tuning
- **[Credential Management](../credential-management.md)** — why env vars fundamentally fail, credential proxy architecture
- **[Curated References](../references.md)** — 120+ repos, tools, papers, and incident reports
