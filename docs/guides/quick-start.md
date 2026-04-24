# Harden Your AI Agent Setup in 30 Minutes

**Time estimate:** ~30 minutes | **Prerequisites:** macOS or Linux, Claude Code installed

> Cursor and Windsurf users: most concepts apply, but hook syntax differs. See [docs/hardening/cursor.md](../hardening/cursor.md) and [docs/hardening/windsurf.md](../hardening/windsurf.md) for agent-specific steps.

---

## Step 1: Verify Your Sandbox (~2 min)

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

## Step 2: Install the Bash Firewall Hook (~5 min)

The bash firewall blocks destructive commands (`rm -rf /`, `curl | sh`, `chmod 777`, etc.) before they execute.

1. Copy the hook into place:

```bash
mkdir -p ~/.claude/hooks
cp examples/hooks/bash-firewall.js ~/.claude/hooks/
```

2. Add to your settings:

```json
// ~/.claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/bash-firewall.js",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**Verify it works:** Ask Claude to run `rm -rf ~/`. The hook should block the command and return an error before execution.

---

## Step 3: Install the Secret Guard Hook (~5 min)

This hook scans file writes and edits for hardcoded secrets — API keys, private keys, tokens, passwords — and blocks them before they reach disk.

1. Copy the hook:

```bash
cp examples/hooks/secret-guard.js ~/.claude/hooks/
```

2. Add to settings (merge with existing `PreToolUse` array):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/secret-guard.js",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**Verify it works:** Ask Claude to write a file containing a string that matches the AWS access key pattern (starts with `AKIA` followed by 16 alphanumeric characters). The hook should catch it and block the write.

---

## Step 4: Set Up Audit Logging (~5 min)

The audit logger records every tool call to JSONL files — what was called, when, with what arguments, and what it returned. Essential for incident investigation.

1. Copy the hook:

```bash
cp examples/hooks/audit-logger.js ~/.claude/hooks/
```

2. Add to settings as a `PostToolUse` hook (empty matcher = all tools):

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/audit-logger.js",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**Verify it works:** Run a short Claude Code session (ask it to list files or similar). Then check for logs:

```bash
ls -la ~/.claude/audit/
# You should see JSONL files with timestamped entries
```

---

## Step 5: Audit Your Secrets (~10 min)

Every `.env` file in your projects is readable by your agent. Move secrets out.

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

## Step 6: Create a Secret Manifest (~3 min)

A secret manifest declares which secrets a project needs, where they come from, and how to inject them — without containing the secrets themselves.

1. Copy the template:

```bash
cp examples/manifests/secrets.manifest.yaml ./secrets.manifest.yaml
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
| No audit trail | Every tool call logged to JSONL |
| .env files readable by agents | Secrets moved to credential manager |
| No record of what secrets exist | Secret manifest checked into git |

---

## Verify Your Full Setup

After completing all steps, run this comprehensive verification to confirm everything is working together.

### Automated Verification Script

Save this as `verify-hardening.sh` and run it:

```bash
#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1"; ((FAIL++)); }
warn() { echo "  [WARN] $1"; ((WARN++)); }

echo "=== Agent Hardening Verification ==="
echo ""

# 1. Check Claude Code is installed
echo "-- Claude Code Installation --"
if command -v claude &>/dev/null; then
  pass "Claude Code CLI found: $(claude --version 2>/dev/null | head -1)"
else
  fail "Claude Code CLI not found in PATH"
fi

# 2. Check settings.json exists and has hooks
echo ""
echo "-- Settings & Hooks --"
SETTINGS="$HOME/.claude/settings.json"
if [[ -f "$SETTINGS" ]]; then
  pass "settings.json exists at $SETTINGS"
else
  fail "settings.json not found at $SETTINGS"
fi

if [[ -f "$SETTINGS" ]] && grep -q "PreToolUse" "$SETTINGS" 2>/dev/null; then
  pass "PreToolUse hooks configured"
else
  fail "No PreToolUse hooks found in settings.json"
fi

if [[ -f "$SETTINGS" ]] && grep -q "PostToolUse" "$SETTINGS" 2>/dev/null; then
  pass "PostToolUse hooks configured"
else
  fail "No PostToolUse hooks found in settings.json"
fi

# 3. Check hook files exist
echo ""
echo "-- Hook Files --"
for hook in bash-firewall.js secret-guard.js audit-logger.js; do
  if [[ -f "$HOME/.claude/hooks/$hook" ]]; then
    pass "$hook installed"
  else
    fail "$hook not found at ~/.claude/hooks/$hook"
  fi
done

# 4. Check hook files are valid JS (basic syntax check)
echo ""
echo "-- Hook Syntax --"
for hook in bash-firewall.js secret-guard.js audit-logger.js; do
  HOOK_PATH="$HOME/.claude/hooks/$hook"
  if [[ -f "$HOOK_PATH" ]]; then
    if node --check "$HOOK_PATH" 2>/dev/null; then
      pass "$hook passes syntax check"
    else
      fail "$hook has JavaScript syntax errors"
    fi
  fi
done

# 5. Check sandbox setting
echo ""
echo "-- Sandbox --"
if [[ -f "$SETTINGS" ]] && grep -q '"sandbox"' "$SETTINGS" 2>/dev/null; then
  pass "Sandbox configuration present in settings.json"
else
  warn "No explicit sandbox setting found (may be using default)"
fi

# 6. Check audit log directory
echo ""
echo "-- Audit Logging --"
if [[ -d "$HOME/.claude/audit" ]]; then
  LOGCOUNT=$(find "$HOME/.claude/audit" -name "*.jsonl" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$LOGCOUNT" -gt 0 ]]; then
    pass "Audit directory exists with $LOGCOUNT log file(s)"
  else
    warn "Audit directory exists but no log files yet (run a session first)"
  fi
else
  warn "Audit directory (~/.claude/audit/) not yet created (will be created on first session)"
fi

# 7. Check for .env files in Projects
echo ""
echo "-- Secret Exposure --"
if [[ -d "$HOME/Projects" ]]; then
  ENV_COUNT=$(find "$HOME/Projects" -name ".env" \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/.venv/*" \
    2>/dev/null | wc -l | tr -d ' ')
  if [[ "$ENV_COUNT" -eq 0 ]]; then
    pass "No .env files found in ~/Projects"
  else
    warn "$ENV_COUNT .env file(s) found in ~/Projects — review and move secrets to a credential manager"
    find "$HOME/Projects" -name ".env" \
      -not -path "*/node_modules/*" \
      -not -path "*/.git/*" \
      -not -path "*/.venv/*" \
      2>/dev/null | while read -r f; do echo "        $f"; done
  fi
fi

# 8. Check secret scanners are installed
echo ""
echo "-- Secret Scanners --"
for tool in trufflehog gitleaks; do
  if command -v "$tool" &>/dev/null; then
    pass "$tool installed"
  else
    warn "$tool not installed (install: brew install $tool)"
  fi
done

# 9. Summary
echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Warnings: $WARN"
echo ""
if [[ "$FAIL" -eq 0 ]]; then
  echo "All critical checks passed."
else
  echo "Fix the FAIL items above before using your agent on real projects."
fi
```

Run it:

```bash
chmod +x verify-hardening.sh
./verify-hardening.sh
```

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
- **[Curated References](../references.md)** — 50+ repos, tools, papers, and incident reports
