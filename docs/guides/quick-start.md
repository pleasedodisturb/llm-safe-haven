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

## What's Next

You've covered the basics. For deeper hardening:

- **[Full Threat Model](../threat-model.md)** — OWASP Agentic Top 10 mapped to solo dev setups, with real incidents
- **[Claude Code Deep Dive](../hardening/claude-code.md)** — advanced hook patterns, sandbox configuration, permission tuning
- **[Credential Management](../credential-management.md)** — why env vars fundamentally fail, credential proxy architecture
- **[Curated References](../references.md)** — 25+ repos, tools, papers, and incident reports
