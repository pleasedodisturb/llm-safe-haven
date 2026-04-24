# Hook Examples for Claude Code

Three working hooks that harden Claude Code against destructive commands, secret leaks, and provide forensic audit trails. Zero dependencies beyond Node.js built-ins.

## What Each Hook Does

### bash-firewall.js (PreToolUse — Bash)

Intercepts every shell command before execution. Blocks destructive operations (rm -rf /, force push to main, git reset --hard, git clean -f), system file writes, dangerous chmod, fork bombs, disk wipers, and exfiltration of sensitive files via curl/wget/nc. Protected branches are configurable via the `PROTECTED_BRANCHES` environment variable.

### secret-guard.js (PreToolUse — Write|Edit|MultiEdit)

Scans every file write and edit for leaked secrets before the content reaches disk. Detects AWS keys, GitHub tokens (PAT, OAuth, fine-grained, server, refresh), Slack tokens, OpenAI/Anthropic/Stripe keys, private keys, generic API key assignments, hardcoded passwords, and connection strings with embedded credentials. Skips test files, fixtures, and template files (.env.example) to avoid false positives.

### audit-logger.js (PostToolUse — all tools)

Logs every tool call to a JSONL file for forensic review. Records timestamp, session ID, tool name, project, and a truncated input preview. For security, Write/Edit/MultiEdit calls only log the file path — never the content (which could contain secrets). Audit files are created with 0600 permissions in a 0700 directory. Never blocks or fails visibly.

## Installation

1. Copy the hook files to your Claude Code hooks directory:

```bash
mkdir -p ~/.claude/hooks
cp examples/hooks/bash-firewall.js ~/.claude/hooks/
cp examples/hooks/secret-guard.js ~/.claude/hooks/
cp examples/hooks/audit-logger.js ~/.claude/hooks/
chmod +x ~/.claude/hooks/*.js
```

2. Add the hooks to your `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/bash-firewall.js"
          }
        ]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/secret-guard.js"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/audit-logger.js"
          }
        ]
      }
    ]
  }
}
```

An empty `matcher` string matches all tools (used for audit-logger).

## Hook Protocol

Claude Code hooks communicate via stdin/stdout using JSON:

**Input (stdin):** Claude Code sends a JSON object with the tool call details:
```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf /"
  }
}
```

**Blocking (stdout):** To block a tool call, write a JSON object to stdout:
```json
{"decision": "block", "reason": "Blocked: rm -rf targeting root filesystem"}
```

**Allowing:** To allow a tool call, exit silently (no stdout output, exit code 0).

**Timeout:** All hooks implement a 3-second stdin timeout. If no input arrives, they exit silently (allow) to avoid hanging Claude Code.

## Testing

Verify syntax (catches parse errors):
```bash
node -c examples/hooks/bash-firewall.js
node -c examples/hooks/secret-guard.js
node -c examples/hooks/audit-logger.js
```

Verify exports (catches runtime errors):
```bash
node -e "const m = require('./examples/hooks/bash-firewall.js'); console.log(Object.keys(m))"
node -e "const m = require('./examples/hooks/secret-guard.js'); console.log(Object.keys(m))"
node -e "const m = require('./examples/hooks/audit-logger.js'); console.log(Object.keys(m))"
```

Test a specific check:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | node examples/hooks/bash-firewall.js
# Output: {"decision":"block","reason":"Blocked: rm -rf targeting root filesystem"}

echo '{"tool_name":"Write","tool_input":{"file_path":"app.js","content":"const key = \"ghp_abc123def456ghi789jkl\""}}' | node examples/hooks/secret-guard.js
# Output: {"decision":"block","reason":"Secret detected in app.js:\n  - GitHub Personal Access Token (line 1)\n\nMove secrets to environment variables or a credential manager."}
```

## Customization

### Adding protected branches (bash-firewall)

Set the `PROTECTED_BRANCHES` environment variable (comma-separated):
```bash
export PROTECTED_BRANCHES="main,master,production,staging"
```

Default: `main,master`.

### Adding secret patterns (secret-guard)

Add entries to the `SECRET_PATTERNS` array in `secret-guard.js`:
```javascript
{ pattern: /your-regex-here/, name: 'Description of the secret type' },
```

### Adding allowlisted paths (secret-guard)

Add entries to the `ALLOWLISTED_PATHS` array to skip scanning for specific file patterns:
```javascript
/your-path-pattern/,
```

### Changing the audit directory (audit-logger)

Set the `CLAUDE_AUDIT_DIR` environment variable:
```bash
export CLAUDE_AUDIT_DIR=/path/to/audit/logs
```

Default: `~/.claude/audit/`.

### Sensitive file patterns (bash-firewall)

Add entries to the `SENSITIVE_FILE_PATTERNS` array to catch additional exfiltration targets:
```javascript
/your-file-pattern/,
```
