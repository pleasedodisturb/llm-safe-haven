# Hook Examples for Claude Code

Four hooks that harden Claude Code against destructive commands, secret leaks and config-file implants, and keep a forensic audit trail. Zero dependencies beyond Node.js built-ins. They are pattern matchers, not a sandbox: read [Known limitations](#known-limitations) before relying on them.

## What Each Hook Does

### bash-firewall.js (PreToolUse — Bash)

Intercepts every shell command before execution. It normalizes whitespace, splits the command on `;`, `&&`, `||` and `|` (outside quotes), and runs every check on each part. The exfiltration check also runs on the whole command. It blocks:

- `rm` with both recursive and force flags aimed at `/` or `/*`, your home directory (`~`, `$HOME`), or `/home` / `/Users`;
- a force push (`--force`, `-f`, `--force-with-lease`) that names a protected branch, `git reset --hard`, and `git clean` with `-f`. Protected branches come from the `PROTECTED_BRANCHES` environment variable (default `main,master`);
- a `>` or `>>` redirect into `/etc/`, `/usr/`, `/System/` or `/Library/`;
- `chmod 777` that is recursive or aimed at `/`;
- fork bombs;
- `dd` from `/dev/zero`, `/dev/random` or `/dev/urandom` to a `/dev/` device, and any `mkfs`;
- `curl`, `wget`, `nc`, `ncat` or `netcat` in a command that names a sensitive file (`SENSITIVE_FILE_PATTERNS`: `.env`, `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `credentials.json`, `.secret`/`.secrets`, `secret_key.*`);
- a `python -c` / `python3 -c` / `node -e` inline script that names such a file;
- a base64 decode piped to `sh`, `bash` or `zsh`;
- a TLS-verify-disabled `curl`/`wget` download that writes into `/tmp/` (the May 2026 postinstall-worm signature).

It **fails closed**, meaning it blocks, on a command longer than `MAX_COMMAND_CHARS` (100,000 chars), on stdin that has not finished arriving within 3 seconds, and on input that is not valid JSON. Every check runs in linear time, so a long command cannot push the hook past Claude Code's hook timeout (see [Hook Protocol](#hook-protocol)).

### secret-guard.js (PreToolUse — Write|Edit|MultiEdit)

Scans the content of every Write, Edit and MultiEdit before it reaches disk. It detects AWS keys, GitHub tokens (PAT, OAuth, fine-grained, server, refresh), Slack tokens, OpenAI/Anthropic/Stripe keys, private keys, generic API key assignments, hardcoded passwords, and connection strings with embedded credentials. It does not inspect Bash commands or network traffic.

To avoid false positives on test data, some paths are not scanned (the allowlist). Since G-668, the allowlist is anchored to the project root that Claude Code passes to the hook in `CLAUDE_PROJECT_DIR`. A path is skipped only when it lies inside that root AND either:

- a directory below the root is named exactly one of `TEST_DIR_SEGMENTS`: `test`, `tests`, `__tests__`, `fixtures`, `__fixtures__`, `mocks`, `__mocks__`. A directory like `latest/`, a `tests` directory outside the project, or one in the path above the project root does not count; or
- the file name matches `ALLOWLISTED_PATHS`: `*.env.example`, `*.env.template`, `*.env.sample`, `*.test.js/ts/jsx/tsx`, `*.spec.js/ts/jsx/tsx`, and the hook sources `secret-guard.js` and `bash-firewall.js`.

With no absolute `CLAUDE_PROJECT_DIR`, nothing is allowlisted. `CLAUDE.md` and `README.md` are scanned like any other file, unless you set `LSH_SECRET_GUARD_ALLOW_DOCS=1` (exactly `1`); that opt-in skips every file with one of those two names, wherever it is. Content longer than `MAX_CONTENT_CHARS` (1,000,000 chars) is blocked unscanned, and the guard also blocks when stdin has not finished arriving within 3 seconds or is not valid JSON.

### config-guard.js (PreToolUse — Write|Edit|MultiEdit)

Blocks the agent from writing supply-chain execution implants into config files that auto-run code — the vectors abused by the June 2026 Miasma / Mini Shai-Hulud wave. Inspects writes to `binding.gyp` (node-gyp runs it on `npm install` with no postinstall, via GYP command-substitution `<!(...)`), `.github/workflows/*.yml` (privileged-trigger + untrusted-head checkout, secret exfil, the "Run Copilot" workflow), `.vscode/tasks.json` (`runOn:folderOpen` autorun), and `.claude/settings.json` (hook commands on any event, or `type:http` posting off-box). A legitimate edit — a real native addon, a normal dev task, a formatting hook — does not match; it only blocks on execution/network/secret signatures. This is the write-time complement to the point-in-time `scripts/scan-miasma-june2026.sh` scanner.

### audit-logger.js (PostToolUse — all tools)

Logs every tool call that ran to a JSONL file for forensic review. It is a PostToolUse hook, so a call that a PreToolUse hook blocked never reaches it. Records timestamp, session ID, tool name, project, and a truncated input preview. For security, Write/Edit/MultiEdit calls log only the file path, never the content, and Bash calls log no command text (arguments can carry secrets). Audit files are created with 0600 permissions in a 0700 directory. Never blocks or fails visibly.

## Integrity Checksums

The `checksums.json` file contains SHA256 hashes of each hook file. These checksums protect against **post-install tampering** (e.g., an agent modifying hook files after they are deployed to `~/.claude/hooks/`). They do **not** protect against supply-chain attacks — if a compromised version of this package is published to npm, the checksums will match the compromised code. For supply-chain protection, use `npm audit signatures` and pin to a specific version.

## Installation

1. Copy the hook files to your Claude Code hooks directory:

```bash
mkdir -p ~/.claude/hooks
cp hooks/bash-firewall.js ~/.claude/hooks/
cp hooks/secret-guard.js ~/.claude/hooks/
cp hooks/config-guard.js ~/.claude/hooks/
cp hooks/audit-logger.js ~/.claude/hooks/
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
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "node ~/.claude/hooks/config-guard.js"
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

**Timeout:** bash-firewall, secret-guard and config-guard write a block decision if stdin has not finished arriving within 3 seconds; audit-logger exits silently. Separately, Claude Code has its own per-hook timeout (the installer sets 5 seconds). A hook that Claude Code kills at that timeout renders no decision, and the tool call proceeds. That is why bash-firewall and secret-guard cap their input size and run in linear time: they must always finish well inside that timeout.

## Testing

Verify syntax (catches parse errors):
```bash
node -c hooks/bash-firewall.js
node -c hooks/secret-guard.js
node -c hooks/config-guard.js
node -c hooks/audit-logger.js
```

Verify exports (catches runtime errors):
```bash
node -e "const m = require('./hooks/bash-firewall.js'); console.log(Object.keys(m))"
node -e "const m = require('./hooks/secret-guard.js'); console.log(Object.keys(m))"
node -e "const m = require('./hooks/config-guard.js'); console.log(Object.keys(m))"
node -e "const m = require('./hooks/audit-logger.js'); console.log(Object.keys(m))"
```

Test a specific check:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | node hooks/bash-firewall.js
# Output: {"decision":"block","reason":"Blocked: rm -rf targeting root filesystem"}

echo '{"tool_name":"Write","tool_input":{"file_path":"app.js","content":"const key = \"ghp_abc123def456ghi789jkl\""}}' | node hooks/secret-guard.js
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

Both lists apply only to paths inside the project root (`CLAUDE_PROJECT_DIR`).

- `ALLOWLISTED_PATHS` is tested against the file name (basename) only. Anchor new entries with `^` and `$`, so that a longer name that merely contains yours does not match:
  ```javascript
  /^your-file-name\.ext$/,
  ```
- `TEST_DIR_SEGMENTS` lists the directory names whose contents are skipped. A directory must equal an entry exactly; substrings never match.

To allow `CLAUDE.md` and `README.md` to carry secret-shaped strings, set `LSH_SECRET_GUARD_ALLOW_DOCS=1` in the environment Claude Code runs hooks with. Leave it unset unless you have a reason: those files are loaded into agent context.

### Size limits (bash-firewall, secret-guard)

`MAX_COMMAND_CHARS` (bash-firewall, default 100,000) and `MAX_CONTENT_CHARS` (secret-guard, default 1,000,000) set the size above which each hook blocks without analysing. Raising them trades away the timing margin described under [Hook Protocol](#hook-protocol).

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

## Known limitations

These hooks match patterns in the text of one tool call. They are a tripwire for common mistakes and known attack shapes, not a boundary: pair them with the sandbox and permission deny rules.

**bash-firewall**

- **Wrapped commands are not unwrapped before checking (tracked in G-1787).** Commands wrapped in a shell's `-c` argument, in `eval`, or in command substitution, and command names split up by quotes, are not analysed as commands. A command the firewall blocks in plain form can pass when it is wrapped or quoted this way.
- **Download-and-execute is not blocked.** Content fetched by `curl`/`wget` and piped to a shell or passed to `eval` passes. Only a base64 decode piped to `sh`/`bash`/`zsh` is blocked.
- **Writes to `~/.ssh` are not blocked**, including `authorized_keys`. The system-write check covers only `>`/`>>` redirects into `/etc/`, `/usr/`, `/System/` and `/Library/`, and not `tee`, `cp` or `mv`.
- **Environment dumps are not blocked.** `printenv`, `env` and echoing a variable pass, and an agent can read every exported variable.
- **Only the files named by `SENSITIVE_FILE_PATTERNS` count as sensitive.** Uploading any other file passes, for example shell startup or history files, or cloud credential files with other names.
- From the in-code notes on the exfiltration check: exfiltration through DNS lookups, through variables decoded at run time, or split across separate commands is not detected. Inline `python -c` / `node -e` scripts are checked only for sensitive file names, not for network calls.
- **Over-blocking by design:** the checks read the whole command text, including quoted strings, comments and heredoc bodies. A commit message that quotes a blocked pattern can be blocked. Write such text to a file with the Write tool and pass the file instead.

**secret-guard**

- It scans only Write, Edit and MultiEdit content. A secret written through a Bash command (`echo … > file`) or sent over the network is not seen by this hook.
- Allowlisted paths are not scanned at all: a real secret placed in an in-root `tests/` or `fixtures/` directory, or in a `.env.example`, is not caught. Keep a pre-commit scanner such as gitleaks for that.
- Symlinks are not resolved. A symlinked directory named `tests` inside the project root is trusted by its name.
- Outside Claude Code, or whenever `CLAUDE_PROJECT_DIR` is unset or relative, nothing is allowlisted, so the hook blocks more (every test fixture is scanned).
- Detection is pattern-based. Secrets with no pattern in `SECRET_PATTERNS` pass. The connection-string pattern does not match a password longer than 256 chars.
- Content over `MAX_CONTENT_CHARS` is blocked even when it is clean. Write large files in parts.
