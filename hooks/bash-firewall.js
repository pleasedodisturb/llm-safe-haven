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
    // "git push -f origin main" or "git push --force origin master"
    if (new RegExp(`\\b${branch}\\b`).test(cmd)) {
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
 * Blocks curl/wget/nc posting sensitive files.
 */
function checkExfiltration(cmd) {
  const hasUploadTool = /\b(curl|wget|nc|ncat|netcat)\b/.test(cmd);
  if (!hasUploadTool) return null;

  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    if (pattern.test(cmd)) {
      const match = cmd.match(pattern);
      return `Blocked: potential exfiltration of sensitive file (matched: ${match[0]})`;
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
  return null;
}

// Hook stdin handler
function main() {
  let input = '';

  // 3-second timeout — if no input, exit silently (allow)
  const timeout = setTimeout(() => {
    process.exit(0);
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
    } catch {
      // Parse error — fail open (allow)
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
