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
      return 'Blocked: rm -rf targeting root filesystem (recursive delete of a protected path)';
    }
    // H-5: Block rm -rf targeting home directory
    if (/\s~(\/|\s|$)/.test(cmd) || /\s\$HOME\b/.test(cmd)) {
      return 'Blocked: rm -rf targeting home directory (recursive delete of a protected path)';
    }
    // H-5: Block rm -rf targeting /home/ or /Users/ (all user directories)
    if (/\s\/home(\/|\s|$)/.test(cmd) || /\s\/Users(\/|\s|$)/.test(cmd)) {
      return 'Blocked: rm -rf targeting user directories (recursive delete of a protected path)';
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
 * Wrapped, substituted and quote-spliced forms, DNS substitution and dynamic
 * eval are handled by the structural analysis below (G-1787).
 *
 * Known limitations:
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
    return 'Blocked: base64-decoded content fed to a shell interpreter (base64 -d | sh)';
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
// Structural shell analysis (G-1787)
//
// The checks above match regexes against command text, so a command hidden in
// `sh -c '…'`, `eval`, `$(…)`, backticks or a quote-spliced command word
// (`r''m`) slipped past them. The lexer below parses the shell grammar; the
// analysis re-runs every check on the literal text of each nested command
// string and applies structural rules (credential paths, keychain, decode to
// interpreter, delete targets, hostnames, command words, ~/.ssh writes).
//
// Anything the analysis cannot resolve statically blocks: unterminated syntax,
// nesting deeper than MAX_ANALYSIS_DEPTH, more than MAX_ANALYSED_CHARS of
// nested text, dynamic eval / `sh -c` text, and expansions as the command word.
// Every scanner is iterative and linear-time (see the G-1799 rule above).
// ---------------------------------------------------------------------------

const MAX_ANALYSIS_DEPTH = 8;
const MAX_ANALYSED_CHARS = 400000;

class ShellSyntaxError extends Error {}

/**
 * Index of the character that closes `opener` ('(' or '{'), scanning from
 * `start` (just past the opener). Honours quotes, backticks and nested
 * $( / ${. Returns -1 when unterminated. Iterative: no recursion.
 */
function scanClose(src, start, opener) {
  const stack = [opener];
  let j = start;
  while (j < src.length) {
    const top = stack[stack.length - 1];
    const c = src[j];
    if (top === '"') {
      if (c === '\\') { j += 2; continue; }
      if (c === '"') { stack.pop(); j++; continue; }
      if (c === '`') { stack.push('`'); j++; continue; }
      if (c === '$' && src[j + 1] === '(') { stack.push('('); j += 2; continue; }
      if (c === '$' && src[j + 1] === '{') { stack.push('{'); j += 2; continue; }
      j++;
      continue;
    }
    if (top === '`') {
      if (c === '\\') { j += 2; continue; }
      if (c === '`') stack.pop();
      j++;
      continue;
    }
    if (c === '\\') { j += 2; continue; }
    if (c === "'") {
      const end = src.indexOf("'", j + 1);
      if (end === -1) return -1;
      j = end + 1;
      continue;
    }
    if (c === '"' || c === '`') { stack.push(c); j++; continue; }
    if (c === '$' && (src[j + 1] === '(' || src[j + 1] === '{')) { stack.push(src[j + 1]); j += 2; continue; }
    if (c === top) { stack.push(c); j++; continue; }
    if ((top === '(' && c === ')') || (top === '{' && c === '}')) {
      stack.pop();
      if (stack.length === 0) return j;
    }
    j++;
  }
  return -1;
}

/** Index of the backtick closing one that ends just before `start`, or -1. */
function scanBacktick(src, start) {
  for (let j = start; j < src.length; j++) {
    if (src[j] === '\\') { j++; continue; }
    if (src[j] === '`') return j;
  }
  return -1;
}

function unescapeBacktickBody(body) {
  return body.replace(/\\([\\`$])/g, '$1');
}

const ANSI_C_ESCAPES = {
  n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', v: '\v',
  '\\': '\\', "'": "'", '"': '"', '?': '?',
};

/** Decodes a $'…' string whose body starts at `start`. */
function readAnsiC(src, start) {
  let out = '';
  let j = start;
  while (j < src.length) {
    const c = src[j];
    if (c === "'") return { text: out, end: j };
    if (c !== '\\') { out += c; j++; continue; }
    const d = src[j + 1];
    if (d === undefined) break;
    if (Object.prototype.hasOwnProperty.call(ANSI_C_ESCAPES, d)) { out += ANSI_C_ESCAPES[d]; j += 2; continue; }
    const rest = src.slice(j + 1, j + 11);
    let m;
    if ((m = /^x([0-9a-fA-F]{1,2})/.exec(rest))) {
      out += String.fromCharCode(parseInt(m[1], 16));
    } else if ((m = /^u([0-9a-fA-F]{1,4})/.exec(rest)) || (m = /^U([0-9a-fA-F]{1,8})/.exec(rest))) {
      const cp = parseInt(m[1], 16);
      out += cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    } else if ((m = /^([0-7]{1,3})/.exec(rest))) {
      out += String.fromCharCode(parseInt(m[1], 8) & 0xff);
    } else if ((m = /^c(.)/.exec(rest))) {
      out += String.fromCharCode(m[1].charCodeAt(0) & 0x1f);
    } else {
      out += '\\' + d;
      j += 2;
      continue;
    }
    j += 1 + m[0].length;
  }
  throw new ShellSyntaxError("unterminated $'…' string");
}

function newWord(start) {
  return {
    start, raw: '', text: '', kinds: [], substs: [], procsubs: [],
    dynamic: false, hasSubst: false, unquotedGlob: false, quoted: false, paramSubst: false,
    onlySubst: null,
  };
}

/**
 * Lexes shell source into pipelines of simple commands.
 * A word's `text` is its quote-removed literal, with every expansion kept as
 * its source spelling ($HOME, $(pwd), …) and flagged `dynamic`.
 * Throws ShellSyntaxError on unterminated quotes / substitutions.
 */
function lexShell(src) {
  const pipelines = [];
  const pendingHeredocs = [];
  const n = src.length;
  let pipeline = [];
  let cmd = { words: [], redirects: [], heredocs: [] };
  let word = null;
  let pendingRedirect = null;
  let i = 0;

  const ensure = () => word || (word = newWord(i));
  const pushLit = (text, quoted) => {
    const w = ensure();
    if (quoted) w.quoted = true;
    if (!text) return;
    w.text += text;
    if (w.kinds[w.kinds.length - 1] !== 'lit') w.kinds.push('lit');
  };
  const pushDynamic = (kind, source, body) => {
    const w = ensure();
    w.text += source;
    w.dynamic = true;
    w.kinds.push(kind);
    if (kind === 'subst') { w.hasSubst = true; w.substs.push(body); }
    if (kind === 'procsub') { w.hasSubst = true; w.procsubs.push(body); }
  };

  function readDollar(j, inDq) {
    const next = src[j + 1];
    if (next === '(') {
      const end = scanClose(src, j + 2, '(');
      if (end === -1) throw new ShellSyntaxError('unterminated $( command substitution');
      const body = src.slice(j + 2, end);
      if (body[0] === '(' && src[end - 1] === ')') pushDynamic('arith', src.slice(j, end + 1));
      else pushDynamic('subst', src.slice(j, end + 1), body);
      return end + 1;
    }
    if (next === '{') {
      const end = scanClose(src, j + 2, '{');
      if (end === -1) throw new ShellSyntaxError('unterminated ${ parameter expansion');
      const body = src.slice(j + 2, end);
      pushDynamic('param', src.slice(j, end + 1));
      if (body.includes('$(') || body.includes('`')) word.paramSubst = true;
      return end + 1;
    }
    if (next === "'" && !inDq) {
      const decoded = readAnsiC(src, j + 2);
      pushLit(decoded.text, true);
      return decoded.end + 1;
    }
    if (next === '"' && !inDq) return j + 1; // $"…" locale string: the quote follows
    if (next !== undefined && /[A-Za-z_]/.test(next)) {
      let k = j + 2;
      while (k < n && /[A-Za-z0-9_]/.test(src[k])) k++;
      pushDynamic('param', src.slice(j, k));
      return k;
    }
    if (next !== undefined && /[0-9@*#?$!-]/.test(next)) {
      pushDynamic('param', src.slice(j, j + 2));
      return j + 2;
    }
    pushLit('$', inDq);
    return j + 1;
  }

  function readBacktick(j) {
    const end = scanBacktick(src, j + 1);
    if (end === -1) throw new ShellSyntaxError('unterminated backtick substitution');
    pushDynamic('subst', src.slice(j, end + 1), unescapeBacktickBody(src.slice(j + 1, end)));
    return end + 1;
  }

  function readDouble(j) {
    ensure().quoted = true;
    let k = j + 1;
    let buf = '';
    const flush = () => { if (buf) { pushLit(buf, true); buf = ''; } };
    while (k < n) {
      const c = src[k];
      if (c === '"') { flush(); return k + 1; }
      if (c === '\\') {
        const d = src[k + 1];
        if (d === undefined) break;
        if (d === '\n') { k += 2; continue; }
        if (d === '$' || d === '`' || d === '"' || d === '\\') { buf += d; k += 2; continue; }
        buf += c;
        k++;
        continue;
      }
      if (c === '$') { flush(); k = readDollar(k, true); continue; }
      if (c === '`') { flush(); k = readBacktick(k); continue; }
      buf += c;
      k++;
    }
    throw new ShellSyntaxError('unterminated double quote');
  }

  function endWord(pos) {
    if (!word) return;
    word.raw = src.slice(word.start, pos);
    word.onlySubst = word.kinds.length === 1 && word.kinds[0] === 'subst' ? word.substs[0] : null;
    if (pendingRedirect) {
      const redirect = pendingRedirect;
      pendingRedirect = null;
      redirect.word = word;
      cmd.redirects.push(redirect);
      if (redirect.op === '<<' || redirect.op === '<<-') {
        pendingHeredocs.push({ cmd, delim: word.text, strip: redirect.op === '<<-', quoted: word.quoted });
      }
    } else {
      cmd.words.push(word);
    }
    word = null;
  }

  function endCmd(pos) {
    endWord(pos);
    if (pendingRedirect) throw new ShellSyntaxError('redirection without a target');
    if (cmd.words.length || cmd.redirects.length) pipeline.push(cmd);
    cmd = { words: [], redirects: [], heredocs: [] };
  }

  function endPipeline(pos) {
    endCmd(pos);
    if (pipeline.length) pipelines.push(pipeline);
    pipeline = [];
  }

  function readHeredocs(pos) {
    while (pendingHeredocs.length) {
      const heredoc = pendingHeredocs.shift();
      let body = '';
      while (pos < n) {
        const nl = src.indexOf('\n', pos);
        const line = src.slice(pos, nl === -1 ? n : nl);
        pos = nl === -1 ? n : nl + 1;
        if ((heredoc.strip ? line.replace(/^\t+/, '') : line) === heredoc.delim) break;
        body += line + '\n';
      }
      heredoc.cmd.heredocs.push({ body, quoted: heredoc.quoted });
    }
    return pos;
  }

  function readRedirectOp(j) {
    const three = src.slice(j, j + 3);
    if (three === '<<<' || three === '<<-') return three;
    const two = src.slice(j, j + 2);
    if (['<<', '>>', '<&', '>&', '<>', '>|'].includes(two)) return two;
    return src[j];
  }

  function setRedirect(op) {
    if (pendingRedirect) throw new ShellSyntaxError('redirection without a target');
    pendingRedirect = { op };
  }

  while (i < n) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\r') { endWord(i); i++; continue; }
    if (c === '\n') { endPipeline(i); i = readHeredocs(i + 1); continue; }
    if (c === '\\') {
      if (src[i + 1] === '\n') { i += 2; continue; }
      if (i + 1 < n) { pushLit(src[i + 1], true); i += 2; continue; }
      pushLit('\\', false);
      i++;
      continue;
    }
    if (c === "'") {
      const end = src.indexOf("'", i + 1);
      if (end === -1) throw new ShellSyntaxError('unterminated single quote');
      pushLit(src.slice(i + 1, end), true);
      i = end + 1;
      continue;
    }
    if (c === '"') { i = readDouble(i); continue; }
    if (c === '`') { i = readBacktick(i); continue; }
    if (c === '$') { i = readDollar(i, false); continue; }
    if ((c === '<' || c === '>') && src[i + 1] === '(') {
      const end = scanClose(src, i + 2, '(');
      if (end === -1) throw new ShellSyntaxError('unterminated process substitution');
      pushDynamic('procsub', src.slice(i, end + 1), src.slice(i + 2, end));
      i = end + 1;
      continue;
    }
    if (c === '#' && !word) {
      const nl = src.indexOf('\n', i);
      i = nl === -1 ? n : nl;
      continue;
    }
    if (c === '|') {
      if (src[i + 1] === '|') { endPipeline(i); i += 2; continue; }
      endCmd(i);
      i += src[i + 1] === '&' ? 2 : 1;
      continue;
    }
    if (c === '&') {
      if (src[i + 1] === '&') { endPipeline(i); i += 2; continue; }
      if (src[i + 1] === '>') {
        endWord(i);
        const op = src[i + 2] === '>' ? '&>>' : '&>';
        setRedirect(op);
        i += op.length;
        continue;
      }
      endPipeline(i);
      i++;
      continue;
    }
    if (c === ';') { endPipeline(i); i += src[i + 1] === ';' ? 2 : 1; continue; }
    if (c === '(' || c === ')') { endPipeline(i); i++; continue; }
    if (c === '<' || c === '>') {
      if (word && !word.quoted && !word.dynamic && /^\d+$/.test(word.text)) word = null; // fd prefix
      else endWord(i);
      const op = readRedirectOp(i);
      setRedirect(op);
      i += op.length;
      continue;
    }
    pushLit(c, false);
    if (c === '*' || c === '?' || c === '[') word.unquotedGlob = true;
    i++;
  }
  endPipeline(n);
  readHeredocs(n);
  return { pipelines };
}

// --- Command resolution ----------------------------------------------------

const RESERVED_WORDS = new Set(['{', '}', '!', 'if', 'then', 'else', 'elif', 'fi', 'do', 'done',
  'while', 'until', 'function', 'coproc']);

// Commands that run another command; value = flags that consume the next word.
const WRAPPER_ARG_FLAGS = {
  sudo: new Set(['-u', '-g', '-h', '-p', '-C', '-U', '-r', '-t', '-T', '-D', '-R', '--user', '--group',
    '--host', '--prompt', '--close-from', '--chdir', '--role', '--type', '--other-user', '--command-timeout']),
  busybox: new Set(),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '-C', '-P', '--unset', '--chdir']),
  command: new Set(),
  exec: new Set(['-a']),
  nohup: new Set(),
  nice: new Set(['-n', '--adjustment']),
  time: new Set(['-f', '-o', '--format', '--output']),
  timeout: new Set(['-s', '-k', '--signal', '--kill-after']),
  stdbuf: new Set(['-i', '-o', '-e']),
  xargs: new Set(['-I', '-n', '-P', '-L', '-d', '-E', '-s', '-a', '--arg-file', '--delimiter',
    '--max-args', '--max-procs', '--replace']),
  builtin: new Set(),
  caffeinate: new Set(['-t', '-w']),
};

const isAssignmentWord = (w) => /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/.test(w.raw);

function commandName(text) {
  const slash = text.lastIndexOf('/');
  return slash === -1 ? text : text.slice(slash + 1);
}

function excerpt(text) {
  const clean = String(text).replace(/[\x00-\x1f\x7f]/g, '?');
  return clean.length > 80 ? `${clean.slice(0, 77)}...` : clean;
}

/**
 * Finds the command a simple command actually runs: skips assignments,
 * reserved words and wrappers (sudo, env, timeout, …).
 * Returns { name, args, splitString } or { blocked: reason }.
 */
function resolveCommand(cmd) {
  const words = cmd.words;
  let k = 0;
  let splitString = null;
  const wrappers = [];
  let xargsReplace = false;
  for (;;) {
    while (k < words.length && isAssignmentWord(words[k])) k++;
    while (k < words.length && !words[k].dynamic && RESERVED_WORDS.has(words[k].text)) k++;
    if (k >= words.length) return { name: null, args: [], splitString, wrappers, xargsReplace };
    const w = words[k];
    if (w.dynamic) {
      return { blocked: `Blocked: the command word is an expansion (${excerpt(w.raw)}) — the command ` +
        'to run is not statically known, so the firewall cannot check it' };
    }
    if (w.unquotedGlob) {
      return { blocked: `Blocked: the command word is a glob pattern (${excerpt(w.raw)}) — the command ` +
        'to run is not statically known, so the firewall cannot check it' };
    }
    const name = commandName(w.text);
    const argFlags = WRAPPER_ARG_FLAGS[name];
    if (!argFlags) return { name, word: w, args: words.slice(k + 1), splitString, wrappers, xargsReplace };
    wrappers.push(name);
    k++;
    while (k < words.length && !words[k].dynamic) {
      const t = words[k].text;
      if (t === '--') { k++; break; }
      if (name === 'env' && (t === '-S' || t === '--split-string')) {
        splitString = words[k + 1] || null;
        k += 2;
        continue;
      }
      if (name === 'env' && t.startsWith('--split-string=')) {
        splitString = { text: t.slice('--split-string='.length), dynamic: words[k].dynamic };
        k++;
        continue;
      }
      if (name === 'env' && /^-S./.test(t)) {
        splitString = { text: t.slice(2), dynamic: words[k].dynamic };
        k++;
        continue;
      }
      if (!t.startsWith('-') || t === '-') break;
      if (name === 'xargs' && (t.startsWith('-I') || t.startsWith('-J') || t === '-i' || t.startsWith('--replace'))) {
        xargsReplace = true;
      }
      k += argFlags.has(t) ? 2 : 1;
    }
    // timeout always takes a DURATION operand (any spelling, e.g. 1e3s) before the command.
    if (name === 'timeout' && k < words.length) k++;
    if (splitString) return { name: null, args: [], splitString, wrappers, xargsReplace };
  }
}

// --- Shared predicates -----------------------------------------------------

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'fish']);
const INTERPRETERS = new Set(['node', 'nodejs', 'deno', 'bun', 'perl', 'ruby', 'php', 'osascript',
  'lua', 'source', '.']);
const isInterpreter = (name) => SHELLS.has(name) || INTERPRETERS.has(name) || /^python[0-9.]*$/.test(name);

function parseShellArgs(args) {
  let cFlag = false;
  let sFlag = false;
  let j = 0;
  for (; j < args.length; j++) {
    const w = args[j];
    const t = w.text;
    if (w.dynamic) break;
    if (t === '--' || t === '-') { j++; break; }
    if (t.startsWith('--')) {
      if (t === '--rcfile' || t === '--init-file') j++;
      continue;
    }
    if ((t[0] === '-' || t[0] === '+') && t.length > 1) {
      const letters = t.slice(1);
      if (letters.includes('c')) cFlag = true;
      if (letters.includes('s')) sFlag = true;
      if (/[oO]$/.test(letters)) j++;
      continue;
    }
    break;
  }
  const positional = args.slice(j);
  return {
    script: cFlag ? positional[0] || null : null,
    readsStdin: !cFlag && (positional.length === 0 || sFlag),
  };
}

function interpreterReadsStdin(name, args) {
  if (SHELLS.has(name)) return parseShellArgs(args).readsStdin;
  if (name === 'source' || name === '.') {
    return args.length > 0 && (args[0].text === '-' || args[0].text === '/dev/stdin');
  }
  // Whether the interpreter takes its program from stdin. Option letters mean
  // different things per interpreter and many take a value (python3 -W ignore,
  // node --require x.js), so the table below is per interpreter: a word only
  // counts as the program when it is inline code / a module flag, or a
  // script-file operand that is not an option value. Otherwise: stdin.
  const spec = interpreterOptionSpec(name);
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    const t = w.text;
    if (t === '-' || t === '/dev/stdin') return true;
    if (w.dynamic) return true;
    if (t.startsWith('-')) {
      if (spec.code.test(t)) return false;
      if (spec.values.has(t)) k++;
      continue;
    }
    return !SCRIPT_FILE_RE.test(t);
  }
  return true;
}

// code: an option word that supplies the program inline (or runs a module);
// values: options whose value is the NEXT word.
const INTERPRETER_OPTIONS = {
  python: { code: /^-[bBdEhiIOPqsSuvVx]*[cm]/, values: new Set(['-W', '-X', '--check-hash-based-pycs']) },
  node: { code: /^(-e|-p|--eval|--print)(=|$)/, values: new Set(['-r', '--require', '--import', '--loader',
    '--experimental-loader', '-C', '--conditions', '--input-type', '--env-file', '--title', '--redirect-warnings']) },
  perl: { code: /^-[aclnpstTuUwWX0-9]*[eE]$/, values: new Set(['-I', '-M', '-m', '-x']) },
  ruby: { code: /^-[acdlnpsvwyU]*e$/, values: new Set(['-I', '-r', '-C', '-E', '-K', '-x', '-F']) },
  php: { code: /^-r$/, values: new Set(['-c', '-d', '-z']) },
  osascript: { code: /^-e$/, values: new Set(['-l', '-s']) },
  lua: { code: /^-[e]$/, values: new Set(['-l']) },
  none: { code: /^$/, values: new Set() },
};

function interpreterOptionSpec(name) {
  if (/^python[0-9.]*$/.test(name)) return INTERPRETER_OPTIONS.python;
  if (name === 'node' || name === 'nodejs' || name === 'bun' || name === 'deno') return INTERPRETER_OPTIONS.node;
  return INTERPRETER_OPTIONS[name] || INTERPRETER_OPTIONS.none;
}

const SCRIPT_FILE_RE = /\.(py|pyw|pyz|js|mjs|cjs|ts|mts|cts|jsx|tsx|pl|pm|t|rb|php|scpt|applescript|lua|sh|bash|zsh)$/i;

const FILE_OUTPUT_OPS = new Set(['>', '>>', '>|', '&>', '&>>']);

/** True when this command writes decoded or downloaded bytes to stdout. */
function isContentProducer(name, args, redirects) {
  const texts = args.map((w) => w.text);
  const cluster = (letter) => texts.some((t) => /^-[A-Za-z]+$/.test(t) && t.slice(1).includes(letter));
  const toFile = redirects.some((r) => FILE_OUTPUT_OPS.has(r.op) && r.word.text !== '/dev/stdout');
  switch (name) {
    case 'base64':
    case 'gbase64':
      return cluster('d') || cluster('D') || texts.includes('--decode');
    case 'xxd':
      return cluster('r') || texts.includes('-revert');
    case 'openssl':
      return texts.some((t) => t === 'base64' || t === 'enc' || t === '-base64' || t === '-a') &&
        (texts.includes('-d') || cluster('d'));
    case 'curl': {
      if (toFile) return false;
      // -o/--output only diverts the body when its value is not '-' (stdout).
      for (let k = 0; k < texts.length; k++) {
        const t = texts[k];
        if (t === '--remote-name' || t === '--remote-name-all' || (!t.startsWith('--') && /^-[A-Za-z]*O/.test(t))) return false;
        if (t === '--output') { if (texts[k + 1] !== '-') return false; k++; continue; }
        if (t.startsWith('--output=')) { if (t !== '--output=-') return false; continue; }
        if (!t.startsWith('--') && /^-[A-Za-z]*o/.test(t)) {
          const attached = t.slice(t.indexOf('o') + 1);
          const value = attached || texts[k + 1];
          if (value !== '-') return false;
          if (!attached) k++;
        }
      }
      return true;
    }
    case 'wget':
      return texts.some((t, k) => /^-[A-Za-z]*O-$/.test(t) || t === '--output-document=-' ||
        (/^-[A-Za-z]*O$/.test(t) && texts[k + 1] === '-'));
    default:
      return false;
  }
}

/** True when shell text (a substitution body) runs a content producer. */
function textHasProducer(body, depth) {
  if (depth > MAX_ANALYSIS_DEPTH) return true;
  let parsed;
  try { parsed = lexShell(body); } catch { return true; }
  for (const pipeline of parsed.pipelines) {
    for (const cmd of pipeline) {
      const res = resolveCommand(cmd);
      if (res.name && isContentProducer(res.name, res.args, cmd.redirects)) return true;
      for (const w of cmd.words) {
        for (const inner of [...w.substs, ...w.procsubs]) if (textHasProducer(inner, depth + 1)) return true;
      }
    }
  }
  return false;
}

// Path glob matching without regex construction (linear, no backtracking blow-up).
function segmentMatch(pattern, segment) {
  let pi = 0;
  let si = 0;
  let star = -1;
  let mark = 0;
  while (si < segment.length) {
    if (pi < pattern.length && (pattern[pi] === '?' || pattern[pi] === segment[si])) { pi++; si++; }
    else if (pi < pattern.length && pattern[pi] === '*') { star = pi++; mark = si; }
    else if (star !== -1) { pi = star + 1; si = ++mark; }
    else return false;
  }
  while (pi < pattern.length && pattern[pi] === '*') pi++;
  return pi === pattern.length;
}

function globMatchesPath(glob, path) {
  const g = glob.split('/');
  const p = path.split('/');
  return g.length === p.length && g.every((seg, k) => segmentMatch(seg, p[k]));
}

const bracketsToWildcard = (text) => text.replace(/\[[^\]/]*\]/g, '?');

const HOME_PREFIX_RE = /^(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/]+|\/home\/[^/]+|\/root|\/var\/root)(?:\/(.*))?$/;

/** Path relative to a home directory, '' for the home itself, or null. */
function homeRelative(text) {
  const m = HOME_PREFIX_RE.exec(text);
  return m ? (m[1] || '') : null;
}

const SENSITIVE_HOME_PATHS = [
  '.claude.json', '.claude/.credentials.json', '.codex/auth.json', '.config/goose/config.yaml',
  '.config/goose/secrets.yaml', '.cursor/mcp.json', '.gemini/settings.json', '.gemini/oauth_creds.json',
  '.aws/credentials', '.aws/config', '.npmrc', '.pypirc', '.netrc', '.git-credentials',
  '.docker/config.json', '.kube/config', '.config/gh/hosts.yml', '.zsh_history', '.bash_history',
  '.python_history', '.node_repl_history', '.psql_history', '.mysql_history',
];
const SENSITIVE_HOME_DIRS = ['.ssh', '.gnupg', '.aws', '.codex'];
const DOTENV_NAMES = ['.env', '.env.local', '.env.development', '.env.production', '.env.test', '.envrc'];

function isSensitivePath(text) {
  if (!text) return false;
  const glob = bracketsToWildcard(text);
  const base = glob.slice(glob.lastIndexOf('/') + 1);
  if (DOTENV_NAMES.some((name) => segmentMatch(base, name))) return true;
  const rel = homeRelative(glob);
  if (rel === null || rel === '') return false;
  if (SENSITIVE_HOME_PATHS.some((p) => globMatchesPath(rel, p))) return true;
  const segs = rel.split('/');
  return segs.length >= 2 && SENSITIVE_HOME_DIRS.some((d) => segmentMatch(segs[0], d));
}

/** Strips option / key= / @ prefixes a network tool puts in front of a file path. */
function argPath(text) {
  let t = text;
  const long = /^--?[A-Za-z][A-Za-z0-9-]*=/.exec(t);
  if (long) t = t.slice(long[0].length);
  else if (/^-[A-Za-z]@/.test(t)) t = t.slice(2);
  else {
    const kv = /^[A-Za-z0-9_.-]+=/.exec(t);
    if (kv) t = t.slice(kv[0].length);
  }
  return t.startsWith('@') ? t.slice(1) : t;
}

function textReferencesSensitive(body) {
  let parsed;
  try { parsed = lexShell(body); } catch { return true; }
  return parsed.pipelines.some((p) => p.some((cmd) =>
    cmd.words.some((w) => isSensitivePath(argPath(w.text))) ||
    cmd.redirects.some((r) => isSensitivePath(r.word.text))));
}

function isSshTarget(text) {
  const rel = homeRelative(bracketsToWildcard(text));
  return rel !== null && rel !== '' && segmentMatch(rel.split('/')[0], '.ssh');
}

// --- Rules -------------------------------------------------------------------

const NETWORK_SINKS = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'scp', 'sftp', 'rsync',
  'ftp', 'tftp', 'telnet']);
const SINK_VALUE_FLAGS = {
  scp: new Set(['-i', '-F', '-o', '-P', '-l', '-c', '-J', '-S']),
  sftp: new Set(['-i', '-F', '-o', '-P', '-l', '-c', '-J', '-S']),
  rsync: new Set(['-e', '--rsh']),
};

function sensitiveReference(stage) {
  const { cmd, res } = stage;
  const valueFlags = (res.name && SINK_VALUE_FLAGS[res.name]) || null;
  const words = res.name ? res.args : cmd.words;
  for (let k = 0; k < words.length; k++) {
    const w = words[k];
    if (valueFlags && valueFlags.has(w.text)) { k++; continue; }
    if (isSensitivePath(argPath(w.text))) return w.text;
    for (const body of [...w.substs, ...w.procsubs]) if (textReferencesSensitive(body)) return w.text;
  }
  for (const r of cmd.redirects) {
    if ((r.op === '<' || r.op === '<>') && isSensitivePath(r.word.text)) return r.word.text;
  }
  return null;
}

/** Pipeline-wide rules: credential files near a network sink; content fed to an interpreter. */
function checkPipeline(stages, depth, state) {
  if (stages.some((s) => s.res.name && NETWORK_SINKS.has(s.res.name))) {
    for (const stage of stages) {
      const hit = sensitiveReference(stage);
      if (hit) {
        return `Blocked: credential file sent to the network (${excerpt(hit)}) — agent, cloud, ` +
          'package and shell-history credentials must not leave the machine';
      }
    }
  }
  let producerSeen = false;
  for (let j = 0; j < stages.length; j++) {
    const { cmd, res } = stages[j];
    const earlierProducer = producerSeen;
    if (res.name && isContentProducer(res.name, res.args, cmd.redirects)) producerSeen = true;
    if (!res.name || !isInterpreter(res.name)) continue;
    const reason = `Blocked: decoded or downloaded content fed to an interpreter (${excerpt(res.name)}) — ` +
      'the code that would run cannot be inspected before it runs';
    const readsStdin = j > 0 && interpreterReadsStdin(res.name, res.args);
    if (readsStdin && earlierProducer) return reason;
    if (readsStdin) {
      const prev = stages[j - 1];
      if (SHELLS.has(res.name) && (prev.res.name === 'echo' || prev.res.name === 'printf')) {
        if (prev.res.args.some((w) => w.dynamic)) return dynamicReason(`${prev.res.name} piped into ${res.name}`);
        const piped = analyzeShell(literalOutput(prev.res.name, prev.res.args), depth + 1, state);
        if (piped) return piped;
      } else {
        return `Blocked: unanalysable command (${excerpt(res.name)} reads its script from a pipe whose ` +
          'content cannot be inspected) — the firewall fails closed when it cannot parse a command';
      }
    }
    for (const w of [...res.args, ...cmd.redirects.map((r) => r.word)]) {
      for (const body of [...w.substs, ...w.procsubs]) if (textHasProducer(body, 0)) return reason;
    }
  }
  return null;
}

const ESCAPE_CHARS = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', f: '\f', v: '\v', e: '\x1b', '\\': '\\' };

function decodeEscapes(text) {
  return text.replace(/\\(x[0-9a-fA-F]{1,2}|0?[0-7]{1,3}|[ntrabfve\\])/g, (m, e) => {
    if (e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8) & 0xff);
    return ESCAPE_CHARS[e];
  });
}

/** Text echo/printf would write, with escapes and %-conversions resolved (superset for printf). */
function literalOutput(name, args) {
  const texts = args.map((w) => w.text);
  if (name === 'echo') return decodeEscapes(texts.filter((t) => !/^-[neE]+$/.test(t)).join(' '));
  if (texts.length === 0) return '';
  const rest = texts.slice(1);
  let out = decodeEscapes(texts[0]).replace(/%[-+ #0-9.]*[sbdiqcuxXoeEfgG%]/g, (conv) =>
    conv.endsWith('%') ? '%' : (rest.length ? decodeEscapes(rest.shift()) : ''));
  if (rest.length) out += '\n' + rest.map(decodeEscapes).join('\n');
  return out;
}

function checkKeychain(name, args) {
  if (name !== 'security' || args.length === 0) return null;
  const sub = args[0].text;
  const readsSecret = sub === 'dump-keychain' || sub === 'export' ||
    (/^find-(generic|internet)-password$/.test(sub) &&
      args.slice(1).some((w) => /^-[A-Za-z]*[wg]/.test(w.text) && !w.text.startsWith('--')));
  return readsSecret
    ? `Blocked: macOS keychain secret read (security ${excerpt(sub)}) — keychain passwords must not be read by an agent`
    : null;
}

function trimTrailingSlashes(text) {
  let end = text.length;
  while (end > 1 && text[end - 1] === '/') end--;
  return text.slice(0, end);
}

const PROTECTED_LITERAL_TARGETS = new Set(['/', '/*', '~', '~/*', '.', './*', '..', '../*']);
const PROTECTED_EXPANSION_RE = /^(?:\$HOME|\$\{HOME\}|\$PWD|\$\{PWD\}|\$OLDPWD|\$\{OLDPWD\})(?:\/\*?)?$/;
const PWD_SUBST_RE = /^(?:\$\(\s*pwd(?:\s+-[LP])?\s*\)|`\s*pwd(?:\s+-[LP])?\s*`)(?:\/\*?)?$/;

function substResolvesToProtected(body) {
  let parsed;
  try { parsed = lexShell(body); } catch { return true; }
  return parsed.pipelines.some((p) => p.some((cmd) => {
    const res = resolveCommand(cmd);
    if (!res.name) return false;
    const texts = res.args.map((w) => w.text);
    return res.name === 'pwd' ||
      (res.name === 'git' && texts.includes('rev-parse') && texts.includes('--show-toplevel')) ||
      ((res.name === 'realpath' || res.name === 'readlink') && texts.includes('.'));
  }));
}

function isProtectedDeleteTarget(w) {
  if (w.onlySubst !== null) return substResolvesToProtected(w.onlySubst);
  const t = w.text;
  if (PWD_SUBST_RE.test(t)) return true;
  const trimmed = trimTrailingSlashes(t);
  return PROTECTED_LITERAL_TARGETS.has(trimmed) || PROTECTED_EXPANSION_RE.test(trimmed);
}

function deleteReason(target) {
  return `Blocked: recursive delete of a protected path (${excerpt(target)}) — home, working directory, ` +
    'repository root or filesystem root';
}

function checkRecursiveDelete(name, args, viaXargs) {
  if (name === 'rm') {
    let recursive = false;
    let endOfOptions = false;
    const targets = [];
    for (const w of args) {
      const t = w.text;
      if (!endOfOptions && !w.dynamic && t === '--') { endOfOptions = true; continue; }
      if (!endOfOptions && !w.dynamic && t.startsWith('--')) { if (t === '--recursive') recursive = true; continue; }
      if (!endOfOptions && !w.dynamic && t.length > 1 && t[0] === '-') {
        if (/[rR]/.test(t.slice(1))) recursive = true;
        continue;
      }
      targets.push(w);
    }
    if (!recursive) return null;
    if (viaXargs) return deleteReason('targets supplied at runtime by xargs');
    const hit = targets.find(isProtectedDeleteTarget);
    return hit ? deleteReason(hit.raw) : null;
  }
  if (name === 'find') {
    let k = 0;
    while (k < args.length && (['-H', '-L', '-P'].includes(args[k].text) || /^-O\d$/.test(args[k].text))) k++;
    const paths = [];
    for (; k < args.length; k++) {
      const t = args[k].text;
      if (t.startsWith('-') || t === '(' || t === '!') break;
      paths.push(args[k]);
    }
    const rest = args.slice(k).map((w) => w.text);
    const deletes = rest.includes('-delete') || rest.some((t, j) =>
      (t === '-exec' || t === '-execdir' || t === '-ok') && /^(rm|unlink|shred)$/.test(commandName(rest[j + 1] || '')));
    if (!deletes) return null;
    if (viaXargs) return deleteReason('paths supplied at runtime by xargs');
    if (paths.length === 0) return deleteReason('. (find default)');
    const hit = paths.find(isProtectedDeleteTarget);
    return hit ? deleteReason(hit.raw) : null;
  }
  return null;
}

const HOST_TOOLS = new Set(['dig', 'nslookup', 'host', 'drill', 'ping', 'ping6', 'traceroute', 'traceroute6',
  'tracepath', 'mtr', 'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'whois']);

const CURL_VALUE_SHORT = new Set('AbcCdDeEFHKmoPQrTuUwxXyYz'.split(''));
const CURL_VALUE_LONG = new Set(['--header', '--output', '--data', '--data-raw', '--data-binary', '--data-ascii',
  '--data-urlencode', '--form', '--form-string', '--user', '--user-agent', '--referer', '--cookie', '--cookie-jar',
  '--proxy', '--proxy-user', '--request', '--write-out', '--config', '--cert', '--key', '--cacert', '--capath',
  '--connect-to', '--resolve', '--max-time', '--connect-timeout', '--retry', '--retry-delay', '--upload-file',
  '--output-dir', '--range', '--limit-rate', '--oauth2-bearer', '--interface', '--dns-servers', '--json']);
const WGET_VALUE_SHORT = new Set('oaOeUPTtwQiBlDA'.split(''));
const WGET_VALUE_LONG = new Set(['--output-file', '--append-output', '--output-document', '--execute', '--user-agent',
  '--directory-prefix', '--timeout', '--tries', '--wait', '--quota', '--input-file', '--base', '--level', '--domains',
  '--accept', '--header', '--user', '--password', '--post-data', '--post-file', '--body-data', '--body-file',
  '--method', '--referer', '--load-cookies', '--save-cookies', '--ca-certificate', '--certificate', '--private-key']);

/** Words of a curl/wget command that sit in URL position (option values skipped). */
function urlPositionArgs(name, args) {
  const shortValues = name === 'curl' ? CURL_VALUE_SHORT : WGET_VALUE_SHORT;
  const longValues = name === 'curl' ? CURL_VALUE_LONG : WGET_VALUE_LONG;
  const out = [];
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    const t = w.text;
    if (t === '--url') { if (args[k + 1]) out.push(args[k + 1]); k++; continue; }
    if (t.startsWith('--url=')) { out.push(w); continue; }
    if (t.startsWith('--')) { if (!t.includes('=') && longValues.has(t)) k++; continue; }
    if (t[0] === '-' && t.length > 1 && !w.dynamic) {
      const letters = t.slice(1);
      const at = [...letters].findIndex((ch) => shortValues.has(ch));
      if (at === letters.length - 1) k++;
      continue;
    }
    out.push(w);
  }
  return out;
}

function checkHostnameSubstitution(name, args) {
  if (!HOST_TOOLS.has(name)) return null;
  const candidates = name === 'curl' || name === 'wget'
    ? urlPositionArgs(name, args)
    : args.filter((w) => !w.text.startsWith('-'));
  const hit = candidates.find((w) => w.hasSubst);
  return hit
    ? `Blocked: command substitution in a hostname or network argument of ${name} (${excerpt(hit.raw)}) — ` +
      'a DNS/URL exfiltration channel'
    : null;
}

const COPY_LIKE = new Set(['cp', 'mv', 'install', 'ln', 'rsync', 'ditto']);
const WRITE_REDIRECT_OPS = new Set(['>', '>>', '>|', '&>', '&>>', '<>']);

function sshReason(target) {
  return `Blocked: write into ~/.ssh (${excerpt(target)}) — SSH keys and authorized_keys must not be changed by an agent`;
}

function checkSshWrite(name, args, redirects) {
  for (const r of redirects) if (WRITE_REDIRECT_OPS.has(r.op) && isSshTarget(r.word.text)) return sshReason(r.word.raw);
  if (!name) return null;
  if (name === 'tee') {
    const hit = args.find((w) => !w.text.startsWith('-') && isSshTarget(w.text));
    return hit ? sshReason(hit.raw) : null;
  }
  if (name === 'dd') {
    const hit = args.find((w) => w.text.startsWith('of=') && isSshTarget(w.text.slice(3)));
    return hit ? sshReason(hit.raw) : null;
  }
  if (COPY_LIKE.has(name)) {
    for (let k = 0; k < args.length; k++) {
      const t = args[k].text;
      if ((t === '-t' || t === '--target-directory') && args[k + 1] && isSshTarget(args[k + 1].text)) return sshReason(args[k + 1].raw);
      if (t.startsWith('--target-directory=') && isSshTarget(t.slice(19))) return sshReason(t);
    }
    const operands = args.filter((w) => !w.text.startsWith('-'));
    if (operands.length >= 2 && isSshTarget(operands[operands.length - 1].text)) return sshReason(operands[operands.length - 1].raw);
  }
  return null;
}

function dynamicReason(what) {
  return `Blocked: ${what} runs dynamic text that cannot be analysed before it runs — ` +
    'the firewall fails closed on dynamic command strings';
}

/** Substitutions an unquoted here-document body expands before the command runs. */
function heredocSubstitutions(body) {
  const out = [];
  for (let j = 0; j < body.length; j++) {
    const c = body[j];
    if (c === '\\') { j++; continue; }
    if (c === '$' && body[j + 1] === '(') {
      const end = scanClose(body, j + 2, '(');
      if (end === -1) throw new ShellSyntaxError('unterminated $( in a here-document');
      const inner = body.slice(j + 2, end);
      if (!(inner[0] === '(' && body[end - 1] === ')')) out.push(inner);
      j = end;
      continue;
    }
    if (c === '`') {
      const end = scanBacktick(body, j + 1);
      if (end === -1) throw new ShellSyntaxError('unterminated backtick in a here-document');
      out.push(unescapeBacktickBody(body.slice(j + 1, end)));
      j = end;
    }
  }
  return out;
}

function checkCommand(stage, depth, state) {
  const { cmd, res } = stage;
  if (res.blocked) return res.blocked;
  if (res.splitString) {
    if (res.splitString.dynamic) return dynamicReason('env -S');
    const reason = analyzeShell(res.splitString.text, depth + 1, state);
    if (reason) return reason;
  }
  const name = res.name;
  const viaXargs = (res.wrappers || []).includes('xargs');
  for (const w of cmd.words) {
    if (w.dynamic && /\$\{?IFS\b/.test(w.text)) return dynamicReason(`IFS word splitting (${excerpt(w.raw)})`);
  }
  if (viaXargs && res.xargsReplace && name && (isInterpreter(name) || name === 'eval')) {
    return dynamicReason(`xargs -I substituting runtime text into ${name}`);
  }
  if (name === 'alias') {
    for (const w of res.args) {
      const eq = w.text.indexOf('=');
      if (eq <= 0) continue;
      if (w.dynamic) return dynamicReason('alias');
      const reason = analyzeShell(w.text.slice(eq + 1), depth + 1, state);
      if (reason) return reason;
    }
  }
  if (name === 'find') {
    const texts = res.args.map((w) => w.text);
    for (let k = 0; k < texts.length; k++) {
      if (!['-exec', '-execdir', '-ok', '-okdir'].includes(texts[k])) continue;
      let end = k + 1;
      while (end < texts.length && texts[end] !== ';' && texts[end] !== '+') end++;
      const execCmd = { words: res.args.slice(k + 1, end), redirects: [], heredocs: [] };
      const legacy = runLegacyChecks(execCmd.words.map((w) => w.text).join(' '));
      if (legacy) return legacy;
      const reason = checkCommand({ cmd: execCmd, res: resolveCommand(execCmd) }, depth, state);
      if (reason) return reason;
      k = end;
    }
  }
  if (name && SHELLS.has(name)) {
    const { script, readsStdin } = parseShellArgs(res.args);
    if (readsStdin) {
      for (const r of cmd.redirects) {
        if (r.op !== '<<<') continue;
        if (r.word.dynamic && !r.word.substs.length && !r.word.procsubs.length) return dynamicReason(`${name} <<<`);
        const reason = analyzeShell(r.word.text, depth + 1, state);
        if (reason) return reason;
      }
    }
    if (script) {
      if (script.dynamic) return dynamicReason(`${name} -c`);
      const reason = analyzeShell(script.text, depth + 1, state);
      if (reason) return reason;
    }
    for (const heredoc of cmd.heredocs) {
      const reason = analyzeShell(heredoc.body, depth + 1, state);
      if (reason) return reason;
    }
  } else if (name === 'eval') {
    if (res.args.some((w) => w.dynamic)) return dynamicReason('eval');
    const reason = analyzeShell(res.args.map((w) => w.text).join(' '), depth + 1, state);
    if (reason) return reason;
  }
  if (name) {
    const reason = checkKeychain(name, res.args) || checkRecursiveDelete(name, res.args, viaXargs) ||
      checkHostnameSubstitution(name, res.args);
    if (reason) return reason;
  }
  const sshWrite = checkSshWrite(name, res.args || [], cmd.redirects);
  if (sshWrite) return sshWrite;
  if (!(name && SHELLS.has(name))) {
    for (const heredoc of cmd.heredocs) {
      if (heredoc.quoted) continue;
      for (const body of heredocSubstitutions(heredoc.body)) {
        const reason = analyzeShell(body, depth + 1, state);
        if (reason) return reason;
      }
    }
  }
  for (const w of [...cmd.words, ...cmd.redirects.map((r) => r.word)]) {
    if (w.paramSubst) {
      return 'Blocked: unanalysable command (command substitution inside ${…}) — the firewall fails closed ' +
        'when it cannot parse a command';
    }
    for (const body of [...w.substs, ...w.procsubs]) {
      const reason = analyzeShell(body, depth + 1, state);
      if (reason) return reason;
    }
  }
  return null;
}

function reconstructPipeline(pipeline) {
  return pipeline.map((cmd) => [
    ...cmd.words.map((w) => w.text),
    ...cmd.redirects.map((r) => `${r.op} ${r.word.text}`),
  ].join(' ')).join(' | ');
}

/**
 * Recursive structural analysis. `depth` counts nested command strings
 * (sh -c, eval, substitutions); `state.chars` totals nested text analysed.
 */
function analyzeShell(src, depth, state) {
  if (depth > MAX_ANALYSIS_DEPTH) {
    return `Blocked: nesting depth exceeds ${MAX_ANALYSIS_DEPTH} levels of sh -c / eval / substitution — ` +
      'the firewall fails closed beyond its analysis depth';
  }
  if (depth > 0) {
    state.chars += src.length;
    if (state.chars > MAX_ANALYSED_CHARS) {
      return `Blocked: nested command text exceeds the ${MAX_ANALYSED_CHARS}-char analysis budget — ` +
        'the firewall fails closed on input too large to analyse';
    }
    const legacy = runLegacyChecks(src);
    if (legacy) return legacy;
  }
  let parsed;
  try {
    parsed = lexShell(src);
  } catch (err) {
    if (err instanceof ShellSyntaxError) {
      return `Blocked: unanalysable command (${err.message}) — the firewall fails closed when it cannot parse a command`;
    }
    throw err;
  }
  for (const pipeline of parsed.pipelines) {
    const legacy = runLegacyChecks(reconstructPipeline(pipeline));
    if (legacy) return legacy;
    const stages = pipeline.map((cmd) => ({ cmd, res: resolveCommand(cmd) }));
    const piped = checkPipeline(stages, depth, state);
    if (piped) return piped;
    for (const stage of stages) {
      const reason = checkCommand(stage, depth, state);
      if (reason) return reason;
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
  checkInsecureBinaryDrop,
];

function runChecks(command) {
  if (typeof command !== 'string') {
    return 'Blocked: command is not a string — the bash firewall fails closed on malformed input';
  }
  // G-1799: fail closed on oversized input before any regex runs.
  if (command.length > MAX_COMMAND_CHARS) {
    return `Blocked: command is ${command.length} chars, which exceeds the bash firewall's ` +
      `${MAX_COMMAND_CHARS}-char limit — the firewall fails closed on input too large to ` +
      'analyse in time. Split the command, or use the Write tool for large content.';
  }

  // The regex checks run first and unchanged, so the structural analysis can
  // only add blocks, never remove one.
  const legacy = runLegacyChecks(command);
  if (legacy) return legacy;
  return analyzeShell(command, 0, { chars: 0 });
}

function runLegacyChecks(command) {
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
  runLegacyChecks,
  analyzeShell,
  lexShell,
  hasFlagLetter,
  MAX_COMMAND_CHARS,
  MAX_ANALYSIS_DEPTH,
  MAX_ANALYSED_CHARS,
  PROTECTED_BRANCHES,
  SENSITIVE_FILE_PATTERNS,
};
