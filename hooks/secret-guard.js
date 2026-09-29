#!/usr/bin/env node
// Secret Guard — PreToolUse hook (matcher: Write|Edit|MultiEdit)
// Scans content being written/edited for leaked secrets.
// Output: {"decision":"block","reason":"..."} to block, or exit silently to allow.
//
// Install: copy to ~/.claude/hooks/ and add to settings.json
// Zero dependencies — Node.js built-ins only.

'use strict';

const path = require('path');

const SECRET_PATTERNS = [
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS Access Key ID' },
  { pattern: /\bghp_[A-Za-z0-9_]{20,}\b/, name: 'GitHub Personal Access Token' },
  { pattern: /\bgho_[A-Za-z0-9_]{20,}\b/, name: 'GitHub OAuth Token' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{22,82}\b/, name: 'GitHub Fine-Grained PAT' },
  { pattern: /\bghs_[A-Za-z0-9_]{36}\b/, name: 'GitHub Server Token' },
  { pattern: /\bghr_[A-Za-z0-9_]{36}\b/, name: 'GitHub Refresh Token' },
  { pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}\b/, name: 'Slack Bot Token' },
  { pattern: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}\b/, name: 'Slack User Token' },
  { pattern: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/, name: 'OpenAI API Key' },
  { pattern: /\bsk-proj-[A-Za-z0-9\-_]{40,}\b/, name: 'OpenAI API Key (project)' },
  { pattern: /\bsk-ant-[A-Za-z0-9\-_]{80,}\b/, name: 'Anthropic API Key' },
  { pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/, name: 'Stripe Live Secret Key' },
  { pattern: /\brk_live_[A-Za-z0-9]{24,}\b/, name: 'Stripe Live Restricted Key' },
  { pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, name: 'Private Key' },
  { pattern: /(?:api_key|apikey|api_secret|access_token|auth_token|secret_key)\s*[=:]\s*["'][A-Za-z0-9\-_\.]{20,}["']/i, name: 'Generic API Key/Token assignment' },
  { pattern: /(?:password|passwd)\s*[=:]\s*["'][^"'\s]{8,}["']/i, name: 'Hardcoded password' },
  // G-1799: linear form. The user part excludes whitespace, ':' and '/', so
  // it ends at the ':' that must follow it and each '://' start scans at most
  // to the next '/' or ':'. The password part is bounded ({1,256}) and
  // excludes '@', so it never competes with the '@' after it. (The old
  // `[^:]+:[^@\s]+` form was quadratic on a repeated '://a:' run: a
  // 200,000-char line outlived Claude Code's hook timeout.) Passwords that
  // contain a raw '/' are still caught; the only shapes the old form matched
  // and this one does not have whitespace or '/' in the user part, or a
  // password over 256 chars.
  { pattern: /:\/\/[^\s:/]+:[^\s@]{1,256}@[^/\s]+/, name: 'Connection string with embedded credentials' },
];

// G-1799: content above this size is blocked (fail closed) instead of being
// scanned. A hook killed by Claude Code's per-hook timeout renders no decision
// and the Write proceeds, so the scan must always finish well inside it.
const MAX_CONTENT_CHARS = 1000000;

// G-668: the allowlist is anchored to the project root. A path is exempt from
// scanning only when it lies inside CLAUDE_PROJECT_DIR (set by Claude Code in
// the hook's environment, never by the agent's own tool calls) AND either
//   - a DIRECTORY segment of its root-relative path equals one of
//     TEST_DIR_SEGMENTS exactly (so latest/, contests/ or /tmp/tests/ do not
//     count, and neither does a tests segment in the root's own path), or
//   - its basename matches ALLOWLISTED_PATHS (template env files, *.test.*,
//     *.spec.*, and this repo's own hook sources).
// With no absolute project root, nothing is allowlisted (fail closed).
// CLAUDE.md and README.md are scanned unless LSH_SECRET_GUARD_ALLOW_DOCS is
// exactly '1'. Symlinks are not resolved: a symlinked tests/ dir inside the
// root is trusted by its name.
//
// M-3: Security note — allowlisted test files are NOT scanned, so a real
// secret placed in in-root test code is not caught here. Enforce secret
// hygiene in test code with a pre-commit scanner (e.g., gitleaks, trufflehog).
const TEST_DIR_SEGMENTS = ['test', 'tests', '__tests__', 'fixtures', '__fixtures__', 'mocks', '__mocks__'];

const DOC_BASENAMES = ['CLAUDE.md', 'README.md'];

// Tested against the BASENAME only, and only for paths inside the project root.
const ALLOWLISTED_PATHS = [
  /\.env\.example$/,
  /\.env\.template$/,
  /\.env\.sample$/,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /^secret-guard\.js$/,
  /^bash-firewall\.js$/,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The project root from the hook environment: an absolute, non-empty
 * CLAUDE_PROJECT_DIR (normalised), otherwise null.
 */
function resolveProjectRoot(env) {
  const raw = env && typeof env.CLAUDE_PROJECT_DIR === 'string' ? env.CLAUDE_PROJECT_DIR : '';
  if (!raw || !path.isAbsolute(raw)) return null;
  return path.resolve(raw);
}

/**
 * Returns true if filePath is allowlisted relative to projectRoot (G-668).
 * Missing or relative root, a path outside the root, or the root itself: false.
 */
function isAllowlisted(filePath, projectRoot) {
  if (!filePath || typeof filePath !== 'string') return false;
  if (!projectRoot || typeof projectRoot !== 'string' || !path.isAbsolute(projectRoot)) return false;

  const root = path.resolve(projectRoot);
  const rel = path.relative(root, path.resolve(root, filePath));
  if (!rel || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return false;

  const segments = rel.split(path.sep);
  const basename = segments.pop();
  if (segments.some((seg) => TEST_DIR_SEGMENTS.includes(seg))) return true;
  return ALLOWLISTED_PATHS.some((re) => re.test(basename));
}

/**
 * Scans text for secret patterns.
 * Returns an array of { name, line } objects for each match found.
 */
function scanContent(content) {
  if (!content) return [];

  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of SECRET_PATTERNS) {
      if (pattern.test(lines[i])) {
        findings.push({ name, line: i + 1 });
      }
    }
  }

  return findings;
}

/**
 * Extracts content and file path from tool_input based on the tool name.
 * Returns { content, filePath } or null if nothing to scan.
 */
function extractFromToolInput(toolName, toolInput) {
  if (!toolInput) return null;

  switch (toolName) {
    case 'Write': {
      return {
        content: toolInput.content || '',
        filePath: toolInput.file_path || '',
      };
    }
    case 'Edit': {
      return {
        content: toolInput.new_string || '',
        filePath: toolInput.file_path || '',
      };
    }
    case 'MultiEdit': {
      // MultiEdit has an edits array, each with new_string
      const edits = toolInput.edits || [];
      const combined = edits.map((e) => e.new_string || '').join('\n');
      return {
        content: combined,
        filePath: toolInput.file_path || '',
      };
    }
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function checkForSecrets(toolName, toolInput, env = process.env) {
  const extracted = extractFromToolInput(toolName, toolInput);
  if (!extracted) return null;

  const { content, filePath } = extracted;
  const hookEnv = env || {};

  // G-668: CLAUDE.md / README.md only with the explicit opt-in (exactly '1').
  if (hookEnv.LSH_SECRET_GUARD_ALLOW_DOCS === '1' && DOC_BASENAMES.includes(path.basename(filePath))) {
    return null;
  }

  // G-668: allowlist anchored to path segments inside the project root.
  if (isAllowlisted(filePath, resolveProjectRoot(hookEnv))) return null;

  // G-1799: fail closed on content too large to scan in time.
  if (content.length > MAX_CONTENT_CHARS) {
    return `Blocked: content for ${filePath || 'unknown file'} is ${content.length} chars, which exceeds ` +
      `secret guard's ${MAX_CONTENT_CHARS}-char limit — the guard fails closed on content too large ` +
      'to scan in time. Write the file in smaller parts.';
  }

  const findings = scanContent(content);
  if (findings.length === 0) return null;

  const details = findings
    .map((f) => `  - ${f.name} (line ${f.line})`)
    .join('\n');

  return `Secret detected in ${filePath || 'unknown file'}:\n${details}\n\nMove secrets to environment variables or a credential manager.`;
}

function main() {
  let input = '';

  // 3-second timeout — fail closed for security (C-4 fix)
  const timeout = setTimeout(() => {
    process.stdout.write(JSON.stringify({
      decision: 'block',
      reason: 'Secret guard timed out waiting for input — blocking as precaution',
    }));
    process.exit(1);
  }, 3000);

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    clearTimeout(timeout);

    try {
      const event = JSON.parse(input);
      const toolName = event?.tool_name || '';
      const toolInput = event?.tool_input || {};

      const reason = checkForSecrets(toolName, toolInput, process.env);
      if (reason) {
        process.stdout.write(JSON.stringify({ decision: 'block', reason }));
      }
    } catch (err) {
      // Parse error — fail closed for security (C-3 fix)
      process.stdout.write(JSON.stringify({
        decision: 'block',
        reason: `Secret guard failed to parse input: ${err.message}. Blocking as precaution.`,
      }));
    }

    process.exit(0);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  SECRET_PATTERNS,
  MAX_CONTENT_CHARS,
  ALLOWLISTED_PATHS,
  TEST_DIR_SEGMENTS,
  DOC_BASENAMES,
  resolveProjectRoot,
  isAllowlisted,
  scanContent,
  extractFromToolInput,
  checkForSecrets,
};
