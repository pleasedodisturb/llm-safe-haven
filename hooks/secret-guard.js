#!/usr/bin/env node
// Secret Guard — PreToolUse hook (matcher: Write|Edit|MultiEdit)
// Scans content being written/edited for leaked secrets.
// Output: {"decision":"block","reason":"..."} to block, or exit silently to allow.
//
// Install: copy to ~/.claude/hooks/ and add to settings.json
// Zero dependencies — Node.js built-ins only.

'use strict';

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
  { pattern: /\bsk-ant-[A-Za-z0-9\-_]{80,}\b/, name: 'Anthropic API Key' },
  { pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/, name: 'Stripe Live Secret Key' },
  { pattern: /\brk_live_[A-Za-z0-9]{24,}\b/, name: 'Stripe Live Restricted Key' },
  { pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, name: 'Private Key' },
  { pattern: /(?:api_key|apikey|api_secret|access_token|auth_token|secret_key)\s*[=:]\s*["'][A-Za-z0-9\-_\.]{20,}["']/i, name: 'Generic API Key/Token assignment' },
  { pattern: /(?:password|passwd)\s*[=:]\s*["'][^"'\s]{8,}["']/i, name: 'Hardcoded password' },
  { pattern: /:\/\/[^:]+:[^@\s]+@[^/\s]+/, name: 'Connection string with embedded credentials' },
];

const ALLOWLISTED_PATHS = [
  /\.env\.example$/,
  /\.env\.template$/,
  /\.env\.sample$/,
  /CLAUDE\.md$/,
  /README\.md$/,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /tests?\//,
  /__tests__\//,
  /fixtures?\//,
  /mocks?\//,
  /secret-guard\.js$/,
  /bash-firewall\.js$/,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if the given file path is in the allowlist.
 */
function isAllowlisted(filePath) {
  if (!filePath) return false;
  return ALLOWLISTED_PATHS.some((re) => re.test(filePath));
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

function checkForSecrets(toolName, toolInput) {
  const extracted = extractFromToolInput(toolName, toolInput);
  if (!extracted) return null;

  const { content, filePath } = extracted;

  // Skip allowlisted paths
  if (isAllowlisted(filePath)) return null;

  const findings = scanContent(content);
  if (findings.length === 0) return null;

  const details = findings
    .map((f) => `  - ${f.name} (line ${f.line})`)
    .join('\n');

  return `Secret detected in ${filePath || 'unknown file'}:\n${details}\n\nMove secrets to environment variables or a credential manager.`;
}

function main() {
  let input = '';

  const timeout = setTimeout(() => {
    process.exit(0);
  }, 3000);

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    clearTimeout(timeout);

    try {
      const event = JSON.parse(input);
      const toolName = event?.tool_name || '';
      const toolInput = event?.tool_input || {};

      const reason = checkForSecrets(toolName, toolInput);
      if (reason) {
        process.stdout.write(JSON.stringify({ decision: 'block', reason }));
      }
    } catch {
      // Parse error — fail open (allow)
    }

    process.exit(0);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  SECRET_PATTERNS,
  ALLOWLISTED_PATHS,
  isAllowlisted,
  scanContent,
  extractFromToolInput,
  checkForSecrets,
};
