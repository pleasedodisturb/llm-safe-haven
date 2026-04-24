#!/usr/bin/env node
// Audit Logger — PostToolUse hook (matcher: all)
// Logs every tool call to JSONL for forensic review.
// Never blocks — this is a passive observer.
//
// Install: copy to ~/.claude/hooks/ and add to settings.json
// Zero dependencies — Node.js built-ins only.

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const AUDIT_DIR = process.env.CLAUDE_AUDIT_DIR || path.join(os.homedir(), '.claude', 'audit');

// Tools whose content must NEVER be logged (security: file contents could contain secrets)
const REDACTED_INPUT_TOOLS = new Set(['Write', 'Edit', 'MultiEdit']);

const INPUT_PREVIEW_MAX = 200;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Ensures the audit directory exists with secure permissions (0o700).
 */
function ensureAuditDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/**
 * Returns today's date as YYYY-MM-DD.
 */
function todayDateString() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/**
 * Builds a safe input preview from tool_input.
 * - For Write/Edit/MultiEdit: only includes file_path (never content/new_string).
 * - For other tools: truncated JSON of input, newlines stripped.
 */
function buildInputPreview(toolName, toolInput) {
  if (!toolInput) return '';

  if (REDACTED_INPUT_TOOLS.has(toolName)) {
    // Only expose the path, never the content
    const filePath = toolInput.file_path || '[unknown]';
    return `file_path: ${filePath}`;
  }

  try {
    let preview = JSON.stringify(toolInput);
    preview = preview.replace(/[\n\r]/g, ' ');
    if (preview.length > INPUT_PREVIEW_MAX) {
      preview = preview.slice(0, INPUT_PREVIEW_MAX) + '...';
    }
    return preview;
  } catch {
    return '[unserializable]';
  }
}

/**
 * Writes a single audit record to the JSONL log file.
 */
function writeAuditRecord(record) {
  try {
    ensureAuditDir(AUDIT_DIR);

    const logFile = path.join(AUDIT_DIR, `${todayDateString()}.jsonl`);
    const line = JSON.stringify(record) + '\n';

    // Append with secure permissions (0o600)
    const fd = fs.openSync(logFile, 'a', 0o600);
    fs.writeSync(fd, line);
    fs.closeSync(fd);
  } catch {
    // Silent fail — audit logging must never break Claude Code
  }
}

/**
 * Builds and writes an audit record from a hook event.
 */
function logToolCall(event) {
  const toolName = event?.tool_name || 'unknown';
  const toolInput = event?.tool_input || {};

  const record = {
    ts: new Date().toISOString(),
    session_id: process.env.CLAUDE_SESSION_ID || 'unknown',
    tool: toolName,
    project: process.env.CLAUDE_PROJECT_DIR || process.cwd(),
    status: 'allowed',
    input_preview: buildInputPreview(toolName, toolInput),
  };

  writeAuditRecord(record);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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
      logToolCall(event);
    } catch {
      // Parse error — fail silently
    }

    process.exit(0);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  AUDIT_DIR,
  REDACTED_INPUT_TOOLS,
  INPUT_PREVIEW_MAX,
  ensureAuditDir,
  todayDateString,
  buildInputPreview,
  writeAuditRecord,
  logToolCall,
};
