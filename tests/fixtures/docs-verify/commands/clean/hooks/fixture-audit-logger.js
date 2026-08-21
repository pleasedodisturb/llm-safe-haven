'use strict';

// A miniature stand-in for the real hooks/audit-logger.js (G-1570, 21-04).
// Composes the fixture "audit directory" from TWO quoted string-literal
// arguments to path.join -- a dot-claude segment and a further named
// segment -- with a non-literal first argument (os.homedir()), mirroring
// the real file's exact shape (`path.join(os.homedir(), '.claude',
// 'audit')`) so Check 6's composition-evidence tier has something real to
// grade. The per-day filename is a template literal, never a plain quoted
// string literal, matching the real file's date-shaped naming too.

const os = require('os');
const path = require('path');

const FIXTURE_AUDIT_DIR = process.env.FIXTURE_AUDIT_DIR || path.join(os.homedir(), '.claude', 'fixture-audit');

function todayDateString() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function fixtureLogFilePath() {
  return path.join(FIXTURE_AUDIT_DIR, `${todayDateString()}.jsonl`);
}

module.exports = { FIXTURE_AUDIT_DIR, todayDateString, fixtureLogFilePath };
