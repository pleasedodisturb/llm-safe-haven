'use strict';

/**
 * Auto-discovery registry + aggregation for docs:verify (G-1570).
 *
 * Mirrors lib/mcp/detectors/index.js's structural pattern (readdirSync +
 * shape gate + per-module try/catch auto-discovery), with TWO deliberate
 * divergences from that precedent -- both exist because this subsystem's
 * whole promise is never reporting clean on an unfinished sweep:
 *
 *   1. loadChecks() returns { checks, errors }, never a bare array.
 *      lib/mcp/detectors/index.js:35 swallows a require() failure and
 *      skips the module silently; here, a module that fails to require()
 *      or fails the shape gate pushes { file, reason } onto errors. A
 *      broken check must not vanish while six others run and the sweep
 *      exits 0 or 1 (T-21-01-07).
 *   2. checks is sorted by id with a byte-wise comparison, never
 *      localeCompare -- its collation is locale- and ICU-build-dependent,
 *      which is not a stable total order across machines.
 *
 * Shared helpers live under lib/docs-verify/helpers/ precisely so the
 * top-level .js filter below never sees them and the SKIP set stays a
 * single entry.
 */

const fs = require('fs');
const path = require('path');

const { sanitizeForTerminal } = require('./helpers/sanitize.js');

const EXIT = Object.freeze({ CLEAN: 0, FINDINGS: 1, INCOMPLETE: 2 });

const SKIP = new Set(['index.js']);

function byteCompare(a, b) {
  const as = String(a);
  const bs = String(b);
  return as < bs ? -1 : as > bs ? 1 : 0;
}

/**
 * `dir` defaults to this module's own directory (the real registry). A
 * caller may point this at a temporary directory for testing the
 * require()-failure path without ever dropping a broken file into the
 * real lib/docs-verify/ (tests/docs-verify/cli.test.js).
 */
function loadChecks(dir) {
  const useDir = dir || __dirname;
  const checks = [];
  const errors = [];
  let entries;
  try {
    entries = fs.readdirSync(useDir).filter((f) => f.endsWith('.js') && !SKIP.has(f));
  } catch (err) {
    errors.push({ file: useDir, reason: (err && err.code) || 'read-error' });
    return { checks, errors };
  }
  for (const file of entries) {
    try {
      // eslint-disable-next-line import/no-dynamic-require, global-require
      const mod = require(path.join(useDir, file));
      if (typeof mod.id === 'string' && mod.id !== '' && typeof mod.run === 'function') {
        checks.push(mod);
      } else {
        errors.push({ file, reason: 'invalid-shape' });
      }
    } catch (err) {
      errors.push({ file, reason: (err && err.message) || 'require-failed' });
    }
  }
  checks.sort((a, b) => byteCompare(a.id, b.id));
  return { checks, errors };
}

/**
 * `checks` and `checkErrors` are both optional and independently
 * defaultable to loadChecks()'s own result -- this lets tests inject fake
 * check objects (checks) and/or a fabricated load-error list
 * (checkErrors) without touching the real registry directory or its
 * on-disk state.
 */
function runAll(context, checks, checkErrors) {
  let effectiveChecks = checks;
  let effectiveCheckErrors = checkErrors;
  if (effectiveChecks === undefined || effectiveCheckErrors === undefined) {
    const loaded = loadChecks();
    if (effectiveChecks === undefined) effectiveChecks = loaded.checks;
    if (effectiveCheckErrors === undefined) effectiveCheckErrors = loaded.errors;
  }

  const findings = [];
  const incomplete = [];

  if (!Array.isArray(effectiveChecks) || effectiveChecks.length === 0) {
    incomplete.push({ check: null, reason: 'no-checks-loaded' });
  }

  if (!context || !Array.isArray(context.mdFiles) || context.mdFiles.length === 0) {
    incomplete.push({ check: null, reason: 'no-markdown-discovered' });
  }

  for (const err of effectiveCheckErrors || []) {
    incomplete.push({ check: err.file || null, reason: `check-load-failed: ${err.reason}` });
  }

  for (const err of (context && context.errors) || []) {
    incomplete.push({ check: err.file || null, reason: `context-error: ${err.reason}` });
  }

  for (const check of Array.isArray(effectiveChecks) ? effectiveChecks : []) {
    let result;
    try {
      result = check.run(context);
    } catch (err) {
      incomplete.push({ check: check.id, reason: `check-threw: ${(err && err.message) || 'unknown error'}` });
      continue;
    }
    // Array.isArray(promise) is false -- this branch also catches the
    // accidental-async-check slip (a check.run() that returns a Promise
    // fails Array.isArray exactly like undefined/null/a plain object).
    if (!Array.isArray(result)) {
      incomplete.push({ check: check.id, reason: 'check-returned-non-array' });
      continue;
    }
    findings.push(...result);
  }

  return { findings, incomplete };
}

/**
 * The single findings[] -> severityCounts aggregator on the exit-critical
 * path. Both main() and every test go through this -- no call site builds
 * a severityCounts object by hand.
 */
function tallySeverities(findings) {
  const counts = { fail: 0, warn: 0 };
  for (const f of Array.isArray(findings) ? findings : []) {
    if (f && f.severity === 'fail') counts.fail += 1;
    else if (f && f.severity === 'warn') counts.warn += 1;
  }
  return counts;
}

/**
 * Precedence 2 > 1 > 0: incomplete outranks findings.
 *
 * This DELIBERATELY INVERTS lib/traverse/index.js computeExit()'s
 * fail-before-incomplete ordering. That inversion is correct there
 * because a real compromise finding must never be masked by an
 * unrelated unfinished scan. Here, this gate is wired non-blocking in
 * CI (docs:verify is advisory until Phase 22 turns it green) -- an
 * incomplete sweep's finding count is not trustworthy, and reporting an
 * incomplete sweep as "1 findings" would hide the incompleteness
 * entirely, letting a broken check module or an unreadable target look
 * like an ordinary, fixable drift finding.
 */
function computeExit(input) {
  if (!input || typeof input !== 'object' || Object.prototype.hasOwnProperty.call(input, 'findingCount')) {
    throw new TypeError(
      'computeExit: expected { severityCounts, incomplete } -- the legacy ' +
      '{ findingCount } shape is not supported'
    );
  }
  const { severityCounts, incomplete } = input;
  if (!severityCounts || typeof severityCounts !== 'object') {
    throw new TypeError('computeExit: severityCounts is required -- { fail, warn }');
  }
  const incompleteList = Array.isArray(incomplete) ? incomplete : [];
  if (incompleteList.length > 0) return EXIT.INCOMPLETE;
  const fail = severityCounts.fail || 0;
  if (fail > 0) return EXIT.FINDINGS;
  return EXIT.CLEAN;
}

function formatReport({ findings, incomplete }) {
  const safeFindings = Array.isArray(findings) ? findings : [];
  const safeIncomplete = Array.isArray(incomplete) ? incomplete : [];

  const sorted = safeFindings.slice().sort((a, b) => {
    if (a.file !== b.file) return byteCompare(a.file, b.file);
    const aLine = a.line || 0;
    const bLine = b.line || 0;
    if (aLine !== bLine) return aLine - bLine;
    return byteCompare(a.check, b.check);
  });

  const lines = [];
  for (const f of sorted) {
    // F1 (Codex review, PR #105): every field here is attacker-derived
    // (an on-disk filename or doc-authored text) -- sanitize each one
    // individually at this print choke point so a control byte in ANY
    // one field can never forge or hide a report line. f.line is a
    // number (or defaults to 0), never sanitized text.
    lines.push(
      `${sanitizeForTerminal(f.severity)}  ${sanitizeForTerminal(f.check)}  ${sanitizeForTerminal(f.file)}:${f.line || 0}  ${sanitizeForTerminal(f.message)}`
    );
  }
  if (safeIncomplete.length > 0) {
    lines.push('Incomplete:');
    for (const inc of safeIncomplete) {
      lines.push(`incomplete  ${sanitizeForTerminal(inc.check || '-')}  ${sanitizeForTerminal(inc.reason)}`);
    }
  }
  const fileCount = new Set(safeFindings.map((f) => f.file)).size;
  const checkCount = new Set(safeFindings.map((f) => f.check)).size;
  lines.push(
    `Summary: ${safeFindings.length} findings, ${fileCount} files, ${checkCount} checks with findings, ${safeIncomplete.length} incomplete`
  );
  return lines.join('\n');
}

module.exports = { loadChecks, runAll, tallySeverities, computeExit, formatReport, EXIT };
