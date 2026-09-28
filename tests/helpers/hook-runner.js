'use strict';

// Spawns a REAL hook file (hooks/<name>.js) as Claude Code does: a fresh node
// process fed the tool event as JSON on stdin. Used for end-to-end proof and
// for the G-1799 timing batteries, where the in-process call would not show
// what matters (a hook killed by the harness timeout renders no decision, and
// Claude Code lets the tool call proceed).
//
// Fail-closed reading of the result: a killed, crashed or garbled run is
// 'error', never 'allow'. 'allow' requires empty stdout, exit status 0 and no
// signal; 'block' requires stdout that parses to { decision: 'block' }.
//
// Lives under tests/helpers/ (outside the `tests/*.test.js` glob) so the test
// runner never picks it up as a test file.

const { spawnSync } = require('child_process');
const path = require('path');

const HOOKS_DIR = path.join(__dirname, '..', '..', 'hooks');

function defaultEnv() {
  const env = { ...process.env };
  // Tests must be deterministic: never inherit the ambient project root or
  // the secret-guard docs opt-in from the session that runs the suite.
  delete env.CLAUDE_PROJECT_DIR;
  delete env.LSH_SECRET_GUARD_ALLOW_DOCS;
  return env;
}

function classify(res) {
  const stdout = typeof res.stdout === 'string' ? res.stdout : '';
  if (res.error || res.signal) return { decision: 'error', reason: null };
  if (stdout.length > 0) {
    let parsed = null;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return { decision: 'error', reason: null };
    }
    if (parsed && typeof parsed === 'object' && parsed.decision === 'block') {
      return { decision: 'block', reason: typeof parsed.reason === 'string' ? parsed.reason : '' };
    }
    return { decision: 'error', reason: null };
  }
  if (res.status === 0) return { decision: 'allow', reason: null };
  return { decision: 'error', reason: null };
}

/**
 * Run hooks/<hookFile> with `event` on stdin.
 * @param {string} hookFile  e.g. 'bash-firewall.js'
 * @param {object} event     tool event, serialised with JSON.stringify
 * @param {{timeoutMs?: number, env?: object}} [opts]
 * @returns {{decision: 'block'|'allow'|'error', reason: string|null,
 *            status: number|null, signal: string|null, elapsedMs: number, stdout: string}}
 */
function runHook(hookFile, event, opts = {}) {
  const hookPath = path.join(HOOKS_DIR, hookFile);
  const timeoutMs = opts.timeoutMs === undefined ? 4500 : opts.timeoutMs;
  const env = opts.env || defaultEnv();
  const started = process.hrtime.bigint();
  const res = spawnSync(process.execPath, [hookPath], {
    input: JSON.stringify(event),
    encoding: 'utf8',
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const { decision, reason } = classify(res);
  return {
    decision,
    reason,
    status: res.status,
    signal: res.signal || null,
    elapsedMs,
    stdout: typeof res.stdout === 'string' ? res.stdout : '',
  };
}

/** Convenience: run bash-firewall.js on a Bash tool event for `command`. */
function runFirewall(command, opts) {
  return runHook('bash-firewall.js', { tool_name: 'Bash', tool_input: { command } }, opts);
}

module.exports = { runHook, runFirewall, classify, defaultEnv, HOOKS_DIR };
