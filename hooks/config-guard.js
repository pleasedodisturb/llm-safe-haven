#!/usr/bin/env node
// Config Guard — PreToolUse hook (matcher: Write|Edit|MultiEdit)
// Blocks the agent from writing supply-chain execution implants into config
// files that auto-run code — the vectors the June 2026 "Miasma" / Mini
// Shai-Hulud wave abused:
//
//   - binding.gyp        → node-gyp runs it on `npm install` (no postinstall needed)
//   - .github/workflows  → privileged-trigger + untrusted checkout / secret exfil
//   - .vscode/tasks.json → runOn:folderOpen auto-executes on folder open
//   - .claude/settings.json hooks → SessionStart/PreToolUse/... auto-execute
//
// A legitimate edit to these files (a real native addon, a normal dev task, a
// formatting hook) does NOT match — we only block on execution/network/secret
// signatures. Defense-in-depth against prompt-injection-driven self-sabotage.
//
// Output: {"decision":"block","reason":"..."} to block, or exit silently to allow.
// Install: copy to ~/.claude/hooks/ and add to settings.json (PreToolUse).
// Zero dependencies — Node.js built-ins only.

'use strict';

// ---------------------------------------------------------------------------
// Config-file classifiers (by file path)
// ---------------------------------------------------------------------------
const TARGETS = {
  bindingGyp: /(^|\/)binding\.gyp$/,
  workflow: /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/,
  vscodeTasks: /(^|\/)\.vscode\/tasks\.json$/,
  claudeSettings: /(^|\/)\.claude\/settings(\.local)?\.json$/,
};

// Paths we never scan — this hook's own source and test fixtures, to avoid
// self-trips (mirrors secret-guard.js's allowlist approach).
// Only the hook's own source and test/spec FILES are allowlisted — NOT whole
// test/fixture directories. A malicious binding.gyp or settings.json is still
// worth blocking even under a tests/ path, and config-guard's own tests call
// the functions directly (they never round-trip through a real file).
const ALLOWLISTED_PATHS = [
  /config-guard\.js$/,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
];

// ---------------------------------------------------------------------------
// Per-target danger signatures
// ---------------------------------------------------------------------------

// GYP command-substitution executes a shell command when node-gyp processes
// the file. Legit native addons (e.g. sharp) DO use <!(node -p "require(...)")
// to read build config — that alone is not malicious. We only flag a <!() that
// ALSO carries a danger token: network fetch, base64/eval, output suppression,
// or the "&& echo <stub>" trick the Phantom Gyp payload uses.
const GYP_SUBST = /<!@?\(/;
const GYP_DANGER = /\bcurl\b|\bwget\b|base64|\beval\b|fromCharCode|Invoke-WebRequest|>\s*\/dev\/null|&&\s*echo/;
const GYP_EXEC = /"(sh|bash|cmd|powershell|curl|wget|nc|eval)"|node\s+-e/;

// Secret-scrape / dead-drop signatures — the actual Miasma workflow IOC. A bare
// `curl | sh` is NOT included: it is the standard way legit CI installs rustup,
// bun, nvm, sentry-cli, so blocking it would be a constant false positive.
const SECRET_SCRAPE = /"isSecret"\s*:\s*true|Runner\.Worker|169\.254\.169\.254|liuende501/;
// Kept in sync with scan-miasma-june2026.sh WF_UNTRUSTED_CHECKOUT_RE.
const WF_UNTRUSTED_CHECKOUT = /github\.event\.pull_request\.head\.(sha|ref)|github\.event\.workflow_run\.head_(branch|sha)|github\.head_ref/;

// Exec/network/dead-drop signatures shared by both auto-run contexts.
const EXEC_NET = /(curl|wget)\b[^|&;\n]*\|\s*(ba)?sh\b|base64\s+(-d|--decode)\b[^|\n]*\|\s*(ba)?sh\b|eval\s+\$?\(?\s*(curl|wget|echo)|node\s+-e\b|\/tmp\/[^"\s]*\.(sh|py|mjs|lock)|liuende501|169\.254\.169\.254|thebeautifulmarchoftime/;
// The specific Miasma payload entrypoints — `.claude/setup.mjs`, `.github/setup.js`.
// Matching the FILE (not the whole .claude/ dir) avoids flagging the normal case
// of a hook command that points at ~/.claude/hooks/<something>.js.
const SETUP_IMPLANT = /[./]\.?(claude|github)\/setup\.(mjs|js|cjs|sh)\b/;

// Hook commands (.claude/settings.json, any event): exec/net + the setup implant.
// Deliberately does NOT match a bare `.claude/` reference — canonical hooks live
// in ~/.claude/hooks/ and a normal `node ~/.claude/hooks/x.js` command is fine.
function hookCmdDanger(cmd) {
  return EXEC_NET.test(cmd) || SETUP_IMPLANT.test(cmd);
}
// folderOpen tasks are stricter: a dev-server autorun has no business referencing
// .claude/ or invoking any setup script, so flag those too.
function autorunDanger(cmd) {
  return hookCmdDanger(cmd) || /\.claude\//.test(cmd) || /setup\.(mjs|js|sh)\b/.test(cmd);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isAllowlisted(filePath) {
  if (!filePath) return false;
  return ALLOWLISTED_PATHS.some((re) => re.test(filePath));
}

/**
 * Classifies the file path into one of the TARGETS keys, or null.
 */
function classify(filePath) {
  if (!filePath) return null;
  for (const [key, re] of Object.entries(TARGETS)) {
    if (re.test(filePath)) return key;
  }
  return null;
}

/**
 * Returns true if a .vscode/tasks.json body has a folderOpen autorun whose
 * command carries a danger signature.
 */
function tasksJsonIsDangerous(content) {
  if (!/"runOn"\s*:\s*"folderOpen"/.test(content)) return false;
  // Examine each "command": "..." value.
  const re = /"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (autorunDanger(m[1])) return true;
  }
  return false;
}

/**
 * Returns true if a .claude/settings.json body wires a hook command (any event)
 * that carries a danger signature, or an http hook posting off-box.
 */
function settingsJsonIsDangerous(content) {
  const cmdRe = /"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = cmdRe.exec(content)) !== null) {
    if (hookCmdDanger(m[1])) return true;
  }
  // type:"http" hook to a non-localhost URL. Anchor the host boundary so
  // `localhost.evil.com` / `127.0.0.1.attacker.net` are NOT treated as local.
  if (/"type"\s*:\s*"http"/.test(content)) {
    const urlRe = /"url"\s*:\s*"(https?:\/\/[^"]+)"/g;
    let u;
    while ((u = urlRe.exec(content)) !== null) {
      if (!/^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(u[1])) return true;
    }
  }
  return false;
}

/**
 * Returns true if a workflow YAML body carries an injection/exfil signature.
 */
function workflowIsDangerous(content) {
  if (/^\s*name:\s*["']?Run Copilot/m.test(content)) return true;
  if (SECRET_SCRAPE.test(content)) return true;
  if (/pull_request_target|workflow_run/.test(content) && WF_UNTRUSTED_CHECKOUT.test(content)) return true;
  return false;
}

/**
 * Returns true if a binding.gyp body carries an exec signature. A bare
 * command-substitution that only reads config (sharp-style `<!(node -p ...)`)
 * is allowed; we require a danger token on a substitution line, or an
 * action/rule array that shells out.
 */
function bindingGypIsDangerous(content) {
  if (GYP_EXEC.test(content)) return true;
  const lines = content.split('\n');
  for (const line of lines) {
    if (GYP_SUBST.test(line) && GYP_DANGER.test(line)) return true;
  }
  return false;
}

/**
 * Core check: given a target type and content, return a human-readable reason
 * string if the write should be blocked, or null to allow.
 */
function checkConfig(target, content, filePath) {
  if (!content) return null;
  let dangerous = false;
  let what = '';

  switch (target) {
    case 'bindingGyp':
      dangerous = bindingGypIsDangerous(content);
      what = 'binding.gyp build config (node-gyp auto-runs this on `npm install` — no postinstall needed)';
      break;
    case 'workflow':
      dangerous = workflowIsDangerous(content);
      what = 'GitHub Actions workflow (privileged trigger / untrusted checkout / secret exfil)';
      break;
    case 'vscodeTasks':
      dangerous = tasksJsonIsDangerous(content);
      what = '.vscode/tasks.json folderOpen task (auto-runs the moment the folder is opened)';
      break;
    case 'claudeSettings':
      dangerous = settingsJsonIsDangerous(content);
      what = '.claude/settings.json hook (auto-executes on agent events)';
      break;
    default:
      return null;
  }

  if (!dangerous) return null;

  return `Blocked write to ${filePath || 'a config file'} — ${what} contains an execution/network/secret signature.\n` +
    `This matches the Miasma / Mini Shai-Hulud supply-chain vector. If this is intentional, write the file manually outside the agent.`;
}

// ---------------------------------------------------------------------------
// Tool-input extraction (mirrors secret-guard.js)
// ---------------------------------------------------------------------------

function extractFromToolInput(toolName, toolInput) {
  if (!toolInput) return null;
  switch (toolName) {
    case 'Write':
      return { content: toolInput.content || '', filePath: toolInput.file_path || '' };
    case 'Edit':
      return { content: toolInput.new_string || '', filePath: toolInput.file_path || '' };
    case 'MultiEdit': {
      const edits = toolInput.edits || [];
      const combined = edits.map((e) => e.new_string || '').join('\n');
      return { content: combined, filePath: toolInput.file_path || '' };
    }
    default:
      return null;
  }
}

function checkForConfigImplant(toolName, toolInput) {
  const extracted = extractFromToolInput(toolName, toolInput);
  if (!extracted) return null;

  const { content, filePath } = extracted;
  if (isAllowlisted(filePath)) return null;

  const target = classify(filePath);
  if (!target) return null;

  return checkConfig(target, content, filePath);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  let input = '';

  // 3-second timeout — fail closed for security (match secret-guard.js).
  const timeout = setTimeout(() => {
    process.stdout.write(JSON.stringify({
      decision: 'block',
      reason: 'Config guard timed out waiting for input — blocking as precaution',
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
      const reason = checkForConfigImplant(toolName, toolInput);
      if (reason) {
        process.stdout.write(JSON.stringify({ decision: 'block', reason }));
      }
    } catch (err) {
      // Parse error — fail closed for security.
      process.stdout.write(JSON.stringify({
        decision: 'block',
        reason: `Config guard failed to parse input: ${err.message}. Blocking as precaution.`,
      }));
    }
    process.exit(0);
  });
}

if (require.main === module) {
  main();
}

module.exports = {
  TARGETS,
  ALLOWLISTED_PATHS,
  isAllowlisted,
  classify,
  bindingGypIsDangerous,
  workflowIsDangerous,
  tasksJsonIsDangerous,
  settingsJsonIsDangerous,
  checkConfig,
  extractFromToolInput,
  checkForConfigImplant,
};
