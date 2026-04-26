'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { commandExists, getVersion } = require('./base.js');
const { verifyHooks } = require('../integrity.js');

const HOOKS_DIR = path.join(os.homedir(), '.claude', 'hooks');
const SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');
const AUDIT_DIR = path.join(os.homedir(), '.claude', 'audit');

const HOOK_FILES = ['bash-firewall.js', 'secret-guard.js', 'audit-logger.js'];

const MAX_BACKUPS = 3;

/**
 * Create a timestamped backup of filePath and keep only the most recent MAX_BACKUPS.
 * Returns the backup path on success, or null if the source file doesn't exist.
 * Errors are caught so a failed backup never prevents the main operation.
 */
function backupFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }

    const dir = path.dirname(filePath);
    const base = path.basename(filePath);
    const timestamp = new Date().toISOString().replace(/:/g, '');
    const backupPath = path.join(dir, `${base}.bak.${timestamp}`);

    fs.copyFileSync(filePath, backupPath);

    // Clean up old backups — keep only the MAX_BACKUPS most recent
    const backupPrefix = `${base}.bak.`;
    const backups = fs.readdirSync(dir)
      .filter(f => f.startsWith(backupPrefix))
      .sort();

    if (backups.length > MAX_BACKUPS) {
      const toDelete = backups.slice(0, backups.length - MAX_BACKUPS);
      for (const old of toDelete) {
        fs.unlinkSync(path.join(dir, old));
      }
    }

    return backupPath;
  } catch {
    // Never let backup failure block the main operation
    return null;
  }
}

const HOOK_CONFIG = {
  PreToolUse: [
    {
      matcher: 'Bash',
      hooks: [{ type: 'command', command: `node ${path.join(HOOKS_DIR, 'bash-firewall.js')}`, timeout: 5 }],
    },
    {
      matcher: 'Write|Edit|MultiEdit',
      hooks: [{ type: 'command', command: `node ${path.join(HOOKS_DIR, 'secret-guard.js')}`, timeout: 5 }],
    },
  ],
  PostToolUse: [
    {
      matcher: '',
      hooks: [{ type: 'command', command: `node ${path.join(HOOKS_DIR, 'audit-logger.js')}`, timeout: 10 }],
    },
  ],
};

function detect() {
  const found = commandExists('claude');
  const version = found ? getVersion('claude', '--version') : null;
  return { found, version, path: found ? 'claude' : null };
}

function harden(projectDir, flags) {
  const actions = [];
  const warnings = [];

  if (flags.dryRun) {
    actions.push('[dry-run] Would copy hooks to ' + HOOKS_DIR);
    actions.push('[dry-run] Would merge hook config into ' + SETTINGS_PATH);
    return { actions, warnings };
  }

  // 1. Copy hooks
  fs.mkdirSync(HOOKS_DIR, { recursive: true });
  const hooksSource = path.join(__dirname, '..', '..', 'hooks');

  for (const hook of HOOK_FILES) {
    const src = path.join(hooksSource, hook);
    const dest = path.join(HOOKS_DIR, hook);

    if (fs.existsSync(dest)) {
      actions.push(`${hook} — already installed, skipped`);
    } else if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      fs.chmodSync(dest, 0o755);
      actions.push(`${hook} — installed`);
    } else {
      warnings.push(`${hook} — source not found at ${src}`);
    }
  }

  // 2. Merge settings.json
  const mergeResult = mergeSettings(flags);
  actions.push(...mergeResult.actions);
  warnings.push(...mergeResult.warnings);

  return { actions, warnings };
}

function mergeSettings(flags) {
  const actions = [];
  const warnings = [];

  let existing = {};
  if (fs.existsSync(SETTINGS_PATH)) {
    try {
      existing = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
    } catch {
      warnings.push('settings.json exists but is not valid JSON — skipping merge');
      return { actions, warnings };
    }
  }

  if (!existing.hooks) {
    existing.hooks = {};
  }

  let changed = false;

  // Merge PreToolUse hooks
  for (const [event, newHooks] of Object.entries(HOOK_CONFIG)) {
    if (!existing.hooks[event]) {
      existing.hooks[event] = [];
    }

    for (const newHook of newHooks) {
      const alreadyExists = existing.hooks[event].some(h => {
        const existingCmd = h.hooks?.[0]?.command || '';
        const newCmd = newHook.hooks?.[0]?.command || '';
        // Match by hook filename, not full path (handles different install paths)
        const existingFile = existingCmd.split('/').pop();
        const newFile = newCmd.split('/').pop();
        return existingFile === newFile && h.matcher === newHook.matcher;
      });

      if (!alreadyExists) {
        existing.hooks[event].push(newHook);
        changed = true;
      }
    }
  }

  if (changed) {
    // Back up existing settings before overwriting
    const backupPath = backupFile(SETTINGS_PATH);
    if (backupPath) {
      actions.push(`settings.json — backed up to ${path.basename(backupPath)}`);
    }

    // Ensure directory exists
    fs.mkdirSync(path.dirname(SETTINGS_PATH), { recursive: true });
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(existing, null, 2) + '\n');
    actions.push('settings.json — hooks config merged');
  } else {
    actions.push('settings.json — hooks already configured');
  }

  return { actions, warnings };
}

function audit() {
  const checks = [];

  // Check sandbox
  checks.push({
    name: 'Sandbox',
    pass: true, // On by default since v1.0, no easy way to check programmatically
    detail: 'Seatbelt sandbox is on by default since Claude Code v1.0',
  });

  // Check each hook
  for (const hook of HOOK_FILES) {
    const hookPath = path.join(HOOKS_DIR, hook);
    const exists = fs.existsSync(hookPath);
    const label = hook.replace('.js', '').replace(/-/g, ' ');

    if (exists) {
      // Syntax check
      try {
        require('child_process').execFileSync('node', ['-c', hookPath], { stdio: 'pipe' });
        checks.push({ name: label, pass: true, detail: 'Installed and valid' });
      } catch {
        checks.push({ name: label, pass: false, detail: 'Installed but has syntax errors' });
      }
    } else {
      checks.push({ name: label, pass: false, detail: 'Not installed' });
    }
  }

  // Check settings.json has hooks wired
  let settingsWired = false;
  if (fs.existsSync(SETTINGS_PATH)) {
    try {
      const settings = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      settingsWired = !!(settings.hooks?.PreToolUse?.length || settings.hooks?.PostToolUse?.length);
    } catch { /* ignore */ }
  }
  checks.push({
    name: 'Settings hooks',
    pass: settingsWired,
    detail: settingsWired ? 'Hooks wired in settings.json' : 'No hooks in settings.json',
  });

  // Check hook integrity (SHA256 verification)
  const integrity = verifyHooks(HOOKS_DIR);
  for (const result of integrity.results) {
    const label = result.name.replace('.js', '').replace(/-/g, ' ') + ' integrity';

    if (result.status === 'ok') {
      checks.push({ name: label, pass: true, detail: 'SHA256 matches known-good checksum' });
    } else if (result.status === 'tampered') {
      checks.push({
        name: label,
        pass: false,
        detail: `SHA256 mismatch — expected ${result.expected.slice(0, 12)}..., got ${result.actual.slice(0, 12)}...`,
      });
    } else if (result.status === 'missing') {
      checks.push({
        name: label,
        pass: false,
        detail: result.detail || 'Hook file not installed',
      });
    }
  }

  // Check audit logs
  let auditActive = false;
  if (fs.existsSync(AUDIT_DIR)) {
    try {
      const files = fs.readdirSync(AUDIT_DIR).filter(f => f.endsWith('.jsonl'));
      if (files.length > 0) {
        const latest = files.sort().pop();
        const stat = fs.statSync(path.join(AUDIT_DIR, latest));
        const ageMs = Date.now() - stat.mtimeMs;
        auditActive = ageMs < 7 * 24 * 60 * 60 * 1000; // active within 7 days
      }
    } catch { /* ignore */ }
  }
  checks.push({
    name: 'Audit logging',
    pass: auditActive,
    detail: auditActive ? 'Audit logs active (written within 7 days)' : 'No recent audit logs',
  });

  // Calculate level
  const passCount = checks.filter(c => c.pass).length;
  let level = 0;
  if (passCount >= 2) level = 1; // basic hooks
  if (passCount >= 4) level = 2; // hooks + audit
  if (passCount >= 6) level = 3; // full hardening
  // Level 4 requires container isolation (checked elsewhere)

  return { checks, level };
}

module.exports = {
  name: 'Claude Code',
  id: 'claude-code',
  tier: 1,
  detect,
  harden,
  audit,
  // Exposed for testing
  _backupFile: backupFile,
  _mergeSettings: mergeSettings,
};
