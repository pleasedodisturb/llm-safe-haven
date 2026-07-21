'use strict';

const path = require('path');

/**
 * Per-agent MCP config source path table.
 *
 * None of the existing lib/agents/*.js detect() functions expose an MCP
 * config file path — they return a CLI binary / .app bundle / VS Code
 * extension string, never a config location. This module owns its own
 * hardcoded path table; detect() results are used ONLY as an install-
 * presence pre-filter in discover() below, never as a source of paths.
 *
 * Every function takes an opts param (opts-injection pattern from
 * lib/scan.js:78-83) so tests never touch the real filesystem or the
 * real ~/.claude.json / ~/.cursor/mcp.json / etc.
 */

const KNOWN_AGENT_IDS = [
  'claude-code', 'cursor', 'windsurf', 'cline', 'continue-dev',
  'codex-cli', 'gemini-cli', 'goose', 'antigravity', 'github-copilot',
];

/**
 * Resolve the OS-specific VS Code globalStorage base directory used by
 * Cline (and other VS Code extensions that persist settings there).
 */
function clineGlobalStorageBase(homedir, platform, opts) {
  if (platform === 'win32') {
    const appData = opts.env?.APPDATA || process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming');
    return path.join(appData, 'Code', 'User', 'globalStorage');
  }
  if (platform === 'linux') {
    return path.join(homedir, '.config', 'Code', 'User', 'globalStorage');
  }
  // Default / macOS ('darwin')
  return path.join(homedir, 'Library', 'Application Support', 'Code', 'User', 'globalStorage');
}

/**
 * Resolve the OS-specific VS Code User-profile directory (holds mcp.json
 * for GitHub Copilot's user scope). Generalizes clineGlobalStorageBase()'s
 * already-correct 3-way platform precedent — the CORRECT model to follow,
 * NOT lib/agents/github-copilot.js's audit() function (that's a 2-way
 * darwin-vs-not branch missing the win32 case; do not copy it).
 */
function vscodeUserDir(homedir, platform, opts) {
  if (platform === 'win32') {
    const appData = opts.env?.APPDATA || process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming');
    return path.join(appData, 'Code', 'User');
  }
  if (platform === 'linux') {
    return path.join(homedir, '.config', 'Code', 'User');
  }
  // Default / macOS ('darwin')
  return path.join(homedir, 'Library', 'Application Support', 'Code', 'User');
}

/**
 * Return the array of MCP config source descriptors for a given agent id.
 * Does NOT check whether the agent is installed or whether the path
 * exists on disk — that's discover()'s job. This is pure path resolution.
 *
 * @param {string} agentId
 * @param {object} opts - { homedir, cwd, platform, env }
 * @returns {Array<{agentId: string, scope: string, path: string, format: string}>}
 */
function sourcesFor(agentId, opts = {}) {
  const homedir = opts.homedir || require('os').homedir();
  const cwd = opts.cwd || process.cwd();
  const platform = opts.platform || process.platform;

  switch (agentId) {
    case 'claude-code': {
      const claudeJson = path.join(homedir, '.claude.json');
      return [
        { agentId, scope: 'user', path: claudeJson, format: 'json' },
        { agentId, scope: 'local', path: claudeJson, format: 'json' },
        { agentId, scope: 'project', path: path.join(cwd, '.mcp.json'), format: 'json' },
      ];
    }
    case 'cursor': {
      return [
        { agentId, scope: 'global', path: path.join(homedir, '.cursor', 'mcp.json'), format: 'jsonc' },
        { agentId, scope: 'project', path: path.join(cwd, '.cursor', 'mcp.json'), format: 'jsonc' },
      ];
    }
    case 'windsurf': {
      return [
        {
          agentId,
          scope: 'global',
          path: path.join(homedir, '.codeium', 'windsurf', 'mcp_config.json'),
          format: 'jsonc',
        },
      ];
    }
    case 'cline': {
      const base = clineGlobalStorageBase(homedir, platform, opts);
      return [
        {
          agentId,
          scope: 'global',
          path: path.join(base, 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'),
          format: 'jsonc',
        },
      ];
    }
    case 'continue-dev': {
      return [
        { agentId, scope: 'global', path: path.join(homedir, '.continue', 'config.yaml'), format: 'yaml' },
      ];
    }
    case 'codex-cli': {
      return [
        { agentId, scope: 'user', path: path.join(homedir, '.codex', 'config.toml'), format: 'toml' },
      ];
    }
    case 'gemini-cli': {
      return [
        { agentId, scope: 'user', path: path.join(homedir, '.gemini', 'settings.json'), format: 'json' },
        { agentId, scope: 'project', path: path.join(cwd, '.gemini', 'settings.json'), format: 'json' },
      ];
    }
    case 'goose': {
      const gooseBase = platform === 'win32'
        ? path.join(opts.env?.APPDATA || process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming'), 'Block', 'goose', 'config')
        : path.join(homedir, '.config', 'goose');
      return [
        { agentId, scope: 'global', path: path.join(gooseBase, 'config.yaml'), format: 'yaml' },
      ];
    }
    case 'antigravity': {
      return [
        { agentId, scope: 'global', path: path.join(homedir, '.gemini', 'config', 'mcp_config.json'), format: 'json' },
        { agentId, scope: 'project', path: path.join(cwd, '.agents', 'mcp_config.json'), format: 'json' },
      ];
    }
    case 'github-copilot': {
      const userDir = vscodeUserDir(homedir, platform, opts);
      return [
        { agentId, scope: 'project', path: path.join(cwd, '.vscode', 'mcp.json'), format: 'jsonc' },
        { agentId, scope: 'user', path: path.join(userDir, 'mcp.json'), format: 'jsonc' },
      ];
    }
    default:
      return [];
  }
}

/**
 * Resolve which of an agent's MCP config sources actually exist on this
 * machine, presence-filtered through the agent registry.
 *
 * getById(agentId).detect() is used ONLY as an install-presence gate
 * (its .found boolean) — never as a source of a config path (.path on a
 * detect() result is a CLI binary / .app bundle / VS Code extension
 * string, not a config file location; see RESEARCH.md anti-pattern).
 *
 * @param {string} agentId
 * @param {object} opts - { homedir, cwd, platform, env, getById, existsSync }
 * @returns {Array<{agentId: string, scope: string, path: string, format: string, status: 'found'|'not-found'}>}
 */
function discover(agentId, opts = {}) {
  if (!KNOWN_AGENT_IDS.includes(agentId)) {
    return [];
  }

  const getById = opts.getById || require('../agents/index.js').getById;
  const existsSync = opts.existsSync || require('fs').existsSync;

  let agentModule;
  try {
    agentModule = getById(agentId);
  } catch {
    return [];
  }
  if (!agentModule) {
    return [];
  }

  let detected;
  try {
    detected = agentModule.detect();
  } catch {
    return [];
  }
  if (!detected || detected.found !== true) {
    return [];
  }

  return sourcesFor(agentId, opts).map(source => ({
    ...source,
    status: existsSync(source.path) ? 'found' : 'not-found',
  }));
}

/**
 * Run discover() across all known agent ids (KNOWN_AGENT_IDS.length, 10 as
 * of Phase 12) and aggregate the results.
 *
 * @param {object} opts - same shape as discover()
 * @returns {Array} aggregated discover() results across all known agents
 */
function discoverAll(opts = {}) {
  return KNOWN_AGENT_IDS.flatMap(agentId => discover(agentId, opts));
}

module.exports = {
  KNOWN_AGENT_IDS,
  sourcesFor,
  discover,
  discoverAll,
  vscodeUserDir,
};
