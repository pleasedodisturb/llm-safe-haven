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

const KNOWN_AGENT_IDS = ['claude-code', 'cursor', 'windsurf', 'cline', 'continue-dev'];

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
    default:
      return [];
  }
}

module.exports = {
  KNOWN_AGENT_IDS,
  sourcesFor,
};
