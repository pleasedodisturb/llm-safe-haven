'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { sourcesFor } = require('../../lib/mcp/config-sources.js');

const FAKE_HOME = '/fake/home';
const FAKE_CWD = '/fake/repo';

describe('sourcesFor', () => {
  describe('claude-code', () => {
    it('returns exactly three scope-tagged descriptors: user, local, project', () => {
      const sources = sourcesFor('claude-code', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      assert.strictEqual(sources.length, 3);
      const scopes = sources.map(s => s.scope).sort();
      assert.deepEqual(scopes, ['local', 'project', 'user']);
    });

    it('user and local scopes both point at <homedir>/.claude.json', () => {
      const sources = sourcesFor('claude-code', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      const user = sources.find(s => s.scope === 'user');
      const local = sources.find(s => s.scope === 'local');
      const expected = path.join(FAKE_HOME, '.claude.json');
      assert.strictEqual(user.path, expected);
      assert.strictEqual(local.path, expected);
      assert.strictEqual(user.format, 'json');
      assert.strictEqual(local.format, 'json');
    });

    it('project scope points at <cwd>/.mcp.json', () => {
      const sources = sourcesFor('claude-code', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      const project = sources.find(s => s.scope === 'project');
      assert.strictEqual(project.path, path.join(FAKE_CWD, '.mcp.json'));
      assert.strictEqual(project.format, 'json');
    });

    it('every descriptor carries agentId, scope, path, and format keys', () => {
      const sources = sourcesFor('claude-code', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      for (const source of sources) {
        assert.strictEqual(source.agentId, 'claude-code');
        assert.ok(typeof source.scope === 'string');
        assert.ok(typeof source.path === 'string');
        assert.ok(typeof source.format === 'string');
      }
    });
  });

  describe('cursor', () => {
    it('yields global (<homedir>/.cursor/mcp.json) and project (<cwd>/.cursor/mcp.json) sources', () => {
      const sources = sourcesFor('cursor', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      assert.strictEqual(sources.length, 2);
      const global = sources.find(s => s.scope === 'global');
      const project = sources.find(s => s.scope === 'project');
      assert.strictEqual(global.path, path.join(FAKE_HOME, '.cursor', 'mcp.json'));
      assert.strictEqual(project.path, path.join(FAKE_CWD, '.cursor', 'mcp.json'));
      assert.strictEqual(global.format, 'jsonc');
      assert.strictEqual(project.format, 'jsonc');
    });
  });

  describe('windsurf', () => {
    it('yields only a global source (no project path per Assumption A2)', () => {
      const sources = sourcesFor('windsurf', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      assert.strictEqual(sources.length, 1);
      assert.strictEqual(sources[0].scope, 'global');
      assert.strictEqual(sources[0].path, path.join(FAKE_HOME, '.codeium', 'windsurf', 'mcp_config.json'));
      assert.strictEqual(sources[0].format, 'jsonc');
    });
  });

  describe('cline', () => {
    it('resolves the macOS globalStorage path', () => {
      const sources = sourcesFor('cline', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      assert.strictEqual(sources.length, 1);
      const expected = path.join(
        FAKE_HOME, 'Library', 'Application Support', 'Code', 'User', 'globalStorage',
        'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'
      );
      assert.strictEqual(sources[0].path, expected);
      assert.ok(
        sources[0].path.endsWith(
          path.join('Library', 'Application Support', 'Code', 'User', 'globalStorage',
            'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json')
        ),
        'macOS Cline path should end with the expected globalStorage suffix'
      );
    });

    it('resolves the Linux globalStorage path', () => {
      const sources = sourcesFor('cline', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'linux' });
      assert.strictEqual(sources.length, 1);
      const expected = path.join(
        FAKE_HOME, '.config', 'Code', 'User', 'globalStorage',
        'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'
      );
      assert.strictEqual(sources[0].path, expected);
      assert.ok(
        sources[0].path.includes(path.join('.config', 'Code', 'User', 'globalStorage')),
        'Linux Cline path should contain .config/Code/User/globalStorage'
      );
    });

    it('resolves the Windows globalStorage path using APPDATA', () => {
      const sources = sourcesFor('cline', {
        homedir: FAKE_HOME,
        cwd: FAKE_CWD,
        platform: 'win32',
        env: { APPDATA: 'C:\\Users\\fake\\AppData\\Roaming' },
      });
      assert.strictEqual(sources.length, 1);
      const expected = path.join(
        'C:\\Users\\fake\\AppData\\Roaming', 'Code', 'User', 'globalStorage',
        'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'
      );
      assert.strictEqual(sources[0].path, expected);
    });

    it('falls back to <homedir>/AppData/Roaming on Windows when APPDATA is unset', () => {
      const sources = sourcesFor('cline', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'win32', env: {} });
      assert.strictEqual(sources.length, 1);
      const expected = path.join(
        FAKE_HOME, 'AppData', 'Roaming', 'Code', 'User', 'globalStorage',
        'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'
      );
      assert.strictEqual(sources[0].path, expected);
    });
  });

  describe('continue-dev', () => {
    it('yields a single global YAML source at <homedir>/.continue/config.yaml', () => {
      const sources = sourcesFor('continue-dev', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      assert.strictEqual(sources.length, 1);
      assert.strictEqual(sources[0].scope, 'global');
      assert.strictEqual(sources[0].path, path.join(FAKE_HOME, '.continue', 'config.yaml'));
      assert.strictEqual(sources[0].format, 'yaml');
    });
  });

  describe('unknown agent id', () => {
    it('returns an empty array', () => {
      const sources = sourcesFor('does-not-exist', { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' });
      assert.deepEqual(sources, []);
    });
  });
});
