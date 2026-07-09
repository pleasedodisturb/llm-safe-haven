'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { sourcesFor, discover, discoverAll } = require('../../lib/mcp/config-sources.js');

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

describe('discover', () => {
  const baseOpts = { homedir: FAKE_HOME, cwd: FAKE_CWD, platform: 'darwin' };

  function fakeGetById(found) {
    return () => ({ detect: () => ({ found }) });
  }

  it('returns [] when the agent registry reports the agent as not installed', () => {
    const result = discover('cursor', {
      ...baseOpts,
      getById: fakeGetById(false),
      existsSync: () => true,
    });
    assert.deepEqual(result, []);
  });

  it('returns [] when getById cannot find the agent module at all', () => {
    const result = discover('cursor', {
      ...baseOpts,
      getById: () => null,
      existsSync: () => true,
    });
    assert.deepEqual(result, []);
  });

  it('returns [] and swallows a throwing detect() (mirrors detectAll\'s swallow)', () => {
    const result = discover('cursor', {
      ...baseOpts,
      getById: () => ({ detect: () => { throw new Error('boom'); } }),
      existsSync: () => true,
    });
    assert.deepEqual(result, []);
  });

  it('marks existing paths status "found" and missing paths status "not-found" when installed', () => {
    const existingPaths = new Set([path.join(FAKE_HOME, '.cursor', 'mcp.json')]);
    const result = discover('cursor', {
      ...baseOpts,
      getById: fakeGetById(true),
      existsSync: p => existingPaths.has(p),
    });
    assert.strictEqual(result.length, 2);
    const global = result.find(s => s.scope === 'global');
    const project = result.find(s => s.scope === 'project');
    assert.strictEqual(global.status, 'found');
    assert.strictEqual(project.status, 'not-found');
    // Every descriptor still carries the base sourcesFor shape
    for (const source of result) {
      assert.strictEqual(source.agentId, 'cursor');
      assert.ok(typeof source.scope === 'string');
      assert.ok(typeof source.path === 'string');
      assert.ok(typeof source.format === 'string');
      assert.ok(['found', 'not-found'].includes(source.status));
    }
  });

  it('returns [] for an unknown agentId', () => {
    const result = discover('does-not-exist', {
      ...baseOpts,
      getById: fakeGetById(true),
      existsSync: () => true,
    });
    assert.deepEqual(result, []);
  });

  it('never reads .path off the detect() result (presence-filter only)', () => {
    const src = require('fs').readFileSync(
      path.join(__dirname, '..', '..', 'lib', 'mcp', 'config-sources.js'),
      'utf8'
    );
    // A crude but effective guard: detect() result should only ever be
    // interrogated for `.found`, never `.path` (that field is a CLI
    // binary/.app/extension string per the anti-pattern in RESEARCH.md).
    assert.ok(!/detect\(\)\.path/.test(src), 'config-sources.js must not read detect().path');
  });
});

describe('discoverAll', () => {
  it('iterates the 5 known agent ids and aggregates their discovered sources', () => {
    const result = discoverAll({
      homedir: FAKE_HOME,
      cwd: FAKE_CWD,
      platform: 'darwin',
      getById: () => ({ detect: () => ({ found: true }) }),
      existsSync: () => true,
    });
    const agentIds = new Set(result.map(s => s.agentId));
    assert.deepEqual([...agentIds].sort(), ['claude-code', 'cline', 'continue-dev', 'cursor', 'windsurf']);
    // All returned as 'found' since existsSync always true
    assert.ok(result.every(s => s.status === 'found'));
  });

  it('excludes not-installed agents entirely', () => {
    const result = discoverAll({
      homedir: FAKE_HOME,
      cwd: FAKE_CWD,
      platform: 'darwin',
      getById: id => (id === 'cursor' ? { detect: () => ({ found: false }) } : { detect: () => ({ found: true }) }),
      existsSync: () => true,
    });
    assert.ok(!result.some(s => s.agentId === 'cursor'));
    assert.ok(result.some(s => s.agentId === 'windsurf'));
  });
});
