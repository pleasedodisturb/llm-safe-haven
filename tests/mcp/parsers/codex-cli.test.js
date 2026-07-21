'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parse, agentId } = require('../../../lib/mcp/parsers/codex-cli.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'codex-cli');

function source(fixtureName) {
  return { agentId: 'codex-cli', scope: 'user', path: path.join(FIXTURES, fixtureName) };
}

describe('parsers/codex-cli', () => {
  it('exports agentId "codex-cli"', () => {
    assert.strictEqual(agentId, 'codex-cli');
  });

  it('does NOT require any npm TOML package (zero-dep, only ../base.js + node built-ins)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'parsers', 'codex-cli.js'), 'utf8');
    const requireCalls = [...src.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map(m => m[1]);
    // Only the shared base module is required — no toml/@iarna/toml/etc npm
    // package (net-new restricted reader, zero-dep rule).
    assert.deepStrictEqual(requireCalls, ['../base.js']);
  });

  it('valid.toml yields exactly 2 normalized servers with agentId "codex-cli"', () => {
    const result = parse(source('valid.toml'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);
    for (const s of result.servers) {
      assert.strictEqual(s.agentId, 'codex-cli');
    }
  });

  it('valid.toml: fs server has command/args/inline env parsed correctly', () => {
    const result = parse(source('valid.toml'));
    const fsServer = result.servers.find(s => s.name === 'fs');
    assert.ok(fsServer);
    assert.strictEqual(fsServer.command, 'node');
    assert.deepStrictEqual(fsServer.args, ['server.js', '--flag']);
    assert.strictEqual(fsServer.env.API_KEY, 'secret');
  });

  it('valid.toml: api server has a url field and no command (remote transport)', () => {
    const result = parse(source('valid.toml'));
    const api = result.servers.find(s => s.name === 'api');
    assert.ok(api);
    assert.strictEqual(api.url, 'https://api.example.com/mcp');
    assert.strictEqual(api.command, null);
  });

  it('env-subtable.toml: fs.env is populated from the [mcp_servers.fs.env] sub-table form', () => {
    const result = parse(source('env-subtable.toml'));
    assert.strictEqual(result.ok, true);
    const fsServer = result.servers.find(s => s.name === 'fs');
    assert.ok(fsServer);
    assert.strictEqual(fsServer.command, 'node');
    assert.strictEqual(fsServer.env.API_KEY, 'secret');
  });

  it('env-both-forms.toml: a server declaring BOTH inline env and an env sub-table is rejected fail-closed (ambiguous, never picked silently)', () => {
    const result = parse(source('env-both-forms.toml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.code, 2);
  });

  it('array-of-tables.toml ([[mcp_servers]] — Mistral Vibe CLI shape) is rejected fail-closed: reason "unsupported-toml", code 2 — a parser that silently accepts this MUST fail this assertion', () => {
    const result = parse(source('array-of-tables.toml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unsupported-toml');
    assert.strictEqual(result.code, 2);
  });

  it('multiline-string.toml (triple-quoted basic string) fails CLOSED: code 2', () => {
    const result = parse(source('multiline-string.toml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.code, 2);
  });

  it('proto-table.toml (a __proto__ table name) fails CLOSED: reason "polluted", code 2', () => {
    const result = parse(source('proto-table.toml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'polluted');
    assert.strictEqual(result.code, 2);
  });

  it('no-mcp.toml (valid TOML, no [mcp_servers.*] tables) returns ok:true with servers:[] — distinct from a parse failure', () => {
    const result = parse(source('no-mcp.toml'));
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.servers, []);
  });

  it('propagates readConfigSafe failures (nonexistent file) unchanged', () => {
    const result = parse(source('does-not-exist.toml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unreadable');
    assert.strictEqual(result.code, 2);
  });

  it('a bare dotted-key form (mcp_servers.foo.command = "x") outside the two documented table-header forms is rejected fail-closed', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-codex-dotted-'));
    const p = path.join(tmp, 'config.toml');
    fs.writeFileSync(p, 'mcp_servers.foo.command = "node"\n');
    try {
      const result = parse({ agentId: 'codex-cli', scope: 'user', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('a __proto__ key inside a legitimately-named table is also rejected fail-closed (not just a __proto__ table name)', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-codex-protokey-'));
    const p = path.join(tmp, 'config.toml');
    fs.writeFileSync(p, '[mcp_servers.fs]\ncommand = "node"\n__proto__ = "polluted"\n');
    try {
      const result = parse({ agentId: 'codex-cli', scope: 'user', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'polluted');
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('a nested inline table inside env (env = { FOO = { bar = "x" } }) is rejected fail-closed, never silently flattened', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-codex-nested-'));
    const p = path.join(tmp, 'config.toml');
    fs.writeFileSync(p, '[mcp_servers.fs]\ncommand = "node"\nenv = { FOO = { bar = "x" } }\n');
    try {
      const result = parse({ agentId: 'codex-cli', scope: 'user', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
