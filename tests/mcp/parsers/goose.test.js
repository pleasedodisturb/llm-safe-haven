'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parse, agentId } = require('../../../lib/mcp/parsers/goose.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'goose');

function source(fixtureName) {
  return { agentId: 'goose', scope: 'global', path: path.join(FIXTURES, fixtureName) };
}

describe('parsers/goose', () => {
  it('exports agentId "goose"', () => {
    assert.strictEqual(agentId, 'goose');
  });

  it('does NOT require any npm YAML package (zero-dep, only ../base.js + ../restricted-yaml.js + node built-ins)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'parsers', 'goose.js'), 'utf8');
    const requireCalls = [...src.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map(m => m[1]);
    assert.deepStrictEqual(requireCalls, ['../base.js', '../restricted-yaml.js']);
    const npmRequires = requireCalls.filter(r => !r.startsWith('.'));
    assert.ok(!npmRequires.some(r => /yaml/i.test(r)), 'must not require any npm yaml package');
  });

  it('valid.yaml yields exactly 2 normalized servers (builtin skipped) with agentId "goose"', () => {
    const result = parse(source('valid.yaml'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);
    for (const s of result.servers) {
      assert.strictEqual(s.agentId, 'goose');
    }
    assert.ok(!result.servers.some(s => s.name === 'developer'), 'builtin extension "developer" must be skipped');
  });

  it('valid.yaml: filesystem (stdio) has command/args/env parsed correctly', () => {
    const result = parse(source('valid.yaml'));
    const fs2 = result.servers.find(s => s.name === 'filesystem');
    assert.ok(fs2);
    assert.strictEqual(fs2.command, 'npx');
    assert.deepStrictEqual(fs2.args, ['-y', '@modelcontextprotocol/server-filesystem', '/tmp']);
    assert.strictEqual(fs2.env.LOG_LEVEL, 'debug');
  });

  it('valid.yaml: remote-tools (streamable_http) has a url field from uri', () => {
    const result = parse(source('valid.yaml'));
    const remote = result.servers.find(s => s.name === 'remote-tools');
    assert.ok(remote);
    assert.strictEqual(remote.url, 'https://example.com/mcp');
  });

  it('Pitfall 2: env-keys-only.yaml (env_keys populated, envs absent) yields a DEEPLY EMPTY env -- never fabricated from env_keys', () => {
    const result = parse(source('env-keys-only.yaml'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 1);
    const s = result.servers[0];
    assert.strictEqual(s.name, 'secretive');
    // Non-vacuous: assert both the key and its literal presumed value are
    // absent, not just "falsy" -- proves env_keys names never leak in.
    assert.deepStrictEqual(s.env, {});
    assert.strictEqual(Object.keys(s.env).length, 0);
    assert.strictEqual(s.env.OPENAI_API_KEY, undefined);
  });

  it('anchors.yaml fails CLOSED: reason "unparseable", code 2', () => {
    const result = parse(source('anchors.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unparseable');
    assert.strictEqual(result.code, 2);
  });

  it('flow-style.yaml fails CLOSED: reason "unparseable", code 2', () => {
    const result = parse(source('flow-style.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unparseable');
    assert.strictEqual(result.code, 2);
  });

  it('proto-key.yaml (a mapping key of __proto__) fails CLOSED: reason "polluted", code 2', () => {
    const result = parse(source('proto-key.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'polluted');
    assert.strictEqual(result.code, 2);
  });

  it('no-mcp.yaml (valid config, no extensions key) returns ok:true with servers:[] -- distinct from a parse failure', () => {
    const result = parse(source('no-mcp.yaml'));
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.servers, []);
  });

  it('propagates readConfigSafe failures (symlink/oversized/unreadable) unchanged', () => {
    const result = parse(source('does-not-exist.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unreadable');
    assert.strictEqual(result.code, 2);
  });

  it('D-04: an extension with enabled:false is still returned (scan regardless of enabled)', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-goose-disabled-'));
    const p = path.join(tmp, 'config.yaml');
    fs.writeFileSync(p, 'extensions:\n  disabled-server:\n    type: stdio\n    cmd: npx\n    enabled: false\n');
    try {
      const result = parse({ agentId: 'goose', scope: 'global', path: p });
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers.length, 1);
      assert.strictEqual(result.servers[0].name, 'disabled-server');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('a block-sequence extensions: (continue-dev shape, not Goose object-keyed mapping) fails CLOSED', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-goose-blockseq-'));
    const p = path.join(tmp, 'config.yaml');
    fs.writeFileSync(p, 'extensions:\n  - name: filesystem\n    type: stdio\n    cmd: npx\n');
    try {
      const result = parse({ agentId: 'goose', scope: 'global', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('an unrecognized extension type fails CLOSED rather than silently skipping or mis-mapping', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-goose-unknowntype-'));
    const p = path.join(tmp, 'config.yaml');
    fs.writeFileSync(p, 'extensions:\n  mystery:\n    type: quantum\n    cmd: npx\n');
    try {
      const result = parse({ agentId: 'goose', scope: 'global', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('CR-01: stray-key-truncation.yaml (a dotted key "foo.bar:" inside a benign extension, followed by a later evil stdio extension) fails CLOSED -- reason "unparseable", code 2 -- must NEVER return ok:true, servers:[] (scan-bypass regression)', () => {
    const result = parse(source('stray-key-truncation.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unparseable');
    assert.strictEqual(result.code, 2);
  });

  it('CR-01: a leading-digit key ("1key:") inside an extension mapping also fails CLOSED rather than silently truncating the extensions block', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-goose-digitkey-'));
    const p = path.join(tmp, 'config.yaml');
    fs.writeFileSync(
      p,
      'extensions:\n  benign:\n    type: builtin\n    1key: x\n  evil:\n    type: stdio\n    cmd: malware\n'
    );
    try {
      const result = parse({ agentId: 'goose', scope: 'global', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'unparseable');
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('CR-01: a merge key ("<<:") inside an extension mapping also fails CLOSED rather than silently truncating the extensions block', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-goose-mergekey-'));
    const p = path.join(tmp, 'config.yaml');
    fs.writeFileSync(
      p,
      'extensions:\n  benign:\n    type: builtin\n    <<: x\n  evil:\n    type: stdio\n    cmd: malware\n'
    );
    try {
      const result = parse({ agentId: 'goose', scope: 'global', path: p });
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'unparseable');
      assert.strictEqual(result.code, 2);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
