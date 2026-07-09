'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parse, agentId } = require('../../../lib/mcp/parsers/continue-dev.js');

const FIXTURES = path.join(__dirname, '..', 'fixtures', 'continue-dev');

function source(fixtureName) {
  return { agentId: 'continue-dev', scope: 'global', path: path.join(FIXTURES, fixtureName) };
}

describe('parsers/continue-dev', () => {
  it('exports agentId "continue-dev"', () => {
    assert.strictEqual(agentId, 'continue-dev');
  });

  it('does NOT require any npm YAML package (zero-dep, only ../base.js + node built-ins)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'parsers', 'continue-dev.js'), 'utf8');
    const requireCalls = [...src.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map(m => m[1]);
    // Only the shared base module is required — no yaml/js-yaml/etc package.
    assert.deepStrictEqual(requireCalls, ['../base.js']);
    assert.ok(!requireCalls.some(r => /yaml/i.test(r)), 'must not require any yaml package');
  });

  it('valid.yaml yields exactly 2 normalized servers with agentId "continue-dev"', () => {
    const result = parse(source('valid.yaml'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 2);
    for (const s of result.servers) {
      assert.strictEqual(s.agentId, 'continue-dev');
    }
  });

  it('valid.yaml: local-server has command/args/env parsed correctly', () => {
    const result = parse(source('valid.yaml'));
    const local = result.servers.find(s => s.name === 'local-server');
    assert.ok(local);
    assert.strictEqual(local.command, 'node');
    assert.deepStrictEqual(local.args, ['server.js', '--flag']);
    assert.strictEqual(local.env.API_KEY, '${env:API_KEY}');
  });

  it('valid.yaml: remote-server has a url field', () => {
    const result = parse(source('valid.yaml'));
    const remote = result.servers.find(s => s.name === 'remote-server');
    assert.ok(remote);
    assert.strictEqual(remote.url, 'https://mcp.example.com/mcp');
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

  it('CR-03: block-scalar.yaml (command: | with a hidden curl|sh body) fails CLOSED: reason "unsupported-yaml", code 2 — never ok:true with command "|"', () => {
    const result = parse(source('block-scalar.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unsupported-yaml');
    assert.strictEqual(result.code, 2);
  });

  it('CR-03: inline-comment.yaml (url: ... # prod endpoint) fails CLOSED: reason "unsupported-yaml", code 2 — comment text must never be appended to a scanned value', () => {
    const result = parse(source('inline-comment.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unsupported-yaml');
    assert.strictEqual(result.code, 2);
  });

  it('CR-03: a "#" with no preceding whitespace (URL fragment) is NOT an inline comment and still parses', () => {
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-continue-frag-'));
    const p = path.join(tmp, 'config.yaml');
    fs.writeFileSync(p, 'mcpServers:\n  - name: srv\n    url: https://mcp.example.com/mcp#section\n');
    try {
      const result = parse({ agentId: 'continue-dev', scope: 'global', path: p });
      assert.strictEqual(result.ok, true);
      assert.strictEqual(result.servers[0].url, 'https://mcp.example.com/mcp#section');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('no-mcp.yaml (valid config, no mcpServers key) returns ok:true with servers:[] — distinct from a parse failure', () => {
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

  it('SEC-1: a quoted mapping key ("command":) fails closed, not silently drops the field (scan evasion)', () => {
    // "command": is valid YAML that Continue.dev's real parser loads; the
    // restricted reader must reject it rather than return ok:true with
    // command/args/url nulled (which would let a hostile server evade the scan).
    const result = parse(source('quoted-key.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unsupported-yaml');
    assert.strictEqual(result.code, 2);
  });

  it('SEC-1 regression: quoted SCALAR list items (- "server.js") still parse — not falsely rejected as quoted keys', () => {
    const result = parse(source('quoted-scalar-args.yaml'));
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.servers.length, 1);
    assert.strictEqual(result.servers[0].command, 'node');
    assert.deepStrictEqual(result.servers[0].args, ['server.js', '--flag']);
  });

  it('RV-2: a prototype-pollution mapping key (__proto__/constructor/prototype) fails closed as polluted', () => {
    // obj['__proto__'] = <object> in the line parsers would set the item's
    // PROTOTYPE (never an own key), letting command/env be INHERITED from
    // attacker-controlled YAML past stripProtoPollution — so the reader
    // must reject the construct outright, same policy as the JSON parsers.
    const result = parse(source('proto-key.yaml'));
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'polluted');
    assert.strictEqual(result.code, 2);
  });
});
