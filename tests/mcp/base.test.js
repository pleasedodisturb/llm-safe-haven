'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  readConfigSafe,
  stripProtoPollution,
  stripJsonc,
  MAX_CONFIG_SIZE,
  SCHEMA_VERSION,
  CONFIDENCE,
  SEVERITY,
  EXIT,
  Finding,
  normalizeServer,
} = require('../../lib/mcp/base.js');

describe('readConfigSafe', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-mcp-base-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns { ok:false, reason:"symlink", code:2 } for a symlinked config (checked via lstatSync, never following the link)', () => {
    const targetPath = path.join(tmpDir, 'target.json');
    fs.writeFileSync(targetPath, '{"mcpServers":{}}');
    const linkPath = path.join(tmpDir, 'link.json');
    fs.symlinkSync(targetPath, linkPath);

    const result = readConfigSafe(linkPath);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'symlink');
    assert.strictEqual(result.code, 2);
  });

  it('returns { ok:false, reason:"oversized", code:2 } for a file over MAX_CONFIG_SIZE', () => {
    const bigPath = path.join(tmpDir, 'big.json');
    const oversized = Buffer.alloc(MAX_CONFIG_SIZE + 1, 'a');
    fs.writeFileSync(bigPath, oversized);

    const result = readConfigSafe(bigPath);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'oversized');
    assert.strictEqual(result.code, 2);
  });

  it('CR-02: returns { ok:false, reason:"not-regular-file", code:2 } for a FIFO/named pipe — must never block in readFileSync', (t) => {
    // mkfifo is POSIX-only; skip on platforms without it (e.g. Windows).
    const { spawnSync } = require('child_process');
    const fifoPath = path.join(tmpDir, 'fifo.json');
    const mkfifo = spawnSync('mkfifo', [fifoPath]);
    if (mkfifo.error || mkfifo.status !== 0) {
      t.skip('mkfifo not available on this platform');
      return;
    }

    // If the isFile() guard is missing this call hangs forever (fail-open
    // DoS) — the guard must reject BEFORE any read is attempted.
    const result = readConfigSafe(fifoPath);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'not-regular-file');
    assert.strictEqual(result.code, 2);
  });

  it('returns { ok:false, reason:"unreadable", code:2 } for a nonexistent path, and never throws', () => {
    const missingPath = path.join(tmpDir, 'does-not-exist.json');

    let result;
    assert.doesNotThrow(() => {
      result = readConfigSafe(missingPath);
    });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'unreadable');
    assert.strictEqual(result.code, 2);
  });

  it('returns { ok:true, raw } for a well-formed small regular file', () => {
    const goodPath = path.join(tmpDir, 'good.json');
    fs.writeFileSync(goodPath, '{"mcpServers":{}}');

    const result = readConfigSafe(goodPath);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.raw, '{"mcpServers":{}}');
  });

  it('WR-05: a symlink swapped in AFTER the lstat check is still refused (O_NOFOLLOW closes the TOCTOU window)', (t) => {
    if (!fs.constants.O_NOFOLLOW) {
      t.skip('O_NOFOLLOW not available on this platform');
      return;
    }
    const targetPath = path.join(tmpDir, 'target.json');
    fs.writeFileSync(targetPath, '{"mcpServers":{}}');
    const linkPath = path.join(tmpDir, 'race-link.json');
    fs.symlinkSync(targetPath, linkPath);

    // Simulate the race: lstatSync reports "not a symlink" (as if the
    // regular file was swapped for a symlink right after the check).
    // The kernel-level O_NOFOLLOW open must still refuse to follow.
    const lyingFs = Object.create(fs);
    lyingFs.lstatSync = () => ({ isSymbolicLink: () => false });

    const result = readConfigSafe(linkPath, { fs: lyingFs });
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.reason, 'symlink');
    assert.strictEqual(result.code, 2);
  });

  it('WR-05: guards and read operate on a single fd — the read returns the bytes of the file that was opened', () => {
    const goodPath = path.join(tmpDir, 'fd-read.json');
    fs.writeFileSync(goodPath, '{"mcpServers":{"a":{"command":"node"}}}');
    const result = readConfigSafe(goodPath);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.raw, '{"mcpServers":{"a":{"command":"node"}}}');
  });

  it('never throws for any hostile input class (symlink, oversized, unreadable)', () => {
    const linkPath = path.join(tmpDir, 'link2.json');
    const targetPath = path.join(tmpDir, 'target2.json');
    fs.writeFileSync(targetPath, '{}');
    fs.symlinkSync(targetPath, linkPath);

    assert.doesNotThrow(() => readConfigSafe(linkPath));
    assert.doesNotThrow(() => readConfigSafe(path.join(tmpDir, 'nope.json')));
  });
});

describe('stripJsonc', () => {
  // Combines a // line comment, a /* block */ comment, a trailing comma
  // before }, and a URL value containing // in one blob — the single
  // fixture required by RESEARCH.md Pattern 6 / Pitfall 5.
  const blob = `{
  // this is a line comment
  "name": "test-server", /* inline block comment */
  "url": "https://mcp.example.com/mcp",
  "args": ["a", "b",],
}`;

  it('removes // line comments and /* block */ comments and trailing commas', () => {
    const stripped = stripJsonc(blob);
    const parsed = JSON.parse(stripped);
    assert.strictEqual(parsed.name, 'test-server');
    assert.deepStrictEqual(parsed.args, ['a', 'b']);
  });

  it('does NOT truncate a URL value containing //', () => {
    const stripped = stripJsonc(blob);
    const parsed = JSON.parse(stripped);
    assert.strictEqual(parsed.url, 'https://mcp.example.com/mcp');
  });

  it('does not strip a // that appears inside a string literal', () => {
    const input = '{"comment_lookalike": "http://example.com//path"}';
    const parsed = JSON.parse(stripJsonc(input));
    assert.strictEqual(parsed.comment_lookalike, 'http://example.com//path');
  });

  it('preserves escaped quotes inside strings so string boundaries are tracked correctly', () => {
    const input = '{"quoted": "a \\"quoted\\" value // not a comment"}';
    const parsed = JSON.parse(stripJsonc(input));
    assert.strictEqual(parsed.quoted, 'a "quoted" value // not a comment');
  });

  it('produces output parseable by JSON.parse for a full valid JSONC sample', () => {
    assert.doesNotThrow(() => JSON.parse(stripJsonc(blob)));
  });

  it('WR-04: a trailing backslash at EOF never appends the literal string "undefined"', () => {
    const input = '{"a": "x\\';
    const output = stripJsonc(input);
    assert.ok(!output.includes('undefined'), 'output must not contain phantom "undefined"');
    assert.strictEqual(output, input);
    // Still correctly rejected downstream as malformed (exit-2 path).
    assert.throws(() => JSON.parse(output));
  });

  it('WR-02: does NOT delete a ", }" or ", ]" sequence inside a string value', () => {
    const parsed = JSON.parse(stripJsonc('{"note":"end, }"}'));
    assert.strictEqual(parsed.note, 'end, }');
    const parsed2 = JSON.parse(stripJsonc('{"args":["a, ]", "b"]}'));
    assert.deepStrictEqual(parsed2.args, ['a, ]', 'b']);
  });

  it('WR-02: strips a trailing comma separated from the closer by a // line comment', () => {
    const parsed = JSON.parse(stripJsonc('{"a": 1, // trailing\n}'));
    assert.deepStrictEqual(parsed, { a: 1 });
  });

  it('WR-02: strips a trailing comma separated from the closer by a /* block */ comment', () => {
    const parsed = JSON.parse(stripJsonc('{"a": [1, 2, /* done */ ]}'));
    assert.deepStrictEqual(parsed.a, [1, 2]);
  });

  it('WR-02: a non-trailing comma is never dropped', () => {
    const parsed = JSON.parse(stripJsonc('{"a": 1, "b": [2, 3]}'));
    assert.deepStrictEqual(parsed, { a: 1, b: [2, 3] });
  });

  it('WR-02: a comma pending at EOF is emitted verbatim so JSON.parse reports the true failure', () => {
    assert.strictEqual(stripJsonc('{"a": 1,'), '{"a": 1,');
    assert.throws(() => JSON.parse(stripJsonc('{"a": 1,')));
  });
});

describe('stripProtoPollution', () => {
  it('deletes __proto__, constructor, and prototype own-keys and returns the object', () => {
    const obj = JSON.parse('{"__proto__":{"polluted":true},"constructor":"bad","prototype":"bad","safe":"value"}');
    const result = stripProtoPollution(obj);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, '__proto__'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, 'constructor'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, 'prototype'), false);
    assert.strictEqual(result.safe, 'value');
  });

  it('returns {} for a non-plain-object input (array)', () => {
    const result = stripProtoPollution([1, 2, 3]);
    assert.deepStrictEqual(result, {});
  });

  it('returns {} for a non-plain-object input (null)', () => {
    const result = stripProtoPollution(null);
    assert.deepStrictEqual(result, {});
  });

  it('returns {} for a non-plain-object input (primitive string)', () => {
    const result = stripProtoPollution('not an object');
    assert.deepStrictEqual(result, {});
  });
});

describe('extractServerEntries (shared mcpServers container policy)', () => {
  const { extractServerEntries } = require('../../lib/mcp/base.js');

  it('absent (undefined/null) → ok:true with empty entries', () => {
    assert.deepStrictEqual(extractServerEntries(undefined), { ok: true, entries: {} });
    assert.deepStrictEqual(extractServerEntries(null), { ok: true, entries: {} });
  });

  it('array / string / number → malformed, code 2', () => {
    for (const hostile of [['x'], 'str', 42]) {
      const result = extractServerEntries(hostile);
      assert.strictEqual(result.ok, false);
      assert.strictEqual(result.reason, 'malformed');
      assert.strictEqual(result.code, 2);
    }
  });

  it('a pollution-token server name among legit ones → polluted, code 2 (never silently dropped)', () => {
    for (const hostileName of ['__proto__', 'constructor', 'prototype']) {
      const raw = JSON.parse(`{"legit":{"command":"node"},"${hostileName}":{"command":"curl"}}`);
      const result = extractServerEntries(raw);
      assert.strictEqual(result.ok, false, `${hostileName} must fail closed`);
      assert.strictEqual(result.reason, 'polluted');
      assert.strictEqual(result.code, 2);
    }
  });

  it('a clean object → ok:true with the same entries', () => {
    const raw = JSON.parse('{"a":{"command":"node"},"b":{"url":"https://x"}}');
    const result = extractServerEntries(raw);
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(Object.keys(result.entries).sort(), ['a', 'b']);
  });
});

describe('frozen schema contract', () => {
  it('SCHEMA_VERSION is the string "1"', () => {
    assert.strictEqual(SCHEMA_VERSION, '1');
  });

  it('CONFIDENCE enum has exactly verified and unverified members', () => {
    assert.strictEqual(CONFIDENCE.VERIFIED, 'verified');
    assert.strictEqual(CONFIDENCE.UNVERIFIED, 'unverified');
    assert.deepStrictEqual(Object.keys(CONFIDENCE).sort(), ['UNVERIFIED', 'VERIFIED']);
  });

  it('CONFIDENCE is frozen (Object.freeze)', () => {
    assert.strictEqual(Object.isFrozen(CONFIDENCE), true);
  });

  it('SEVERITY enum has the ordered set info/low/medium/high/critical', () => {
    assert.strictEqual(SEVERITY.INFO, 'info');
    assert.strictEqual(SEVERITY.LOW, 'low');
    assert.strictEqual(SEVERITY.MEDIUM, 'medium');
    assert.strictEqual(SEVERITY.HIGH, 'high');
    assert.strictEqual(SEVERITY.CRITICAL, 'critical');
  });

  it('SEVERITY is frozen (Object.freeze)', () => {
    assert.strictEqual(Object.isFrozen(SEVERITY), true);
  });

  it('EXIT constants are CLEAN=0, FINDINGS=1, INCOMPLETE=2', () => {
    assert.strictEqual(EXIT.CLEAN, 0);
    assert.strictEqual(EXIT.FINDINGS, 1);
    assert.strictEqual(EXIT.INCOMPLETE, 2);
  });

  it('EXIT is frozen (Object.freeze)', () => {
    assert.strictEqual(Object.isFrozen(EXIT), true);
  });

  it('Finding() returns an object with the frozen key set, confidence defaulting to unverified', () => {
    const finding = Finding({
      id: 'f1',
      detector: 'test-detector',
      severity: SEVERITY.HIGH,
      agentId: 'claude-code',
      scope: 'user',
      serverName: 'test-server',
      message: 'a message',
    });
    assert.deepStrictEqual(Object.keys(finding).sort(), [
      'agentId', 'confidence', 'detector', 'id', 'message', 'scope', 'serverName', 'severity',
    ]);
    assert.strictEqual(finding.confidence, 'unverified');
  });

  it('Finding() coerces an invalid confidence value to unverified', () => {
    const finding = Finding({
      id: 'f2',
      detector: 'test-detector',
      severity: SEVERITY.LOW,
      confidence: 'bogus',
      agentId: 'claude-code',
      scope: 'user',
      serverName: 'test-server',
      message: 'a message',
    });
    assert.strictEqual(finding.confidence, 'unverified');
  });

  it('Finding() accepts a valid confidence value (verified) unchanged', () => {
    const finding = Finding({
      id: 'f3',
      detector: 'test-detector',
      severity: SEVERITY.CRITICAL,
      confidence: CONFIDENCE.VERIFIED,
      agentId: 'claude-code',
      scope: 'user',
      serverName: 'test-server',
      message: 'a message',
    });
    assert.strictEqual(finding.confidence, 'verified');
  });

  it('normalizeServer() returns all nine keys with args/env/headers defaulting correctly', () => {
    const server = normalizeServer({
      agentId: 'claude-code',
      scope: 'user',
      configPath: '/home/x/.claude.json',
    });
    assert.deepStrictEqual(Object.keys(server).sort(), [
      'agentId', 'args', 'command', 'configPath', 'env', 'headers', 'name', 'scope', 'url',
    ]);
    assert.strictEqual(server.name, null);
    assert.strictEqual(server.command, null);
    assert.deepStrictEqual(server.args, []);
    assert.deepStrictEqual(server.env, {});
    assert.strictEqual(server.url, null);
    assert.deepStrictEqual(server.headers, {});
  });

  it('WR-03: normalizeServer() never launders wrong-typed fields into the frozen shape', () => {
    const server = normalizeServer({
      agentId: 'cursor',
      scope: 'global',
      configPath: '/fake/.cursor/mcp.json',
      name: ['not-a-string'],
      command: 42,
      args: 'rm -rf /',        // string, not array
      env: ['A=1'],            // array, not object
      url: { hostile: true },  // object, not string
      headers: 'x',            // string, not object
    });
    assert.strictEqual(server.name, null);
    assert.strictEqual(server.command, null);
    assert.deepStrictEqual(server.args, []);
    assert.deepStrictEqual(server.env, {});
    assert.strictEqual(server.url, null);
    assert.deepStrictEqual(server.headers, {});
  });

  it('WR-03: cursor/claude-code parsers no longer forward wrong-typed args/env raw', () => {
    const { _extractServers } = require('../../lib/mcp/parsers/cursor.js');
    const result = _extractServers(
      JSON.parse('{"srv":{"command":"node","args":"rm -rf /","env":["A=1"]}}'),
      'cursor', 'global', '/fake/.cursor/mcp.json'
    );
    assert.strictEqual(result.ok, true);
    assert.deepStrictEqual(result.servers[0].args, []);
    assert.deepStrictEqual(result.servers[0].env, {});
  });

  it('normalizeServer() preserves provided values and treats ${...} tokens as opaque', () => {
    const server = normalizeServer({
      agentId: 'cursor',
      scope: 'project',
      configPath: '/repo/.cursor/mcp.json',
      name: 'my-server',
      command: 'node',
      args: ['server.js'],
      env: { API_KEY: '${env:API_KEY}' },
      url: 'https://mcp.example.com',
      headers: { Authorization: 'Bearer ${TOKEN}' },
    });
    assert.strictEqual(server.name, 'my-server');
    assert.strictEqual(server.command, 'node');
    assert.deepStrictEqual(server.args, ['server.js']);
    assert.strictEqual(server.env.API_KEY, '${env:API_KEY}');
    assert.strictEqual(server.url, 'https://mcp.example.com');
    assert.strictEqual(server.headers.Authorization, 'Bearer ${TOKEN}');
  });

  it('RV-1: normalizeServer() strips prototype-pollution own-keys from env and headers', () => {
    // JSON.parse creates __proto__ as an own data property — the normalized
    // shape must guarantee it never reaches a detector (an unsafe
    // Object.assign(target, server.env) downstream would invoke the setter).
    const hostile = JSON.parse(
      '{"env":{"__proto__":{"polluted":1},"constructor":"x","GOOD":"1"},' +
      '"headers":{"__proto__":{"polluted":1},"Auth":"y"}}'
    );
    const server = normalizeServer({
      agentId: 'cursor',
      scope: 'global',
      configPath: '/fake/.cursor/mcp.json',
      name: 'srv',
      command: 'node',
      env: hostile.env,
      headers: hostile.headers,
    });
    assert.strictEqual(Object.prototype.hasOwnProperty.call(server.env, '__proto__'), false);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(server.env, 'constructor'), false);
    assert.strictEqual(server.env.GOOD, '1');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(server.headers, '__proto__'), false);
    assert.strictEqual(server.headers.Auth, 'y');
    assert.strictEqual(({}).polluted, undefined);
  });
});
