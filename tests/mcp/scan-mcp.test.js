'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { buildEnvelope, scanMcp } = require('../../lib/scan-mcp.js');
const { SCHEMA_VERSION, EXIT } = require('../../lib/mcp/base.js');
const { parseArgs } = require('../../lib/cli.js');
const { scan } = require('../../lib/scan.js');

const FIXED_NOW = () => '2026-01-01T00:00:00.000Z';

function source(overrides = {}) {
  return {
    agentId: 'claude-code',
    scope: 'user',
    path: '/fake/home/.claude.json',
    format: 'json',
    status: 'not-found',
    ...overrides,
  };
}

function okParser(servers, agentId = 'claude-code') {
  return { parse: () => ({ ok: true, servers }), agentId };
}

function failParser(reason, agentId = 'claude-code') {
  return { parse: () => ({ ok: false, reason, code: 2 }), agentId };
}

describe('buildEnvelope', () => {
  it('returns exitCode 0 (CLEAN) when discoverAll yields zero sources', () => {
    const envelope = buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(envelope.exitCode, EXIT.CLEAN);
    assert.deepEqual(envelope.servers, []);
    assert.deepEqual(envelope.findings, []);
    assert.deepEqual(envelope.sources, []);
  });

  it('always has schemaVersion "1" and findings === [] regardless of input', () => {
    const envelope = buildEnvelope({}, { discoverAll: () => [source({ status: 'not-found' })], now: FIXED_NOW });
    assert.strictEqual(envelope.schemaVersion, SCHEMA_VERSION);
    assert.deepEqual(envelope.findings, []);
  });

  it('has the frozen top-level key set', () => {
    const envelope = buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.deepEqual(Object.keys(envelope).sort(), [
      'exitCode', 'findings', 'generatedAt', 'offline', 'schemaVersion', 'servers', 'sources', 'summary',
    ]);
  });

  it('offline is true, summary is { bySeverity:{}, byDetector:{} }', () => {
    const envelope = buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(envelope.offline, true);
    assert.deepEqual(envelope.summary, { bySeverity: {}, byDetector: {} });
  });

  it('exitCode 0 when a source is found and its parser succeeds', () => {
    const envelope = buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': okParser([{ name: 'srv1' }]) },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.CLEAN);
    assert.strictEqual(envelope.servers.length, 1);
    assert.strictEqual(envelope.sources[0].status, 'parsed');
  });

  it('generatedAt is injectable via opts.now for deterministic testing', () => {
    const envelope = buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(envelope.generatedAt, '2026-01-01T00:00:00.000Z');
  });

  it('a malformed source among valid ones bumps exitCode to 2 (INCOMPLETE) while retaining valid servers (partial data)', () => {
    const sources = [
      source({ agentId: 'claude-code', scope: 'user', status: 'found' }),
      source({ agentId: 'cursor', scope: 'global', status: 'found', path: '/fake/home/.cursor/mcp.json' }),
    ];
    const envelope = buildEnvelope({}, {
      discoverAll: () => sources,
      parsers: {
        'claude-code': okParser([{ name: 'good-server' }]),
        cursor: failParser('malformed', 'cursor'),
      },
      now: FIXED_NOW,
    });

    assert.strictEqual(envelope.exitCode, EXIT.INCOMPLETE);
    assert.strictEqual(envelope.servers.length, 1);
    assert.strictEqual(envelope.servers[0].name, 'good-server');

    const badSource = envelope.sources.find(s => s.agentId === 'cursor');
    assert.strictEqual(badSource.status, 'malformed');
    const goodSource = envelope.sources.find(s => s.agentId === 'claude-code');
    assert.strictEqual(goodSource.status, 'parsed');

    assert.deepEqual(envelope.findings, []);
    assert.strictEqual(envelope.schemaVersion, SCHEMA_VERSION);
  });

  it('a not-found source passes through with status not-found and does not affect exitCode', () => {
    const envelope = buildEnvelope({}, {
      discoverAll: () => [source({ status: 'not-found' })],
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.CLEAN);
    assert.strictEqual(envelope.sources[0].status, 'not-found');
  });

  it('WR-06: a parser whose agentId disagrees with source.agentId fails closed (parser-mismatch, exit 2), never runs the wrong grammar', () => {
    const envelope = buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })], // agentId 'claude-code'
      parsers: {
        // Wrong module wired under the claude-code key — its own
        // identity says 'windsurf'. Must never be invoked.
        'claude-code': {
          agentId: 'windsurf',
          parse: () => { throw new Error('wrong parser must never run'); },
        },
      },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.INCOMPLETE);
    assert.strictEqual(envelope.sources[0].status, 'parser-mismatch');
    assert.deepEqual(envelope.servers, []);
  });

  it('a parser throwing is caught and treated as incomplete (never throws, never reports clean)', () => {
    const envelope = buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': { agentId: 'claude-code', parse: () => { throw new Error('boom'); } } },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.INCOMPLETE);
  });
});

describe('scanMcp', () => {
  it('never throws and returns an object with a numeric .code', () => {
    let result;
    assert.doesNotThrow(() => {
      result = scanMcp({ quiet: true }, { discoverAll: () => [], now: FIXED_NOW });
    });
    assert.strictEqual(typeof result.code, 'number');
    assert.strictEqual(result.ran, true);
    assert.strictEqual(result.findingsCount, 0);
  });

  it('with flags.json, prints JSON.stringify(envelope) via console.log', () => {
    const originalLog = console.log;
    let printed = '';
    console.log = (msg) => { printed = msg; };
    try {
      scanMcp({ json: true }, { discoverAll: () => [], now: FIXED_NOW });
    } finally {
      console.log = originalLog;
    }
    const parsed = JSON.parse(printed);
    assert.strictEqual(parsed.schemaVersion, SCHEMA_VERSION);
  });

  it('propagates exitCode 2 through .code when a source fails to parse', () => {
    const result = scanMcp({ quiet: true }, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': failParser('oversized') },
      now: FIXED_NOW,
    });
    assert.strictEqual(result.code, EXIT.INCOMPLETE);
  });
});

// Schema-freeze gate (Task 2): a checked-in expected-envelope.json fixture
// this test diffs the built envelope against, via assert.deepEqual — NOT
// node:test experimental snapshot (t.assert.snapshot needs Node >=22.3,
// above this project's >=18 floor). A later phase renaming `findings` to
// `results`, or adding/removing any top-level key, fails HERE.
describe('--json envelope shape (frozen fixture-diff)', () => {
  const DETERMINISTIC_SOURCES = [
    { agentId: 'claude-code', scope: 'user', path: '/fake/home/.claude.json', format: 'json', status: 'not-found' },
    { agentId: 'claude-code', scope: 'local', path: '/fake/home/.claude.json', format: 'json', status: 'not-found' },
    { agentId: 'claude-code', scope: 'project', path: '/fake/repo/.mcp.json', format: 'json', status: 'not-found' },
  ];

  it('matches the checked-in tests/mcp/fixtures/expected-envelope.json exactly', () => {
    const expected = require('./fixtures/expected-envelope.json');
    const actual = buildEnvelope({ json: true }, {
      discoverAll: () => DETERMINISTIC_SOURCES,
      now: () => '2026-01-01T00:00:00.000Z',
    });
    assert.deepEqual(actual, expected);
  });
});

// Task 3: --mcp wiring (parseArgs flag + scan.js dispatch)
describe('--mcp CLI wiring', () => {
  it('parseArgs(["scan","--mcp"]) sets flags.mcp true', () => {
    const args = parseArgs(['scan', '--mcp']);
    assert.strictEqual(args.command, 'scan');
    assert.strictEqual(args.flags.mcp, true);
  });

  it('scan({ mcp:true, quiet:true }, injectedOpts) dispatches to scanMcp and returns an object with a numeric .code', () => {
    const result = scan({ mcp: true, quiet: true }, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(typeof result.code, 'number');
    assert.strictEqual(result.ran, true);
  });
});
