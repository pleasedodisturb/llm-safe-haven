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
  it('returns exitCode 0 (CLEAN) when discoverAll yields zero sources', async () => {
    const envelope = await buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(envelope.exitCode, EXIT.CLEAN);
    assert.deepEqual(envelope.servers, []);
    assert.deepEqual(envelope.findings, []);
    assert.deepEqual(envelope.sources, []);
  });

  it('always has schemaVersion "1" and findings === [] regardless of input', async () => {
    const envelope = await buildEnvelope({}, { discoverAll: () => [source({ status: 'not-found' })], now: FIXED_NOW });
    assert.strictEqual(envelope.schemaVersion, SCHEMA_VERSION);
    assert.deepEqual(envelope.findings, []);
  });

  it('has the frozen top-level key set', async () => {
    const envelope = await buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.deepEqual(Object.keys(envelope).sort(), [
      'exitCode', 'findings', 'generatedAt', 'offline', 'schemaVersion', 'servers', 'sources', 'summary',
    ]);
  });

  it('offline is true, summary is { bySeverity:{}, byDetector:{} }', async () => {
    const envelope = await buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(envelope.offline, true);
    assert.deepEqual(envelope.summary, { bySeverity: {}, byDetector: {} });
  });

  it('exitCode 0 when a source is found and its parser succeeds', async () => {
    const envelope = await buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': okParser([{ name: 'srv1' }]) },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.CLEAN);
    assert.strictEqual(envelope.servers.length, 1);
    assert.strictEqual(envelope.sources[0].status, 'parsed');
  });

  it('generatedAt is injectable via opts.now for deterministic testing', async () => {
    const envelope = await buildEnvelope({}, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(envelope.generatedAt, '2026-01-01T00:00:00.000Z');
  });

  it('a malformed source among valid ones bumps exitCode to 2 (INCOMPLETE) while retaining valid servers (partial data)', async () => {
    const sources = [
      source({ agentId: 'claude-code', scope: 'user', status: 'found' }),
      source({ agentId: 'cursor', scope: 'global', status: 'found', path: '/fake/home/.cursor/mcp.json' }),
    ];
    const envelope = await buildEnvelope({}, {
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

  it('a not-found source passes through with status not-found and does not affect exitCode', async () => {
    const envelope = await buildEnvelope({}, {
      discoverAll: () => [source({ status: 'not-found' })],
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.CLEAN);
    assert.strictEqual(envelope.sources[0].status, 'not-found');
  });

  it('WR-06: a parser whose agentId disagrees with source.agentId fails closed (parser-mismatch, exit 2), never runs the wrong grammar', async () => {
    const envelope = await buildEnvelope({}, {
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

  it('a parser throwing is caught and treated as incomplete (never throws, never reports clean)', async () => {
    const envelope = await buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': { agentId: 'claude-code', parse: () => { throw new Error('boom'); } } },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.INCOMPLETE);
  });

  // D-08/Pitfall 5 regression: a malformed source AND zero verified
  // findings together must still exit 2 (INCOMPLETE), never downgraded
  // to 0 by the findings-based exit-code check.
  it('a malformed source AND zero verified findings together still exit 2, not 0 (INCOMPLETE never downgraded)', async () => {
    const envelope = await buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': failParser('malformed') },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.INCOMPLETE);
    assert.deepEqual(envelope.findings, []);
  });

  // D-02/D-09: the real detector loop (lib/mcp/detectors/index.js
  // runAll()) is now wired in and produces at least one confidence:
  // verified finding for a genuinely unpinned npx server — exitCode
  // upgrades from CLEAN to FINDINGS.
  it('a server with an unpinned npx spec produces a confidence:verified finding and exitCode 1 (FINDINGS)', async () => {
    const envelope = await buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: {
        'claude-code': okParser([{
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake/home/.claude.json',
          name: 'unpinned-server',
          command: 'npx',
          args: ['some-unpinned-package'],
          env: {},
          url: null,
          headers: {},
        }]),
      },
      now: FIXED_NOW,
    });
    assert.strictEqual(envelope.exitCode, EXIT.FINDINGS);
    assert.ok(envelope.findings.some(f => f.confidence === 'verified'));
  });
});

describe('scanMcp', () => {
  it('never throws and returns an object with a numeric .code', async () => {
    const result = await scanMcp({ quiet: true }, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(typeof result.code, 'number');
    assert.strictEqual(result.ran, true);
    assert.strictEqual(result.findingsCount, 0);
  });

  it('with flags.json, prints JSON.stringify(envelope) via console.log', async () => {
    const originalLog = console.log;
    let printed = '';
    console.log = (msg) => { printed = msg; };
    try {
      await scanMcp({ json: true }, { discoverAll: () => [], now: FIXED_NOW });
    } finally {
      console.log = originalLog;
    }
    const parsed = JSON.parse(printed);
    assert.strictEqual(parsed.schemaVersion, SCHEMA_VERSION);
  });

  it('propagates exitCode 2 through .code when a source fails to parse', async () => {
    const result = await scanMcp({ quiet: true }, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': failParser('oversized') },
      now: FIXED_NOW,
    });
    assert.strictEqual(result.code, EXIT.INCOMPLETE);
  });

  // Default (no --online) path: scanMcp must write NOTHING to stderr —
  // the offline scan has no notices, warnings, or degradation messages
  // to emit. Guards against a future change quietly adding stderr chatter
  // to the default path (the --json contract routes any notice to stderr,
  // so stderr silence is the observable "no notices" invariant).
  it('default (no --online) scanMcp writes zero stderr', async () => {
    const originalError = console.error;
    const originalLog = console.log;
    const lines = [];
    console.error = (msg) => { lines.push(String(msg)); };
    console.log = () => {}; // swallow the --json envelope on stdout
    try {
      await scanMcp({ quiet: true, json: true }, { discoverAll: () => [], now: FIXED_NOW });
    } finally {
      console.error = originalError;
      console.log = originalLog;
    }
    assert.deepStrictEqual(lines, [], 'the default offline scan must emit nothing on stderr');
  });

  // D-03: --online is live — the stale stderr placeholder notice
  // ("live registry check activates in the next release") is gone.
  // A scan with --online now runs the real (test-injected) fetchImpl
  // through the detector pipeline instead of printing a no-op notice.
  it('--online no longer prints any stderr notice', async () => {
    const originalError = console.error;
    const lines = [];
    console.error = (msg) => { lines.push(String(msg)); };
    try {
      await scanMcp({ quiet: true, online: true }, { discoverAll: () => [], now: FIXED_NOW });
    } finally {
      console.error = originalError;
    }
    assert.deepStrictEqual(lines, []);
  });

  describe('WR-02: --json build-error path emits a structured error envelope', () => {
    const THROWING_DISCOVER = () => { throw new Error('boom'); };

    it('emits a valid JSON error envelope to stdout (schemaVersion, exitCode 2, error: build-error, frozen keys)', async () => {
      const originalLog = console.log;
      const printed = [];
      console.log = (msg) => { printed.push(msg); };
      let result;
      try {
        result = await scanMcp({ json: true }, { discoverAll: THROWING_DISCOVER, now: FIXED_NOW });
      } finally {
        console.log = originalLog;
      }

      assert.strictEqual(result.ran, false);
      assert.strictEqual(result.code, EXIT.INCOMPLETE);

      assert.strictEqual(printed.length, 1, 'exactly one stdout write — pure JSON, nothing else');
      const parsed = JSON.parse(printed[0]); // must not throw — the pure-JSON contract
      assert.strictEqual(parsed.schemaVersion, SCHEMA_VERSION);
      assert.strictEqual(parsed.exitCode, EXIT.INCOMPLETE, 'a build error is INCOMPLETE, never clean');
      assert.strictEqual(parsed.error, 'build-error', 'the additive error field names the failure');
      // The frozen envelope key set is preserved (with empty defaults) so
      // existing consumers keep parsing; `error` is the only addition.
      assert.deepEqual(Object.keys(parsed).sort(), [
        'error', 'exitCode', 'findings', 'generatedAt', 'offline', 'schemaVersion', 'servers', 'sources', 'summary',
      ]);
      assert.deepEqual(parsed.findings, []);
      assert.deepEqual(parsed.sources, []);
      assert.deepEqual(parsed.servers, []);
      assert.deepEqual(parsed.summary, { bySeverity: {}, byDetector: {} });
      assert.strictEqual(parsed.generatedAt, '2026-01-01T00:00:00.000Z');
      assert.strictEqual(parsed.offline, true);
    });

    it('without --json, a build error still prints nothing to stdout and returns code 2', async () => {
      const originalLog = console.log;
      const printed = [];
      console.log = (msg) => { printed.push(msg); };
      let result;
      try {
        result = await scanMcp({ quiet: true }, { discoverAll: THROWING_DISCOVER, now: FIXED_NOW });
      } finally {
        console.log = originalLog;
      }
      assert.strictEqual(result.code, EXIT.INCOMPLETE);
      assert.deepStrictEqual(printed, [], 'the human/quiet build-error path stays silent on stdout');
    });
  });

  it('--online sets envelope.offline to false even with zero servers', async () => {
    let printed = '';
    const originalLog = console.log;
    console.log = (msg) => { printed = msg; };
    try {
      await scanMcp({ json: true, online: true }, { discoverAll: () => [], now: FIXED_NOW });
    } finally {
      console.log = originalLog;
    }
    const parsed = JSON.parse(printed);
    assert.strictEqual(parsed.offline, false);
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

  it('matches the checked-in tests/mcp/fixtures/expected-envelope.json exactly', async () => {
    const expected = require('./fixtures/expected-envelope.json');
    const actual = await buildEnvelope({ json: true }, {
      discoverAll: () => DETERMINISTIC_SOURCES,
      now: () => '2026-01-01T00:00:00.000Z',
    });
    assert.deepEqual(actual, expected);
  });
});

// Second frozen snapshot (07-01, Task 3): a findings-populated + summary-
// populated envelope, exercised through the REAL detector registry
// (lib/mcp/detectors/index.js runAll()) now that Phase 7 wires it in.
// One npx server with a PINNED version spec deterministically produces
// exactly one finding — provenance/unverified-offline (confidence:
// unverified, since this scan runs offline) — and no verified findings,
// so exitCode stays 0 (CLEAN) per D-08: unverified-only findings never
// upgrade the exit code. Regenerate this fixture from the actual resolved
// envelope if a detector's message text intentionally changes.
describe('--json envelope shape, findings populated (frozen fixture-diff)', () => {
  const FINDINGS_SOURCES = [
    { agentId: 'claude-code', scope: 'user', path: '/fake/home/.claude.json', format: 'json', status: 'found' },
  ];

  const FINDINGS_SERVER = {
    agentId: 'claude-code',
    scope: 'user',
    configPath: '/fake/home/.claude.json',
    name: 'test-fixture-server',
    command: 'npx',
    args: ['test-fixture-package@1.0.0'],
    env: {},
    url: null,
    headers: {},
  };

  it('matches the checked-in tests/mcp/fixtures/expected-envelope-findings.json exactly', async () => {
    const expected = require('./fixtures/expected-envelope-findings.json');
    const actual = await buildEnvelope({ json: true }, {
      discoverAll: () => FINDINGS_SOURCES,
      parsers: { 'claude-code': okParser([FINDINGS_SERVER]) },
      now: () => '2026-01-01T00:00:00.000Z',
    });
    assert.deepEqual(actual, expected);
    assert.strictEqual(actual.exitCode, EXIT.CLEAN);
    assert.ok(actual.findings.length > 0);
    assert.ok(actual.findings.every(f => f.confidence === 'unverified'));
  });
});

// Phase 7 Plan 03, Task 2: end-to-end exit-code suite (D-12) exercising
// the FULLY COMPOSED pipeline via scanMcp() — real detector registry,
// real config-sources/parsers shape (via injected discoverAll/parsers),
// only fetchImpl (network) is faked. Detector/parser unit tests already
// exist from Phases 4-6 (verified via the test-contract meta-test); this
// suite verifies the WIRING, not detector correctness.
describe('scanMcp e2e (D-12)', () => {
  const ONE_SOURCE = () => [source({ status: 'found' })];

  it('CLEAN — a well-formed server with no detector-triggering content yields 0 findings and exitCode 0', async () => {
    // Remote HTTPS endpoint, version-bound path (unpinned-execution),
    // Authorization header present (insecure-endpoint), a name that does
    // not match any scope-breadth capability identifier.
    const cleanServer = {
      agentId: 'claude-code',
      scope: 'user',
      configPath: '/fake/home/.claude.json',
      name: 'https-with-auth',
      command: null,
      args: [],
      env: {},
      url: 'https://mcp.example.com/v2.0/server',
      headers: { Authorization: 'Bearer redacted' },
    };
    const result = await scanMcp({ quiet: true }, {
      discoverAll: ONE_SOURCE,
      parsers: { 'claude-code': okParser([cleanServer]) },
      now: FIXED_NOW,
    });
    assert.strictEqual(result.code, EXIT.CLEAN);
    assert.strictEqual(result.findingsCount, 0);
  });

  it('FINDINGS — an --online injected fetchImpl yielding a confidence:verified provenance finding produces exitCode 1', async () => {
    const npxServer = {
      agentId: 'claude-code',
      scope: 'user',
      configPath: '/fake/home/.claude.json',
      name: 'npm-no-attestation',
      command: 'npx',
      args: ['some-generic-pkg@1.2.3'],
      env: {},
      url: null,
      headers: {},
    };
    // Registry response WITHOUT dist.attestations -> provenance/no-
    // attestation, confidence:verified (shaped per provenance.test.js's
    // fetchReturning() helper).
    const fetchImpl = async () => new Response(JSON.stringify({ dist: {} }), { status: 200 });

    const result = await scanMcp({ online: true, quiet: true }, {
      discoverAll: ONE_SOURCE,
      parsers: { 'claude-code': okParser([npxServer]) },
      now: FIXED_NOW,
      fetchImpl,
    });
    assert.strictEqual(result.code, EXIT.FINDINGS);
    assert.ok(result.findingsCount > 0);
  });

  it('INCOMPLETE — a malformed source yields exitCode 2 while findings from good sources are retained', async () => {
    const goodSources = [
      source({ agentId: 'claude-code', scope: 'user', status: 'found' }),
      source({ agentId: 'cursor', scope: 'global', status: 'found', path: '/fake/home/.cursor/mcp.json' }),
    ];
    const npxServer = {
      agentId: 'claude-code',
      scope: 'user',
      configPath: '/fake/home/.claude.json',
      name: 'unpinned-server',
      command: 'npx',
      args: ['some-unpinned-package'],
      env: {},
      url: null,
      headers: {},
    };
    const result = await scanMcp({ quiet: true }, {
      discoverAll: () => goodSources,
      parsers: {
        'claude-code': okParser([npxServer]),
        cursor: failParser('malformed', 'cursor'),
      },
      now: FIXED_NOW,
    });
    assert.strictEqual(result.code, EXIT.INCOMPLETE);
    // The good source's server still went through the detector pass —
    // findings from it are retained, not dropped by the malformed source.
    assert.ok(result.findingsCount > 0);
  });

  it('UNVERIFIED-ONLY -> CLEAN (D-14 regression) — an offline server with only unverified findings still exits 0', async () => {
    const pinnedNpxServer = {
      agentId: 'claude-code',
      scope: 'user',
      configPath: '/fake/home/.claude.json',
      name: 'npx-pinned',
      command: 'npx',
      args: ['some-mcp-server@1.2.3'],
      env: {},
      url: null,
      headers: {},
    };
    // Offline (no --online): provenance emits ONLY
    // provenance/unverified-offline (confidence:unverified) for this
    // pinned, non-capability-matching npx server.
    const result = await scanMcp({ quiet: true }, {
      discoverAll: ONE_SOURCE,
      parsers: { 'claude-code': okParser([pinnedNpxServer]) },
      now: FIXED_NOW,
    });
    assert.ok(result.findingsCount > 0, 'expected at least one (unverified) finding');
    assert.strictEqual(result.code, EXIT.CLEAN);
  });
});

// Phase 7 Plan 03, Task 2: performance-budget test (D-10, MCPO-05).
// Offline path only (no --online, fetch never invoked) — matches the
// roadmap criterion "full discovery plus all 8 detectors" under 5s.
describe('perf budget (MCPO-05, D-10)', () => {
  const AGENTS = ['claude-code', 'cursor', 'windsurf', 'cline', 'continue-dev'];

  // ~15 servers across ~5 agents (3 each) — a realistic config size per
  // 07-CONTEXT.md D-10, normalizeServer-shaped.
  const REALISTIC_15_SERVER_FIXTURE = [];
  for (const agentId of AGENTS) {
    for (let i = 0; i < 3; i++) {
      REALISTIC_15_SERVER_FIXTURE.push({
        agentId,
        scope: 'user',
        configPath: `/fake/home/${agentId}/config`,
        name: `server-${agentId}-${i}`,
        command: 'npx',
        args: [`@fake-scope/server-${agentId}-${i}@1.0.${i}`],
        env: { API_KEY: '${env:API_KEY}' },
        url: null,
        headers: {},
      });
    }
  }

  it('full offline scanMcp() completes in under 5s against a 15-server/5-agent fixture', async () => {
    const started = process.hrtime.bigint();
    const envelope = await buildEnvelope({}, {
      discoverAll: () => [source({ status: 'found' })],
      parsers: { 'claude-code': okParser(REALISTIC_15_SERVER_FIXTURE) },
      now: FIXED_NOW,
    });
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 5000, `expected <5000ms, got ${elapsedMs}ms`);
    assert.ok(envelope.findings.length > 0, 'sanity: the fixture should produce findings (npx servers offline)');
  });
});

// Task 3: --mcp wiring (parseArgs flag + scan.js dispatch)
describe('--mcp CLI wiring', () => {
  it('parseArgs(["scan","--mcp"]) sets flags.mcp true', () => {
    const args = parseArgs(['scan', '--mcp']);
    assert.strictEqual(args.command, 'scan');
    assert.strictEqual(args.flags.mcp, true);
  });

  it('scan({ mcp:true, quiet:true }, injectedOpts) dispatches to scanMcp and returns an object with a numeric .code', async () => {
    const result = await scan({ mcp: true, quiet: true }, { discoverAll: () => [], now: FIXED_NOW });
    assert.strictEqual(typeof result.code, 'number');
    assert.strictEqual(result.ran, true);
  });
});
