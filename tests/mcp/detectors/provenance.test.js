'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { id, requirement, run } = require('../../../lib/mcp/detectors/provenance.js');

const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures', 'detectors', 'provenance');

function loadFixture(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `${name}.json`), 'utf8'));
}

// MCPO-04 zero-fetch assertion: a spy fetchImpl that THROWS if ever
// invoked. Used on every offline-path test — if the detector ever
// referenced fetchImpl offline, these tests would fail loudly instead
// of silently passing.
function throwingFetch() {
  throw new Error('fetchImpl must never be called when offline (MCPO-04/D-11)');
}

// Injected fetchImpl factory returning a REAL Response (Node 18 global)
// so the body is a genuine ReadableStream, exactly like real fetch —
// F7 removed the text()-only fallback (it buffered the whole body
// before a UTF-16-unit size check), so every double must stream.
// Response derives .ok from the status code, like fetch does.
function fetchReturning({ status = 200, body = null } = {}) {
  return async () => new Response(JSON.stringify(body), { status });
}

describe('provenance detector (MCPD-02)', () => {
  it('exports id "provenance" and requirement "MCPD-02"', () => {
    assert.strictEqual(id, 'provenance');
    assert.strictEqual(requirement, 'MCPD-02');
  });

  describe('offline (MCPO-04 zero-fetch guarantee)', () => {
    it('every npx server yields provenance/unverified-offline and NEVER calls fetchImpl', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      assert.ok(findings.length > 0);
      for (const f of findings) {
        assert.strictEqual(f.id, 'provenance/unverified-offline');
        assert.strictEqual(f.severity, 'info');
        assert.strictEqual(f.confidence, 'unverified');
      }
    });

    it('defaults to offline when context.online is omitted entirely', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { fetchImpl: throwingFetch });
      assert.ok(findings.length > 0);
      assert.ok(findings.every((f) => f.id === 'provenance/unverified-offline'));
    });

    it('never produces a clean result or a higher-severity finding offline', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      const npxCount = servers.filter((s) => s.command === 'npx').length;
      assert.strictEqual(findings.length, npxCount);
      for (const f of findings) {
        assert.notStrictEqual(f.severity, 'high');
        assert.notStrictEqual(f.severity, 'critical');
        assert.notStrictEqual(f.severity, 'medium');
      }
    });

    it('the offline message reads as neutral status, not alarming', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      for (const f of findings) {
        assert.ok(f.message.includes('--online'), `expected --online guidance in: ${f.message}`);
      }
    });
  });

  describe('online + attestations present', () => {
    it('produces zero findings (clean)', async () => {
      const servers = loadFixture('clean');
      const fetchImpl = fetchReturning({ body: { dist: { attestations: { url: 'https://example.com' } } } });
      const findings = await run(servers, { online: true, fetchImpl });
      assert.deepStrictEqual(findings, []);
    });
  });

  describe('online + attestations absent', () => {
    it('produces provenance/no-attestation (low, verified)', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f, 'expected a provenance/no-attestation finding');
      assert.strictEqual(f.severity, 'low');
      assert.strictEqual(f.confidence, 'verified');
    });

    it('the message says "lacks a provenance attestation", never "verified authentic"', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f.message.toLowerCase().includes('lacks a provenance attestation'));
      assert.ok(!f.message.toLowerCase().includes('verified authentic'));
    });
  });

  describe('online + fetch failure', () => {
    it('a throwing fetchImpl produces provenance/fetch-failed (info, unverified) and run() never rejects', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = async () => {
        throw new Error('network down');
      };
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      const f = findings.find((x) => x.id === 'provenance/fetch-failed');
      assert.ok(f, 'expected a provenance/fetch-failed finding');
      assert.strictEqual(f.severity, 'info');
      assert.strictEqual(f.confidence, 'unverified');
    });

    it('passes redirect:error so a registry 3xx is never followed (SSRF hardening)', async () => {
      const servers = loadFixture('bad');
      let seenOpts;
      // fetch() with redirect:'error' rejects on a redirect; simulate that
      // by throwing when the option is present, and record the option so we
      // also assert it is actually passed (not silently dropped).
      const fetchImpl = async (_url, opts) => {
        seenOpts = opts;
        throw new TypeError('unexpected redirect');
      };
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.strictEqual(seenOpts.redirect, 'error', 'fetch must be called with redirect:error');
      assert.ok(
        findings.some((f) => f.id === 'provenance/fetch-failed'),
        'a redirected (non-followed) lookup must degrade to fetch-failed',
      );
      assert.ok(
        !findings.some((f) => f.id === 'provenance/no-attestation'),
        'a redirect must never be misreported as no-attestation',
      );
    });

    it('a 404-shaped response produces provenance/fetch-failed, NOT no-attestation (Pitfall 5)', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ status: 404, body: 'Not Found' });
      const findings = await run(servers, { online: true, fetchImpl });
      const provenanceFindings = findings.filter((f) => f.id.startsWith('provenance/'));
      assert.ok(provenanceFindings.some((f) => f.id === 'provenance/fetch-failed'));
      assert.ok(!provenanceFindings.some((f) => f.id === 'provenance/no-attestation'));
    });

    it('an oversized response degrades to fetch-failed, never throws', async () => {
      const servers = loadFixture('bad');
      const hugeBody = { dist: { attestations: null }, padding: 'x'.repeat(6 * 1024 * 1024) };
      const fetchImpl = fetchReturning({ body: hugeBody });
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.ok(findings.some((f) => f.id === 'provenance/fetch-failed'));
    });

    it('WR-03: an oversized Content-Length header is rejected BEFORE any body read (text()/body never touched)', async () => {
      const servers = loadFixture('bad');
      let bodyTouched = false;
      const fetchImpl = async () => ({
        ok: true,
        status: 200,
        headers: { get: (name) => (name === 'content-length' ? String(50 * 1024 * 1024) : null) },
        get body() { bodyTouched = true; return null; },
        text: async () => { bodyTouched = true; return '{}'; },
      });
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.ok(findings.some((f) => f.id === 'provenance/fetch-failed'));
      assert.strictEqual(bodyTouched, false, 'the body must never be read when Content-Length exceeds the cap');
    });

    it('WR-03: a chunked streaming body with no Content-Length is aborted mid-stream once the cap is crossed', async () => {
      const servers = loadFixture('bad');
      // 2MB chunks, endless supply — without the mid-stream cap this
      // read would buffer forever. The cap (5MB) must cancel the reader
      // after at most 3 chunks.
      const chunk = new Uint8Array(2 * 1024 * 1024);
      let reads = 0;
      let cancelled = false;
      const fetchImpl = async () => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: {
          getReader: () => ({
            read: async () => {
              reads++;
              return { done: false, value: chunk };
            },
            cancel: async () => { cancelled = true; },
          }),
        },
        text: async () => { throw new Error('text() must not be used when a streaming body exists'); },
      });
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.ok(findings.some((f) => f.id === 'provenance/fetch-failed'));
      assert.ok(cancelled, 'the stream must be cancelled once the cap is crossed');
      assert.ok(reads <= 4, `read loop must stop at the cap, saw ${reads} reads`);
    });

    it('F7: a response WITHOUT a streaming body degrades to fetch-failed — the text() fallback (unbounded buffering + UTF-16-unit size check) is gone', async () => {
      const servers = loadFixture('bad');
      let textCalled = false;
      const fetchImpl = async () => ({
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: null,
        text: async () => { textCalled = true; return '{}'; },
      });
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.ok(findings.some((f) => f.id === 'provenance/fetch-failed'));
      assert.strictEqual(textCalled, false, 'text() must never be called — there is no fallback read');
    });

    it('F7: the size cap counts BYTES, not UTF-16 code units — 2M euro-sign chars (6MB UTF-8) exceed the 5MB cap', async () => {
      const servers = loadFixture('bad');
      // 2 * 1024 * 1024 code units — under the cap if (mis)counted in
      // UTF-16 units, but 3 bytes each in UTF-8 = 6MB > 5MB.
      const multiByte = '€'.repeat(2 * 1024 * 1024);
      const fetchImpl = async () => new Response(multiByte, { status: 200 });
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run(servers, { online: true, fetchImpl });
      });
      assert.ok(findings.some((f) => f.id === 'provenance/fetch-failed'),
        'a 6MB-in-bytes body must be rejected even though it is only 2M UTF-16 units');
    });

    it('WR-03: a small streaming body is read fully and parsed normally', async () => {
      const servers = loadFixture('bad');
      const payload = Buffer.from(JSON.stringify({ dist: { attestations: { url: 'https://example.com' } } }));
      const fetchImpl = async () => {
        let delivered = false;
        return {
          ok: true,
          status: 200,
          headers: { get: (name) => (name === 'content-length' ? String(payload.length) : null) },
          body: {
            getReader: () => ({
              read: async () => {
                if (delivered) return { done: true, value: undefined };
                delivered = true;
                return { done: false, value: new Uint8Array(payload) };
              },
              cancel: async () => {},
            }),
          },
        };
      };
      const findings = await run(servers, { online: true, fetchImpl });
      // attestations present -> clean for npx servers; nothing degraded.
      assert.ok(!findings.some((f) => f.id === 'provenance/fetch-failed'));
      assert.ok(!findings.some((f) => f.id === 'provenance/no-attestation'));
    });
  });

  describe('D-08: npm-only gating', () => {
    it('uvx and url-only servers yield nothing, even online', async () => {
      const servers = loadFixture('bad');
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      const npxCount = servers.filter((s) => s.command === 'npx').length;
      assert.strictEqual(findings.length, npxCount);
    });

    it('uvx and url-only servers yield nothing offline either', async () => {
      const servers = loadFixture('bad');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      const npxCount = servers.filter((s) => s.command === 'npx').length;
      assert.strictEqual(findings.length, npxCount);
    });
  });

  describe('D-10: version selection', () => {
    it('a pinned spec fetches that exact version', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'pinned',
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem@1.2.3'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      let requestedUrl = null;
      const fetchImpl = async (url) => {
        requestedUrl = url;
        return new Response(JSON.stringify({ dist: {} }), { status: 200 });
      };
      await run(servers, { online: true, fetchImpl });
      assert.ok(requestedUrl, 'expected fetchImpl to be called');
      assert.ok(requestedUrl.endsWith('/1.2.3'), `expected pinned version in URL: ${requestedUrl}`);
      // IN-02: the scoped package name must be a single encoded path
      // segment (@scope/name -> %40scope%2Fname) — the registry URL
      // shape verified live; a change that stops encoding the '/'
      // would silently alter the path structure.
      assert.ok(
        requestedUrl.includes(encodeURIComponent('@modelcontextprotocol/server-filesystem')),
        `expected encoded scoped name segment in URL: ${requestedUrl}`
      );
    });

    it('an unpinned spec fetches "latest" and the message notes the caveat', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'unpinned',
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      let requestedUrl = null;
      const fetchImpl = async (url) => {
        requestedUrl = url;
        return new Response(JSON.stringify({ dist: {} }), { status: 200 });
      };
      const findings = await run(servers, { online: true, fetchImpl });
      assert.ok(requestedUrl, 'expected fetchImpl to be called');
      assert.ok(requestedUrl.endsWith('/latest'), `expected "latest" in URL: ${requestedUrl}`);
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f);
      assert.ok(f.message.toLowerCase().includes('latest'), `expected latest caveat in: ${f.message}`);
    });

    // WR-02 regression: ranges resolve against 'latest' with the caveat;
    // dist-tags are fetched directly but still carry the floating-ref
    // caveat; a v-prefixed exact semver is normalized (the registry
    // rejects v-prefixed versions).
    function npxServer(spec) {
      return [{
        agentId: 'claude-code',
        scope: 'user',
        configPath: '/fake',
        name: 'wr02',
        command: 'npx',
        args: [spec],
        env: {},
        url: null,
        headers: {},
      }];
    }

    function capturingFetch(holder) {
      return async (url) => {
        holder.url = url;
        return new Response(JSON.stringify({ dist: {} }), { status: 200 });
      };
    }

    it('WR-02: a caret range (pkg@^1.0.0) fetches "latest" and the caveat renders', async () => {
      const holder = {};
      const findings = await run(npxServer('pkg@^1.0.0'), { online: true, fetchImpl: capturingFetch(holder) });
      assert.ok(holder.url.endsWith('/latest'), `expected latest fetch for a caret range: ${holder.url}`);
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f);
      assert.ok(f.message.includes('latest'), `expected floating-ref caveat in: ${f.message}`);
    });

    it('WR-02: a tilde range (pkg@~2.3.4) fetches "latest", never the raw range', async () => {
      const holder = {};
      await run(npxServer('pkg@~2.3.4'), { online: true, fetchImpl: capturingFetch(holder) });
      assert.ok(holder.url.endsWith('/latest'), `expected latest fetch for a tilde range: ${holder.url}`);
      assert.ok(!holder.url.includes('~'), `raw range must never reach the URL: ${holder.url}`);
    });

    it('WR-02: an x-range (pkg@1.x) and an operator range (pkg@>=2.0.0) both fetch "latest"', async () => {
      const holder = {};
      await run(npxServer('pkg@1.x'), { online: true, fetchImpl: capturingFetch(holder) });
      assert.ok(holder.url.endsWith('/latest'), `expected latest for x-range: ${holder.url}`);
      await run(npxServer('pkg@>=2.0.0'), { online: true, fetchImpl: capturingFetch(holder) });
      assert.ok(holder.url.endsWith('/latest'), `expected latest for operator range: ${holder.url}`);
    });

    it('WR-02: a dist-tag (@scope/pkg@next) is fetched directly AND still carries the floating-ref caveat', async () => {
      const holder = {};
      const findings = await run(npxServer('@scope/pkg@next'), { online: true, fetchImpl: capturingFetch(holder) });
      assert.ok(holder.url.endsWith('/next'), `expected direct dist-tag fetch: ${holder.url}`);
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f, 'expected a no-attestation finding');
      assert.ok(f.message.includes('"next"'), `expected the dist-tag caveat in: ${f.message}`);
      assert.ok(f.message.includes('floating'), `expected floating-ref wording in: ${f.message}`);
    });

    it('WR-02: a v-prefixed exact semver (pkg@v1.2.3) is normalized to /1.2.3 and pinned (no caveat)', async () => {
      const holder = {};
      const findings = await run(npxServer('pkg@v1.2.3'), { online: true, fetchImpl: capturingFetch(holder) });
      assert.ok(holder.url.endsWith('/1.2.3'), `expected normalized version in URL: ${holder.url}`);
      const f = findings.find((x) => x.id === 'provenance/no-attestation');
      assert.ok(f);
      assert.ok(!f.message.includes('floating'), `pinned spec must not carry the caveat: ${f.message}`);
    });

    it('never re-reports unpinnedness itself (that is MCPD-01 territory)', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'unpinned',
          command: 'npx',
          args: ['@modelcontextprotocol/server-filesystem'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      const fetchImpl = fetchReturning({ body: { dist: {} } });
      const findings = await run(servers, { online: true, fetchImpl });
      assert.ok(!findings.some((f) => f.id.includes('unpinned')));
    });
  });

  describe('F6: lookup dedupe + bounded concurrency', () => {
    function npxNamed(name, spec) {
      return {
        agentId: 'claude-code',
        scope: 'user',
        configPath: '/fake',
        name,
        command: 'npx',
        args: [spec],
        env: {},
        url: null,
        headers: {},
      };
    }

    function deferred() {
      let resolve;
      const promise = new Promise((r) => { resolve = r; });
      return { promise, resolve };
    }

    const tick = () => new Promise((r) => setImmediate(r));

    it('identical pkg@ref lookups across servers share ONE request — fetchImpl called once, both findings emitted', async () => {
      let calls = 0;
      const fetchImpl = async () => {
        calls++;
        return new Response(JSON.stringify({ dist: {} }), { status: 200 });
      };
      const servers = [npxNamed('one', 'pkg@1.0.0'), npxNamed('two', 'pkg@1.0.0')];
      const findings = await run(servers, { online: true, fetchImpl });
      assert.strictEqual(calls, 1, 'the second identical lookup must reuse the in-flight promise');
      assert.strictEqual(findings.filter((f) => f.id === 'provenance/no-attestation').length, 2,
        'dedupe must not swallow the second server\'s finding');
    });

    it('distinct refs of the same package are NOT deduped', async () => {
      let calls = 0;
      const fetchImpl = async () => {
        calls++;
        return new Response(JSON.stringify({ dist: {} }), { status: 200 });
      };
      const servers = [npxNamed('one', 'pkg@1.0.0'), npxNamed('two', 'pkg@2.0.0')];
      await run(servers, { online: true, fetchImpl });
      assert.strictEqual(calls, 2);
    });

    it('at most 4 lookups are in flight; a 5th starts only after one completes (no real sleeps)', async () => {
      const gates = [];
      let started = 0;
      const fetchImpl = async () => {
        started++;
        const gate = deferred();
        gates.push(gate);
        await gate.promise;
        return new Response(JSON.stringify({ dist: { attestations: { url: 'https://example.com' } } }), { status: 200 });
      };
      const servers = Array.from({ length: 8 }, (_, i) => npxNamed(`s${i}`, `pkg-${i}@1.0.0`));
      const done = run(servers, { online: true, fetchImpl });
      await tick();
      assert.strictEqual(started, 4, `exactly the concurrency cap must start immediately, saw ${started}`);

      gates[0].resolve();
      for (let t = 0; t < 20 && started < 5; t++) await tick();
      assert.strictEqual(started, 5, 'a completed slot must admit exactly one more lookup');

      // Drain: keep resolving every open gate until all 8 have run.
      for (let t = 0; t < 100 && started < 8; t++) {
        for (const g of gates) g.resolve();
        await tick();
      }
      for (const g of gates) g.resolve();
      const findings = await done;
      assert.strictEqual(started, 8, 'every distinct lookup must eventually run');
      assert.deepStrictEqual(findings, [], 'attestations present -> clean');
    });

    it('findings order follows server index even when a later fetch resolves first', async () => {
      const slowGate = deferred();
      const fetchImpl = async (url) => {
        if (url.includes('slow-pkg')) await slowGate.promise;
        return new Response(JSON.stringify({ dist: {} }), { status: 200 });
      };
      const servers = [npxNamed('first', 'slow-pkg@1.0.0'), npxNamed('second', 'fast-pkg@1.0.0')];
      const done = run(servers, { online: true, fetchImpl });
      await tick();
      slowGate.resolve();
      const findings = await done;
      assert.deepStrictEqual(findings.map((f) => f.serverName), ['first', 'second'],
        'deterministic order by server index, not by response arrival');
    });
  });

  describe('hostile / edge-case handling', () => {
    it('empty servers array resolves to [] and does not throw', async () => {
      let findings;
      await assert.doesNotReject(async () => {
        findings = await run([], { online: false, fetchImpl: throwingFetch });
      });
      assert.deepStrictEqual(findings, []);
    });

    it('a server with command null produces no findings and does not throw, offline or online', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'no-command',
          command: null,
          args: [],
          env: {},
          url: null,
          headers: {},
        },
      ];
      await assert.doesNotReject(async () => {
        assert.deepStrictEqual(await run(servers, { online: false, fetchImpl: throwingFetch }), []);
        assert.deepStrictEqual(await run(servers, { online: true, fetchImpl: throwingFetch }), []);
      });
    });

    it('an npx server with only flag args (no package spec) produces no finding', async () => {
      const servers = [
        {
          agentId: 'claude-code',
          scope: 'user',
          configPath: '/fake',
          name: 'flags-only',
          command: 'npx',
          args: ['--yes'],
          env: {},
          url: null,
          headers: {},
        },
      ];
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      assert.deepStrictEqual(findings, []);
    });

    it('every emitted finding carries detector "provenance"', async () => {
      const servers = loadFixture('offline');
      const findings = await run(servers, { online: false, fetchImpl: throwingFetch });
      assert.ok(findings.length > 0);
      for (const f of findings) assert.strictEqual(f.detector, 'provenance');
    });

    it('does not construct RegExp dynamically from server data', () => {
      const src = fs.readFileSync(
        path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'provenance.js'),
        'utf8'
      );
      assert.strictEqual((src.match(/new RegExp/g) || []).length, 0);
    });

    it('F9: the response size cap aliases base.js MAX_CONFIG_SIZE — never a drift-prone twin literal', () => {
      const src = fs.readFileSync(
        path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'provenance.js'),
        'utf8'
      );
      assert.ok(src.includes('const MAX_RESPONSE_SIZE = MAX_CONFIG_SIZE'),
        'MAX_RESPONSE_SIZE must alias the imported MAX_CONFIG_SIZE');
      assert.ok(!/MAX_RESPONSE_SIZE\s*=\s*\d/.test(src),
        'MAX_RESPONSE_SIZE must not be a numeric literal');
    });

    it('the registry host is a hardcoded literal, never built from server.url', () => {
      const src = fs.readFileSync(
        path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors', 'provenance.js'),
        'utf8'
      );
      assert.ok(src.includes("'registry.npmjs.org'"));
      assert.ok(!/server\.url.*registry\.npmjs\.org/.test(src));
    });
  });
});
