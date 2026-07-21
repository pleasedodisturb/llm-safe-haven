'use strict';

// Shared fixture factories (Phase 11 / TESTQ-02 — previously byte-identical
// copies lived in tests/install.test.js and tests/audit.test.js).
//
// Lives under tests/helpers/ (NOT matching the package.json test glob
// `tests/*.test.js`), so the test runner never picks it up as a test file.
//
// Real (non-stubbed) collaborators: mcp/base.js frozen enums/Finding. This
// require is one level deeper than tests/*.test.js (tests/helpers/ ->
// lib/mcp/base.js), hence the ../../ prefix.
const { CONFIDENCE, EXIT, Finding, SEVERITY } = require('../../lib/mcp/base.js');

function fakeAgent(overrides = {}) {
  return {
    id: 'fake-agent',
    name: 'Fake Agent',
    tier: 1,
    detected: { found: true, version: '1.2.3' },
    audit: () => ({ checks: [{ name: 'check', detail: 'ok', pass: true }], level: 3 }),
    ...overrides,
  };
}

function mcpFinding(overrides = {}) {
  return Finding({
    id: 'detector/rule',
    detector: 'detector',
    severity: SEVERITY.HIGH,
    confidence: CONFIDENCE.VERIFIED,
    agentId: 'fake-agent',
    scope: 'user',
    serverName: 'srv',
    message: 'a finding',
    ...overrides,
  });
}

function envelope({ exitCode = EXIT.CLEAN, findings = [] } = {}) {
  return { exitCode, findings, servers: [], sources: [] };
}

module.exports = { fakeAgent, mcpFinding, envelope };
