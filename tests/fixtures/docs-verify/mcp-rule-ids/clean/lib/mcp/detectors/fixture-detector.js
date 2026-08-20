'use strict';

// Fixture detector for tests/docs-verify/mcp-rule-ids.test.js and the
// clean/defect fixture pair under tests/fixtures/docs-verify/mcp-rule-ids/.
// Reproduces the real shipped shape lib/docs-verify/mcp-rule-ids.js parses:
// two literal `${id}/<suffix>` emission sites, mirroring
// lib/mcp/detectors/credential-passthrough.js, plus one dynamic
// `${id}/${bin}-no-version` site whose `bin` value is fixed by a
// two-value strict-equality comparison set, mirroring
// lib/mcp/detectors/unpinned-execution.js:80/:96.

const id = 'fixture-detector';

function run(servers) {
  const findings = [];

  for (const server of Array.isArray(servers) ? servers : []) {
    const bin = server.bin;
    if (bin === 'npx' || bin === 'uvx') {
      findings.push({
        id: `${id}/${bin}-no-version`,
      });
    }
  }

  findings.push({ id: `${id}/inlined-secret` });
  findings.push({ id: `${id}/broad-inheritance` });

  return findings;
}

module.exports = { id, run };
