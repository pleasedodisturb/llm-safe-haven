'use strict';

/**
 * Tool-name shadowing / server-name collision detector (Phase 5, MCPD-08).
 *
 * Static config files carry no live tool list — literal tool-level
 * shadowing (a runtime introspection concept) is not something this
 * detector can structurally observe (research Pitfall 2 / Assumption A4).
 * The honest static proxy: group servers across the FULL cross-server
 * array (D-02; Open Question 2 resolution — compares across ALL
 * agents/scopes) by `name`, and flag any name whose (command, args, url)
 * signature differs across occurrences — the same identifier resolving
 * to different implementations depending on which configured source a
 * client reads. An identical signature under the same name across
 * scopes is Claude Code's legitimate scope-override design and produces
 * zero findings. Every finding message states this is a static
 * server-name collision check, not verified tool-level shadowing,
 * mirroring MCPD-05's D-09 honesty framing, with no specific attack
 * narrative implied.
 */

const { Finding, SEVERITY, CONFIDENCE } = require('../base.js');

const id = 'tool-shadowing';
const requirement = 'MCPD-08';

/**
 * Groups servers by name (servers with a falsy name are ignored) and
 * compares the (command, args, url) signature across occurrences.
 * Returns one entry per name with more than one distinct signature;
 * `sources` is the count of distinct signatures (not raw occurrences).
 */
function findNameCollisions(servers) {
  const byName = new Map();
  for (const s of Array.isArray(servers) ? servers : []) {
    if (!s.name) continue;
    const sig = JSON.stringify([s.command, s.args, s.url]);
    if (!byName.has(s.name)) byName.set(s.name, new Set());
    byName.get(s.name).add(sig);
  }
  return [...byName.entries()]
    .filter(([, sigs]) => sigs.size > 1)
    .map(([name, sigs]) => ({ name, sources: sigs.size }));
}

function run(servers, context = {}) {
  return findNameCollisions(servers).map(({ name, sources }) => Finding({
    id: `${id}/name-collision`,
    detector: id,
    severity: SEVERITY.MEDIUM,
    confidence: CONFIDENCE.VERIFIED,
    agentId: null,
    scope: null,
    serverName: name,
    message: `Server name "${name}" resolves to ${sources} different configurations across configured sources. This is a static server-name collision check, not verified tool-level shadowing.`,
  }));
}

module.exports = { id, requirement, run };
