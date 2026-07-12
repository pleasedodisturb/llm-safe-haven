'use strict';

/**
 * Typosquat-proximity detector (Phase 6, MCPD-03).
 *
 * For every npx/uvx server, derives the install-time package name (D-01 —
 * via npx-args.js's derivePackageName, NEVER server.name; a benign display
 * name with a typosquat in the args is still flagged) and compares it
 * against the bundled manifests/mcp-known-servers.json allowlist. A server
 * whose url is set but has no npx/uvx command produces zero findings —
 * this detector never inspects server.url (D-01).
 *
 * D-02: an EXACT match short-circuits to zero findings for that server,
 * even when the derived name happens to be within threshold of a
 * DIFFERENT allowlist entry. Two allowlist storage shapes both count as
 * "known": a bare name and a full "@scope/name" spec (~10 of 28 entries,
 * e.g. "@upstash/context7-mcp", stored whole because their scope is not
 * a blanket-trusted knownScopes entry on its own). Bare entries have two
 * meanings the manifest distinguishes (WR-04): genuinely-unscoped npm
 * names (e.g. "firecrawl-mcp" — exact-known on their own) vs
 * scopedOnly[] name halves (e.g. "server-filesystem" — only known when
 * paired with a knownScopes[] scope; bare or foreign-scoped use is
 * scope-confusion, see below).
 *
 * D-03: distance is a restricted (OSA) Damerau-Levenshtein edit distance.
 * The threshold is decided PER COMPARISON PAIR from the shorter of the two
 * segment lengths (min(a.length, b.length)) — this is the FP guard: any
 * pair where the shorter side is under 4 characters is skipped entirely
 * (a 1-char edit on a 3-char string is proportionally huge and noisy),
 * 4-6 chars allows distance <= 1, 7+ chars allows distance <= 2.
 *
 * Near-match is computed across THREE comparison classes, and the closest
 * within-threshold hit across all three wins:
 *   (1) the derived NAME segment vs every BARE-stored allowlist entry —
 *       catches the classic single-edit package-name typosquat.
 *   (2) the derived SCOPE segment vs every knownScopes entry — catches a
 *       scope-squat (e.g. "@modelcontextprotocoI", capital I) even when
 *       the trailing name segment is a legitimate, exactly-known name.
 *   (3) the FULL derived spec (@scope/name, or the bare name if unscoped)
 *       vs every FULL-SPEC-stored allowlist entry — without this class a
 *       single-edit near-miss of a full-spec-stored entry (e.g.
 *       "@upstash/kontext7-mcp" vs "@upstash/context7-mcp") is
 *       structurally unreachable by classes (1)/(2), since the bare name
 *       half of a full-spec entry is never stored on its own.
 * A distance-0 comparison result is never a "near" hit — it means that
 * particular segment IS a known value, which is not typosquat signal on
 * its own (this is what keeps D-04's combosquat fixture at zero findings:
 * its scope segment is an exact match, but that alone must not fire).
 *
 * WR-04 scope-confusion class (exact-name, NOT distance-based, checked
 * only when no near-match fired): an input whose NAME segment exactly
 * matches a known scoped entry's name half — a manifest scopedOnly[]
 * entry (the @modelcontextprotocol server-* halves, only legitimate
 * under a known scope) or the name half of a full-spec entry — but whose
 * scope is missing or unrecognized is flagged typosquat/scope-confusion
 * (high): both the unscoped bare name ("server-filesystem") and a
 * foreign-scope variant ("@evil/server-filesystem") are
 * attacker-registerable npm names, and an exact known name under the
 * wrong/no scope is a stronger squat signal than a distance-1 edit.
 * Name segments under 4 chars are exempt (the D-03 FP guard — e.g. the
 * "mcp" half of "@playwright/mcp" would otherwise flag every bare "mcp"
 * package). Honest limitation: a GENUINELY-UNSCOPED known name
 * republished under a foreign scope (e.g. "@evil/firecrawl-mcp") is NOT
 * flagged — legitimate scoped forks of unscoped packages are common
 * enough that the exact-name signal is weak there; the distance classes
 * still apply to it.
 *
 * D-04 (honest limitation, deliberate): edit distance cannot and does not
 * attempt to catch a combosquat (a legitimate-looking compound name like
 * "easy-server-filesystem" that inserts/prepends several characters) —
 * the distance is always far outside threshold for that failure mode.
 * This is locked by a passing zero-findings regression test, not
 * pretended coverage.
 *
 * D-07: the allowlist is REQUIRED input for this detector's core check,
 * not best-effort enrichment (a deliberate divergence from tool-poisoning's
 * Tier-2 "skip silently" idiom) — a load failure (missing/corrupt/
 * oversized/symlinked/missing servers[]) emits exactly ONE
 * typosquat/allowlist-unavailable finding (info, unverified) and returns
 * immediately. It never returns [] on failure (which would read as
 * "clean") and never throws.
 */

const path = require('path');
const { Finding, SEVERITY, CONFIDENCE, readConfigSafe } = require('../base.js');
const { commandBasename, derivePackageName } = require('../npx-args.js');

const id = 'typosquat';
const requirement = 'MCPD-03';

/**
 * Restricted (OSA) Damerau-Levenshtein distance between two strings.
 * O(a.length * b.length) time and space — trivial at allowlist scale
 * (~28 entries, segments under ~40 chars).
 */
function editDistance(a, b) {
  const al = a.length;
  const bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;

  const d = Array.from({ length: al + 1 }, () => new Array(bl + 1).fill(0));
  for (let i = 0; i <= al; i++) d[i][0] = i;
  for (let j = 0; j <= bl; j++) d[0][j] = j;

  for (let i = 1; i <= al; i++) {
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost // substitution
      );
      // Transposition (restricted/OSA): adjacent swap only.
      if (
        i > 1 && j > 1 &&
        a[i - 1] === b[j - 2] &&
        a[i - 2] === b[j - 1]
      ) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + cost);
      }
    }
  }
  return d[al][bl];
}

// D-03: segments shorter than 4 chars skip matching entirely (FP guard);
// 4-6 chars allows distance <= 1; 7+ chars allows distance <= 2.
function thresholdFor(segmentLength) {
  if (segmentLength < 4) return null;
  return segmentLength <= 6 ? 1 : 2;
}

/**
 * D-07: readConfigSafe + JSON.parse + servers[]-array validation. Returns
 * { ok:false } on ANY failure — missing/corrupt/oversized/symlinked file,
 * a non-object parse result, or a missing/non-array servers field. context
 * is threaded straight through to readConfigSafe so its opts.fs convention
 * remains test-injectable.
 */
function loadAllowlist(context = {}) {
  const manifestPath = context.manifestPath || path.join(__dirname, '..', '..', '..', 'manifests', 'mcp-known-servers.json');
  const result = readConfigSafe(manifestPath, context);
  if (!result.ok) return { ok: false };
  try {
    const parsed = JSON.parse(result.raw);
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.servers)) return { ok: false };
    return { ok: true, manifest: parsed };
  } catch {
    return { ok: false };
  }
}

/**
 * Splits manifest.servers into bare-name entries (no "/") and full-spec
 * entries ("@scope/name", ~10 of 28) — the two comparison-class pools —
 * plus the knownScopes set. Non-string entries are dropped defensively.
 *
 * WR-04 additions: scopedOnlyNames (manifest.scopedOnly — the subset of
 * bare entries that are name-halves of scoped packages, NOT genuinely
 * unscoped npm names) and fullSpecNameHalves (name half -> Set of
 * scopes it is known under, derived from the full-spec entries) — the
 * two pools the scope-confusion class checks exact name matches
 * against.
 */
function indexAllowlist(manifest) {
  const knownScopes = new Set(Array.isArray(manifest.knownScopes) ? manifest.knownScopes.filter(s => typeof s === 'string') : []);
  const scopedOnlyNames = new Set(Array.isArray(manifest.scopedOnly) ? manifest.scopedOnly.filter(s => typeof s === 'string' && s !== '') : []);
  const bareServers = new Set();
  const fullSpecServers = new Set();
  const fullSpecNameHalves = new Map();
  for (const entry of manifest.servers) {
    if (typeof entry !== 'string' || entry === '') continue;
    if (entry.includes('/')) {
      fullSpecServers.add(entry);
      const m = /^(@[^/]+)\/(.+)$/.exec(entry);
      if (m) {
        if (!fullSpecNameHalves.has(m[2])) fullSpecNameHalves.set(m[2], new Set());
        fullSpecNameHalves.get(m[2]).add(m[1]);
      }
    } else {
      bareServers.add(entry);
    }
  }
  return { knownScopes, scopedOnlyNames, bareServers, fullSpecServers, fullSpecNameHalves };
}

/**
 * Finds the closest within-threshold, non-zero-distance match between
 * `input` and every string in `candidates`. The threshold for each pair
 * is decided from the SHORTER of the two segment lengths (D-03 FP guard —
 * a very short candidate is just as noisy to match against as a very
 * short input). Returns null when nothing qualifies.
 */
function closestNearMatch(input, candidates) {
  let best = null;
  for (const candidate of candidates) {
    const threshold = thresholdFor(Math.min(input.length, candidate.length));
    if (threshold === null) continue;
    const distance = editDistance(input, candidate);
    if (distance <= 0 || distance > threshold) continue;
    if (best === null || distance < best.distance) {
      best = { distance, knownName: candidate };
    }
  }
  return best;
}

function run(servers, context = {}) {
  const findings = [];

  const allowlistResult = loadAllowlist(context);
  if (!allowlistResult.ok) {
    findings.push(Finding({
      id: `${id}/allowlist-unavailable`,
      detector: id,
      severity: SEVERITY.INFO,
      confidence: CONFIDENCE.UNVERIFIED,
      agentId: null,
      scope: null,
      serverName: null,
      message: 'The bundled MCP known-servers allowlist could not be loaded (missing, corrupt, or malformed) — typosquat proximity checks were skipped for this scan.',
    }));
    return findings;
  }

  const { knownScopes, scopedOnlyNames, bareServers, fullSpecServers, fullSpecNameHalves } = indexAllowlist(allowlistResult.manifest);

  for (const server of Array.isArray(servers) ? servers : []) {
    const bin = commandBasename(server.command);
    if (bin !== 'npx' && bin !== 'uvx') continue;

    const args = Array.isArray(server.args) ? server.args : [];
    const pkgName = derivePackageName(args);
    if (!pkgName) continue;

    const scopeMatch = /^(@[^/]+)\/(.+)$/.exec(pkgName);
    const pkgScope = scopeMatch ? scopeMatch[1] : null;
    const pkgNameOnly = scopeMatch ? scopeMatch[2] : pkgName;

    // D-02 exact-match short-circuit — checked BEFORE any near-match
    // computation, so an exact match never even gets compared against a
    // different, nearby entry.
    const exactBare = bareServers.has(pkgNameOnly);
    const exactFull = pkgScope !== null && fullSpecServers.has(pkgName);
    const exactKnownScope = pkgScope !== null && knownScopes.has(pkgScope);

    if (exactFull) continue;
    // WR-04: an unscoped input only short-circuits as exact-known when
    // the bare entry is GENUINELY unscoped — a scopedOnly[] name half
    // (e.g. "server-filesystem") published without its scope is an
    // attacker-registerable npm name and must fall through to the
    // scope-confusion check below.
    if (pkgScope === null && exactBare && !scopedOnlyNames.has(pkgNameOnly)) continue;
    if (pkgScope !== null && exactKnownScope && exactBare) continue;

    // Near-match, closest hit across all three comparison classes wins.
    let best = null;
    const consider = (candidate) => {
      if (candidate !== null && (best === null || candidate.distance < best.distance)) {
        best = candidate;
      }
    };

    // Class 1: name segment vs every BARE-stored entry.
    consider(closestNearMatch(pkgNameOnly, bareServers));

    // Class 2: scope segment vs every knownScopes entry (catches
    // scope-squats even when the name segment is exactly known).
    if (pkgScope !== null) {
      consider(closestNearMatch(pkgScope, knownScopes));
    }

    // Class 3: the FULL derived spec vs every FULL-SPEC-stored entry —
    // reaches the ~10 allowlist entries whose bare-name half is never
    // stored on its own.
    consider(closestNearMatch(pkgName, fullSpecServers));

    if (best !== null) {
      findings.push(Finding({
        id: `${id}/near-known-name`,
        detector: id,
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}"'s package "${pkgName}" is within edit distance ${best.distance} of known package "${best.knownName}" — possible typosquat.`,
      }));
      continue;
    }

    // WR-04 scope-confusion class: no near-match fired, but the NAME
    // segment EXACTLY matches a known scoped entry's name half while
    // the scope is missing or unrecognized — both variants are
    // attacker-registerable npm names. Name halves under 4 chars are
    // exempt (D-03 FP guard). A recognized scope never reaches a
    // finding: exact full-spec matches and knownScope+bare pairings
    // already short-circuited above, and any remaining knownScopes
    // scope requires owning that scope to publish under (unexploitable).
    if (pkgNameOnly.length >= 4 && (scopedOnlyNames.has(pkgNameOnly) || fullSpecNameHalves.has(pkgNameOnly))) {
      const legitimateScopes = fullSpecNameHalves.get(pkgNameOnly);
      const scopeRecognized = pkgScope !== null &&
        (knownScopes.has(pkgScope) || (legitimateScopes !== undefined && legitimateScopes.has(pkgScope)));
      if (!scopeRecognized) {
        const reason = pkgScope === null
          ? 'is the exact name of a known scoped package, published WITHOUT its scope — the unscoped npm name is registerable by anyone'
          : `reuses the exact name of a known scoped package under the unrecognized scope "${pkgScope}"`;
        findings.push(Finding({
          id: `${id}/scope-confusion`,
          detector: id,
          severity: SEVERITY.HIGH,
          confidence: CONFIDENCE.VERIFIED,
          agentId: server.agentId,
          scope: server.scope,
          serverName: server.name,
          message: `Server "${server.name}"'s package "${pkgName}" ${reason} — possible scope-confusion squat.`,
        }));
      }
    }
  }

  return findings;
}

module.exports = { id, requirement, run };
