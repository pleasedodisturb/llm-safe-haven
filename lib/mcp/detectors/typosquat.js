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
 *   (1) the derived NAME segment vs every BARE-stored allowlist entry
 *       AND every full-spec entry's NAME HALF (F3: pools are derived
 *       from ONE storage shape in indexAllowlist — an UNSCOPED
 *       single-edit typo of a full-spec entry's name half, e.g.
 *       "kontext7-mcp" vs "@upstash/context7-mcp", was previously
 *       unreachable: class 1 only saw bare-stored entries and class 3
 *       only compared full inputs). A name-half hit names the FULL SPEC
 *       in the finding message.
 *   (2) the derived SCOPE segment vs every knownScopes entry — catches a
 *       scope-squat (e.g. "@modelcontextprotocoI", capital I) even when
 *       the trailing name segment is a legitimate, exactly-known name.
 *   (3) the FULL derived spec (@scope/name, or the bare name if unscoped)
 *       vs every FULL-SPEC-stored allowlist entry — catches the scoped
 *       single-edit near-miss ("@upstash/kontext7-mcp") where the edit
 *       may fall in either segment.
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

// F4: npm's maximum package-name length. An input segment longer than
// this can never be a plausible npm name, and — with the near-match
// threshold capped at 2 — can never be within threshold of any real
// allowlist entry. Refusing to compare it bounds editDistance's O(a*b)
// cost against attacker-sized args (a hostile config arg is unbounded;
// a multi-hundred-KB "name" would otherwise allocate a matrix of
// hundreds of millions of cells per allowlist entry).
const MAX_COMPARED_LENGTH = 214;

/**
 * Restricted (OSA) Damerau-Levenshtein distance between two strings.
 * O(a.length * b.length) time, O(b.length) space — rolling three-row DP
 * (curr/prev, plus prev2 for the transposition lookback) instead of the
 * full matrix (F4). Callers bound a.length via MAX_COMPARED_LENGTH and
 * prune length-mismatched pairs before calling.
 */
function editDistance(a, b) {
  const al = a.length;
  const bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;

  let prev2 = null;
  let prev = new Array(bl + 1);
  for (let j = 0; j <= bl; j++) prev[j] = j;

  for (let i = 1; i <= al; i++) {
    const curr = new Array(bl + 1);
    curr[0] = i;
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1, // deletion
        curr[j - 1] + 1, // insertion
        prev[j - 1] + cost // substitution
      );
      // Transposition (restricted/OSA): adjacent swap only.
      if (
        i > 1 && j > 1 &&
        a[i - 1] === b[j - 2] &&
        a[i - 2] === b[j - 1]
      ) {
        curr[j] = Math.min(curr[j], prev2[j - 2] + cost);
      }
    }
    prev2 = prev;
    prev = curr;
  }
  return prev[bl];
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
 *
 * F3 derivation discipline — every pool traces back to ONE storage
 * shape, never a hand-maintained sibling list:
 *   - nameCandidates (the class-1 near-match pool) is DERIVED here from
 *     bare entries plus every full-spec entry's name half, each mapped
 *     to the allowlist entry a finding should NAME (the full spec for a
 *     name half). A full-spec entry added to servers[] automatically
 *     contributes its name half — no second list to keep in lockstep.
 *   - scopedOnly[] stays a manifest field (it encodes information the
 *     entries themselves cannot: WHICH bare entries are scoped-only),
 *     but is VALIDATED at load time: every scopedOnly entry must exist
 *     as a bare servers[] entry, otherwise the two arrays have drifted
 *     apart and the whole allowlist is treated as malformed
 *     ({ ok:false } -> allowlist-unavailable) rather than silently
 *     mis-classifying names.
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

  // F3 lockstep check: a scopedOnly[] entry with no matching bare
  // servers[] entry means the manifest's two arrays drifted — fail
  // closed (the caller reports allowlist-unavailable, never a silently
  // weaker scan).
  for (const name of scopedOnlyNames) {
    if (!bareServers.has(name)) return { ok: false };
  }

  // F3: class-1 candidate pool — bare entries name themselves; a
  // full-spec entry's name half names the full spec. A half that
  // collides with an existing bare entry keeps the bare entry's display
  // (the bare entry is exact-known on its own and more specific).
  const nameCandidates = new Map();
  for (const entry of bareServers) nameCandidates.set(entry, entry);
  for (const [half, scopes] of fullSpecNameHalves) {
    if (!nameCandidates.has(half)) {
      nameCandidates.set(half, `${scopes.values().next().value}/${half}`);
    }
  }

  return { ok: true, knownScopes, scopedOnlyNames, bareServers, fullSpecServers, fullSpecNameHalves, nameCandidates };
}

/**
 * Finds the closest within-threshold, non-zero-distance match between
 * `input` and every string in `candidates`. The threshold for each pair
 * is decided from the SHORTER of the two segment lengths (D-03 FP guard —
 * a very short candidate is just as noisy to match against as a very
 * short input). Returns null when nothing qualifies.
 */
function closestNearMatch(input, candidates) {
  // F4: an attacker-sized input segment (longer than any legal npm
  // name) can never be within threshold of a real allowlist entry —
  // skip ALL comparisons before any matrix work.
  if (input.length > MAX_COMPARED_LENGTH) return null;
  let best = null;
  for (const candidate of candidates) {
    const threshold = thresholdFor(Math.min(input.length, candidate.length));
    if (threshold === null) continue;
    // F4: |len(a) - len(b)| is a lower bound on edit distance — a pair
    // whose length difference already exceeds the threshold can never
    // qualify; skip the DP entirely.
    if (Math.abs(input.length - candidate.length) > threshold) continue;
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

  // D-07 (+F3): a load failure OR an internally-inconsistent manifest
  // (scopedOnly[] entry missing from servers[]) both fail closed as
  // allowlist-unavailable — never a silently weaker scan.
  const allowlistResult = loadAllowlist(context);
  const index = allowlistResult.ok ? indexAllowlist(allowlistResult.manifest) : { ok: false };
  if (!index.ok) {
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

  const { knownScopes, scopedOnlyNames, bareServers, fullSpecServers, fullSpecNameHalves, nameCandidates } = index;

  for (const server of Array.isArray(servers) ? servers : []) {
    const bin = commandBasename(server.command);
    if (bin !== 'npx' && bin !== 'uvx') continue;

    const args = Array.isArray(server.args) ? server.args : [];
    const pkgName = derivePackageName(args, bin);
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
    // Each candidate carries the KIND of allowlist entry it matched
    // (IN-03): a class-2 hit matched a SCOPE, not a package, and the
    // message must say so — comparing a full name against a scope reads
    // as a larger edit distance than stated.
    let best = null;
    const consider = (candidate, kind) => {
      if (candidate !== null && (best === null || candidate.distance < best.distance)) {
        best = { distance: candidate.distance, knownName: candidate.knownName, kind };
      }
    };

    // Class 1: name segment vs every bare-stored entry AND every
    // full-spec entry's name half (F3) — a name-half hit reports the
    // full spec it belongs to.
    const class1 = closestNearMatch(pkgNameOnly, nameCandidates.keys());
    consider(class1 === null ? null : { distance: class1.distance, knownName: nameCandidates.get(class1.knownName) }, 'package');

    // Class 2: scope segment vs every knownScopes entry (catches
    // scope-squats even when the name segment is exactly known).
    if (pkgScope !== null) {
      consider(closestNearMatch(pkgScope, knownScopes), 'scope');
    }

    // Class 3: the FULL derived spec vs every FULL-SPEC-stored entry —
    // catches scoped near-misses where the edit may fall in either
    // segment of the full spec.
    consider(closestNearMatch(pkgName, fullSpecServers), 'package');

    if (best !== null) {
      const subject = best.kind === 'scope'
        ? `package "${pkgName}"'s scope "${pkgScope}"`
        : `package "${pkgName}"`;
      findings.push(Finding({
        id: `${id}/near-known-name`,
        detector: id,
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.VERIFIED,
        agentId: server.agentId,
        scope: server.scope,
        serverName: server.name,
        message: `Server "${server.name}"'s ${subject} is within edit distance ${best.distance} of known ${best.kind} "${best.knownName}" — possible typosquat.`,
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
