'use strict';

/**
 * Check 6 -- documented-command and inline path sanity, broadened per D-03
 * (G-1570, GUARD-01).
 *
 * Implements the pinned grammar in
 * .planning/phases/21-doc-drift-guard/21-04-PLAN.md Task 1. Read that
 * section before editing this file.
 *
 * D-03 BROADENING: candidates come from TWO places -- a fenced command
 * block (tokenizeFencedLine) AND a single-backtick span anywhere in prose
 * OUTSIDE a fence (the inline branch below). This is what makes DOC-03a
 * mechanically nameable: docs/credential-management.md:564 tells the
 * reader to review a flat `~/.claude/audit.jsonl` file in inline prose,
 * not inside a fenced block -- a fence-only scanner would never see it.
 *
 * NEVER-EXECUTE: this module contains NO subprocess-spawning or network
 * primitive of any kind. A documented command is tokenised as text and
 * never run -- enforced positively by
 * tests/docs-verify/commands.test.js's sentinel-file-absence case and
 * negatively by that same test file's source scan for the relevant
 * Node built-in APIs (never named literally in this comment, so this
 * file's own prose cannot trip its own negative scan).
 *
 * HONEST SCOPE (21-04-PLAN.md "Honest scope" section): the agent-home
 * segment rule is a PRESENCE test, not a composition test. A
 * composition-tuple match (the ordered string-literal arguments of a
 * SAME-FILE path.join(...)/path.resolve(...) call) is preferred, strong
 * evidence; a bare-literal-presence match is the weaker fallback tier,
 * and the finding text always says which tier failed. A wrong
 * ARRANGEMENT of real segments that never happens to co-occur in a
 * composition call is not caught by the weak tier -- a stated precision
 * limit, not an undiscovered bug.
 *
 * PLACEHOLDER GRAMMAR (21-REVIEW.md CR-01): a fourth shape, a
 * shell-variable interpolation (`$var` / `${var}`), is also exempt from
 * the segment rule -- it is a runtime substitution bound by the enclosing
 * shell construct (e.g. a `for hook in ...; do ... $hook ... done` loop),
 * never a literal filename claim, so it is never existence/presence
 * checked against source. docs/guides/quick-start.md:659 is the real
 * corpus's example of this shape.
 */

const fs = require('fs');
const path = require('path');

const { resolveInRoot } = require('./helpers/context.js');

const id = 'commands';

// Repo-relative prefixes: everything under these top-level directories is
// in scope for existence-checking against the inspected root.
const REPO_RELATIVE_PREFIXES = Object.freeze([
  'hooks/',
  'lib/',
  'docs/',
  'scripts/',
  'bin/',
  'tests/',
  // 21-REVIEW.md WR-03: the repo genuinely has both `test/` and `tests/`
  // top-level directories (package.json's own `test` script runs both;
  // `test/backup-file.test.js` exists on disk) -- discover-md.js's own
  // STATIC_SKIP_DIRS already anticipates both spellings, so omitting this
  // one here was an oversight, not a deliberate scope decision.
  'test/',
  'manifests/',
  '.github/',
]);

// Agent-home prefix: graded segment-wise against source literals scraped
// from hooks/**/*.js and lib/**/*.js -- never dereferenced against a real
// home directory (T-21-04-02).
const AGENT_HOME_PREFIX = '~/.claude/';

// A single frozen array with two groups, per the plan's Artifacts table --
// callers that need to distinguish the groups use AGENT_HOME_PREFIX /
// REPO_RELATIVE_PREFIXES directly (below), which this array is built from.
const INTERNAL_PATH_PREFIXES = Object.freeze([...REPO_RELATIVE_PREFIXES, AGENT_HOME_PREFIX]);

// ---------------------------------------------------------------------------
// Placeholder segment grammar
// ---------------------------------------------------------------------------

// A segment CONTAINING an angle-bracketed span -- a containment test
// (matching the wildcard rule's own containment shape below), so both the
// bare `<name>` form the acceptance grammar tests AND a real-corpus form
// with a trailing extension outside the brackets (`.github/agent-
// protocols/<file>.md`) are both exempt.
const ANGLE_BRACKET_SEGMENT_RE = /<[^<>]+>/;

// A segment CONTAINING an asterisk or a question mark anywhere -- per the
// plan text ("a wildcard token containing an asterisk or a question
// mark"), this is a containment test, not a full-segment-match test.
const WILDCARD_SEGMENT_CHARS_RE = /[*?]/;

// The literal placeholder spelling: four Y, a hyphen, two M, a hyphen, two
// D, case-insensitive, with an optional dotted extension. A near-miss
// (three Ys, lowercase mismatched counts, etc.) must NOT match.
const DATE_PLACEHOLDER_SPELLING_RE = /^YYYY-MM-DD(\.[A-Za-z0-9]+)?$/i;

// A real digit date: four digits, a hyphen, two digits, a hyphen, two
// digits, with an optional dotted extension. A near-miss (single-digit
// month/day) must NOT match.
const DIGIT_DATE_RE = /^\d{4}-\d{2}-\d{2}(\.[A-Za-z0-9]+)?$/;

// A segment that IS, or STARTS WITH, a shell-variable reference -- `$var`
// or `${var}` -- substituted at runtime by the enclosing shell construct
// (e.g. a `for` loop) and therefore never a literal filename claim
// (21-REVIEW.md CR-01). Anchored at the start only (a leading '$'), so a
// bare word ('hook') or a trailing-only '$' ('hook$') does NOT match.
const SHELL_VAR_SEGMENT_RE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/;

/**
 * isDateShapedSegment(segment) -- accepts BOTH spellings (both required,
 * the corpus contains each): the literal `YYYY-MM-DD` placeholder text,
 * and a real digit date. Written as two named static regex literals
 * rather than one combined pattern, so dropping either one is visible.
 */
function isDateShapedSegment(segment) {
  const s = String(segment);
  return DATE_PLACEHOLDER_SPELLING_RE.test(s) || DIGIT_DATE_RE.test(s);
}

/**
 * isPlaceholderSegment(segment) -- four disjoint shapes: an
 * angle-bracketed name, a wildcard token, a shell-variable interpolation
 * (CR-01), or a date-shaped token (delegated to isDateShapedSegment).
 */
function isPlaceholderSegment(segment) {
  const s = String(segment);
  if (ANGLE_BRACKET_SEGMENT_RE.test(s)) return true;
  if (WILDCARD_SEGMENT_CHARS_RE.test(s)) return true;
  if (SHELL_VAR_SEGMENT_RE.test(s)) return true;
  if (isDateShapedSegment(s)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Fenced-line tokenisation (pinned grammar)
// ---------------------------------------------------------------------------

// A trailing backslash (optionally followed by whitespace) at end-of-line
// -- a shell line continuation. Unsupported: yields zero candidates rather
// than a partial token list.
const TRAILING_BACKSLASH_RE = /\\\s*$/;

// A leading shell prompt ("$ ") or a leading comment marker ("# "),
// stripped before tokenising.
const LEADING_PROMPT_OR_COMMENT_RE = /^\s*(?:\$|#)\s+/;

/**
 * tokenizeFencedLine(line) -- returns the candidate tokens for one fenced
 * line under the pinned rules (see 21-04-PLAN.md Task 1 <action>):
 *   - a trailing backslash continuation yields [] (unsupported shape);
 *   - a leading "$ " prompt or "# " comment marker is stripped;
 *   - split on whitespace runs; a quoted run containing a space is
 *     dropped entirely (never reassembled into two wrong candidates); a
 *     fully-quoted single token has its outer quote pair stripped;
 *   - a token beginning with "-" (a flag), containing "=" (an
 *     assignment), or naming a URI scheme / "://" (a URL) is dropped.
 * Heredoc-body awareness is NOT this function's job -- it has no
 * cross-line state. extractPathTokens (below) tracks heredoc state across
 * lines and never calls this function on a heredoc marker/body/terminator
 * line.
 */
function tokenizeFencedLine(line) {
  const raw = String(line);
  if (TRAILING_BACKSLASH_RE.test(raw)) return [];

  const stripped = raw.replace(LEADING_PROMPT_OR_COMMENT_RE, '');
  const rawTokens = stripped.split(/\s+/).filter((t) => t.length > 0);

  const tokens = [];
  let skippingQuoted = false;
  let quoteChar = null;

  for (const tok0 of rawTokens) {
    if (skippingQuoted) {
      if (tok0.endsWith(quoteChar)) {
        skippingQuoted = false;
        quoteChar = null;
      }
      continue;
    }

    let tok = tok0;

    if (tok.length >= 2 && (tok[0] === "'" || tok[0] === '"') && tok[tok.length - 1] === tok[0]) {
      tok = tok.slice(1, -1);
    } else if (tok[0] === "'" || tok[0] === '"') {
      // Opens a quote but does not close on this same whitespace-split
      // fragment -- a quoted path containing a space. Drop every
      // fragment until (and including) the matching close quote.
      skippingQuoted = true;
      quoteChar = tok[0];
      continue;
    }

    if (tok.startsWith('-')) continue; // a flag
    if (tok.includes('=')) continue; // an assignment
    if (tok.includes('://') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(tok)) continue; // a URL / scheme

    tokens.push(tok);
  }

  return tokens;
}

// ---------------------------------------------------------------------------
// extractPathTokens -- the fence/heredoc-aware, inline-span-broadened walk
// ---------------------------------------------------------------------------

const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/;
const HEREDOC_START_RE = /<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/;
const TRAILING_PUNCT_RE = /[,.:;)\]]+$/;

function trimTrailingPunctuation(token) {
  let t = String(token).replace(TRAILING_PUNCT_RE, '');
  t = t.replace(/\/+$/, '');
  return t;
}

/**
 * extractPathTokens(text) -- walks the document line by line, tracking
 * fenced-block state (backtick and tilde fences, info-strings included).
 *
 * Inside a fence: heredoc state is tracked (a `<<MARKER` line and every
 * line up to and including its terminator contribute ZERO candidates --
 * a compound/unsupported shape) and otherwise candidates come from
 * tokenizeFencedLine.
 *
 * Outside a fence: only the full content of a single-backtick span is a
 * candidate. THIS IS THE D-03 BROADENING that makes the DOC-03a claim
 * (docs/credential-management.md:564's inline `~/.claude/audit.jsonl`)
 * mechanically nameable -- a fence-only scanner would never see it.
 *
 * Both branches trim trailing sentence punctuation (comma, period, colon,
 * semicolon, closing paren/bracket) and a trailing slash before returning
 * `{ token, line, inFence }` records.
 */
function extractPathTokens(text) {
  const lines = String(text).split('\n');
  const found = [];

  let inFence = false;
  let fenceChar = null;
  let fenceLen = 0;
  let inHeredoc = false;
  let heredocTerminator = null;

  lines.forEach((lineText, idx) => {
    const lineNo = idx + 1;
    const fenceMatch = lineText.match(FENCE_RE);

    if (inFence) {
      const closesFence =
        fenceMatch &&
        fenceMatch[1][0] === fenceChar &&
        fenceMatch[1].length >= fenceLen &&
        lineText.trim() === fenceMatch[1];
      if (closesFence) {
        inFence = false;
        fenceChar = null;
        fenceLen = 0;
        inHeredoc = false;
        heredocTerminator = null;
        return;
      }

      if (inHeredoc) {
        if (lineText.trim() === heredocTerminator) {
          inHeredoc = false;
          heredocTerminator = null;
        }
        return; // heredoc body/terminator lines: zero candidates
      }

      const heredocMatch = lineText.match(HEREDOC_START_RE);
      if (heredocMatch) {
        inHeredoc = true;
        heredocTerminator = heredocMatch[1];
        return; // heredoc marker line itself: zero candidates (unsupported)
      }

      for (const raw of tokenizeFencedLine(lineText)) {
        const trimmed = trimTrailingPunctuation(raw);
        if (trimmed) found.push({ token: trimmed, line: lineNo, inFence: true });
      }
      return;
    }

    if (fenceMatch) {
      inFence = true;
      fenceChar = fenceMatch[1][0];
      fenceLen = fenceMatch[1].length;
      return;
    }

    // D-03 broadening: an inline single-backtick span anywhere in prose,
    // outside a fence, is a candidate -- this is what makes DOC-03a
    // (the flat ~/.claude/audit.jsonl claim) mechanically nameable.
    const spanRe = /`([^`]+)`/g;
    let m = spanRe.exec(lineText);
    while (m !== null) {
      const trimmed = trimTrailingPunctuation(m[1].trim());
      if (trimmed) found.push({ token: trimmed, line: lineNo, inFence: false });
      m = spanRe.exec(lineText);
    }
  });

  return found;
}

// ---------------------------------------------------------------------------
// Prefix classification
// ---------------------------------------------------------------------------

function classifyPrefix(token) {
  if (token.startsWith(AGENT_HOME_PREFIX)) return 'agent-home';
  if (REPO_RELATIVE_PREFIXES.some((p) => token.startsWith(p))) return 'repo-relative';
  return null;
}

// ---------------------------------------------------------------------------
// Source-evidence set (composition tuples -- strong; bare literals -- weak)
// ---------------------------------------------------------------------------

const STRING_LITERAL_RE = /'([^'\\]*)'|"([^"\\]*)"/g;

// Plain string needles (never a regex with an escaped dot, which would
// put a backslash between "path" and "." in this file's own raw source
// text) -- both call names appear as literal, contiguous source text
// here, which is what the composition-evidence-tier source scan in
// tests/docs-verify/commands.test.js asserts is present.
const PATH_JOIN_CALL = 'path.join(';
const PATH_RESOLVE_CALL = 'path.resolve(';
const CALL_NEEDLES = [PATH_JOIN_CALL, PATH_RESOLVE_CALL];

/**
 * findCallOpenParens(text, needle) -- every index in `text` where `needle`
 * (a literal call-name-plus-open-paren string, e.g. "path.join(") starts.
 * A plain-string search, never a regex -- see the CALL_NEEDLES comment.
 */
function findCallOpenParens(text, needle) {
  const indexes = [];
  let from = 0;
  let idx = text.indexOf(needle, from);
  while (idx !== -1) {
    indexes.push(idx + needle.length - 1); // index of the '('
    from = idx + needle.length;
    idx = text.indexOf(needle, from);
  }
  return indexes;
}

/**
 * findMatchingParen(text, openIdx) -- text[openIdx] MUST be '('. Scans
 * forward tracking paren depth, skipping the contents of string literals
 * (so a nested '(' or ')' inside a string never miscounts), and returns
 * the index of the matching ')' or -1 if unbalanced. This is what lets
 * buildSourceEvidence correctly parse
 * `path.join(os.homedir(), '.claude', 'audit')` -- a naive
 * `[^)]*` regex would stop at the ')' that closes `os.homedir(`.
 */
function findMatchingParen(text, openIdx) {
  let depth = 0;
  let inString = null;
  for (let i = openIdx; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      inString = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * splitTopLevelArgs(argsText) -- splits on top-level commas only (never
 * inside nested parens or string literals).
 */
function splitTopLevelArgs(argsText) {
  const args = [];
  let depth = 0;
  let inString = null;
  let current = '';
  for (let i = 0; i < argsText.length; i += 1) {
    const ch = argsText[i];
    if (inString) {
      current += ch;
      if (ch === '\\') {
        i += 1;
        if (i < argsText.length) current += argsText[i];
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      inString = ch;
      current += ch;
      continue;
    }
    if (ch === '(') {
      depth += 1;
      current += ch;
      continue;
    }
    if (ch === ')') {
      depth -= 1;
      current += ch;
      continue;
    }
    if (ch === ',' && depth === 0) {
      args.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim() !== '') args.push(current.trim());
  return args;
}

function wholeStringLiteral(argText) {
  const m = argText.match(/^'([^'\\]*)'$|^"([^"\\]*)"$/);
  if (!m) return null;
  return m[1] !== undefined ? m[1] : m[2];
}

// The agent-home segment as it appears INSIDE a composition tuple -- the
// literal path.join/path.resolve argument text ('.claude'), not
// AGENT_HOME_PREFIX ('~/.claude/', which is a documented-token prefix, a
// different string shape entirely). hooks/audit-logger.js:19's
// `path.join(os.homedir(), '.claude', 'audit')` yields the tuple
// ('.claude', 'audit') -- AGENT_HOME_SEGMENT is what locates '.claude'
// inside that tuple so deriveAgentHomeOwnedSegments can take the segment
// that follows it.
const AGENT_HOME_SEGMENT = '.claude';

/**
 * segmentStem(segment) -- the basename with a single trailing extension
 * removed (the last '.' and everything after it). A segment with no dot,
 * or one that starts with a dot and has no further dot (a dotfile with no
 * extension of its own), returns itself unchanged -- 'audit' -> 'audit',
 * 'audit.jsonl' -> 'audit', 'settings.json' -> 'settings'.
 */
function segmentStem(segment) {
  const s = String(segment);
  const lastDot = s.lastIndexOf('.');
  if (lastDot <= 0) return s;
  return s.slice(0, lastDot);
}

/**
 * deriveAgentHomeOwnedSegments(compositionTuples) -- D-02: the set of
 * segments this repository composes IMMEDIATELY under an agent-home
 * marker, derived from compositionTuples (never enumerated by hand). For
 * every tuple, wherever AGENT_HOME_SEGMENT ('.claude') occurs, the segment
 * that follows it -- plus that segment's stem -- is added to the set.
 * hooks/audit-logger.js:19 + lib/agents/claude-code.js:11
 * (`('.claude', 'audit')`), lib/update.js:8 + lib/agents/claude-code.js:9
 * (`('.claude', 'hooks')`), and lib/agents/claude-code.js:10
 * (`('.claude', 'settings.json')`) together derive the real-repo set
 * `{audit, hooks, settings.json, settings}` -- confirmed at planning time
 * (`/usr/bin/grep -rn "'\.claude'" hooks lib`) and re-derived here at
 * every run, never pinned as a literal list.
 */
function deriveAgentHomeOwnedSegments(compositionTuples) {
  const owned = new Set();
  for (const tuple of compositionTuples) {
    for (let i = 0; i < tuple.length - 1; i += 1) {
      if (tuple[i] === AGENT_HOME_SEGMENT) {
        const next = tuple[i + 1];
        owned.add(next);
        owned.add(segmentStem(next));
      }
    }
  }
  return owned;
}

/**
 * buildSourceEvidence(context) -- reads every .js file under hooks/ and
 * lib/ (recursive; a genuinely-missing top-level directory is zero
 * source there, never a broken sweep -- mirrors identifiers.js's own
 * ENOENT-tolerance) and collects:
 *   - compositionTuples: the ordered STRING-LITERAL arguments of every
 *     path.join(...)/path.resolve(...) call (non-literal arguments, such
 *     as os.homedir(), are skipped -- only the literal arguments form the
 *     tuple, in order). hooks/audit-logger.js:19's
 *     `path.join(os.homedir(), '.claude', 'audit')` yields the tuple
 *     ('.claude', 'audit').
 *   - bareLiterals: every single/double-quoted string literal, flat.
 *   - agentHomeOwnedSegments: derived from compositionTuples via
 *     deriveAgentHomeOwnedSegments (D-02) -- the segments this repository
 *     genuinely composes immediately under an agent home, feeding the
 *     in-scope predicate below.
 */
function buildSourceEvidence(context) {
  const compositionTuples = [];
  const bareLiterals = new Set();

  for (const dir of ['hooks', 'lib']) {
    const listing = context.listFiles(dir, { ext: '.js', recursive: true });
    if (listing.error) {
      if (listing.error === 'ENOENT') continue;
      throw new Error(`commands: could not list ${dir}: ${listing.error}`);
    }
    for (const file of listing.files) {
      const result = context.readText(file);
      if (result.error) {
        throw new Error(`commands: could not read ${file}: ${result.error}`);
      }
      const text = result.text;

      STRING_LITERAL_RE.lastIndex = 0;
      let lm = STRING_LITERAL_RE.exec(text);
      while (lm !== null) {
        const val = lm[1] !== undefined ? lm[1] : lm[2];
        if (val) bareLiterals.add(val);
        lm = STRING_LITERAL_RE.exec(text);
      }

      for (const needle of CALL_NEEDLES) {
        for (const openIdx of findCallOpenParens(text, needle)) {
          const closeIdx = findMatchingParen(text, openIdx);
          if (closeIdx === -1) continue;
          const argsText = text.slice(openIdx + 1, closeIdx);
          const tuple = [];
          for (const argText of splitTopLevelArgs(argsText)) {
            const lit = wholeStringLiteral(argText);
            if (lit !== null) tuple.push(lit);
          }
          if (tuple.length > 0) compositionTuples.push(tuple);
        }
      }
    }
  }

  const agentHomeOwnedSegments = deriveAgentHomeOwnedSegments(compositionTuples);

  return { compositionTuples, bareLiterals, agentHomeOwnedSegments };
}

/**
 * isRepoOwnedAgentHomeToken(segments, evidence) -- D-02 in-scope predicate,
 * run BEFORE gradeAgentHomeSegments. Anchored at the first non-placeholder
 * segment after the agent-home marker: an agent-home token is in scope for
 * grading iff that segment -- or its stem (segmentStem) -- equals a
 * segment this repository composes under the same agent home
 * (evidence.agentHomeOwnedSegments). A token whose anchor segment fails
 * this test is not this repository's claim to make and produces NO
 * finding at any tier -- not a pass-with-weak-evidence, which would be a
 * different and quieter lie.
 *
 * A token with no non-placeholder segment at all (every segment is a
 * placeholder) has no anchor to test and is vacuously in scope -- there is
 * no concrete claim to be out of scope about, matching
 * isContiguousSubsequence's own vacuous-empty-segments convention.
 */
function isRepoOwnedAgentHomeToken(segments, evidence) {
  const anchor = segments.find((s) => !isPlaceholderSegment(s));
  if (anchor === undefined) return true;
  if (evidence.agentHomeOwnedSegments.has(anchor)) return true;
  return evidence.agentHomeOwnedSegments.has(segmentStem(anchor));
}

/**
 * isContiguousSubsequence(segments, tuples) -- true when `segments`
 * (already placeholder-filtered) occurs as a contiguous, same-order run
 * inside ANY tuple. An empty `segments` (every segment was a placeholder)
 * is vacuously true -- there is nothing left to prove.
 */
function isContiguousSubsequence(segments, tuples) {
  if (segments.length === 0) return true;
  return tuples.some((tuple) => {
    if (segments.length > tuple.length) return false;
    for (let start = 0; start <= tuple.length - segments.length; start += 1) {
      let match = true;
      for (let i = 0; i < segments.length; i += 1) {
        if (tuple[start + i] !== segments[i]) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
    return false;
  });
}

/**
 * gradeAgentHomeSegments(segments, evidence) -- prefers composition-level
 * evidence over bare-literal presence; the finding text (built by the
 * caller) records which tier was used or which tier failed.
 */
function gradeAgentHomeSegments(segments, evidence) {
  const nonPlaceholder = segments.filter((s) => !isPlaceholderSegment(s));

  if (isContiguousSubsequence(nonPlaceholder, evidence.compositionTuples)) {
    return { ok: true, evidenceLevel: 'composition' };
  }

  for (const seg of nonPlaceholder) {
    if (!evidence.bareLiterals.has(seg)) {
      return { ok: false, badSegment: seg, evidenceLevel: 'presence' };
    }
  }
  return { ok: true, evidenceLevel: 'presence' };
}

// ---------------------------------------------------------------------------
// run(context)
// ---------------------------------------------------------------------------

/**
 * run(context) -- see module header and 21-04-PLAN.md Task 1 <action> for
 * the full grading rules. Repo-relative tokens are resolved through
 * resolveInRoot and stat-checked; agent-home tokens are graded
 * segment-wise against buildSourceEvidence's two-tier evidence set. A
 * token matching neither prefix group is out of scope and NEVER reported.
 */
function run(context) {
  const findings = [];
  const evidence = buildSourceEvidence(context);

  for (const doc of context.mdFiles) {
    const tokens = extractPathTokens(doc.text);
    for (const rec of tokens) {
      const group = classifyPrefix(rec.token);
      if (group === null) continue; // out of scope -- never reported

      if (group === 'repo-relative') {
        // A repo-relative token containing a placeholder segment (an
        // angle-bracketed name, a wildcard, or a date-shaped token -- the
        // same three shapes graded for agent-home tokens) is a
        // documentation template, not a claim about a real file, and is
        // never existence-checked -- e.g. `docs/hardening/*.md` or
        // `.github/agent-protocols/<file>.md`.
        const tokenSegments = rec.token.split('/').filter((s) => s.length > 0);
        if (tokenSegments.some((s) => isPlaceholderSegment(s))) continue;

        const resolved = resolveInRoot(context.root, rec.token);
        if (!resolved.ok) {
          findings.push({
            check: id,
            file: doc.path,
            line: rec.line,
            severity: 'fail',
            message: `documented path '${rec.token}' at ${doc.path}:${rec.line} resolves out-of-tree (${resolved.reason})`,
          });
          continue; // never opened
        }
        let exists;
        try {
          fs.statSync(resolved.abs);
          exists = true;
        } catch (err) {
          if (err && err.code === 'ENOENT') exists = false;
          else throw err;
        }
        if (!exists) {
          findings.push({
            check: id,
            file: doc.path,
            line: rec.line,
            severity: 'fail',
            message: `documented path '${rec.token}' at ${doc.path}:${rec.line} does not exist under the repository root`,
          });
        }
      } else {
        const afterPrefix = rec.token.slice(AGENT_HOME_PREFIX.length);
        const segments = afterPrefix.split(path.posix.sep).filter((s) => s.length > 0);
        // D-02: an agent-home token is graded only where this repository
        // composes something by that name -- a token whose first
        // non-placeholder segment this repo never composes is not this
        // repo's claim to make and is out of scope (no finding, at any
        // tier). This runs BEFORE gradeAgentHomeSegments, never after.
        if (!isRepoOwnedAgentHomeToken(segments, evidence)) continue;
        const result = gradeAgentHomeSegments(segments, evidence);
        if (!result.ok) {
          findings.push({
            check: id,
            file: doc.path,
            line: rec.line,
            severity: 'fail',
            message: `documented path '${rec.token}' at ${doc.path}:${rec.line} -- segment '${result.badSegment}' does not appear as a literal in hooks/**/*.js or lib/**/*.js (searched hooks/ and lib/; evidence tier: ${result.evidenceLevel})`,
          });
        }
      }
    }
  }

  return findings;
}

module.exports = {
  id,
  run,
  extractPathTokens,
  INTERNAL_PATH_PREFIXES,
  isPlaceholderSegment,
  isDateShapedSegment,
  tokenizeFencedLine,
  isRepoOwnedAgentHomeToken,
};
