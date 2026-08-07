'use strict';

/**
 * Git-delegated ignore semantics (G-1482, TRAV-03, D-14).
 *
 * (a) This module answers ONE question -- may the BULK content tier skip
 *     this file -- and its answer is never consulted by any targeted IOC
 *     check, because `.gitignore` is attacker-controlled and must never be
 *     able to hide a payload (D-13).
 * (b) A degradation here fails OPEN and therefore does NOT make the scan
 *     incomplete -- a machine without git scans MORE files, not fewer, so
 *     reporting exit 2 there would train operators to ignore the one exit
 *     code that must never be ignored. Degradations are reported, not
 *     escalated.
 *
 * Cost model: two `spawnSync` calls per repository (one `rev-parse
 * --is-inside-work-tree` probe, one `ls-files`), built lazily and cached
 * per repo root, and only ever for repositories that actually contain a
 * bulk-tier candidate. A tree with 50 repositories therefore costs about
 * 100 short-lived subprocesses concentrated at the start of the bulk tier;
 * `stats().subprocesses` makes that number assertable rather than
 * speculative, and the targeted tier never triggers any of them.
 */

const path = require('path');
const { normalizeOptions } = require('./index.js');

/**
 * One shared spawnSync options object, built once per resolver (or once
 * per standalone `probeRepo` call) and reused for every invocation so the
 * probe and the listing call can never drift apart:
 *
 *   encoding: 'utf8'      -- so stdout/stderr are strings, not Buffers.
 *   timeout                -- bounds a hung git process (network mount, a
 *                             lock held by another process) rather than
 *                             blocking the scan forever (T-17-08).
 *   maxBuffer               -- Node's default is roughly 1 MiB. A 300k-file
 *                             repository's NUL-delimited `ls-files` output
 *                             runs to tens of megabytes, so the default
 *                             would truncate or error out on exactly the
 *                             large repositories where bulk pruning matters
 *                             most -- and because the failure surfaces as an
 *                             error rather than as short output, it would
 *                             degrade to a false "git unavailable" state and
 *                             silently disable pruning there. Raised to
 *                             `DEFAULTS.gitMaxBufferBytes` (256 MiB).
 *   env.GIT_OPTIONAL_LOCKS -- '0' so a concurrent git process elsewhere on
 *                             the machine never makes this call wait on a
 *                             lock it does not need to take.
 *   env.GIT_PAGER          -- '' so `ls-files`/`rev-parse` output can never
 *                             be piped through a pager and block on a TTY
 *                             that does not exist in a scan context.
 *   env.GIT_TERMINAL_PROMPT -- '0' so git can never block waiting for a
 *                             credential prompt.
 */
function buildSharedSpawnOpts(normalized) {
  return {
    encoding: 'utf8',
    timeout: normalized.gitTimeoutMs,
    maxBuffer: normalized.gitMaxBufferBytes,
    env: {
      ...normalized.env,
      GIT_OPTIONAL_LOCKS: '0',
      GIT_PAGER: '',
      GIT_TERMINAL_PROMPT: '0',
    },
  };
}

/**
 * Maps the common failure shapes of a `spawnSync('git', ...)` result --
 * shapes shared by BOTH the `rev-parse` probe and the `ls-files` listing --
 * to a named degradation reason. Returns `null` when the process exited
 * with status 0 (the caller then inspects stdout itself, since "success"
 * means something different for the two commands). There is no fall-through
 * that returns a healthy result from this function -- every non-zero /
 * errored / killed shape gets a name.
 */
function classifyGitFailure(result) {
  if (result.error) {
    if (result.error.code === 'ENOENT') {
      return { reason: 'no-git', detail: { code: result.error.code } };
    }
    // Any other spawn error (ENOBUFS from an oversized buffer, EAGAIN,
    // etc.) is treated the same as a timeout/kill -- the process did not
    // give us a usable answer, and the safest name for "git did not
    // complete" is git-timeout, mirroring lib/scan.js's killed-by-signal
    // handling.
    return {
      reason: 'git-timeout',
      detail: { code: result.error.code, signal: result.signal || null },
    };
  }

  // spawnSync reports BOTH a timeout firing and the process being killed by
  // a signal as `status: null` -- there is no way to tell them apart from
  // the result shape alone, so both map to the same named reason.
  if (result.status === null) {
    return { reason: 'git-timeout', detail: { signal: result.signal || null } };
  }

  if (result.status === 128) {
    const stderr = String(result.stderr || '');
    // Match on exit code plus substring, never full-string equality --
    // exact wording varies by git version (RESEARCH.md B2).
    if (stderr.includes('dubious ownership')) {
      return { reason: 'git-refused', detail: { status: 128, stderr } };
    }
    return { reason: 'not-a-repo', detail: { status: 128, stderr } };
  }

  if (result.status !== 0) {
    return {
      reason: 'git-refused',
      detail: { status: result.status, stderr: String(result.stderr || '') },
    };
  }

  return null;
}

/**
 * Runs the cheap correctness probe: `git -C <dir> rev-parse
 * --is-inside-work-tree`. Returns `{ ok: true }` or `{ ok: false, reason,
 * detail }` -- never throws, and there is no unrecognised-shape branch that
 * falls through to `ok: true`.
 */
function runProbe(dir, spawnSyncFn, sharedOpts) {
  const result = spawnSyncFn('git', ['-C', dir, 'rev-parse', '--is-inside-work-tree'], sharedOpts);

  const failure = classifyGitFailure(result);
  if (failure) {
    return { ok: false, reason: failure.reason, detail: failure.detail };
  }

  // status === 0 -- the ONLY case classifyGitFailure defers to us. A bare
  // repository answers this question successfully (exit 0) with stdout
  // "false" -- this is the case that would throw if `ls-files` were called
  // anyway, so it must be distinguished from "true" here, not downstream.
  const stdout = String(result.stdout || '').trim();
  if (stdout === 'false') {
    return { ok: false, reason: 'bare-repo', detail: {} };
  }
  if (stdout === 'true') {
    return { ok: true };
  }
  // Any other stdout shape on exit 0 is unrecognised -- degrade, do not
  // assume "true".
  return { ok: false, reason: 'git-refused', detail: { status: 0, stdout } };
}

/**
 * Runs `git -C <repoRoot> ls-files --cached --others --exclude-standard
 * --full-name -z` and splits the NUL-delimited output. `--full-name` is
 * MANDATORY: without it, a `git -C <subdir>` invocation returns paths
 * relative to that subdirectory, and every join against an absolute walk
 * path would be wrong (RESEARCH.md B1). Splits on NUL, never on newline --
 * filenames may legally contain literal newlines, and a newline split would
 * desynchronise the list.
 */
function runListFiles(repoRoot, spawnSyncFn, sharedOpts) {
  const result = spawnSyncFn(
    'git',
    ['-C', repoRoot, 'ls-files', '--cached', '--others', '--exclude-standard', '--full-name', '-z'],
    sharedOpts
  );

  const failure = classifyGitFailure(result);
  if (failure) {
    return { ok: false, reason: failure.reason, detail: failure.detail };
  }

  const stdout = typeof result.stdout === 'string' ? result.stdout : String(result.stdout || '');
  const parts = stdout.split('\0');
  // `-z` NUL-terminates every entry including the last, so splitting on NUL
  // leaves one trailing empty segment to drop. An entirely empty stdout
  // (an empty repo) legitimately yields zero entries here -- that is NOT a
  // degradation, it is a correct, healthy, empty result.
  if (parts.length > 0 && parts[parts.length - 1] === '') {
    parts.pop();
  }

  return { ok: true, listed: parts };
}

/**
 * Converts an absolute path to a repo-root-relative path in the same
 * normalisation used to build the index's Set. `path.relative` never
 * consults `process.cwd()`, so this is correct regardless of the caller's
 * working directory or how deeply nested `repoRoot` is. Forward slashes are
 * used defensively (Windows separators would otherwise never match git's
 * always-forward-slash output) even though this project's supported
 * platforms are POSIX (CLAUDE.md: no Windows support).
 *
 * On macOS's case-insensitive APFS, a case-differing path is deliberately
 * NOT normalised for case here -- git's own output is authoritative, and
 * silently case-folding would risk treating two distinct git-tracked paths
 * as the same entry.
 */
function toRepoRelative(absPath, repoRoot) {
  const rel = path.relative(repoRoot, absPath);
  return rel.split(path.sep).join('/');
}

/**
 * `probeRepo(dir, options)` -- standalone entry point for the cheap
 * correctness probe, normalizing `options` (so `options.spawnSync` /
 * `options.env` / `options.gitTimeoutMs` / `options.gitMaxBufferBytes`
 * injectable seams from `lib/traverse/index.js` all apply) and delegating
 * to `runProbe`.
 */
function probeRepo(dir, options) {
  const normalized = normalizeOptions(options);
  const sharedOpts = buildSharedSpawnOpts(normalized);
  return runProbe(dir, normalized.spawnSync, sharedOpts);
}

/**
 * `createIgnoreResolver(options)` -- builds a resolver that lazily probes
 * and lists each repository ONCE (cached by repo root), and answers the
 * single question this module exists to answer: may the bulk content tier
 * skip this path.
 */
function createIgnoreResolver(options) {
  const normalized = normalizeOptions(options);
  const sharedOpts = buildSharedSpawnOpts(normalized);
  const spawnSyncFn = normalized.spawnSync;

  const cache = new Map(); // repoRoot -> { degraded: string|null, listed: Set|null }
  const degradationMap = new Map(); // repoRoot -> reason
  let subprocesses = 0;
  let cacheHits = 0;

  function indexFor(repoRoot) {
    if (cache.has(repoRoot)) {
      cacheHits += 1;
      return cache.get(repoRoot);
    }

    subprocesses += 1;
    const probe = runProbe(repoRoot, spawnSyncFn, sharedOpts);

    if (!probe.ok) {
      const index = { degraded: probe.reason, listed: null };
      cache.set(repoRoot, index);
      degradationMap.set(repoRoot, probe.reason);
      return index;
    }

    subprocesses += 1;
    const listing = runListFiles(repoRoot, spawnSyncFn, sharedOpts);

    let index;
    if (!listing.ok) {
      // A failed listing after a HEALTHY probe must degrade, never collapse
      // to an empty Set -- an empty Set from a failed call would read as
      // "everything is ignored" and prune the entire repo from the bulk
      // tier (T-17-03-02).
      index = { degraded: listing.reason, listed: null };
      degradationMap.set(repoRoot, listing.reason);
    } else {
      // An empty Set from a SUCCESSFUL listing is a legitimate result (an
      // empty repo), not a degradation -- this is the deliberate opposite
      // of the failed-listing case above.
      index = { degraded: null, listed: new Set(listing.listed) };
    }

    cache.set(repoRoot, index);
    return index;
  }

  function isBulkEligible(absPath, repoRoot) {
    const index = indexFor(repoRoot);

    if (index.degraded) {
      // Fail OPEN for the bulk tier only: a missing/refusing/timed-out git
      // must never REDUCE detection, so the file stays eligible for the
      // bulk scan and the degradation is surfaced as a note, not a prune.
      return { eligible: true, reason: index.degraded };
    }

    const rel = toRepoRelative(absPath, repoRoot);
    if (index.listed.has(rel)) {
      return { eligible: true, reason: null };
    }
    return { eligible: false, reason: 'gitignored' };
  }

  function degradations() {
    return Object.fromEntries(degradationMap);
  }

  function stats() {
    return { repos: cache.size, subprocesses, cacheHits };
  }

  return { indexFor, isBulkEligible, degradations, stats };
}

module.exports = { createIgnoreResolver, probeRepo };
