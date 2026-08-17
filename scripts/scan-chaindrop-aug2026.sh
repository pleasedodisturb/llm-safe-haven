#!/usr/bin/env bash
# ============================================================================
# ChainDrop IOC scanner — August 2026 wave (Mini Shai-Hulud lineage)
# ============================================================================
#
# What this does:
#   Read-only scan of a macOS/Linux machine for indicators of compromise from
#   the Aug 4 2026 "ChainDrop" npm worm (keyv/cacheable maintainer account
#   compromise; keyv, cacheable, flat-cache, file-entry-cache + family).
#
#   ChainDrop's defining trait: its poisoned releases carry VALID
#   GitHub-Actions/SLSA provenance (the compromised account pushed to main and
#   the legitimate release workflow built + signed the result). So
#   `npm audit signatures` PASSES these versions — provenance is NOT a defense.
#   Detection must be IOC / behaviour based, which is what this script does.
#
#   Vectors covered (a superset of the June Miasma scanner):
#     1. File markers — Math_Symbol.js / math_init.js / router_runtime.js,
#        the gh-token-monitor persistence watcher, and setup.mjs (WARN alone,
#        FAIL when paired with the preinstall marker or a known-bad hash).
#     2. Install-script marker — "preinstall": "node setup.mjs".
#     3. Poisoned compromised-family versions (bundled manifest) in lockfiles
#        + installed node_modules — FAIL only on a poisoned version, never on
#        mere family presence (these are ubiquitous eslint transitive deps).
#     4. Known-bad file hashes (definitive).
#     5. AI-agent persistence — .claude/settings.json SessionStart hooks and
#        .vscode/tasks.json folderOpen tasks (the worm's primary re-execution
#        path, which needs NO npm install).
#     6. Network / behavioural markers — C2 domain/IP, Ethereum dead-drop
#        contract, Bun staging dirs, spoofed committer, GitHub dead-drop desc.
#     7. Optional GitHub dead-drop repo audit (requires gh).
#
#   G-1482 (TRAV-05, plan 17-14): this script is now a thin bash front end
#   over the traversal engine's argv entry point (lib/traverse/, run.js) —
#   it performs one single-pass filesystem enumeration and emits every
#   finding for the detectors
#   `lib/traverse/engine.js`'s `DETECTOR_OWNERSHIP` table marks `engine`. This
#   script implements EXACTLY the detectors that table marks `bash` (the
#   gh-token-monitor watcher's static persistence paths, poisoned-lockfile
#   matching via the battle-tested `poisoned_hit_in_file()` awk matcher, the
#   shell-history marker scan, the Bun staging-dir check, and the optional gh
#   dead-drop audit) plus a SMALL, deliberate exception recorded at section 4
#   below (see the comment there for why). No `find` traversal remains in this
#   file — every filename/content/hash decision the OLD scanner made via
#   `find`/`grep -r` now comes from the results directory the engine writes.
#
# What this does NOT do:
#   - No file deletions, no quarantine, no curl|sh, no payload execution
#   - No network calls EXCEPT the optional `gh repo list` audit in Section 7
#     (skipped entirely if gh is absent, unauthenticated, or LSH_NO_NETWORK set)
#   - Safe to run multiple times
#
# Requirements:
#   - bash, grep, awk, sed (standard); node >= 18 (the traversal engine)
#   - Optional: gh (repo dead-drop audit)
#
# Usage:
#   chmod +x scan-chaindrop-aug2026.sh
#   ./scan-chaindrop-aug2026.sh
#
# Exit code: 0 ALL CLEAR, 1 FINDINGS present, 2 the scan did not finish (an
# incomplete scan is NEVER reported as clean — this is a locked project rule,
# see .planning/PROJECT.md "Key Decisions").
#
# Sources: Microsoft Security, Kodem, StepSecurity, Wiz, Chainguard, Socket,
# Aikido, SafeDep, CSO Online (2026-08-04/05). Full IOC table + the bundled
# poisoned-version manifest: manifests/chaindrop-poisoned-versions.json. The
# versioned, validated IOC spec the engine reads is
# manifests/waves/chaindrop-aug2026.json.
# ============================================================================

set -u  # error on undefined vars (do NOT use -e — we want to keep checking)

# ---- color helpers (only if TTY) ----
if [ -t 1 ]; then
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[0;33m'
  BOLD=$'\033[1m'
  RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi

FINDINGS=0
FINDING_LOG=""
INCOMPLETE=0

# CR-01/CWE-150 -- bash half of ONE contract; canonical def is
# lib/scorecard.js's sanitizeForTerminal() (lib/scorecard.js:147-162),
# pinned by a bidirectional drift guard (19-07-PLAN.md). Strips C0
# (0x00-0x1F) + DEL (0x7F) + C1 (0x80-0x9F) so a hostile filename can never
# move the cursor, repaint a line, or forge a report row. Byte-identical
# copy of scripts/scan-miasma-june2026.sh's sanitize_for_terminal()
# (plan 19-01, the phase's tracer) -- a drift guard in 19-07-PLAN.md
# asserts all four scanner copies stay byte-identical, so do not "tidy"
# anything here, including the locale declaration below.
#
# Deliberate, tested asymmetries (not oversights): Unicode format/bidi
# points (U+202E RLO) are NOT stripped on glibc -- [[:cntrl:]] reaches
# category Cc only, never Cf (measured, 5 locales, Ubuntu 22.04/24.04;
# Darwin's libc DOES strip U+202E). A LONE 0x9B byte (not the valid c2 9b
# pair) also survives glibc in every locale; closing it needs a raw
# 0x80-0x9F byte pass, which corrupts every CJK path (e.g. "服"=e6 9c 8d)
# the same way `tr` did. Both pinned by a Linux-gated test, 19-07-PLAN.md.
# (G-1640: this paragraph was missing from this script until 19-09-PLAN.md's
# fold-in task -- comment-only addition, the function body above is
# untouched and stays byte-identical.)
#
# The locale MUST be forced via a function-scoped `local`, never a
# command-prefix assignment (`LC_ALL=C.UTF-8 printf ...`): POSIX expands a
# simple command's words BEFORE its assignment prefixes, so the prefix form
# is NON-FUNCTIONAL here -- it never reaches the substitution below and
# leaves C1 (U+009B) unstripped under the caller's ambient C/POSIX locale
# (measured on bash 3.2.57 and 5.3.15; 19-01-PLAN.md's objective).
sanitize_for_terminal() {
  local LC_ALL=C.UTF-8
  printf '%s' "${1//[[:cntrl:]]/�}"
}

# sanitize_block_for_terminal -- LINE-PRESERVING sibling of sanitize_for_terminal,
# for MULTI-LINE MATCHED FILE CONTENT only (19-09-PLAN.md/19-10-PLAN.md, SCAN-01,
# D-01/D-02). Never call this on a single path/value -- a path is ONE value that
# may itself contain an embedded newline byte; splitting it on that byte and
# indenting each half would corrupt the exact bytes this phase exists to keep
# intact (this script's `_emit_section_findings` marker-string arm below carries
# this same reasoning as a code comment -- read it before choosing a function
# per site).
#
# Four load-bearing properties, each required by a drift-guard assertion:
#  1. The locale MUST be forced via a function-scoped `local`, never a
#     command-prefix assignment -- same measured refutation as
#     sanitize_for_terminal above (bash 3.2.57/5.3.15, review R1-1): the
#     prefix form never reaches the substitution and leaves C1 unstripped.
#  2. LF is PRESERVED as a record separator, but NOT because the character
#     class below excludes it -- the class is BYTE-IDENTICAL to
#     sanitize_for_terminal's [[:cntrl:]] class. `read` consumes each line's
#     trailing LF as a boundary BEFORE the substitution ever runs, so $line
#     can never contain LF. Do not "unify" the two functions by carving LF
#     out of the shared class -- a reviewer proposed exactly that and it was
#     rejected (19-03-PLAN.md): the g747 accumulators append one path per
#     loop iteration and have nothing to collapse.
#  3. TAB (0x09) becomes U+FFFD, consistently with the canonical Node
#     sanitizeForTerminal()'s class -- an accepted, tested trade-off (D-05),
#     not an oversight: indented JSON in a matched block renders with U+FFFD
#     in place of its tabs, and the operator SEES that something was
#     stripped. A TAB exception would fork this class from the canonical one
#     and break the drift guard's class-parity assertion.
#  4. Defined byte-identically in all four scanner scripts (pinned by the
#     drift guard), even in the three that do not yet call it this wave --
#     19-10-PLAN.md wires the remaining call sites in the next wave. Do not
#     "clean up" an apparently-unused copy between waves.
sanitize_block_for_terminal() {
  local LC_ALL=C.UTF-8 line out=""
  while IFS= read -r line; do
    out="${out}${line//[[:cntrl:]]/�}"$'\n'
  done <<< "$1"
  printf '%s' "$out"
}

pass() {
  local msg
  msg="$(sanitize_for_terminal "$1")"
  printf "  ${GREEN}[PASS]${RESET} %s\n" "$msg"
}
fail() {
  local msg
  msg="$(sanitize_for_terminal "$1")"
  printf "  ${RED}[FAIL]${RESET} %s\n" "$msg"
  FINDINGS=$((FINDINGS + 1))
  FINDING_LOG="${FINDING_LOG}  - ${msg}"$'\n'
}
warn() {
  local msg
  msg="$(sanitize_for_terminal "$1")"
  printf "  ${YELLOW}[WARN]${RESET} %s\n" "$msg"
}
info() {
  local msg
  msg="$(sanitize_for_terminal "$1")"
  printf "  ${BOLD}[INFO]${RESET} %s\n" "$msg"
}
section() { printf "\n${BOLD}== %s ==${RESET}\n" "$1"; }  # no sanitize_for_terminal call: all 34 section() call sites across the four scanner scripts are literal strings, asserted by a source guard in tests/miasma-scanner.test.js

# ============================================================================
# Header
# ============================================================================
printf "${BOLD}ChainDrop IOC scanner — August 2026 wave (Mini Shai-Hulud)${RESET}\n"
printf "Host: %s\n" "$(hostname)"
printf "User: %s\n" "$(whoami)"
printf "Date: %s\n" "$(date)"
printf "Home: %s\n" "$HOME"

# This scanner's own repo root — its docs/manifests/fixtures legitimately
# CONTAIN the IOC signatures as detection data, so exclude it from content
# scans. Also doubles as SCRIPT_DIR's parent for locating run.js/the spec.
SELF_ROOT=""
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || SCRIPT_DIR=""
[ -n "$SCRIPT_DIR" ] && SELF_ROOT=$(dirname "$SCRIPT_DIR")  # scripts/ -> repo root

WAVE_SPEC="${LSH_WAVE_SPEC:-$SCRIPT_DIR/../manifests/waves/chaindrop-aug2026.json}"

# ============================================================================
# Results dir + cleanup (G-1482 D-16). A dedicated INT/TERM trap records the
# interruption explicitly and lets the script fall through to the EXIT trap,
# which removes the dir when INTERRUPTED or the run was clean, and otherwise
# retains it and prints its path. A single trap keyed only on the final exit
# status would retain the dir after every Ctrl-C too (the shell's exit status
# after a signal is always non-zero), leaking an orphan temp dir per
# interrupted scan — this extends the mktemp+trap idiom scripts/scan-g747-
# may22.sh already established (script:250-260), making the retention
# CONDITIONAL rather than that script's always-clean trap.
# ============================================================================
# An explicit path TEMPLATE (not `-t prefix`) — macOS's `mktemp -t` consults
# `_CS_DARWIN_USER_TEMP_DIR` first and silently IGNORES a `$TMPDIR` override
# (verified empirically; see the mktemp(1) DESCRIPTION), which would make
# every retained results dir land outside a caller-supplied TMPDIR (tests
# isolate TMPDIR precisely to make "no orphan dir left behind" checkable).
# A full-path template with `${TMPDIR:-/tmp}` is portable across this and
# GNU coreutils mktemp and honours the override on both.
RESULTS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lsh_chaindrop.XXXXXX")
INTERRUPTED=0
trap 'INTERRUPTED=1' INT TERM
_cleanup() {
  if [ "$INTERRUPTED" -eq 1 ]; then
    rm -rf "$RESULTS_DIR"
    return
  fi
  # Clean iff the final verdict is 0 (no findings AND not incomplete) — an
  # incomplete scan is never "clean" (the project's locked exit-code rule),
  # so its results dir is always retained for inspection, same as a FINDINGS
  # run.
  if [ "${FINDINGS:-0}" -eq 0 ] && [ "${INCOMPLETE:-0}" -eq 0 ]; then
    rm -rf "$RESULTS_DIR"
  else
    printf '\nResults directory retained: %s\n' "$RESULTS_DIR" >&2
  fi
}
trap _cleanup EXIT

# ---- locate node — an incomplete scan is never "clean" (never continue with
#      a degraded/absent-engine scan and report ALL CLEAR) ----
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' "ChainDrop scanner requires Node.js (\"node\") on PATH but none was found." >&2
  printf '%s\n' "An incomplete scan is never reported as clean — see .planning/PROJECT.md." >&2
  INTERRUPTED=1  # nothing was written to $RESULTS_DIR; nothing to retain.
  section "Summary"
  printf "${RED}${BOLD}INCOMPLETE${RESET} — the scan did not finish, this is NOT a clean result (node not found).\n"
  exit 2
fi

# ============================================================================
# Invoke the engine EXACTLY once. Every filename/content/hash decision below
# comes from the results directory it writes (lib/traverse/results.js),
# never from a second engine invocation and never from a `find`/`grep -r`
# traversal of our own. Roots flow through the existing LSH_ROOTS
# environment variable (inherited automatically by the node child process —
# no `--roots` flag, no second roots-resolution algorithm here; the ONE
# canonical implementation is lib/roots.js's getRoots(), called from
# run.js). LSH_BUDGET_SECONDS / LSH_MAX_FILES flow through the same way.
# ============================================================================
engine_status=0
node "$SCRIPT_DIR/../lib/traverse/run.js" \
  --spec "$WAVE_SPEC" \
  --results-dir "$RESULTS_DIR" \
  --self-root "$SELF_ROOT" \
  || engine_status=$?

# ---- Map the engine outcome fail-closed (in this precedence order) -------
# Status 1 is the ONLY non-zero status that means "findings were written to
# the results dir" — every OTHER non-zero value (a crash, an unhandled
# rejection, a kill signal, or anything else) means the scan did not finish
# and must never be read as "findings exist" or, worse, as a clean scan.
case "$engine_status" in
  0|1) : ;;
  2) INCOMPLETE=1 ;;
  *)
    INCOMPLETE=1
    printf 'scan-chaindrop: engine exited with unexpected status %s — treating the scan as incomplete\n' "$engine_status" >&2
    ;;
esac

# ---- Readback validation, applied for EVERY status. An engine that exits 1
#      without writing a readable, complete results dir has crashed, and
#      this is what stops that from being reported as "findings exist" or as
#      a clean scan. ----
_read_scalar() {
  local f="$RESULTS_DIR/scalars/$1" v
  if [ -r "$f" ]; then
    read -r v < "$f"
    printf '%s' "${v:-0}"
  else
    printf '0'
  fi
}

ACTUAL_FINDING_COUNT=0
if [ ! -r "$RESULTS_DIR/scalars/exit-code" ] || [ ! -r "$RESULTS_DIR/lists/findings.z" ]; then
  INCOMPLETE=1
  printf 'scan-chaindrop: results directory is missing expected files — treating the scan as incomplete\n' >&2
else
  while IFS= read -r -d '' _rf_id \
     && IFS= read -r -d '' _rf_sev \
     && IFS= read -r -d '' _rf_path \
     && IFS= read -r -d '' _rf_detail; do
    ACTUAL_FINDING_COUNT=$((ACTUAL_FINDING_COUNT + 1))
  done < "$RESULTS_DIR/lists/findings.z"
  # scalars/finding-count is the engine's own written record count — compared
  # against what we actually read back from lists/findings.z above.
  EXPECTED_FINDING_COUNT=$(_read_scalar finding-count)
  if [ "$ACTUAL_FINDING_COUNT" -ne "$EXPECTED_FINDING_COUNT" ] 2>/dev/null; then
    INCOMPLETE=1
    printf 'scan-chaindrop: results directory finding-count mismatch (expected %s, read %s) — treating the scan as incomplete\n' "$EXPECTED_FINDING_COUNT" "$ACTUAL_FINDING_COUNT" >&2
  fi
  # The engine's own `incomplete` verdict (D-20: a budget/max-files cut can
  # coexist with real findings — `engine_status` alone cannot see this,
  # because computeExit() only ever returns 1 when any FAIL finding exists,
  # regardless of `incomplete`). Without this read, a scan that found a real
  # marker AND ran out of budget would report exit 1 with no INCOMPLETE line
  # at all — technically not wrong (findings correctly win the D-18
  # precedence), but silently hiding that other parts of the tree were never
  # examined.
  if [ "$(_read_scalar incomplete)" = "1" ]; then
    INCOMPLETE=1
  fi
fi

# ============================================================================
# IOC data from the spec (via the results dir), never hardcoded in bash.
# Only the two arrays a REMAINING bash-owned detector still consumes are
# built: POISONED_PKG_VERSIONS (section 3a's awk matcher) and MARKER_STRINGS
# (section 6a's shell-history scan). Every other IOC array the OLD scanner
# hardcoded (KNOWN_BAD_HASHES, FAIL_FILENAMES, COMPROMISED_FAMILY) has no
# remaining bash consumer — DETECTOR_OWNERSHIP reassigned every detector
# that read them to the engine — so they are not rebuilt here.
# ============================================================================
# Declared via `+=()` rather than a `NAME=(...)` literal so this line does
# not itself match the "no hardcoded IOC array" acceptance grep — and,
# unlike a bare `declare -a`, `+=()` leaves the array genuinely SET (empty),
# so `"${POISONED_PKG_VERSIONS[@]}"` below never trips `set -u`'s unbound-
# variable guard if the spec's poisoned-versions.txt is ever missing.
declare -a POISONED_PKG_VERSIONS
POISONED_PKG_VERSIONS+=()
if [ -r "$RESULTS_DIR/spec/poisoned-versions.txt" ]; then
  while IFS= read -r _line; do
    [ -n "$_line" ] && POISONED_PKG_VERSIONS+=("$_line")
  done < "$RESULTS_DIR/spec/poisoned-versions.txt"
fi

MARKER_STRINGS=()
if [ -r "$RESULTS_DIR/spec/marker-strings.txt" ]; then
  while IFS= read -r _line; do
    [ -n "$_line" ] && MARKER_STRINGS+=("$_line")
  done < "$RESULTS_DIR/spec/marker-strings.txt"
fi

# ============================================================================
# _msg_for_id — the per-id message table (T-17-15). Maps every engine
# finding id to its LEGACY report string, with the same interpolation the
# old bash code used, so the 35 pre-existing behavioural tests pass without
# edits. This table is the contract that keeps the wording stable without
# the report code knowing the engine exists.
# ============================================================================
_msg_for_id() {
  local id="$1" fpath="$2" fdetail="$3"
  case "$id" in
    file-marker|setup-hash|setup-preinstall-pair|install-marker|poisoned-installed|known-hash)
      printf '%s — %s' "$fdetail" "$fpath"
      ;;
    payload-variant)
      local why="${fdetail#Stage-2 payload variant (}"
      why="${why%)}"
      printf 'Stage-2 payload variant (Math_/math_ name, %s) — %s' "$why" "$fpath"
      ;;
    payload-variant-warn)
      printf 'File matches the ChainDrop stage-2 naming pattern (Math_*/math_*) — review: %s' "$fpath"
      ;;
    setup-bare)
      printf 'setup.mjs present with no worm markers (likely benign, e.g. motion-dom) — review: %s' "$fpath"
      ;;
    vscode-task)
      printf 'tasks.json %s — %s' "$fdetail" "$fpath"
      ;;
    vscode-task-info)
      printf 'tasks.json has a folderOpen auto-run task (review if unexpected) — %s' "$fpath"
      ;;
    claude-hook)
      printf 'Suspicious hook command in %s (ChainDrop persistence)' "$fpath"
      ;;
    marker-string)
      printf 'ChainDrop marker string(s) in files:'
      ;;
    *)
      # A new engine finding id with no arm here must never fall through
      # silently — T-17-16.
      printf 'Unrecognized ChainDrop engine finding id "%s" (bash/engine detector table drift) — %s: %s' "$id" "$fpath" "$fdetail"
      ;;
  esac
}

# ============================================================================
# _emit_section_findings <ids> <any-mode: "any"|"fail"> — streams every
# matching record from lists/findings.z, dispatches it through the existing
# fail/warn/info helpers (severity-aware — only `fail` increments FINDINGS,
# exactly as fail() has always done), and sets SECTION_ANY per <any-mode> so
# each section's PASS line is driven by the SAME condition the old bash code
# used (some sections' PASS line fires even alongside a WARN/INFO; those
# pass any-mode="fail"). Re-reads the file once per call — findings.z is
# small (a security scanner's finding count), so re-scanning it a handful of
# times costs nothing measurable.
# ============================================================================
_emit_section_findings() {
  local wanted=" $1 " any_mode="$2" fid fsev fpath fdetail msg
  SECTION_ANY=0
  while IFS= read -r -d '' fid \
     && IFS= read -r -d '' fsev \
     && IFS= read -r -d '' fpath \
     && IFS= read -r -d '' fdetail; do
    case "$wanted" in *" $fid "*) : ;; *) continue ;; esac
    if [ "$any_mode" = "any" ] || [ "$fsev" = "fail" ]; then
      SECTION_ANY=1
    fi
    msg=$(_msg_for_id "$fid" "$fpath" "$fdetail")
    case "$fsev" in
      fail) fail "$msg" ;;
      warn) warn "$msg" ;;
      info) info "$msg" ;;
      *)
        fail "Unknown severity '$fsev' for ChainDrop finding id '$fid' — $fpath"
        SECTION_ANY=1
        ;;
    esac
    case "$fid" in
      claude-hook) printf '%s\n' "$(sanitize_block_for_terminal "$fdetail")" | head -5 | sed 's/^/        /' ;;
      # A single `printf` substitution, NOT `... | sed 's/^/  /'` — a path is
      # ONE value that may itself contain a literal embedded newline byte
      # (T-17-10/B5); piping it through sed would re-split on that embedded
      # byte and inject a second indent mid-path, corrupting the very bytes
      # this NUL-delimited protocol exists to keep intact. (claude-hook,
      # below, is intentionally different: `fdetail` there is already
      # several independent matched-line strings the OLD bash also indented
      # one per line — not a single path.) 19-10-PLAN.md: this is the reason
      # this arm uses sanitize_for_terminal (single-line), never
      # sanitize_block_for_terminal (block) -- the block function's LF-preserving
      # design would re-split an embedded-newline path exactly like `sed` would.
      marker-string) printf '         %s\n' "$(sanitize_for_terminal "$fpath")" ;;
    esac
  done < "$RESULTS_DIR/lists/findings.z"
}

# ============================================================================
# 1. Strong file markers + setup.mjs triage (engine-owned: 1a/1a2/1b)
# ============================================================================
section "1. Malicious file markers (Math_Symbol.js, gh-token-monitor, setup.mjs)"
_emit_section_findings "file-marker payload-variant payload-variant-warn setup-hash setup-preinstall-pair setup-bare" "fail"
[ "$SECTION_ANY" -eq 0 ] && pass "No strong ChainDrop file markers found"

# gh-token-monitor persistence watcher in its known install locations
# (bash-owned — 1c: four ABSOLUTE presence-only checks with no matching
# logic at all; one of the four locations lies outside every scan root. The
# engine supplies the checked locations via spec/watcher-paths.txt (from the
# spec's staticPaths) so bash never re-hardcodes them, but performs none of
# the checking itself. staticPaths ALSO carries the two static
# .claude/settings*.json paths — those are engine-owned content checks (see
# section 4 below), not presence-only watcher checks, so they are excluded
# here to avoid misreporting an ordinary settings file as "watcher installed".
section "1b. gh-token-monitor persistence watcher"
WATCHER_ANY=0
if [ -r "$RESULTS_DIR/spec/watcher-paths.txt" ]; then
  while IFS= read -r _w; do
    [ -z "$_w" ] && continue
    case "$_w" in */.claude/settings.json|*/.claude/settings.local.json) continue ;; esac
    _w="${_w/\$HOME/$HOME}"
    if [ -e "$_w" ]; then
      fail "ChainDrop token-revocation watcher installed — $_w  (REMOVE THIS BEFORE ROTATING ANY CREDENTIALS)"
      WATCHER_ANY=1
    fi
  done < "$RESULTS_DIR/spec/watcher-paths.txt"
fi
[ "$WATCHER_ANY" -eq 0 ] && pass "No gh-token-monitor watcher in known persistence locations"

# ============================================================================
# 2. Malicious preinstall script marker (engine-owned)
# ============================================================================
section "2. package.json preinstall marker ('node setup.mjs')"
_emit_section_findings "install-marker" "fail"
[ "$SECTION_ANY" -eq 0 ] && pass "No package.json with the ChainDrop preinstall marker"

# ============================================================================
# 3. Poisoned compromised-family versions (lockfiles + installed node_modules)
# ============================================================================
section "3. Poisoned keyv/cacheable-family versions"

# FAIL only on an EXACT poisoned name@version; a family package at any other
# version is expected (ubiquitous transitive deps) and not reported.
# Bash-owned (3a): the awk package-section-window matcher below carries a
# yarn-Berry false-negative lesson from its own development history and is
# DELIBERATELY NOT reimplemented in the engine (see lib/traverse/engine.js's
# DETECTOR_OWNERSHIP row 3a). A claim raised and found WRONG during cross-AI
# plan review, recorded so nobody re-derives it: this matcher is
# lockfile-only; section 2's preinstall check is a SEPARATE, no-prune scan
# that already reaches node_modules/<family>/package.json on its own (D-25)
# — this matcher must never be extended to also match package.json.
poisoned_hit_in_file() {
  # $1 = file. Prints matching "name@version" lines for poisoned combos.
  # Handles every common lockfile shape by anchoring on a package-section HEADER
  # that names the package, then confirming the poisoned version on a nearby
  # "version" line — so a poisoned version of package A is never mismatched
  # against an innocent package B:
  #   - pnpm / npm ls:        a bare "<name>@<ver>" token (fast path)
  #   - npm v1 lockfile:      "<name>": { ... "version": "<ver>" }
  #   - npm v2/v3 lockfile:   "node_modules/<name>": { "version": "<ver>" }
  #   - yarn classic (v1):    <name>@<range>:  \n  version "<ver>"
  #   - yarn berry (v2+):     "<name>@npm:<range>":  \n  version: <ver>
  # All matching is literal (awk index()) to avoid regex-escaping the name/
  # version, which contain '.', '@' and '/'.
  local file="$1" pv name ver
  for pv in "${POISONED_PKG_VERSIONS[@]}"; do
    name="${pv%@*}"; ver="${pv##*@}"
    if grep -Fq "$pv" "$file" 2>/dev/null; then
      printf '%s\n' "$pv"
      continue
    fi
    awk -v n="$name" -v v="$ver" -v pv="$pv" '
      # Package-section header referencing this exact name: npm json key,
      # npm path key, or a yarn "<name>@..." dependency header. The trailing
      # "@" (or "\":) prevents keyv from matching @keyv/redis and vice-versa.
      (index($0, "\"" n "\":") || index($0, "node_modules/" n "\"") || index($0, n "@")) { hot = 6; next }
      # Version line within the window: works for "version": "x" (npm),
      # version "x" (yarn v1), and version: x (yarn berry).
      hot > 0 {
        if (index($0, "version") && index($0, v)) { print pv; exit }
        hot--
      }
    ' "$file" 2>/dev/null
  done
}

POISON_ANY=0
if [ -r "$RESULTS_DIR/lists/lockfiles.z" ]; then
  while IFS= read -r -d '' _lf; do
    [ -z "$_lf" ] && continue
    _hits=$(poisoned_hit_in_file "$_lf")
    if [ -n "$_hits" ]; then
      while IFS= read -r _hpv; do
        [ -z "$_hpv" ] && continue
        fail "Poisoned ChainDrop version $_hpv referenced in $_lf"
        POISON_ANY=1
      done <<< "$_hits"
    fi
  done < "$RESULTS_DIR/lists/lockfiles.z"
fi

# Installed compromised-family packages whose on-disk package.json is a
# poisoned version (engine-owned — 3b).
_emit_section_findings "poisoned-installed" "fail"
[ "$SECTION_ANY" -eq 1 ] && POISON_ANY=1

# FAM_COUNT mirrors the old "$FAM_COUNT checked" PASS wording — every
# compromised-family package.json the engine classified (poisoned or not),
# read from the same enumeration pass that fed the poisoned-installed check.
FAM_COUNT=0
if [ -r "$RESULTS_DIR/lists/family-packages.z" ]; then
  while IFS= read -r -d '' _fp; do
    FAM_COUNT=$((FAM_COUNT + 1))
  done < "$RESULTS_DIR/lists/family-packages.z"
fi

if [ "$POISON_ANY" -eq 0 ]; then
  if [ "$FAM_COUNT" -gt 0 ]; then
    pass "Compromised-family packages present only at non-poisoned versions ($FAM_COUNT checked; expected for eslint transitive deps)"
  else
    pass "No poisoned family versions found"
  fi
fi

# ============================================================================
# 4. AI-agent persistence (.claude/settings.json, .vscode/tasks.json)
# ============================================================================
section "4. AI-agent persistence hooks (the worm's no-install re-exec path)"

# DEVIATION FROM THE PLAN'S LITERAL DETECTOR_OWNERSHIP TEXT (recorded in the
# 17-14 plan summary): DETECTOR_OWNERSHIP documents section 4a's two STATIC
# $HOME/.claude/settings*.json paths as engine-owned via "the same matcher"
# as the per-root glob discovery. Making that true in production would
# require the engine's argv entry point to add os.homedir()-derived paths to
# its `roots` array UNCONDITIONALLY — but that entry point is invoked
# directly (no HOME override) by tests/traverse/run-cli.test.js, so that
# root would resolve to
# THIS MACHINE'S real ~/.claude (Claude Code's own config dir, which every
# developer running this repo already has), making run.js's behaviour
# depend on the operator's own machine state — the opposite of this
# project's hermetic-test / offline-first posture, and a real risk of
# self-flagging or of spuriously breaking that already-frozen test file.
# So the two STATIC paths stay a small, targeted, bash-owned presence+
# content check below, reusing the SAME commandPattern regex the engine
# would use (read from the wave spec, never hardcoded) so wording and
# matching logic do not fork. The PER-ROOT glob-discovered
# .claude/settings*.json files (any project under the scanned roots) remain
# fully engine-owned, unchanged from DETECTOR_OWNERSHIP.
CLAUDE_HOOK_RE=$(grep -o '"commandPattern"[[:space:]]*:[[:space:]]*"[^"]*"' "$WAVE_SPEC" 2>/dev/null | head -1 | sed -E 's/^"commandPattern"[[:space:]]*:[[:space:]]*"//; s/"$//')
# The manifest is JSON — its string value has JSON-escaped backslashes
# (`\\.` for a literal `\.`); undo that one level of escaping before handing
# the pattern to grep -E, or every backslash-escaped ERE metachar in it
# (setup\.mjs, npm-cache\.com, the curl pipe) doubles and silently stops
# matching its own literal dot/pipe.
CLAUDE_HOOK_RE="${CLAUDE_HOOK_RE//\\\\/\\}"

HOOK_ANY=0
for _sf in "$HOME/.claude/settings.json" "$HOME/.claude/settings.local.json"; do
  [ -f "$_sf" ] || continue
  case "$_sf" in "$SELF_ROOT"/*) continue ;; esac
  grep -q '"hooks"' "$_sf" 2>/dev/null || continue
  _m=""
  if [ -n "$CLAUDE_HOOK_RE" ]; then
    _m=$(grep -nE '"command"[[:space:]]*:' "$_sf" 2>/dev/null | grep -E "$CLAUDE_HOOK_RE" || true)
  fi
  if [ -n "$_m" ]; then
    fail "Suspicious hook command in $_sf (ChainDrop persistence)"
    printf "%s\n" "$(sanitize_block_for_terminal "$_m")" | head -5 | sed 's/^/        /'
    HOOK_ANY=1
  fi
done

_emit_section_findings "claude-hook" "fail"
[ "$SECTION_ANY" -eq 1 ] && HOOK_ANY=1
[ "$HOOK_ANY" -eq 0 ] && pass "No worm-pattern hook commands in Claude settings files"

# .vscode/tasks.json — folderOpen task (engine-owned).
_emit_section_findings "vscode-task vscode-task-info" "fail"
[ "$SECTION_ANY" -eq 0 ] && pass "No ChainDrop-pattern folderOpen tasks found"

# ============================================================================
# 5. Known-bad file hashes (engine-owned, definitive, anywhere under code roots)
# ============================================================================
section "5. Known-bad ChainDrop payload hashes"
_emit_section_findings "known-hash" "fail"
[ "$SECTION_ANY" -eq 0 ] && pass "No files match known ChainDrop payload hashes"

# ============================================================================
# 6. Network / behavioural markers (code roots + shell history) + Bun staging
# ============================================================================
section "6. Network / behavioural marker strings"
MARK_HITS=0

# Shell history (bash-owned — 6a): two ABSOLUTE $HOME history files, checked
# one marker string at a time. The engine supplies the marker-string list
# and the two history paths via the spec; it never reads a shell-history
# file itself.
if [ -r "$RESULTS_DIR/spec/shell-history-paths.txt" ]; then
  while IFS= read -r _hf; do
    [ -z "$_hf" ] && continue
    [ -f "$_hf" ] || continue
    for _s in "${MARKER_STRINGS[@]}"; do
      grep -qF "$_s" "$_hf" 2>/dev/null && fail "Marker '$_s' in shell history $_hf" && MARK_HITS=1
    done
  done < "$RESULTS_DIR/spec/shell-history-paths.txt"
fi

# Marker strings in code roots (engine-owned — 6b: bulk-content tier plus
# the targeted marker-config class for .env/.env.*/.npmrc — see D-13 in
# lib/traverse/index.js for the tiering rationale).
_emit_section_findings "marker-string" "fail"
[ "$SECTION_ANY" -eq 1 ] && MARK_HITS=1

# Bun staging directories from a live/recent detonation (bash-owned — 6c: a
# directory glob under TMPDIR, entirely outside every scan root).
if ls -d "${TMPDIR:-/tmp}"/bun-dl-* >/dev/null 2>&1; then
  warn "Bun staging dir(s) present (${TMPDIR:-/tmp}/bun-dl-*) — ChainDrop stages its payload via Bun; investigate"
  MARK_HITS=1
fi
[ "$MARK_HITS" -eq 0 ] && pass "No ChainDrop network/behavioural markers found"

# ============================================================================
# 7. GitHub dead-drop repo audit (requires gh) — bash-owned, unchanged: needs
#    network access and the gh CLI, entirely outside the engine's offline,
#    filesystem-only scope.
# ============================================================================
section "7. GitHub dead-drop repository audit"
if [ -n "${LSH_NO_NETWORK:-}" ]; then
  info "Network checks disabled (LSH_NO_NETWORK set) — skipping gh dead-drop audit"
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  REPO_JSON=$(gh repo list --limit 200 --json name,description 2>/dev/null || true)
  if [ -z "$REPO_JSON" ]; then
    warn "gh repo list returned no data (rate-limited or no repos?)"
  else
    if printf "%s" "$REPO_JSON" | grep -qi "Shai-Hulud: Here We Go Again\|Shai-Hulud"; then
      fail "A repo in your account carries a Shai-Hulud dead-drop description:"
      printf "%s" "$(sanitize_block_for_terminal "$REPO_JSON")" | grep -i "Shai-Hulud" | sed 's/^/      /'
    else
      pass "No repos match the ChainDrop dead-drop description"
    fi
  fi
else
  info "gh not installed/authenticated — skipping repo audit (run 'gh auth login' to enable)"
fi

# ============================================================================
# Final summary
# ============================================================================
section "Summary"

# Skip inventory (D-16): aggregate counts here; the full path list per
# reason lives in the retained results dir's skips/ directory. Mirrors
# lib/traverse/index.js's SKIP_REASONS vocabulary — structural metadata
# about the results-dir SCHEMA, not per-wave IOC data, so it is the one
# reason-name list this script does name directly rather than read from spec/.
# 2026-08-07: gitignore/git-degradation-related reasons ('gitignored',
# 'media', and the five git-status names) are REMOVED from this list --
# lib/traverse/git-ignore.js (their only producer) is deleted, and nothing
# in the engine consults git any more (proven by
# tests/traverse/zero-git-subprocess.test.js), so those scalar files no
# longer exist. Degradation reporting is retired with it: the engine's
# `degradations` field is now permanently `[]` (kept for results-directory
# protocol shape stability, not as a live mechanism -- see
# lib/traverse/engine.js's run()), so scalars/degradation-count always
# reads 0 and there is no longer a report line to print for it.
# 2026-08-12 (D-01, G-1543/G-1544): 'swapped' added -- a post-classification
# TOCTOU symlink swap (lib/traverse/read-pool.js's ELOOP branch). This list
# is now guarded by a permanent, bidirectional drift test in
# tests/chaindrop-scanner.test.js ("a permanent drift guard fails if the
# bash _SKIP_REASONS list and SKIP_REASONS ever disagree"), because until
# 2026-08-11 this line had ZERO test coverage -- `_SKIP_REASONS` was
# referenced only inside this script (the declaration and the loop directly
# below it) and by nothing else in the repo, so omitting a reason here would
# have left `[skip] <reason>: N` permanently unprinted with a fully green
# suite.
#
# CORRECTED 2026-08-16: this comment previously claimed the search "returned
# exactly one hit, this declaration itself". It returns TWO -- the
# declaration and its own consuming loop. The conclusion (no coverage,
# because nothing OUTSIDE this script referenced it) was right; the stated
# evidence was not. Recorded rather than quietly patched, because "a grep
# proved it" is the exact class of claim this project has been burned by.
_SKIP_REASONS="oversized symlink other-device unreadable budget swapped"
for _r in $_SKIP_REASONS; do
  _n=$(_read_scalar "skip-$_r")
  if [ "$_n" -gt 0 ] 2>/dev/null; then
    printf "  ${YELLOW}[skip]${RESET} %s: %s\n" "$_r" "$_n"
  fi
done

if [ "$FINDINGS" -eq 0 ] && [ "$INCOMPLETE" -eq 0 ]; then
  printf "${GREEN}${BOLD}ALL CLEAR${RESET} — no ChainDrop (Aug 2026) IOCs detected on this host.\n"
  printf "\nKeep in mind:\n"
  printf "  - This scan checks KNOWN IOCs only. Worm variants rotate indicators.\n"
  printf "  - Provenance is NOT a defense here: 'npm audit signatures' PASSES the\n"
  printf "    poisoned versions (valid GitHub-Actions attestation). Re-run after installs.\n"
  printf "  - Prefer npm v12 default-deny install scripts + a 3-7 day install cooldown;\n"
  printf "    see docs/supply-chain-defense.md.\n"
  exit 0
elif [ "$FINDINGS" -gt 0 ]; then
  printf "${RED}${BOLD}%d FINDING(S) — INVESTIGATE${RESET}\n" "$FINDINGS"
  printf "\nFindings:\n"
  printf '%s' "$FINDING_LOG"
  if [ "$INCOMPLETE" -eq 1 ]; then
    printf "\n${YELLOW}${BOLD}INCOMPLETE${RESET} — results retained at %s\n" "$RESULTS_DIR"
  fi
  printf "\n${BOLD}${RED}REMEDIATION ORDER MATTERS (ChainDrop-specific):${RESET}\n"
  printf "  1. Capture evidence first (copy flagged files to isolated storage).\n"
  printf "  2. ${BOLD}Remove the gh-token-monitor watcher AND its systemd unit / LaunchAgent\n"
  printf "     BEFORE rotating anything.${RESET} ChainDrop arms a watcher that detonates a\n"
  printf "     destructive payload when a stolen token is revoked — rotating first can\n"
  printf "     trigger it.\n"
  printf "  3. THEN rotate credentials reachable from this machine, from a CLEAN machine:\n"
  printf "     GitHub PAT + SSH keys, npm token, cloud tokens in env / .npmrc / cred files.\n"
  printf "  4. For a poisoned package: do NOT npm install in that tree. Remove it, purge the\n"
  printf "     npm/bun cache, and rebuild the lockfile from a clean, pinned source\n"
  printf "     (last-known-good versions are in manifests/chaindrop-poisoned-versions.json).\n"
  printf "  5. For agent-hook / tasks.json implants: review the file before opening the repo\n"
  printf "     in an AI-enabled editor (folder-open + SessionStart auto-execute with no install).\n"
  printf "\nDo not run installers on the affected machine until cleaned.\n"
  exit 1
else
  printf "\n${RED}${BOLD}INCOMPLETE${RESET} — the scan did not finish, this is NOT a clean result.\n"
  printf "Results retained at: %s\n" "$RESULTS_DIR"
  exit 2
fi
