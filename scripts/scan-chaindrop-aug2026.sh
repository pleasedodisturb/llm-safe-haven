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
# What this does NOT do:
#   - No file deletions, no quarantine, no curl|sh, no payload execution
#   - No network calls EXCEPT the optional `gh repo list` audit in Section 7
#     (skipped entirely if gh is absent, unauthenticated, or LSH_NO_NETWORK set)
#   - Safe to run multiple times
#
# Requirements:
#   - bash, grep, find, awk (standard); shasum or sha256sum (for hash checks)
#   - Optional: node/npm (global package list), gh (repo dead-drop audit)
#
# Usage:
#   chmod +x scan-chaindrop-aug2026.sh
#   ./scan-chaindrop-aug2026.sh
#
# Exit code: 0 if ALL CLEAR, 1 if any FINDINGS. (The Node wrapper maps a
# could-not-complete run to exit 2 — an incomplete scan is never "clean".)
#
# Sources: Microsoft Security, Kodem, StepSecurity, Wiz, Chainguard, Socket,
# Aikido, SafeDep, CSO Online (2026-08-04/05). Full IOC table + the bundled
# poisoned-version manifest: manifests/chaindrop-poisoned-versions.json.
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

pass() { printf "  ${GREEN}[PASS]${RESET} %s\n" "$1"; }
fail() {
  printf "  ${RED}[FAIL]${RESET} %s\n" "$1"
  FINDINGS=$((FINDINGS + 1))
  FINDING_LOG="${FINDING_LOG}  - $1\n"
}
warn() { printf "  ${YELLOW}[WARN]${RESET} %s\n" "$1"; }
info() { printf "  ${BOLD}[INFO]${RESET} %s\n" "$1"; }
section() { printf "\n${BOLD}== %s ==${RESET}\n" "$1"; }

# sha256_of FILE — prints hex digest, or empty string if no hashing tool.
sha256_of() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'
  else
    echo ""
  fi
}

# ============================================================================
# Header
# ============================================================================
printf "${BOLD}ChainDrop IOC scanner — August 2026 wave (Mini Shai-Hulud)${RESET}\n"
printf "Host: %s\n" "$(hostname)"
printf "User: %s\n" "$(whoami)"
printf "Date: %s\n" "$(date)"
printf "Home: %s\n" "$HOME"

# Common code roots. Kept in sync with lib/scan.js SCAN_DIRS so the shell
# scanner and the JS secret-scanner examine the same trees. Intentionally does
# NOT include ~/Documents — code lives in these roots, and recursively walking a
# large Documents folder made the scan take minutes. Override with LSH_ROOTS
# (colon-separated) to scan elsewhere.
SEARCH_ROOTS=()
if [ -n "${LSH_ROOTS:-}" ]; then
  IFS=':' read -r -a _lsh_roots <<< "$LSH_ROOTS"
  for d in "${_lsh_roots[@]}"; do [ -d "$d" ] && SEARCH_ROOTS+=("$d"); done
else
  for d in "$HOME/Projects" "$HOME/Developer" "$HOME/Code" "$HOME/src" "$HOME/repos" "$HOME/workspace"; do
    [ -d "$d" ] && SEARCH_ROOTS+=("$d")
  done
fi

# ChainDrop known-bad SHA256s (loaders + stage-2 harvester).
KNOWN_BAD_HASHES=(
  "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"  # Math_Symbol.js/math_init.js (727680 B)
  "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"  # setup.mjs wave-1 (29918 B)
  "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"  # setup.mjs later (11017 B)
)

# Strong file-name markers (FAIL on presence — these have no legitimate use).
FAIL_FILENAMES=( "Math_Symbol.js" "math_init.js" "router_runtime.js" \
  "gh-token-monitor.sh" "gh-token-monitor.service" "com.user.gh-token-monitor.plist" )

# Compromised family → poisoned version(s). FAIL only on an exact poisoned
# version; family presence at any other version is NOT an IOC. Kept in sync
# with manifests/chaindrop-poisoned-versions.json by the script-parity test.
POISONED_PKG_VERSIONS=(
  "keyv@6.0.0"
  "flat-cache@6.1.24"
  "file-entry-cache@11.1.6"
  "file-entry-cache@11.1.7"
  "cacheable-request@13.0.20"
  "cacheable@2.5.1"
  "cache-manager@7.2.10"
  "ecto@5.0.1"
  "@cacheable/utils@2.5.1"
  "@cacheable/memory@2.2.1"
  "@cacheable/node-cache@3.1.2"
  "@cacheable/net@2.1.1"
  "@keyv/redis@6.0.0"
  "@keyv/sqlite@6.0.0"
  "@keyv/mongo@6.0.0"
  "@keyv/postgres@6.0.0"
  "@keyv/mysql@6.0.0"
  "@keyv/memcache@6.0.0"
  "@keyv/etcd@6.0.0"
  "@keyv/dynamo@6.0.0"
  "@keyv/valkey@6.0.0"
  "@keyv/compress-brotli@6.0.0"
  "@keyv/compress-gzip@6.0.0"
  "@keyv/test-suite@6.0.0"
)
COMPROMISED_FAMILY=( "keyv" "cacheable" "cacheable-request" "cache-manager" \
  "flat-cache" "file-entry-cache" "ecto" "@cacheable/utils" "@cacheable/memory" \
  "@cacheable/node-cache" "@cacheable/net" \
  "@keyv/redis" "@keyv/sqlite" "@keyv/mongo" "@keyv/postgres" "@keyv/mysql" \
  "@keyv/memcache" "@keyv/etcd" "@keyv/dynamo" "@keyv/valkey" \
  "@keyv/compress-brotli" "@keyv/compress-gzip" "@keyv/test-suite" )

# Network / behavioural marker strings (code roots + shell history).
MARKER_STRINGS=(
  "npm-cache.com"
  "pypi-get.com"
  "js-mirror.com"
  "104.21.35.216"
  "0xE1f2395ee43e45A1556EC6438a88c31B83493103"
  "Shai-Hulud: Here We Go Again"
)

# This scanner's own repo root — its docs/manifests/fixtures legitimately
# CONTAIN the IOC signatures as detection data, so exclude it from content scans.
SELF_ROOT=""
_sd=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || _sd=""
[ -n "$_sd" ] && SELF_ROOT=$(dirname "$_sd")  # scripts/ -> repo root

PRUNE_COMMON=( -name .git -o -name target -o -name dist -o -name build -o -name .next -o -name .nuxt -o -path '*/.claude/worktrees' )

# ============================================================================
# 1. Strong file markers + setup.mjs triage
# ============================================================================
section "1. Malicious file markers (Math_Symbol.js, gh-token-monitor, setup.mjs)"

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No common code directories found — skipping file-marker scan"
else
  info "Scanning under: ${SEARCH_ROOTS[*]}"
  # (a) Strong filename markers — FAIL on presence.
  MARKER_ANY=0
  for name in "${FAIL_FILENAMES[@]}"; do
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      case "$hit" in "$SELF_ROOT"/*) continue;; esac
      fail "ChainDrop file marker '$name' present — $hit"
      MARKER_ANY=1
    done < <(find "${SEARCH_ROOTS[@]}" \( \( "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f -name "$name" -print \) 2>/dev/null)
  done

  # (b) setup.mjs — WARN alone (a common legit filename, e.g. motion-dom's
  #     gesture helper), FAIL when it carries a known-bad hash OR sits next to a
  #     package.json with the preinstall marker.
  while IFS= read -r sm; do
    [ -z "$sm" ] && continue
    case "$sm" in "$SELF_ROOT"/*) continue;; esac
    sm_dir=$(dirname "$sm")
    sm_sha=$(sha256_of "$sm")
    hashbad=0
    for h in "${KNOWN_BAD_HASHES[@]}"; do
      [ -n "$sm_sha" ] && [ "$sm_sha" = "$h" ] && hashbad=1 && break
    done
    if [ "$hashbad" -eq 1 ]; then
      fail "setup.mjs matches a known ChainDrop loader hash — $sm"
      MARKER_ANY=1
    elif grep -Eq '"preinstall"[[:space:]]*:[[:space:]]*"node[[:space:]]+setup\.mjs"' "$sm_dir/package.json" 2>/dev/null; then
      fail "setup.mjs paired with a 'preinstall: node setup.mjs' package.json (ChainDrop) — $sm"
      MARKER_ANY=1
    else
      warn "setup.mjs present with no worm markers (likely benign, e.g. motion-dom) — review: $sm"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" \( \( "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f -name 'setup.mjs' -print \) 2>/dev/null)

  [ "$MARKER_ANY" -eq 0 ] && pass "No strong ChainDrop file markers found"
fi

# gh-token-monitor persistence watcher in its known install locations.
section "1b. gh-token-monitor persistence watcher"
WATCHER_ANY=0
for w in "$HOME/.local/bin/gh-token-monitor.sh" \
         "$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist" \
         "$HOME/.config/systemd/user/gh-token-monitor.service" \
         "/etc/systemd/system/gh-token-monitor.service"; do
  if [ -e "$w" ]; then
    fail "ChainDrop token-revocation watcher installed — $w  (REMOVE THIS BEFORE ROTATING ANY CREDENTIALS)"
    WATCHER_ANY=1
  fi
done
[ "$WATCHER_ANY" -eq 0 ] && pass "No gh-token-monitor watcher in known persistence locations"

# ============================================================================
# 2. Malicious preinstall script marker
# ============================================================================
section "2. package.json preinstall marker ('node setup.mjs')"

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping preinstall scan"
else
  PRE_HITS=$(grep -rlE '"preinstall"[[:space:]]*:[[:space:]]*"node[[:space:]]+setup\.mjs"' \
    "${SEARCH_ROOTS[@]}" --include=package.json 2>/dev/null || true)
  [ -n "$SELF_ROOT" ] && PRE_HITS=$(printf "%s\n" "$PRE_HITS" | grep -v "^${SELF_ROOT}/" || true)
  PRE_HITS=$(printf "%s\n" "$PRE_HITS" | grep -v '^[[:space:]]*$' || true)
  if [ -n "$PRE_HITS" ]; then
    while IFS= read -r ph; do
      [ -z "$ph" ] && continue
      fail "package.json has 'preinstall: node setup.mjs' (ChainDrop install trigger) — $ph"
    done <<< "$PRE_HITS"
  else
    pass "No package.json with the ChainDrop preinstall marker"
  fi
fi

# ============================================================================
# 3. Poisoned compromised-family versions (lockfiles + installed node_modules)
# ============================================================================
section "3. Poisoned keyv/cacheable-family versions"

# FAIL only on an EXACT poisoned name@version; a family package at any other
# version is expected (ubiquitous transitive deps) and not reported.
poisoned_hit_in_file() {
  # $1 = file. Prints matching "name@version" lines for poisoned combos.
  # Handles every common lockfile shape:
  #   - yarn classic / npm ls / pnpm:  a bare "<name>@<ver>" token
  #   - npm v1 lockfile:               "<name>": { ... "version": "<ver>" }
  #   - npm v2/v3 lockfile:            "node_modules/<name>": { "version": "<ver>" }
  # The awk pass ties the version to the package KEY (within a few lines) so a
  # poisoned version of package A isn't mismatched against an innocent package B.
  local file="$1" pv name ver
  for pv in "${POISONED_PKG_VERSIONS[@]}"; do
    name="${pv%@*}"; ver="${pv##*@}"
    if grep -Fq "$pv" "$file" 2>/dev/null; then
      printf '%s\n' "$pv"
      continue
    fi
    awk -v n="$name" -v v="$ver" -v pv="$pv" '
      index($0, "\"" n "\":") || index($0, "node_modules/" n "\"") { hot = 5; next }
      hot > 0 {
        if (index($0, "\"version\"") && index($0, "\"" v "\"")) { print pv; exit }
        hot--
      }
    ' "$file" 2>/dev/null
  done
}

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping version scan"
else
  POISON_ANY=0
  while IFS= read -r lf; do
    [ -z "$lf" ] && continue
    case "$lf" in "$SELF_ROOT"/*) continue;; esac
    hits=$(poisoned_hit_in_file "$lf")
    if [ -n "$hits" ]; then
      while IFS= read -r hpv; do
        [ -z "$hpv" ] && continue
        fail "Poisoned ChainDrop version $hpv referenced in $lf"
        POISON_ANY=1
      done <<< "$hits"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \) -print \) 2>/dev/null)

  # Installed compromised-family packages whose on-disk package.json is a
  # poisoned version. We read the EXACT version and check it against the
  # poisoned map, so a precise FAIL is possible — no need for a noisy
  # "reinstalled in the attack window" mtime heuristic (which fires on every
  # ordinary post-Aug-4 install and, for the core family, adds no signal over
  # the exact-version check).
  FAM_COUNT=0
  while IFS= read -r fam_pkg; do
    [ -z "$fam_pkg" ] && continue
    case "$fam_pkg" in "$SELF_ROOT"/*) continue;; esac
    FAM_COUNT=$((FAM_COUNT + 1))
    dv=$(grep -m1 -E '"version"[[:space:]]*:' "$fam_pkg" 2>/dev/null | sed -E 's/.*:[[:space:]]*"([^"]+)".*/\1/')
    nm=$(grep -m1 -E '"name"[[:space:]]*:' "$fam_pkg" 2>/dev/null | sed -E 's/.*:[[:space:]]*"([^"]+)".*/\1/')
    [ -z "$nm" ] && continue
    for pv in "${POISONED_PKG_VERSIONS[@]}"; do
      if [ "$nm@$dv" = "$pv" ]; then
        fail "Installed poisoned version on disk: $nm@$dv — $fam_pkg"
        POISON_ANY=1
      fi
    done
  done < <(
    # One find over all roots matching any compromised-family package.json,
    # via a -path alternation built from COMPROMISED_FAMILY (a single traversal
    # instead of one per family per root). Prune agent worktrees, which just
    # duplicate a repo's node_modules N times.
    FAM_PATHS=()
    for fam in "${COMPROMISED_FAMILY[@]}"; do
      [ ${#FAM_PATHS[@]} -gt 0 ] && FAM_PATHS+=( -o )
      FAM_PATHS+=( -path "*/node_modules/$fam/package.json" )
    done
    find "${SEARCH_ROOTS[@]}" \( -path '*/.claude/worktrees/*' -prune \) -o \( -type f \( "${FAM_PATHS[@]}" \) -print \) 2>/dev/null)

  if [ "$POISON_ANY" -eq 0 ]; then
    if [ "$FAM_COUNT" -gt 0 ]; then
      pass "Compromised-family packages present only at non-poisoned versions ($FAM_COUNT checked; expected for eslint transitive deps)"
    else
      pass "No poisoned family versions found"
    fi
  fi
fi

# ============================================================================
# 4. AI-agent persistence (.claude/settings.json, .vscode/tasks.json)
# ============================================================================
section "4. AI-agent persistence hooks (the worm's no-install re-exec path)"

# .claude/settings.json — SessionStart (and any) hook running the loader.
HOOK_SUS_RE='setup\.mjs|Math_Symbol|math_init|gh-token-monitor|node[[:space:]]+-e|curl[[:space:]].*\|[[:space:]]*(sh|bash)|npm-cache\.com|bun-dl-'
SETTINGS_FILES=()
for f in "$HOME/.claude/settings.json" "$HOME/.claude/settings.local.json"; do
  [ -f "$f" ] && SETTINGS_FILES+=("$f")
done
if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  for root in "${SEARCH_ROOTS[@]}"; do
    while IFS= read -r f; do [ -n "$f" ] && SETTINGS_FILES+=("$f"); done \
      < <(find "$root" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f \( -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' \) -print \) 2>/dev/null)
  done
fi
if [ ${#SETTINGS_FILES[@]} -eq 0 ]; then
  info "No Claude settings.json files found — skipping hook audit"
else
  HOOK_ANY=0
  for sf in "${SETTINGS_FILES[@]}"; do
    case "$sf" in "$SELF_ROOT"/*) continue;; esac
    grep -q '"hooks"' "$sf" 2>/dev/null || continue
    M=$(grep -nE '"command"[[:space:]]*:' "$sf" 2>/dev/null | grep -E "$HOOK_SUS_RE" || true)
    if [ -n "$M" ]; then
      fail "Suspicious hook command in $sf (ChainDrop persistence)"
      printf "%s\n" "$M" | head -5 | sed 's/^/        /'
      HOOK_ANY=1
    fi
  done
  [ "$HOOK_ANY" -eq 0 ] && pass "No worm-pattern hook commands in Claude settings files"
fi

# .vscode/tasks.json — folderOpen task (the "Environment Setup" auto-runner).
if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  TASK_ANY=0
  while IFS= read -r tf; do
    [ -z "$tf" ] && continue
    case "$tf" in "$SELF_ROOT"/*) continue;; esac
    grep -lq '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$tf" 2>/dev/null || continue
    cmds=$(grep -oE '"(command|label)"[[:space:]]*:[[:space:]]*"[^"]*"' "$tf" 2>/dev/null)
    if printf "%s\n" "$cmds" | grep -Eiq 'setup\.mjs|Math_Symbol|math_init|Environment Setup|node[[:space:]]+-e|npm-cache\.com'; then
      fail "tasks.json folderOpen task matches ChainDrop persistence — $tf"
      TASK_ANY=1
    else
      # A folderOpen task auto-runs on open; legitimate dev tasks (dev servers,
      # watchers) use it routinely, so this is INFO, not a finding. The
      # ChainDrop-specific pattern above is the FAIL gate.
      info "tasks.json has a folderOpen auto-run task (review if unexpected) — $tf"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f -path '*/.vscode/tasks.json' -print \) 2>/dev/null)
  [ "$TASK_ANY" -eq 0 ] && pass "No ChainDrop-pattern folderOpen tasks found"
fi

# ============================================================================
# 5. Known-bad file hashes (definitive, anywhere under code roots)
# ============================================================================
section "5. Known-bad ChainDrop payload hashes"
if [ ${#SEARCH_ROOTS[@]} -eq 0 ] || ! { command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; }; then
  info "No code roots or no hashing tool — skipping hash scan"
else
  HASH_ANY=0
  # Only hash the handful of files whose NAMES already match a ChainDrop
  # payload — hashing every *.js under the code roots was the scan's slowest
  # step for no added coverage (a renamed payload is caught by the family +
  # preinstall + network checks, not by a blind hash sweep).
  while IFS= read -r cand; do
    [ -z "$cand" ] && continue
    case "$cand" in "$SELF_ROOT"/*) continue;; esac
    cs=$(sha256_of "$cand")
    for h in "${KNOWN_BAD_HASHES[@]}"; do
      if [ -n "$cs" ] && [ "$cs" = "$h" ]; then
        fail "File matches a known ChainDrop payload hash — $cand"
        HASH_ANY=1
      fi
    done
  done < <(find "${SEARCH_ROOTS[@]}" \( \( "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f \( -name 'setup.mjs' -o -name 'Math_Symbol.js' -o -name 'math_init.js' -o -name 'router_runtime.js' \) -size -1024k -print \) 2>/dev/null)
  [ "$HASH_ANY" -eq 0 ] && pass "No files match known ChainDrop payload hashes"
fi

# ============================================================================
# 6. Network / behavioural markers (code roots + shell history) + Bun staging
# ============================================================================
section "6. Network / behavioural marker strings"
MARK_HITS=0
for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
  [ -f "$hf" ] || continue
  for s in "${MARKER_STRINGS[@]}"; do
    grep -qF "$s" "$hf" 2>/dev/null && fail "Marker '$s' in shell history $hf" && MARK_HITS=1
  done
done
if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  MARK_RE=$(printf '%s|' "${MARKER_STRINGS[@]}"); MARK_RE="${MARK_RE%|}"
  # Enumerate small text/code files first, then grep only those. An unbounded
  # `grep -r` over the whole tree stalls on large data/media blobs (BSD grep
  # has no --max-filesize), and a C2 domain / hash / dead-drop string only ever
  # lands in source, config, lockfiles or history anyway — which this covers.
  # xargs keeps the arg list bounded on huge trees.
  HIT=$(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o -name .cache -o "${PRUNE_COMMON[@]}" \) -prune \) -o \
        \( -type f -size -256k \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' \
           -o -name '*.json' -o -name '*.sh' -o -name '*.zsh' -o -name '*.bash' -o -name '*.yml' -o -name '*.yaml' \
           -o -name '*.md' -o -name '*.lock' -o -name '.npmrc' -o -name '.env' \) -print0 \) 2>/dev/null \
        | xargs -0 grep -lIE "$MARK_RE" 2>/dev/null || true)
  [ -n "$SELF_ROOT" ] && HIT=$(printf "%s\n" "$HIT" | grep -v "^${SELF_ROOT}/" || true)
  HIT=$(printf "%s\n" "$HIT" | grep -v '^[[:space:]]*$' | head -10 || true)
  if [ -n "$HIT" ]; then
    fail "ChainDrop marker string(s) in files:"
    printf "%s\n" "$HIT" | sed 's/^/         /'
    MARK_HITS=1
  fi
fi
# Bun staging directories from a live/recent detonation.
if ls -d "${TMPDIR:-/tmp}"/bun-dl-* >/dev/null 2>&1; then
  warn "Bun staging dir(s) present (${TMPDIR:-/tmp}/bun-dl-*) — ChainDrop stages its payload via Bun; investigate"
  MARK_HITS=1
fi
[ "$MARK_HITS" -eq 0 ] && pass "No ChainDrop network/behavioural markers found"

# ============================================================================
# 7. GitHub dead-drop repo audit (requires gh)
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
      printf "%s" "$REPO_JSON" | grep -i "Shai-Hulud" | sed 's/^/      /'
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
if [ "$FINDINGS" -eq 0 ]; then
  printf "${GREEN}${BOLD}ALL CLEAR${RESET} — no ChainDrop (Aug 2026) IOCs detected on this host.\n"
  printf "\nKeep in mind:\n"
  printf "  - This scan checks KNOWN IOCs only. Worm variants rotate indicators.\n"
  printf "  - Provenance is NOT a defense here: 'npm audit signatures' PASSES the\n"
  printf "    poisoned versions (valid GitHub-Actions attestation). Re-run after installs.\n"
  printf "  - Prefer npm v12 default-deny install scripts + a 3-7 day install cooldown;\n"
  printf "    see docs/supply-chain-defense.md.\n"
  exit 0
else
  printf "${RED}${BOLD}%d FINDING(S) — INVESTIGATE${RESET}\n" "$FINDINGS"
  printf "\nFindings:\n"
  printf "%b" "$FINDING_LOG"
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
fi
