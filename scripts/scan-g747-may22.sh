#!/usr/bin/env bash
# ============================================================================
# G-747 supplementary IOC scanner — May 22, 2026 wave
# ============================================================================
#
# What this does:
#   Read-only scan for IOCs from the four events landed on/around May 22, 2026
#   that are NOT covered by scan-shai-hulud-may2026.sh:
#
#     A. parikhpreyash4 postinstall worm (gvfsd-network → /tmp/.sshd)
#     B. Laravel-Lang Composer RCE (autoload.files + flipboxstudio[.]info)
#     C. Nx Console v18.95.0 (~/.claude/settings.json exfil)
#     D. Dependency sweep for compromised npm/PyPI/Composer packages
#     E. TrapDoor zero-width Unicode injection in AI config files
#
# What this does NOT do:
#   - No file deletions, no quarantine, no network calls
#   - No modifications to shell, npm, npmrc, or system config
#   - Safe to run multiple times; complements (not replaces) the parent scanner
#
# Requirements:
#   - macOS (some checks also work on Linux)
#   - bash, grep, find, perl (for Unicode regex), dscacheutil (macOS DNS check)
#
# Usage:
#   chmod +x scan-g747-may22.sh
#   ./scan-g747-may22.sh
#
# Exclusion:
#   By default, paths matching */llm-safe-haven/docs/* are skipped when
#   grepping for IOC strings inside project trees — our own defense docs
#   intentionally contain IOC strings and would otherwise self-flag.
#   Override via G747_EXCLUDE_PATHS (colon-separated glob fragments).
#
# Exit code: 0 if ALL CLEAR, 1 if any FINDINGS.
# ============================================================================

set -u

if [ -t 1 ]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
  BOLD=$'\033[1m'; RESET=$'\033[0m'
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

# Exclusion patterns for IOC string searches inside project trees.
#
# Default skips the entire llm-safe-haven repo: it IS a security toolkit and
# its docs + scanners intentionally contain IOC strings (XOR keys, beacon
# domains, attacker handles). A self-flagged repo would also be uninformative
# — real compromise of this repo would surface elsewhere (commits, lockfiles,
# settings files) that the parent scan-shai-hulud-may2026.sh already audits.
#
# Add more entries here if you have other defensive-content repos.
DEFAULT_EXCLUDE="llm-safe-haven"
EXCLUDES="${G747_EXCLUDE_PATHS:-$DEFAULT_EXCLUDE}"

# Check whether a path matches any exclusion fragment.
is_excluded() {
  local p="$1"
  local IFS=':'
  for frag in $EXCLUDES; do
    [ -z "$frag" ] && continue
    case "$p" in *"$frag"*) return 0 ;; esac
  done
  return 1
}

# Determine which code roots exist on this host.
SEARCH_ROOTS=()
for d in "$HOME/Projects" "$HOME/Code" "$HOME/Documents" "$HOME/src" "$HOME/Work"; do
  [ -d "$d" ] && SEARCH_ROOTS+=("$d")
done

printf "${BOLD}G-747 supplementary IOC scanner — May 22, 2026 wave${RESET}\n"
printf "Host: %s\n" "$(hostname)"
printf "User: %s\n" "$(whoami)"
printf "Date: %s\n" "$(date)"
printf "Search roots: %s\n" "${SEARCH_ROOTS[*]:-(none found)}"
printf "Exclusions: %s\n" "$EXCLUDES"

# ============================================================================
# A. Postinstall worm — parikhpreyash4 / gvfsd-network → /tmp/.sshd
# ============================================================================
section "A. Postinstall worm (parikhpreyash4 / gvfsd-network)"

if [ -e /tmp/.sshd ]; then
  fail "/tmp/.sshd EXISTS — postinstall worm artifact ($(ls -la /tmp/.sshd 2>/dev/null | head -1))"
else
  pass "/tmp/.sshd absent"
fi

GVFSD_HITS=""
for loc in /tmp /usr/local/bin "$HOME/.local/bin" "$HOME/bin"; do
  [ -d "$loc" ] || continue
  while IFS= read -r f; do
    [ -n "$f" ] && GVFSD_HITS="${GVFSD_HITS}${f}\n"
  done < <(find "$loc" -maxdepth 2 -name "gvfsd-network" 2>/dev/null)
done
if [ -n "$GVFSD_HITS" ]; then
  fail "gvfsd-network binary found:"
  printf "$GVFSD_HITS"
else
  pass "gvfsd-network binary absent from /tmp, /usr/local/bin, ~/.local/bin, ~/bin"
fi

PROC_HITS=$(ps -axo command 2>/dev/null | grep -E "gvfsd-network|/tmp/\.sshd" | grep -v grep || true)
if [ -n "$PROC_HITS" ]; then
  fail "Suspicious processes running:"
  printf "%s\n" "$PROC_HITS"
else
  pass "No gvfsd-network or /tmp/.sshd processes running"
fi

# parikhpreyash4 references in shell history + git config
PARIKH_HITS=""
for h in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history" "$HOME/.gitconfig"; do
  [ -f "$h" ] || continue
  if grep -q "parikhpreyash4\|systemd-network-helper-aa5c751f" "$h" 2>/dev/null; then
    PARIKH_HITS="${PARIKH_HITS}${h}\n"
  fi
done
if [ -n "$PARIKH_HITS" ]; then
  warn "parikhpreyash4 / systemd-network-helper-aa5c751f references found in:"
  printf "$PARIKH_HITS"
else
  pass "No parikhpreyash4 references in shell history / git config"
fi

# ============================================================================
# B. Laravel-Lang RCE — flipboxstudio[.]info / autoload.files
# ============================================================================
section "B. Laravel-Lang RCE (flipboxstudio[.]info / autoload.files)"

FLIPBOX_HITS=""
for h in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history"; do
  [ -f "$h" ] || continue
  if grep -q "flipboxstudio" "$h" 2>/dev/null; then
    FLIPBOX_HITS="${FLIPBOX_HITS}${h}\n"
  fi
done
if [ -n "$FLIPBOX_HITS" ]; then
  fail "flipboxstudio reference in shell history:"
  printf "$FLIPBOX_HITS"
else
  pass "No flipboxstudio reference in shell history"
fi

if command -v dscacheutil >/dev/null 2>&1; then
  if dscacheutil -q host -a name flipboxstudio.info 2>/dev/null | grep -q "ip_address"; then
    fail "DNS cache resolved flipboxstudio.info — may have been queried"
  else
    pass "flipboxstudio.info not in macOS DNS cache"
  fi
else
  info "dscacheutil not available — skipping DNS cache check"
fi

TMPDIR_REAL="${TMPDIR:-/tmp}"
if [ -d "${TMPDIR_REAL%/}/.laravel_locale" ]; then
  fail "Laravel-Lang staging dir EXISTS: ${TMPDIR_REAL%/}/.laravel_locale"
else
  pass "${TMPDIR_REAL%/}/.laravel_locale staging dir absent"
fi

# DebugChromium.exe Windows artifact — unlikely on macOS but cheap to check
DEBUG_HITS=""
while IFS= read -r f; do
  [ -n "$f" ] && DEBUG_HITS="${DEBUG_HITS}${f}\n"
done < <(find "$HOME" -maxdepth 4 -name "DebugChromium.exe" 2>/dev/null)
if [ -n "$DEBUG_HITS" ]; then
  fail "DebugChromium.exe Windows artifact found:"
  printf "$DEBUG_HITS"
else
  pass "DebugChromium.exe absent (macOS expected)"
fi

# XOR-key string search — scoped to SEARCH_ROOTS, with exclusion of defense docs
if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping XOR-key string search"
else
  XOR_HITS=""
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    is_excluded "$f" && continue
    XOR_HITS="${XOR_HITS}${f}\n"
  done < <(grep -rlF "k9X2mP7vL4nQ8wR1" "${SEARCH_ROOTS[@]}" \
              --exclude-dir=node_modules --exclude-dir=.git \
              --exclude-dir=vendor --exclude-dir=.venv --exclude-dir=venv \
              2>/dev/null)
  if [ -n "$XOR_HITS" ]; then
    fail "Laravel-Lang XOR key string 'k9X2mP7vL4nQ8wR1' found in:"
    printf "$XOR_HITS"
  else
    pass "Laravel-Lang XOR key string not found in project trees"
  fi
fi

# ============================================================================
# C. Nx Console v18.95.0
# ============================================================================
section "C. Nx Console v18.95.0 VS Code extension"

EXT_DIRS=(
  "$HOME/.vscode/extensions"
  "$HOME/.vscode-insiders/extensions"
  "$HOME/.cursor/extensions"
  "$HOME/.windsurf/extensions"
  "$HOME/.vscode-server/extensions"
)
NXC_INSTALLED=""
NXC_BAD=""
for d in "${EXT_DIRS[@]}"; do
  [ -d "$d" ] || continue
  while IFS= read -r ext; do
    [ -n "$ext" ] || continue
    NXC_INSTALLED="${NXC_INSTALLED}${ext}\n"
    case "$ext" in *18.95.0*) NXC_BAD="${NXC_BAD}${ext}\n" ;; esac
  done < <(find "$d" -maxdepth 1 -type d -name "nrwl.angular-console-*" 2>/dev/null)
done
if [ -n "$NXC_BAD" ]; then
  fail "Nx Console v18.95.0 (compromised) installed:"
  printf "$NXC_BAD"
elif [ -n "$NXC_INSTALLED" ]; then
  info "Nx Console installed (not v18.95.0 — verify version manually):"
  printf "$NXC_INSTALLED"
  pass "Compromised v18.95.0 not present"
else
  pass "Nx Console (nrwl.angular-console) not installed in known IDE extension dirs"
fi

# ============================================================================
# D. Dependency sweep across SEARCH_ROOTS
# ============================================================================
section "D. Dependency sweep — May 2026 wave affected packages"

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping dependency sweep"
else
  # Build a list of manifest files once, applying exclusions, to avoid
  # repeated find calls and to apply the defense-doc filter uniformly.
  MANIFESTS=$(mktemp -t g747_manifests.XXXXXX)
  trap 'rm -f "$MANIFESTS"' EXIT
  find "${SEARCH_ROOTS[@]}" -maxdepth 6 -type f \
    \( -name package-lock.json -o -name pnpm-lock.yaml -o -name yarn.lock \
       -o -name package.json -o -name composer.json -o -name composer.lock \
       -o -name "requirements*.txt" -o -name pyproject.toml \
       -o -name uv.lock -o -name poetry.lock \
       -o -name Pipfile.lock \) \
    -not -path "*/node_modules/*" -not -path "*/vendor/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" \
    -not -path "*/.git/*" 2>/dev/null \
    | while IFS= read -r f; do is_excluded "$f" || printf "%s\n" "$f"; done > "$MANIFESTS"

  N_MANIFESTS=$(wc -l < "$MANIFESTS" | tr -d ' ')
  info "Auditing $N_MANIFESTS manifest files (post-exclusion)"

  # D1: @tanstack/* 1.169.5 or 1.169.8
  TS_HITS=""
  while IFS= read -r f; do
    bad=$(grep -nE '"@tanstack/[^"]+":[[:space:]]*"?\^?1\.169\.(5|8)"?' "$f" 2>/dev/null)
    [ -n "$bad" ] && TS_HITS="${TS_HITS}${f}\n"
  done < "$MANIFESTS"
  if [ -n "$TS_HITS" ]; then
    fail "Compromised @tanstack/* version (1.169.5 or 1.169.8) in:"
    printf "$TS_HITS"
  else
    pass "No compromised @tanstack/* version pinned in any manifest"
  fi

  # D2: @mistralai/mistralai 2.2.3/2.2.4 or @opensearch-project/opensearch 3.6.2
  ML_HITS=""
  while IFS= read -r f; do
    bad=$(grep -nE '"@mistralai/mistralai":[[:space:]]*"?\^?2\.2\.(3|4)"?|"@opensearch-project/opensearch":[[:space:]]*"?\^?3\.6\.2"?' "$f" 2>/dev/null)
    [ -n "$bad" ] && ML_HITS="${ML_HITS}${f}\n"
  done < "$MANIFESTS"
  if [ -n "$ML_HITS" ]; then
    fail "Compromised npm package (mistralai/opensearch) in:"
    printf "$ML_HITS"
  else
    pass "No compromised @mistralai/* or @opensearch-project/* version pinned"
  fi

  # D3: @antv/* (entire ecosystem — audit needed)
  AV_HITS=""
  while IFS= read -r f; do
    grep -q '"@antv/' "$f" 2>/dev/null && AV_HITS="${AV_HITS}${f}\n"
  done < "$MANIFESTS"
  if [ -n "$AV_HITS" ]; then
    warn "@antv/* package present (audit version against May 18-19 compromised list):"
    printf "$AV_HITS"
  else
    pass "No @antv/* dependencies"
  fi

  # D4: PyPI mistralai 2.4.6 / guardrails-ai 0.10.1
  PY_HITS=""
  while IFS= read -r f; do
    case "$f" in *.txt|*.toml|*.lock)
      bad=$(grep -nE "^mistralai==2\.4\.6|^guardrails-ai==0\.10\.1|name = \"mistralai\".*2\.4\.6|name = \"guardrails-ai\".*0\.10\.1" "$f" 2>/dev/null)
      [ -n "$bad" ] && PY_HITS="${PY_HITS}${f}\n"
    ;; esac
  done < "$MANIFESTS"
  if [ -n "$PY_HITS" ]; then
    fail "Compromised PyPI package (mistralai 2.4.6 / guardrails-ai 0.10.1) in:"
    printf "$PY_HITS"
  else
    pass "No compromised PyPI mistralai / guardrails-ai version pinned"
  fi

  # D5: Laravel-Lang (any version of any of the 4 packages)
  LL_HITS=""
  while IFS= read -r f; do
    case "$f" in *composer.json|*composer.lock)
      bad=$(grep -nE '"laravel-lang/(lang|http-statuses|attributes|actions)"' "$f" 2>/dev/null)
      [ -n "$bad" ] && LL_HITS="${LL_HITS}${f}\n"
    ;; esac
  done < "$MANIFESTS"
  if [ -n "$LL_HITS" ]; then
    fail "Laravel-Lang package present (no clean tag exists — pin to commit SHA before 2026-05-22 22:32 UTC):"
    printf "$LL_HITS"
  else
    pass "No laravel-lang/* packages in any composer manifest"
  fi

  # D6: parikhpreyash4-affected 8 Packagist packages (dev-* branches only)
  PK_LIST='devdojo/wave|devdojo/genesis|katanaui/katana|elitedevsquad/sidecar-laravel|moritz-sauer-13/silverstripe-cms-theme|crosiersource/crosierlib-base|r2luna/brain|baskarcm/tzi-chat-ui'
  PK_HITS=""
  PK_FAILS=""
  while IFS= read -r f; do
    case "$f" in *composer.json|*composer.lock) ;;
      *) continue ;;
    esac
    pkg_lines=$(grep -nE "\"($PK_LIST)\"" "$f" 2>/dev/null)
    [ -z "$pkg_lines" ] && continue
    PK_HITS="${PK_HITS}${f}\n"
    # Flag FAIL if the constraint is dev-main / dev-master / 3.x-dev (the
    # branch-tracking constraints that the campaign actually compromised).
    bad_constraint=$(printf "%s\n" "$pkg_lines" | grep -E "dev-(main|master)|3\.x-dev")
    [ -n "$bad_constraint" ] && PK_FAILS="${PK_FAILS}${f}\n"
  done < "$MANIFESTS"
  if [ -n "$PK_FAILS" ]; then
    fail "parikhpreyash4-affected Packagist package on a dev-* branch constraint (compromised) in:"
    printf "$PK_FAILS"
  elif [ -n "$PK_HITS" ]; then
    warn "parikhpreyash4-listed Packagist package present (constraint is NOT dev-*, so likely safe — verify manually):"
    printf "$PK_HITS"
  else
    pass "None of the 8 parikhpreyash4-affected Packagist packages present"
  fi

  # D7: composer.json autoload.files containing src/helpers.php
  AL_HITS=""
  while IFS= read -r f; do
    case "$f" in *composer.json) ;;
      *) continue ;;
    esac
    # Scope the autoload check to the autoload block (rough but cheap).
    if grep -A40 '"autoload"' "$f" 2>/dev/null | grep -E 'src/helpers\.php' >/dev/null; then
      AL_HITS="${AL_HITS}${f}\n"
    fi
  done < "$MANIFESTS"
  if [ -n "$AL_HITS" ]; then
    warn "composer.json with autoload.files: src/helpers.php — verify provenance (Laravel-Lang attack pattern, not necessarily malicious in YOUR repo):"
    printf "$AL_HITS"
  else
    pass "No composer.json autoload.files: src/helpers.php pattern found"
  fi
fi

# ============================================================================
# E. TrapDoor zero-width Unicode injection in AI config files
# ============================================================================
section "E. TrapDoor zero-width Unicode in AI config files"

AI_CONFIG_ROOTS=()
[ -d "$HOME/Projects" ] && AI_CONFIG_ROOTS+=("$HOME/Projects")
[ -d "$HOME/Code" ] && AI_CONFIG_ROOTS+=("$HOME/Code")
[ -d "$HOME/.claude" ] && AI_CONFIG_ROOTS+=("$HOME/.claude")
[ -d "$HOME/.cursor" ] && AI_CONFIG_ROOTS+=("$HOME/.cursor")
[ -d "$HOME/.codex" ] && AI_CONFIG_ROOTS+=("$HOME/.codex")
[ -d "$HOME/.aider" ] && AI_CONFIG_ROOTS+=("$HOME/.aider")

if [ ${#AI_CONFIG_ROOTS[@]} -eq 0 ]; then
  info "No AI config roots found — skipping TrapDoor scan"
elif ! command -v perl >/dev/null 2>&1; then
  warn "perl not available — skipping TrapDoor scan (perl is needed for Unicode regex)"
else
  AI_FILES=$(find "${AI_CONFIG_ROOTS[@]}" -type f \
    \( -name "CLAUDE.md" -o -name ".cursorrules" -o -name "*.mdc" \
       -o -name "AGENTS.md" -o -name "MEMORY.md" \
       -o -name "SKILL.md" -o -name "SOUL.md" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null \
    | while IFS= read -r f; do is_excluded "$f" || printf "%s\n" "$f"; done)

  N_AI=$(printf "%s\n" "$AI_FILES" | grep -c . || true)
  info "Scanning $N_AI AI config files for U+200B / U+200C / U+200D / U+FEFF"

  TD_HITS=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    # Skip UTF-8 BOM at byte 0 (a legitimate file marker, not injection).
    # Detect zero-width chars *past* the first 3 bytes.
    if perl -CSD -e '
      open(my $fh, "<:raw", $ARGV[0]) or exit 0;
      read($fh, my $head, 3);
      my $rest = do { local $/; <$fh> };
      close($fh);
      utf8::decode($rest);
      exit (defined($rest) && $rest =~ /[\x{200B}\x{200C}\x{200D}\x{FEFF}]/ ? 1 : 0);
    ' "$f" 2>/dev/null; then
      :  # exit 0 = no hit
    else
      TD_HITS="${TD_HITS}${f}\n"
    fi
  done <<< "$AI_FILES"

  if [ -n "$TD_HITS" ]; then
    fail "Zero-width Unicode chars in AI config files (TrapDoor pattern):"
    printf "$TD_HITS"
  else
    pass "No zero-width Unicode injection detected in $N_AI AI config files"
  fi
fi

# ============================================================================
# Summary
# ============================================================================
section "Summary"

if [ "$FINDINGS" -eq 0 ]; then
  printf "${GREEN}${BOLD}ALL CLEAR${RESET} — no G-747 IOCs detected on this host.\n\n"
  printf "Reminders:\n"
  printf "  - Pair this with scripts/scan-shai-hulud-may2026.sh (waves through May 19).\n"
  printf "  - Re-run after any 'npm install' / 'composer install' / IDE extension install.\n"
  printf "  - Override defense-doc exclusion via G747_EXCLUDE_PATHS env var.\n"
  exit 0
else
  printf "${RED}${BOLD}FINDINGS: %s${RESET}\n" "$FINDINGS"
  printf "%b" "$FINDING_LOG"
  printf "\nNext steps:\n"
  printf "  - Treat affected hosts as potentially compromised.\n"
  printf "  - Rotate credentials accessible from the host (npm/GitHub/cloud/SSH/AI tool keys).\n"
  printf "  - Review the case study in docs/supply-chain-defense.md for IOC context.\n"
  exit 1
fi
