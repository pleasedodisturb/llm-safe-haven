#!/usr/bin/env bash
# ============================================================================
# Miasma / Mini Shai-Hulud IOC scanner — June-July 2026 waves
# ============================================================================
#
# What this does:
#   Read-only scan of a macOS/Linux machine for indicators of compromise from
#   the June 2026 "Miasma" (a.k.a. Mini Shai-Hulud / "Hades") npm + Go wave.
#   This wave moved BEYOND postinstall scripts into four new execution vectors:
#
#     1. binding.gyp "Phantom Gyp" — a binding.gyp dropped into a pure-JS
#        package auto-runs `node-gyp rebuild` on `npm install` with NO
#        postinstall entry, via GYP command-substitution: "<!(node index.js ...)"
#     2. GitHub Actions workflow injection (.github/workflows/*.yml) —
#        pull_request_target / workflow_run + untrusted-head checkout, secret
#        scraping, a workflow named "Run Copilot".
#     3. VS Code folder-open tasks (.vscode/tasks.json runOn:folderOpen) — the
#        execution vector for the Go victim (Verana), since Go has no install hook.
#     4. AI-agent hooks (.claude/settings.json SessionStart/PreToolUse/...) and
#        Cursor rules — local-environment persistence + instruction injection.
#
# What this does NOT do:
#   - No file deletions, no quarantine, no curl|sh, no payload execution
#   - No modifications to your shell, npm, or system config
#   - No network calls EXCEPT the optional `gh repo list` dead-drop audit in
#     Section 7 (skipped entirely if gh is absent or not authenticated)
#   - Safe to run multiple times
#
# Requirements:
#   - bash, grep, find, awk (standard); shasum or sha256sum (for hash checks)
#   - Optional: node/npm (global package list), gh (repo dead-drop audit)
#
# Usage:
#   chmod +x scan-miasma-june2026.sh
#   ./scan-miasma-june2026.sh
#
# Exit code: 0 if ALL CLEAR, 1 if any FINDINGS.
#
# Sources: Socket.dev, StepSecurity, Tenable, Wiz, Sonatype, JFrog (June 2026).
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

pass() {
  printf "  ${GREEN}[PASS]${RESET} %s\n" "$1"
}

fail() {
  printf "  ${RED}[FAIL]${RESET} %s\n" "$1"
  FINDINGS=$((FINDINGS + 1))
  FINDING_LOG="${FINDING_LOG}  - $1\n"
}

warn() {
  printf "  ${YELLOW}[WARN]${RESET} %s\n" "$1"
}

info() {
  printf "  ${BOLD}[INFO]${RESET} %s\n" "$1"
}

section() {
  printf "\n${BOLD}== %s ==${RESET}\n" "$1"
}

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
printf "${BOLD}Miasma / Mini Shai-Hulud IOC scanner — June-July 2026 waves${RESET}\n"
printf "Host: %s\n" "$(hostname)"
printf "User: %s\n" "$(whoami)"
printf "Date: %s\n" "$(date)"
printf "Home: %s\n" "$HOME"

# Common code roots (used by several sections below)
SEARCH_ROOTS=()
for d in "$HOME/Projects" "$HOME/Code" "$HOME/Documents" "$HOME/src" "$HOME/Work" "$HOME/go/src" "$HOME/dev"; do
  if [ -d "$d" ]; then
    SEARCH_ROOTS+=("$d")
  fi
done

# Known-bad SHA256 of the reused binding.gyp implant (Jun 3 + ImmobiliareLabs).
KNOWN_BAD_GYP_SHA="ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90"

# This scanner's own repo root. Its docs/hooks/fixtures legitimately CONTAIN the
# IOC signatures and marker strings as detection data, so we exclude it from the
# content scans to avoid the scanner flagging itself.
SELF_ROOT=""
_sd=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || _sd=""
[ -n "$_sd" ] && SELF_ROOT=$(dirname "$_sd")  # scripts/ -> repo root

# Directories pruned from filesystem scans: VCS, build artifacts, and transient
# agent worktrees (which duplicate a repo's workflows/config N times). node_modules
# is pruned per-section — the binding.gyp scan intentionally keeps it (the worm
# lands in installed deps), the others prune it.
PRUNE_COMMON=( -name .git -o -name target -o -name dist -o -name build -o -name .next -o -name .nuxt -o -path '*/.claude/worktrees' )

# ============================================================================
# 1. binding.gyp "Phantom Gyp" install vector (NEW)
# ============================================================================
section "1. binding.gyp 'Phantom Gyp' install vector"

# GYP command-substitution tokens execute a shell command when node-gyp
# processes the file — the mere presence of binding.gyp triggers node-gyp on
# install, so NO postinstall script is needed. Legit native addons rarely use
# <!() / <!@() this way; treat them as high-signal.
#   <!(cmd)   runs cmd, substitutes stdout
#   <!@(cmd)  runs cmd, splits stdout into a list
GYP_SUBST_RE='<!@?\('
# IMPORTANT: legit native addons (e.g. sharp) use <!(node -p "require(...)") to
# read build config — that alone is NOT an IOC. We only FAIL when a <!() line
# ALSO carries a danger token: a network fetch, base64/eval, output suppression
# (> /dev/null), or the "&& echo <stub>" trick the Phantom Gyp payload uses to
# return a fake source filename so gyp doesn't error.
# Note: bare `eval` is intentionally omitted — it substring-matches benign words
# like "retrieval"/"evaluation" inside `<!(node -p "require('retrieval')")`. The
# documented Phantom Gyp pattern is caught by `> /dev/null` + `&& echo` anyway.
GYP_DANGER_RE='curl|wget|base64|fromCharCode|Invoke-WebRequest|>[[:space:]]*/dev/null|&&[[:space:]]*echo'
# An action/rule "action" array that shells out or fetches the network.
GYP_EXEC_RE='"(sh|bash|cmd|powershell|curl|wget|nc|eval)"|node[[:space:]]+-e|curl|wget|Invoke-WebRequest|fromCharCode|base64'

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No common code directories found — skipping binding.gyp scan"
else
  info "Scanning for binding.gyp under: ${SEARCH_ROOTS[*]}"
  GYP_ANY=0
  while IFS= read -r gyp; do
    [ -z "$gyp" ] && continue
    GYP_ANY=1
    pkgdir=$(dirname "$gyp")

    # (a) Known-bad hash match — definitive.
    gyp_sha=$(sha256_of "$gyp")
    if [ -n "$gyp_sha" ] && [ "$gyp_sha" = "$KNOWN_BAD_GYP_SHA" ]; then
      fail "binding.gyp matches known Miasma implant SHA256 — $gyp"
      continue
    fi

    # (b) Command-substitution that ALSO carries a danger token — high signal.
    subst_lines=$(grep -nE "$GYP_SUBST_RE" "$gyp" 2>/dev/null || true)
    if [ -n "$subst_lines" ]; then
      danger=$(printf "%s\n" "$subst_lines" | grep -Ei "$GYP_DANGER_RE" || true)
      if [ -n "$danger" ]; then
        fail "binding.gyp command-substitution runs a suspicious command (Phantom Gyp) — $gyp"
        printf "%s\n" "$danger" | head -5 | sed 's/^/         /'
        continue
      else
        # Benign <!() — common in real native addons (sharp, etc.). Note, don't fail.
        info "binding.gyp uses command-substitution but no danger token (likely legit native addon) — $gyp"
      fi
    fi

    # (c) action/rule arrays that shell out or fetch the network.
    if grep -Eq "$GYP_EXEC_RE" "$gyp" 2>/dev/null; then
      warn "binding.gyp invokes a shell/downloader in a build step — review: $gyp"
      grep -nE "$GYP_EXEC_RE" "$gyp" 2>/dev/null | head -5 | sed 's/^/         /'
    fi

    # (d) binding.gyp present in a package that ships no native sources.
    #     Pure-JS packages have no reason to carry one. Skipped inside
    #     node_modules: spawning a find per dependency is slow and noisy there,
    #     and the cheap hash/token/exec checks above already cover deps.
    case "$gyp" in
      */node_modules/*) ;;  # skip the source-tree heuristic for installed deps
      *)
        if ! find "$pkgdir" -maxdepth 2 \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) 2>/dev/null | grep -q .; then
          if ! grep -Eq '"gypfile"[[:space:]]*:[[:space:]]*true' "$pkgdir/package.json" 2>/dev/null; then
            warn "binding.gyp in a package with no native sources (pure-JS?) — review: $gyp"
          fi
        fi
        ;;
    esac
  done < <(find "${SEARCH_ROOTS[@]}" \( \( "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f -name 'binding.gyp' -print \) 2>/dev/null)

  if [ "$GYP_ANY" -eq 0 ]; then
    pass "No binding.gyp files found under code roots"
  elif [ "$FINDINGS" -eq 0 ]; then
    pass "binding.gyp files found but none match Phantom Gyp patterns"
  fi
fi

# ============================================================================
# 1b. Wave J "M-RED-TEAM" (AsyncAPI, July 14 2026) persistence artifacts (NEW)
# ============================================================================
section "1b. Wave J 'M-RED-TEAM' persistence artifacts"

# Wave J fires at IMPORT time (require/import), not install time — the
# binding.gyp and postinstall vectors above do NOT catch it. This section
# checks the persistence artifacts the second-stage payload drops after a
# compromised @asyncapi/* package is actually loaded, not just installed.
WAVE_J_PATHS=(
  "$HOME/.config/.miasma/run/node.lock|Wave J lock file (node.lock)"
  "$HOME/.cache/.sys_cache/.diag.enc|Wave J local artifact cache (.diag.enc)"
  "$HOME/.local/share/NodeJS/sync.js|Wave J Linux drop path (sync.js)"
  "$HOME/Library/Application Support/NodeJS/sync.js|Wave J macOS drop path (sync.js)"
  "$HOME/.config/systemd/user/miasma-monitor.service|Wave J systemd unit (miasma-monitor.service)"
)
WAVE_J_ANY=0
for entry in "${WAVE_J_PATHS[@]}"; do
  path="${entry%%|*}"
  desc="${entry#*|}"
  if [ -e "$path" ]; then
    fail "$desc EXISTS: $path"
    WAVE_J_ANY=1
  fi
done
[ "$WAVE_J_ANY" -eq 0 ] && pass "No Wave J filesystem persistence artifacts found"

# Windows persistence key (only checkable if running under WSL/Cygwin with reg.exe on PATH)
if command -v reg.exe >/dev/null 2>&1; then
  if reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v miasma-monitor >/dev/null 2>&1; then
    fail "Wave J Windows persistence key found: HKCU...\\Run\\miasma-monitor"
  else
    pass "No Wave J Windows persistence key (miasma-monitor)"
  fi
fi

# ============================================================================
# 2. GitHub Actions workflow injection (NEW)
# ============================================================================
section "2. GitHub Actions workflow injection (.github/workflows)"

# Privileged triggers (pull_request_target, workflow_run) run with a
# read-write token + secret access. Abuse = checking out the UNTRUSTED PR head
# and running it, or scraping secrets from the runner and exfiltrating them.
# Secret-scrape / dead-drop signatures — these are the actual Miasma IOC (FAIL).
WF_SCRAPE_RE='"isSecret"[[:space:]]*:[[:space:]]*true|Runner\.Worker|169\.254\.169\.254|liuende501'
# Pipe-to-shell — extremely common for LEGIT tool installers in CI (rustup, bun,
# nvm, sentry-cli). Not an IOC by itself, so this is a WARN, not a FAIL.
WF_PIPE_RE='(curl|wget)[^|&;]*\|[[:space:]]*(ba)?sh|base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba)?sh'
# Kept in sync with config-guard.js WF_UNTRUSTED_CHECKOUT.
WF_UNTRUSTED_CHECKOUT_RE='github\.event\.pull_request\.head\.(sha|ref)|github\.event\.workflow_run\.head_(branch|sha)|github\.head_ref'

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping workflow scan"
else
  WF_ANY=0
  while IFS= read -r wf; do
    [ -z "$wf" ] && continue
    # Skip this scanner's own repo (its workflows are detection data / legit CI).
    if [ -n "$SELF_ROOT" ]; then case "$wf" in "$SELF_ROOT"/*) continue;; esac; fi
    WF_ANY=1
    wf_bad=0

    # (a) "Run Copilot" — the workflow name used by this campaign.
    if grep -Eq '^[[:space:]]*name:[[:space:]]*["'\'']?Run Copilot' "$wf" 2>/dev/null; then
      fail "Workflow named 'Run Copilot' (Miasma IOC) — $wf"
      wf_bad=1
    fi

    # (b) Privileged trigger + checkout of untrusted PR head.
    if grep -Eq 'pull_request_target|workflow_run' "$wf" 2>/dev/null \
       && grep -Eq "$WF_UNTRUSTED_CHECKOUT_RE" "$wf" 2>/dev/null; then
      fail "Privileged trigger checks out untrusted PR head (code-exec risk) — $wf"
      wf_bad=1
    fi

    # (c) Secret-scrape / dead-drop signatures in run: steps — real IOC.
    if grep -Eq "$WF_SCRAPE_RE" "$wf" 2>/dev/null; then
      fail "Workflow scrapes/exfiltrates secrets (Miasma signature) — $wf"
      grep -nE "$WF_SCRAPE_RE" "$wf" 2>/dev/null | head -3 | sed 's/^/         /'
      wf_bad=1
    fi

    # (c2) Pipe-to-shell — common for legit installers; WARN, review the URL.
    #      Ignore matches inside an echo / step-summary / comment: those write
    #      the command as TEXT (e.g. install instructions), they don't run it.
    if [ "$wf_bad" -eq 0 ]; then
      pipe_lines=$(grep -nE "$WF_PIPE_RE" "$wf" 2>/dev/null \
                    | grep -vE 'echo|GITHUB_STEP_SUMMARY|^[[:space:]]*[0-9]+:[[:space:]]*#' || true)
      if [ -n "$pipe_lines" ]; then
        warn "Workflow pipes a download to a shell (legit installer or implant?) — review: $wf"
        printf "%s\n" "$pipe_lines" | head -3 | sed 's/^/         /'
      fi
    fi

    # (d) Generic CI-hygiene smell (NOT a Miasma IOC): github.event.* near run:.
    #     Kept at INFO so it doesn't drown the real findings — interpolating
    #     attacker-controllable event fields into a shell is a known injection
    #     class worth a glance, but legit on commitlint/labeler/Claude workflows.
    if [ "$wf_bad" -eq 0 ] && grep -Eq '\$\{\{[[:space:]]*github\.event\.[^}]*\}\}' "$wf" 2>/dev/null \
       && grep -Eq '^[[:space:]]*run:' "$wf" 2>/dev/null; then
      info "Workflow interpolates github.event.* near run: (review for script injection) — $wf"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f -path '*/.github/workflows/*' \( -name '*.yml' -o -name '*.yaml' \) -print \) 2>/dev/null)

  if [ "$WF_ANY" -eq 0 ]; then
    pass "No GitHub Actions workflow files found under code roots"
  fi
fi

# ============================================================================
# 3. VS Code folder-open tasks (.vscode/tasks.json) — TIGHTENED
# ============================================================================
section "3. VS Code folder-open autorun tasks (runOn:folderOpen)"

# A folderOpen task runs automatically the moment the folder is opened. The
# May-2026 scanner only FAILed on known worm patterns and downgraded everything
# else to INFO — a novel command (node ./setup.js) escaped. Here we WARN on any
# unrecognized folderOpen command (auto-run is inherently high risk) and only
# stay quiet for an explicit benign allowlist.
WORM_CMD_RE='curl[^|&;]+\|[[:space:]]*(ba)?sh|wget[^|&;]+\|[[:space:]]*(ba)?sh|base64[[:space:]]+-d[^|]*\|[[:space:]]*(ba)?sh|eval[[:space:]]+.*curl|setup\.(mjs|js|sh)|\.claude/|\.github/setup|node[[:space:]]+-e|/tmp/[^"[:space:]]*\.(sh|py|mjs)|liuende501|169\.254\.169\.254'
# Benign dev tasks that are commonly auto-run on folder open.
BENIGN_TASK_RE='^(npm|pnpm|yarn|bun)[[:space:]]+(run[[:space:]]+)?(dev|start|watch|build)|uvicorn|flask[[:space:]]+run|rails[[:space:]]+server|make[[:space:]]+(dev|watch)|docker[[:space:]]+compose[[:space:]]+up|tsc[[:space:]]+-w|vite|next[[:space:]]+dev'

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping tasks.json scan"
else
  TASK_ANY=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    grep -lq '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" 2>/dev/null || continue
    TASK_ANY=1
    cmds=$(grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null)
    bad=$(printf "%s\n" "$cmds" | grep -iE "$WORM_CMD_RE" || true)
    if [ -n "$bad" ]; then
      fail "tasks.json runOn:folderOpen with worm-pattern command — $f"
      printf "%s\n" "$bad" | sed 's/^/         /'
      continue
    fi
    # Strip the "command": "..." wrapper to test the bare command against allowlist.
    bare=$(printf "%s\n" "$cmds" | sed -E 's/^"command"[[:space:]]*:[[:space:]]*"//; s/"$//')
    unknown=$(printf "%s\n" "$bare" | grep -vE "$BENIGN_TASK_RE" | grep -v '^[[:space:]]*$' || true)
    if [ -n "$unknown" ]; then
      warn "tasks.json runOn:folderOpen auto-runs an unrecognized command — review: $f"
      printf "%s\n" "$unknown" | sed 's/^/         /'
    else
      info "tasks.json runOn:folderOpen with recognized dev command — $f"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f -path '*/.vscode/tasks.json' -print \) 2>/dev/null)

  if [ "$TASK_ANY" -eq 0 ]; then
    pass "No tasks.json files with runOn:folderOpen found"
  fi
fi

# ============================================================================
# 4. AI-agent hooks — ALL event arrays + Cursor rules (GENERALIZED)
# ============================================================================
section "4. AI-agent hook persistence (.claude/settings.json, Cursor rules)"

# The May scanner audited only the SessionStart block. This generalizes to
# EVERY "command" appearing anywhere in a settings.json, plus type:"http"
# hooks pointing off-box, plus Cursor/agent rule files carrying injection.
SUSPICIOUS_HOOK_PATTERNS=(
  'curl[[:space:]].*\|[[:space:]]*(sh|bash)'
  'wget[[:space:]].*\|[[:space:]]*(sh|bash)'
  'base64[[:space:]]+(-d|--decode)[[:space:]]*\|[[:space:]]*(sh|bash)'
  'eval[[:space:]]+\$\(curl'
  'eval[[:space:]]+\$\(wget'
  'node[[:space:]]+-e'
  'setup\.(mjs|js)'
  '\.github/setup'
  '/tmp/[^[:space:]"]*\.(sh|py|mjs|lock)'
  'liuende501'
  '169\.254\.169\.254'
  'thebeautifulmarchoftime'
)

SETTINGS_FILES=()
for f in "$HOME/.claude/settings.json" "$HOME/.claude/settings.local.json"; do
  [ -f "$f" ] && SETTINGS_FILES+=("$f")
done
if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  for root in "${SEARCH_ROOTS[@]}"; do
    while IFS= read -r f; do
      [ -n "$f" ] && SETTINGS_FILES+=("$f")
    done < <(find "$root" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f \( -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' \) -print \) 2>/dev/null)
  done
fi

if [ ${#SETTINGS_FILES[@]} -eq 0 ]; then
  info "No Claude settings.json files found — skipping hook audit"
else
  info "Auditing ${#SETTINGS_FILES[@]} settings.json file(s) — ALL hook events"
  ANY_SUS=0
  for sf in "${SETTINGS_FILES[@]}"; do
    grep -q '"hooks"' "$sf" 2>/dev/null || continue
    # Every "command": line in the file (across all event arrays).
    cmd_lines=$(grep -nE '"command"[[:space:]]*:' "$sf" 2>/dev/null || true)
    file_sus=0
    for pat in "${SUSPICIOUS_HOOK_PATTERNS[@]}"; do
      M=$(printf "%s\n" "$cmd_lines" | grep -nE "$pat" || true)
      if [ -n "$M" ]; then
        fail "Suspicious hook command in $sf (matches: $pat)"
        printf "%s\n" "$M" | sed 's/^/        /'
        file_sus=1; ANY_SUS=1
      fi
    done
    # type:"http" hook pointing at a non-localhost URL.
    HTTP=$(grep -nE '"type"[[:space:]]*:[[:space:]]*"http"' "$sf" 2>/dev/null || true)
    if [ -n "$HTTP" ]; then
      OFFBOX=$(grep -nE '"url"[[:space:]]*:[[:space:]]*"https?://[^"]*"' "$sf" 2>/dev/null | grep -vE 'localhost|127\.0\.0\.1' || true)
      if [ -n "$OFFBOX" ]; then
        warn "settings.json has an http hook posting off-box — review: $sf"
        printf "%s\n" "$OFFBOX" | sed 's/^/        /'
      fi
    fi
    [ "$file_sus" -eq 0 ] && pass "No worm-pattern hook commands in $sf"
  done
  [ "$ANY_SUS" -eq 0 ] && info "No settings.json hook commands matched known injection patterns"
fi

# Cursor / agent rules files — zero-width Unicode + instruction injection.
section "4b. Cursor / agent rules files (instruction injection)"
RULES_FOUND=0
if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  while IFS= read -r rf; do
    [ -z "$rf" ] && continue
    RULES_FOUND=1
    # Zero-width / bidi / tag chars (high signal — legit rules are plain text).
    # Use perl for Unicode-aware matching (BSD/macOS grep lacks -P); skip if absent.
    if command -v perl >/dev/null 2>&1; then
      if perl -CSD -ne 'BEGIN{$f=0} $f=1 if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}\x{E0000}-\x{E007F}]/; END{exit($f?0:1)}' "$rf" 2>/dev/null; then
        fail "Rules file contains hidden/zero-width Unicode — $rf"
      fi
    fi
    # Role-spoofing / exfil-imperative instructions.
    if grep -Eiq 'ignore (all |the )?previous instructions|you are now|exfiltrat|send .*(secret|token|credential)|run this (command|silently)|disable (safety|security)' "$rf" 2>/dev/null; then
      warn "Rules file contains injection-style imperatives — review: $rf"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f \( -name '.cursorrules' -o -name '.clinerules' -o -path '*/.cursor/rules/*.mdc' \) -print \) 2>/dev/null)
fi
[ "$RULES_FOUND" -eq 0 ] && info "No Cursor/Cline rules files found under code roots"

# ============================================================================
# 5. Compromised June-2026 packages (global + lockfiles)
# ============================================================================
section "5. Compromised packages — June 2026 Miasma wave"

# LeoPlatform/RStreams (acct czirker), ImmobiliareLabs Backstage (acct
# simonecorsi), + extras. We flag presence regardless of version and let the
# user verify against the advisories.
COMPROMISED_PKGS=(
  "leo-auth" "leo-aws" "leo-cache" "leo-cdk-lib" "leo-cli" "leo-config"
  "leo-connector-elasticsearch" "leo-connector-mongo" "leo-connector-mysql"
  "leo-connector-oracle" "leo-connector-redshift" "leo-cron" "leo-logger"
  "leo-sdk" "leo-streams" "rstreams-metrics" "rstreams-shard-util"
  "serverless-convention" "serverless-leo"
  "@immobiliarelabs/backstage-plugin-gitlab"
  "@immobiliarelabs/backstage-plugin-gitlab-backend"
  "@immobiliarelabs/backstage-plugin-ldap-auth"
  "@immobiliarelabs/backstage-plugin-ldap-auth-backend"
  "hexo-deployer-wrangler" "hexo-shoka-swiper" "prism-silq" "solo-nav"
  # Wave J / "M-RED-TEAM" — AsyncAPI (July 14, 2026). IMPORT-TIME execution —
  # presence in a lockfile is lower-signal than for the install-time waves
  # above; a hit here means the package was pulled in, not that it ran.
  "@asyncapi/specs" "@asyncapi/generator" "@asyncapi/generator-components"
  "@asyncapi/generator-helpers"
)

if command -v npm >/dev/null 2>&1; then
  NPM_GLOBAL=$(npm list -g --depth=0 2>/dev/null || true)
  ANY_HIT=0
  for pkg in "${COMPROMISED_PKGS[@]}"; do
    pkg_escaped=$(printf '%s' "$pkg" | sed 's/[.[\*^$()+?{|/]/\\&/g')
    M=$(printf "%s" "$NPM_GLOBAL" | grep -E "(^|[[:space:]])${pkg_escaped}@" || true)
    if [ -n "$M" ]; then
      fail "Globally installed (compromised): $M"
      ANY_HIT=1
    fi
  done
  [ "$ANY_HIT" -eq 0 ] && pass "No globally installed packages match the June compromised list"
else
  info "npm not installed — skipping global package audit"
fi

if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  LOCK_HITS=$(mktemp -t miasma-lock-hits.XXXXXX)
  : > "$LOCK_HITS"
  while IFS= read -r lockfile; do
    [ -z "$lockfile" ] && continue
    for pkg in "${COMPROMISED_PKGS[@]}"; do
      pkg_for_grep=$(printf '%s' "$pkg" | sed 's/[.[\*^$()+?{|/]/\\&/g')
      M=$(grep -nE "\"${pkg_for_grep}\"|(^|[[:space:]])${pkg_for_grep}@" "$lockfile" 2>/dev/null | head -3 || true)
      if [ -n "$M" ]; then
        printf "  FILE: %s\n  PKG: %s\n" "$lockfile" "$pkg" >> "$LOCK_HITS"
        printf "%s\n\n" "$M" | sed 's/^/    /' >> "$LOCK_HITS"
      fi
    done
  done < <(find "${SEARCH_ROOTS[@]}" \( \( -name node_modules -o "${PRUNE_COMMON[@]}" \) -prune \) -o \( -type f \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \) -print \) 2>/dev/null)
  if [ -s "$LOCK_HITS" ]; then
    N=$(grep -c '^  FILE:' "$LOCK_HITS" || echo 0)
    fail "$N lockfile/package combination(s) reference compromised packages"
    cat "$LOCK_HITS"
  else
    pass "No lockfiles reference June compromised packages"
  fi
  rm -f "$LOCK_HITS"
fi

# ============================================================================
# 6. Campaign marker strings (code roots + shell history)
# ============================================================================
section "6. Campaign marker strings"

MARKER_STRINGS=(
  "thebeautifulmarchoftime"
  "Alright Lets See If This Works"
  "firedalazer"
  "RevokeAndItGoesKaboom"
  "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner"
  "Miasma: The Spreading Blight"
  "liuende501"
  "M-RED-TEAM"
  "miasma-train-p1"
  "elzotebo999"
  "miasma-monitor"
)

MARK_HITS=0
# Shell history
for hf in "$HOME/.zsh_history" "$HOME/.bash_history"; do
  [ -f "$hf" ] || continue
  for s in "${MARKER_STRINGS[@]}"; do
    if grep -qF "$s" "$hf" 2>/dev/null; then
      fail "Marker string '$s' in shell history $hf"
      MARK_HITS=1
    fi
  done
done
# Code roots — single recursive pass over all markers (skip heavy dirs).
if [ ${#SEARCH_ROOTS[@]} -gt 0 ]; then
  # Build one alternation regex from the marker list (ERE-safe: markers contain
  # only letters, spaces and a colon).
  MARK_RE=$(printf '%s|' "${MARKER_STRINGS[@]}"); MARK_RE="${MARK_RE%|}"
  HIT=$(grep -rIlE "$MARK_RE" "${SEARCH_ROOTS[@]}" \
        --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.cache \
        --exclude-dir=Library --exclude-dir=target --exclude-dir=dist \
        --exclude-dir=build --exclude-dir=.next --exclude-dir=worktrees 2>/dev/null || true)
  # Exclude this scanner's own repo — its docs/hooks/fixtures contain the marker
  # strings as detection data, not as an infection.
  if [ -n "$SELF_ROOT" ]; then
    HIT=$(printf "%s\n" "$HIT" | grep -v "^${SELF_ROOT}/" || true)
  fi
  HIT=$(printf "%s\n" "$HIT" | grep -v '^[[:space:]]*$' | head -10 || true)
  if [ -n "$HIT" ]; then
    fail "Campaign marker string(s) found in files:"
    printf "%s\n" "$HIT" | sed 's/^/         /'
    MARK_HITS=1
  fi
fi
[ "$MARK_HITS" -eq 0 ] && pass "No campaign marker strings found"

# ============================================================================
# 7. GitHub dead-drop repo audit (requires gh)
# ============================================================================
section "7. GitHub dead-drop repository audit"

DEAD_DROP_PATTERNS=(
  "Alright Lets See If This Works"
  "Miasma"
  "Shai-Hulud"
  "Here We Go Again"
  "M-RED-TEAM"
)

if [ -n "${LSH_NO_NETWORK:-}" ]; then
  info "Network checks disabled (LSH_NO_NETWORK set) — skipping gh dead-drop audit"
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  REPO_JSON=$(gh repo list --limit 200 --json name,description 2>/dev/null || true)
  if [ -z "$REPO_JSON" ]; then
    warn "gh repo list returned no data (rate-limited or no repos?)"
  else
    ANY=0
    for pat in "${DEAD_DROP_PATTERNS[@]}"; do
      M=$(printf "%s" "$REPO_JSON" | grep -i "$pat" || true)
      if [ -n "$M" ]; then
        fail "Dead-drop pattern '$pat' in your GitHub repos:"
        printf "%s\n" "$M" | sed 's/^/      /'
        ANY=1
      fi
    done
    [ "$ANY" -eq 0 ] && pass "No repos match Miasma dead-drop naming patterns"
  fi
else
  info "gh not installed/authenticated — skipping repo audit (run 'gh auth login' to enable)"
fi

# ============================================================================
# Final summary
# ============================================================================
section "Summary"

if [ "$FINDINGS" -eq 0 ]; then
  printf "${GREEN}${BOLD}ALL CLEAR${RESET} — no IOCs detected for the June 2026 Miasma wave on this host.\n"
  printf "\nKeep in mind:\n"
  printf "  - This scan checks KNOWN IOCs only. New variants rotate indicators.\n"
  printf "  - The binding.gyp vector runs at INSTALL time — re-run after any npm install.\n"
  printf "  - --ignore-scripts alone does NOT stop binding.gyp; see docs/supply-chain-defense.md.\n"
  exit 0
else
  printf "${RED}${BOLD}%d FINDING(S) — INVESTIGATE${RESET}\n" "$FINDINGS"
  printf "\nFindings:\n"
  printf "%b" "$FINDING_LOG"
  printf "\n"
  printf "${BOLD}What to do if FAIL:${RESET}\n"
  printf "  1. DO NOT panic-delete. Capture evidence first (copy flagged files to isolated storage).\n"
  printf "  2. Rotate credentials reachable from this machine: GitHub PAT + SSH keys, npm token,\n"
  printf "     any cloud tokens in shell env / .npmrc / credential files.\n"
  printf "  3. For a flagged binding.gyp: do NOT npm install in that tree. Remove the package,\n"
  printf "     clean cache, rebuild lockfile from a clean source.\n"
  printf "  4. For agent-hook / tasks.json / workflow implants: review the file before opening the\n"
  printf "     repo in an AI-enabled editor (folder-open + SessionStart auto-execute).\n"
  printf "  5. Audit GitHub for dead-drop repos (account 'liuende501' style mass repo creation).\n"
  printf "\nDo not run installers on the affected machine until cleaned.\n"
  exit 1
fi
