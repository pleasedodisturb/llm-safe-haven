#!/usr/bin/env bash
# ============================================================================
# Shai-Hulud npm worm IOC scanner — May 2026 waves
# ============================================================================
#
# What this does:
#   Read-only scan of a macOS machine for indicators of compromise from the
#   May 11 + May 19, 2026 Shai-Hulud npm worm waves (AntV / ECharts / TanStack
#   Router pivot, kitty-monitor C2 persistence, m-kosche.com beacons).
#
# What this does NOT do:
#   - No file deletions, no quarantine, no network calls, no curl|sh
#   - No modifications to your shell, npm, or system config
#   - Safe to run multiple times
#
# Requirements:
#   - macOS (some checks also work on Linux but are macOS-targeted)
#   - bash, grep, find, awk (standard)
#   - Optional: node/npm (for global package list), gh (for repo audit)
#
# Usage:
#   chmod +x scan-shai-hulud-may2026.sh
#   ./scan-shai-hulud-may2026.sh
#
# Exit code: 0 if ALL CLEAR, 1 if any FINDINGS.
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

# ============================================================================
# Header
# ============================================================================
printf "${BOLD}Shai-Hulud npm worm IOC scanner — May 2026 waves${RESET}\n"
printf "Host: %s\n" "$(hostname)"
printf "User: %s\n" "$(whoami)"
printf "Date: %s\n" "$(date)"
printf "Home: %s\n" "$HOME"

# ============================================================================
# 1. Filesystem persistence artifacts
# ============================================================================
section "1. Filesystem persistence artifacts"

check_file_absent() {
  local path="$1"
  local desc="$2"
  if [ -e "$path" ]; then
    fail "$desc EXISTS: $path"
  else
    pass "$desc absent: $path"
  fi
}

check_file_absent "$HOME/.local/share/kitty/cat.py" "kitty C2 daemon (cat.py)"
check_file_absent "$HOME/.local/bin/gh-token-monitor.sh" "gh-token-monitor.sh"
check_file_absent "$HOME/Library/LaunchAgents/com.user.kitty-monitor.plist" "macOS LaunchAgent (kitty-monitor)"
check_file_absent "$HOME/.config/systemd/user/kitty-monitor.service" "Linux systemd unit (kitty-monitor)"
check_file_absent "/tmp/tmp.987654321.lock" "older Shai-Hulud lock file"

# Also scan all LaunchAgents for anything kitty-related, in case the name varies
LA_DIR="$HOME/Library/LaunchAgents"
if [ -d "$LA_DIR" ]; then
  KITTY_LA=$(grep -lir "kitty" "$LA_DIR" 2>/dev/null || true)
  if [ -n "$KITTY_LA" ]; then
    while IFS= read -r f; do
      fail "LaunchAgent references 'kitty': $f"
    done <<< "$KITTY_LA"
  else
    pass "No LaunchAgents reference 'kitty'"
  fi
else
  info "No LaunchAgents directory (~/Library/LaunchAgents) — skipping"
fi

# Miasma Wave D (June 1, 2026) IOC: Bun binary in /tmp/b-*/
# Payload downloads Bun runtime to a random temp dir matching /tmp/b-<random>/bun
MIASMA_BUN=$(find /tmp -maxdepth 2 -name "bun" -path "*/b-*" -type f 2>/dev/null || true)
if [ -n "$MIASMA_BUN" ]; then
  while IFS= read -r f; do
    fail "Miasma Wave D IOC: Bun binary found at $f (Wave D / RHSB-2026-006 — payload may have crashed)"
  done <<< "$MIASMA_BUN"
else
  pass "No Miasma Wave D Bun binary found in /tmp/b-*/"
fi

# Miasma Wave D IOC: JS payload file in /tmp/p*.js
# Payload writes a JS file matching /tmp/p<base36>.js; removed on success, persists on crash
MIASMA_JS=$(find /tmp -maxdepth 1 -name "p*.js" -type f 2>/dev/null || true)
if [ -n "$MIASMA_JS" ]; then
  while IFS= read -r f; do
    fail "Miasma Wave D IOC: Possible payload JS at $f (p<base36>.js pattern — Wave D / RHSB-2026-006)"
  done <<< "$MIASMA_JS"
else
  pass "No Miasma Wave D payload JS file found in /tmp/p*.js"
fi

# ============================================================================
# 2. VSCode autorun task IOC (.vscode/tasks.json with runOn: folderOpen)
# ============================================================================
section "2. VSCode autorun task IOC (runOn: folderOpen)"

SEARCH_ROOTS=()
for d in "$HOME/Projects" "$HOME/Code" "$HOME/Documents" "$HOME/src" "$HOME/Work"; do
  if [ -d "$d" ]; then
    SEARCH_ROOTS+=("$d")
  fi
done

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No common code directories found — skipping VSCode tasks.json scan"
else
  info "Scanning: ${SEARCH_ROOTS[*]}"

  # Worm command patterns. A folderOpen task is only a FAIL if its command
  # matches one of these — legitimate dev-server tasks (uvicorn, npm run dev,
  # etc.) are not worm IOCs even though they use runOn:folderOpen.
  WORM_CMD_RE='curl[^|&;]+\|[[:space:]]*(ba)?sh|wget[^|&;]+\|[[:space:]]*(ba)?sh|base64[[:space:]]+-d[^|]*\|[[:space:]]*(ba)?sh|eval[[:space:]]+.*curl|m-kosche|kitty-monitor|gh-token-monitor|/tmp/[^"[:space:]]*\.(sh|py|lock)|\.local/share/kitty|LaunchAgents/.+\.plist'

  FOLDEROPEN_FILES=""
  while IFS= read -r f; do
    if [ -n "$f" ] && grep -l '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" >/dev/null 2>&1; then
      FOLDEROPEN_FILES="${FOLDEROPEN_FILES}${f}\n"
    fi
  done < <(find "${SEARCH_ROOTS[@]}" -type f -path '*/.vscode/tasks.json' 2>/dev/null)

  if [ -z "$FOLDEROPEN_FILES" ]; then
    pass "No tasks.json files with runOn:folderOpen found"
  else
    # Triage each file: FAIL if any command matches worm patterns, else INFO.
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      # Extract every "command": "..." value from the file
      bad_cmds=$(grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null \
                  | grep -iE "$WORM_CMD_RE" || true)
      if [ -n "$bad_cmds" ]; then
        fail "tasks.json runOn:folderOpen with worm-pattern command — $f"
        printf "       Matched commands:\n"
        printf "%s\n" "$bad_cmds" | sed 's/^/         /'
        FINDING_LOG="${FINDING_LOG}  - VSCode tasks.json worm-pattern folderOpen: $f\n"
      else
        # folderOpen present but commands look like normal dev tasks
        info "tasks.json has runOn:folderOpen but commands look legitimate — $f"
        printf "       Commands (review manually if unfamiliar):\n"
        grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" 2>/dev/null \
          | sed 's/^/         /'
      fi
    done < <(printf "%b" "$FOLDEROPEN_FILES")
  fi
fi

# ============================================================================
# 3. Claude settings.json SessionStart hooks audit
# ============================================================================
section "3. Claude settings.json SessionStart hooks"

# We extract just the SessionStart block from each settings.json (no jq needed —
# we use awk to walk braces) and flag commands matching known-bad worm patterns.
# Whitelisting is brittle (legit hooks include osascript, npx, uvx, custom paths),
# so we look for known-bad shapes instead: curl|sh, base64|sh, eval $(curl ...),
# beacon domain, /tmp/*.lock execution, etc.

SUSPICIOUS_HOOK_PATTERNS=(
  'curl[[:space:]].*\|[[:space:]]*(sh|bash)'
  'wget[[:space:]].*\|[[:space:]]*(sh|bash)'
  'base64[[:space:]]+(-d|--decode)[[:space:]]*\|[[:space:]]*(sh|bash)'
  'eval[[:space:]]+\$\(curl'
  'eval[[:space:]]+\$\(wget'
  'eval[[:space:]]+["\x27]?\$\(echo'
  'm-kosche'
  'kitty-monitor'
  'gh-token-monitor'
  '/tmp/[^[:space:]"]*\.(sh|py|lock)'
  '\.local/share/kitty/cat\.py'
)

SETTINGS_FILES=()
for f in "$HOME/.claude/settings.json" "$HOME/.claude/settings.local.json"; do
  [ -f "$f" ] && SETTINGS_FILES+=("$f")
done
for root in "${SEARCH_ROOTS[@]}"; do
  while IFS= read -r f; do
    [ -n "$f" ] && SETTINGS_FILES+=("$f")
  done < <(find "$root" -type f \( -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' \) 2>/dev/null)
done

# extract_session_start_block: prints just the SessionStart array from a JSON
# settings file, using brace/bracket counting (no jq dependency).
extract_session_start_block() {
  local file="$1"
  awk '
    BEGIN { in_block = 0; depth = 0 }
    {
      if (!in_block) {
        # Look for the key "SessionStart" followed (eventually) by [
        if (match($0, /"SessionStart"[[:space:]]*:/)) {
          in_block = 1
          # Track brackets from this line onward
          line = substr($0, RSTART)
        } else {
          next
        }
      } else {
        line = $0
      }
      if (in_block) {
        # Count [ and ] to find the end of the SessionStart array
        n = length(line)
        for (i = 1; i <= n; i++) {
          c = substr(line, i, 1)
          if (c == "[") depth++
          else if (c == "]") {
            depth--
            if (depth == 0 && started) { in_block = 0 }
          }
          if (depth > 0) started = 1
        }
        print line
        if (!in_block) exit
      }
    }
  ' "$file"
}

if [ ${#SETTINGS_FILES[@]} -eq 0 ]; then
  info "No Claude settings.json files found — skipping SessionStart audit"
else
  info "Found ${#SETTINGS_FILES[@]} settings.json file(s)"
  ANY_SUSPICIOUS=0
  ANY_HAD_SESSION_START=0
  for sf in "${SETTINGS_FILES[@]}"; do
    if ! grep -q '"SessionStart"' "$sf" 2>/dev/null; then
      continue
    fi
    ANY_HAD_SESSION_START=1
    BLOCK=$(extract_session_start_block "$sf")
    if [ -z "$BLOCK" ]; then
      continue
    fi
    info "SessionStart hook commands in: $sf"
    # Print each "command" entry in the block for transparency
    printf "%s\n" "$BLOCK" | grep -nE '"command"[[:space:]]*:' | sed -E 's/^/      /' || true
    # Flag suspicious patterns within the block
    FILE_SUS=0
    for pat in "${SUSPICIOUS_HOOK_PATTERNS[@]}"; do
      M=$(printf "%s" "$BLOCK" | grep -nE "$pat" || true)
      if [ -n "$M" ]; then
        fail "Suspicious SessionStart pattern in $sf (matches: $pat)"
        printf "%s\n" "$M" | sed 's/^/        /'
        FILE_SUS=1
        ANY_SUSPICIOUS=1
      fi
    done
    if [ "$FILE_SUS" -eq 0 ]; then
      pass "No worm-pattern matches in SessionStart block of $sf"
    fi
  done
  if [ "$ANY_HAD_SESSION_START" -eq 0 ]; then
    pass "No settings.json contains a SessionStart block"
  elif [ "$ANY_SUSPICIOUS" -eq 0 ]; then
    pass "No SessionStart hooks match known worm injection patterns"
  fi
  printf "    ${BOLD}Note:${RESET} review the printed command list manually — anything that pipes\n"
  printf "    network output to a shell, decodes base64 at runtime, or references unknown\n"
  printf "    /tmp paths is suspicious even if it didn't match a pattern above.\n"
fi

# ============================================================================
# 4. Shell rc injection
# ============================================================================
section "4. Shell rc injection"

RC_FILES=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zprofile" "$HOME/.zshenv")

# Patterns: base64 -d | sh/bash, curl ... | sh/bash, eval ... curl, kitty.*monitor, m-kosche
RC_BAD_PATTERNS=(
  'base64[[:space:]]+-d[[:space:]]*\|[[:space:]]*(sh|bash)'
  'base64[[:space:]]+--decode[[:space:]]*\|[[:space:]]*(sh|bash)'
  'curl[[:space:]].*\|[[:space:]]*(sh|bash)'
  'wget[[:space:]].*\|[[:space:]]*(sh|bash)'
  'eval[[:space:]].*curl'
  'eval[[:space:]].*wget'
  'eval[[:space:]].*base64'
  'kitty.*monitor'
  'm-kosche'
)

for rc in "${RC_FILES[@]}"; do
  if [ ! -f "$rc" ]; then
    continue
  fi
  HITS=""
  for pat in "${RC_BAD_PATTERNS[@]}"; do
    M=$(grep -nE "$pat" "$rc" 2>/dev/null || true)
    if [ -n "$M" ]; then
      HITS="${HITS}\n  pattern: ${pat}\n${M}\n"
    fi
  done
  # Heredoc tags with random 8+ char identifiers (a common obfuscation): looks like <<XYZ12345
  # We grep for <<[A-Za-z0-9_]{8,}
  HEREDOC=$(grep -nE '<<[A-Za-z0-9_]{8,}' "$rc" 2>/dev/null || true)
  if [ -n "$HEREDOC" ]; then
    HITS="${HITS}\n  pattern: random-tag heredoc\n${HEREDOC}\n"
  fi

  if [ -n "$HITS" ]; then
    fail "Suspicious patterns in $rc"
    printf "%b" "$HITS" | sed 's/^/      /'
  else
    pass "$rc clean"
  fi
done

# ============================================================================
# 5. Shell history for m-kosche / kitty-monitor references
# ============================================================================
section "5. Shell history beacon-domain references"

HIST_FILES=("$HOME/.zsh_history" "$HOME/.bash_history")
HIST_PATTERNS=('m-kosche' 'kitty-monitor' 'gh-token-monitor' 'sportsontheweb')

for hf in "${HIST_FILES[@]}"; do
  if [ ! -f "$hf" ]; then
    continue
  fi
  HITS=""
  for pat in "${HIST_PATTERNS[@]}"; do
    M=$(grep -n "$pat" "$hf" 2>/dev/null || true)
    if [ -n "$M" ]; then
      HITS="${HITS}\n  pattern: ${pat}\n${M}\n"
    fi
  done
  if [ -n "$HITS" ]; then
    fail "Beacon strings in $hf"
    printf "%b" "$HITS" | sed 's/^/      /'
  else
    pass "$hf clean"
  fi
done

# ============================================================================
# 6. Global npm package audit (May 11 + May 19 wave)
# ============================================================================
section "6. Global npm packages (May 2026 worm waves)"

# Compromised package names from May 11 (TanStack pivot) and May 19 (AntV wave).
# Pinned bad versions noted but we flag presence regardless and let the user
# verify version.
COMPROMISED_PKGS=(
  "@antv/g2"
  "@antv/g6"
  "@antv/g"
  "echarts-for-react"
  "size-sensor"
  "timeago.js"
  "@tanstack/react-router"
  "@tanstack/router-core"
  "@tanstack/router-cli"
  # vpmdhaj typosquatted packages (May 28, 2026) — exfil: aab.sportsontheweb[.]net
  "opensearch-security-scanner"
  "opensearch-setup"
  "opensearch-setup-tool"
  "opensearch-client-helper"
  "opensearch-node-client"
  "elasticsearch-helper"
  "elasticsearch-node-client"
  "@vpmdhaj/elastic-helper"
  "@vpmdhaj/devops-tools"
  "@vpmdhaj/cloud-config"
  "env-config-manager"
  "aws-env-loader"
  "vault-secret-loader"
  "ci-env-helper"
  # @redhat-cloud-services packages (Wave D / Miasma, June 1, 2026)
  # Two names confirmed from public sources; see RHSB-2026-006 for the full list of 32 packages
  "@redhat-cloud-services/frontend-components"
  "@redhat-cloud-services/chrome"
  # Wave E / Phantom Gyp (June 3, 2026) — binding.gyp hijack; --ignore-scripts does NOT protect
  "vapi"
  "ai-sdk-ollama"
  # Wave F / Hades (June 8, 2026) — PyPI ONLY; not scannable via npm
  # This script cannot check PyPI packages. Run separately:
  #   pip list | grep -E "ensmallen|embiggen|gpsea|pyphetools|mflux-streamlit|nhmpy|ppkt2synergy"
  # Any match on a version published June 8, 2026 = treat host as compromised.
  # Note: import-time execution (payload in __init__.py) — if you ran `import ensmallen`
  # (or any affected package) after June 8, rotate credentials regardless of pip audit results.
  # AI-powered scanners may return false-clean: the payload includes AI Analyst Misdirection.
  # Wave G / Hades MCP-targeting (June 9, 2026) — PyPI ONLY; not scannable via npm
  # Targets MCP developers and AI tooling consumers. Run separately:
  #   pip list | grep -E "rsquests|tlask|rlask|langchain-core-mcp"
  # Any match = treat host as compromised. Also check for orphaned .pth loader:
  #   find $(python3 -c "import site; print(' '.join(site.getsitepackages()))") \
  #     -name "*.pth" -exec grep -l "_index.js" {} \;
  # The langchain-core-mcp split-loader deposits a .pth file in site-packages that persists
  # after pip uninstall and re-executes on every Python process start. Delete it if found.
  # Atomic Arch AUR attack (June 11-12, 2026) — INDEPENDENT actor (not TeamPCP/UNC6780)
  # Attack vector: orphaned AUR PKGBUILDs modified to install malicious npm/bun packages.
  # Malicious npm packages used as intermediaries: atomic-lockfile (Sonatype-2026-003775, CVSS 8.7), js-digest.
  # If you run Arch Linux or a derivative, also run: https://github.com/lenucksi/aur-malware-check
  "atomic-lockfile"
  "js-digest"
  # Wave H / Miasma — Leo Platform / RStreams (June 24, 2026); compromised maintainers "czirker" + "llxlr"
  # 20+ LeoPlatform/RStreams pkgs (SDK/CLI/AWS/cron/logging/connector/serverless) trojanized in a ~6s window.
  # binding.gyp install-time execution (--ignore-scripts does NOT protect) + Bun-staged /tmp/p.js (checked in section 1 above).
  # Exact LeoPlatform/RStreams versions vary — run `npm ls` against your LeoPlatform deps and treat any
  # version published June 24, 2026 onward as compromised. The Verana Blockchain Go project also staged
  # payloads in a .claude/setup.mjs invoked by a .vscode/tasks.json folderOpen task.
  # Individually confirmed names:
  "hexo-deployer-wrangler"
  "hexo-shoka-swiper"
  "prism-silq"
  # Wave I / Miasma — @immobiliarelabs Backstage Plugins (June 26, 2026); codfish/semantic-release-action tag-hijacking
  # 4 @immobiliarelabs/backstage-plugin-* packages backdoored via compromised CI action; ~600K monthly downloads.
  # binding.gyp install-time execution (--ignore-scripts does NOT protect) + Bun-staged AES-128-GCM payload.
  # Plants SessionStart hook in .claude/settings.json and folderOpen task in .vscode/tasks.json for AI agent persistence.
  # Check both install artifacts and AI coding assistant config files if these packages are or were installed.
  "@immobiliarelabs/backstage-plugin-aws-apps"
  "@immobiliarelabs/backstage-plugin-aws-apps-backend"
  "@immobiliarelabs/backstage-plugin-gitlab"
  "@immobiliarelabs/backstage-plugin-gitlab-backend"
)

if command -v npm >/dev/null 2>&1; then
  NPM_GLOBAL=$(npm list -g --depth=0 2>/dev/null || true)
  ANY_HIT=0
  for pkg in "${COMPROMISED_PKGS[@]}"; do
    # Escape regex specials in package name
    pkg_escaped=$(printf '%s' "$pkg" | sed 's/[.[\*^$()+?{|]/\\&/g')
    M=$(printf "%s" "$NPM_GLOBAL" | grep -E "(^|[[:space:]])${pkg_escaped}@" || true)
    if [ -n "$M" ]; then
      fail "Globally installed: $M"
      ANY_HIT=1
    fi
  done
  if [ "$ANY_HIT" -eq 0 ]; then
    pass "No globally installed packages match the compromised list"
  fi

  # npm config ignore-scripts (defense)
  IGNORE_SCRIPTS=$(npm config get ignore-scripts 2>/dev/null || echo "unknown")
  if [ "$IGNORE_SCRIPTS" = "true" ]; then
    pass "npm config ignore-scripts = true (postinstall scripts disabled — good)"
  else
    warn "npm config ignore-scripts = $IGNORE_SCRIPTS (not a finding, but consider setting to true)"
  fi
else
  info "npm not installed — skipping global package audit"
fi

# ============================================================================
# 7. Local project lockfiles (package-lock.json / yarn.lock)
# ============================================================================
section "7. Local lockfiles under code roots"

if [ ${#SEARCH_ROOTS[@]} -eq 0 ]; then
  info "No code roots — skipping lockfile scan"
else
  LOCK_HITS_FILE=$(mktemp -t shai-lock-hits.XXXXXX)
  : > "$LOCK_HITS_FILE"

  # Find all lockfiles, skip node_modules
  while IFS= read -r lockfile; do
    [ -z "$lockfile" ] && continue
    for pkg in "${COMPROMISED_PKGS[@]}"; do
      # Match "package-name" within the lockfile (quoted form catches both
      # package-lock.json and yarn.lock conventions)
      pkg_for_grep=$(printf '%s' "$pkg" | sed 's/[.[\*^$()+?{|/]/\\&/g')
      MATCHES=$(grep -nE "\"${pkg_for_grep}\"" "$lockfile" 2>/dev/null | head -5 || true)
      # Yarn lockfile uses different syntax (pkg@version: at start of line)
      MATCHES2=$(grep -nE "(^|[[:space:]])${pkg_for_grep}@" "$lockfile" 2>/dev/null | head -5 || true)
      if [ -n "$MATCHES" ] || [ -n "$MATCHES2" ]; then
        printf "  FILE: %s\n  PKG: %s\n" "$lockfile" "$pkg" >> "$LOCK_HITS_FILE"
        [ -n "$MATCHES" ] && printf "%s\n" "$MATCHES" | sed 's/^/    /' >> "$LOCK_HITS_FILE"
        [ -n "$MATCHES2" ] && printf "%s\n" "$MATCHES2" | sed 's/^/    /' >> "$LOCK_HITS_FILE"
        printf "\n" >> "$LOCK_HITS_FILE"
      fi
    done
  done < <(find "${SEARCH_ROOTS[@]}" \( -name node_modules -prune \) -o \( -type f \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \) -print \) 2>/dev/null)

  if [ -s "$LOCK_HITS_FILE" ]; then
    HIT_LINES=$(grep -c '^  FILE:' "$LOCK_HITS_FILE" || echo 0)
    fail "$HIT_LINES lockfile/package combination(s) reference compromised packages"
    cat "$LOCK_HITS_FILE"
  else
    pass "No lockfiles reference compromised packages"
  fi
  rm -f "$LOCK_HITS_FILE"
fi

# ============================================================================
# 8. GitHub dead-drop repo audit (requires gh)
# ============================================================================
section "8. GitHub dead-drop repository audit"

DEAD_DROP_PATTERNS=(
  "Shai-Hulud"
  "Here We Go Again"
  "Miasma"
  "Spreading Blight"
  "sandworm"
  "sardaukar"
  "ornithopter"
  "fremen"
  "harkonnen"
)

if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then
    REPO_JSON=$(gh repo list --limit 200 --json name,description 2>/dev/null || true)
    if [ -z "$REPO_JSON" ]; then
      warn "gh repo list returned no data (rate-limited or no repos?)"
    else
      ANY_DEAD_DROP=0
      for pat in "${DEAD_DROP_PATTERNS[@]}"; do
        M=$(printf "%s" "$REPO_JSON" | grep -i "$pat" || true)
        if [ -n "$M" ]; then
          fail "Dead-drop pattern '$pat' found in your GitHub repos:"
          printf "%s\n" "$M" | sed 's/^/      /'
          ANY_DEAD_DROP=1
        fi
      done
      if [ "$ANY_DEAD_DROP" -eq 0 ]; then
        pass "No repos match Shai-Hulud dead-drop naming patterns"
      fi
    fi
  else
    info "gh is installed but not authenticated — skipping repo audit (run 'gh auth login' to enable)"
  fi
else
  info "gh CLI not installed — skipping repo audit"
fi

# ============================================================================
# Final summary
# ============================================================================
section "Summary"

if [ "$FINDINGS" -eq 0 ]; then
  printf "${GREEN}${BOLD}ALL CLEAR${RESET} — no IOCs detected for the May 2026 Shai-Hulud waves on this host.\n"
  printf "\nKeep in mind:\n"
  printf "  - This scan checks KNOWN IOCs only. New worm variants may use different artifacts.\n"
  printf "  - Re-run after any major npm install activity or every few weeks during active waves.\n"
  exit 0
else
  printf "${RED}${BOLD}%d FINDING(S) — INVESTIGATE${RESET}\n" "$FINDINGS"
  printf "\nFindings:\n"
  printf "%b" "$FINDING_LOG"
  printf "\n"
  printf "${BOLD}What to do if FAIL:${RESET}\n"
  printf "  1. DO NOT panic-delete. Capture evidence first:\n"
  printf "       - Copy any flagged file to a USB stick or other isolated location.\n"
  printf "       - Save this scan's output:  ./scan-shai-hulud-may2026.sh | tee shai-scan.log\n"
  printf "  2. Rotate credentials from the affected machine immediately:\n"
  printf "       - GitHub PAT + SSH keys (https://github.com/settings/tokens, .../keys)\n"
  printf "       - npm token (npm token list ; npm token revoke <id>)\n"
  printf "       - Any cloud provider tokens used in shell env or .npmrc / .env files\n"
  printf "  3. For each compromised package found in a lockfile:\n"
  printf "       - Pin or remove the package; rebuild the lockfile with a clean cache.\n"
  printf "       - npm cache clean --force ; rm -rf node_modules package-lock.json ; npm install\n"
  printf "  4. For LaunchAgent / file persistence artifacts:\n"
  printf "       - launchctl unload <plist>  then move (not rm) the plist to a quarantine dir.\n"
  printf "  5. Audit GitHub for dead-drop repos created in your account (private + public).\n"
  printf "  6. Reach out: %s  (this is Vitalik's contact — use a clean device)\n" "claude.rancidity392@passmail.com"
  printf "\nDo not run 'npm install' or any installer on the affected machine until cleaned.\n"
  exit 1
fi
