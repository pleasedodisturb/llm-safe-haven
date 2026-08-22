# Exit Codes and Scan Scope

The contract every scanning command honours, and the two places it changed in ways a CI pipeline
notices. This is the long form of the [README's Exit codes section](../README.md#exit-codes).

## The three-valued contract

| Code | Meaning |
|------|---------|
| `0` | Clean — the scan completed and found nothing |
| `1` | Findings — something was observed that you need to act on. For `audit`, also a completed posture below Level 2 (including the no-agents case) |
| `2` | The scan did not finish — treat as unknown, never as clean |

**An incomplete scan is never reported as clean.** A finding takes precedence over incompleteness:
if a `.env` was actually observed, that is exit `1` even when other paths could not be read, because
what was seen is a fact regardless of what was missed. Exit precedence is derived in exactly one
place (`computeExit()` in `lib/traverse/index.js`); `audit` and `scan` both route through it.

`install` has no exit code of its own — it exits `0` regardless of what the embedded scan found. Its
rendered scorecard is its verdict. Script against `scan` or `audit` if you need a status code.

A complete CI step that pins the scan root and handles all three outcomes (treat anything else as a
failure too — an unknown code means the tool did not run as documented):

```bash
#!/usr/bin/env bash
# Scan the checked-out repository only, and fail closed on anything but a clean, complete scan.
LSH_ROOTS="$PWD" npx llm-safe-haven scan
status=$?
case "$status" in
  0) echo "scan clean" ;;
  1) echo "exposed secrets found -- see output above" >&2; exit 1 ;;
  2) echo "scan did not finish -- not clean, investigate the '◆ could not verify' block" >&2; exit 2 ;;
  *) echo "unexpected exit code $status" >&2; exit 1 ;;
esac
```

## Behaviour change (v0.7): `scan` exits `1` on findings

`scan` previously exited `0` even when it found tracked `.env` files, while printing them as a red
`✗`. It now exits `1`, as the table says it should. Any pipeline treating `scan`'s `0` as "the command
ran OK" rather than "nothing was found" will start failing — correctly. Use `--json` (on `audit`) or
check for `1` explicitly if you need to distinguish "found something" from "could not run".

## Zero default scan roots

`scan`, `audit`, `install`, and `scan --supply-chain` all resolve their scan scope from the same six
default directory names under `$HOME` (`Projects`, `Developer`, `Code`, `src`, `repos`, `workspace`),
or from `LSH_ROOTS` if you set it. A machine where **none** of the six exist used to report a silent
all-clear — the scan examined zero bytes and still printed a green check.

Now, when zero default roots resolve:

- if the current directory looks like a project (it contains a `.git` entry or a `package.json`),
  that directory becomes the sole scan root. Exactly one line is printed to stderr noting the
  fallback, and the exit code follows findings as usual.
- otherwise, the run is reported incomplete: `scan`, `audit` and `scan --supply-chain` exit `2` —
  never a silent `0`. `install` prints the same `◆ could not verify` block but, as always, exits `0`.

A machine with one or more of the six default roots present is unaffected: no new stderr line, no
exit-code change, byte-identical output to before this change.

**Behaviour change (v0.7) — containers and CI runners.** A runner whose code lives outside
`~/{Projects,Developer,Code,src,repos,workspace}` and whose working directory is not itself a project
(no `.git`, no `package.json`) now exits `2` from `scan`, `audit` and `scan --supply-chain` where it
previously exited `0`. This is intentional: `0` means "the scan ran and found nothing" — it never
meant "the scan ran nowhere." Either set `LSH_ROOTS` to the directory you want scanned, or run the
command from that directory.

## Machine-readable posture: `audit --json`

**Gate CI on `audit`'s exit status, not on the JSON alone.** `audit`'s exit code follows the same
contract: `0` for Level 2 ("Guarded") or higher with both scans complete, `1` below Level 2 —
including when a `.env` was observed during an otherwise incomplete scan — and `2` when a scan did
not finish and nothing was found.

The JSON envelope is for the *why*: `overallLevel` is the posture, and `levelCaps` names what held
it down — an unfinished `.env` scan records `env-incomplete`, an unfinished MCP scan
`mcp-incomplete`, and either caps `overallLevel` at 2. That ceiling is the **same value** as the
Level-2 pass threshold, so a consumer that only checks `overallLevel >= 2` and ignores the process
exit status would pass an unfinished scan. If you must gate on JSON, check `levelCaps` for an
`*-incomplete` entry (or `envIncomplete` / `mcp.ran`) *before* applying the level threshold. The
product-side fix for this trap — a cap that cannot equal the threshold, or an explicit `complete`
field — is tracked as G-1679.
