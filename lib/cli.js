'use strict';

const path = require('path');
const fs = require('fs');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

const HELP = `
  llm-safe-haven v${pkg.version}
  Harden your AI coding agent in 60 seconds.

  Usage:
    npx llm-safe-haven [command] [options]

  Commands:
    install     Install security hooks and configure your agent (default)
    audit       Check your security posture and maturity level
    scan        Scan for exposed secrets and dangerous patterns
    update      Update hooks to the latest version

  Options:
    --dry-run        Show what would happen without making changes
    --agent          Target a specific agent: claude-code, cursor, windsurf, cline, aider, codex-cli
    --json           Output results as JSON (audit command)
    --supply-chain   Run the supply-chain IOC scan (scan command; macOS/Linux)
    --mcp            Scan MCP server configs across installed agents (scan command)
    --online         Opt in to network calls for provenance checks on scan --mcp
                     (transmits package names to registry.npmjs.org; default off).
    --quiet          Suppress the human-readable scan output (scan command)
    --help           Show this help message
    --version        Show version number

  Examples:
    npx llm-safe-haven                  # Install everything (interactive)
    npx llm-safe-haven --dry-run        # Preview changes
    npx llm-safe-haven audit            # Check your security posture
    npx llm-safe-haven audit --json     # Machine-readable output
    npx llm-safe-haven scan             # Find exposed secrets
    npx llm-safe-haven scan --supply-chain  # Scan for Miasma/Shai-Hulud IOCs
    npx llm-safe-haven scan --mcp --json    # Scan MCP server configs (JSON output)
    npx llm-safe-haven scan --mcp --online  # Opt in to registry provenance checks

  Docs: https://github.com/pleasedodisturb/llm-safe-haven
`;

function parseArgs(argv) {
  const args = {
    command: 'install',
    flags: {},
    unknownFlags: [],
  };

  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === '--help' || arg === '-h') {
      args.flags.help = true;
    } else if (arg === '--version' || arg === '-v') {
      args.flags.version = true;
    } else if (arg === '--dry-run') {
      args.flags.dryRun = true;
    } else if (arg === '--json') {
      args.flags.json = true;
    } else if (arg === '--supply-chain') {
      args.flags.supplyChain = true;
    } else if (arg === '--mcp') {
      args.flags.mcp = true;
    } else if (arg === '--online') {
      args.flags.online = true;
    } else if (arg === '--quiet') {
      // Consumed by lib/scan-mcp.js (suppresses the human-readable
      // report). Must be recognized here — an unrecognized --quiet would
      // trip the WR-01 fail-closed guard and refuse the scan with exit 2.
      args.flags.quiet = true;
    } else if (arg === '--agent') {
      // IN-04: never consume a following FLAG as the --agent value
      // (previously `--agent --json` set agent='--json' AND lost the
      // --json flag), and never silently drop a trailing valueless
      // --agent.
      const value = argv[i + 1];
      if (typeof value === 'string' && value !== '' && !value.startsWith('-')) {
        args.flags.agent = argv[++i];
      } else {
        console.error('Warning: --agent requires a value (e.g. --agent claude-code) — ignored.');
      }
    } else if (arg.startsWith('-')) {
      // WR-05/WR-01: a typo'd security flag (--onlien, --supply-chian, or
      // a typo'd --mcp) must never degrade the scan without any signal — a
      // CI gate would believe the requested scan ran when it never did.
      // Warn on stderr and record it; run() fails the `scan` command
      // closed (exit 2) when unknownFlags is non-empty.
      args.unknownFlags.push(arg);
      console.error(`Warning: unknown option "${arg}" ignored. Run with --help to list supported options.`);
    } else if (arg !== '') {
      positional.push(arg);
    }
  }

  if (positional.length > 0) {
    args.command = positional[0];
  }

  return args;
}

/**
 * Single dispatch-settlement helper for every command case below (Phase 8
 * review F3 — the audit/scan/install cases had drifted three hand-rolled
 * copies of the same then/catch/sync-fallback pattern, and scan's copy
 * was missing the WR-04 stderr diagnostic).
 *
 *   - A thenable result settles asynchronously: r.code (when numeric)
 *     propagates to process.exitCode; an escaped rejection fails CLOSED
 *     to opts.errorExitCode with a one-line-per-frame stderr diagnostic
 *     (err.stack when available — exit N with zero bytes of explanation
 *     is undebuggable for a security gate; someone has to act on a
 *     fail-closed result, which requires knowing what happened). --json
 *     stdout purity is preserved: the diagnostic goes to stderr only.
 *   - A synchronous result propagates SYNCHRONOUSLY — scan's
 *     supply-chain/env paths return plain objects and programmatic
 *     callers of the exported run() read process.exitCode right after it
 *     returns; wrapping sync results in Promise.resolve().then() would
 *     defer the assignment by a microtask tick (a pre-Phase-7 behavior
 *     regression). run() still returns a promise embedders/tests can
 *     await.
 *
 * process.exitCode (never process.exit()) preserves stdout/stderr
 * flushing — Node waits for the pending promise before exiting.
 */
function settleCommand(result, { label, errorExitCode }) {
  if (result && typeof result.then === 'function') {
    return result
      .then((r) => {
        if (r && typeof r.code === 'number') process.exitCode = r.code;
      })
      .catch((err) => {
        console.error(`${label} failed: ${err && err.stack ? err.stack : err}`);
        process.exitCode = errorExitCode;
      });
  }
  if (result && typeof result.code === 'number') process.exitCode = result.code;
  return Promise.resolve();
}

function run(argv) {
  const args = parseArgs(argv);

  if (args.flags.version) {
    console.log(pkg.version);
    process.exit(0);
  }

  if (args.flags.help) {
    console.log(HELP);
    process.exit(0);
  }

  switch (args.command) {
    case 'install': {
      // install() is async as of the Phase 8 CR-01 fix (it awaits the
      // same offline getMcpInputs path audit uses). Exit-code contract:
      // success resolves without touching process.exitCode (implicit 0,
      // as before; install is informational, never a CI gate — see
      // docs/mcp-security.md §6), and a failure — which pre-Phase-8
      // escaped run() as a synchronous throw and crashed bin/ with a
      // non-zero code — fails via settleCommand with a stderr diagnostic
      // and exitCode 1 (still non-zero, no unhandled rejection).
      const { install } = require('./install.js');
      return settleCommand(install(args.flags), { label: 'install', errorExitCode: 1 });
    }
    case 'audit': {
      // audit() is async as of Phase 8 (D-04/D-05), returning { code }
      // rather than exiting the process itself. Audit exit contract (see
      // auditExitCode() in lib/audit.js): 0 = Level 2+, 1 = Level < 2,
      // 2 = the in-process MCP scan did not complete (fail closed — the
      // locked security-gate-exit-codes rule) or an escaped rejection
      // (settleCommand's fail-closed catch, T-08-05/WR-04).
      const { audit } = require('./audit.js');
      return settleCommand(audit(args.flags), { label: 'audit', errorExitCode: 2 });
    }
    case 'scan': {
      // WR-01: fail closed on unrecognized flags for the security-gate
      // command. `scan --mpc` (typo'd --mcp) would otherwise silently run
      // the plain env-secret scan and exit 0, and `scan --onlien` would
      // run offline — a CI gate keying on the exit code would see "clean"
      // even though the requested scan never ran (a security tool must
      // never exit 0 when the scan did not finish: 0=clean, 1=findings,
      // 2=error/incomplete). Scoped to `scan` only so install/audit/update
      // keep their existing warn-and-continue behavior. process.exitCode
      // (not process.exit()) preserves stdout/stderr flushing.
      if (args.unknownFlags.length > 0) {
        console.error(`Refusing to run scan: unknown option(s) ${args.unknownFlags.join(', ')}. Run with --help to list supported options.`);
        process.exitCode = 2;
        break;
      }
      const { scan } = require('./scan.js');
      // Propagate the scan's exit code so CI can gate on it: 0 = clean,
      // 1 = findings, 2 = error/could-not-complete. The normal env-scan
      // path returns undefined, --supply-chain returns a plain object
      // synchronously (settleCommand propagates sync results
      // synchronously — main-parity), and --mcp (async since Phase 7)
      // returns a Promise. IN-01: scanMcp() is written to never reject,
      // but the exit-code contract must not depend on that invariant
      // holding forever — an escaped rejection fails closed to 2 (with a
      // stderr diagnostic as of the F3 dedupe — previously scan's copy
      // of this pattern was silently missing the WR-04 explanation).
      return settleCommand(scan(args.flags), { label: 'scan', errorExitCode: 2 });
    }
    case 'update': {
      const { update } = require('./update.js');
      update(args.flags);
      break;
    }
    default:
      console.error(`Unknown command: ${args.command}`);
      console.log(HELP);
      process.exit(1);
  }
}

module.exports = { run, parseArgs };
