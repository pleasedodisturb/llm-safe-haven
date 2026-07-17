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
      const { install } = require('./install.js');
      install(args.flags);
      break;
    }
    case 'audit': {
      const { audit } = require('./audit.js');
      audit(args.flags);
      break;
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
      const result = scan(args.flags);
      // Propagate the scan's exit code so CI can gate on it: 0 = clean,
      // 1 = findings, 2 = error/could-not-complete. The normal env-scan
      // path returns undefined, --supply-chain returns a plain object
      // synchronously, and --mcp (async since Phase 7) returns a Promise.
      // Promise.resolve() normalizes all three uniformly. Assignment to
      // process.exitCode (never process.exit()) preserves stdout/stderr
      // flushing — Node waits for the pending promise before exiting.
      // IN-01: scanMcp() is written to never reject, but the exit-code
      // contract must not depend on that invariant holding forever — an
      // escaped rejection would otherwise leave exitCode 0 (a silent
      // false-clean) plus an unhandled-rejection warning. Fail closed.
      Promise.resolve(result)
        .then(r => {
          if (r && typeof r.code === 'number') process.exitCode = r.code;
        })
        .catch(() => { process.exitCode = 2; });
      break;
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
