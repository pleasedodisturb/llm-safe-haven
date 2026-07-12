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
                     Accepted now; the live registry check activates in the next release.
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
    npx llm-safe-haven scan --mcp --online  # Opt in to registry provenance checks (live check lands next release)

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
      // WR-05: a typo'd security flag (--onlien, --supply-chian) must
      // never degrade the scan without any signal — a CI gate would
      // believe the requested scan ran when it never did. Warn loudly
      // on stderr and record it; strict rejection (exit 2) is a
      // candidate behavior change for the Phase 7/release CLI wiring.
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
      const { scan } = require('./scan.js');
      const result = scan(args.flags);
      // Propagate the supply-chain scanner's exit code so CI can gate on it:
      // 0 = clean, 1 = findings, 2 = error/could-not-complete. The normal
      // env-scan path returns undefined, so the typeof guard leaves exit 0.
      if (result && typeof result.code === 'number') process.exitCode = result.code;
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
