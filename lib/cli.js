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

  Docs: https://github.com/pleasedodisturb/llm-safe-haven
`;

function parseArgs(argv) {
  const args = {
    command: 'install',
    flags: {},
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
    } else if (arg === '--agent' && argv[i + 1]) {
      args.flags.agent = argv[++i];
    } else if (!arg.startsWith('-') && arg !== '') {
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
