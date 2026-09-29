'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { BLOCKED_SEEDS, ALLOWED_SEEDS } = require('./fixtures/firewall-corpus.js');

const {
  checkDestructiveRm,
  checkForceGitPush,
  checkExfiltration,
  checkInsecureBinaryDrop,
  runChecks,
} = require('../hooks/bash-firewall.js');

// ---------------------------------------------------------------------------
// H-3: Expanded exfiltration detection
// ---------------------------------------------------------------------------

describe('H-3: checkExfiltration — piped exfiltration', () => {
  it('blocks cat .env piped to curl', () => {
    const reason = checkExfiltration(BLOCKED_SEEDS[0]);
    assert.ok(reason);
    assert.match(reason, /exfiltration/i);
  });

  it('blocks cat id_rsa piped to nc', () => {
    const reason = checkExfiltration(BLOCKED_SEEDS[1]);
    assert.ok(reason);
    assert.match(reason, /exfiltration/i);
  });
});

describe('H-3: checkExfiltration — base64 decode to shell', () => {
  it('blocks base64 -d piped to sh', () => {
    const reason = checkExfiltration(BLOCKED_SEEDS[2]);
    assert.ok(reason);
    assert.match(reason, /base64/i);
  });

  it('blocks base64 -d piped to bash', () => {
    const reason = checkExfiltration(BLOCKED_SEEDS[3]);
    assert.ok(reason);
    assert.match(reason, /base64/i);
  });

  it('allows base64 -d without pipe to shell', () => {
    const reason = checkExfiltration(ALLOWED_SEEDS[0]);
    assert.equal(reason, null);
  });
});

describe('H-3: checkExfiltration — inline scripts referencing sensitive files', () => {
  it('blocks python3 -c referencing .env', () => {
    const reason = checkExfiltration(BLOCKED_SEEDS[4]);
    assert.ok(reason);
    assert.match(reason, /inline script/i);
  });

  it('blocks node -e referencing .env', () => {
    const reason = checkExfiltration(BLOCKED_SEEDS[5]);
    assert.ok(reason);
    assert.match(reason, /inline script/i);
  });

  it('allows python3 -c without sensitive file reference', () => {
    const reason = checkExfiltration(ALLOWED_SEEDS[1]);
    assert.equal(reason, null);
  });
});

describe('H-3: runChecks — piped exfil across pipe boundaries', () => {
  it('catches cat .env | curl even though splitCommands breaks on pipe', () => {
    const reason = runChecks(BLOCKED_SEEDS[6]);
    assert.ok(reason);
    assert.match(reason, /exfiltration/i);
  });
});

// ---------------------------------------------------------------------------
// H-4: Regex-escaped branch names
// ---------------------------------------------------------------------------

describe('H-4: checkForceGitPush — regex metacharacters in branch names', () => {
  it('still blocks force push to main', () => {
    const reason = checkForceGitPush(BLOCKED_SEEDS[7]);
    assert.ok(reason);
    assert.match(reason, /main/);
  });

  it('does not crash on branch name with regex metacharacters', () => {
    // If PROTECTED_BRANCHES contained "feat.test", unescaped "." would match any char.
    // This test ensures the function doesn't throw with crafted input.
    const reason = checkForceGitPush(ALLOWED_SEEDS[2]);
    // Should not match "main" or "master"
    assert.equal(reason, null);
  });
});

// ---------------------------------------------------------------------------
// H-5: Block rm -rf targeting home directory
// ---------------------------------------------------------------------------

describe('H-5: checkDestructiveRm — home directory targets', () => {
  it('blocks rm -rf ~', () => {
    const reason = checkDestructiveRm(BLOCKED_SEEDS[8]);
    assert.ok(reason);
    assert.match(reason, /home directory/i);
  });

  it('blocks rm -rf ~/', () => {
    const reason = checkDestructiveRm(BLOCKED_SEEDS[9]);
    assert.ok(reason);
    assert.match(reason, /home directory/i);
  });

  it('blocks rm -rf $HOME', () => {
    const reason = checkDestructiveRm(BLOCKED_SEEDS[10]);
    assert.ok(reason);
    assert.match(reason, /home directory/i);
  });

  it('blocks rm -rf /home/', () => {
    const reason = checkDestructiveRm(BLOCKED_SEEDS[11]);
    assert.ok(reason);
    assert.match(reason, /user directories/i);
  });

  it('blocks rm -rf /Users/', () => {
    const reason = checkDestructiveRm(BLOCKED_SEEDS[12]);
    assert.ok(reason);
    assert.match(reason, /user directories/i);
  });

  it('still blocks rm -rf /', () => {
    const reason = checkDestructiveRm(BLOCKED_SEEDS[13]);
    assert.ok(reason);
    assert.match(reason, /root filesystem/i);
  });

  it('allows rm -rf on a regular directory', () => {
    const reason = checkDestructiveRm(ALLOWED_SEEDS[3]);
    assert.equal(reason, null);
  });
});

// ---------------------------------------------------------------------------
// G-747: May 2026 postinstall-worm signature — TLS-disabled fetch + /tmp/ drop
// ---------------------------------------------------------------------------

describe('G-747: checkInsecureBinaryDrop — postinstall worm signature', () => {
  it('blocks curl -k writing to /tmp/ (parikhpreyash4 700-repo signature)', () => {
    const reason = checkInsecureBinaryDrop(
      BLOCKED_SEEDS[14]
    );
    assert.ok(reason);
    assert.match(reason, /TLS-verify-disabled|postinstall-worm/i);
  });

  it('blocks curl --insecure writing to /tmp/', () => {
    const reason = checkInsecureBinaryDrop(
      BLOCKED_SEEDS[15]
    );
    assert.ok(reason);
  });

  it('blocks wget --no-check-certificate writing to /tmp/', () => {
    const reason = checkInsecureBinaryDrop(
      BLOCKED_SEEDS[16]
    );
    assert.ok(reason);
  });

  it('blocks curl -k with redirect (> /tmp/)', () => {
    const reason = checkInsecureBinaryDrop(
      BLOCKED_SEEDS[17]
    );
    assert.ok(reason);
  });

  it('allows curl -k against a non-/tmp path (still suspicious but out of scope)', () => {
    // Self-signed dev server pattern — out of scope for this check
    const reason = checkInsecureBinaryDrop(
      ALLOWED_SEEDS[4]
    );
    assert.equal(reason, null);
  });

  it('allows curl with TLS verification writing to /tmp/', () => {
    const reason = checkInsecureBinaryDrop(
      ALLOWED_SEEDS[5]
    );
    assert.equal(reason, null);
  });

  it('runChecks catches the full worm one-liner via subcommand split', () => {
    const cmd = BLOCKED_SEEDS[18];
    const reason = runChecks(cmd);
    assert.ok(reason);
    assert.match(reason, /postinstall-worm|TLS-verify-disabled/i);
  });
});
