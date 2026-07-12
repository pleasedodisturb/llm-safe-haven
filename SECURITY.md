# Security Policy

`llm-safe-haven` is a security tool, so the integrity of the package and its release
pipeline is treated as safety-critical. This document describes how to report a
vulnerability and what to expect in return.

## Supported versions

The project is pre-1.0 and evolving quickly. Security fixes are applied to the latest
published version on npm only; there are no long-term support branches yet.

| Version | Supported |
| ------- | --------- |
| latest (npm `llm-safe-haven`) | ✅ |
| older   | ❌ (please upgrade) |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately through either channel:

1. **GitHub Private Vulnerability Reporting** — the preferred route:
   [Report a vulnerability](https://github.com/pleasedodisturb/llm-safe-haven/security/advisories/new).
2. **Email** — `claude.rancidity392@passmail.com` with `[SECURITY]` in the subject.

Include, where possible: affected version, a description of the issue and its impact,
and steps or a proof of concept to reproduce it.

## What to expect (coordinated disclosure)

This is a solo-maintained project, so timelines are best-effort but taken seriously:

- **Acknowledgement:** within 3 business days.
- **Initial assessment:** within 10 business days (severity + whether it's in scope).
- **Fix & disclosure:** coordinated with you. The aim is a patched release before public
  disclosure; a published GitHub Security Advisory (with credit, if you want it) follows
  the fix. If a report is out of scope or a non-issue, you'll get a clear explanation.

Please give a reasonable window to remediate before any public disclosure.

## Scope

In scope: the published npm package, its dependency/build/release pipeline, the hooks and
scanners it installs, and anything that could cause `llm-safe-haven` to give a user a
false sense of security or to weaken the environment it is meant to harden.

Out of scope: vulnerabilities in the third-party AI agents this tool hardens (report those
to the respective projects), and issues requiring a already-compromised local machine.

## No bug bounty

There is no paid bounty program at this time. Credit is given in the advisory and release
notes for valid, responsibly-disclosed reports.
