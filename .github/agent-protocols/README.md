# Agent Protocols

These markdown files **are the prompts** for the project's scheduled cloud agents
(Claude Code Remote triggers). Each trigger's prompt is just a short pointer:

> Read `.github/agent-protocols/<file>.md` from the repo and execute it exactly.

Keeping the real instructions in the repo (instead of inline in the trigger config) means:

- The job's behavior is **versioned and reviewable** — changes go through a PR like any code.
- You can **edit the job without recreating the trigger** (the trigger reads the file fresh
  at each fire). No trigger-ID churn, no model/source drift.

## Triggers

| File | Trigger | Cadence | Purpose |
|------|---------|---------|---------|
| `maintenance-sweep.md` | LLM Safe Haven — Weekly Wide Sweep | Weekly (Mon 08:00 UTC) | Comprehensive research sweep (incidents/CVEs, npm+PyPI supply chain, tools, changelogs, papers, link health) in rolling-PR mode. |
| `high-severity-triage.md` | LLM Safe Haven — Daily High-Severity Alert | Daily (08:00 UTC) | Lean triage for incidents that need immediate maintainer action; opens a `🚨 ACTION REQUIRED` issue + push notification, or exits quietly. |

To change what a job does, edit its file here and merge — the next run picks it up.
