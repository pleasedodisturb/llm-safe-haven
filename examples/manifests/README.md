# Secret Manifest Format

A declarative format for controlling which secrets AI coding agents can access in a project. The manifest enforces least-privilege: agents only get the secrets explicitly listed, nothing more.

## Purpose

AI coding agents need secrets (API keys, database URLs, tokens) to run tests, deploy, and interact with services. Without a manifest, agents either get all your secrets (overprivileged) or none (broken workflows). The manifest sits in the middle: it declares exactly which secrets the agent needs, where they come from, and how much access is allowed.

Check `secrets.manifest.yaml` into your repository. It is a security policy, not a secret. It contains no actual secret values.

## Field Reference

### Top-level fields

| Field | Required | Description |
|-------|----------|-------------|
| `project` | Yes | Project identifier. Used for audit logging and proxy routing. |
| `secrets` | Yes | Array of secret declarations. |
| `limits` | No | Rate-limiting and access controls. |

### Secret entry fields

| Field | Required | Description |
|-------|----------|-------------|
| `env` | Yes | Environment variable name the agent sees (e.g., `DATABASE_URL`). |
| `source` | Yes | Where the secret comes from. See "Sources" below. |
| `name` | Depends | Bitwarden item name. Required when `source: bitwarden`. |
| `field` | Depends | Field within the Bitwarden item. Required when `source: bitwarden`. |

### Sources

| Source | Description | Extra fields |
|--------|-------------|--------------|
| `bitwarden` | Retrieved via `rbw` CLI from Bitwarden vault. | `name`, `field` |
| `gh-auth` | Token from `gh auth token` (GitHub CLI). | None |
| `env` | Passthrough from host environment. | None |
| `file` | Read from a file path on disk. | `path` |

### Limits fields

| Field | Default | Description |
|-------|---------|-------------|
| `max_requests_per_minute` | unlimited | Maximum credential proxy requests per minute. Prevents runaway loops. |
| `max_unique_secrets_per_session` | unlimited | Maximum distinct secrets an agent can access in one session. Limits blast radius. |

## How It Works with Credential Proxies

The manifest alone is a declaration. Enforcement happens through a credential proxy that sits between the agent and the secret store:

```
Agent process  -->  Credential Proxy  -->  Bitwarden / gh / env
                        |
                  reads manifest
                  enforces limits
                  logs access
```

1. Agent requests a secret by environment variable name (e.g., `DATABASE_URL`).
2. Proxy reads the manifest to check if that secret is declared for this project.
3. If declared, proxy retrieves the value from the configured source and injects it.
4. If not declared, proxy denies the request and logs the attempt.
5. Rate limits are enforced per session — breaching a limit blocks all further requests.

The agent never sees the raw secret store. It only sees environment variables that the proxy populates on demand.

## Creating a Manifest for Your Project

1. List every secret your project actually uses:
   ```bash
   grep -r 'process\.env\.' src/ | grep -oP 'process\.env\.\K[A-Z_]+' | sort -u
   ```

2. For each secret, decide the source (Bitwarden, gh-auth, env, file).

3. Create `secrets.manifest.yaml` at your project root:
   ```yaml
   project: your-project-name

   secrets:
     - env: YOUR_SECRET_NAME
       source: bitwarden
       name: "Bitwarden Item Name"
       field: field_name

   limits:
     max_requests_per_minute: 10
     max_unique_secrets_per_session: 3
   ```

4. Commit it to git. Review it in PRs like any security policy.

## Integration with rbw-proxy

The `rbw-proxy` (forthcoming) is a credential proxy implementation that:

- Reads `secrets.manifest.yaml` from the project root
- Runs as a local daemon that the agent process connects to
- Retrieves secrets from Bitwarden via `rbw get` on demand
- Caches decrypted values in memory (never on disk)
- Enforces rate limits and logs every access to an audit file
- Supports `gh auth token` as a source for GitHub tokens
- Integrates with the audit-logger hook for unified security logging

Until rbw-proxy ships, you can use the manifest as documentation for manual credential setup and as input to custom proxy scripts.
