# CyberZen CLI

`cyberzen` provides scriptable access to CyberZen security operations from a terminal or automation agent.

## Install

From this repository:

```bash
cd apps/cli
bun install
bun run build
node dist/cyberzen.js --help
```

The package is designed for npm publication as `cyberzen` and supports a compiled Bun binary through `bun run compile`.

## Authentication

Human browser login uses the CyberZen device flow:

```bash
cyberzen auth login
```

For CI, agents, and non-interactive shells, pass a tenant API key:

```bash
cyberzen auth login --token 'czk_...'
# or
export CYBERZEN_API_KEY='czk_...'
```

Credentials are stored in the platform config directory:

- Windows: `%APPDATA%/cyberzen/auth.json`
- Linux/macOS: `~/.config/cyberzen/auth.json`
- Override with `CYBERZEN_CONFIG_DIR`.

The CLI never prints the full credential. `cyberzen auth whoami` displays only a short preview.

## Directory linkage

Link a working directory to a tenant and optional repository:

```bash
cyberzen link --tenant acme --repo acme/payments
cyberzen link-status
cyberzen unlink
```

After linking, tenant/repository-scoped commands can omit those flags. Explicit flags take precedence over environment and project configuration.

## Machine-readable operation

Every command supports global output flags:

```bash
cyberzen findings --help
cyberzen --json --tenant acme findings list
cyberzen --json --ndjson findings list | jq
```

Contract:

- stdout contains data only;
- stderr contains diagnostics;
- exit `0` means success;
- exit `1` means API/runtime failure;
- exit `2` means authentication failure;
- exit `64` means invalid usage.

Use the capability manifest for agent discovery:

```bash
cyberzen system schema | jq
```

## Implemented command groups

- `auth`, `tenants`, `link`, `dashboard`
- `agents`, `billing`, `memory`, `integrations`, `jobs`
- `findings`, `repos`, `scan`, `scans`
- `sbom`, `drift`, `repository`
- `gates`, `attack`, `trust`, `threat`
- `compliance`, `reports`, `sla`, `remediation`
- `security`, `crypto`, `traffic`
- `webhooks`, `siem`, `honeypot`, `sandbox`
- `marketplace`, `mssp`
- `system status`, `system schema`, `system version`, `system completions <shell>`

All implemented operations call real CyberZen HTTP endpoints. Scanner and analysis logic remains server-side; the CLI does not simulate findings, scans, or results.

## URLs and environments

```bash
export CYBERZEN_SITE_URL='https://animated-viper-811.eu-west-1.convex.site'
export CYBERZEN_API_URL='https://animated-viper-811.eu-west-1.convex.cloud'
export CYBERZEN_TENANT='acme'
```

The HTTP transport sends `Authorization: Bearer <key>` for tenant API routes and `X-MSSP-Api-Key` for MSSP routes.

## Development

```bash
bun test
bun run check
bun run build
bun run compile
```

Do not deploy the backend from an unconfigured local shell. The dashboard command requires the explicit backend route `/api/cli/dashboard`, which must be deployed to the configured Convex deployment before it is used against production.

## Security model

Tenant API keys are validated and rate-limited by CyberZen. The CLI does not accept a tenant identifier as an authorization substitute: tenant flags select a requested resource scope, while the server validates the key and route authorization.

The CLI dashboard bridge is an explicit endpoint, not an arbitrary Convex-function proxy. Future Convex-backed features must be exposed through similarly concrete, allow-listed backend endpoints.

## Release

Before publishing:

1. Confirm the npm package name and version.
2. Run `bun test`, `bun run check`, and `bun run build`.
3. Run a live smoke test with a disposable tenant key.
4. Build platform binaries with `bun run compile`.
5. Publish only from a clean, reviewed commit.

Never include `auth.json`, API keys, or local environment files in a release artifact.

## License

MIT
