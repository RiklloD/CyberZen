# CyberZen CLI (`cyberzen`) Implementation Plan

> **For Hermes:** Use the `subagent-driven-development` skill to implement this plan task-by-task.

**Goal:** Build a standalone CLI, `cyberzen`, that exposes **every** CyberZen security-operations feature through the terminal — scriptable, machine-readable, and agent-friendly — with Vercel/Convex-style auth (browser device-flow + `--token`).

**Architecture:** A new pnpm/bun workspace package `apps/cli` written in TypeScript. It talks to CyberZen two ways (hybrid transport):
1. **HTTP** to the 143 existing authenticated routes on the Convex HTTP Actions URL (`https://animated-viper-811.eu-west-1.convex.site`), authenticated with a tenant API key (`czk_…`).
2. **Thin Convex client** (`convex/browser`) for the public queries/mutations that have **no** HTTP route (dashboard overview, agents, neural-memory, onboarding, 2FA, billing, integrations).

Auth is stored at `~/.cyberzen/auth.json` + `~/.cyberzen/config.json` (global, Vercel-style) with optional per-directory `.cyberzen/project.json` linkage (Convex-style). Output defaults to pretty tables for humans, `--json` / NDJSON for agents, plus a `--schema` introspection mode.

**Tech Stack:** TypeScript, Bun (build) / Node ≥18 (runtime), `commander` (command tree), `convex` (browser client), `open` (browser flow), `undici`/`fetch` (HTTP), `vitest` (tests). Published to npm as `cyberzen` + a standalone binary via `bun build --compile`.

---

## 0. Decisions already made (do not re-litigate)

| Decision | Choice | Rationale |
|---|---|---|
| Transport | **Hybrid**: HTTP for 143 routes + Convex client for no-route functions | Maximizes coverage without re-implementing backend |
| Auth | **Both**: browser device-flow for humans + `--token` for agents/CI | Device-flow is most secure; `--token` is CI/agent essential |
| Package location | `apps/cli` in the existing monorepo | Reuses workspace tooling, shares `convex/_generated` types |
| CLI framework | `commander` | Standard, typed, subcommand nesting, easy `--help` |
| Machine output | `--json` flag on every command + `CYBERZEN_OUTPUT=json` env | Agent-friendliness is a prime directive |

---

## 1. Facts on the ground (verified against the codebase)

These are **real, confirmed** facts the implementer must rely on. Do not invent endpoints.

- **HTTP Actions base URL:** `https://animated-viper-811.eu-west-1.convex.site`
- **Convex cloud URL (client):** `https://animated-viper-811.eu-west-1.convex.cloud`
- **HTTP routes file:** `apps/web/convex/http.ts` (6,223 lines, 143 routes). Full route inventory in §4.
- **HTTP auth:** `X-Sentinel-Api-Key: <key>` **or** `Authorization: Bearer <key>`. Tenant keys are prefixed `czk_` and validated/rate-limited by `internal.apiKeys.checkAndRecordTenantKeyUsage`. Operator key `SENTINEL_API_KEY` bypasses rate limiting. See `authenticateApiRequest` (`http.ts:280`).
- **MSSP routes** use a separate key: `X-MSSP-Api-Key` (`msk_…`), validated by `internal.msspApiKeys.validateMsspKey` (`http.ts:222`).
- **Public (no-key) routes** the CLI must NOT require auth for: `/api/github/oauth/callback`, `/api/slack/oauth/callback`, `/api/slack/commands`, `/api/stripe/webhook`, `/webhooks/*` (inbound provider webhooks), `/metrics`.
- **Backend source:** `apps/web/convex/*.ts` — 205 modules. The repo-root `convex/` dir is generated/aux only. **Always scope backend work to `apps/web/convex`.**
- **Public Convex functions:** defined with `query({…})` / `mutation({…})` / `action({…})` across those modules; the generated API tree is `apps/web/convex/_generated/api`.
- **Frontend routes (feature inventory, 36 pages):** `apps/web/src/routes/` — `index` (dashboard), `findings`, `sbom`, `repositories`, `ci-cd`, `breach-intel`, `attack-paths`, `agents`, `agent-activity`, `neural-memory`, `compliance`, `supply-chain`, `drift-posture`, `executive-report`, `exploit-validation`, `marketplace`, `mssp`, `maturity`, `posture`, `remediation`, `reports`, `timeline`, `zero-day`, `business-impact`, `cross-repo`, `audit-log`, `status`, `integrations`, `onboarding`, `pricing`, `about`, `settings/*` (jobs, two-factor, …), `sign-in.$`, `sign-up.$`.
- **Tenant scoping:** Almost every query/mutation takes `tenantSlug` and resolves via `resolveTenant()`. The CLI must thread a `--tenant` flag / `CYBERZEN_TENANT` env through every command.
- **TS2589:** The 195-table schema overflows TypeScript recursion → build/deploy the **backend** with `--typecheck=disable`. The CLI package itself does not import the schema, so it is unaffected.
- **Zero-simulation rule:** No fake data anywhere. Every CLI command must call a real endpoint/function.

---

## 2. Command surface (the full feature map)

Top-level command groups. Each maps to a real API surface (§4 gives exact endpoints/functions). `R` = read, `W` = write/mutation, `H` = HTTP route, `C` = Convex function.

```
cyberzen
├── auth        login · logout · whoami · token (print/refresh)
├── link        link · unlink · status                # Convex-style project/dir linkage
├── tenants     list · current · use <slug> · create · members · invites
├── repos       list · add · remove · scan · get · health
├── scan        run <repo> [--scanner T] · status <runId> · logs <runId> · watch <runId>
├── findings    list · get <id> · triage · status · risk-accept · poc · reasoning · cross-repo · escalations · export
├── sbom        get · export [--format cyclonedx|spdx] · diff · commit · cve-scan · license-scan · malicious-scan · confusion-scan · attestation · supply-chain-posture · container-scan · update-recs · quality
├── breach      list · sync · match                   # breach-intel / advisory feeds
├── threat      kev list · kev sync · epss get · epss sync · tier3
├── gates       list · get · policies · evaluate · override   # CI/CD gate enforcement
├── drift       posture · <domain> …                  # ~45 repository drift domains (§4.3)
├── attack      surface score · surface history · surface components · surface scan · paths · blast-radius · blast-radius graph
├── trust       list · detail · history
├── compliance  evidence · attestation · remediation-plan · report
├── reports     generate · download · security-posture · compliance · adversarial · executive
├── marketplace list · get · deploy · contributions · vote · stats
├── mssp        tenants list · tenants create · tenant get · tenant summary · dashboard
├── agents      list · run <name> · tasks · logs · usage · red-blue
├── memory      snapshots · episodes · patterns · predictions · notes   # neural-memory
├── remediation queue · auto-runs · playbooks · proposals
├── sla         status · breaches
├── webhooks    list · create · delete · deliveries · test
├── siem        push
├── honeypot    trigger
├── sandbox     environment · summary
├── integrations list · health · connect <provider>   # slack, jira, linear, pagerduty, teams, datadog, opsgenie…
├── billing     plans · subscription · invoices · usage · portal
├── settings    2fa enroll/verify/disable · jobs list · jobs pause/resume · ip-allowlist · retention · sso
├── admin       users · audit-log · feature-flags · seed · migrations
├── status      platform status
└── system      version · update · completions · docs · schema
```

> The drift domains are the ~45 `/api/repository/*-drift` endpoints. Implement them via a single parameterized command family (see Task 12) so we don't hand-write 45 commands.

---

## 3. File-by-file implementation

Create the package `apps/cli`. All paths below are relative to repo root `C:\Dev\CyberZen`.

### 3.1 Package scaffolding

**Create** `apps/cli/package.json`
```json
{
  "name": "cyberzen-cli",
  "version": "0.1.0",
  "description": "CyberZen security-operations CLI — full platform control from the terminal.",
  "type": "module",
  "bin": { "cyberzen": "./dist/cyberzen.js" },
  "files": ["dist", "README.md"],
  "scripts": {
    "build": "bun build src/index.ts --outfile dist/cyberzen.js --target node --format esm --banner:js '#!/usr/bin/env node'",
    "compile": "bun build src/index.ts --outfile dist/cyberzen --compile",
    "dev": "bun run src/index.ts",
    "test": "vitest run",
    "lint": "biome lint .",
    "check": "biome check ."
  },
  "dependencies": {
    "commander": "^12.1.0",
    "convex": "^1.32.0",
    "open": "^10.1.0",
    "undici": "^6.19.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "typescript": "^5.5.0",
    "vitest": "^2.0.0"
  }
}
```

**Create** `apps/cli/tsconfig.json`
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "declaration": false,
    "outDir": "dist",
    "types": ["node"]
  },
  "include": ["src"]
}
```

**Create** `apps/cli/src/index.ts` — the commander entrypoint. Registers every command group (each in its own module under `src/commands/`). Registers global flags `--json`, `--tenant <slug>`, `--profile <name>`, `--api-url <url>`, `--site-url <url>`, `--verbose`, `--no-color`, `--timeout <ms>`.

```ts
#!/usr/bin/env node
import { Command } from 'commander'
import { registerAuth } from './commands/auth.js'
import { registerLink } from './commands/link.js'
import { registerTenants } from './commands/tenants.js'
// … one import per group from §2
import { applyGlobalFlags } from './lib/globalFlags.js'
import { handleError } from './lib/errors.js'

const program = new Command()
  .name('cyberzen')
  .description('CyberZen — security operations from the terminal')
  .version(process.env.CYBERZEN_CLI_VERSION ?? '0.1.0')

applyGlobalFlags(program)   // --json --tenant --profile --api-url --site-url --verbose --no-color --timeout

registerAuth(program)
registerLink(program)
registerTenants(program)
// … register every group from §2

program.exitOverride()
try {
  await program.parseAsync(process.argv)
} catch (err) {
  handleError(err)         // maps ApiError/AuthError/usage errors → stderr + exit code
}
```

### 3.2 Core library (`apps/cli/src/lib/`)

**`config.ts`** — config persistence. Global config lives in the OS config dir:
- `configDir()`: `%APPDATA%/cyberzen` on Windows, `~/.config/cyberzen` on POSIX (override with `CYBERZEN_CONFIG_DIR`).
- `authPath()` → `<dir>/auth.json`, `configPath()` → `<dir>/config.json`.
- `readAuth()` / `writeAuth()`: shape `{ token: string, tenantSlug?: string, email?: string, createdAt: number, profiles?: Record<string, Profile> }`. `chmod 600` after write.
- `readConfig()` / `writeConfig()`: shape `{ apiUrl, siteUrl, tenant?, telemetry: false, output: 'table'|'json' }`.
- Env precedence (highest→lowest): CLI flag → `CYBERZEN_*` env → project `.cyberzen/project.json` → global config → built-in default.

**`project.ts`** — Convex/Vercel-style directory linkage.
- `linkProject(dir, { tenantSlug, repoFullName? })` writes `<dir>/.cyberzen/project.json` → `{ tenantSlug, repoFullName?, linkedAt }`.
- `resolveProject(cwd)` walks up from `cwd` to find `.cyberzen/project.json`; returns `null` if none.
- Used to default `--tenant` (and repo for repo-scoped commands) when not passed.

**`api.ts`** — HTTP client for the 143 routes.
```ts
export interface ApiOptions { method?: string; path: string; body?: unknown; query?: Record<string, string|number|boolean|undefined>; mssp?: boolean }
export class ApiError extends Error { constructor(public status: number, public url: string, body: string) { super(`${status} ${url}: ${body}`) } }
export async function api<T>(opts: ApiOptions): Promise<T>
```
- Builds URL from `siteUrl()` (default `https://animated-viper-811.eu-west-1.convex.site`).
- Header: MSSP routes → `X-MSSP-Api-Key`; everything else → `Authorization: Bearer <czk_>` (fallback `X-Sentinel-Api-Key`). Reads token via `getToken()` from `auth.ts`.
- On 401 → throw `AuthError('Run `cyberzen login`')`. On 429 → surface `Retry-After`. On 5xx → `ApiError`. Timeout via `AbortController` (default 30s, `--timeout` overrides).
- Never logs the token. Redacts `authorization` in `--verbose` output.

**`convexClient.ts`** — lazy singleton `ConvexClient` from `convex/browser` pointed at `apiUrl()` (default `https://animated-viper-811.eu-west-1.convex.cloud`).
- Exposes `queryClient(fnRef, args)`, `mutationClient(fnRef, args)` using **string** function references (e.g. `"dashboard:overview"`) so the CLI does not depend on the generated `_generated/api` tree (keeps the package decoupled and avoids TS2589).
- Auth for Convex functions: Clerk session token is **not** available in a CLI. For functions that require `ctx.auth`, the CLI passes the tenant API key and the functions are resolved through the HTTP bridge (see §5, Task 9) — Convex functions that already accept an explicit `tenantSlug` + key are called directly. Document which commands use which path in the command module header comment.

**`auth.ts`** — token resolution + device flow.
```ts
export async function getToken(): Promise<string | null>   // flag --token > CYBERZEN_API_KEY > auth.json
export async function requireToken(): Promise<string>       // throws AuthError if none
export async function deviceLoginFlow(opts): Promise<LoginResult>
```
- `deviceLoginFlow`:
  1. `POST /api/cli/device/start` → `{ deviceCode, userCode, verificationUrl, expiresIn, interval }`.
  2. Open `verificationUrl` in the browser (`open`), print `userCode`.
  3. Poll `POST /api/cli/device/poll { deviceCode }` every `interval`s until `{ status:'authorized', token }` or `expired`/`denied`.
  4. On success `writeAuth({ token, tenantSlug, email })`, `chmod 600`, print confirmation.
- Backend endpoints `/api/cli/device/*` are **new** and built in Task 9 (§5).

**`output.ts`** — rendering.
- `render(data, { json, columns })`: if `json` → `JSON.stringify(data)` (single line for arrays = NDJSON when `--ndjson`); else render a table via a tiny internal table formatter (no heavy dep) honoring `--no-color` and `NO_COLOR`.
- `renderKeyValue(obj)` for single-record views.
- Every command ends by calling one of these — never `console.log(data)` directly.

**`errors.ts`** — `handleError(err)`: maps `AuthError`→exit 2 + login hint, `ApiError`→exit 1 + status, commander usage errors→exit 64, unknown→exit 1 with `--verbose` stack. All errors to **stderr**; data to **stdout** (hard rule for agent use).

**`globalFlags.ts`** — registers the global options and a pre-hook that loads `project.ts` resolution + sets the renderer mode.

**`spin.ts`** — minimal TTY spinner for `scan watch` / long polls; disabled when `!process.stdout.isTTY` or `--json`.

### 3.3 Command modules (`apps/cli/src/commands/`)

One file per top-level group from §2. Each exports `registerX(program: Command)`. Pattern per command:

```ts
// commands/findings.ts
import type { Command } from 'commander'
import { api } from '../lib/api.js'
import { render } from '../lib/output.js'
import { tenantArg } from '../lib/tenant.js'

export function registerFindings(p: Command) {
  const f = p.command('findings').description('Security findings')
  f.command('list')
    .option('--severity <sev>').option('--status <st>').option('--repo <name>').option('--limit <n>')
    .action(async (opts, cmd) => {
      const g = cmd.optsWithGlobals()
      const data = await api({ path: '/api/findings', query: { tenant: tenantArg(g), ...opts } })
      render(data, g)
    })
  // … get, triage, status, risk-accept, poc, reasoning, cross-repo, escalations, export
}
```

`lib/tenant.ts` — `tenantArg(globals)` resolves tenant from `--tenant` flag → `CYBERZEN_TENANT` → `linkProject()` → global config; throws a clear error if none and the command requires it.

---

## 4. Exact API mapping (authoritative — do not guess)

### 4.1 HTTP routes (wrap these 1:1; from `apps/web/convex/http.ts`)

Auth: `Authorization: Bearer <czk_>` unless noted. All accept `tenant=<slug>` (or `tenantSlug`) query/body param — confirm per handler when implementing.

**Findings / triage / risk**
- `GET  /api/findings` — list (filters: severity, status, repo, limit)
- `GET  /api/findings/detail` — single finding
- `POST /api/findings/status` — change status
- `GET  /api/findings/poc` — proof-of-concept
- `GET  /api/findings/reasoning` — LLM reasoning log
- `GET  /api/findings/cross-repo-impact`
- `GET  /api/findings/escalations`
- `GET  /api/findings/triage` · `POST /api/findings/triage`
- `POST /api/findings/risk-accept` · `GET /api/findings/risk-accept` · `GET /api/findings/risk-acceptances`

**SBOM / supply chain**
- `GET /api/sbom` · `GET /api/sbom/export` (fmt cyclonedx|spdx) · `GET /api/sbom/commit` · `GET /api/sbom/diff`
- `GET /api/sbom/cve-scan` · `GET /api/sbom/license-scan` · `GET /api/sbom/malicious-scan` · `GET /api/sbom/confusion-scan`
- `GET /api/sbom/attestation` · `GET /api/sbom/supply-chain-posture` · `GET /api/sbom/container-image-scan` · `GET /api/sbom/update-recommendations`

**Repository security + health**
- `POST /api/repositories/scan` — trigger scan (same endpoint the GitHub Action uses)
- `GET /api/repository/health-score` · `/sensitive-files` · `/branch-protection` · `/commit-messages` · `/git-integrity` · `/high-risk-changes` · `/security-config-drift` · `/test-coverage-gaps` · `/database-security` · `/container-hardening` · `/cloud-security-drift` · `/build-config` · `/dep-lock` · `/api-security-drift` · `/cert-pki-drift` · `/endpoint-security-drift`

**Drift posture (45 domains — one parameterized family)**
`GET /api/repository/<domain>-drift` where `<domain>` ∈ {drift-posture (aggregate), network-monitoring, voip-security, virtualization-security, iot-embedded-security, wireless-radius, os-security-hardening, dns-security, storage-data-security, siem-security, backup-dr-security, vpn-remote-access, cfg-mgmt-security, artifact-registry, ml-ai-platform, data-pipeline, sso-provider, messaging-security, serverless-faas, email-security, web-server-security, mobile-app-security, cicd-pipeline-security, service-mesh-security, observability-security, identity-access, dev-sec-tools, network-firewall, runtime-security, supply-chain-attestation, k8s-admission, secret-mgmt, dep-mgr-security, ai-ml-security}.

**Attack surface / blast radius / trust**
- `GET /api/attack-surface/score` · `/score/history` · `/components` · `GET /api/attack-surface/scan`
- `GET /api/attack-paths` (via `attackPaths` module) · `GET /api/blast-radius` · `GET /api/blast-radius/graph`
- `GET /api/trust-scores` · `/trust-scores/detail` · `/trust-scores/history`

**Compliance / reports**
- `GET /api/compliance/evidence` · `GET /api/compliance/attestation` · `GET /api/compliance/remediation-plan` · `GET /api/reports/compliance`
- `POST /api/reports/generate` · `GET /api/reports/download` · `GET /api/reports/security-posture` · `GET /api/reports/adversarial`
- `GET /api/tenant/executive-report`

**Threat intel**
- `GET /api/threat-intel/cisa-kev` · `POST /api/threat-intel/cisa-kev/sync`
- `GET /api/threat-intel/epss` · `POST /api/threat-intel/epss/sync`

**SLA / remediation / webhooks / SIEM / honeypot / sandbox / traffic**
- `GET /api/sla/status`
- `GET /api/remediation/queue` · `GET /api/remediation/auto-runs`
- `GET /api/webhooks` · `POST /api/webhooks` · `DELETE /api/webhooks` · `GET /api/webhooks/deliveries`
- `POST /api/siem/push`
- `POST /api/honeypot/trigger`
- `GET /api/sandbox/environment` · `GET /api/sandbox/summary`
- `GET /api/traffic/events`

**Marketplace / MSSP**
- `GET /api/marketplace/contributions` · `POST /api/marketplace/contributions` · `POST /api/marketplace/contributions/vote` · `GET /api/marketplace/stats`
- `GET /api/mssp/tenants` · `POST /api/mssp/tenants` · `GET /api/mssp/tenant` · `GET /api/mssp/tenant/summary` · `GET /api/mssp/dashboard`  *(MSSP key `msk_` / `X-MSSP-Api-Key`)*

**Security posture / timeline / debt / crypto / EOL / abandonment**
- `GET /api/security/timeline` · `GET /api/security/debt` · `GET /api/crypto/weaknesses`
- `GET /api/eol/scan` · `GET /api/abandonment/scan` · `GET /api/detection-rules`

**Observability**
- `GET /api/observability/metrics` · `GET /metrics` (Prometheus, no auth)

### 4.2 Convex functions (no HTTP route → use thin client or new bridge)

These public functions back pages with no REST route. Call via `convexClient` string refs, or (preferred for auth-requiring ones) via the new `/api/cli/call` bridge (Task 9). Group → example refs (verify exact names in the module before wiring):

- **Dashboard** (`dashboard.ts`): `dashboard:overview`, `dashboard:kpiStats`, `dashboard:recentFindings`, `dashboard:repoSummaries`, `dashboard:workflowEvents`, `dashboard:ciGateSummary`, `dashboard:escalations` → `cyberzen status` / `cyberzen tenants current`
- **Repositories** (`repositories.ts`): list/get/add/remove → `cyberzen repos …`
- **Onboarding/tenancy** (`onboarding.ts`, `workspaceAuth.ts`): `workspaceAuth:ensureUser`, tenant provisioning → `cyberzen tenants create`, `cyberzen link`
- **Agents** (`agentOrchestrator.ts`, `agentData.ts`, `agents/*`): list agents, run agent, get tasks/reasoning/usage → `cyberzen agents …`
- **Neural memory** (`neuralMemory.ts`, `agentMemory.ts`): snapshots/episodes/patterns/predictions/notes → `cyberzen memory …`
- **2FA** (`twoFactor.ts`): `startEnrollment` → `{secret, otpauthUri, backupCodes}` (render `otpauthUri` as an ASCII QR in the terminal), `verify`, `disable` → `cyberzen settings 2fa …`
- **Jobs** (`jobMonitoring.ts`): `getJobHealth`, `getJobHistory`, `toggleJobPause`, `getPausedJobs` → `cyberzen settings jobs …`
- **Billing** (`billing.ts`, `plans.ts`, `usage.ts`, `billingPortal.ts`): plans/subscription/invoices/usage → `cyberzen billing …`
- **Integrations** (`integrations.ts`, `slack.ts`, `jira.ts`, `linear.ts`, `pagerduty.ts`, `teams.ts`, `datadog.ts`, `opsgenie.ts`, `integrationHealth.ts`): list/health/connect → `cyberzen integrations …`
- **Feature flags / admin** (`featureFlags.ts`, `rbac.ts`, `auditLog.ts`, `userProfile.ts`, `seed.ts`, `migrations.ts`) → `cyberzen admin …`

> **Implementer rule:** before wiring any Convex ref, open the module and confirm the exact exported function name + arg validator. The names above are from the skill map and must be verified — never call a ref you haven't read.

---

## 5. Backend work required (new code in `apps/web/convex/`)

The CLI is 95% client, but two backend additions are needed to make auth + full coverage real.

### Task 9a — Device-flow endpoints (`apps/web/convex/cliDeviceAuth.ts` + routes in `http.ts`)
Mirror the OAuth device-authorization grant using the existing `apiKeys` backend:
- New table `cliDeviceCodes`: `{ deviceCode (indexed), userCode, status: 'pending'|'authorized'|'denied', apiKeyId?, tenantSlug?, email?, createdAt, expiresAt }` with index `by_device_code` and `by_user_code`.
- `POST /api/cli/device/start` (public): creates a `cliDeviceCodes` row, returns `{ deviceCode, userCode, verificationUrl: <SITE_URL>/cli/device?code=<userCode>, expiresIn: 600, interval: 3 }`.
- `POST /api/cli/device/poll` (public, rate-limited): given `deviceCode`, returns `{ status }`; when the web page authorizes, it mints a **tenant API key (`czk_`)** via the existing `apiKeys` creation mutation, stores `apiKeyId` on the row, and the poll returns `{ status:'authorized', token: <czk_>, tenantSlug, email }` **once**, then the row is consumed/deleted.
- Web page `apps/web/src/routes/cli.device.tsx` (signed-in): shows the `userCode`, lists the user's tenants, "Authorize CLI" button → creates the `czk_` key scoped to the chosen tenant and marks the device row authorized.

### Task 9b — Generic Convex bridge `POST /api/cli/call` (in `http.ts`)
For Convex functions with no HTTP route that need Clerk auth, expose a guarded bridge:
- Authenticates with `czk_` (reuse `authenticateApiRequest`).
- Body: `{ fn: "<module>:<function>", args: {...} }`.
- Whitelist: only function refs in an explicit allow-list (`CLI_CALLABLE` set in `cliDeviceAuth.ts`) may be invoked — **never** an open proxy to arbitrary functions. Resolves the caller's tenant from the key and injects `tenantSlug` if the target declares it.
- This is how `dashboard`, `agents`, `memory`, `billing`, `2fa`, `jobs`, `integrations`, `admin` commands reach their functions with proper auth.

> **Security note (standing):** fail closed. The bridge refuses any ref not in the allow-list, and reuses the existing rate-limit + IP-allowlist path. No secrets in logs.

---

## 6. Auth & linkage UX (the Vercel/Convex copy)

**`cyberzen login`** (human, browser):
```
$ cyberzen login
Opening browser to authorize the CLI…
Visit: https://cyber-zen-web.vercel.app/cli/device?code=WD4K-9P2Q
Code: WD4K-9P2Q
Waiting for authorization… ✓ Authorized as lorik@… (tenant: acme)
Credentials saved to C:\Users\lorik\.config\cyberzen\auth.json
```

**`cyberzen login --token czk_…`** (agent/CI): validates the key by calling `GET /api/findings?limit=1`, then stores it. Non-interactive; safe for CI.

**`cyberzen whoami`** → prints email, tenant, key prefix (`czk_…ab12`), auth source.

**`cyberzen logout`** → deletes `auth.json` (and optionally revokes the key server-side via a new `DELETE /api/cli/token`).

**`cyberzen link`** (Convex-style, per-directory): prompts for tenant (and optional repo), writes `.cyberzen/project.json`. **`cyberzen link --tenant acme`** non-interactive. **`cyberzen unlink`** removes it. Repo-scoped commands then run without `--tenant`.

**Env vars:** `CYBERZEN_API_KEY`, `CYBERZEN_TENANT`, `CYBERZEN_SITE_URL`, `CYBERZEN_API_URL`, `CYBERZEN_CONFIG_DIR`, `CYBERZEN_OUTPUT`, `NO_COLOR`.

---

## 7. Agent-friendliness contract (hard requirements)

1. **Every command supports `--json`.** Output is the raw API payload, one JSON value; `--ndjson` streams arrays as NDJSON.
2. **Stdout = data, stderr = diagnostics.** Piping `cyberzen findings list --json | jq` always works.
3. **Stable exit codes:** `0` ok, `1` API/runtime error, `2` auth error, `64` usage error.
4. **`cyberzen schema`** prints a machine-readable manifest of every command, its flags, and its endpoint/function — so an agent can enumerate capabilities programmatically.
5. **Idempotent writes.** Mutating commands are safe to re-run; server-side dedupe (`ingestionEvents.dedupeKey`, etc.) is preserved.
6. **Non-interactive by default in CI.** When `!isTTY` or `CI=true`, never prompt; require explicit flags and fail with a usage error telling the agent exactly which flag is missing.
7. **`--yes` flag** on all destructive/one-way commands (`repos remove`, `webhooks delete`, `findings status`, `risk-accept`, `logout`) to skip the interactive confirm.
8. **Machine docs:** `cyberzen <cmd> --help` is complete and accurate; `cyberzen docs` prints the full command tree.

---

## 8. Task breakdown (bite-sized, TDD, frequent commits)

> Each task: write failing test → run (fail) → implement → run (pass) → commit. Run tests with `cd apps/cli && bun run test`. Build with `bun run build`. Lint with `bun run check`.

**Phase 0 — Scaffold**
- **T1** Create `apps/cli` package (§3.1), wire into root workspace `package.json` `workspaces`, `bun install`. Verify `bun run dev -- --version` prints. Commit.
- **T2** `lib/config.ts` + tests (paths, env precedence, read/write). Commit.
- **T3** `lib/errors.ts` + `lib/output.ts` + tests (table vs `--json`, NDJSON, exit codes). Commit.

**Phase 1 — HTTP client + auth**
- **T4** `lib/api.ts` + tests (header selection, 401→AuthError, 429 Retry-After, timeout, token redaction). Mock `fetch`. Commit.
- **T5** `lib/auth.ts` token resolution + `lib/project.ts` linkage + tests. Commit.
- **T6** `auth` commands: `login --token`, `whoami`, `logout` (no browser flow yet). Tests. Commit.
- **T7** `link`/`unlink`/`status` + `.cyberzen/project.json`. Tests. Commit.
- **T8** `tenants list/current/use` via HTTP (`/api/mssp/tenants` is MSSP; tenant list comes from Convex `tenants` — wire via bridge once T9 done; for now `--tenant` threading). Commit.

**Phase 2 — Backend device flow + bridge (one-way/backend work — confirm before deploy)**
- **T9** Implement §5 (Task 9a `cliDeviceAuth.ts` + `cliDeviceCodes` table + 3 routes; Task 9b `/api/cli/call` bridge + `CLI_CALLABLE` allow-list; `cli.device.tsx` page). Migrate schema, `npx convex dev --once --typecheck=disable`. **This is a backend deploy — confirm with user before pushing.**
- **T10** Wire browser `login` device flow in `lib/auth.ts` against the new endpoints + `open`. Tests with mocked poll. Commit.

**Phase 3 — Core feature commands (HTTP)**
- **T11** `findings` group (all §4.1 findings routes) + `repos` group + `scan run/status/logs/watch`. Tests. Commit.
- **T12** `sbom` group (all SBOM routes) + `drift` parameterized family (§4.1 drift list) driven by a domain registry constant. Tests. Commit.
- **T13** `gates`, `attack`, `trust`, `threat`, `compliance`, `reports`, `sla`, `remediation`. Tests. Commit.
- **T14** `webhooks`, `siem`, `honeypot`, `sandbox`, `marketplace`, `mssp` (MSSP key path). Tests. Commit.

**Phase 4 — Convex-backed commands (bridge)**
- **T15** `agents` group (list/run/tasks/logs/usage/red-blue). Commit.
- **T16** `memory` (neural-memory) + `settings` (2fa enroll/verify/disable with ASCII QR, jobs pause/resume, ip-allowlist, retention, sso). Commit.
- **T17** `billing`, `integrations`, `admin`, `status`, `dashboard`→`tenants current`. Commit.

**Phase 5 — Polish + ship**
- **T18** `schema` manifest command + `docs` + shell completions (`commander` completion + zsh/bash/fish scripts under `apps/cli/completions/`). Commit.
- **T19** README (`apps/cli/README.md`) with install, auth, per-command examples, agent usage. Commit.
- **T20** `bun build --compile` standalone binaries; npm `publishConfig`; a GitHub Action (`.github/workflows/cli-release.yml`) to build+attach binaries on tag. Commit.
- **T21** Final sweep: every command honors `--json`, exit codes, no-simulation; `bun run build` + `bun run check` clean.

---

## 9. Verification & definition of done

- `cd apps/cli && bun run build` compiles clean; `bun run check` lints clean; `bun run test` all green.
- `cyberzen --help` lists every group in §2; `cyberzen <group> --help` lists every subcommand.
- Against the **live** deployment: `cyberzen login --token <real czk_>` → `cyberzen findings list --json` returns real findings; `cyberzen repos list`; `cyberzen sbom export --format cyclonedx` emits a valid document; `cyberzen schema | jq` enumerates all commands.
- Auth edge cases: no token → exit 2 + login hint; bad token → 401 message; expired device code → clear error.
- Backend (T9) verified via `convex dev --once --typecheck=disable` then exercised end-to-end through the browser flow.
- No simulated data anywhere; every command hits a real route/function.

---

## 10. Risks, trade-offs, open questions

- **Backend deploys are one-way.** T9 changes the schema (`cliDeviceCodes`) and adds routes. Per the prime directive, **confirm before `convex deploy` / pushing to production.** Local `convex dev` is fine to iterate.
- **Convex auth from a CLI.** Clerk session tokens aren't available headless — that's why authed Convex functions go through the `/api/cli/call` bridge with a `czk_` key, not a direct Clerk JWT. This is the biggest design constraint; the allow-list keeps it safe.
- **45 drift commands.** Parameterized family avoids bloat but must still appear in `--help`/`schema` — solved with the domain registry (T12).
- **Convex client vs bridge.** Where a function is read-only and already accepts `tenantSlug`, the thin client is fine; where it needs Clerk identity, use the bridge. Each command module documents its path.
- **Open question:** Should `cyberzen scan run` default to `full_scan` (matching the Connect-GitHub "Start Initial Scan" behavior) — confirm with user; default assumed `full_scan`.
- **Open question:** npm package name — `cyberzen` may be taken; fallback `@cyberzen/cli`. Confirm before publish (T20).

---

## 11. Out of scope (do not build)

- Re-implementing any scanner/analysis logic client-side (all server-side).
- A TUI dashboard (this is a scriptable CLI, not an interactive TUI).
- Inbound provider webhook receivers (those stay server-side `/webhooks/*`).
- Changing the existing web app beyond the single `cli.device.tsx` authorize page.
