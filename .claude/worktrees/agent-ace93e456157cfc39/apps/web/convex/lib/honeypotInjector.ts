/**
 * Honeypot Code Auto-Injection — pure computation library (spec §3.9)
 *
 * Generates canary trap proposals (fake endpoints, database fields, files, and
 * document tokens) placed intelligently adjacent to the repository's real
 * sensitive assets, as identified by the Blast Radius Causality Graph.
 *
 * All input → output logic is pure and synchronous so it can be fully exercised
 * in Vitest without a Convex runtime.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export type HoneypotKind = 'endpoint' | 'database_field' | 'file' | 'token'

export type HoneypotInput = {
  /** Services reachable from the blast radius of known findings */
  reachableServices: string[]
  /** Data layers exposed (e.g. "users", "payments", "secrets") */
  exposedDataLayers: string[]
  /** Maximum attack path depth across all blast radius snapshots */
  attackPathDepth: number
  /** Number of open critical findings in this repository */
  openCriticalCount: number
}

export type HoneypotProposal = {
  kind: HoneypotKind
  /** Route, field name, file path, or token URI */
  path: string
  description: string
  /** Why this placement was chosen — links to the blast radius context */
  rationale: string
  /** The service or data layer this honeypot is placed adjacent to */
  targetContext: string | undefined
  /** 0–100: how attractive this target would appear to a lateral-moving attacker */
  attractivenessScore: number
}

export type HoneypotPlanResult = {
  proposals: HoneypotProposal[]
  totalProposals: number
  endpointCount: number
  fileCount: number
  databaseFieldCount: number
  tokenCount: number
  topAttractiveness: number
  summary: string
}

// ─── Internal template types ──────────────────────────────────────────────────

type EndpointTemplate = {
  path: string
  description: string
  /** Service keywords that raise this template's relevance */
  affinityKeywords: string[]
  baseScore: number
}

type DataLayerTemplate = {
  path: string
  description: string
  affinityKeywords: string[]
  baseScore: number
}

type FileTemplate = {
  path: string
  description: string
  baseScore: number
}

type TokenTemplate = {
  path: string
  description: string
  baseScore: number
}

// ─── Canary endpoint templates ────────────────────────────────────────────────
//
// Paths are designed to look like high-value targets during attacker
// reconnaissance: admin exports, debug surfaces, service account tokens.

const ENDPOINT_TEMPLATES: EndpointTemplate[] = [
  {
    path: '/api/admin/export-users',
    description: 'Canary admin user-export endpoint that appears to dump all user records',
    affinityKeywords: ['admin', 'user', 'auth', 'account', 'identity'],
    baseScore: 75,
  },
  {
    path: '/internal/billing/payment-methods',
    description: 'Canary billing endpoint appearing to return stored payment method list',
    affinityKeywords: ['billing', 'payment', 'finance', 'stripe', 'checkout'],
    baseScore: 80,
  },
  {
    path: '/debug/env',
    description: 'Canary debug surface appearing to expose raw environment variable values',
    affinityKeywords: ['api', 'debug', 'config', 'service'],
    baseScore: 88,
  },
  {
    path: '/api/tokens/service-account',
    description: 'Canary endpoint appearing to expose a service-account credential token',
    affinityKeywords: ['auth', 'token', 'api', 'service', 'oauth'],
    baseScore: 82,
  },
  {
    path: '/internal/config/secrets',
    description: 'Canary internal config route appearing to list application secrets',
    affinityKeywords: ['config', 'secret', 'vault', 'admin', 'infra'],
    baseScore: 87,
  },
  {
    path: '/api/v1/auth/bypass',
    description: 'Canary authentication bypass route that looks like a developer shortcut',
    affinityKeywords: ['auth', 'login', 'identity', 'sso', 'session'],
    baseScore: 92,
  },
  {
    path: '/api/admin/users-dump',
    description: 'Canary bulk user-data dump endpoint with a plausible admin-tool path',
    affinityKeywords: ['admin', 'user', 'account', 'export', 'crm'],
    baseScore: 74,
  },
  {
    path: '/internal/metrics/raw',
    description: 'Canary internal metrics endpoint appearing to expose system telemetry',
    affinityKeywords: ['metrics', 'monitoring', 'observability', 'infra', 'ops'],
    baseScore: 68,
  },
]

// ─── Canary database field templates ─────────────────────────────────────────

const DB_FIELD_TEMPLATES: DataLayerTemplate[] = [
  {
    path: 'users.sentinel_admin@trap.internal',
    description: 'Canary admin user record injected into the users/accounts table',
    affinityKeywords: ['user', 'users', 'account', 'auth', 'identity', 'member'],
    baseScore: 72,
  },
  {
    path: 'api_keys.sentinel_canary_a1b2c3d4e5f6',
    description: 'Canary API key record injected into the api_keys / credentials table',
    affinityKeywords: ['api', 'key', 'token', 'credential', 'secret', 'service'],
    baseScore: 78,
  },
  {
    path: 'payment_methods.4111_1111_1111_1118',
    description: 'Canary credit-card record injected into the payment methods table',
    affinityKeywords: ['payment', 'billing', 'finance', 'stripe', 'card', 'checkout'],
    baseScore: 82,
  },
  {
    path: 'secrets.SENTINEL_TRAP_MASTER_KEY',
    description: 'Canary secrets-store entry that looks like a high-value master credential',
    affinityKeywords: ['secret', 'vault', 'config', 'credential', 'kms', 'key'],
    baseScore: 85,
  },
]

// ─── Canary file templates ────────────────────────────────────────────────────

const FILE_TEMPLATES: FileTemplate[] = [
  {
    path: '/.env.backup',
    description: 'Canary env-file backup that looks like a forgotten production credential file',
    baseScore: 92,
  },
  {
    path: '/backup/users_export.csv',
    description: 'Canary CSV appearing to contain a user PII export from a past backup job',
    baseScore: 82,
  },
  {
    path: '/config/db_credentials.json',
    description: 'Canary JSON credential file with fake database connection strings',
    baseScore: 87,
  },
  {
    path: '/.git/config.bak',
    description: 'Canary git-config backup appearing to embed remote credential URLs',
    baseScore: 76,
  },
]

// ─── Canary document token templates ─────────────────────────────────────────

const TOKEN_TEMPLATES: TokenTemplate[] = [
  {
    path: 'internal-runbook://sentinel-beacon-alpha',
    description: 'Canary beacon token embedded in internal runbook or wiki pages',
    baseScore: 65,
  },
  {
    path: 'config://sentinel-slack-trap-webhook',
    description: 'Canary tracking URL embedded in shared Slack workspace configs',
    baseScore: 60,
  },
]

// ─── Scoring helpers ──────────────────────────────────────────────────────────

/** Bonus points added per unit of attackPathDepth (max cap: 15). */
const DEPTH_BONUS_PER_LEVEL = 5
const MAX_DEPTH_BONUS = 15

/** Bonus when a template's affinity keyword matches a detected service / layer. */
const AFFINITY_BONUS = 10

function depthBonus(attackPathDepth: number): number {
  return Math.min(MAX_DEPTH_BONUS, attackPathDepth * DEPTH_BONUS_PER_LEVEL)
}

function hasAffinity(keywords: string[], candidates: string[]): boolean {
  const normalised = candidates.map((c) => c.toLowerCase())
  return keywords.some((kw) => normalised.some((c) => c.includes(kw)))
}

function findMatchingContext(keywords: string[], candidates: string[]): string | undefined {
  return candidates.find((c) => keywords.some((kw) => c.toLowerCase().includes(kw)))
}

// ─── Main computation ─────────────────────────────────────────────────────────

/**
 * Generates a full honeypot placement plan for a repository.
 *
 * Placement is driven by the repository's blast radius data (reachableServices,
 * exposedDataLayers, attackPathDepth). Templates are ranked by attractiveness
 * — a blend of inherent target appeal and affinity with the detected context —
 * and the top candidates are returned as the proposed decoy set.
 */
export function computeHoneypotPlan(input: HoneypotInput): HoneypotPlanResult {
  const bonus = depthBonus(input.attackPathDepth)

  const proposals: HoneypotProposal[] = []

  // ── Endpoint proposals (always; top 4 by score) ───────────────────────────
  const rankedEndpoints = ENDPOINT_TEMPLATES.map((t) => {
    const affinity = hasAffinity(t.affinityKeywords, input.reachableServices)
    const score = Math.min(100, t.baseScore + (affinity ? AFFINITY_BONUS : 0) + bonus)
    const ctx = findMatchingContext(t.affinityKeywords, input.reachableServices)
    return { t, score, ctx }
  })
    .sort((a, b) => b.score - a.score)
    .slice(0, 4)

  for (const { t, score, ctx } of rankedEndpoints) {
    proposals.push({
      kind: 'endpoint',
      path: t.path,
      description: t.description,
      rationale: ctx
        ? `Placed adjacent to the "${ctx}" service identified in the blast radius graph`
        : 'Standard high-value canary endpoint for attacker-reconnaissance detection',
      targetContext: ctx,
      attractivenessScore: score,
    })
  }

  // ── Database field proposals (only if data layers exist; top 2) ───────────
  if (input.exposedDataLayers.length > 0) {
    const rankedFields = DB_FIELD_TEMPLATES.map((t) => {
      const affinity = hasAffinity(t.affinityKeywords, input.exposedDataLayers)
      const score = Math.min(100, t.baseScore + (affinity ? AFFINITY_BONUS : 0) + bonus)
      const ctx =
        findMatchingContext(t.affinityKeywords, input.exposedDataLayers) ??
        input.exposedDataLayers[0]
      return { t, score, ctx }
    })
      .sort((a, b) => b.score - a.score)
      .slice(0, 2)

    for (const { t, score, ctx } of rankedFields) {
      proposals.push({
        kind: 'database_field',
        path: t.path,
        description: t.description,
        rationale: `Injected into the "${ctx}" data layer to trigger an alert on any unauthorised SELECT`,
        targetContext: ctx,
        attractivenessScore: score,
      })
    }
  }

  // ── File proposals (always; top 3 by base score) ──────────────────────────
  const topFiles = FILE_TEMPLATES.slice(0, 3)
  for (const t of topFiles) {
    proposals.push({
      kind: 'file',
      path: t.path,
      description: t.description,
      rationale: 'Canary file targeting attacker filesystem reconnaissance and backup-hunting patterns',
      targetContext: undefined,
      attractivenessScore: Math.min(100, t.baseScore + bonus),
    })
  }

  // ── Token proposals (only when attack path is deep, indicating lateral movement risk) ─
  if (input.attackPathDepth >= 2) {
    for (const t of TOKEN_TEMPLATES) {
      proposals.push({
        kind: 'token',
        path: t.path,
        description: t.description,
        rationale: 'Beacon token for detecting lateral movement through internal document access',
        targetContext: undefined,
        attractivenessScore: Math.min(100, t.baseScore + bonus),
      })
    }
  }

  // Sort descending by attractiveness
  proposals.sort((a, b) => b.attractivenessScore - a.attractivenessScore)

  const endpointCount = proposals.filter((p) => p.kind === 'endpoint').length
  const fileCount = proposals.filter((p) => p.kind === 'file').length
  const databaseFieldCount = proposals.filter((p) => p.kind === 'database_field').length
  const tokenCount = proposals.filter((p) => p.kind === 'token').length
  const topAttractiveness = proposals[0]?.attractivenessScore ?? 0

  const summary =
    `Generated ${proposals.length} honeypot proposal${proposals.length !== 1 ? 's' : ''} ` +
    `(${endpointCount} endpoint${endpointCount !== 1 ? 's' : ''}, ` +
    `${fileCount} file${fileCount !== 1 ? 's' : ''}, ` +
    `${databaseFieldCount} DB field${databaseFieldCount !== 1 ? 's' : ''}, ` +
    `${tokenCount} token${tokenCount !== 1 ? 's' : ''}) ` +
    `with peak attractiveness score ${topAttractiveness}/100.`

  return {
    proposals,
    totalProposals: proposals.length,
    endpointCount,
    fileCount,
    databaseFieldCount,
    tokenCount,
    topAttractiveness,
    summary,
  }
}
