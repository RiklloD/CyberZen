import { v } from 'convex/values'
import { paginationOptsValidator } from 'convex/server'
import {
  internalAction,
  internalMutation,
  internalQuery,
  mutation,
  query,
} from './_generated/server'
import { internal } from './_generated/api'
import type { ActionCtx } from './_generated/server'
import type { Doc, Id } from './_generated/dataModel'

// ─── Risk Scoring ─────────────────────────────────────────────────────────────
//
// This function is the product heart of the Vendor Trust feature.
// It converts raw signals into the 0–100 score that drives every
// alert, recommendation, and dashboard badge customers see.
//
// TODO: Implement computeVendorRiskScore below (5–10 lines of logic).
// See the request at the bottom of this file for full context.

/**
 * Computes a 0–100 vendor risk score from runtime signals.
 * Higher = riskier. Drives `riskLevel` and `recommendation` on every snapshot.
 *
 * @param inputs.accessLevel        'admin' carries significantly more weight
 * @param inputs.dataCategories     'env_vars' / 'source_code' are critical
 * @param inputs.grantedScopesCount more scopes = wider blast radius per vendor
 * @param inputs.darkWebMentions    any match in the last 30 days is a red flag
 * @param inputs.credentialDumpMatches direct evidence of exfiltrated credentials
 * @param inputs.daysSinceLastVerified stale integrations accumulate undetected drift
 */
function computeVendorRiskScore(inputs: {
  accessLevel: 'read_only' | 'read_write' | 'admin' | 'unknown'
  dataCategories: string[]
  grantedScopesCount: number
  darkWebMentions: number
  credentialDumpMatches: number
  daysSinceLastVerified: number
}): number {
  let score = 0

  // 1. Access level baseline — admin blast radius is disproportionately larger.
  //    'unknown' treated conservatively: we can't audit what we can't see.
  const accessBase: Record<string, number> = {
    admin: 30, unknown: 20, read_write: 15, read_only: 5,
  }
  score += accessBase[inputs.accessLevel] ?? 20

  // 2. Critical data exposure — env_vars / source_code is the Vercel failure mode.
  //    Any vendor that can read secrets or code gets a significant baseline bump.
  const hasCriticalData = inputs.dataCategories.some(d =>
    ['env_vars', 'source_code', 'credentials', 'secrets'].includes(d),
  )
  if (hasCriticalData) score += 20

  // 3. Scope breadth on a log scale — 40 scopes is not 8× riskier than 5 scopes,
  //    but it does represent a wider attack surface that deserves a medium floor.
  //    Cap at 25 so this never dominates over breach signals.
  score += Math.min(25, Math.round(Math.log2(inputs.grantedScopesCount + 1) * 5))

  // 4. Breach signals — additive with a per-source cap so a single noisy feed
  //    can't manufacture a critical alert on its own.
  //    Dark web: 3+ mentions reaches the contribution ceiling.
  //    Credential dump: 1 match is serious; 2 pushes into critical territory alone.
  score += Math.min(25, inputs.darkWebMentions * 10)
  score += Math.min(60, inputs.credentialDumpMatches * 30)

  // 5. Staleness penalty — plateaus at 90 days so an ancient integration doesn't
  //    accumulate infinite score. The hard floor below handles persistent risk.
  score += Math.min(10, Math.floor(inputs.daysSinceLastVerified / 9))

  // 6. Compound staleness × breach signal — a stale integration appearing in any
  //    dark-web feed is riskier than either factor alone (unaudited drift + exposure).
  if (inputs.daysSinceLastVerified > 30 && inputs.darkWebMentions > 0) score += 10

  // 7. Hard floor: non-read-only access to critical data is always at least medium.
  //    This is the "nothing bad has happened yet" guard — the exact blind spot
  //    that let the Context AI → Vercel pivot go undetected.
  if (hasCriticalData && inputs.accessLevel !== 'read_only') {
    score = Math.max(score, 40)
  }

  return Math.min(100, score)
}

// ─── Derived helpers ──────────────────────────────────────────────────────────

function scoreToLevel(
  score: number,
): 'critical' | 'high' | 'medium' | 'low' | 'trusted' {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'trusted'
}

function levelToRecommendation(
  level: 'critical' | 'high' | 'medium' | 'low' | 'trusted',
  breachDetected: boolean,
): 'no_action' | 'monitor' | 'review_scopes' | 'revoke_immediately' {
  if (breachDetected && level === 'critical') return 'revoke_immediately'
  if (level === 'critical' || level === 'high') return 'review_scopes'
  if (level === 'medium') return 'monitor'
  return 'no_action'
}

// ─── Core assessment logic ────────────────────────────────────────────────────
// Extracted into a plain async function so both assessVendorRisk (single) and
// sweepVendorRisk (batch) can call it directly — avoiding an action-to-action
// hop per Convex guidelines.

async function runVendorAssessment(
  ctx: ActionCtx,
  tenantId: Id<'tenants'>,
  vendor: Doc<'connectedVendors'>,
): Promise<void> {
  const LOOKBACK_MS = 30 * 24 * 60 * 60 * 1000 // 30-day window

  // 1. Check tier3ThreatSignals for dark-web / Telegram / paste-site mentions
  const threatSignals: Array<Doc<'tier3ThreatSignals'>> =
    await ctx.runQuery(internal.vendorTrust.getThreatSignalsForVendor, {
      vendorName: vendor.name,
      lookbackMs: LOOKBACK_MS,
    })

  const darkWebMentions = threatSignals.filter(
    s => s.source === 'dark_web',
  ).length
  const credentialDumpMatches = threatSignals.filter(
    s => s.hasCredentialPattern,
  ).length
  const breachDetected = darkWebMentions > 0 || credentialDumpMatches > 0

  // Top signals for the snapshot (skip low-severity noise, cap at 10)
  const signals = threatSignals
    .filter(s => s.threatLevel !== 'low')
    .slice(0, 10)
    .map(s => ({
      kind: s.source as string,
      severity: s.threatLevel,
      description: s.text.slice(0, 200),
      detectedAt: s.capturedAt,
    }))

  // 2. Scope-creep detection — diff current scopes against last snapshot
  const prevSnapshot: Doc<'vendorRiskSnapshots'> | null =
    await ctx.runQuery(internal.vendorTrust.getLatestSnapshotForVendor, {
      vendorId: vendor._id,
    })
  const prevScopeSet = new Set(prevSnapshot?.snapshotScopes ?? [])
  // On the first assessment prevSnapshot is null — no prior baseline to diff against,
  // so newScopes is empty by definition (nothing was "added" relative to nothing).
  const newScopes =
    prevSnapshot !== null
      ? vendor.grantedScopes.filter(s => !prevScopeSet.has(s))
      : []
  const scopeCreepDetected = prevSnapshot !== null && newScopes.length > 0

  // 3. Staleness — days since the integration was last verified
  const daysSinceLastVerified = vendor.lastVerifiedAt
    ? (Date.now() - vendor.lastVerifiedAt) / 86_400_000
    : 999

  // 4. Score → level → recommendation
  const riskScore = computeVendorRiskScore({
    accessLevel: vendor.accessLevel,
    dataCategories: vendor.dataCategories,
    grantedScopesCount: vendor.grantedScopes.length,
    darkWebMentions,
    credentialDumpMatches,
    daysSinceLastVerified,
  })

  const riskLevel = scoreToLevel(riskScore)
  const recommendation = levelToRecommendation(riskLevel, breachDetected)

  const lastKnownBreachAt =
    threatSignals.length > 0
      ? Math.max(...threatSignals.map(s => s.capturedAt))
      : undefined

  // 5. Persist snapshot and refresh lastVerifiedAt on the vendor profile
  await ctx.runMutation(internal.vendorTrust.upsertRiskSnapshot, {
    tenantId,
    vendorId: vendor._id,
    riskScore,
    riskLevel,
    breachDetected,
    breachSummary: breachDetected
      ? `${darkWebMentions} dark-web mention(s), ${credentialDumpMatches} credential-dump match(es) in the last 30 days`
      : undefined,
    scopeCreepDetected,
    snapshotScopes: vendor.grantedScopes,
    newScopes,
    darkWebMentions,
    credentialDumpMatches,
    lastKnownBreachAt,
    signals,
    recommendation,
  })
}

// ─── Public mutations ─────────────────────────────────────────────────────────

/** Register a new third-party SaaS / OAuth integration for a tenant. */
export const registerVendor = mutation({
  args: {
    tenantId: v.id('tenants'),
    name: v.string(),
    category: v.union(
      v.literal('ai_tool'),
      v.literal('observability'),
      v.literal('auth_provider'),
      v.literal('database'),
      v.literal('ci_cd'),
      v.literal('communication'),
      v.literal('security'),
      v.literal('other'),
    ),
    authMethod: v.union(
      v.literal('oauth2'),
      v.literal('api_key'),
      v.literal('service_account'),
      v.literal('webhook_secret'),
      v.literal('basic_auth'),
    ),
    accessLevel: v.union(
      v.literal('read_only'),
      v.literal('read_write'),
      v.literal('admin'),
      v.literal('unknown'),
    ),
    grantedScopes: v.array(v.string()),
    dataCategories: v.array(v.string()),
    grantedAt: v.optional(v.number()),
    notes: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert('connectedVendors', {
      ...args,
      status: 'active',
      addedAt: Date.now(),
    })
  },
})

/** Revoke or suspend a vendor integration. */
export const updateVendorStatus = mutation({
  args: {
    vendorId: v.id('connectedVendors'),
    status: v.union(
      v.literal('active'),
      v.literal('revoked'),
      v.literal('suspended'),
    ),
    notes: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.vendorId, {
      status: args.status,
      ...(args.notes !== undefined ? { notes: args.notes } : {}),
    })
  },
})

/**
 * Update the granted scopes for a vendor.
 * Scope-creep is detected lazily on the next risk sweep — this mutation
 * stays fast and atomic by not computing risk inline.
 */
export const updateVendorScopes = mutation({
  args: {
    vendorId: v.id('connectedVendors'),
    grantedScopes: v.array(v.string()),
    dataCategories: v.optional(v.array(v.string())),
  },
  handler: async (ctx, args) => {
    await ctx.db.patch(args.vendorId, {
      grantedScopes: args.grantedScopes,
      ...(args.dataCategories !== undefined
        ? { dataCategories: args.dataCategories }
        : {}),
    })
  },
})

// ─── Public queries ───────────────────────────────────────────────────────────

/**
 * List all vendors for a tenant, each enriched with their latest risk snapshot.
 * Optionally filter by status (default: all statuses).
 */
export const listVendors = query({
  args: {
    tenantId: v.id('tenants'),
    status: v.optional(
      v.union(
        v.literal('active'),
        v.literal('revoked'),
        v.literal('suspended'),
      ),
    ),
  },
  handler: async (ctx, args) => {
    const vendors = args.status
      ? await ctx.db
          .query('connectedVendors')
          .withIndex('by_tenant_and_status', q =>
            q.eq('tenantId', args.tenantId).eq('status', args.status!),
          )
          .take(100)
      : await ctx.db
          .query('connectedVendors')
          .withIndex('by_tenant', q => q.eq('tenantId', args.tenantId))
          .take(100)

    return await Promise.all(
      vendors.map(async vendor => {
        const latestRisk = await ctx.db
          .query('vendorRiskSnapshots')
          .withIndex('by_vendor_and_computed_at', q =>
            q.eq('vendorId', vendor._id),
          )
          .order('desc')
          .first()
        return { ...vendor, latestRisk: latestRisk ?? null }
      }),
    )
  },
})

/** Paginated risk-assessment history for a single vendor. */
export const getVendorRiskHistory = query({
  args: {
    vendorId: v.id('connectedVendors'),
    paginationOpts: paginationOptsValidator,
  },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('vendorRiskSnapshots')
      .withIndex('by_vendor_and_computed_at', q =>
        q.eq('vendorId', args.vendorId),
      )
      .order('desc')
      .paginate(args.paginationOpts)
  },
})

/**
 * Slug-based variant of listVendors — used by the global dashboard panel.
 * Resolves tenant by slug then returns all vendors enriched with their
 * latest risk snapshot (bounded at 100).
 */
export const listVendorsBySlug = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', q => q.eq('slug', args.tenantSlug))
      .first()
    if (!tenant) return null

    const vendors = await ctx.db
      .query('connectedVendors')
      .withIndex('by_tenant', q => q.eq('tenantId', tenant._id))
      .take(100)

    return await Promise.all(
      vendors.map(async vendor => {
        const latestRisk = await ctx.db
          .query('vendorRiskSnapshots')
          .withIndex('by_vendor_and_computed_at', q =>
            q.eq('vendorId', vendor._id),
          )
          .order('desc')
          .first()
        return { ...vendor, latestRisk: latestRisk ?? null }
      }),
    )
  },
})

/** Most recent risk snapshots across all vendors for a tenant — useful for the dashboard. */
export const listLatestRiskByTenant = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('vendorRiskSnapshots')
      .withIndex('by_tenant_and_computed_at', q =>
        q.eq('tenantId', args.tenantId),
      )
      .order('desc')
      .take(50)
  },
})

// ─── Internal queries ─────────────────────────────────────────────────────────

export const getVendorById = internalQuery({
  args: { vendorId: v.id('connectedVendors') },
  handler: async (ctx, args) => {
    return await ctx.db.get(args.vendorId)
  },
})

export const getLatestSnapshotForVendor = internalQuery({
  args: { vendorId: v.id('connectedVendors') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('vendorRiskSnapshots')
      .withIndex('by_vendor_and_computed_at', q =>
        q.eq('vendorId', args.vendorId),
      )
      .order('desc')
      .first()
  },
})

export const listActiveVendorsForSweep = internalQuery({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    return await ctx.db
      .query('connectedVendors')
      .withIndex('by_tenant_and_status', q =>
        q.eq('tenantId', args.tenantId).eq('status', 'active'),
      )
      .take(200)
  },
})

/**
 * Fetch tier3ThreatSignals that mention a vendor name.
 * Uses a time-bounded index scan + in-memory text filter since
 * tier3ThreatSignals has no full-text search index.
 * (Add a searchIndex on `text` if signal volume grows beyond ~10k/30d.)
 */
export const getThreatSignalsForVendor = internalQuery({
  args: {
    vendorName: v.string(),
    lookbackMs: v.number(),
  },
  handler: async (ctx, args) => {
    const since = Date.now() - args.lookbackMs
    const recentSignals = await ctx.db
      .query('tier3ThreatSignals')
      .withIndex('by_captured_at', q => q.gte('capturedAt', since))
      .take(500)
    const nameLower = args.vendorName.toLowerCase()
    return recentSignals.filter(
      s =>
        s.text.toLowerCase().includes(nameLower) ||
        s.packageMentions.some(p => p.toLowerCase().includes(nameLower)),
    )
  },
})

// ─── Internal mutations ───────────────────────────────────────────────────────

export const upsertRiskSnapshot = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    vendorId: v.id('connectedVendors'),
    riskScore: v.number(),
    riskLevel: v.union(
      v.literal('critical'),
      v.literal('high'),
      v.literal('medium'),
      v.literal('low'),
      v.literal('trusted'),
    ),
    breachDetected: v.boolean(),
    breachSummary: v.optional(v.string()),
    scopeCreepDetected: v.boolean(),
    snapshotScopes: v.array(v.string()),
    newScopes: v.array(v.string()),
    darkWebMentions: v.number(),
    credentialDumpMatches: v.number(),
    lastKnownBreachAt: v.optional(v.number()),
    signals: v.array(
      v.object({
        kind: v.string(),
        severity: v.union(
          v.literal('critical'),
          v.literal('high'),
          v.literal('medium'),
          v.literal('low'),
        ),
        description: v.string(),
        detectedAt: v.number(),
      }),
    ),
    recommendation: v.union(
      v.literal('no_action'),
      v.literal('monitor'),
      v.literal('review_scopes'),
      v.literal('revoke_immediately'),
    ),
  },
  handler: async (ctx, args) => {
    const now = Date.now()
    await ctx.db.insert('vendorRiskSnapshots', { ...args, computedAt: now })
    // Keep the vendor profile's lastVerifiedAt in sync
    await ctx.db.patch(args.vendorId, { lastVerifiedAt: now })
  },
})

// ─── Internal actions ─────────────────────────────────────────────────────────

/** Assess risk for a single vendor. Can be called on-demand after registration. */
export const assessVendorRisk = internalAction({
  args: {
    tenantId: v.id('tenants'),
    vendorId: v.id('connectedVendors'),
  },
  handler: async (ctx, args) => {
    const vendor: Doc<'connectedVendors'> | null = await ctx.runQuery(
      internal.vendorTrust.getVendorById,
      { vendorId: args.vendorId },
    )
    if (!vendor || vendor.status !== 'active') return
    await runVendorAssessment(ctx, args.tenantId, vendor)
  },
})

/**
 * Assess all active vendors for a tenant.
 * Intended to be called by the daily cron via:
 *   ctx.runAction(internal.vendorTrust.sweepVendorRisk, { tenantId })
 */
export const sweepVendorRisk = internalAction({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, args) => {
    const vendors: Array<Doc<'connectedVendors'>> = await ctx.runQuery(
      internal.vendorTrust.listActiveVendorsForSweep,
      { tenantId: args.tenantId },
    )
    for (const vendor of vendors) {
      await runVendorAssessment(ctx, args.tenantId, vendor)
    }
  },
})

/**
 * Cron target — fans out `sweepVendorRisk` across every active tenant.
 * Runs daily; each per-tenant sweep is dispatched as an independent scheduled
 * action so failures are isolated and retried without blocking the others.
 */
export const sweepAllTenantsVendorRisk = internalMutation({
  args: {},
  handler: async (ctx) => {
    const tenants = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('status'), 'active'))
      .take(200)

    for (const tenant of tenants) {
      await ctx.scheduler.runAfter(
        0,
        internal.vendorTrust.sweepVendorRisk,
        { tenantId: tenant._id },
      )
    }
  },
})
