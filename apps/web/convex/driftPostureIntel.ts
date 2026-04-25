/**
 * WS-96 — Configuration Drift Aggregate Health Score: Convex entrypoints.
 *
 * Reads the latest result from all 41 configuration-drift scanner tables
 * (WS-60 through WS-109) and produces a single weighted 0–100 drift posture
 * score with an A–F grade, per-category breakdown, and trend direction.
 *
 * Triggered fire-and-forget from events.ts on every push (runAfter 3000ms so
 * most individual drift scans have a chance to persist first).
 *
 * Entrypoints:
 *   recordDriftPostureScan          — internalMutation: aggregate + persist
 *   triggerDriftPostureForRepository — public mutation: on-demand by slug+fullName
 *   getLatestDriftPosture           — public query: most recent result for a repo
 *   getLatestDriftPostureBySlug     — public query: slug-based (dashboard/HTTP)
 *   getDriftPostureHistory          — public query: last 30 lean summaries
 *   getDriftPostureSummaryByTenant  — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { computeDriftPostureScore } from './lib/driftPostureScore'

const MAX_ROWS_PER_REPO = 30

// ---------------------------------------------------------------------------
// recordDriftPostureScan — internalMutation
// ---------------------------------------------------------------------------

export const recordDriftPostureScan = internalMutation({
  args: {
    tenantId:     v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { tenantId, repositoryId }) => {
    // Read latest from all 41 drift tables in parallel
    const [
      ws60, ws61, ws62, ws63, ws64, ws65, ws66, ws67, ws68, ws69,
      ws70, ws71, ws72, ws73, ws74, ws75, ws76, ws77, ws78, ws79,
      ws80, ws81, ws82, ws83, ws84, ws85, ws86, ws87, ws88, ws89,
      ws90, ws91, ws92, ws93, ws94, ws95, ws101, ws103, ws105, ws107, ws109,
    ] = await Promise.all([
      ctx.db.query('securityConfigDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('testCoverageGapResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('cloudSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('containerHardeningDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('databaseSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('apiSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('certPkiDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('runtimeSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('networkFirewallDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('devSecToolsDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('identityAccessDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('observabilitySecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('serviceMeshSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('cicdPipelineSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('mobileAppSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('webServerSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('emailSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('serverlessFaasDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('messagingSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('ssoProviderDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('dataPipelineDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('mlAiPlatformDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('artifactRegistryDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('cfgMgmtSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('vpnRemoteAccessDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('backupDrSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('siemSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('storageDataSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('dnsSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('osSecurityHardeningDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('wirelessRadiusDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('iotEmbeddedSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('virtualizationSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('voipSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('networkMonitoringDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('endpointSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('aiMlSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('depMgrSecurityDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('secretMgmtDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('k8sAdmissionDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
      ctx.db.query('supplyChainAttestationDriftResults').withIndex('by_repository_and_scanned_at', (q) => q.eq('repositoryId', repositoryId)).order('desc').first(),
    ])

    // Previous score for trend
    const previous = await ctx.db
      .query('driftPostureResults')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()

    const report = computeDriftPostureScore(
      {
        ws60_riskScore: ws60?.riskScore ?? null, ws60_riskLevel: ws60?.riskLevel ?? null,
        ws61_riskScore: ws61?.riskScore ?? null, ws61_riskLevel: ws61?.riskLevel ?? null,
        ws62_riskScore: ws62?.riskScore ?? null, ws62_riskLevel: ws62?.riskLevel ?? null,
        ws63_riskScore: ws63?.riskScore ?? null, ws63_riskLevel: ws63?.riskLevel ?? null,
        ws64_riskScore: ws64?.riskScore ?? null, ws64_riskLevel: ws64?.riskLevel ?? null,
        ws65_riskScore: ws65?.riskScore ?? null, ws65_riskLevel: ws65?.riskLevel ?? null,
        ws66_riskScore: ws66?.riskScore ?? null, ws66_riskLevel: ws66?.riskLevel ?? null,
        ws67_riskScore: ws67?.riskScore ?? null, ws67_riskLevel: ws67?.riskLevel ?? null,
        ws68_riskScore: ws68?.riskScore ?? null, ws68_riskLevel: ws68?.riskLevel ?? null,
        ws69_riskScore: ws69?.riskScore ?? null, ws69_riskLevel: ws69?.riskLevel ?? null,
        ws70_riskScore: ws70?.riskScore ?? null, ws70_riskLevel: ws70?.riskLevel ?? null,
        ws71_riskScore: ws71?.riskScore ?? null, ws71_riskLevel: ws71?.riskLevel ?? null,
        ws72_riskScore: ws72?.riskScore ?? null, ws72_riskLevel: ws72?.riskLevel ?? null,
        ws73_riskScore: ws73?.riskScore ?? null, ws73_riskLevel: ws73?.riskLevel ?? null,
        ws74_riskScore: ws74?.riskScore ?? null, ws74_riskLevel: ws74?.riskLevel ?? null,
        ws75_riskScore: ws75?.riskScore ?? null, ws75_riskLevel: ws75?.riskLevel ?? null,
        ws76_riskScore: ws76?.riskScore ?? null, ws76_riskLevel: ws76?.riskLevel ?? null,
        ws77_riskScore: ws77?.riskScore ?? null, ws77_riskLevel: ws77?.riskLevel ?? null,
        ws78_riskScore: ws78?.riskScore ?? null, ws78_riskLevel: ws78?.riskLevel ?? null,
        ws79_riskScore: ws79?.riskScore ?? null, ws79_riskLevel: ws79?.riskLevel ?? null,
        ws80_riskScore: ws80?.riskScore ?? null, ws80_riskLevel: ws80?.riskLevel ?? null,
        ws81_riskScore: ws81?.riskScore ?? null, ws81_riskLevel: ws81?.riskLevel ?? null,
        ws82_riskScore: ws82?.riskScore ?? null, ws82_riskLevel: ws82?.riskLevel ?? null,
        ws83_riskScore: ws83?.riskScore ?? null, ws83_riskLevel: ws83?.riskLevel ?? null,
        ws84_riskScore: ws84?.riskScore ?? null, ws84_riskLevel: ws84?.riskLevel ?? null,
        ws85_riskScore: ws85?.riskScore ?? null, ws85_riskLevel: ws85?.riskLevel ?? null,
        ws86_riskScore: ws86?.riskScore ?? null, ws86_riskLevel: ws86?.riskLevel ?? null,
        ws87_riskScore: ws87?.riskScore ?? null, ws87_riskLevel: ws87?.riskLevel ?? null,
        ws88_riskScore: ws88?.riskScore ?? null, ws88_riskLevel: ws88?.riskLevel ?? null,
        ws89_riskScore: ws89?.riskScore ?? null, ws89_riskLevel: ws89?.riskLevel ?? null,
        ws90_riskScore: ws90?.riskScore ?? null, ws90_riskLevel: ws90?.riskLevel ?? null,
        ws91_riskScore: ws91?.riskScore ?? null, ws91_riskLevel: ws91?.riskLevel ?? null,
        ws92_riskScore: ws92?.riskScore ?? null, ws92_riskLevel: ws92?.riskLevel ?? null,
        ws93_riskScore: ws93?.riskScore ?? null, ws93_riskLevel: ws93?.riskLevel ?? null,
        ws94_riskScore: ws94?.riskScore ?? null, ws94_riskLevel: ws94?.riskLevel ?? null,
        ws95_riskScore: ws95?.riskScore ?? null, ws95_riskLevel: ws95?.riskLevel ?? null,
        ws101_riskScore: ws101?.riskScore ?? null, ws101_riskLevel: ws101?.riskLevel ?? null,
        ws103_riskScore: ws103?.riskScore ?? null, ws103_riskLevel: ws103?.riskLevel ?? null,
        ws105_riskScore: ws105?.riskScore ?? null, ws105_riskLevel: ws105?.riskLevel ?? null,
        ws107_riskScore: ws107?.riskScore ?? null, ws107_riskLevel: ws107?.riskLevel ?? null,
        ws109_riskScore: ws109?.riskScore ?? null, ws109_riskLevel: ws109?.riskLevel ?? null,
      },
      previous?.overallScore ?? null,
    )

    await ctx.db.insert('driftPostureResults', {
      tenantId,
      repositoryId,
      overallScore:             report.overallScore,
      overallGrade:             report.overallGrade,
      trend:                    report.trend,
      categoryScores:           report.categoryScores,
      totalWorkstreamsScanned:  report.totalWorkstreamsScanned,
      criticalDriftCount:       report.criticalDriftCount,
      highDriftCount:           report.highDriftCount,
      topRisks:                 report.topRisks,
      summary:                  report.summary,
      computedAt:               Date.now(),
    })

    // Prune to MAX_ROWS_PER_REPO
    const all = await ctx.db
      .query('driftPostureResults')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .collect()
    if (all.length > MAX_ROWS_PER_REPO) {
      for (const old of all.slice(MAX_ROWS_PER_REPO)) {
        await ctx.db.delete(old._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerDriftPostureForRepository — public mutation
// ---------------------------------------------------------------------------

export const triggerDriftPostureForRepository = mutation({
  args: {
    tenantSlug:         v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repository) return

    // Inline re-run (mirrors internalMutation logic for public access)
    await ctx.scheduler.runAfter(0, 'driftPostureIntel:recordDriftPostureScan' as any, {
      tenantId:     tenant._id,
      repositoryId: repository._id,
    })
  },
})

// ---------------------------------------------------------------------------
// getLatestDriftPosture — public query
// ---------------------------------------------------------------------------

export const getLatestDriftPosture = query({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('driftPostureResults')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getLatestDriftPostureBySlug — public query (dashboard + HTTP)
// ---------------------------------------------------------------------------

export const getLatestDriftPostureBySlug = query({
  args: {
    tenantSlug:         v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .first()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .first()
    if (!repository) return null

    return ctx.db
      .query('driftPostureResults')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repository._id))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getDriftPostureHistory — public query (lean, no category details)
// ---------------------------------------------------------------------------

export const getDriftPostureHistory = query({
  args: {
    repositoryId: v.id('repositories'),
    limit:        v.optional(v.number()),
  },
  handler: async (ctx, { repositoryId, limit = 30 }) => {
    const rows = await ctx.db
      .query('driftPostureResults')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(limit)
    return rows.map((r) => ({
      _id:                    r._id,
      overallScore:           r.overallScore,
      overallGrade:           r.overallGrade,
      trend:                  r.trend,
      criticalDriftCount:     r.criticalDriftCount,
      highDriftCount:         r.highDriftCount,
      totalWorkstreamsScanned: r.totalWorkstreamsScanned,
      summary:                r.summary,
      computedAt:             r.computedAt,
    }))
  },
})

// ---------------------------------------------------------------------------
// getDriftPostureSummaryByTenant — public query
// ---------------------------------------------------------------------------

export const getDriftPostureSummaryByTenant = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    const rows = await ctx.db
      .query('driftPostureResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(200)

    // One result per repository (latest only)
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const r of rows) {
      const key = r.repositoryId.toString()
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(r)
      }
    }

    const gradeA  = latest.filter((r) => r.overallGrade === 'A').length
    const gradeB  = latest.filter((r) => r.overallGrade === 'B').length
    const gradeC  = latest.filter((r) => r.overallGrade === 'C').length
    const gradeDF = latest.filter((r) => r.overallGrade === 'D' || r.overallGrade === 'F').length
    const criticalRepos = latest.filter((r) => r.criticalDriftCount > 0).length
    const avgScore = latest.length > 0
      ? Math.round(latest.reduce((a, r) => a + r.overallScore, 0) / latest.length)
      : null

    const worst = [...latest].sort((a, b) => a.overallScore - b.overallScore)[0]

    return {
      totalRepositories: latest.length,
      gradeA,
      gradeB,
      gradeC,
      gradeDF,
      criticalRepos,
      avgScore,
      worstRepositoryId: worst?.repositoryId ?? null,
      worstScore:        worst?.overallScore ?? null,
    }
  },
})
