/**
 * WS-26 — LLM-Native Application Security Certification (spec §10 Phase 4)
 *
 * Convex entrypoints.
 *
 *   refreshCertification          — internalMutation: fetches snapshots from all
 *       7 source tables, runs computeCertificationResult, inserts a new report.
 *       Prunes old reports > 20 per repository.
 *
 *   refreshCertificationForRepository — public mutation: dashboard trigger.
 *
 *   getLatestCertificationReport  — query: latest report with full domain results.
 *
 *   getTenantCertificationSummary — query: tenant-wide tier distribution +
 *       aggregate score.
 */

import { internalMutation, mutation, query } from './_generated/server'
import { internal } from './_generated/api'
import { v } from 'convex/values'
import { computeCertificationResult, type CertificationInput } from './lib/llmCertification'

// ── refreshCertification (internal) ──────────────────────────────────────────

export const refreshCertification = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const repository = await ctx.db.get(repositoryId)
    if (!repository) throw new Error(`Repository ${repositoryId} not found`)

    // ── Fetch all 7 signal sources in parallel ──────────────────────────────

    const [
      latestInjectionScan,
      supplyChainRows,
      latestAgenticScan,
      exploitRuns,
      latestRegulatoryDrift,
      latestAttackSurface,
      latestSnapshot,
    ] = await Promise.all([
      // 1. Prompt injection — most recent scan
      ctx.db
        .query('promptInjectionScans')
        .withIndex('by_repository_and_scanned_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // 2. Supply chain analyses — up to 100 latest (deduplicate by package below)
      ctx.db
        .query('supplyChainAnalyses')
        .withIndex('by_repository_and_analyzed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .take(100),

      // 3. Agentic workflow scans — most recent
      ctx.db
        .query('agenticWorkflowScans')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // 4. Exploit validation runs — up to 50 recent
      ctx.db
        .query('exploitValidationRuns')
        .withIndex('by_repository_and_started_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .take(50),

      // 5. Regulatory drift — most recent snapshot
      ctx.db
        .query('regulatoryDriftSnapshots')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // 6. Attack surface — most recent snapshot
      ctx.db
        .query('attackSurfaceSnapshots')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // 7. SBOM snapshot — most recent (to look up components)
      ctx.db
        .query('sbomSnapshots')
        .withIndex('by_repository_and_captured_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),
    ])

    // ── SBOM component trust aggregation ─────────────────────────────────────
    let dependencyTrust: CertificationInput['dependencyTrust'] = null
    if (latestSnapshot) {
      const components = await ctx.db
        .query('sbomComponents')
        .withIndex('by_snapshot', (q) => q.eq('snapshotId', latestSnapshot._id))
        .take(500)

      if (components.length > 0) {
        const avgTrustScore = Math.round(
          components.reduce((sum, c) => sum + c.trustScore, 0) / components.length,
        )
        const untrustedCount = components.filter((c) => c.trustScore < 30).length
        dependencyTrust = { avgTrustScore, untrustedCount, totalComponents: components.length }
      }
    }

    // ── Supply chain aggregation — deduplicate by package name ───────────────
    let supplyChain: CertificationInput['supplyChain'] = null
    if (supplyChainRows.length > 0) {
      const seenPackages = new Set<string>()
      const latestPerPackage = supplyChainRows.filter((row) => {
        if (seenPackages.has(row.packageName)) return false
        seenPackages.add(row.packageName)
        return true
      })

      const RISK_ORDER = ['compromised', 'suspicious', 'at_risk', 'monitor', 'trusted']
      const compromisedCount = latestPerPackage.filter((r) => r.overallRiskLevel === 'compromised').length
      const suspiciousCount  = latestPerPackage.filter((r) => r.overallRiskLevel === 'suspicious').length
      const atRiskCount      = latestPerPackage.filter((r) => r.overallRiskLevel === 'at_risk').length

      let highestRiskLevel = 'trusted'
      for (const pkg of latestPerPackage) {
        if (RISK_ORDER.indexOf(pkg.overallRiskLevel) < RISK_ORDER.indexOf(highestRiskLevel)) {
          highestRiskLevel = pkg.overallRiskLevel
        }
      }

      supplyChain = {
        totalPackages: latestPerPackage.length,
        compromisedCount,
        suspiciousCount,
        atRiskCount,
        highestRiskLevel,
      }
    }

    // ── Exploit validation aggregation ────────────────────────────────────────
    let exploitValidation: CertificationInput['exploitValidation'] = null
    if (exploitRuns.length > 0) {
      const validatedCount        = exploitRuns.filter((r) => r.outcome === 'validated').length
      const likelyExploitableCount = exploitRuns.filter((r) => r.outcome === 'likely_exploitable').length
      exploitValidation = { totalRuns: exploitRuns.length, validatedCount, likelyExploitableCount }
    }

    // ── Build certification input ─────────────────────────────────────────────
    const input: CertificationInput = {
      promptInjection: latestInjectionScan
        ? { riskLevel: latestInjectionScan.riskLevel, score: latestInjectionScan.score }
        : null,

      supplyChain,

      agenticPipeline: latestAgenticScan
        ? {
            criticalCount: latestAgenticScan.criticalCount,
            highCount: latestAgenticScan.highCount,
            mediumCount: latestAgenticScan.mediumCount,
          }
        : null,

      exploitValidation,

      regulatoryCompliance: latestRegulatoryDrift
        ? {
            overallDriftLevel: latestRegulatoryDrift.overallDriftLevel,
            criticalGapCount: latestRegulatoryDrift.criticalGapCount,
            openGapCount: latestRegulatoryDrift.openGapCount,
          }
        : null,

      attackSurface: latestAttackSurface
        ? {
            score: latestAttackSurface.score,
            openCriticalCount: latestAttackSurface.openCriticalCount,
            openHighCount: latestAttackSurface.openHighCount,
            trend: latestAttackSurface.trend,
          }
        : null,

      dependencyTrust,
    }

    const certResult = computeCertificationResult(input)

    // ── Insert new report ─────────────────────────────────────────────────────
    await ctx.db.insert('llmCertificationReports', {
      repositoryId,
      tenantId: repository.tenantId,
      tier: certResult.tier,
      passCount: certResult.passCount,
      warnCount: certResult.warnCount,
      failCount: certResult.failCount,
      overallScore: certResult.overallScore,
      criticalFailedDomains: certResult.criticalFailedDomains,
      domainResults: certResult.domainResults,
      summary: certResult.summary,
      computedAt: Date.now(),
    })

    // ── Prune old reports — keep at most 20 per repository ───────────────────
    const oldReports = await ctx.db
      .query('llmCertificationReports')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('asc')
      .take(50)

    if (oldReports.length > 20) {
      const toDelete = oldReports.slice(0, oldReports.length - 20)
      for (const report of toDelete) {
        await ctx.db.delete(report._id)
      }
    }

    return { tier: certResult.tier, overallScore: certResult.overallScore }
  },
})

// ── refreshCertificationForRepository (public trigger) ───────────────────────

export const refreshCertificationForRepository = mutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const repo = await ctx.db.get(repositoryId)
    if (!repo) throw new Error(`Repository ${repositoryId} not found`)

    // Schedule the heavy internal mutation to run immediately after this
    // mutation commits — keeps each transaction within Convex limits.
    await ctx.scheduler.runAfter(0, internal.llmCertificationIntel.refreshCertification, {
      repositoryId,
    })
  },
})

// ── Queries ───────────────────────────────────────────────────────────────────

/** Latest certification report for a repository, with full domain results. */
export const getLatestCertificationReport = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('llmCertificationReports')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()
  },
})

/** Lean history for sparklines — last 10 reports, no domainResults payload. */
export const getCertificationHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const rows = await ctx.db
      .query('llmCertificationReports')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(10)
    return rows.map(({ domainResults: _dr, ...rest }) => rest)
  },
})

/** Tenant-wide certification summary: tier distribution + average score. */
export const getTenantCertificationSummary = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    const allReports = await ctx.db
      .query('llmCertificationReports')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(100)

    // Deduplicate: keep only the latest report per repository
    const seen = new Set<string>()
    const latestPerRepo = allReports.filter((r) => {
      if (seen.has(r.repositoryId)) return false
      seen.add(r.repositoryId)
      return true
    })

    const tierCounts = { gold: 0, silver: 0, bronze: 0, uncertified: 0 }
    for (const r of latestPerRepo) {
      tierCounts[r.tier]++
    }

    const avgScore = latestPerRepo.length > 0
      ? Math.round(latestPerRepo.reduce((sum, r) => sum + r.overallScore, 0) / latestPerRepo.length)
      : 0

    return {
      tierCounts,
      avgScore,
      reposEvaluated: latestPerRepo.length,
      certifiedCount: tierCounts.gold + tierCounts.silver + tierCounts.bronze,
    }
  },
})
