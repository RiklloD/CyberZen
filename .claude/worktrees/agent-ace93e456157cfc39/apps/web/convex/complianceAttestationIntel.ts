/**
 * WS-46 — Compliance Attestation Report Generator: Convex entrypoints.
 *
 * Reads the latest persisted results from each of 12 supply-chain / security
 * scanners and maps them to per-framework regulatory compliance status across:
 *   SOC 2 Type II, GDPR, PCI-DSS 4.0, HIPAA, NIS2
 *
 * Scheduled with a 5-second delay from sbom.ingestRepositoryInventory so that
 * all concurrent scanner mutations have finished writing before this reads.
 *
 * Entrypoints:
 *   recordComplianceAttestation               — internalMutation: compute + persist
 *   triggerComplianceAttestationForRepository — public mutation: on-demand trigger
 *   getLatestComplianceAttestation            — public query: most recent result
 *   getComplianceAttestationHistory           — public query: last 30 lean summaries
 *   getComplianceAttestationSummaryByTenant   — public query: tenant-wide aggregate
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { computeComplianceAttestation } from './lib/complianceAttestationReport'
import type { ComplianceAttestationInput } from './lib/complianceAttestationReport'

// ---------------------------------------------------------------------------
// recordComplianceAttestation — internalMutation
// ---------------------------------------------------------------------------

/**
 * Load the latest result from each of 12 scanners, build the compliance
 * attestation input, compute the report, and persist. Prunes to 30 per repo.
 */
export const recordComplianceAttestation = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // ── Load latest result from each scanner in parallel ──────────────────
    const [
      secretRow,
      cryptoRow,
      eolRow,
      abandonmentRow,
      attestationRow,
      confusionRow,
      maliciousRow,
      cveRow,
      qualityRow,
      iacRow,
      cicdRow,
      containerRow,
    ] = await Promise.all([
      // WS-30 — Secret Detection
      ctx.db
        .query('secretScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-37 — Cryptography Weakness Detector
      ctx.db
        .query('cryptoWeaknessResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-38 — Dependency & Runtime EOL Detection
      ctx.db
        .query('eolDetectionResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-39 — Open-Source Package Abandonment Detector
      ctx.db
        .query('abandonmentScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-40 — SBOM Attestation (uses different index key)
      ctx.db
        .query('sbomAttestationRecords')
        .withIndex('by_repository_and_attested_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-41 — Dependency Confusion Attack Detector
      ctx.db
        .query('confusionAttackScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-42 — Malicious Package Detection
      ctx.db
        .query('maliciousPackageScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-43 — Known CVE Version Range Scanner
      ctx.db
        .query('cveVersionScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-32 — SBOM Quality & Completeness Scoring
      ctx.db
        .query('sbomQualitySnapshots')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-33 — IaC Security Scanner
      ctx.db
        .query('iacScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-35 — CI/CD Pipeline Security Scanner
      ctx.db
        .query('cicdScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),

      // WS-45 — Container Image Security Analyzer
      ctx.db
        .query('containerImageScanResults')
        .withIndex('by_repository_and_computed_at', (q) =>
          q.eq('repositoryId', repositoryId),
        )
        .order('desc')
        .first(),
    ])

    // ── Build the compliance input from persisted scanner results ─────────
    const input: ComplianceAttestationInput = {
      // WS-30
      secretCriticalCount: secretRow?.criticalCount ?? 0,
      secretHighCount: secretRow?.highCount ?? 0,
      // WS-37
      cryptoRisk: cryptoRow?.overallRisk ?? 'none',
      cryptoCriticalCount: cryptoRow?.criticalCount ?? 0,
      cryptoHighCount: cryptoRow?.highCount ?? 0,
      // WS-38 — eolDetectionResults.overallStatus is 'critical'|'warning'|'ok'; default 'none'
      eolStatus: eolRow?.overallStatus ?? 'none',
      eolCriticalCount: eolRow?.eolCount ?? 0,
      // WS-39
      abandonmentRisk: abandonmentRow?.overallRisk ?? 'none',
      abandonmentCriticalCount: abandonmentRow?.criticalCount ?? 0,
      // WS-40 — sbomAttestationRecords.status is 'valid'|'tampered'|'unverified'; default 'none'
      attestationStatus: attestationRow?.status ?? 'none',
      // WS-41
      confusionRisk: confusionRow?.overallRisk ?? 'none',
      confusionCriticalCount: confusionRow?.criticalCount ?? 0,
      // WS-42
      maliciousRisk: maliciousRow?.overallRisk ?? 'none',
      maliciousCriticalCount: maliciousRow?.criticalCount ?? 0,
      // WS-43
      cveRisk: cveRow?.overallRisk ?? 'none',
      cveCriticalCount: cveRow?.criticalCount ?? 0,
      cveHighCount: cveRow?.highCount ?? 0,
      // WS-32 — sbomQualitySnapshots.grade is 'excellent'|'good'|'fair'|'poor'; default 'unknown'
      sbomGrade: qualityRow?.grade ?? 'unknown',
      // WS-33
      iacRisk: iacRow?.overallRisk ?? 'none',
      iacCriticalCount: iacRow?.criticalCount ?? 0,
      // WS-35
      cicdRisk: cicdRow?.overallRisk ?? 'none',
      cicdCriticalCount: cicdRow?.criticalCount ?? 0,
      // WS-45
      containerRisk: containerRow?.overallRisk ?? 'none',
      containerCriticalCount: containerRow?.criticalCount ?? 0,
    }

    // ── Compute the compliance attestation ────────────────────────────────
    const report = computeComplianceAttestation(input)

    const nowMs = Date.now()

    // ── Persist ───────────────────────────────────────────────────────────
    await ctx.db.insert('complianceAttestationResults', {
      tenantId,
      repositoryId,
      frameworks: report.frameworks,
      overallStatus: report.overallStatus,
      criticalGapCount: report.criticalGapCount,
      highGapCount: report.highGapCount,
      fullyCompliantCount: report.fullyCompliantCount,
      summary: report.summary,
      computedAt: nowMs,
    })

    // ── Prune: keep at most 30 rows per repository ────────────────────────
    const old = await ctx.db
      .query('complianceAttestationResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('asc')
      .take(100)

    if (old.length > 30) {
      for (const row of old.slice(0, old.length - 30)) {
        await ctx.db.delete(row._id)
      }
    }
  },
})

// ---------------------------------------------------------------------------
// triggerComplianceAttestationForRepository — public mutation
// ---------------------------------------------------------------------------

/** On-demand compliance attestation trigger. Resolves by slug + full name. */
export const triggerComplianceAttestationForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<void> => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), args.repositoryFullName),
        ),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    await ctx.scheduler.runAfter(
      0,
      internal.complianceAttestationIntel.recordComplianceAttestation,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestComplianceAttestation — public query
// ---------------------------------------------------------------------------

/** Return the most recent compliance attestation for a repository. */
export const getLatestComplianceAttestation = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return null

    return ctx.db
      .query('complianceAttestationResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getComplianceAttestationHistory — lean public query (no controlGaps detail)
// ---------------------------------------------------------------------------

/** Return up to 30 recent attestation summaries for trend/sparkline display. */
export const getComplianceAttestationHistory = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return []

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return []

    const rows = await ctx.db
      .query('complianceAttestationResults')
      .withIndex('by_repository_and_computed_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .take(30)

    // Strip per-framework controlGaps to keep response lean.
    return rows.map((row) => ({
      ...row,
      frameworks: row.frameworks.map(({ controlGaps: _g, ...lean }) => lean),
    }))
  },
})

// ---------------------------------------------------------------------------
// getComplianceAttestationSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide compliance posture aggregates: repos by overall status,
 * and the most non-compliant repository for quick dashboard triage.
 */
export const getComplianceAttestationSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('complianceAttestationResults')
      .withIndex('by_tenant_and_computed_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent attestation per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    const nonCompliantRepos = latest.filter((r) => r.overallStatus === 'non_compliant').length
    const atRiskRepos = latest.filter((r) => r.overallStatus === 'at_risk').length
    const compliantRepos = latest.filter((r) => r.overallStatus === 'compliant').length

    const STATUS_RANK: Record<string, number> = {
      non_compliant: 0,
      at_risk: 1,
      compliant: 2,
    }
    const worst = latest.reduce<(typeof latest)[0] | null>((acc, r) => {
      if (!acc) return r
      return (STATUS_RANK[r.overallStatus] ?? 3) < (STATUS_RANK[acc.overallStatus] ?? 3) ? r : acc
    }, null)

    const totalCriticalGaps = latest.reduce((s, r) => s + r.criticalGapCount, 0)
    const totalHighGaps = latest.reduce((s, r) => s + r.highGapCount, 0)

    return {
      repoCount: latest.length,
      nonCompliantRepos,
      atRiskRepos,
      compliantRepos,
      totalCriticalGaps,
      totalHighGaps,
      worstRepositoryId: worst?.repositoryId ?? null,
      worstOverallStatus: worst?.overallStatus ?? null,
    }
  },
})
