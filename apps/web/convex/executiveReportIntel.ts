/**
 * WS-97 — Tenant Security Executive Report: Convex entrypoints
 *
 * Assembles a cross-repository executive security summary for an entire
 * tenant by fanning out to four existing scoring tables (WS-49 health,
 * WS-96 drift posture, WS-44 supply chain, WS-46 compliance) and merging
 * the results through `computeExecutiveReport`.
 *
 * No new schema table — this is a pure computed view assembled at query time.
 *
 * Entrypoints:
 *   getExecutiveReport      — public query (tenantSlug)
 *   getExecutiveReportById  — public query (tenantId — internal convenience)
 */

import { v } from 'convex/values'
import { query } from './_generated/server'
import type { QueryCtx } from './_generated/server'
import type { Id } from './_generated/dataModel'
import {
  computeExecutiveReport,
  type FrameworkStatus,
  type RepoFrameworkData,
  type RepoSnapshot,
  type TenantExecutiveReport,
} from './lib/executiveReport'

// ---------------------------------------------------------------------------
// Internal: fan-out data loader
// ---------------------------------------------------------------------------

async function loadTenantData(ctx: QueryCtx, tenantId: Id<'tenants'>) {
  // Load latest record per repo from each of the four scoring tables.
  // Pattern: take 200 by tenant index (ordered DESC), deduplicate by repositoryId.

  const [healthRows, driftRows, supplyRows, complianceRows] = await Promise.all([
    ctx.db
      .query('repositoryHealthScoreResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(200),

    ctx.db
      .query('driftPostureResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(200),

    ctx.db
      .query('supplyChainPostureScores')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(200),

    ctx.db
      .query('complianceAttestationResults')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(200),
  ])

  // Deduplicate: keep first (= latest) per repositoryId
  function dedup<T extends { repositoryId: Id<'repositories'> }>(rows: T[]): Map<string, T> {
    const m = new Map<string, T>()
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!m.has(key)) m.set(key, row)
    }
    return m
  }

  return {
    healthByRepo: dedup(healthRows),
    driftByRepo: dedup(driftRows),
    supplyByRepo: dedup(supplyRows),
    complianceByRepo: dedup(complianceRows),
  }
}

/**
 * Build the union of repositoryIds seen across all four tables, then
 * load repository names from the `repositories` table.
 */
async function loadRepoNames(
  ctx: QueryCtx,
  repositoryIds: Set<string>,
): Promise<Map<string, string>> {
  const nameMap = new Map<string, string>()
  for (const id of repositoryIds) {
    const repo = await ctx.db.get(id as Id<'repositories'>)
    if (repo) nameMap.set(id, repo.fullName)
  }
  return nameMap
}

// ---------------------------------------------------------------------------
// Assembler
// ---------------------------------------------------------------------------

async function assembleReport(
  ctx: QueryCtx,
  tenantId: Id<'tenants'>,
  tenantSlug: string,
): Promise<TenantExecutiveReport> {
  const { healthByRepo, driftByRepo, supplyByRepo, complianceByRepo } = await loadTenantData(
    ctx,
    tenantId,
  )

  // Collect all repo IDs across all four tables
  const allRepoIds = new Set<string>([
    ...healthByRepo.keys(),
    ...driftByRepo.keys(),
    ...supplyByRepo.keys(),
    ...complianceByRepo.keys(),
  ])

  const nameMap = await loadRepoNames(ctx, allRepoIds)

  const snapshots: RepoSnapshot[] = []

  for (const repoId of allRepoIds) {
    const fullName = nameMap.get(repoId) ?? repoId
    const health = healthByRepo.get(repoId)
    const drift = driftByRepo.get(repoId)
    const supply = supplyByRepo.get(repoId)
    const compliance = complianceByRepo.get(repoId)

    const frameworks: RepoFrameworkData[] = (compliance?.frameworks ?? []).map((fw) => ({
      framework: fw.label,
      status: fw.status as FrameworkStatus,
      score: fw.score,
    }))

    snapshots.push({
      repositoryId: repoId,
      repositoryFullName: fullName,
      healthScore: health?.overallScore ?? null,
      healthGrade: health?.overallGrade ?? null,
      healthTopRisks: health?.topRisks ?? [],
      driftPostureScore: drift?.overallScore ?? null,
      driftGrade: drift?.overallGrade ?? null,
      driftTopRisks: drift?.topRisks ?? [],
      supplyChainScore: supply?.score ?? null,
      supplyChainGrade: supply?.grade ?? null,
      frameworks,
    })
  }

  return computeExecutiveReport(tenantSlug, snapshots)
}

// ---------------------------------------------------------------------------
// Public queries
// ---------------------------------------------------------------------------

/**
 * Get the tenant executive report by tenant slug.
 * Suitable for dashboard use and the HTTP API.
 */
export const getExecutiveReport = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }): Promise<TenantExecutiveReport | null> => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .first()
    if (!tenant) return null
    return assembleReport(ctx, tenant._id, tenantSlug)
  },
})

/**
 * Get the tenant executive report by tenantId.
 * Convenience alias for internal callers that already have the ID.
 */
export const getExecutiveReportById = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }): Promise<TenantExecutiveReport | null> => {
    const tenant = await ctx.db.get(tenantId)
    if (!tenant) return null
    return assembleReport(ctx, tenantId, tenant.slug)
  },
})
