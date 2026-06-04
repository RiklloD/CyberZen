/**
 * Agentic Workflow Security Intel — WS-25 (spec §10 Phase 4)
 *
 * Persists results from the `agent-core` `/analyze/agentic-workflows` endpoint
 * into Convex, surfaces scan history via queries, and wires a fire-and-forget
 * call into the SBOM ingestion path (since a new push is the right trigger for
 * scanning agentic pipeline files).
 */

import { internalMutation, mutation, query } from './_generated/server'
import { v } from 'convex/values'

// ── Store result from agent-core ───────────────────────────────────────────────

/**
 * Persist a completed agentic workflow scan result.
 * Called by the action that invokes the agent-core HTTP endpoint.
 */
export const persistAgenticScan = internalMutation({
  args: {
    repositoryId: v.id('repositories'),
    tenantId: v.id('tenants'),
    totalFilesScanned: v.number(),
    frameworksDetected: v.array(v.string()),
    criticalCount: v.number(),
    highCount: v.number(),
    mediumCount: v.number(),
    findings: v.array(v.object({
      file: v.string(),
      line: v.number(),
      framework: v.string(),
      vulnClass: v.string(),
      severity: v.string(),
      evidence: v.string(),
      remediation: v.string(),
    })),
    summary: v.string(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert('agenticWorkflowScans', {
      ...args,
      computedAt: Date.now(),
    })
  },
})

// ── On-demand trigger ─────────────────────────────────────────────────────────

/**
 * Trigger an agentic workflow scan for a specific repository.
 * Calls the agent-core service and persists the result.
 * Requires `AGENT_CORE_URL` Convex env var to be set.
 */
export const triggerAgenticScanForRepository = mutation({
  args: {
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, { repositoryId }) => {
    const repo = await ctx.db.get(repositoryId)
    if (!repo) throw new Error(`Repository ${repositoryId} not found`)

    const agentCoreUrl = process.env.AGENT_CORE_URL
    if (!agentCoreUrl) {
      console.warn('agenticWorkflowIntel: AGENT_CORE_URL not set — skipping scan')
      return null
    }

    try {
      const res = await fetch(`${agentCoreUrl}/analyze/agentic-workflows`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository_path: repo.fullName ?? repo.name }),
      })

      if (!res.ok) {
        console.warn(`agenticWorkflowIntel: agent-core returned ${res.status}`)
        return null
      }

      const data = (await res.json()) as {
        total_files_scanned: number
        frameworks_detected: string[]
        critical_count: number
        high_count: number
        medium_count: number
        findings: Array<{
          file: string; line: number; framework: string
          vuln_class: string; severity: string; evidence: string; remediation: string
        }>
        summary: string
      }

      await ctx.db.insert('agenticWorkflowScans', {
        repositoryId,
        tenantId: repo.tenantId,
        totalFilesScanned: data.total_files_scanned,
        frameworksDetected: data.frameworks_detected,
        criticalCount: data.critical_count,
        highCount: data.high_count,
        mediumCount: data.medium_count,
        findings: data.findings.map((f) => ({
          file: f.file,
          line: f.line,
          framework: f.framework,
          vulnClass: f.vuln_class,
          severity: f.severity,
          evidence: f.evidence,
          remediation: f.remediation,
        })),
        summary: data.summary,
        computedAt: Date.now(),
      })

      return { criticalCount: data.critical_count, highCount: data.high_count }
    } catch (err) {
      console.warn('agenticWorkflowIntel: scan failed', err)
      return null
    }
  },
})

// ── Queries ────────────────────────────────────────────────────────────────────

/** Latest scan for a repository, including all findings. */
export const getLatestAgenticScan = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return ctx.db
      .query('agenticWorkflowScans')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .first()
  },
})

/** Recent scan history (up to 10) with aggregated counts only (no findings). */
export const getAgenticScanHistory = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const rows = await ctx.db
      .query('agenticWorkflowScans')
      .withIndex('by_repository_and_computed_at', (q) => q.eq('repositoryId', repositoryId))
      .order('desc')
      .take(10)
    return rows.map(({ findings: _f, ...rest }) => rest)
  },
})

/** Tenant-wide agentic security summary. */
export const getTenantAgenticSummary = query({
  args: { tenantId: v.id('tenants') },
  handler: async (ctx, { tenantId }) => {
    // Collect latest scan per repository
    const allScans = await ctx.db
      .query('agenticWorkflowScans')
      .withIndex('by_tenant_and_computed_at', (q) => q.eq('tenantId', tenantId))
      .order('desc')
      .take(100)

    // Deduplicate: keep only the most recent scan per repository
    const seen = new Set<string>()
    const latestPerRepo = allScans.filter((s) => {
      const key = s.repositoryId
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })

    const totalCritical = latestPerRepo.reduce((sum, s) => sum + s.criticalCount, 0)
    const totalHigh = latestPerRepo.reduce((sum, s) => sum + s.highCount, 0)
    const reposWithFindings = latestPerRepo.filter((s) => s.criticalCount + s.highCount + s.mediumCount > 0).length
    const allFrameworks = [...new Set(latestPerRepo.flatMap((s) => s.frameworksDetected))].sort()

    return { totalCritical, totalHigh, reposWithFindings, allFrameworks, reposScanned: latestPerRepo.length }
  },
})
