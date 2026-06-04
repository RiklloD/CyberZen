/**
 * Blue Agent Intelligence — Convex entrypoints (spec §3.3.3)
 *
 * Generates detection rules from Red Agent wins and stores them for export.
 * Called fire-and-forget after every red_wins round in redBlueIntel.ts.
 *
 * Export endpoints:
 *   GET /api/detection-rules?format=nginx|modsecurity|splunk|elastic|sentinel|log_regex
 */

import { v } from 'convex/values'
import {
  internalMutation,
  mutation,
  query,
} from './_generated/server'
import { internal } from './_generated/api'
import { generateDetectionRules } from './lib/blueAgent'

// ── Public queries ────────────────────────────────────────────────────────────

export const getDetectionRuleSnapshot = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    return await ctx.db
      .query('detectionRuleSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()
  },
})

export const getDetectionRuleSummary = query({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const snapshot = await ctx.db
      .query('detectionRuleSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    if (!snapshot) return null

    return {
      totalRules: snapshot.totalRules,
      nginxCount: snapshot.nginxCount,
      modsecurityCount: snapshot.modsecurityCount,
      splunkCount: snapshot.splunkCount,
      elasticCount: snapshot.elasticCount,
      sentinelCount: snapshot.sentinelCount,
      logRegexCount: snapshot.logRegexCount,
      generatedAt: snapshot.generatedAt,
      summary: snapshot.summary,
    }
  },
})

// Slug-based variant for HTTP endpoints
export const getDetectionRulesBySlug = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    format: v.union(
      v.literal('nginx'),
      v.literal('modsecurity'),
      v.literal('splunk'),
      v.literal('elastic'),
      v.literal('sentinel'),
      v.literal('log_regex'),
    ),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName, format }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const repo = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
      )
      .unique()
    if (!repo) return null

    const snapshot = await ctx.db
      .query('detectionRuleSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', repo._id),
      )
      .order('desc')
      .first()

    if (!snapshot) return null

    const formatMap: Record<string, unknown> = {
      nginx: snapshot.nginxRules,
      modsecurity: snapshot.modsecurityRules,
      splunk: snapshot.splunkRules,
      elastic: snapshot.elasticRules,
      sentinel: snapshot.sentinelRules,
      log_regex: snapshot.logRegexRules,
    }

    return {
      format,
      rules: formatMap[format] ?? [],
      generatedAt: snapshot.generatedAt,
      repositoryFullName,
    }
  },
})

// Trigger from dashboard
export const refreshDetectionRules = mutation({
  args: { tenantSlug: v.string(), repositoryFullName: v.string() },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) throw new Error('Tenant not found')

    const repo = await ctx.db
      .query('repositories')
      .withIndex('by_tenant_and_full_name', (q) =>
        q.eq('tenantId', tenant._id).eq('fullName', repositoryFullName),
      )
      .unique()
    if (!repo) throw new Error('Repository not found')

    await ctx.scheduler.runAfter(
      0,
      internal.blueAgentIntel.generateAndStoreDetectionRules,
      { repositoryId: repo._id },
    )

    return { scheduled: true }
  },
})

// ── Internal actions ──────────────────────────────────────────────────────────

export const generateAndStoreDetectionRules = internalMutation({
  args: { repositoryId: v.id('repositories') },
  handler: async (ctx, { repositoryId }) => {
    const repo = await ctx.db.get(repositoryId)
    if (!repo) return

    // Load all red-wins rounds for this repository
    const rounds = await ctx.db
      .query('redBlueRounds')
      .withIndex('by_repository_and_ran_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .take(50)

    const ruleSetInput = rounds.map((r) => ({
      exploitChains: r.exploitChains,
      redStrategySummary: r.redStrategySummary,
      attackSurfaceCoverage: r.attackSurfaceCoverage,
      blueDetectionScore: r.blueDetectionScore,
      roundOutcome: r.roundOutcome,
      repositoryName: repo.name,
    }))

    const ruleSet = generateDetectionRules(ruleSetInput, repo.name)

    // Serialize rules to arrays of content strings for storage
    const toStrings = (rules: { content: string }[]) =>
      rules.map((r) => r.content)

    // Upsert snapshot
    const existing = await ctx.db
      .query('detectionRuleSnapshots')
      .withIndex('by_repository_and_generated_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    const data = {
      tenantId: repo.tenantId,
      repositoryId,
      totalRules: ruleSet.totalRules,
      nginxCount: ruleSet.nginx.length,
      modsecurityCount: ruleSet.modsecurity.length,
      splunkCount: ruleSet.splunk.length,
      elasticCount: ruleSet.elastic.length,
      sentinelCount: ruleSet.sentinel.length,
      logRegexCount: ruleSet.logRegex.length,
      // Store serialized rule content only (bounded)
      nginxRules: toStrings(ruleSet.nginx).slice(0, 20),
      modsecurityRules: toStrings(ruleSet.modsecurity).slice(0, 20),
      splunkRules: toStrings(ruleSet.splunk).slice(0, 10),
      elasticRules: toStrings(ruleSet.elastic).slice(0, 10),
      sentinelRules: toStrings(ruleSet.sentinel).slice(0, 10),
      logRegexRules: toStrings(ruleSet.logRegex).slice(0, 20),
      summary: ruleSet.summary,
      generatedAt: Date.now(),
    }

    if (existing) {
      await ctx.db.patch(existing._id, data)
    } else {
      await ctx.db.insert('detectionRuleSnapshots', data)
    }

    // Fire-and-forget: push rules to configured SIEM endpoints (Splunk + Elastic).
    // Runs after the snapshot is stored; failures are logged but never propagate.
    try {
      await ctx.scheduler.runAfter(
        0,
        internal.siemIntel.pushToSiem,
        { repositoryId },
      )
    } catch (e) {
      console.error('[siem] failed to schedule SIEM push', e)
    }

    return { totalRules: ruleSet.totalRules }
  },
})
