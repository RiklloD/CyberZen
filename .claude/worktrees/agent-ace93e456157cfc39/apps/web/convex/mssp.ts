/**
 * MSSP White-Label Partner API — spec §10.3 (Phase 3 roadmap)
 *
 * Allows Managed Security Service Providers (MSSPs) to manage multiple
 * customer tenants through a single API key with elevated permissions.
 *
 * MSSP endpoints (separate from the customer-facing API):
 *   POST   /api/mssp/tenants               — provision a new tenant
 *   GET    /api/mssp/tenants               — list all managed tenants
 *   GET    /api/mssp/tenants/:slug/summary — aggregate security posture for tenant
 *   DELETE /api/mssp/tenants/:slug         — deprovision tenant (soft delete)
 *   GET    /api/mssp/dashboard             — cross-tenant risk overview
 *
 * Authentication: X-MSSP-Api-Key header (separate from per-tenant SENTINEL_API_KEY)
 *
 * Configuration:
 *   npx convex env set MSSP_API_KEY <your-mssp-key>
 *
 * White-labeling:
 *   MSSP_BRAND_NAME env var replaces "Sentinel" in webhook payloads + report headers.
 *   MSSP_DASHBOARD_URL configures the link back to the MSSP's own portal.
 */

import { v } from 'convex/values'
import {
  internalMutation,
  internalQuery,
} from './_generated/server'

// ── Auth helpers (used by http.ts MSSP routes) ────────────────────────────────

export function requireMsspApiKey(
  request: Request,
): Response | null {
  const expectedKey = process.env.MSSP_API_KEY
  if (!expectedKey) {
    // No key configured — fail closed for MSSP endpoints
    return new Response(
      JSON.stringify({ error: 'MSSP API not configured. Set MSSP_API_KEY env var.' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const key =
    request.headers.get('x-mssp-api-key') ??
    request.headers.get('authorization')?.replace(/^Bearer\s+/i, '')

  if (key !== expectedKey) {
    return new Response(
      JSON.stringify({ error: 'Invalid MSSP API key.' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  return null // authorized
}

// ── Tenant provisioning ───────────────────────────────────────────────────────

export const provisionTenant = internalMutation({
  args: {
    slug: v.string(),
    name: v.string(),
    deploymentMode: v.union(
      v.literal('cloud_saas'),
      v.literal('vpc_injection'),
      v.literal('on_prem'),
    ),
    currentPhase: v.optional(
      v.union(
        v.literal('phase_0'),
        v.literal('phase_1'),
        v.literal('phase_2'),
        v.literal('phase_3'),
        v.literal('phase_4'),
      ),
    ),
  },
  handler: async (ctx, args) => {
    // Check for duplicate slug
    const existing = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.slug))
      .unique()

    if (existing) {
      throw new Error(`Tenant with slug "${args.slug}" already exists.`)
    }

    const tenantId = await ctx.db.insert('tenants', {
      slug: args.slug,
      name: args.name,
      status: 'active',
      deploymentMode: args.deploymentMode,
      currentPhase: args.currentPhase ?? 'phase_1',
      createdAt: Date.now(),
    })

    return { tenantId, slug: args.slug, name: args.name }
  },
})

export const deprovisionTenant = internalMutation({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique()

    if (!tenant) throw new Error(`Tenant "${slug}" not found.`)

    // Soft delete — pause instead of hard delete to preserve audit trail
    await ctx.db.patch(tenant._id, { status: 'paused' })
    return { deprovisioned: true, slug }
  },
})

// ── Read queries ──────────────────────────────────────────────────────────────

export const listAllTenants = internalQuery({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query('tenants').take(200)
  },
})

export const getTenantSummary = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique()

    if (!tenant) return null

    const repos = await ctx.db
      .query('repositories')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(50)

    const repoIds = repos.map((r) => r._id)

    // Aggregate open findings across all repos
    let totalFindings = 0
    let criticalFindings = 0
    let highFindings = 0

    for (const repoId of repoIds) {
      const findings = await ctx.db
        .query('findings')
        .withIndex('by_repository_and_status', (q) =>
          q.eq('repositoryId', repoId).eq('status', 'open'),
        )
        .take(100)

      totalFindings += findings.length
      criticalFindings += findings.filter((f) => f.severity === 'critical').length
      highFindings += findings.filter((f) => f.severity === 'high').length
    }

    return {
      tenant: {
        slug: tenant.slug,
        name: tenant.name,
        status: tenant.status,
        deploymentMode: tenant.deploymentMode,
        currentPhase: tenant.currentPhase,
        createdAt: tenant.createdAt,
      },
      repositories: repos.length,
      findings: {
        total: totalFindings,
        critical: criticalFindings,
        high: highFindings,
      },
    }
  },
})

export const getCrossTenantDashboard = internalQuery({
  args: {},
  handler: async (ctx) => {
    const tenants = await ctx.db.query('tenants').take(200)
    const activeTenants = tenants.filter((t) => t.status === 'active')

    let totalRepos = 0
    let totalCritical = 0
    let totalHigh = 0
    const tenantSummaries: Array<{
      slug: string
      name: string
      critical: number
      high: number
    }> = []

    for (const tenant of activeTenants.slice(0, 50)) {
      const repos = await ctx.db
        .query('repositories')
        .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
        .take(20)

      totalRepos += repos.length

      let tenantCritical = 0
      let tenantHigh = 0

      for (const repo of repos.slice(0, 5)) {
        const findings = await ctx.db
          .query('findings')
          .withIndex('by_repository_and_status', (q) =>
            q.eq('repositoryId', repo._id).eq('status', 'open'),
          )
          .take(50)

        const crit = findings.filter((f) => f.severity === 'critical').length
        const high = findings.filter((f) => f.severity === 'high').length
        tenantCritical += crit
        tenantHigh += high
      }

      totalCritical += tenantCritical
      totalHigh += tenantHigh

      if (tenantCritical > 0 || tenantHigh > 0) {
        tenantSummaries.push({
          slug: tenant.slug,
          name: tenant.name,
          critical: tenantCritical,
          high: tenantHigh,
        })
      }
    }

    return {
      totalTenants: activeTenants.length,
      totalRepositories: totalRepos,
      criticalFindings: totalCritical,
      highFindings: totalHigh,
      tenantsWithCritical: tenantSummaries
        .filter((t) => t.critical > 0)
        .sort((a, b) => b.critical - a.critical)
        .slice(0, 10),
      brandName: process.env.MSSP_BRAND_NAME ?? 'Sentinel',
      generatedAt: Date.now(),
    }
  },
})
