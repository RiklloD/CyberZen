import { v } from 'convex/values'
import { action, internalAction, internalMutation, internalQuery, query } from './_generated/server'
import { internal } from './_generated/api'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type OtxPulse = {
  id: string
  name: string
  description: string
  modified: string
  tags: string[]
  references: string[]
  threat_actor_names?: string[]
  attack_ids?: Array<{ id: string; name: string }>
  indicators?: Array<{
    type: string
    indicator: string
  }>
  targeted_countries?: string[]
  adversary?: string
}

type CisaKevEntry = {
  cveID: string
  vendorProject: string
  product: string
  vulnerabilityName: string
  dateAdded: string
  shortDescription: string
  requiredAction: string
  dueDate: string
  notes: string
  knownRansomwareCampaignUse?: string
}

type IocBundle = {
  ips: string[]
  domains: string[]
  hashes: string[]
}

// ---------------------------------------------------------------------------
// syncAlienVaultOTX — pull recent OTX pulses related to tenant CVEs
// ---------------------------------------------------------------------------

export const syncAlienVaultOTX = action({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const otxApiKey = process.env.OTX_API_KEY
    if (!otxApiKey) {
      console.log('OTX_API_KEY not configured — skipping OTX sync')
      return { synced: 0, correlated: 0 }
    }

    // Fetch recent subscribed pulses (last 30 days)
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=${since}&limit=50`,
      { headers: { 'X-OTX-API-KEY': otxApiKey } },
    )

    if (!res.ok) {
      console.error('OTX API error', res.status)
      return { synced: 0, correlated: 0 }
    }

    const data = (await res.json()) as { results?: OtxPulse[] }
    const pulses: OtxPulse[] = data.results ?? []

    let synced = 0
    for (const pulse of pulses) {
      const cves = (pulse.tags ?? []).filter((t) => /^CVE-\d{4}-\d+$/.test(t))
      const iocs: IocBundle = { ips: [], domains: [], hashes: [] }

      for (const ind of pulse.indicators ?? []) {
        if (ind.type === 'IPv4' || ind.type === 'IPv6') iocs.ips.push(ind.indicator)
        else if (ind.type === 'domain' || ind.type === 'hostname')
          iocs.domains.push(ind.indicator)
        else if (ind.type === 'FileHash-MD5' || ind.type === 'FileHash-SHA256')
          iocs.hashes.push(ind.indicator)
      }

      await ctx.runMutation(internal.threatIntelligence.upsertThreatIntel, {
        tenantSlug: args.tenantSlug,
        source: 'otx',
        externalId: pulse.id,
        title: pulse.name,
        description: pulse.description ?? '',
        cves,
        threatActors: [
          ...(pulse.threat_actor_names ?? []),
          ...(pulse.adversary ? [pulse.adversary] : []),
        ],
        iocs: JSON.stringify(iocs),
        severity: cves.length > 0 ? 'high' : 'medium',
        publishedAt: new Date(pulse.modified).getTime(),
      })
      synced++
    }

    const correlated: number = await ctx.runMutation(
      internal.threatIntelligence.correlateWithFindings,
      { tenantSlug: args.tenantSlug },
    )

    return { synced, correlated }
  },
})

// ---------------------------------------------------------------------------
// syncAlienVaultOTXScheduled — internal variant for cron use
// ---------------------------------------------------------------------------

export const syncAlienVaultOTXScheduled = internalAction({
  args: {},
  handler: async (ctx) => {
    const otxApiKey = process.env.OTX_API_KEY
    if (!otxApiKey) return

    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=${since}&limit=50`,
      { headers: { 'X-OTX-API-KEY': otxApiKey } },
    )

    if (!res.ok) {
      console.error('OTX sync failed', res.status)
      return
    }

    const data = (await res.json()) as { results?: OtxPulse[] }
    const pulses: OtxPulse[] = data.results ?? []

    // Get all tenants to fan out
    const tenants: string[] = await ctx.runQuery(
      internal.threatIntelligence.getAllTenantSlugs,
      {},
    )

    for (const tenantSlug of tenants) {
      for (const pulse of pulses) {
        const cves = (pulse.tags ?? []).filter((t) => /^CVE-\d{4}-\d+$/.test(t))
        const iocs: IocBundle = { ips: [], domains: [], hashes: [] }

        for (const ind of pulse.indicators ?? []) {
          if (ind.type === 'IPv4' || ind.type === 'IPv6') iocs.ips.push(ind.indicator)
          else if (ind.type === 'domain' || ind.type === 'hostname')
            iocs.domains.push(ind.indicator)
          else if (ind.type === 'FileHash-MD5' || ind.type === 'FileHash-SHA256')
            iocs.hashes.push(ind.indicator)
        }

        await ctx.runMutation(internal.threatIntelligence.upsertThreatIntel, {
          tenantSlug,
          source: 'otx',
          externalId: pulse.id,
          title: pulse.name,
          description: pulse.description ?? '',
          cves,
          threatActors: [
            ...(pulse.threat_actor_names ?? []),
            ...(pulse.adversary ? [pulse.adversary] : []),
          ],
          iocs: JSON.stringify(iocs),
          severity: cves.length > 0 ? 'high' : 'medium',
          publishedAt: new Date(pulse.modified).getTime(),
        })
      }
      await ctx.runMutation(internal.threatIntelligence.correlateWithFindings, {
        tenantSlug,
      })
    }
  },
})

// ---------------------------------------------------------------------------
// syncCisaKevThreatIntel — import CISA KEV catalog as threat intel entries
// ---------------------------------------------------------------------------

export const syncCisaKevThreatIntel = internalAction({
  args: {},
  handler: async (ctx) => {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    )
    if (!res.ok) {
      console.error('CISA KEV fetch failed', res.status)
      return
    }

    const data = (await res.json()) as {
      vulnerabilities?: CisaKevEntry[]
    }
    const entries = (data.vulnerabilities ?? []).slice(0, 100)

    const tenants: string[] = await ctx.runQuery(
      internal.threatIntelligence.getAllTenantSlugs,
      {},
    )

    for (const tenantSlug of tenants) {
      for (const entry of entries) {
        await ctx.runMutation(internal.threatIntelligence.upsertThreatIntel, {
          tenantSlug,
          source: 'cisa_kev',
          externalId: entry.cveID,
          title: entry.vulnerabilityName,
          description: `${entry.shortDescription} Required action: ${entry.requiredAction}`,
          cves: [entry.cveID],
          threatActors: [],
          iocs: JSON.stringify({ ips: [], domains: [], hashes: [] }),
          severity: 'critical',
          publishedAt: new Date(entry.dateAdded).getTime(),
        })
      }
      await ctx.runMutation(internal.threatIntelligence.correlateWithFindings, {
        tenantSlug,
      })
    }
  },
})

// ---------------------------------------------------------------------------
// upsertThreatIntel — internal mutation to insert/update a threat intel record
// ---------------------------------------------------------------------------

export const upsertThreatIntel = internalMutation({
  args: {
    tenantSlug: v.string(),
    source: v.string(),
    externalId: v.string(),
    title: v.string(),
    description: v.string(),
    cves: v.array(v.string()),
    threatActors: v.array(v.string()),
    iocs: v.string(),
    severity: v.string(),
    publishedAt: v.number(),
  },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return

    const existing = await ctx.db
      .query('threatIntel')
      .withIndex('by_external_id', (q) => q.eq('externalId', args.externalId))
      .filter((q) => q.eq(q.field('tenantId'), tenant._id))
      .first()

    const now = Date.now()

    if (existing) {
      await ctx.db.patch(existing._id, {
        title: args.title,
        description: args.description,
        cves: args.cves,
        threatActors: args.threatActors,
        iocs: args.iocs,
        severity: args.severity,
        publishedAt: args.publishedAt,
        fetchedAt: now,
      })
    } else {
      await ctx.db.insert('threatIntel', {
        tenantId: tenant._id,
        source: args.source,
        externalId: args.externalId,
        title: args.title,
        description: args.description,
        cves: args.cves,
        threatActors: args.threatActors,
        iocs: args.iocs,
        severity: args.severity,
        publishedAt: args.publishedAt,
        fetchedAt: now,
      })
    }
  },
})

// ---------------------------------------------------------------------------
// correlateWithFindings — match threat intel CVEs against open findings
// ---------------------------------------------------------------------------

export const correlateWithFindings = internalMutation({
  args: { tenantSlug: v.string() },
  returns: v.number(),
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return 0

    // Get recent threat intel records for this tenant
    const intelRecords = await ctx.db
      .query('threatIntel')
      .withIndex('by_tenant_and_fetched_at', (q) => q.eq('tenantId', tenant._id))
      .order('desc')
      .take(200)

    // Get open findings for this tenant
    const findings = await ctx.db
      .query('findings')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', tenant._id).eq('status', 'open'),
      )
      .take(200)

    let correlated = 0

    for (const intel of intelRecords) {
      for (const finding of findings) {
        // CVE match: finding's disclosureRef matches a CVE in the intel record
        const disclosureRef = finding.disclosureRef ?? ''
        const cveMatch = intel.cves.some(
          (cve) =>
            disclosureRef.includes(cve) ||
            finding.title.includes(cve) ||
            finding.affectedPackages.some((pkg) => disclosureRef.includes(pkg)),
        )

        if (!cveMatch) continue

        // Check if correlation already exists
        const existing = await ctx.db
          .query('findingThreatIntel')
          .withIndex('by_finding_and_correlation_type', (q) =>
            q.eq('findingId', finding._id).eq('correlationType', 'cve_match'),
          )
          .filter((q) => q.eq(q.field('threatIntelId'), intel._id))
          .first()

        if (!existing) {
          await ctx.db.insert('findingThreatIntel', {
            tenantId: tenant._id,
            findingId: finding._id,
            threatIntelId: intel._id,
            correlationType: 'cve_match',
            confidence: intel.source === 'cisa_kev' ? 0.95 : 0.8,
          })
          correlated++
        }
      }
    }

    return correlated
  },
})

// ---------------------------------------------------------------------------
// getAllTenantSlugs — internal query for fan-out actions
// ---------------------------------------------------------------------------

export const getAllTenantSlugs = internalQuery({
  args: {},
  returns: v.array(v.string()),
  handler: async (ctx) => {
    const tenants = await ctx.db.query('tenants').take(50)
    return tenants.map((t) => t.slug)
  },
})

// ---------------------------------------------------------------------------
// getThreatIntelForFinding — public query for finding detail drawer
// ---------------------------------------------------------------------------

export const getThreatIntelForFinding = query({
  args: { findingId: v.id('findings') },
  returns: v.array(
    v.object({
      _id: v.id('findingThreatIntel'),
      correlationType: v.string(),
      confidence: v.number(),
      intel: v.object({
        _id: v.id('threatIntel'),
        source: v.string(),
        title: v.string(),
        description: v.string(),
        cves: v.array(v.string()),
        threatActors: v.array(v.string()),
        iocs: v.string(),
        severity: v.string(),
        publishedAt: v.number(),
        externalId: v.string(),
      }),
    }),
  ),
  handler: async (ctx, args) => {
    const correlations = await ctx.db
      .query('findingThreatIntel')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .take(20)

    const results = []
    for (const corr of correlations) {
      const intel = await ctx.db.get(corr.threatIntelId)
      if (!intel) continue
      results.push({
        _id: corr._id,
        correlationType: corr.correlationType,
        confidence: corr.confidence,
        intel: {
          _id: intel._id,
          source: intel.source,
          title: intel.title,
          description: intel.description,
          cves: intel.cves,
          threatActors: intel.threatActors,
          iocs: intel.iocs,
          severity: intel.severity,
          publishedAt: intel.publishedAt,
          externalId: intel.externalId,
        },
      })
    }
    return results
  },
})

// ---------------------------------------------------------------------------
// getThreatIntelSummary — lightweight summary for findings list badges
// ---------------------------------------------------------------------------

export const getThreatIntelSummary = query({
  args: { findingId: v.id('findings') },
  returns: v.object({
    isActivelyExploited: v.boolean(),
    threatActors: v.array(v.string()),
    sources: v.array(v.string()),
  }),
  handler: async (ctx, args) => {
    const correlations = await ctx.db
      .query('findingThreatIntel')
      .withIndex('by_finding', (q) => q.eq('findingId', args.findingId))
      .take(10)

    const sources: string[] = []
    const threatActors: string[] = []
    let isActivelyExploited = false

    for (const corr of correlations) {
      const intel = await ctx.db.get(corr.threatIntelId)
      if (!intel) continue
      sources.push(intel.source)
      threatActors.push(...intel.threatActors)
      if (intel.source === 'cisa_kev') isActivelyExploited = true
    }

    return {
      isActivelyExploited,
      threatActors: [...new Set(threatActors)].slice(0, 5),
      sources: [...new Set(sources)],
    }
  },
})
