/**
 * Tier 2 Breach Intelligence Feeds — spec §3.10.2
 *
 * Pre-CVE early warning sources. These detect vulnerabilities days/weeks
 * before a CVE is assigned, closing the "CVE gap" where organizations are
 * blind even with up-to-date Tier 1 feeds.
 *
 * Sources implemented:
 *   - GitHub Issues: security-labelled issues on monitored package repos
 *   - HackerOne: publicly disclosed vulnerability reports
 *   - oss-security: Openwall mailing list (primary pre-CVE disclosure channel)
 *   - Packet Storm: security advisory RSS feed
 *
 * All normalized to the same NormalizedDisclosure format → same ingestion pipeline.
 *
 * Additional env vars:
 *   HACKERONE_API_IDENTIFIER, HACKERONE_API_KEY (optional — public disclosures only)
 */

import { ConvexError, v } from 'convex/values'
import { action } from './_generated/server'
import { api } from './_generated/api'
import {
  normalizeGithubIssueDisclosure,
  normalizeHackerOneReport,
  normalizeOssSecurityPost,
  normalizePacketStormEntry,
  type GitHubIssueDisclosure,
  type HackerOneReport,
  type OssSecurityPost,
  type PacketStormEntry,
} from './lib/breachFeeds'
import type { NormalizedDisclosure } from './lib/breachFeeds'

// ── Shared helper (mirrors the one in breachIngest.ts) ────────────────────────

function disclosureToArgs(
  tenantSlug: string,
  repositoryFullName: string,
  d: NormalizedDisclosure,
) {
  return {
    tenantSlug,
    repositoryFullName,
    packageName: d.packageName,
    sourceName: d.sourceName,
    sourceRef: d.sourceRef,
    summary: d.summary,
    ecosystem: d.ecosystem,
    sourceType: d.sourceType as 'github_issues' | 'hackerone' | 'oss_security' | 'packet_storm' | 'manual' | 'github_security_advisory' | 'osv' | 'nvd' | 'npm_advisory' | 'pypi_safety' | 'rustsec' | 'go_vuln',
    sourceTier: d.sourceTier as 'tier_1' | 'tier_2' | 'tier_3',
    affectedVersions: d.affectedVersions,
    fixVersion: d.fixVersion,
    exploitAvailable: d.exploitAvailable,
    aliases: d.aliases,
    publishedAt: d.publishedAt,
    severity: d.severity,
  }
}

// ── Shared RSS parser ─────────────────────────────────────────────────────────

function parseRssItems(
  xml: string,
  limit: number,
): Array<{ title: string; link: string; description?: string; pubDate?: string; category?: string }> {
  const itemRe = /<item>([\s\S]*?)<\/item>/g
  const get = (block: string, tag: string): string | undefined => {
    const m = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`).exec(block)
    return m?.[1]?.trim()
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
  }

  const items: Array<{ title: string; link: string; description?: string; pubDate?: string; category?: string }> = []
  let m: RegExpExecArray | null

  while ((m = itemRe.exec(xml)) !== null && items.length < limit) {
    const b = m[1]
    const title = get(b, 'title') ?? ''
    const link = get(b, 'link') ?? ''
    if (!title || !link) continue
    items.push({ title, link, description: get(b, 'description'), pubDate: get(b, 'pubDate'), category: get(b, 'category') })
  }
  return items
}

function guessEcosystem(content: string): string {
  if (/\bnpm\b|node\.js|javascript/.test(content)) return 'npm'
  if (/pypi|python|pip\b/.test(content)) return 'pip'
  if (/\bruby\b|rubygem/.test(content)) return 'gem'
  if (/golang|\bgo\b/.test(content)) return 'go'
  if (/\brust\b|cargo/.test(content)) return 'cargo'
  if (/\bjava\b|maven|gradle/.test(content)) return 'maven'
  if (/\bphp\b|composer/.test(content)) return 'composer'
  return 'unknown'
}

// ── GitHub Issues Security Scanner ───────────────────────────────────────────

const SECURITY_LABELS = [
  'security', 'vulnerability', 'security-advisory', 'exploit', 'critical',
]

export const scanGithubIssuesForPackage = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** GitHub "owner/repo" path for the package source repository */
    packageRepoPath: v.string(),
    packageName: v.string(),
    ecosystem: v.string(),
    lookbackDays: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN
    const since = new Date(
      Date.now() - (args.lookbackDays ?? 30) * 24 * 3600 * 1000,
    ).toISOString().slice(0, 10)

    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Sentinel-Security-Agent/1.0',
    }
    if (token) headers.Authorization = `Bearer ${token}`

    const labelQuery = SECURITY_LABELS.map((l) => `label:"${l}"`).join(' OR ')
    const q = encodeURIComponent(
      `repo:${args.packageRepoPath} is:issue created:>=${since} (${labelQuery})`,
    )

    const resp = await fetch(
      `https://api.github.com/search/issues?q=${q}&sort=created&per_page=20`,
      { headers },
    )
    if (!resp.ok) throw new ConvexError(`GitHub Issues search failed: ${resp.status}`)

    const data = (await resp.json()) as {
      items?: Array<{
        number: number; title: string; body?: string | null; html_url: string
        state: string; labels: Array<{ name: string }>; created_at?: string | null; closed_at?: string | null
      }>
    }

    let imported = 0; let skipped = 0

    for (const issue of data.items ?? []) {
      const disclosure: GitHubIssueDisclosure = {
        issueNumber: issue.number, title: issue.title, body: issue.body,
        htmlUrl: issue.html_url, state: issue.state === 'open' ? 'open' : 'closed',
        labels: issue.labels.map((l) => l.name), createdAt: issue.created_at,
        closedAt: issue.closed_at, packageName: args.packageName,
        ecosystem: args.ecosystem, repoFullName: args.packageRepoPath,
      }
      const normalized = normalizeGithubIssueDisclosure(disclosure)
      try {
        await ctx.runMutation(api.events.ingestBreachDisclosure,
          disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))
        imported++
      } catch { skipped++ }
    }
    return { total: (data.items ?? []).length, imported, skipped }
  },
})

// ── HackerOne Disclosed Reports ───────────────────────────────────────────────

export const syncHackerOneDisclosures = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** HackerOne program handles to query (e.g. "nodejs", "rails") */
    programHandles: v.array(v.string()),
    ecosystem: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const identifier = process.env.HACKERONE_API_IDENTIFIER
    const apiKey = process.env.HACKERONE_API_KEY
    if (!identifier || !apiKey) {
      console.log('[hackerone] credentials not set — skipping')
      return { total: 0, imported: 0, skipped: 0 }
    }
    const authHeader = `Basic ${btoa(`${identifier}:${apiKey}`)}`
    let imported = 0; let skipped = 0; let total = 0

    for (const handle of args.programHandles.slice(0, 10)) {
      const resp = await fetch(
        `https://api.hackerone.com/v1/reports?filter[program][]=${encodeURIComponent(handle)}&filter[state]=disclosed&page[size]=10&sort=-disclosed_at`,
        { headers: { Authorization: authHeader, Accept: 'application/json' } },
      )
      if (!resp.ok) { skipped++; continue }

      const data = (await resp.json()) as {
        data?: Array<{
          id: string
          attributes: HackerOneReport & { disclosed_at?: string; state?: string }
          relationships?: { weakness?: { data?: { attributes?: { name?: string } } } }
        }>
      }

      for (const report of data.data ?? []) {
        total++
        const attrs = report.attributes
        const normalized = normalizeHackerOneReport(
          { id: report.id, title: attrs.title, vulnerability_information: attrs.vulnerability_information,
            state: attrs.state ?? 'disclosed', severity: attrs.severity,
            weakness: { name: report.relationships?.weakness?.data?.attributes?.name },
            program: { handle }, disclosed_at: attrs.disclosed_at, cve_ids: attrs.cve_ids },
          handle, args.ecosystem ?? 'unknown',
        )
        try {
          await ctx.runMutation(api.events.ingestBreachDisclosure,
            disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))
          imported++
        } catch { skipped++ }
      }
    }
    return { total, imported, skipped }
  },
})

// ── oss-security Mailing List ─────────────────────────────────────────────────

export const syncOssSecurityList = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Package names from SBOM to match against post content */
    packages: v.array(v.string()),
    maxItems: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const maxItems = Math.min(args.maxItems ?? 50, 100)
    let xml: string
    try {
      const resp = await fetch('https://marc.info/?l=oss-security&r=1&b=&q=&w=4&o=o&s=&n=&f=XML', {
        headers: { 'User-Agent': 'Sentinel-Security-Agent/1.0' },
        signal: AbortSignal.timeout(15_000),
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      xml = await resp.text()
    } catch (err) {
      console.warn(`[oss-security] RSS fetch failed: ${err}`)
      return { total: 0, imported: 0, skipped: 0 }
    }

    const items = parseRssItems(xml, maxItems)
    let imported = 0; let skipped = 0

    for (const item of items) {
      const content = `${item.title} ${item.description ?? ''}`.toLowerCase()
      const matchedPkg = args.packages.find((p) => content.includes(p.toLowerCase()))
      if (!matchedPkg) continue
      const post: OssSecurityPost = { ...item, packageName: matchedPkg, ecosystem: guessEcosystem(content) }
      const normalized = normalizeOssSecurityPost(post)
      if (!normalized) { skipped++; continue }
      try {
        await ctx.runMutation(api.events.ingestBreachDisclosure,
          disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))
        imported++
      } catch { skipped++ }
    }
    return { total: items.length, imported, skipped }
  },
})

// ── Packet Storm Security ─────────────────────────────────────────────────────

export const syncPacketStormAdvisories = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    packages: v.array(v.string()),
    maxItems: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const maxItems = Math.min(args.maxItems ?? 30, 50)
    let xml: string
    try {
      const resp = await fetch('https://rss.packetstormsecurity.com/files/advisories/', {
        headers: { 'User-Agent': 'Sentinel-Security-Agent/1.0' },
        signal: AbortSignal.timeout(15_000),
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      xml = await resp.text()
    } catch (err) {
      console.warn(`[packet-storm] RSS fetch failed: ${err}`)
      return { total: 0, imported: 0, skipped: 0 }
    }

    const items = parseRssItems(xml, maxItems)
    let imported = 0; let skipped = 0

    for (const item of items) {
      const content = `${item.title} ${item.description ?? ''}`.toLowerCase()
      const matchedPkg = args.packages.find((p) => content.includes(p.toLowerCase()))
      if (!matchedPkg) continue
      const entry: PacketStormEntry = { ...item }
      const normalized = normalizePacketStormEntry(entry, matchedPkg, guessEcosystem(content))
      if (!normalized) { skipped++; continue }
      try {
        await ctx.runMutation(api.events.ingestBreachDisclosure,
          disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))
        imported++
      } catch { skipped++ }
    }
    return { total: items.length, imported, skipped }
  },
})

