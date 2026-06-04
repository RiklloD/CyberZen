/**
 * Tier 3 Breach Intelligence Feeds — spec §3.10.2
 *
 * Dark web and credential intelligence. These signals appear before any
 * public disclosure — the highest-urgency early warning tier.
 *
 * Sources implemented:
 *   - Paste site monitoring (Pastebin public RSS, generic paste site search)
 *   - HaveIBeenPwned domain search (credential dumps affecting customer domain)
 *   - Dark web mention ingestion (operator-submitted intel, scaffold for future)
 *
 * Architecture note: Full Tor-based dark web monitoring requires a separate
 * Tor-capable agent. This module provides:
 *   1. The ingestion pipeline (normalizers already in breachFeeds.ts)
 *   2. Accessible public sources (Pastebin RSS, HIBP API)
 *   3. A `ingestDarkWebMention` mutation for operator-submitted or
 *      third-party-fed dark web intelligence
 *
 * New env vars:
 *   HIBP_API_KEY        — HaveIBeenPwned API key (required for domain search)
 *   PASTEBIN_API_KEY    — Optional Pastebin Pro API key (higher rate limits)
 *   CUSTOMER_DOMAIN     — Primary customer domain for credential monitoring
 */

import { ConvexError, v } from 'convex/values'
import { action, mutation, query } from './_generated/server'
import { api } from './_generated/api'
import {
  normalizePasteSiteMention,
  normalizeHibpDomainBreach,
  normalizeDarkWebMention,
  type PasteSiteMention,
  type HibpDomainBreach,
  type DarkWebMention,
} from './lib/breachFeeds'
import type { NormalizedDisclosure } from './lib/breachFeeds'

// ── Shared helper ─────────────────────────────────────────────────────────────

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
    sourceType: d.sourceType as
      | 'paste_site' | 'credential_dump' | 'dark_web_mention'
      | 'manual' | 'github_security_advisory' | 'osv' | 'nvd'
      | 'npm_advisory' | 'pypi_safety' | 'rustsec' | 'go_vuln'
      | 'github_issues' | 'hackerone' | 'oss_security' | 'packet_storm',
    sourceTier: d.sourceTier as 'tier_1' | 'tier_2' | 'tier_3',
    affectedVersions: d.affectedVersions,
    fixVersion: d.fixVersion,
    exploitAvailable: d.exploitAvailable,
    aliases: d.aliases,
    publishedAt: d.publishedAt,
    severity: d.severity,
  }
}

// ── Paste site monitoring ─────────────────────────────────────────────────────
//
// Monitors public paste sites for mentions of:
//   - Package names from the SBOM
//   - Customer domain strings
//   - NPM tokens (npm_*) / PyPI tokens / GitHub tokens (ghp_*, ghs_*)
//
// Pastebin public RSS: https://pastebin.com/rss.php (no auth, 10 min cache)
// We scrape the latest pastes and search for keyword matches.

const PASTEBIN_RSS = 'https://pastebin.com/rss.php'

// Token patterns that indicate a credential dump
const CREDENTIAL_PATTERNS = [
  /npm_[A-Za-z0-9]{36}/,     // npm auth tokens
  /ghp_[A-Za-z0-9]{36}/,     // GitHub personal access tokens
  /ghs_[A-Za-z0-9]{36}/,     // GitHub secret tokens
  /pypi-[A-Za-z0-9]{36}/,    // PyPI API tokens
  /sk-[A-Za-z0-9]{48}/,      // OpenAI API keys
  /AKIA[A-Z0-9]{16}/,         // AWS access key IDs
  /password\s*[:=]\s*\S{8,}/i, // password assignments
  /passwd\s*[:=]\s*\S{8,}/i,
]

function detectCredentials(content: string): boolean {
  return CREDENTIAL_PATTERNS.some((pattern) => pattern.test(content))
}

function classifySensitivity(
  content: string,
  _matchedTerm: string,
): PasteSiteMention['sensitivityLevel'] {
  const hasCredentials = detectCredentials(content)
  if (hasCredentials) return 'critical'
  if (/exploit|poc|proof.of.concept|remote.code.execution|rce/i.test(content)) return 'high'
  if (/vulnerability|cve|security|injection|xss|sqli/i.test(content)) return 'medium'
  return 'low'
}

export const scanPasteSites = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Package names or domain strings to search for */
    searchTerms: v.array(v.string()),
    minSensitivity: v.optional(
      v.union(v.literal('low'), v.literal('medium'), v.literal('high'), v.literal('critical')),
    ),
  },
  handler: async (ctx, args) => {
    const minLevel = args.minSensitivity ?? 'medium'
    const severityOrder = ['low', 'medium', 'high', 'critical']
    const minIdx = severityOrder.indexOf(minLevel)

    // Fetch Pastebin RSS
    let xml: string
    try {
      const resp = await fetch(PASTEBIN_RSS, {
        headers: { 'User-Agent': 'Sentinel-Security-Agent/1.0' },
        signal: AbortSignal.timeout(15_000),
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      xml = await resp.text()
    } catch (err) {
      console.warn(`[paste-site] Pastebin RSS failed: ${err}`)
      return { scanned: 0, matched: 0, imported: 0 }
    }

    // Parse RSS items
    const itemRe = /<item>([\s\S]*?)<\/item>/g
    const titleRe = /<title[^>]*>([\s\S]*?)<\/title>/
    const linkRe = /<link>([\s\S]*?)<\/link>/
    const descRe = /<description>([\s\S]*?)<\/description>/
    const dateRe = /<pubDate>([\s\S]*?)<\/pubDate>/

    const items: Array<{ title: string; link: string; content: string; date?: string }> = []
    let m: RegExpExecArray | null

    while ((m = itemRe.exec(xml)) !== null) {
      const b = m[1]
      const title = titleRe.exec(b)?.[1]?.trim() ?? ''
      const link = linkRe.exec(b)?.[1]?.trim() ?? ''
      const content = descRe.exec(b)?.[1]?.trim() ?? ''
      const date = dateRe.exec(b)?.[1]?.trim()
      if (!link) continue
      items.push({ title, link, content, date })
    }

    let matched = 0; let imported = 0

    for (const item of items) {
      const combinedText = `${item.title} ${item.content}`.toLowerCase()
      const matchedTerm = args.searchTerms.find((t) => combinedText.includes(t.toLowerCase()))
      if (!matchedTerm) continue

      const sensitivity = classifySensitivity(item.content, matchedTerm)
      if (severityOrder.indexOf(sensitivity) < minIdx) continue

      matched++

      // Extract paste ID from URL (e.g. https://pastebin.com/AbCd1234 → AbCd1234)
      const pasteId = item.link.split('/').pop() ?? item.link

      const mention: PasteSiteMention = {
        pasteId,
        title: item.title || undefined,
        content: item.content.slice(0, 2000),
        url: item.link,
        pasteDate: item.date,
        matchedTerm,
        containsCredentials: detectCredentials(item.content),
        sensitivityLevel: sensitivity,
      }

      const normalized = normalizePasteSiteMention(mention, matchedTerm, 'unknown')

      try {
        await ctx.runMutation(api.events.ingestBreachDisclosure,
          disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))
        imported++
      } catch (err) {
        console.warn(`[paste-site] ingest failed: ${err}`)
      }
    }

    return { scanned: items.length, matched, imported }
  },
})

// ── HaveIBeenPwned domain search ──────────────────────────────────────────────
//
// Checks if any accounts on the customer domain have appeared in known
// credential breaches. A compromised engineer account can enable:
//   - npm publish of backdoored packages
//   - Git credential theft → supply chain compromise
//
// Requires HIBP_API_KEY env var.
// Rate limit: 1 request per 1500ms per API key.
// API docs: https://haveibeenpwned.com/API/v3

export const checkHibpDomainBreaches = action({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    /** Customer domain to check e.g. "acme.com" */
    customerDomain: v.string(),
    /** Only import breaches newer than this many days */
    lookbackDays: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const apiKey = process.env.HIBP_API_KEY
    if (!apiKey) {
      console.log('[hibp] HIBP_API_KEY not set — skipping domain breach check')
      return { checked: false, breaches: 0, imported: 0 }
    }

    const resp = await fetch(
      `https://haveibeenpwned.com/api/v3/breacheddomain/${encodeURIComponent(args.customerDomain)}`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'Sentinel-Security-Agent/1.0',
          Accept: 'application/json',
        },
      },
    )

    if (resp.status === 404) {
      return { checked: true, breaches: 0, imported: 0, reason: 'no_breaches' }
    }
    if (!resp.ok) {
      throw new ConvexError(`HIBP API error: ${resp.status}`)
    }

    const data = (await resp.json()) as Record<string, string[]>
    // Format: { "email@domain.com": ["BreachName1", "BreachName2"] }
    const breachNames = new Set(Object.values(data).flat())

    const lookbackMs = (args.lookbackDays ?? 365) * 24 * 3600 * 1000
    const cutoff = Date.now() - lookbackMs
    let imported = 0

    // Fetch breach details for each unique breach name
    for (const breachName of Array.from(breachNames).slice(0, 20)) {
      try {
        const breachResp = await fetch(
          `https://haveibeenpwned.com/api/v3/breach/${encodeURIComponent(breachName)}`,
          {
            headers: {
              'hibp-api-key': apiKey,
              'User-Agent': 'Sentinel-Security-Agent/1.0',
            },
          },
        )
        if (!breachResp.ok) continue

        const breach = (await breachResp.json()) as HibpDomainBreach

        // Skip old breaches
        if (breach.AddedDate && Date.parse(breach.AddedDate) < cutoff) continue

        // Skip fabricated or non-verified breaches
        if (breach.IsFabricated) continue

        const normalized = normalizeHibpDomainBreach(breach, args.customerDomain)
        await ctx.runMutation(api.events.ingestBreachDisclosure,
          disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))
        imported++
      } catch {
        // Skip individual breach fetch failures
      }
    }

    return { checked: true, breaches: breachNames.size, imported }
  },
})

// ── Manual dark web intelligence ingestion ────────────────────────────────────
//
// Allows security operators or third-party dark web intelligence services to
// feed mentions directly into Sentinel's ingestion pipeline via the API.
// This is the integration point for future Tor-capable agents or licensed
// threat intelligence feeds (Recorded Future, Mandiant, etc.).

export const ingestDarkWebMention = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
    source: v.union(
      v.literal('telegram_channel'),
      v.literal('forum'),
      v.literal('marketplace'),
      v.literal('irc_channel'),
    ),
    sourceName: v.string(),
    title: v.string(),
    snippet: v.string(),
    matchedPackage: v.string(),
    ecosystem: v.string(),
    exploitConfidence: v.union(v.literal('low'), v.literal('medium'), v.literal('high')),
    cveId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const mention: DarkWebMention = {
      id: `manual-${Date.now()}`,
      source: args.source,
      sourceName: args.sourceName,
      title: args.title,
      snippet: args.snippet,
      detectedAt: new Date().toISOString(),
      matchedPackage: args.matchedPackage,
      ecosystem: args.ecosystem,
      exploitConfidence: args.exploitConfidence,
      cveId: args.cveId,
    }

    const normalized = normalizeDarkWebMention(mention)

    await ctx.runMutation(api.events.ingestBreachDisclosure,
      disclosureToArgs(args.tenantSlug, args.repositoryFullName, normalized))

    return { ingested: true, severity: normalized.severity }
  },
})

// ── Dashboard query — Tier 3 signal summary ───────────────────────────────────

export const getTier3SignalSummary = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const tier3Types = ['paste_site', 'credential_dump', 'dark_web_mention']

    const disclosures = await ctx.db
      .query('breachDisclosures')
      .withIndex('by_published_at')
      .order('desc')
      .take(200)

    const tier3 = disclosures.filter((d) => tier3Types.includes(d.sourceType))

    return {
      total: tier3.length,
      pasteSite: tier3.filter((d) => d.sourceType === 'paste_site').length,
      credentialDump: tier3.filter((d) => d.sourceType === 'credential_dump').length,
      darkWebMention: tier3.filter((d) => d.sourceType === 'dark_web_mention').length,
      latest: tier3[0] ?? null,
      criticalCount: tier3.filter((d) => d.severity === 'critical').length,
    }
  },
})

