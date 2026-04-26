import { v } from 'convex/values'
import { internalMutation } from './_generated/server'
import {
  buildDisclosureMatchSummary,
  matchDisclosureToInventory,
  normalizePackageName,
} from './lib/breachMatching'

type BackfillBreachDisclosure = {
  _id: string
  packageName: string
  ecosystem: string
  sourceName: string
  summary: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  publishedAt: number
  affectedVersions: string[]
  fixVersion?: string
  repositoryId?: string
  aliases?: string[]
  sourceRef?: string
  sourceType?:
    | 'manual'
    | 'github_security_advisory'
    | 'osv'
    | 'nvd'
    | 'npm_advisory'
    | 'pypi_safety'
    | 'rustsec'
    | 'go_vuln'
    | 'github_issues'
    | 'hackerone'
    | 'oss_security'
    | 'packet_storm'
    | 'paste_site'
    | 'credential_dump'
    | 'dark_web_mention'
    | 'cisa_kev'
    | 'telegram'
  sourceTier?:
    | 'tier_1'
    | 'tier_2'
    | 'tier_3'
  normalizedPackageName?: string
  matchStatus?:
    | 'matched'
    | 'version_unaffected'
    | 'version_unknown'
    | 'unmatched'
    | 'no_snapshot'
  versionMatchStatus?: 'affected' | 'unaffected' | 'unknown'
  matchedComponentCount?: number
  affectedComponentCount?: number
  matchedVersions?: string[]
  affectedMatchedVersions?: string[]
  matchSummary?: string
}

type BackfillSbomComponent = {
  _id: string
  name: string
  normalizedName?: string
}

function inferSourceType(
  sourceName: string,
):
  | 'manual'
  | 'github_security_advisory'
  | 'osv'
  | 'nvd'
  | 'npm_advisory'
  | 'pypi_safety'
  | 'rustsec'
  | 'go_vuln'
  | 'github_issues'
  | 'hackerone'
  | 'oss_security'
  | 'packet_storm'
  | 'paste_site'
  | 'credential_dump'
  | 'dark_web_mention'
  | 'cisa_kev'
  | 'telegram' {
  const low = sourceName.toLowerCase()
  if (low.includes('github security advisory')) return 'github_security_advisory'
  if (low.includes('osv')) return 'osv'
  if (low.includes('nvd')) return 'nvd'
  if (low.includes('npm')) return 'npm_advisory'
  if (low.includes('pypi')) return 'pypi_safety'
  if (low.includes('rustsec')) return 'rustsec'
  if (low.includes('go vuln') || low.includes('go-vuln')) return 'go_vuln'
  if (low.includes('github issue')) return 'github_issues'
  if (low.includes('hackerone')) return 'hackerone'
  if (low.includes('oss security')) return 'oss_security'
  if (low.includes('packet storm')) return 'packet_storm'
  if (low.includes('paste')) return 'paste_site'
  if (low.includes('credential dump')) return 'credential_dump'
  if (low.includes('dark web')) return 'dark_web_mention'
  if (low.includes('cisa kev') || low.includes('kev')) return 'cisa_kev'
  if (low.includes('telegram')) return 'telegram'
  return 'manual'
}

function syntheticSourceRef(disclosure: BackfillBreachDisclosure) {
  return `${disclosure.packageName}:${Math.trunc(disclosure.publishedAt)}`
}

export const backfillLegacyBreachDisclosures = internalMutation({
  args: {},
  returns: v.object({
    processed: v.number(),
  }),
  handler: async (ctx) => {
    const disclosures = (await ctx.db
      .query('breachDisclosures')
      .order('asc')
      .take(1000)) as BackfillBreachDisclosure[]

    let processed = 0

    for (const disclosure of disclosures) {
      const patch: Record<string, unknown> = {}

      const normalizedPackageName =
        disclosure.normalizedPackageName ??
        normalizePackageName(disclosure.packageName)
      patch.normalizedPackageName = normalizedPackageName

      patch.sourceType = disclosure.sourceType ?? inferSourceType(disclosure.sourceName)
      patch.sourceRef = disclosure.sourceRef ?? syntheticSourceRef(disclosure)
      patch.aliases = disclosure.aliases ?? []
      patch.affectedComponentCount = disclosure.affectedComponentCount ?? 0
      patch.matchedComponentCount = disclosure.matchedComponentCount ?? 0
      patch.matchedVersions = disclosure.matchedVersions ?? []
      patch.affectedMatchedVersions = disclosure.affectedMatchedVersions ?? []
      patch.matchStatus = disclosure.matchStatus ?? 'unmatched'
      patch.versionMatchStatus = disclosure.versionMatchStatus ?? 'unknown'
      patch.matchSummary = disclosure.matchSummary ?? disclosure.summary

      if (disclosure.repositoryId) {
        const repository = await ctx.db.get(disclosure.repositoryId)
        if (repository) {
          const latestSnapshot = await ctx.db
            .query('sbomSnapshots')
            .withIndex('by_repository_and_captured_at', (q) =>
              q.eq('repositoryId', repository._id),
            )
            .order('desc')
            .first()

          if (latestSnapshot) {
            const components = (await ctx.db
              .query('sbomComponents')
              .withIndex('by_snapshot', (q) =>
                q.eq('snapshotId', latestSnapshot._id),
              )
              .take(1000)) as Array<{
              name: string
              normalizedName?: string
              version: string
              ecosystem: string
              layer: string
              isDirect: boolean
              sourceFile: string
              dependents: string[]
            }>

            const match = matchDisclosureToInventory({
              packageName: disclosure.packageName,
              ecosystem: disclosure.ecosystem,
              affectedVersions: disclosure.affectedVersions,
              fixVersion: disclosure.fixVersion,
              components,
            })

            patch.matchStatus = match.matchStatus
            patch.versionMatchStatus = match.versionMatchStatus
            patch.matchedComponentCount = match.matchedComponentCount
            patch.affectedComponentCount = match.affectedComponentCount
            patch.matchedVersions = match.matchedVersions
            patch.affectedMatchedVersions = match.affectedMatchedVersions
            patch.matchSummary = buildDisclosureMatchSummary({
              packageName: disclosure.packageName,
              repositoryName: repository.name,
              matchStatus: match.matchStatus,
              matchedComponentCount: match.matchedComponentCount,
              affectedComponentCount: match.affectedComponentCount,
              matchedVersions: match.matchedVersions,
              affectedMatchedVersions: match.affectedMatchedVersions,
              affectedVersions: disclosure.affectedVersions,
              fixVersion: disclosure.fixVersion,
            })
          } else {
            patch.matchStatus = 'no_snapshot'
            patch.versionMatchStatus = 'unknown'
            patch.matchSummary = buildDisclosureMatchSummary({
              packageName: disclosure.packageName,
              repositoryName: repository.name,
              matchStatus: 'no_snapshot',
              matchedComponentCount: 0,
              affectedComponentCount: 0,
              matchedVersions: [],
              affectedMatchedVersions: [],
              affectedVersions: disclosure.affectedVersions,
              fixVersion: disclosure.fixVersion,
            })
          }
        }
      }

      await ctx.db.patch(disclosure._id, patch)
      processed++
    }

    return { processed }
  },
})

export const backfillLegacySbomComponents = internalMutation({
  args: {},
  returns: v.object({
    processed: v.number(),
  }),
  handler: async (ctx) => {
    const components = (await ctx.db
      .query('sbomComponents')
      .order('asc')
      .take(1000)) as BackfillSbomComponent[]

    let processed = 0

    for (const component of components) {
      if (component.normalizedName !== undefined) {
        continue
      }

      await ctx.db.patch(component._id, {
        normalizedName: normalizePackageName(component.name),
      })
      processed++
    }

    return { processed }
  },
})
