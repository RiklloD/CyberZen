import { describe, expect, test } from 'vitest'
import {
  coerceGithubSecurityAdvisoryInput,
  coerceOsvAdvisoryInput,
  normalizeGithubSecurityAdvisory,
  normalizeGoVulnEntry,
  normalizeGithubIssueDisclosure,
  normalizeHackerOneReport,
  normalizeOssSecurityPost,
  normalizePacketStormEntry,
  normalizePasteSiteMention,
  normalizeHibpDomainBreach,
  normalizeDarkWebMention,
  normalizeNpmAdvisory,
  normalizeNvdCve,
  normalizeOsvAdvisory,
  normalizePypiSafetyEntry,
  normalizeRustSecAdvisory,
} from './breachFeeds'

describe('breachFeeds', () => {
  test('normalizes github advisories and selects the repo-matching package', () => {
    const normalized = normalizeGithubSecurityAdvisory({
      advisory: {
        ghsaId: 'GHSA-77m4-fm8m-6h7p',
        summary: 'PyJWT advisory',
        severity: 'high',
        vulnerabilities: [
          {
            packageName: 'requests',
            ecosystem: 'pip',
            vulnerableVersionRange: '<2.31.0',
            firstPatchedVersion: '2.31.1',
          },
          {
            packageName: 'PyJWT',
            ecosystem: 'pip',
            vulnerableVersionRange: '>=2.8.0, <2.10.2',
            firstPatchedVersion: '2.10.2',
          },
        ],
      },
      inventoryComponents: [
        {
          name: 'pyjwt',
          version: '2.10.1',
          ecosystem: 'pypi',
          layer: 'transitive',
          isDirect: false,
          sourceFile: 'poetry.lock',
          dependents: ['auth-core'],
        },
      ],
    })

    expect(normalized.packageName).toBe('PyJWT')
    expect(normalized.ecosystem).toBe('pypi')
    expect(normalized.sourceType).toBe('github_security_advisory')
    expect(normalized.affectedVersions).toEqual(['>=2.8.0, <2.10.2'])
    expect(normalized.fixVersion).toBe('2.10.2')
  })

  test('normalizes osv advisories and converts range events to affected ranges', () => {
    const normalized = normalizeOsvAdvisory({
      advisory: {
        id: 'OSV-2026-0001',
        summary: 'PyJWT advisory',
        severityScore: 8.4,
        affected: [
          {
            packageName: 'pyjwt',
            ecosystem: 'PyPI',
            ranges: [
              {
                type: 'ECOSYSTEM',
                events: [
                  { introduced: '2.8.0' },
                  { fixed: '2.10.2' },
                ],
              },
            ],
          },
        ],
      },
    })

    expect(normalized.packageName).toBe('pyjwt')
    expect(normalized.sourceType).toBe('osv')
    expect(normalized.severity).toBe('high')
    expect(normalized.affectedVersions).toEqual(['>=2.8.0, <2.10.2'])
    expect(normalized.fixVersion).toBe('2.10.2')
  })

  test('coerces live github advisory payloads into the normalized advisory input shape', () => {
    const advisory = coerceGithubSecurityAdvisoryInput({
      ghsa_id: 'GHSA-77m4-fm8m-6h7p',
      summary: 'PyJWT advisory',
      description: 'Imported from the GitHub advisories API.',
      severity: 'high',
      published_at: '2026-04-05T10:15:00Z',
      identifiers: [
        { type: 'GHSA', value: 'GHSA-77m4-fm8m-6h7p' },
        { type: 'CVE', value: 'CVE-2026-1234' },
      ],
      vulnerabilities: [
        {
          package: { name: 'PyJWT', ecosystem: 'pip' },
          vulnerable_version_range: '>=2.8.0, <2.10.2',
          first_patched_version: { identifier: '2.10.2' },
        },
      ],
    })

    expect(advisory.ghsaId).toBe('GHSA-77m4-fm8m-6h7p')
    expect(advisory.aliases).toEqual(['CVE-2026-1234'])
    expect(advisory.vulnerabilities).toEqual([
      {
        packageName: 'PyJWT',
        ecosystem: 'pip',
        vulnerableVersionRange: '>=2.8.0, <2.10.2',
        firstPatchedVersion: '2.10.2',
      },
    ])
    expect(advisory.publishedAt).toBe(Date.parse('2026-04-05T10:15:00Z'))
  })

  test('coerces live osv payloads and preserves package ranges', () => {
    const advisory = coerceOsvAdvisoryInput({
      id: 'GHSA-abcd-1234-efgh',
      summary: 'PyJWT advisory',
      details: 'Imported from OSV.',
      aliases: ['GHSA-abcd-1234-efgh', 'CVE-2026-9876'],
      published: '2026-04-04T08:30:00Z',
      database_specific: {
        severity: 'HIGH',
      },
      affected: [
        {
          package: {
            name: 'pyjwt',
            ecosystem: 'PyPI',
          },
          ranges: [
            {
              type: 'ECOSYSTEM',
              events: [
                { introduced: '2.8.0' },
                { fixed: '2.10.2' },
              ],
            },
          ],
          versions: ['2.10.1'],
        },
      ],
    })

    expect(advisory.id).toBe('GHSA-abcd-1234-efgh')
    expect(advisory.aliases).toEqual(['CVE-2026-9876'])
    expect(advisory.severity).toBe('high')
    expect(advisory.publishedAt).toBe(Date.parse('2026-04-04T08:30:00Z'))
    expect(advisory.affected).toEqual([
      {
        packageName: 'pyjwt',
        ecosystem: 'PyPI',
        versions: ['2.10.1'],
        ranges: [
          {
            type: 'ECOSYSTEM',
            events: [
              { introduced: '2.8.0' },
              { fixed: '2.10.2' },
            ],
          },
        ],
      },
    ])
  })
})

// ── New Tier 1 feed adapters ─────────────────────────────────────────────────

describe('normalizeNvdCve', () => {
  test('maps CVSS v3.1 severity correctly', () => {
    const result = normalizeNvdCve({
      cve: {
        id: 'CVE-2024-1234',
        published: '2024-01-15T12:00:00.000',
        descriptions: [{ lang: 'en', value: 'A critical vulnerability in example-lib' }],
        metrics: {
          cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }],
        },
      },
      packageName: 'example-lib',
      ecosystem: 'npm',
      affectedVersions: ['<2.0.0'],
      fixVersion: '2.0.0',
    })

    expect(result.sourceType).toBe('nvd')
    expect(result.sourceTier).toBe('tier_1')
    expect(result.severity).toBe('critical')
    expect(result.sourceRef).toBe('CVE-2024-1234')
    expect(result.aliases).toContain('CVE-2024-1234')
    expect(result.fixVersion).toBe('2.0.0')
    expect(result.ecosystem).toBe('npm')
  })

  test('falls back to v3 metrics when v3.1 absent', () => {
    const result = normalizeNvdCve({
      cve: {
        id: 'CVE-2024-5678',
        published: '2024-03-10T00:00:00.000',
        descriptions: [{ lang: 'en', value: 'High severity vuln' }],
        metrics: {
          cvssMetricV3: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }],
        },
      },
      packageName: 'some-pkg',
      ecosystem: 'pypi',
    })

    expect(result.severity).toBe('high')
    expect(result.ecosystem).toBe('pypi')
  })

  test('defaults severity to medium when metrics absent', () => {
    const result = normalizeNvdCve({
      cve: { id: 'CVE-2024-0000', published: '2024-01-01T00:00:00.000' },
      packageName: 'pkg',
      ecosystem: 'cargo',
    })

    expect(result.severity).toBe('medium')
  })
})

describe('normalizeNpmAdvisory', () => {
  test('normalizes a standard npm advisory', () => {
    const result = normalizeNpmAdvisory({
      id: 12345,
      url: 'https://npmjs.com/advisories/12345',
      title: 'Prototype Pollution in lodash',
      severity: 'high',
      module_name: 'lodash',
      vulnerable_versions: '<4.17.21',
      patched_versions: '>=4.17.21',
      cves: ['CVE-2021-23337'],
      created: '2021-02-15T00:00:00.000Z',
    })

    expect(result).not.toBeNull()
    expect(result!.sourceType).toBe('npm_advisory')
    expect(result!.sourceTier).toBe('tier_1')
    expect(result!.packageName).toBe('lodash')
    expect(result!.ecosystem).toBe('npm')
    expect(result!.severity).toBe('high')
    expect(result!.aliases).toContain('CVE-2021-23337')
  })

  test('returns null when package name missing', () => {
    expect(normalizeNpmAdvisory({ title: 'No package' })).toBeNull()
  })
})

describe('normalizePypiSafetyEntry', () => {
  test('normalizes a safety DB entry', () => {
    const result = normalizePypiSafetyEntry([
      'requests',
      '<2.28.0',
      'GHSA-xyz-1234',
      'SSRF vulnerability in requests library before 2.28.0',
    ])

    expect(result).not.toBeNull()
    expect(result!.sourceType).toBe('pypi_safety')
    expect(result!.packageName).toBe('requests')
    expect(result!.ecosystem).toBe('pip')
    expect(result!.sourceRef).toBe('GHSA-xyz-1234')
    expect(result!.affectedVersions).toContain('<2.28.0')
  })

  test('returns null when vulnId missing', () => {
    expect(normalizePypiSafetyEntry(['pkg', '<1.0', '', 'desc'])).toBeNull()
  })
})

describe('normalizeRustSecAdvisory', () => {
  test('normalizes a RustSec advisory', () => {
    const result = normalizeRustSecAdvisory({
      id: 'RUSTSEC-2024-0001',
      package: 'tokio',
      date: '2024-02-01',
      title: 'Race condition in tokio',
      description: 'A race condition exists in tokio affecting task scheduling.',
      versions: { patched: ['>=1.36.0'] },
      aliases: ['CVE-2024-9999'],
    })

    expect(result).not.toBeNull()
    expect(result!.sourceType).toBe('rustsec')
    expect(result!.packageName).toBe('tokio')
    expect(result!.ecosystem).toBe('cargo')
    expect(result!.fixVersion).toBe('1.36.0')
    expect(result!.aliases).toContain('RUSTSEC-2024-0001')
    expect(result!.aliases).toContain('CVE-2024-9999')
  })

  test('returns null when package is missing', () => {
    expect(normalizeRustSecAdvisory({ id: 'RUSTSEC-2024-0002' })).toBeNull()
  })
})

describe('normalizeGoVulnEntry', () => {
  test('normalizes a Go vulnerability DB entry', () => {
    const result = normalizeGoVulnEntry(
      {
        id: 'GO-2024-1234',
        published: '2024-03-01T00:00:00Z',
        aliases: ['CVE-2024-1111'],
        summary: 'Memory corruption in golang.org/x/net',
      },
      'golang.org/x/net',
      ['<0.20.0'],
      '0.20.0',
    )

    expect(result.sourceType).toBe('go_vuln')
    expect(result.sourceTier).toBe('tier_1')
    expect(result.ecosystem).toBe('go')
    expect(result.packageName).toBe('golang.org/x/net')
    expect(result.aliases).toContain('GO-2024-1234')
    expect(result.aliases).toContain('CVE-2024-1111')
    expect(result.fixVersion).toBe('0.20.0')
  })

  test('uses details as fallback when summary absent', () => {
    const result = normalizeGoVulnEntry(
      { id: 'GO-2024-0001', details: 'Long description of the vulnerability.' },
      'some/module',
      [],
    )
    expect(result.summary).toContain('Long description')
  })
})

// ── Tier 2 normalizers ────────────────────────────────────────────────────────

describe('normalizeGithubIssueDisclosure', () => {
  const base = {
    issueNumber: 42,
    title: 'Security: SQL injection in query builder',
    htmlUrl: 'https://github.com/acme/lib/issues/42',
    state: 'open' as const,
    labels: ['security', 'vulnerability', 'critical'],
    createdAt: '2026-03-01T12:00:00Z',
    packageName: 'acme-lib',
    ecosystem: 'npm',
    repoFullName: 'acme/lib',
  }

  test('normalizes a security-labelled GitHub issue', () => {
    const result = normalizeGithubIssueDisclosure(base)
    expect(result.sourceType).toBe('github_issues')
    expect(result.sourceTier).toBe('tier_2')
    expect(result.packageName).toBe('acme-lib')
    expect(result.ecosystem).toBe('npm')
    expect(result.severity).toBe('critical')
    expect(result.sourceRef).toBe(base.htmlUrl)
  })

  test('detects exploit availability from exploit label', () => {
    const withExploit = { ...base, labels: ['security', 'exploit', 'poc'] }
    const result = normalizeGithubIssueDisclosure(withExploit)
    expect(result.exploitAvailable).toBe(true)
  })

  test('no exploit label → exploitAvailable false', () => {
    const result = normalizeGithubIssueDisclosure(base)
    expect(result.exploitAvailable).toBe(false)
  })

  test('defaults to medium severity when no severity label', () => {
    const noSeverity = { ...base, labels: ['bug'] }
    const result = normalizeGithubIssueDisclosure(noSeverity)
    expect(result.severity).toBe('medium')
  })

  test('includes [Pre-CVE] prefix in summary', () => {
    const result = normalizeGithubIssueDisclosure(base)
    expect(result.summary).toContain('[Pre-CVE]')
  })
})

describe('normalizeHackerOneReport', () => {
  const report = {
    id: '12345',
    title: 'Remote Code Execution in framework XYZ',
    state: 'disclosed',
    severity: { rating: 'critical' },
    cve_ids: ['CVE-2026-1234'],
    disclosed_at: '2026-02-15T00:00:00Z',
  }

  test('normalizes a HackerOne disclosed report', () => {
    const result = normalizeHackerOneReport(report, 'framework-xyz', 'npm')
    expect(result.sourceType).toBe('hackerone')
    expect(result.sourceTier).toBe('tier_2')
    expect(result.severity).toBe('critical')
    expect(result.exploitAvailable).toBe(true)
    expect(result.aliases).toContain('CVE-2026-1234')
  })

  test('HackerOne reports always set exploitAvailable true', () => {
    const result = normalizeHackerOneReport({ ...report, severity: { rating: 'low' } }, 'pkg', 'pip')
    expect(result.exploitAvailable).toBe(true)
  })

  test('aliases include the hackerone report ID', () => {
    const result = normalizeHackerOneReport(report, 'pkg', 'npm')
    expect(result.aliases.some((a) => a.includes('12345'))).toBe(true)
  })
})

describe('normalizeOssSecurityPost', () => {
  const post = {
    title: '[SECURITY] lodash 4.17.20 - prototype pollution CVE-2026-9999',
    link: 'https://marc.info/?t=123456',
    description: 'Prototype pollution vulnerability in lodash affecting versions < 4.17.21',
    pubDate: 'Mon, 10 Mar 2026 12:00:00 +0000',
    packageName: 'lodash',
    ecosystem: 'npm',
  }

  test('normalizes an oss-security post with package name', () => {
    const result = normalizeOssSecurityPost(post)
    expect(result).not.toBeNull()
    expect(result!.sourceType).toBe('oss_security')
    expect(result!.sourceTier).toBe('tier_2')
    expect(result!.packageName).toBe('lodash')
  })

  test('extracts CVE ID into aliases', () => {
    const result = normalizeOssSecurityPost(post)
    expect(result!.aliases.some((a) => a.includes('CVE-2026-9999'))).toBe(true)
  })

  test('returns null when package name cannot be inferred', () => {
    const noPackage = { title: 'Some random post', link: 'https://example.com', pubDate: undefined }
    const result = normalizeOssSecurityPost(noPackage)
    expect(result).toBeNull()
  })

  test('detects exploit from title', () => {
    const exploitPost = { ...post, title: '[SECURITY] exploit published for lodash prototype pollution' }
    const result = normalizeOssSecurityPost(exploitPost)
    expect(result!.exploitAvailable).toBe(true)
  })
})

describe('normalizePacketStormEntry', () => {
  const entry = {
    title: 'Lodash Prototype Pollution Remote Code Execution',
    link: 'https://packetstormsecurity.com/files/123456',
    description: 'CVE-2026-9999 - Exploit for lodash <4.17.21',
    pubDate: 'Tue, 11 Mar 2026 00:00:00 +0000',
    category: 'exploit',
  }

  test('normalizes a Packet Storm entry', () => {
    const result = normalizePacketStormEntry(entry, 'lodash', 'npm')
    expect(result).not.toBeNull()
    expect(result!.sourceType).toBe('packet_storm')
    expect(result!.sourceTier).toBe('tier_2')
    expect(result!.packageName).toBe('lodash')
    expect(result!.ecosystem).toBe('npm')
  })

  test('exploit category → high severity', () => {
    const result = normalizePacketStormEntry(entry, 'lodash', 'npm')
    expect(result!.severity).toBe('high')
    expect(result!.exploitAvailable).toBe(true)
  })

  test('non-exploit advisory → medium severity', () => {
    const advisory = { ...entry, title: 'Security Advisory for lodash', category: 'advisory' }
    const result = normalizePacketStormEntry(advisory, 'lodash', 'npm')
    expect(result!.severity).toBe('medium')
  })

  test('extracts CVE from description', () => {
    const result = normalizePacketStormEntry(entry, 'lodash', 'npm')
    expect(result!.aliases.some((a) => a.includes('CVE-2026-9999'))).toBe(true)
  })

  test('returns null for empty package name', () => {
    expect(normalizePacketStormEntry(entry, '', 'npm')).toBeNull()
  })
})

// ── Tier 3 normalizers ────────────────────────────────────────────────────────

describe('normalizePasteSiteMention', () => {
  const mention = {
    pasteId: 'AbCd1234',
    title: 'Leaked npm tokens from ci pipeline',
    content: 'npm_ABC123456789012345678901234567890123 password=secret123',
    url: 'https://pastebin.com/AbCd1234',
    pasteDate: '2026-04-01T00:00:00Z',
    matchedTerm: 'acme-corp',
    containsCredentials: true,
    sensitivityLevel: 'critical' as const,
  }

  test('normalizes a paste site credential dump', () => {
    const result = normalizePasteSiteMention(mention, 'acme-corp', 'npm')
    expect(result.sourceType).toBe('paste_site')
    expect(result.sourceTier).toBe('tier_3')
    expect(result.severity).toBe('critical')
    expect(result.exploitAvailable).toBe(true)
    expect(result.sourceRef).toContain('pastebin.com')
  })

  test('low sensitivity → low severity and no exploit flag', () => {
    const low = { ...mention, sensitivityLevel: 'low' as const, containsCredentials: false }
    const result = normalizePasteSiteMention(low, 'pkg', 'npm')
    expect(result.severity).toBe('low')
    expect(result.exploitAvailable).toBe(false)
  })

  test('aliases include paste ID', () => {
    const result = normalizePasteSiteMention(mention, 'pkg', 'npm')
    expect(result.aliases.some((a) => a.includes('AbCd1234'))).toBe(true)
  })
})

describe('normalizeHibpDomainBreach', () => {
  const breach: Parameters<typeof normalizeHibpDomainBreach>[0] = {
    Name: 'Adobe',
    Title: 'Adobe',
    Domain: 'adobe.com',
    BreachDate: '2013-10-04',
    AddedDate: '2013-12-04T00:00:00Z',
    Description: 'Adobe breach affecting 153 million users.',
    DataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
    PwnCount: 152445165,
    IsVerified: true,
    IsFabricated: false,
    IsSensitive: false,
  }

  test('normalizes a HIBP domain breach', () => {
    const result = normalizeHibpDomainBreach(breach, 'acme.com')
    expect(result.sourceType).toBe('credential_dump')
    expect(result.sourceTier).toBe('tier_3')
    expect(result.severity).toBe('high')  // has password data class
    expect(result.sourceRef).toContain('haveibeenpwned.com')
  })

  test('breach with password data class → high severity', () => {
    const result = normalizeHibpDomainBreach(breach, 'acme.com')
    expect(result.severity).toBe('high')
  })

  test('breach without credentials → medium severity', () => {
    const noCredBreach = { ...breach, DataClasses: ['Email addresses', 'Names'] }
    const result = normalizeHibpDomainBreach(noCredBreach, 'acme.com')
    expect(result.severity).toBe('medium')
  })

  test('summary includes domain and PwnCount', () => {
    const result = normalizeHibpDomainBreach(breach, 'acme.com')
    expect(result.summary).toContain('acme.com')
    expect(result.summary).toMatch(/152/)
  })

  test('packageName encodes domain', () => {
    const result = normalizeHibpDomainBreach(breach, 'acme.com')
    expect(result.packageName).toContain('acme.com')
  })
})

describe('normalizeDarkWebMention', () => {
  const mention: Parameters<typeof normalizeDarkWebMention>[0] = {
    id: 'dw-001',
    source: 'telegram_channel',
    sourceName: 'threat-intel-channel',
    title: 'New 0day in lodash 4.17.21',
    snippet: 'Working exploit for prototype pollution, affects all versions',
    detectedAt: '2026-03-15T10:00:00Z',
    matchedPackage: 'lodash',
    ecosystem: 'npm',
    exploitConfidence: 'high',
    cveId: 'CVE-2026-9999',
  }

  test('normalizes a dark web telegram mention', () => {
    const result = normalizeDarkWebMention(mention)
    expect(result.sourceType).toBe('dark_web_mention')
    expect(result.sourceTier).toBe('tier_3')
    expect(result.exploitAvailable).toBe(true)
  })

  test('high confidence → critical severity', () => {
    const result = normalizeDarkWebMention(mention)
    expect(result.severity).toBe('critical')
  })

  test('medium confidence → high severity', () => {
    const med = { ...mention, exploitConfidence: 'medium' as const }
    const result = normalizeDarkWebMention(med)
    expect(result.severity).toBe('high')
  })

  test('low confidence → medium severity', () => {
    const low = { ...mention, exploitConfidence: 'low' as const }
    const result = normalizeDarkWebMention(low)
    expect(result.severity).toBe('medium')
  })

  test('CVE ID included in aliases', () => {
    const result = normalizeDarkWebMention(mention)
    expect(result.aliases.some((a) => a.includes('CVE-2026-9999'))).toBe(true)
  })

  test('sourceName reflected in sourceName field', () => {
    const result = normalizeDarkWebMention(mention)
    expect(result.sourceName).toContain('threat-intel-channel')
  })
})
