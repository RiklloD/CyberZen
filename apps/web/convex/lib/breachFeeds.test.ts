import { describe, expect, test } from 'vitest'
import {
  coerceGithubSecurityAdvisoryInput,
  coerceOsvAdvisoryInput,
  normalizeGithubSecurityAdvisory,
  normalizeOsvAdvisory,
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
