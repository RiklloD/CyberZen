import { describe, expect, test } from 'vitest'
import {
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
})
