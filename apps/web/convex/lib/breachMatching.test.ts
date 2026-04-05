import { describe, expect, test } from 'vitest'
import {
  buildDisclosureMatchSummary,
  businessImpactScoreForSeverity,
  matchDisclosureToInventory,
  normalizeEcosystem,
  normalizePackageName,
  uniqueStrings,
} from './breachMatching'

describe('breachMatching', () => {
  test('normalizes package names ecosystems and removes duplicate strings', () => {
    expect(normalizePackageName('  PyJWT  ')).toBe('pyjwt')
    expect(normalizePackageName('pkg:pypi/PyJWT')).toBe('pyjwt')
    expect(normalizePackageName('httpx_client')).toBe('httpx-client')
    expect(normalizeEcosystem('PyPI')).toBe('pypi')
    expect(normalizeEcosystem('crates.io')).toBe('cargo')
    expect(uniqueStrings(['2.10.1', '2.10.1', ' ', '2.10.2'])).toEqual([
      '2.10.1',
      '2.10.2',
    ])
  })

  test('matches affected versions and keeps unaffected name-only hits separate', () => {
    const matched = matchDisclosureToInventory({
      packageName: 'pyjwt',
      ecosystem: 'pypi',
      affectedVersions: ['>=2.8.0', '<2.10.2'],
      fixVersion: '2.10.2',
      components: [
        {
          name: 'pyjwt',
          version: '2.10.1',
          ecosystem: 'pypi',
          layer: 'transitive',
          isDirect: false,
          sourceFile: 'poetry.lock',
          dependents: ['auth-core'],
        },
        {
          name: 'pyjwt',
          version: '2.10.2',
          ecosystem: 'pypi',
          layer: 'direct',
          isDirect: true,
          sourceFile: 'requirements.txt',
          dependents: [],
        },
      ],
    })

    expect(matched.matchStatus).toBe('matched')
    expect(matched.matchedComponentCount).toBe(2)
    expect(matched.affectedComponentCount).toBe(1)
    expect(matched.matchedVersions).toEqual(['2.10.1', '2.10.2'])
    expect(matched.affectedMatchedVersions).toEqual(['2.10.1'])
  })

  test('returns version-unaffected when the package is present but outside the advisory range', () => {
    const match = matchDisclosureToInventory({
      packageName: 'pyjwt',
      ecosystem: 'pypi',
      affectedVersions: ['>=2.8.0, <2.10.2'],
      fixVersion: '2.10.2',
      components: [
        {
          name: 'pyjwt',
          version: '2.10.3',
          ecosystem: 'pypi',
          layer: 'direct',
          isDirect: true,
          sourceFile: 'requirements.txt',
          dependents: [],
        },
      ],
    })

    expect(match.matchStatus).toBe('version_unaffected')
    expect(match.versionMatchStatus).toBe('unaffected')
    expect(match.affectedComponentCount).toBe(0)
  })

  test('builds summaries for each intake state', () => {
    expect(
      buildDisclosureMatchSummary({
        packageName: 'pyjwt',
        repositoryName: 'payments-api',
        matchStatus: 'matched',
        matchedComponentCount: 2,
        affectedComponentCount: 1,
        matchedVersions: ['2.10.1', '2.10.2'],
        affectedMatchedVersions: ['2.10.1'],
        affectedVersions: ['>=2.8.0', '<2.10.2'],
        fixVersion: '2.10.2',
      }),
    ).toContain('affected tracked component')

    expect(
      buildDisclosureMatchSummary({
        packageName: 'pyjwt',
        repositoryName: 'payments-api',
        matchStatus: 'version_unaffected',
        matchedComponentCount: 1,
        affectedComponentCount: 0,
        matchedVersions: ['2.10.3'],
        affectedMatchedVersions: [],
        affectedVersions: ['>=2.8.0', '<2.10.2'],
        fixVersion: '2.10.2',
      }),
    ).toContain('outside the affected advisory range')

    expect(
      buildDisclosureMatchSummary({
        packageName: 'pyjwt',
        repositoryName: 'payments-api',
        matchStatus: 'version_unknown',
        matchedComponentCount: 1,
        affectedComponentCount: 0,
        matchedVersions: ['unknown'],
        affectedMatchedVersions: [],
        affectedVersions: [],
        fixVersion: undefined,
      }),
    ).toContain('could not prove')

    expect(
      buildDisclosureMatchSummary({
        packageName: 'pyjwt',
        repositoryName: 'payments-api',
        matchStatus: 'unmatched',
        matchedComponentCount: 0,
        affectedComponentCount: 0,
        matchedVersions: [],
        affectedMatchedVersions: [],
        affectedVersions: [],
        fixVersion: undefined,
      }),
    ).toContain('was not found')

    expect(
      buildDisclosureMatchSummary({
        packageName: 'pyjwt',
        repositoryName: 'payments-api',
        matchStatus: 'no_snapshot',
        matchedComponentCount: 0,
        affectedComponentCount: 0,
        matchedVersions: [],
        affectedMatchedVersions: [],
        affectedVersions: [],
        fixVersion: undefined,
      }),
    ).toContain('No SBOM snapshot')
  })

  test('scores direct exploit-backed exposure above low severity findings', () => {
    expect(businessImpactScoreForSeverity('high', true, true)).toBeGreaterThan(
      businessImpactScoreForSeverity('low', false, false),
    )
  })
})
