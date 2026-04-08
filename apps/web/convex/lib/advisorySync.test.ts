import { describe, expect, it } from 'vitest'
import {
  buildGithubAdvisoryBatches,
  buildOsvPackageQueries,
  collectOsvVulnerabilityIds,
  dedupeTrackedPackages,
  parseGithubNextCursor,
} from './advisorySync'

describe('dedupeTrackedPackages', () => {
  it('deduplicates packages and filters unsupported ecosystems', () => {
    expect(
      dedupeTrackedPackages([
        { packageName: 'lodash', ecosystem: 'npm', version: '4.17.21' },
        { packageName: 'lodash', ecosystem: 'npm', version: '4.17.21' },
        { packageName: 'busybox', ecosystem: 'container', version: '1.36.1' },
        { packageName: 'requests', ecosystem: 'pypi', version: '2.32.0' },
      ]),
    ).toEqual([
      { packageName: 'lodash', ecosystem: 'npm', version: '4.17.21' },
      { packageName: 'requests', ecosystem: 'pypi', version: '2.32.0' },
    ])
  })
})

describe('buildGithubAdvisoryBatches', () => {
  it('groups tracked packages by GitHub ecosystem and chunks them', () => {
    expect(
      buildGithubAdvisoryBatches(
        [
          { packageName: 'lodash', ecosystem: 'npm', version: '4.17.21' },
          { packageName: 'express', ecosystem: 'npm', version: '4.21.2' },
          { packageName: 'requests', ecosystem: 'pypi', version: '2.32.0' },
        ],
        1,
      ),
    ).toEqual([
      { ecosystem: 'npm', affects: ['lodash@4.17.21'] },
      { ecosystem: 'npm', affects: ['express@4.21.2'] },
      { ecosystem: 'pip', affects: ['requests@2.32.0'] },
    ])
  })
})

describe('buildOsvPackageQueries', () => {
  it('maps tracked packages into OSV query batches', () => {
    expect(
      buildOsvPackageQueries(
        [
          { packageName: 'requests', ecosystem: 'pypi', version: '2.32.0' },
          { packageName: 'serde', ecosystem: 'cargo', version: '1.0.219' },
        ],
        5,
      ),
    ).toEqual([
      [
        {
          package: {
            name: 'requests',
            ecosystem: 'PyPI',
          },
          version: '2.32.0',
        },
        {
          package: {
            name: 'serde',
            ecosystem: 'crates.io',
          },
          version: '1.0.219',
        },
      ],
    ])
  })
})

describe('parseGithubNextCursor', () => {
  it('extracts the next cursor from a GitHub link header', () => {
    expect(
      parseGithubNextCursor(
        '<https://api.github.com/advisories?after=cursor123>; rel="next", <https://api.github.com/advisories?after=cursor456>; rel="last"',
      ),
    ).toBe('cursor123')
  })
})

describe('collectOsvVulnerabilityIds', () => {
  it('deduplicates ids from OSV query results', () => {
    expect(
      collectOsvVulnerabilityIds([
        {
          vulns: [{ id: 'OSV-2026-1' }, { id: 'OSV-2026-2' }],
        },
        {
          vulns: [{ id: 'OSV-2026-2' }, { id: 'OSV-2026-3' }],
        },
      ]),
    ).toEqual(['OSV-2026-1', 'OSV-2026-2', 'OSV-2026-3'])
  })
})
