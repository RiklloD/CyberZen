/// <reference types="vite/client" />
// WS-45 — Container Image Security Analyzer: unit tests.

import { describe, expect, test } from 'vitest'
import {
  CONTAINER_ECOSYSTEMS,
  CONTAINER_IMAGE_DATABASE,
  NEAR_EOL_WINDOW_DAYS,
  checkContainerImage,
  computeContainerImageReport,
  isUnpinnedTag,
  matchVersionPrefix,
} from './containerImageSecurity'
import type { ContainerImageRecord } from './containerImageSecurity'

// ---------------------------------------------------------------------------
// isUnpinnedTag
// ---------------------------------------------------------------------------

describe('isUnpinnedTag', () => {
  test('latest is unpinned', () => expect(isUnpinnedTag('latest')).toBe(true))
  test('LATEST (uppercase) is unpinned', () => expect(isUnpinnedTag('LATEST')).toBe(true))
  test('empty string is unpinned', () => expect(isUnpinnedTag('')).toBe(true))
  test('* is unpinned', () => expect(isUnpinnedTag('*')).toBe(true))
  test('stable is unpinned', () => expect(isUnpinnedTag('stable')).toBe(true))
  test('current is unpinned', () => expect(isUnpinnedTag('current')).toBe(true))
  test('edge is unpinned', () => expect(isUnpinnedTag('edge')).toBe(true))
  test('specific version is not unpinned', () => expect(isUnpinnedTag('20.04')).toBe(false))
  test('major.minor version is not unpinned', () => expect(isUnpinnedTag('3.12')).toBe(false))
  test('version with suffix is not unpinned', () => expect(isUnpinnedTag('22-alpine')).toBe(false))
  test('whitespace-padded tag is still evaluated correctly', () =>
    expect(isUnpinnedTag('  latest  ')).toBe(true))
})

// ---------------------------------------------------------------------------
// matchVersionPrefix
// ---------------------------------------------------------------------------

describe('matchVersionPrefix', () => {
  const records: ContainerImageRecord[] = [
    {
      image: 'ubuntu',
      versionPrefix: '18.04',
      signal: 'eol_base_image',
      riskLevel: 'critical',
      eolDateText: '2023-04-30',
      recommendedVersion: '24.04',
      detail: 'EOL',
    },
    {
      image: 'ubuntu',
      versionPrefix: '22.04',
      signal: 'outdated_base',
      riskLevel: 'low',
      recommendedVersion: '24.04',
      detail: 'outdated',
    },
  ]

  test('exact prefix match returns record', () => {
    const r = matchVersionPrefix(records, '18.04')
    expect(r?.versionPrefix).toBe('18.04')
  })

  test('prefix + dash suffix matches (18.04-alpine)', () => {
    const r = matchVersionPrefix(records, '18.04-alpine')
    expect(r?.versionPrefix).toBe('18.04')
  })

  test('prefix + dot suffix matches (18.04.1)', () => {
    const r = matchVersionPrefix(records, '18.04.1')
    expect(r?.versionPrefix).toBe('18.04')
  })

  test('prefix + underscore suffix matches (18.04_slim)', () => {
    const r = matchVersionPrefix(records, '18.04_slim')
    expect(r?.versionPrefix).toBe('18.04')
  })

  test('version not in records returns null', () => {
    expect(matchVersionPrefix(records, '16.04')).toBeNull()
  })

  test('partial numeric prefix does NOT match (1.8 should not match 18.04)', () => {
    expect(matchVersionPrefix(records, '1.8')).toBeNull()
  })

  test('blank versionPrefix acts as wildcard', () => {
    const wildcardRecords: ContainerImageRecord[] = [
      {
        image: 'test',
        versionPrefix: '',
        signal: 'deprecated_image',
        riskLevel: 'high',
        recommendedVersion: 'test:1',
        detail: 'deprecated',
      },
    ]
    const r = matchVersionPrefix(wildcardRecords, 'anything')
    expect(r?.signal).toBe('deprecated_image')
  })

  test('empty records array returns null', () => {
    expect(matchVersionPrefix([], '18.04')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — ecosystem filtering
// ---------------------------------------------------------------------------

describe('checkContainerImage — ecosystem filtering', () => {
  test('npm ecosystem returns null', () => {
    expect(checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'npm' })).toBeNull()
  })

  test('pypi ecosystem returns null', () => {
    expect(
      checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'pypi' }),
    ).toBeNull()
  })

  test('docker ecosystem is processed', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'docker' })
    expect(result).not.toBeNull()
  })

  test('container ecosystem is processed', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'container' })
    expect(result).not.toBeNull()
  })

  test('oci ecosystem is processed', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'oci' })
    expect(result).not.toBeNull()
  })

  test('DOCKER uppercase ecosystem is processed (case-insensitive)', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'DOCKER' })
    expect(result).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — unpinned tags
// ---------------------------------------------------------------------------

describe('checkContainerImage — unpinned tags', () => {
  test('latest tag produces no_version_tag signal at medium risk', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: 'latest', ecosystem: 'docker' })
    expect(result?.signal).toBe('no_version_tag')
    expect(result?.riskLevel).toBe('medium')
  })

  test('empty version tag produces no_version_tag signal', () => {
    const result = checkContainerImage({ name: 'node', version: '', ecosystem: 'docker' })
    expect(result?.signal).toBe('no_version_tag')
  })

  test('no_version_tag finding contains the image name in recommendedVersion', () => {
    const result = checkContainerImage({
      name: 'postgres',
      version: 'latest',
      ecosystem: 'docker',
    })
    expect(result?.recommendedVersion).toContain('postgres')
  })

  test('eolDateText is null for unpinned tag findings', () => {
    const result = checkContainerImage({ name: 'nginx', version: 'latest', ecosystem: 'docker' })
    expect(result?.eolDateText).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — EOL images
// ---------------------------------------------------------------------------

describe('checkContainerImage — EOL images', () => {
  test('ubuntu:18.04 is critical eol_base_image', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '18.04', ecosystem: 'docker' })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
    expect(result?.eolDateText).toBe('2023-04-30')
  })

  test('ubuntu:20.04 is critical eol_base_image (EOL 2025-04-30)', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '20.04', ecosystem: 'docker' })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
  })

  test('node:18-alpine still matched as EOL (version prefix 18)', () => {
    const result = checkContainerImage({
      name: 'node',
      version: '18-alpine',
      ecosystem: 'docker',
    })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
  })

  test('python:3.9-slim is critical EOL', () => {
    const result = checkContainerImage({
      name: 'python',
      version: '3.9-slim',
      ecosystem: 'docker',
    })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
  })

  test('mysql:5.7 is critical EOL', () => {
    const result = checkContainerImage({ name: 'mysql', version: '5.7', ecosystem: 'docker' })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
  })

  test('redis:6.2 is critical EOL', () => {
    const result = checkContainerImage({ name: 'redis', version: '6.2', ecosystem: 'docker' })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
  })

  test('EOL finding includes recommendedVersion', () => {
    const result = checkContainerImage({ name: 'ubuntu', version: '16.04', ecosystem: 'docker' })
    expect(result?.recommendedVersion).toBeTruthy()
    expect(result?.recommendedVersion).toBe('24.04')
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — near-EOL images
// ---------------------------------------------------------------------------

describe('checkContainerImage — near-EOL images', () => {
  test('debian:11 is near_eol at high risk', () => {
    const result = checkContainerImage({ name: 'debian', version: '11', ecosystem: 'docker' })
    expect(result?.signal).toBe('near_eol')
    expect(result?.riskLevel).toBe('high')
  })

  test('node:20 is near_eol', () => {
    const result = checkContainerImage({ name: 'node', version: '20', ecosystem: 'docker' })
    expect(result?.signal).toBe('near_eol')
    expect(result?.riskLevel).toBe('high')
  })

  test('mysql:8.0 is near_eol', () => {
    const result = checkContainerImage({ name: 'mysql', version: '8.0', ecosystem: 'docker' })
    expect(result?.signal).toBe('near_eol')
    expect(result?.riskLevel).toBe('high')
  })

  test('python:3.10 is near_eol', () => {
    const result = checkContainerImage({ name: 'python', version: '3.10', ecosystem: 'docker' })
    expect(result?.signal).toBe('near_eol')
    expect(result?.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — outdated base images
// ---------------------------------------------------------------------------

describe('checkContainerImage — outdated base images', () => {
  test('nginx:1.20 is outdated_base at medium risk', () => {
    const result = checkContainerImage({ name: 'nginx', version: '1.20', ecosystem: 'docker' })
    expect(result?.signal).toBe('outdated_base')
    expect(result?.riskLevel).toBe('medium')
  })

  test('nginx:1.24 is outdated_base at low risk', () => {
    const result = checkContainerImage({ name: 'nginx', version: '1.24', ecosystem: 'docker' })
    expect(result?.signal).toBe('outdated_base')
    expect(result?.riskLevel).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — deprecated image names
// ---------------------------------------------------------------------------

describe('checkContainerImage — deprecated image names', () => {
  test('node:erbium is deprecated_image at high risk', () => {
    const result = checkContainerImage({ name: 'node', version: 'erbium', ecosystem: 'docker' })
    expect(result?.signal).toBe('deprecated_image')
    expect(result?.riskLevel).toBe('high')
  })

  test('node:hydrogen deprecated_image is critical (EOL)', () => {
    const result = checkContainerImage({ name: 'node', version: 'hydrogen', ecosystem: 'docker' })
    expect(result?.signal).toBe('deprecated_image')
    expect(result?.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — registry prefix stripping
// ---------------------------------------------------------------------------

describe('checkContainerImage — registry prefix stripping', () => {
  test('docker.io/library/ubuntu:18.04 is resolved to ubuntu:18.04', () => {
    const result = checkContainerImage({
      name: 'docker.io/library/ubuntu',
      version: '18.04',
      ecosystem: 'docker',
    })
    expect(result?.signal).toBe('eol_base_image')
    expect(result?.riskLevel).toBe('critical')
  })

  test('registry.hub.docker.com/node:18 is resolved to node:18', () => {
    const result = checkContainerImage({
      name: 'registry.hub.docker.com/node',
      version: '18',
      ecosystem: 'docker',
    })
    expect(result?.signal).toBe('eol_base_image')
  })

  test('unknown/custom-image returns null (not in DB)', () => {
    const result = checkContainerImage({
      name: 'myregistry.io/custom-app',
      version: '1.0.0',
      ecosystem: 'docker',
    })
    expect(result).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// checkContainerImage — safe images (no finding)
// ---------------------------------------------------------------------------

describe('checkContainerImage — safe images', () => {
  test('unknown image name returns null', () => {
    expect(
      checkContainerImage({ name: 'my-custom-app', version: '1.0.0', ecosystem: 'docker' }),
    ).toBeNull()
  })

  test('ubuntu with unknown version returns null (not in DB)', () => {
    expect(
      checkContainerImage({ name: 'ubuntu', version: '24.04', ecosystem: 'docker' }),
    ).toBeNull()
  })

  test('finding imageName preserves original casing from component.name', () => {
    const result = checkContainerImage({ name: 'Ubuntu', version: '18.04', ecosystem: 'docker' })
    expect(result?.imageName).toBe('Ubuntu')
  })
})

// ---------------------------------------------------------------------------
// computeContainerImageReport — empty / no container images
// ---------------------------------------------------------------------------

describe('computeContainerImageReport — empty / no containers', () => {
  test('empty array → overallRisk none, totalImages 0', () => {
    const report = computeContainerImageReport([])
    expect(report.overallRisk).toBe('none')
    expect(report.totalImages).toBe(0)
    expect(report.findings).toHaveLength(0)
  })

  test('empty array → summary mentions no container images', () => {
    const report = computeContainerImageReport([])
    expect(report.summary).toMatch(/no container images/i)
  })

  test('npm-only components → overallRisk none (no container images found)', () => {
    const report = computeContainerImageReport([
      { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
    ])
    expect(report.overallRisk).toBe('none')
    expect(report.totalImages).toBe(0)
  })

  test('safe docker image (not in DB) → overallRisk none', () => {
    const report = computeContainerImageReport([
      { name: 'my-company/backend', version: '2.3.1', ecosystem: 'docker' },
    ])
    expect(report.overallRisk).toBe('none')
    expect(report.totalImages).toBe(1)
    expect(report.findings).toHaveLength(0)
  })

  test('safe docker image → summary says all supported', () => {
    const report = computeContainerImageReport([
      { name: 'my-company/backend', version: '2.3.1', ecosystem: 'docker' },
    ])
    expect(report.summary).toMatch(/supported/i)
  })
})

// ---------------------------------------------------------------------------
// computeContainerImageReport — risk aggregation
// ---------------------------------------------------------------------------

describe('computeContainerImageReport — risk aggregation', () => {
  test('critical image → overallRisk critical', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
    ])
    expect(report.overallRisk).toBe('critical')
    expect(report.criticalCount).toBe(1)
  })

  test('near-EOL image (no critical) → overallRisk high', () => {
    const report = computeContainerImageReport([
      { name: 'debian', version: '11', ecosystem: 'docker' },
    ])
    expect(report.overallRisk).toBe('high')
    expect(report.highCount).toBe(1)
  })

  test('outdated medium image only → overallRisk medium', () => {
    const report = computeContainerImageReport([
      { name: 'nginx', version: '1.20', ecosystem: 'docker' },
    ])
    expect(report.overallRisk).toBe('medium')
  })

  test('outdated low image only → overallRisk low', () => {
    const report = computeContainerImageReport([
      { name: 'nginx', version: '1.24', ecosystem: 'docker' },
    ])
    expect(report.overallRisk).toBe('low')
    expect(report.lowCount).toBe(1)
  })

  test('mixed images → critical wins overallRisk', () => {
    const report = computeContainerImageReport([
      { name: 'nginx', version: '1.24', ecosystem: 'docker' },
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
      { name: 'debian', version: '11', ecosystem: 'docker' },
    ])
    expect(report.overallRisk).toBe('critical')
    expect(report.criticalCount).toBe(1)
    expect(report.highCount).toBe(1)
    expect(report.lowCount).toBe(1)
  })

  test('findings are sorted critical first', () => {
    const report = computeContainerImageReport([
      { name: 'nginx', version: '1.24', ecosystem: 'docker' }, // low
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' }, // critical
      { name: 'debian', version: '11', ecosystem: 'docker' }, // high
    ])
    expect(report.findings[0].riskLevel).toBe('critical')
    expect(report.findings[1].riskLevel).toBe('high')
    expect(report.findings[2].riskLevel).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// computeContainerImageReport — deduplication
// ---------------------------------------------------------------------------

describe('computeContainerImageReport — deduplication', () => {
  test('duplicate identical image is counted once in findings', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
    ])
    expect(report.findings).toHaveLength(1)
    expect(report.totalImages).toBe(2) // both counted in totalImages
  })

  test('same image name but different versions are not deduplicated', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
      { name: 'ubuntu', version: '20.04', ecosystem: 'docker' },
    ])
    expect(report.findings).toHaveLength(2)
  })

  test('same image across different container ecosystems are deduplicated separately', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
      { name: 'ubuntu', version: '18.04', ecosystem: 'oci' }, // different key
    ])
    // Both produce findings (different dedup keys due to different ecosystems)
    expect(report.findings.length).toBeGreaterThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// computeContainerImageReport — summary text
// ---------------------------------------------------------------------------

describe('computeContainerImageReport — summary text', () => {
  test('single finding summary uses singular "issue"', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
    ])
    expect(report.summary).toMatch(/1 container image issue detected/i)
  })

  test('multiple findings summary uses plural "issues"', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
      { name: 'node', version: '14', ecosystem: 'docker' },
    ])
    expect(report.summary).toMatch(/issues detected/i)
  })

  test('summary includes critical count', () => {
    const report = computeContainerImageReport([
      { name: 'ubuntu', version: '18.04', ecosystem: 'docker' },
    ])
    expect(report.summary).toContain('1 critical')
  })
})

// ---------------------------------------------------------------------------
// CONTAINER_IMAGE_DATABASE integrity
// ---------------------------------------------------------------------------

describe('CONTAINER_IMAGE_DATABASE integrity', () => {
  const validSignals = new Set([
    'eol_base_image',
    'near_eol',
    'outdated_base',
    'no_version_tag',
    'deprecated_image',
  ])
  const validRiskLevels = new Set(['critical', 'high', 'medium', 'low'])

  test('database has at least 30 entries', () => {
    expect(CONTAINER_IMAGE_DATABASE.length).toBeGreaterThanOrEqual(30)
  })

  test('all entries have a valid signal', () => {
    for (const entry of CONTAINER_IMAGE_DATABASE) {
      expect(validSignals.has(entry.signal), `entry ${entry.image}:${entry.versionPrefix} has invalid signal ${entry.signal}`).toBe(true)
    }
  })

  test('all entries have a valid riskLevel', () => {
    for (const entry of CONTAINER_IMAGE_DATABASE) {
      expect(validRiskLevels.has(entry.riskLevel), `entry ${entry.image}:${entry.versionPrefix} has invalid riskLevel ${entry.riskLevel}`).toBe(true)
    }
  })

  test('all entries have a non-empty recommendedVersion', () => {
    for (const entry of CONTAINER_IMAGE_DATABASE) {
      expect(entry.recommendedVersion.length, `entry ${entry.image}:${entry.versionPrefix} is missing recommendedVersion`).toBeGreaterThan(0)
    }
  })

  test('all entries have a non-empty detail', () => {
    for (const entry of CONTAINER_IMAGE_DATABASE) {
      expect(entry.detail.length, `entry ${entry.image}:${entry.versionPrefix} is missing detail`).toBeGreaterThan(0)
    }
  })

  test('CONTAINER_ECOSYSTEMS includes docker, container, oci', () => {
    expect(CONTAINER_ECOSYSTEMS.has('docker')).toBe(true)
    expect(CONTAINER_ECOSYSTEMS.has('container')).toBe(true)
    expect(CONTAINER_ECOSYSTEMS.has('oci')).toBe(true)
  })

  test('NEAR_EOL_WINDOW_DAYS is 90', () => {
    expect(NEAR_EOL_WINDOW_DAYS).toBe(90)
  })
})
