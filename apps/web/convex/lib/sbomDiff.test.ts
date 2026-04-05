import { describe, expect, test } from 'vitest'
import { compareSnapshotComponents } from './sbomDiff'

describe('sbomDiff', () => {
  test('tracks added removed and updated components between snapshots', () => {
    const comparison = compareSnapshotComponents(
      [
        {
          ecosystem: 'npm',
          name: 'react',
          version: '19.1.0',
          layer: 'direct',
          sourceFile: 'package-lock.json',
          hasKnownVulnerabilities: false,
        },
        {
          ecosystem: 'pypi',
          name: 'pyjwt',
          version: '2.10.1',
          layer: 'transitive',
          sourceFile: 'poetry.lock',
          hasKnownVulnerabilities: true,
        },
      ],
      [
        {
          ecosystem: 'npm',
          name: 'react',
          version: '19.2.0',
          layer: 'direct',
          sourceFile: 'package-lock.json',
          hasKnownVulnerabilities: false,
        },
        {
          ecosystem: 'cargo',
          name: 'serde',
          version: '1.0.217',
          layer: 'direct',
          sourceFile: 'Cargo.lock',
          hasKnownVulnerabilities: false,
        },
      ],
    )

    expect(comparison.addedCount).toBe(1)
    expect(comparison.removedCount).toBe(1)
    expect(comparison.updatedCount).toBe(1)
    expect(comparison.changedComponentCount).toBe(3)
    expect(comparison.vulnerableComponentDelta).toBe(-1)
    expect(comparison.added[0]).toMatchObject({
      ecosystem: 'cargo',
      name: 'serde',
      version: '1.0.217',
    })
    expect(comparison.removed[0]).toMatchObject({
      ecosystem: 'pypi',
      name: 'pyjwt',
      version: '2.10.1',
    })
    expect(comparison.updated[0]).toMatchObject({
      ecosystem: 'npm',
      name: 'react',
      previousVersion: '19.1.0',
      nextVersion: '19.2.0',
    })
  })
})
