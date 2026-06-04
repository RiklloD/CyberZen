/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import { buildSpdxDocument, type SpdxBuildArgs } from './spdx'

function makeArgs(overrides: Partial<SpdxBuildArgs> = {}): SpdxBuildArgs {
  return {
    repositoryFullName: 'acme/payments-api',
    repositoryName: 'payments-api',
    commitSha: 'abc1234def5678901234',
    branch: 'main',
    capturedAt: Date.parse('2026-01-15T10:00:00Z'),
    components: [],
    ...overrides,
  }
}

function makeComponent(overrides = {}) {
  return {
    name: 'lodash',
    version: '4.17.21',
    ecosystem: 'npm',
    layer: 'direct',
    isDirect: true,
    sourceFile: 'package.json',
    license: 'MIT',
    trustScore: 90,
    hasKnownVulnerabilities: false,
    ...overrides,
  }
}

describe('buildSpdxDocument', () => {
  test('produces valid SPDX 2.3 version and data license', () => {
    const doc = buildSpdxDocument(makeArgs())
    expect(doc.spdxVersion).toBe('SPDX-2.3')
    expect(doc.dataLicense).toBe('CC0-1.0')
    expect(doc.SPDXID).toBe('SPDXRef-DOCUMENT')
  })

  test('document namespace includes repository and commit', () => {
    const doc = buildSpdxDocument(makeArgs())
    expect(doc.documentNamespace).toContain('acme/payments-api')
    expect(doc.documentNamespace).toContain('abc1234def5678901234')
  })

  test('creation info includes Sentinel as creator', () => {
    const doc = buildSpdxDocument(makeArgs())
    expect(doc.creationInfo.creators.some((c) => c.includes('Sentinel'))).toBe(true)
  })

  test('creation info uses capturedAt timestamp', () => {
    const args = makeArgs()
    const doc = buildSpdxDocument(args)
    expect(doc.creationInfo.created).toContain('2026-01-15')
  })

  test('root package present and described', () => {
    const doc = buildSpdxDocument(makeArgs())
    expect(doc.documentDescribes).toHaveLength(1)
    const rootId = doc.documentDescribes[0]
    const rootPkg = doc.packages.find((p) => p.SPDXID === rootId)
    expect(rootPkg).toBeDefined()
    expect(rootPkg?.name).toBe('acme/payments-api')
  })

  test('root relationship is DESCRIBES', () => {
    const doc = buildSpdxDocument(makeArgs())
    const describes = doc.relationships.find((r) => r.relationshipType === 'DESCRIBES')
    expect(describes).toBeDefined()
    expect(describes?.spdxElementId).toBe('SPDXRef-DOCUMENT')
  })

  test('component generates SPDXID package', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent()],
    }))
    // Root + 1 component
    expect(doc.packages).toHaveLength(2)
    const lodash = doc.packages.find((p) => p.name === 'lodash')
    expect(lodash).toBeDefined()
    expect(lodash?.versionInfo).toBe('4.17.21')
    expect(lodash?.SPDXID).toMatch(/^SPDXRef-Package-/)
  })

  test('PURL included in externalRefs', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ name: 'express', version: '4.18.2', ecosystem: 'npm' })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'express')
    const purlRef = pkg?.externalRefs.find((r) => r.referenceType === 'purl')
    expect(purlRef?.referenceLocator).toContain('pkg:npm/express@4.18.2')
  })

  test('Python package uses pypi PURL type', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ name: 'requests', version: '2.31.0', ecosystem: 'pypi' })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'requests')
    const purl = pkg?.externalRefs.find((r) => r.referenceType === 'purl')?.referenceLocator
    expect(purl).toContain('pkg:pypi/')
  })

  test('Go package uses golang PURL type', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ name: 'golang.org/x/net', version: '0.20.0', ecosystem: 'go' })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'golang.org/x/net')
    const purl = pkg?.externalRefs.find((r) => r.referenceType === 'purl')?.referenceLocator
    expect(purl).toContain('pkg:golang/')
  })

  test('direct dependency generates DEPENDS_ON relationship', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ isDirect: true })],
    }))
    const rel = doc.relationships.find((r) => r.relationshipType === 'DEPENDS_ON')
    expect(rel).toBeDefined()
  })

  test('transitive dependency generates DEPENDENCY_OF relationship', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ isDirect: false })],
    }))
    const rel = doc.relationships.find((r) => r.relationshipType === 'DEPENDENCY_OF')
    expect(rel).toBeDefined()
  })

  test('MIT license normalized to SPDX identifier', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ license: 'MIT' })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'lodash')
    expect(pkg?.licenseConcluded).toBe('MIT')
  })

  test('Apache license normalized to Apache-2.0', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ license: 'Apache-2.0' })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'lodash')
    expect(pkg?.licenseConcluded).toBe('Apache-2.0')
  })

  test('no license becomes NOASSERTION', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ license: undefined })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'lodash')
    expect(pkg?.licenseConcluded).toBe('NOASSERTION')
  })

  test('vulnerable component gets security externalRef', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ hasKnownVulnerabilities: true })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'lodash')
    const secRef = pkg?.externalRefs.find((r) => r.referenceCategory === 'SECURITY')
    expect(secRef).toBeDefined()
  })

  test('low trust score adds REVIEW annotation', () => {
    const doc = buildSpdxDocument(makeArgs({
      components: [makeComponent({ trustScore: 20 })],
    }))
    const pkg = doc.packages.find((p) => p.name === 'lodash')
    expect(pkg?.annotations).toBeDefined()
    expect(pkg?.annotations?.[0].annotationType).toBe('REVIEW')
  })

  test('duplicate components deduplicated by SPDXID', () => {
    const component = makeComponent()
    const doc = buildSpdxDocument(makeArgs({
      components: [component, component, component],
    }))
    const lodashPackages = doc.packages.filter((p) => p.name === 'lodash')
    expect(lodashPackages).toHaveLength(1)
  })

  test('empty component list produces root + document only', () => {
    const doc = buildSpdxDocument(makeArgs({ components: [] }))
    expect(doc.packages).toHaveLength(1) // root only
    expect(doc.relationships).toHaveLength(1) // DESCRIBES only
  })

  test('large SBOM handles 100+ components', () => {
    const components = Array.from({ length: 150 }, (_, i) => makeComponent({
      name: `pkg-${i}`,
      version: `1.${i}.0`,
    }))
    const doc = buildSpdxDocument(makeArgs({ components }))
    expect(doc.packages).toHaveLength(151) // 150 + root
    expect(doc.relationships).toHaveLength(151) // 150 deps + DESCRIBES
  })
})
