// Pure CycloneDX 1.5 BOM builder — no Convex dependencies.
// Keeping this layer dependency-free makes it easy to unit-test and re-use
// across multiple export paths (HTTP download, S3 upload, dashboard API).

// ---------------------------------------------------------------------------
// Input / output types
// ---------------------------------------------------------------------------

export type SbomInputComponent = {
  name: string
  version: string
  ecosystem: string
  layer: string
  isDirect: boolean
  sourceFile: string
  license?: string
  trustScore: number
  hasKnownVulnerabilities: boolean
}

export type CycloneDxLicense = { license: { id: string } }

export type CycloneDxProperty = { name: string; value: string }

export type CycloneDxComponent = {
  type: 'library' | 'container' | 'framework' | 'application'
  name: string
  version: string
  purl: string
  licenses: CycloneDxLicense[]
  properties: CycloneDxProperty[]
}

export type CycloneDxBom = {
  bomFormat: 'CycloneDX'
  specVersion: '1.5'
  serialNumber: string
  version: 1
  metadata: {
    timestamp: string
    tools: Array<{ vendor: string; name: string; version: string }>
    component: { type: 'application'; name: string; version: string }
  }
  components: CycloneDxComponent[]
}

// ---------------------------------------------------------------------------
// Deterministic UUID — avoids Math.random() in Convex's deterministic runtime
// ---------------------------------------------------------------------------

function deterministicUuid(seed: string): string {
  // Four djb2 hashes over the seed at different salts → 128 pseudorandom bits
  const h = (salt: number): string => {
    let v = salt >>> 0
    for (let i = 0; i < seed.length; i++) {
      v = ((v << 5) + v + seed.charCodeAt(i)) >>> 0
    }
    return v.toString(16).padStart(8, '0')
  }

  const [a, b, c, d] = [0x5eed_0001, 0xbad4_2002, 0xcafe_3003, 0xf00d_4004].map(h)

  // UUID v4 layout: 8-4-4-4-12
  const timeLow = a
  const timeMid = b.slice(0, 4)
  const timeHi = `4${b.slice(5, 8)}` // version 4 marker
  const clockHi = `${(parseInt(c[0]!, 16) & 0x3 | 0x8).toString(16)}${c.slice(1, 4)}`
  const node = c.slice(4) + d.slice(0, 8)

  return `urn:uuid:${timeLow}-${timeMid}-${timeHi}-${clockHi}-${node}`
}

// ---------------------------------------------------------------------------
// Package URL (PURL) generation — purl.github.io/purl-spec
// ---------------------------------------------------------------------------

/**
 * Produce a Package URL for the given component.
 * Ecosystems that map to multiple registry types (npm, yarn, pnpm, bun) all
 * produce `pkg:npm/…` PURLs since npm is the canonical package registry.
 */
export function toPurl(name: string, version: string, ecosystem: string): string {
  const eco = ecosystem.toLowerCase()

  switch (eco) {
    case 'npm':
    case 'yarn':
    case 'pnpm':
    case 'bun': {
      // Scoped packages: @scope/name → pkg:npm/%40scope%2Fname@version
      const encoded = name.startsWith('@')
        ? `%40${name.slice(1).replace('/', '%2F')}`
        : encodeURIComponent(name)
      return `pkg:npm/${encoded}@${encodeURIComponent(version)}`
    }

    case 'pypi':
      // PyPI normalises dashes, underscores, and dots to the same form
      return `pkg:pypi/${name.toLowerCase().replace(/[-_.]+/g, '-')}@${version}`

    case 'cargo':
      return `pkg:cargo/${name}@${version}`

    case 'go':
      // Go module paths often contain slashes — do not encode them
      return `pkg:golang/${name}@${version}`

    case 'maven':
      // Sentinel stores as "group:artifact"; PURL wants "group/artifact"
      return `pkg:maven/${name.replace(':', '/')}@${version}`

    case 'container':
    case 'docker':
      return `pkg:oci/${encodeURIComponent(name)}@${version}`

    default:
      return `pkg:generic/${encodeURIComponent(name)}@${encodeURIComponent(version)}`
  }
}

// ---------------------------------------------------------------------------
// CycloneDX component type mapping
// ---------------------------------------------------------------------------

function componentType(layer: string): CycloneDxComponent['type'] {
  if (layer === 'container') return 'container'
  if (layer === 'ai_model') return 'framework'
  return 'library'
}

// ---------------------------------------------------------------------------
// Top-level BOM assembler
// ---------------------------------------------------------------------------

export function buildCycloneDxBom(params: {
  repositoryName: string
  commitSha: string
  branch: string
  capturedAt: number
  snapshotId: string
  components: SbomInputComponent[]
}): CycloneDxBom {
  const timestamp = new Date(params.capturedAt).toISOString()
  const serialNumber = deterministicUuid(`${params.snapshotId}:${params.commitSha}`)

  const components: CycloneDxComponent[] = params.components.map((c) => {
    const properties: CycloneDxProperty[] = [
      { name: 'sentinel:layer', value: c.layer },
      { name: 'sentinel:isDirect', value: String(c.isDirect) },
      { name: 'sentinel:sourceFile', value: c.sourceFile },
      { name: 'sentinel:trustScore', value: String(c.trustScore) },
      {
        name: 'sentinel:hasKnownVulnerabilities',
        value: String(c.hasKnownVulnerabilities),
      },
    ]

    const licenses: CycloneDxLicense[] = c.license
      ? [{ license: { id: c.license } }]
      : []

    return {
      type: componentType(c.layer),
      name: c.name,
      version: c.version,
      purl: toPurl(c.name, c.version, c.ecosystem),
      licenses,
      properties,
    }
  })

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: 'CyberZen', name: 'Sentinel', version: '1.0' }],
      component: {
        type: 'application',
        name: params.repositoryName,
        version: params.commitSha,
      },
    },
    components,
  }
}
