/**
 * SPDX 2.3 document builder — pure function, no Convex dependencies.
 *
 * Spec: https://spdx.github.io/spdx-spec/v2.3/
 * Format: SPDX 2.3 JSON output
 *
 * Generates an SPDX document from an SBOM snapshot for compliance and
 * legal use cases (Linux Foundation ecosystem, supply chain attestation,
 * EU Cyber Resilience Act compliance).
 */

import type { SbomInputComponent } from './cyclonedx'

// ── SPDX types ────────────────────────────────────────────────────────────────

type SpdxRelationshipType =
  | 'DESCRIBES'
  | 'DEPENDS_ON'
  | 'DEPENDENCY_OF'
  | 'CONTAINS'
  | 'GENERATED_FROM'
  | 'DEV_DEPENDENCY_OF'
  | 'OPTIONAL_DEPENDENCY_OF'
  | 'BUILD_DEPENDENCY_OF'

type SpdxPackageVerification = {
  algorithm: 'SHA256' | 'SHA1' | 'MD5'
  checksumValue: string
}

type SpdxExternalRef = {
  referenceCategory: 'PACKAGE_MANAGER' | 'SECURITY' | 'OTHER'
  referenceType: string
  referenceLocator: string
}

type SpdxPackage = {
  SPDXID: string
  name: string
  versionInfo: string
  downloadLocation: string
  filesAnalyzed: false  // We don't analyze files individually
  packageVerificationCode?: { packageVerificationCodeValue: string }
  checksums?: SpdxPackageVerification[]
  homepage?: string
  sourceInfo?: string
  licenseConcluded: string
  licenseInfoFromFiles: string[]
  licenseDeclared: string
  copyrightText: string
  externalRefs: SpdxExternalRef[]
  comment?: string
  primaryPackagePurpose?: 'LIBRARY' | 'CONTAINER' | 'FRAMEWORK' | 'APPLICATION'
  annotations?: Array<{ annotationType: string; annotator: string; comment: string; annotationDate: string }>
}

type SpdxRelationship = {
  spdxElementId: string
  relationshipType: SpdxRelationshipType
  relatedSpdxElement: string
  comment?: string
}

export type SpdxDocument = {
  spdxVersion: 'SPDX-2.3'
  dataLicense: 'CC0-1.0'
  SPDXID: 'SPDXRef-DOCUMENT'
  name: string
  documentNamespace: string
  documentDescribes: string[]
  creationInfo: {
    created: string
    creators: string[]
    licenseListVersion: string
    comment?: string
  }
  packages: SpdxPackage[]
  relationships: SpdxRelationship[]
  comment?: string
}

// ── Ecosystem → PURL type mapping ────────────────────────────────────────────

function purlType(ecosystem: string): string {
  const map: Record<string, string> = {
    npm: 'npm',
    pypi: 'pypi',
    pip: 'pypi',
    cargo: 'cargo',
    go: 'golang',
    maven: 'maven',
    gradle: 'maven',
    nuget: 'nuget',
    gem: 'gem',
    rubygems: 'gem',
    composer: 'composer',
    docker: 'docker',
    container: 'docker',
    hex: 'hex',
    pub: 'pub',
    swift: 'swift',
  }
  return map[ecosystem.toLowerCase()] ?? 'generic'
}

function buildPurl(name: string, version: string, ecosystem: string): string {
  const type = purlType(ecosystem)
  const encodedName = name.replace(/@/g, '%40').replace(/\//g, '%2F')
  if (version) {
    return `pkg:${type}/${encodedName}@${encodeURIComponent(version)}`
  }
  return `pkg:${type}/${encodedName}`
}

function spdxId(name: string, version: string): string {
  // SPDXID must match [a-zA-Z0-9.-]+
  const clean = `${name}-${version}`
    .replace(/[^a-zA-Z0-9.-]/g, '-')
    .replace(/-{2,}/g, '-')
    .slice(0, 100)
  return `SPDXRef-Package-${clean}`
}

function normalizeLicense(license?: string): string {
  if (!license) return 'NOASSERTION'
  // Common normalizations to SPDX License Identifiers
  const map: Record<string, string> = {
    MIT: 'MIT',
    ISC: 'ISC',
    Apache: 'Apache-2.0',
    'Apache-2': 'Apache-2.0',
    'Apache-2.0': 'Apache-2.0',
    BSD: 'BSD-2-Clause',
    'BSD-2': 'BSD-2-Clause',
    'BSD-3': 'BSD-3-Clause',
    'BSD-3-Clause': 'BSD-3-Clause',
    GPL: 'GPL-2.0-only',
    'GPL-2.0': 'GPL-2.0-only',
    'GPL-3.0': 'GPL-3.0-only',
    LGPL: 'LGPL-2.1-only',
    MPL: 'MPL-2.0',
    CC0: 'CC0-1.0',
    Unlicense: 'Unlicense',
    WTFPL: 'WTFPL',
  }
  const normalized = Object.entries(map).find(([k]) =>
    license.toLowerCase().includes(k.toLowerCase()),
  )
  return normalized ? normalized[1] : license
}

// ── Document builder ──────────────────────────────────────────────────────────

export type SpdxBuildArgs = {
  repositoryFullName: string
  repositoryName: string
  commitSha: string
  branch: string
  capturedAt: number
  components: SbomInputComponent[]
  exportedAt?: number
}

export function buildSpdxDocument(args: SpdxBuildArgs): SpdxDocument {
  const docName = `${args.repositoryName}-${args.commitSha.slice(0, 7)}`
  const timestamp = new Date(args.exportedAt ?? args.capturedAt).toISOString()
  const rootId = 'SPDXRef-DOCUMENT'

  // Root package representing the repository itself
  const rootPackageId = `SPDXRef-Package-${args.repositoryName.replace(/[^a-zA-Z0-9]/g, '-').slice(0, 50)}-root`
  const rootPackage: SpdxPackage = {
    SPDXID: rootPackageId,
    name: args.repositoryFullName,
    versionInfo: args.commitSha.slice(0, 7),
    downloadLocation: `https://github.com/${args.repositoryFullName}/tree/${args.commitSha}`,
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseInfoFromFiles: [],
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    externalRefs: [],
    primaryPackagePurpose: 'APPLICATION',
    comment: `Branch: ${args.branch}`,
  }

  const packages: SpdxPackage[] = [rootPackage]
  const relationships: SpdxRelationship[] = [
    {
      spdxElementId: rootId,
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: rootPackageId,
    },
  ]

  // Deduplicate components (same name+version should produce the same SPDXID)
  const seen = new Set<string>()

  for (const component of args.components) {
    const id = spdxId(component.name, component.version)
    if (seen.has(id)) continue
    seen.add(id)

    const purl = buildPurl(component.name, component.version, component.ecosystem)
    const license = normalizeLicense(component.license)

    const pkg: SpdxPackage = {
      SPDXID: id,
      name: component.name,
      versionInfo: component.version || 'NOASSERTION',
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: license,
      licenseInfoFromFiles: [],
      licenseDeclared: license,
      copyrightText: 'NOASSERTION',
      primaryPackagePurpose: component.layer === 'container' ? 'CONTAINER' : 'LIBRARY',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE_MANAGER',
          referenceType: 'purl',
          referenceLocator: purl,
        },
        ...(component.hasKnownVulnerabilities
          ? [
              {
                referenceCategory: 'SECURITY' as const,
                referenceType: 'advisory',
                referenceLocator: `https://osv.dev/v1/query?package=${encodeURIComponent(component.name)}&ecosystem=${component.ecosystem}`,
              },
            ]
          : []),
      ],
      annotations: component.trustScore < 50
        ? [
            {
              annotationType: 'REVIEW',
              annotator: 'Tool: Sentinel',
              comment: `Trust score: ${component.trustScore}/100 — review recommended`,
              annotationDate: timestamp,
            },
          ]
        : undefined,
    }

    // Source file hint
    if (component.sourceFile) {
      pkg.sourceInfo = `Declared in ${component.sourceFile}`
    }

    packages.push(pkg)

    // Relationship to root
    relationships.push({
      spdxElementId: rootPackageId,
      relationshipType: component.isDirect ? 'DEPENDS_ON' : 'DEPENDENCY_OF',
      relatedSpdxElement: id,
      comment: component.isDirect ? 'direct dependency' : 'transitive dependency',
    })
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: docName,
    documentNamespace: `https://sentinelsec.io/sbom/${args.repositoryFullName}/${args.commitSha}`,
    documentDescribes: [rootPackageId],
    creationInfo: {
      created: timestamp,
      creators: [
        'Tool: Sentinel-1.0',
        `Organization: ${args.repositoryFullName.split('/')[0] ?? 'Unknown'}`,
      ],
      licenseListVersion: '3.22',
      comment: `Generated by Sentinel from commit ${args.commitSha} on branch ${args.branch}`,
    },
    packages,
    relationships,
    comment: `Sentinel SBOM export — ${args.components.length} components across ${args.repositoryFullName}`,
  }
}
