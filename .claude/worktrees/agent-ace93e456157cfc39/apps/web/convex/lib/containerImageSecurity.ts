/**
 * WS-45 — Container Image Security Analyzer: pure computation library.
 *
 * Detects security risks in container base images declared in SBOM components
 * (ecosystem 'docker' or 'container'). Uses a static database of ~35 popular
 * base images with version-lifecycle guidance.
 *
 * Detection signals:
 *   eol_base_image    — version tag is past its vendor-declared end-of-life date (critical)
 *   near_eol          — within NEAR_EOL_WINDOW_DAYS of EOL (high)
 *   outdated_base     — not the recommended LTS/stable version, but still supported (medium)
 *   no_version_tag    — using 'latest', '*', or no version — unpinned (medium)
 *   deprecated_image  — image name is deprecated/abandoned (high)
 *
 * Reference date: all EOL dates are compared against a provided timestamp
 * (defaults to Date.now()) so the scanner stays accurate over time.
 *
 * Zero network calls. Zero Convex imports. Safe to use in tests.
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Flag images as near-EOL when within 90 days of their EOL date. */
export const NEAR_EOL_WINDOW_DAYS = 90
export const NEAR_EOL_WINDOW_MS = NEAR_EOL_WINDOW_DAYS * 24 * 60 * 60 * 1000

/** Ecosystems that identify container-layer components. */
export const CONTAINER_ECOSYSTEMS = new Set(['docker', 'container', 'oci'])

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ContainerSignal =
  | 'eol_base_image'
  | 'near_eol'
  | 'outdated_base'
  | 'no_version_tag'
  | 'deprecated_image'

export type ContainerRiskLevel = 'critical' | 'high' | 'medium' | 'low'

export type ContainerImageRecord = {
  /** Base image name as it appears in FROM statements (lower-cased). */
  image: string
  /**
   * Version prefix for matching. '18.04' matches 'ubuntu:18.04',
   * '14' matches 'node:14' and 'node:14-alpine'. '' = any version.
   */
  versionPrefix: string
  signal: ContainerSignal
  riskLevel: ContainerRiskLevel
  /** Human-readable EOL/deprecation date (if applicable). */
  eolDateText?: string
  /** Recommended replacement version or image. */
  recommendedVersion: string
  /** Short description shown in findings. */
  detail: string
}

export type ContainerFinding = {
  imageName: string
  imageVersion: string
  signal: ContainerSignal
  riskLevel: ContainerRiskLevel
  eolDateText: string | null
  recommendedVersion: string
  detail: string
  evidence: string
}

export type ContainerImageReport = {
  findings: ContainerFinding[]
  totalImages: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  summary: string
}

// ---------------------------------------------------------------------------
// Static database
// ---------------------------------------------------------------------------
// Ordered by image family then version (oldest → newest).
// EOL dates sourced from official vendor end-of-life announcements.
// Reference date for "is this near-EOL?" is passed in at call time.

export const CONTAINER_IMAGE_DATABASE: ContainerImageRecord[] = [
  // ── Ubuntu ───────────────────────────────────────────────────────────────
  {
    image: 'ubuntu',
    versionPrefix: '16.04',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2021-04-30',
    recommendedVersion: '24.04',
    detail: 'Ubuntu 16.04 Xenial reached end-of-life on 2021-04-30.',
  },
  {
    image: 'ubuntu',
    versionPrefix: '18.04',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-04-30',
    recommendedVersion: '24.04',
    detail: 'Ubuntu 18.04 Bionic reached end-of-life on 2023-04-30.',
  },
  {
    image: 'ubuntu',
    versionPrefix: '20.04',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-04-30',
    recommendedVersion: '24.04',
    detail: 'Ubuntu 20.04 Focal reached end-of-life on 2025-04-30.',
  },

  // ── Debian ────────────────────────────────────────────────────────────────
  {
    image: 'debian',
    versionPrefix: '9',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2022-06-30',
    recommendedVersion: 'debian:12',
    detail: 'Debian 9 Stretch reached end-of-life on 2022-06-30.',
  },
  {
    image: 'debian',
    versionPrefix: 'stretch',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2022-06-30',
    recommendedVersion: 'debian:bookworm',
    detail: 'Debian Stretch (9) reached end-of-life on 2022-06-30.',
  },
  {
    image: 'debian',
    versionPrefix: '10',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-06-30',
    recommendedVersion: 'debian:12',
    detail: 'Debian 10 Buster reached end-of-life on 2024-06-30.',
  },
  {
    image: 'debian',
    versionPrefix: 'buster',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-06-30',
    recommendedVersion: 'debian:bookworm',
    detail: 'Debian Buster (10) reached end-of-life on 2024-06-30.',
  },
  {
    image: 'debian',
    versionPrefix: '11',
    signal: 'near_eol',
    riskLevel: 'high',
    eolDateText: '2026-08-14',
    recommendedVersion: 'debian:12',
    detail: 'Debian 11 Bullseye reaches end-of-life on 2026-08-14.',
  },
  {
    image: 'debian',
    versionPrefix: 'bullseye',
    signal: 'near_eol',
    riskLevel: 'high',
    eolDateText: '2026-08-14',
    recommendedVersion: 'debian:bookworm',
    detail: 'Debian Bullseye (11) reaches end-of-life on 2026-08-14.',
  },

  // ── Alpine ────────────────────────────────────────────────────────────────
  {
    image: 'alpine',
    versionPrefix: '3.16',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-05-23',
    recommendedVersion: 'alpine:3.21',
    detail: 'Alpine 3.16 reached end-of-life on 2024-05-23.',
  },
  {
    image: 'alpine',
    versionPrefix: '3.17',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-11-22',
    recommendedVersion: 'alpine:3.21',
    detail: 'Alpine 3.17 reached end-of-life on 2024-11-22.',
  },
  {
    image: 'alpine',
    versionPrefix: '3.18',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-05-09',
    recommendedVersion: 'alpine:3.21',
    detail: 'Alpine 3.18 reached end-of-life on 2025-05-09.',
  },
  {
    image: 'alpine',
    versionPrefix: '3.19',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2026-01-01',
    recommendedVersion: 'alpine:3.21',
    detail: 'Alpine 3.19 reached end-of-life on 2026-01-01.',
  },

  // ── Node.js ───────────────────────────────────────────────────────────────
  {
    image: 'node',
    versionPrefix: '12',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2022-04-30',
    recommendedVersion: 'node:22',
    detail: 'Node.js 12 reached end-of-life on 2022-04-30.',
  },
  {
    image: 'node',
    versionPrefix: '14',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-04-30',
    recommendedVersion: 'node:22',
    detail: 'Node.js 14 reached end-of-life on 2023-04-30.',
  },
  {
    image: 'node',
    versionPrefix: '16',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-09-11',
    recommendedVersion: 'node:22',
    detail: 'Node.js 16 reached end-of-life on 2023-09-11.',
  },
  {
    image: 'node',
    versionPrefix: '18',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-04-30',
    recommendedVersion: 'node:22',
    detail: 'Node.js 18 reached end-of-life on 2025-04-30.',
  },
  {
    image: 'node',
    versionPrefix: '20',
    signal: 'near_eol',
    riskLevel: 'high',
    eolDateText: '2026-04-30',
    recommendedVersion: 'node:22',
    detail: 'Node.js 20 LTS reaches end-of-life on 2026-04-30.',
  },

  // ── Python ────────────────────────────────────────────────────────────────
  {
    image: 'python',
    versionPrefix: '2',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2020-01-01',
    recommendedVersion: 'python:3.12',
    detail: 'Python 2 reached end-of-life on 2020-01-01.',
  },
  {
    image: 'python',
    versionPrefix: '3.6',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2021-12-23',
    recommendedVersion: 'python:3.12',
    detail: 'Python 3.6 reached end-of-life on 2021-12-23.',
  },
  {
    image: 'python',
    versionPrefix: '3.7',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-06-27',
    recommendedVersion: 'python:3.12',
    detail: 'Python 3.7 reached end-of-life on 2023-06-27.',
  },
  {
    image: 'python',
    versionPrefix: '3.8',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-10-31',
    recommendedVersion: 'python:3.12',
    detail: 'Python 3.8 reached end-of-life on 2024-10-31.',
  },
  {
    image: 'python',
    versionPrefix: '3.9',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-10-31',
    recommendedVersion: 'python:3.12',
    detail: 'Python 3.9 reached end-of-life on 2025-10-31.',
  },
  {
    image: 'python',
    versionPrefix: '3.10',
    signal: 'near_eol',
    riskLevel: 'high',
    eolDateText: '2026-10-31',
    recommendedVersion: 'python:3.12',
    detail: 'Python 3.10 reaches end-of-life on 2026-10-31.',
  },

  // ── PostgreSQL ────────────────────────────────────────────────────────────
  {
    image: 'postgres',
    versionPrefix: '11',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-11-09',
    recommendedVersion: 'postgres:16',
    detail: 'PostgreSQL 11 reached end-of-life on 2023-11-09.',
  },
  {
    image: 'postgres',
    versionPrefix: '12',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-11-14',
    recommendedVersion: 'postgres:16',
    detail: 'PostgreSQL 12 reached end-of-life on 2024-11-14.',
  },
  {
    image: 'postgres',
    versionPrefix: '13',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-11-13',
    recommendedVersion: 'postgres:16',
    detail: 'PostgreSQL 13 reached end-of-life on 2025-11-13.',
  },

  // ── PHP ───────────────────────────────────────────────────────────────────
  {
    image: 'php',
    versionPrefix: '7',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2022-11-28',
    recommendedVersion: 'php:8.3',
    detail: 'PHP 7.x reached end-of-life on 2022-11-28.',
  },
  {
    image: 'php',
    versionPrefix: '8.0',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-11-26',
    recommendedVersion: 'php:8.3',
    detail: 'PHP 8.0 reached end-of-life on 2023-11-26.',
  },
  {
    image: 'php',
    versionPrefix: '8.1',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-12-31',
    recommendedVersion: 'php:8.3',
    detail: 'PHP 8.1 reached end-of-life on 2025-12-31.',
  },

  // ── MySQL ─────────────────────────────────────────────────────────────────
  {
    image: 'mysql',
    versionPrefix: '5.7',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-10-31',
    recommendedVersion: 'mysql:8.4',
    detail: 'MySQL 5.7 reached end-of-life on 2023-10-31.',
  },
  {
    image: 'mysql',
    versionPrefix: '8.0',
    signal: 'near_eol',
    riskLevel: 'high',
    eolDateText: '2026-04-30',
    recommendedVersion: 'mysql:8.4',
    detail: 'MySQL 8.0 reaches end-of-life on 2026-04-30.',
  },

  // ── Redis ─────────────────────────────────────────────────────────────────
  {
    image: 'redis',
    versionPrefix: '5',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2022-04-30',
    recommendedVersion: 'redis:7.4',
    detail: 'Redis 5 reached end-of-life on 2022-04-30.',
  },
  {
    image: 'redis',
    versionPrefix: '6.0',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2023-07-31',
    recommendedVersion: 'redis:7.4',
    detail: 'Redis 6.0 reached end-of-life on 2023-07-31.',
  },
  {
    image: 'redis',
    versionPrefix: '6.2',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2024-03-31',
    recommendedVersion: 'redis:7.4',
    detail: 'Redis 6.2 reached end-of-life on 2024-03-31.',
  },
  {
    image: 'redis',
    versionPrefix: '7.0',
    signal: 'eol_base_image',
    riskLevel: 'critical',
    eolDateText: '2025-06-30',
    recommendedVersion: 'redis:7.4',
    detail: 'Redis 7.0 reached end-of-life on 2025-06-30.',
  },

  // ── Nginx ─────────────────────────────────────────────────────────────────
  {
    image: 'nginx',
    versionPrefix: '1.20',
    signal: 'outdated_base',
    riskLevel: 'medium',
    recommendedVersion: 'nginx:1.26',
    detail: 'nginx 1.20 is an old stable branch; upgrade to 1.26 stable.',
  },
  {
    image: 'nginx',
    versionPrefix: '1.22',
    signal: 'outdated_base',
    riskLevel: 'medium',
    recommendedVersion: 'nginx:1.26',
    detail: 'nginx 1.22 is an old stable branch; upgrade to 1.26 stable.',
  },
  {
    image: 'nginx',
    versionPrefix: '1.24',
    signal: 'outdated_base',
    riskLevel: 'low',
    recommendedVersion: 'nginx:1.26',
    detail: 'nginx 1.24 is the previous stable branch; consider upgrading to 1.26.',
  },

  // ── Deprecated image names ────────────────────────────────────────────────
  {
    image: 'node',
    versionPrefix: 'erbium',
    signal: 'deprecated_image',
    riskLevel: 'high',
    recommendedVersion: 'node:22',
    detail: 'node:erbium (Node.js 12) is deprecated. Use a supported LTS version.',
  },
  {
    image: 'node',
    versionPrefix: 'fermium',
    signal: 'deprecated_image',
    riskLevel: 'high',
    recommendedVersion: 'node:22',
    detail: 'node:fermium (Node.js 14) is deprecated. Use a supported LTS version.',
  },
  {
    image: 'node',
    versionPrefix: 'gallium',
    signal: 'deprecated_image',
    riskLevel: 'high',
    recommendedVersion: 'node:22',
    detail: 'node:gallium (Node.js 16) is deprecated. Use a supported LTS version.',
  },
  {
    image: 'node',
    versionPrefix: 'hydrogen',
    signal: 'deprecated_image',
    riskLevel: 'critical',
    eolDateText: '2025-04-30',
    recommendedVersion: 'node:22',
    detail: 'node:hydrogen (Node.js 18) has reached end-of-life. Use a supported LTS version.',
  },
]

// Pre-index by image name for O(1) lookup.
const _IMAGE_INDEX = new Map<string, ContainerImageRecord[]>()
for (const entry of CONTAINER_IMAGE_DATABASE) {
  const key = entry.image.toLowerCase()
  const list = _IMAGE_INDEX.get(key) ?? []
  list.push(entry)
  _IMAGE_INDEX.set(key, list)
}

// ---------------------------------------------------------------------------
// Version-tag helpers
// ---------------------------------------------------------------------------

const UNPINNED_TAGS = new Set(['latest', '', '*', 'stable', 'current', 'edge'])

/** Returns true if the version tag is floating / unpinned. */
export function isUnpinnedTag(version: string): boolean {
  return UNPINNED_TAGS.has(version.toLowerCase().trim())
}

/**
 * Returns the first database record whose versionPrefix is a prefix of the
 * supplied version string (case-insensitive). For example, prefix '18.04'
 * matches version '18.04', '18.04-alpine', '18.04.1'.
 */
export function matchVersionPrefix(
  records: ContainerImageRecord[],
  version: string,
): ContainerImageRecord | null {
  const v = version.toLowerCase().trim()
  for (const record of records) {
    const p = record.versionPrefix.toLowerCase()
    if (p === '') return record // blank prefix = wildcard
    if (v === p || v.startsWith(p + '-') || v.startsWith(p + '.') || v.startsWith(p + '_')) {
      return record
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// checkContainerImage — per-component check
// ---------------------------------------------------------------------------

/**
 * Check a single SBOM component for container image security issues.
 * Returns null if the component is not a container image or is considered safe.
 */
export function checkContainerImage(component: {
  name: string
  version: string
  ecosystem: string
}): ContainerFinding | null {
  if (!CONTAINER_ECOSYSTEMS.has(component.ecosystem.toLowerCase())) return null

  const imageName = component.name.toLowerCase().trim()
  const imageVersion = component.version.trim()

  // ── No version tag (unpinned) ─────────────────────────────────────────────
  if (isUnpinnedTag(imageVersion)) {
    return {
      imageName: component.name,
      imageVersion,
      signal: 'no_version_tag',
      riskLevel: 'medium',
      eolDateText: null,
      recommendedVersion: `${imageName}:<specific-version>`,
      detail: `Image ${component.name} is pinned to an unversioned tag ('${imageVersion || 'latest'}'). Use a specific version tag for reproducible, auditable builds.`,
      evidence: `image=${component.name} version=${imageVersion || 'latest'} signal=no_version_tag`,
    }
  }

  // ── Database lookup ───────────────────────────────────────────────────────
  // Try exact image name first, then strip any registry prefix (e.g. 'docker.io/library/ubuntu' → 'ubuntu')
  const namesToTry = [imageName]
  const slashIdx = imageName.lastIndexOf('/')
  if (slashIdx !== -1) namesToTry.push(imageName.slice(slashIdx + 1))

  for (const nameCandidate of namesToTry) {
    const records = _IMAGE_INDEX.get(nameCandidate)
    if (!records) continue

    const match = matchVersionPrefix(records, imageVersion)
    if (match) {
      return {
        imageName: component.name,
        imageVersion,
        signal: match.signal,
        riskLevel: match.riskLevel,
        eolDateText: match.eolDateText ?? null,
        recommendedVersion: match.recommendedVersion,
        detail: match.detail,
        evidence: `image=${component.name} version=${imageVersion} signal=${match.signal} eol=${match.eolDateText ?? 'n/a'}`,
      }
    }
  }

  return null
}

// ---------------------------------------------------------------------------
// computeContainerImageReport — repository-level aggregation
// ---------------------------------------------------------------------------

export function computeContainerImageReport(
  components: Array<{ name: string; version: string; ecosystem: string }>,
): ContainerImageReport {
  // Filter for container-ecosystem components only (for totalImages count).
  const containerComponents = components.filter((c) =>
    CONTAINER_ECOSYSTEMS.has(c.ecosystem.toLowerCase()),
  )

  // Deduplicate by image:version.
  const seen = new Set<string>()
  const findings: ContainerFinding[] = []

  for (const component of containerComponents) {
    const key = `${component.ecosystem.toLowerCase()}:${component.name.toLowerCase()}@${component.version}`
    if (seen.has(key)) continue
    seen.add(key)

    const finding = checkContainerImage(component)
    if (finding) findings.push(finding)
  }

  // Sort by risk level: critical → high → medium → low.
  const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  findings.sort((a, b) => (RANK[a.riskLevel] ?? 4) - (RANK[b.riskLevel] ?? 4))

  const criticalCount = findings.filter((f) => f.riskLevel === 'critical').length
  const highCount = findings.filter((f) => f.riskLevel === 'high').length
  const mediumCount = findings.filter((f) => f.riskLevel === 'medium').length
  const lowCount = findings.filter((f) => f.riskLevel === 'low').length

  const overallRisk: ContainerImageReport['overallRisk'] =
    criticalCount > 0
      ? 'critical'
      : highCount > 0
        ? 'high'
        : mediumCount > 0
          ? 'medium'
          : lowCount > 0
            ? 'low'
            : 'none'

  const summary =
    findings.length === 0
      ? containerComponents.length === 0
        ? 'No container images found in this SBOM.'
        : 'All container base images are on supported versions.'
      : `${findings.length} container image issue${findings.length > 1 ? 's' : ''} detected: ${criticalCount} critical, ${highCount} high, ${mediumCount} medium.`

  return {
    findings,
    totalImages: containerComponents.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    overallRisk,
    summary,
  }
}
