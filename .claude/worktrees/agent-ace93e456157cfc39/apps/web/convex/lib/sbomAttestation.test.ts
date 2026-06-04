/// <reference types="vite/client" />
// WS-40 — SBOM Attestation: unit tests.

import { describe, expect, test } from 'vitest'
import {
  ATTESTATION_VERSION,
  canonicalizeSbomComponents,
  computeAttestationHash,
  computeContentHash,
  generateSbomAttestation,
  sha256Hex,
  verifyAttestation,
} from './sbomAttestation'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SNAPSHOT_ID = 'snap_test_001'
const TENANT_SLUG = 'acme-corp'
const CAPTURED_AT = Date.UTC(2026, 3, 22, 12, 0, 0) // 2026-04-22T12:00:00Z
const NOW = Date.UTC(2026, 3, 22, 12, 1, 0)

const SAMPLE_COMPONENTS = [
  { name: 'express', version: '4.18.0', ecosystem: 'npm' },
  { name: 'react', version: '18.2.0', ecosystem: 'npm' },
  { name: 'fastapi', version: '0.100.0', ecosystem: 'pypi' },
]

// ---------------------------------------------------------------------------
// sha256Hex — known-answer tests
// ---------------------------------------------------------------------------

describe('sha256Hex', () => {
  test('empty string produces correct SHA-256', () => {
    // RFC 6234 known answer
    expect(sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb924' +
      '27ae41e4649b934ca495991b7852b855',
    )
  })

  test('"abc" produces correct SHA-256', () => {
    // Verified against: openssl dgst -sha256, Python hashlib, Node.js crypto, Wikipedia SHA-2
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223' +
      'b00361a396177a9cb410ff61f20015ad',
    )
  })

  test('"hello world" produces consistent output', () => {
    const hash = sha256Hex('hello world')
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
    // Same input always produces same output
    expect(sha256Hex('hello world')).toBe(hash)
  })

  test('different inputs produce different hashes', () => {
    expect(sha256Hex('abc')).not.toBe(sha256Hex('abd'))
    expect(sha256Hex('sentinel')).not.toBe(sha256Hex('sentinel '))
  })

  test('output is always 64 hex characters', () => {
    for (const msg of ['', 'a', 'hello world', 'x'.repeat(100)]) {
      expect(sha256Hex(msg)).toHaveLength(64)
      expect(sha256Hex(msg)).toMatch(/^[0-9a-f]{64}$/)
    }
  })

  test('handles multi-block input (>55 bytes for padding extension)', () => {
    // 64 characters forces two blocks
    const sixtyFourChars = 'a'.repeat(64)
    const hash = sha256Hex(sixtyFourChars)
    expect(hash).toHaveLength(64)
    // Verify it's deterministic
    expect(sha256Hex(sixtyFourChars)).toBe(hash)
  })

  test('handles unicode input', () => {
    const hash = sha256Hex('café')
    expect(hash).toHaveLength(64)
    expect(sha256Hex('café')).toBe(hash)
  })
})

// ---------------------------------------------------------------------------
// canonicalizeSbomComponents
// ---------------------------------------------------------------------------

describe('canonicalizeSbomComponents', () => {
  test('produces a string starting with the sentinel prefix', () => {
    const canonical = canonicalizeSbomComponents(SAMPLE_COMPONENTS)
    expect(canonical).toMatch(/^sentinel-sbom-v\d+\n/)
  })

  test('output is deterministic regardless of input order', () => {
    const components1 = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
    ]
    const components2 = [
      { name: 'react', version: '18.2.0', ecosystem: 'npm' },
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
    ]
    expect(canonicalizeSbomComponents(components1)).toBe(canonicalizeSbomComponents(components2))
  })

  test('different component lists produce different canonical strings', () => {
    const c1 = [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }]
    const c2 = [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }]
    expect(canonicalizeSbomComponents(c1)).not.toBe(canonicalizeSbomComponents(c2))
  })

  test('deduplicates repeated components', () => {
    const components = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
    ]
    const once = [{ name: 'express', version: '4.18.0', ecosystem: 'npm' }]
    expect(canonicalizeSbomComponents(components)).toBe(canonicalizeSbomComponents(once))
  })

  test('is case-insensitive for ecosystem and name', () => {
    const lower = [{ name: 'express', version: '4.18.0', ecosystem: 'npm' }]
    const upper = [{ name: 'Express', version: '4.18.0', ecosystem: 'NPM' }]
    expect(canonicalizeSbomComponents(lower)).toBe(canonicalizeSbomComponents(upper))
  })

  test('adding a component changes the canonical string', () => {
    const before = SAMPLE_COMPONENTS
    const after = [...SAMPLE_COMPONENTS, { name: 'lodash', version: '4.17.21', ecosystem: 'npm' }]
    expect(canonicalizeSbomComponents(before)).not.toBe(canonicalizeSbomComponents(after))
  })

  test('empty component list produces minimal canonical string', () => {
    const canonical = canonicalizeSbomComponents([])
    expect(canonical).toBe(`sentinel-sbom-v${ATTESTATION_VERSION}\n`)
  })
})

// ---------------------------------------------------------------------------
// computeContentHash
// ---------------------------------------------------------------------------

describe('computeContentHash', () => {
  test('returns 64-char hex string', () => {
    const hash = computeContentHash(SAMPLE_COMPONENTS)
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  test('is deterministic', () => {
    expect(computeContentHash(SAMPLE_COMPONENTS)).toBe(computeContentHash(SAMPLE_COMPONENTS))
  })

  test('is order-independent (same as canonicalization)', () => {
    const shuffled = [
      SAMPLE_COMPONENTS[2],
      SAMPLE_COMPONENTS[0],
      SAMPLE_COMPONENTS[1],
    ]
    expect(computeContentHash(SAMPLE_COMPONENTS)).toBe(computeContentHash(shuffled))
  })

  test('changes when a version changes', () => {
    const original = [{ name: 'express', version: '4.18.0', ecosystem: 'npm' }]
    const updated = [{ name: 'express', version: '4.18.1', ecosystem: 'npm' }]
    expect(computeContentHash(original)).not.toBe(computeContentHash(updated))
  })

  test('changes when a component is added', () => {
    const original = [{ name: 'express', version: '4.18.0', ecosystem: 'npm' }]
    const extended = [
      { name: 'express', version: '4.18.0', ecosystem: 'npm' },
      { name: 'lodash', version: '4.0.0', ecosystem: 'npm' },
    ]
    expect(computeContentHash(original)).not.toBe(computeContentHash(extended))
  })
})

// ---------------------------------------------------------------------------
// computeAttestationHash
// ---------------------------------------------------------------------------

describe('computeAttestationHash', () => {
  test('returns 64-char hex string', () => {
    const contentHash = computeContentHash(SAMPLE_COMPONENTS)
    const hash = computeAttestationHash(contentHash, TENANT_SLUG, SNAPSHOT_ID, CAPTURED_AT)
    expect(hash).toHaveLength(64)
    expect(hash).toMatch(/^[0-9a-f]{64}$/)
  })

  test('different tenant slugs produce different attestation hashes', () => {
    const contentHash = computeContentHash(SAMPLE_COMPONENTS)
    const h1 = computeAttestationHash(contentHash, 'tenant-a', SNAPSHOT_ID, CAPTURED_AT)
    const h2 = computeAttestationHash(contentHash, 'tenant-b', SNAPSHOT_ID, CAPTURED_AT)
    expect(h1).not.toBe(h2)
  })

  test('different snapshot IDs produce different attestation hashes', () => {
    const contentHash = computeContentHash(SAMPLE_COMPONENTS)
    const h1 = computeAttestationHash(contentHash, TENANT_SLUG, 'snap_001', CAPTURED_AT)
    const h2 = computeAttestationHash(contentHash, TENANT_SLUG, 'snap_002', CAPTURED_AT)
    expect(h1).not.toBe(h2)
  })

  test('different capturedAt timestamps produce different attestation hashes', () => {
    const contentHash = computeContentHash(SAMPLE_COMPONENTS)
    const h1 = computeAttestationHash(contentHash, TENANT_SLUG, SNAPSHOT_ID, CAPTURED_AT)
    const h2 = computeAttestationHash(contentHash, TENANT_SLUG, SNAPSHOT_ID, CAPTURED_AT + 1000)
    expect(h1).not.toBe(h2)
  })
})

// ---------------------------------------------------------------------------
// generateSbomAttestation
// ---------------------------------------------------------------------------

describe('generateSbomAttestation', () => {
  test('returns a valid AttestationRecord', () => {
    const rec = generateSbomAttestation(
      SNAPSHOT_ID,
      SAMPLE_COMPONENTS,
      TENANT_SLUG,
      CAPTURED_AT,
      NOW,
    )
    expect(rec.snapshotId).toBe(SNAPSHOT_ID)
    expect(rec.tenantSlug).toBe(TENANT_SLUG)
    expect(rec.capturedAt).toBe(CAPTURED_AT)
    expect(rec.attestedAt).toBe(NOW)
    expect(rec.attestationVersion).toBe(ATTESTATION_VERSION)
    expect(rec.componentCount).toBe(SAMPLE_COMPONENTS.length)
  })

  test('contentHash and attestationHash are 64-char hex', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    expect(rec.contentHash).toHaveLength(64)
    expect(rec.attestationHash).toHaveLength(64)
    expect(rec.contentHash).toMatch(/^[0-9a-f]{64}$/)
    expect(rec.attestationHash).toMatch(/^[0-9a-f]{64}$/)
  })

  test('contentHash and attestationHash are different values', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    expect(rec.contentHash).not.toBe(rec.attestationHash)
  })

  test('same inputs always produce same hashes (deterministic)', () => {
    const rec1 = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const rec2 = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    expect(rec1.contentHash).toBe(rec2.contentHash)
    expect(rec1.attestationHash).toBe(rec2.attestationHash)
  })

  test('deduplicates components for componentCount', () => {
    const duplicated = [
      ...SAMPLE_COMPONENTS,
      SAMPLE_COMPONENTS[0], // duplicate
    ]
    const rec = generateSbomAttestation(SNAPSHOT_ID, duplicated, TENANT_SLUG, CAPTURED_AT, NOW)
    expect(rec.componentCount).toBe(SAMPLE_COMPONENTS.length)
  })
})

// ---------------------------------------------------------------------------
// verifyAttestation
// ---------------------------------------------------------------------------

describe('verifyAttestation', () => {
  test('returns valid when component list is unchanged', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const result = verifyAttestation(
      SAMPLE_COMPONENTS,
      TENANT_SLUG,
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW,
    )
    expect(result.status).toBe('valid')
    expect(result.integrityOk).toBe(true)
    expect(result.storedHash).toBe(rec.attestationHash)
    expect(result.recomputedHash).toBe(rec.attestationHash)
  })

  test('returns tampered when a component version changes', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const tampered = [
      ...SAMPLE_COMPONENTS.slice(0, 2),
      { name: 'fastapi', version: '999.0.0', ecosystem: 'pypi' }, // version bumped
    ]
    const result = verifyAttestation(
      tampered,
      TENANT_SLUG,
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW,
    )
    expect(result.status).toBe('tampered')
    expect(result.integrityOk).toBe(false)
    expect(result.storedHash).not.toBe(result.recomputedHash)
  })

  test('returns tampered when a component is removed', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const reduced = SAMPLE_COMPONENTS.slice(0, 2)
    const result = verifyAttestation(
      reduced,
      TENANT_SLUG,
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW,
    )
    expect(result.status).toBe('tampered')
    expect(result.integrityOk).toBe(false)
  })

  test('returns tampered when a component is added', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const expanded = [
      ...SAMPLE_COMPONENTS,
      { name: 'injected-malware', version: '1.0.0', ecosystem: 'npm' },
    ]
    const result = verifyAttestation(
      expanded,
      TENANT_SLUG,
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW,
    )
    expect(result.status).toBe('tampered')
    expect(result.integrityOk).toBe(false)
  })

  test('returns tampered when wrong tenant slug used for verification', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const result = verifyAttestation(
      SAMPLE_COMPONENTS,
      'different-tenant',
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW,
    )
    expect(result.status).toBe('tampered')
    expect(result.integrityOk).toBe(false)
  })

  test('result includes verifiedAt timestamp', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const result = verifyAttestation(
      SAMPLE_COMPONENTS,
      TENANT_SLUG,
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW + 1000,
    )
    expect(result.verifiedAt).toBe(NOW + 1000)
  })

  test('component order does not affect verification result', () => {
    const rec = generateSbomAttestation(SNAPSHOT_ID, SAMPLE_COMPONENTS, TENANT_SLUG, CAPTURED_AT, NOW)
    const shuffled = [SAMPLE_COMPONENTS[2], SAMPLE_COMPONENTS[0], SAMPLE_COMPONENTS[1]]
    const result = verifyAttestation(
      shuffled,
      TENANT_SLUG,
      SNAPSHOT_ID,
      CAPTURED_AT,
      rec.attestationHash,
      NOW,
    )
    expect(result.status).toBe('valid')
  })
})
