/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import {
  buildPrProposalContent,
  detectFixType,
  generateProposedBranch,
  generatePrBody,
  generatePrTitle,
  type PrProposalInput,
} from './prGeneration'

const baseInput: PrProposalInput = {
  repositoryName: 'payments-api',
  findingTitle: 'PyJWT audience validation wrapper needs exploit confirmation',
  findingSummary:
    'The current auth gateway uses a wrapper around token validation that may bypass the newly disclosed audience-check hardening path.',
  findingSeverity: 'high',
  affectedPackages: ['pyjwt'],
  disclosureRef: 'GHSA-77m4-fm8m-6h7p',
  packageName: 'pyjwt',
  packageEcosystem: 'pypi',
  currentVersion: '2.10.1',
  fixVersion: '2.10.2',
}

// ---------------------------------------------------------------------------
// generateProposedBranch
// ---------------------------------------------------------------------------

describe('generateProposedBranch', () => {
  test('returns a sentinel/ prefixed branch with package and version slug', () => {
    const branch = generateProposedBranch('payments-api', 'pyjwt', '2.10.2')
    expect(branch).toMatch(/^sentinel\/fix-pyjwt-2-10-2-/)
  })

  test('is deterministic for the same inputs', () => {
    const b1 = generateProposedBranch('payments-api', 'pyjwt', '2.10.2')
    const b2 = generateProposedBranch('payments-api', 'pyjwt', '2.10.2')
    expect(b1).toBe(b2)
  })

  test('falls back to security-fix prefix when packageName is undefined', () => {
    const branch = generateProposedBranch('payments-api', undefined, undefined)
    expect(branch).toMatch(/^sentinel\/security-fix-payments-api-/)
  })

  test('slugifies @ and / characters from scoped package names into the branch slug', () => {
    const branch = generateProposedBranch('web', '@scope/my-pkg', '1.0.0')
    // The leading `sentinel/` prefix is expected; verify the package slug portion
    // does not carry through the raw @ or extra path separators from the npm scope.
    const afterPrefix = branch.replace(/^sentinel\/fix-/, '')
    expect(afterPrefix).not.toContain('@')
    expect(afterPrefix).not.toContain('/')
    expect(branch).toMatch(/^sentinel\/fix-/)
  })

  test('stays within a reasonable length', () => {
    const branch = generateProposedBranch(
      'a-very-long-repository-name-that-goes-on-and-on',
      'a-very-long-package-name-that-also-goes-on',
      '100.200.300',
    )
    expect(branch.length).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// generatePrTitle
// ---------------------------------------------------------------------------

describe('generatePrTitle', () => {
  test('generates a version bump title when both versions are known', () => {
    expect(generatePrTitle('pyjwt', '2.10.1', '2.10.2')).toBe(
      'fix(deps): bump pyjwt from 2.10.1 to 2.10.2',
    )
  })

  test('generates an upgrade title when only fixVersion is known', () => {
    expect(generatePrTitle('pyjwt', undefined, '2.10.2')).toBe(
      'fix(deps): upgrade pyjwt to 2.10.2',
    )
  })

  test('generates a patch title when no fixVersion is available', () => {
    expect(generatePrTitle('pyjwt', '2.10.1', undefined)).toBe(
      'fix(security): patch pyjwt vulnerability',
    )
  })

  test('generates a generic security title when packageName is undefined', () => {
    expect(generatePrTitle(undefined, undefined, undefined)).toBe(
      'fix(security): resolve Sentinel security finding',
    )
  })
})

// ---------------------------------------------------------------------------
// generatePrBody
// ---------------------------------------------------------------------------

describe('generatePrBody', () => {
  test('includes the finding title and severity', () => {
    const body = generatePrBody(baseInput)
    expect(body).toContain('PyJWT audience validation wrapper')
    expect(body).toContain('high')
  })

  test('includes the version bump details', () => {
    const body = generatePrBody(baseInput)
    expect(body).toContain('2.10.1')
    expect(body).toContain('2.10.2')
    expect(body).toContain('pyjwt')
  })

  test('includes the disclosure reference when provided', () => {
    const body = generatePrBody(baseInput)
    expect(body).toContain('GHSA-77m4-fm8m-6h7p')
  })

  test('omits the References section when disclosureRef is undefined', () => {
    const body = generatePrBody({ ...baseInput, disclosureRef: undefined })
    expect(body).not.toContain('References')
  })

  test('handles a finding with no packageName without producing "undefined"', () => {
    const body = generatePrBody({
      ...baseInput,
      packageName: undefined,
      currentVersion: undefined,
      fixVersion: undefined,
      affectedPackages: [],
    })
    expect(body).toContain('Security Fix')
    expect(body).not.toContain('undefined')
  })

  test('lists affected packages', () => {
    const body = generatePrBody({
      ...baseInput,
      affectedPackages: ['pyjwt', 'cryptography'],
    })
    expect(body).toContain('`pyjwt`')
    expect(body).toContain('`cryptography`')
  })
})

// ---------------------------------------------------------------------------
// detectFixType
// ---------------------------------------------------------------------------

describe('detectFixType', () => {
  test('returns version_bump when packageName and fixVersion are both present', () => {
    expect(detectFixType('pyjwt', '2.10.2')).toBe('version_bump')
  })

  test('returns patch when packageName is known but fixVersion is not', () => {
    expect(detectFixType('pyjwt', undefined)).toBe('patch')
  })

  test('returns manual when packageName is undefined regardless of fixVersion', () => {
    expect(detectFixType(undefined, '2.10.2')).toBe('manual')
    expect(detectFixType(undefined, undefined)).toBe('manual')
  })
})

// ---------------------------------------------------------------------------
// buildPrProposalContent
// ---------------------------------------------------------------------------

describe('buildPrProposalContent', () => {
  test('composes all fields correctly for a version bump finding', () => {
    const result = buildPrProposalContent(baseInput)
    expect(result.fixType).toBe('version_bump')
    expect(result.prTitle).toBe('fix(deps): bump pyjwt from 2.10.1 to 2.10.2')
    expect(result.targetPackage).toBe('pyjwt')
    expect(result.targetEcosystem).toBe('pypi')
    expect(result.currentVersion).toBe('2.10.1')
    expect(result.fixVersion).toBe('2.10.2')
    expect(result.fixSummary).toContain('2.10.1')
    expect(result.fixSummary).toContain('2.10.2')
    expect(result.proposedBranch).toMatch(/^sentinel\/fix-pyjwt-2-10-2-/)
  })

  test('uses manual fix type and no version fields for a non-package finding', () => {
    const result = buildPrProposalContent({
      ...baseInput,
      packageName: undefined,
      currentVersion: undefined,
      fixVersion: undefined,
    })
    expect(result.fixType).toBe('manual')
    expect(result.targetPackage).toBeUndefined()
    expect(result.currentVersion).toBeUndefined()
    expect(result.fixVersion).toBeUndefined()
    expect(result.fixSummary).toContain('Manual remediation')
  })
})
