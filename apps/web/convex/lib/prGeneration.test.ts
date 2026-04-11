/// <reference types="vite/client" />
import { describe, expect, test } from 'vitest'
import {
  applyVersionBumpToManifest,
  buildPrProposalContent,
  detectFixType,
  generateProposedBranch,
  generatePrBody,
  generatePrTitle,
  patchPackageJson,
  patchPyprojectToml,
  patchRequirementsTxt,
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

// ---------------------------------------------------------------------------
// patchRequirementsTxt
// ---------------------------------------------------------------------------

describe('patchRequirementsTxt', () => {
  test('pins == specifier to new version', () => {
    const result = patchRequirementsTxt('pyjwt==2.10.1\n', 'pyjwt', '2.10.2')
    expect(result).toBe('pyjwt==2.10.2\n')
  })

  test('replaces >= specifier with exact pin', () => {
    const result = patchRequirementsTxt('pyjwt>=2.6.0\n', 'pyjwt', '2.10.2')
    expect(result).toBe('pyjwt==2.10.2\n')
  })

  test('replaces ~= compatible-release specifier with exact pin', () => {
    const result = patchRequirementsTxt('pyjwt~=2.10.0\n', 'pyjwt', '2.10.2')
    expect(result).toBe('pyjwt==2.10.2\n')
  })

  test('handles uppercase package name (PyJWT) and preserves original casing', () => {
    const result = patchRequirementsTxt('PyJWT==2.10.1\nrequests==2.28.0\n', 'pyjwt', '2.10.2')
    expect(result).toBe('PyJWT==2.10.2\nrequests==2.28.0\n')
  })

  test('preserves extras in square brackets', () => {
    const result = patchRequirementsTxt('pyjwt[crypto]>=2.8.0\n', 'pyjwt', '2.10.2')
    expect(result).toBe('pyjwt[crypto]==2.10.2\n')
  })

  test('preserves environment markers after semicolon', () => {
    const result = patchRequirementsTxt(
      "pyjwt>=2.6.0 ; python_version>='3.8'\n",
      'pyjwt',
      '2.10.2',
    )
    expect(result).toBe("pyjwt==2.10.2 ; python_version>='3.8'\n")
  })

  test('preserves trailing inline comment', () => {
    const result = patchRequirementsTxt(
      'pyjwt==2.10.1  # CVE-2022-29217\n',
      'pyjwt',
      '2.10.2',
    )
    expect(result).toContain('pyjwt==2.10.2')
    expect(result).toContain('# CVE-2022-29217')
  })

  test('pins a bare package name (no specifier)', () => {
    const result = patchRequirementsTxt('pyjwt\n', 'pyjwt', '2.10.2')
    expect(result).toBe('pyjwt==2.10.2\n')
  })

  test('returns null when package is not in the file', () => {
    expect(patchRequirementsTxt('requests==2.28.0\n', 'pyjwt', '2.10.2')).toBeNull()
  })

  test('does not match a package whose name starts with the target name', () => {
    const result = patchRequirementsTxt('pyjwt-extensions==1.0.0\npyjwt==2.10.1\n', 'pyjwt', '2.10.2')
    // Only pyjwt should change; pyjwt-extensions must be left alone
    expect(result).toContain('pyjwt-extensions==1.0.0')
    expect(result).toContain('pyjwt==2.10.2')
  })

  test('skips comment-only lines', () => {
    const input = '# pinned packages\npyjwt==2.10.1\n'
    const result = patchRequirementsTxt(input, 'pyjwt', '2.10.2')
    expect(result).toContain('# pinned packages')
    expect(result).toContain('pyjwt==2.10.2')
  })
})

// ---------------------------------------------------------------------------
// patchPackageJson
// ---------------------------------------------------------------------------

describe('patchPackageJson', () => {
  test('bumps an exact version in dependencies', () => {
    const pkg = JSON.stringify({ dependencies: { lodash: '4.17.20' } }, null, 2) + '\n'
    const result = patchPackageJson(pkg, 'lodash', '4.17.21')
    expect(result).not.toBeNull()
    expect(JSON.parse(result!).dependencies.lodash).toBe('4.17.21')
  })

  test('preserves the ^ caret range prefix', () => {
    const pkg = JSON.stringify({ dependencies: { lodash: '^4.17.20' } }, null, 2) + '\n'
    const result = patchPackageJson(pkg, 'lodash', '4.17.21')
    expect(JSON.parse(result!).dependencies.lodash).toBe('^4.17.21')
  })

  test('preserves the ~ tilde range prefix', () => {
    const pkg = JSON.stringify({ dependencies: { lodash: '~4.17.20' } }, null, 2) + '\n'
    const result = patchPackageJson(pkg, 'lodash', '4.17.21')
    expect(JSON.parse(result!).dependencies.lodash).toBe('~4.17.21')
  })

  test('finds package in devDependencies', () => {
    const pkg = JSON.stringify({ devDependencies: { jest: '29.0.0' } }, null, 2)
    const result = patchPackageJson(pkg, 'jest', '29.1.0')
    expect(JSON.parse(result!).devDependencies.jest).toBe('29.1.0')
  })

  test('handles scoped npm package names', () => {
    const pkg = JSON.stringify({ dependencies: { '@scope/pkg': '1.0.0' } }, null, 2)
    const result = patchPackageJson(pkg, '@scope/pkg', '1.0.1')
    expect(JSON.parse(result!).dependencies['@scope/pkg']).toBe('1.0.1')
  })

  test('returns null when package is not found in any dependency field', () => {
    const pkg = JSON.stringify({ dependencies: { react: '18.0.0' } }, null, 2)
    expect(patchPackageJson(pkg, 'lodash', '4.17.21')).toBeNull()
  })

  test('returns null for invalid JSON', () => {
    expect(patchPackageJson('not valid json', 'lodash', '4.17.21')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// patchPyprojectToml
// ---------------------------------------------------------------------------

describe('patchPyprojectToml', () => {
  test('handles Poetry simple specifier (caret range)', () => {
    const content = '[tool.poetry.dependencies]\npyjwt = "^2.10.1"\n'
    const result = patchPyprojectToml(content, 'pyjwt', '2.10.2')
    expect(result).toContain('pyjwt = ">=2.10.2"')
  })

  test('handles PEP 517 dependency array string', () => {
    const content = '[project]\ndependencies = [\n    "pyjwt>=2.6.0",\n]\n'
    const result = patchPyprojectToml(content, 'pyjwt', '2.10.2')
    expect(result).toContain('"pyjwt>=2.10.2"')
  })

  test('handles Poetry inline table with version key', () => {
    const content =
      '[tool.poetry.dependencies]\npyjwt = {version = "^2.10.1", extras = ["crypto"]}\n'
    const result = patchPyprojectToml(content, 'pyjwt', '2.10.2')
    expect(result).not.toBeNull()
    expect(result).toContain('>=2.10.2"')
    expect(result).toContain('extras = ["crypto"]')
  })

  test('handles uppercase PyPI name via normalization', () => {
    const content = '[tool.poetry.dependencies]\nPyJWT = "^2.10.1"\n'
    const result = patchPyprojectToml(content, 'pyjwt', '2.10.2')
    expect(result).not.toBeNull()
    expect(result).toContain('>=2.10.2')
  })

  test('returns null when package is not found', () => {
    const content = '[tool.poetry.dependencies]\nrequests = "^2.28.0"\n'
    expect(patchPyprojectToml(content, 'pyjwt', '2.10.2')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// applyVersionBumpToManifest
// ---------------------------------------------------------------------------

describe('applyVersionBumpToManifest', () => {
  test('dispatches to patchPackageJson for package.json', () => {
    const content = JSON.stringify({ dependencies: { lodash: '4.17.20' } }, null, 2) + '\n'
    const result = applyVersionBumpToManifest('package.json', content, 'lodash', '4.17.21')
    expect(result).not.toBeNull()
    expect(JSON.parse(result!).dependencies.lodash).toBe('4.17.21')
  })

  test('dispatches to patchRequirementsTxt for requirements.txt', () => {
    const result = applyVersionBumpToManifest(
      'requirements.txt',
      'pyjwt==2.10.1\n',
      'pyjwt',
      '2.10.2',
    )
    expect(result).toBe('pyjwt==2.10.2\n')
  })

  test('dispatches to patchRequirementsTxt for nested requirements path', () => {
    const result = applyVersionBumpToManifest(
      'requirements/base.txt',
      'pyjwt>=2.6.0\n',
      'pyjwt',
      '2.10.2',
    )
    expect(result).toBe('pyjwt==2.10.2\n')
  })

  test('dispatches to patchPyprojectToml for pyproject.toml', () => {
    const content = '[tool.poetry.dependencies]\npyjwt = "^2.10.1"\n'
    const result = applyVersionBumpToManifest('pyproject.toml', content, 'pyjwt', '2.10.2')
    expect(result).toContain('>=2.10.2')
  })

  test('returns null for an unrecognised manifest filename', () => {
    expect(applyVersionBumpToManifest('custom.lock', 'pyjwt==2.10.1\n', 'pyjwt', '2.10.2')).toBeNull()
  })
})
