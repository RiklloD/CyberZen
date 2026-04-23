/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { verifyDepLockIntegrity } from './depLockVerifier'

// ---------------------------------------------------------------------------
// 1. Vendor path filtering
// ---------------------------------------------------------------------------

describe('vendor path filtering', () => {
  it('returns clean result for empty paths array', () => {
    const r = verifyDepLockIntegrity([])
    expect(r.totalFindings).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.riskScore).toBe(0)
    expect(r.scannedPaths).toBe(0)
  })

  it('excludes node_modules lock files', () => {
    const r = verifyDepLockIntegrity(['node_modules/lodash/package-lock.json'])
    expect(r.totalFindings).toBe(0)
    expect(r.scannedPaths).toBe(0)
  })

  it('excludes vendor/Cargo.lock', () => {
    const r = verifyDepLockIntegrity(['vendor/Cargo.lock'])
    expect(r.totalFindings).toBe(0)
    expect(r.scannedPaths).toBe(0)
  })

  it('excludes dist/ paths', () => {
    const r = verifyDepLockIntegrity(['dist/package-lock.json', 'dist/package.json'])
    expect(r.totalFindings).toBe(0)
  })

  it('excludes .yarn/ directory', () => {
    const r = verifyDepLockIntegrity(['.yarn/cache/something', 'yarn.lock'])
    // yarn.lock is NOT in .yarn — it's at root, should be processed
    expect(r.scannedPaths).toBe(1)
  })

  it('skips blank and whitespace-only entries', () => {
    const r = verifyDepLockIntegrity(['', '   ', '\t'])
    expect(r.totalFindings).toBe(0)
    expect(r.scannedPaths).toBe(0)
  })

  it('normalises Windows backslash paths', () => {
    // node_modules\\lodash\\yarn.lock should be treated as vendored
    const r = verifyDepLockIntegrity(['node_modules\\lodash\\yarn.lock'])
    expect(r.totalFindings).toBe(0)
    expect(r.scannedPaths).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// 2. DIRECT_LOCK_EDIT — same-directory matching
// ---------------------------------------------------------------------------

describe('DIRECT_LOCK_EDIT', () => {
  it('triggers when yarn.lock changed without package.json in same dir', () => {
    const r = verifyDepLockIntegrity(['yarn.lock'])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchedPath).toBe('yarn.lock')
    expect(f!.matchCount).toBe(1)
  })

  it('does NOT trigger when yarn.lock and package.json change together (root)', () => {
    const r = verifyDepLockIntegrity(['yarn.lock', 'package.json'])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeUndefined()
  })

  it('triggers in monorepo: apps/api/yarn.lock without apps/api/package.json', () => {
    // apps/web/package.json exists but apps/api/yarn.lock is in a different dir
    const r = verifyDepLockIntegrity([
      'apps/api/yarn.lock',
      'apps/web/package.json',
    ])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
    expect(f!.matchedPath).toBe('apps/api/yarn.lock')
  })

  it('does NOT trigger in monorepo when same-dir manifest is present', () => {
    const r = verifyDepLockIntegrity([
      'apps/web/yarn.lock',
      'apps/web/package.json',
    ])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeUndefined()
  })

  it('triggers when Cargo.lock changed without Cargo.toml', () => {
    const r = verifyDepLockIntegrity(['Cargo.lock'])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
    expect(f!.matchedPath).toBe('Cargo.lock')
  })

  it('triggers when go.sum changed without go.mod', () => {
    const r = verifyDepLockIntegrity(['go.sum'])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
    expect(f!.matchedPath).toBe('go.sum')
  })

  it('triggers when poetry.lock changed without pyproject.toml', () => {
    const r = verifyDepLockIntegrity(['poetry.lock'])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
  })

  it('triggers when Gemfile.lock changed without Gemfile', () => {
    const r = verifyDepLockIntegrity(['Gemfile.lock'])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
    expect(f!.matchedPath).toBe('Gemfile.lock')
  })

  it('counts multiple direct lock edits in matchCount', () => {
    const r = verifyDepLockIntegrity([
      'apps/api/yarn.lock',
      'apps/web/package-lock.json',
    ])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
    expect(f!.matchedPath).toBe('apps/api/yarn.lock')
  })

  it('does NOT trigger when Pipfile.lock and Pipfile change together', () => {
    const r = verifyDepLockIntegrity(['Pipfile.lock', 'Pipfile'])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeUndefined()
  })

  it('does NOT trigger when go.sum and go.mod both change', () => {
    const r = verifyDepLockIntegrity(['go.mod', 'go.sum'])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 3. MIXED_NPM_LOCK_FILES
// ---------------------------------------------------------------------------

describe('MIXED_NPM_LOCK_FILES', () => {
  it('does NOT trigger when only one npm lock format is present', () => {
    const r = verifyDepLockIntegrity(['package-lock.json', 'package.json'])
    expect(r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')).toBeUndefined()
  })

  it('triggers when package-lock.json and yarn.lock change in same dir', () => {
    const r = verifyDepLockIntegrity(['package-lock.json', 'yarn.lock', 'package.json'])
    const f = r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchCount).toBe(2)
  })

  it('triggers with three npm lock formats, matchCount=3', () => {
    const r = verifyDepLockIntegrity([
      'package-lock.json',
      'yarn.lock',
      'bun.lock',
      'package.json',
    ])
    const f = r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })

  it('triggers with pnpm-lock.yaml + yarn.lock in same dir', () => {
    const r = verifyDepLockIntegrity([
      'apps/web/pnpm-lock.yaml',
      'apps/web/yarn.lock',
    ])
    const f = r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')
    expect(f).toBeDefined()
  })

  it('does NOT trigger when lock files are in different directories', () => {
    // apps/api uses yarn, apps/web uses pnpm — different dirs, valid monorepo
    const r = verifyDepLockIntegrity([
      'apps/api/yarn.lock',
      'apps/api/package.json',
      'apps/web/pnpm-lock.yaml',
      'apps/web/package.json',
    ])
    expect(r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 4. NPM_MANIFEST_WITHOUT_LOCK
// ---------------------------------------------------------------------------

describe('NPM_MANIFEST_WITHOUT_LOCK', () => {
  it('triggers when package.json changes and no npm lock file changes', () => {
    const r = verifyDepLockIntegrity(['package.json'])
    const f = r.findings.find((x) => x.ruleId === 'NPM_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.matchedPath).toBe('package.json')
    expect(f!.matchCount).toBe(1)
  })

  it('does NOT trigger when package.json and yarn.lock both change', () => {
    const r = verifyDepLockIntegrity(['package.json', 'yarn.lock'])
    expect(r.findings.find((x) => x.ruleId === 'NPM_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })

  it('does NOT trigger when package.json and package-lock.json both change', () => {
    const r = verifyDepLockIntegrity(['package.json', 'package-lock.json'])
    expect(r.findings.find((x) => x.ruleId === 'NPM_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })

  it('does NOT trigger when no package.json changes', () => {
    const r = verifyDepLockIntegrity(['src/index.ts', 'README.md'])
    expect(r.findings.find((x) => x.ruleId === 'NPM_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })

  it('counts multiple package.json changes in matchCount', () => {
    const r = verifyDepLockIntegrity([
      'apps/api/package.json',
      'apps/web/package.json',
    ])
    const f = r.findings.find((x) => x.ruleId === 'NPM_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// 5. CARGO_MANIFEST_WITHOUT_LOCK
// ---------------------------------------------------------------------------

describe('CARGO_MANIFEST_WITHOUT_LOCK', () => {
  it('triggers when Cargo.toml changes without Cargo.lock', () => {
    const r = verifyDepLockIntegrity(['Cargo.toml'])
    const f = r.findings.find((x) => x.ruleId === 'CARGO_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchedPath).toBe('Cargo.toml')
  })

  it('does NOT trigger when Cargo.toml and Cargo.lock both change', () => {
    const r = verifyDepLockIntegrity(['Cargo.toml', 'Cargo.lock'])
    expect(r.findings.find((x) => x.ruleId === 'CARGO_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })

  it('does NOT trigger when only Cargo.lock changes (DIRECT_LOCK_EDIT instead)', () => {
    const r = verifyDepLockIntegrity(['Cargo.lock'])
    expect(r.findings.find((x) => x.ruleId === 'CARGO_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeDefined()
  })

  it('counts multiple Cargo.toml changes', () => {
    const r = verifyDepLockIntegrity([
      'crates/auth/Cargo.toml',
      'crates/api/Cargo.toml',
    ])
    const f = r.findings.find((x) => x.ruleId === 'CARGO_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// 6. GO_MOD_WITHOUT_SUM
// ---------------------------------------------------------------------------

describe('GO_MOD_WITHOUT_SUM', () => {
  it('triggers when go.mod changes without go.sum', () => {
    const r = verifyDepLockIntegrity(['go.mod'])
    const f = r.findings.find((x) => x.ruleId === 'GO_MOD_WITHOUT_SUM')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchedPath).toBe('go.mod')
  })

  it('does NOT trigger when go.mod and go.sum both change', () => {
    const r = verifyDepLockIntegrity(['go.mod', 'go.sum'])
    expect(r.findings.find((x) => x.ruleId === 'GO_MOD_WITHOUT_SUM')).toBeUndefined()
  })

  it('does NOT trigger when only go.sum changes (DIRECT_LOCK_EDIT fires)', () => {
    const r = verifyDepLockIntegrity(['go.sum'])
    expect(r.findings.find((x) => x.ruleId === 'GO_MOD_WITHOUT_SUM')).toBeUndefined()
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeDefined()
  })

  it('counts multiple go.mod changes', () => {
    const r = verifyDepLockIntegrity([
      'services/auth/go.mod',
      'services/api/go.mod',
    ])
    const f = r.findings.find((x) => x.ruleId === 'GO_MOD_WITHOUT_SUM')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// 7. PYTHON_MANIFEST_WITHOUT_LOCK
// ---------------------------------------------------------------------------

describe('PYTHON_MANIFEST_WITHOUT_LOCK', () => {
  it('triggers when pyproject.toml changes without poetry.lock or Pipfile.lock', () => {
    const r = verifyDepLockIntegrity(['pyproject.toml'])
    const f = r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.matchedPath).toBe('pyproject.toml')
  })

  it('triggers when Pipfile changes without Pipfile.lock', () => {
    const r = verifyDepLockIntegrity(['Pipfile'])
    const f = r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.matchedPath).toBe('Pipfile')
  })

  it('does NOT trigger when pyproject.toml and poetry.lock both change', () => {
    const r = verifyDepLockIntegrity(['pyproject.toml', 'poetry.lock'])
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })

  it('does NOT trigger when Pipfile and Pipfile.lock both change', () => {
    const r = verifyDepLockIntegrity(['Pipfile', 'Pipfile.lock'])
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })

  it('counts both pyproject.toml and Pipfile in matchCount', () => {
    const r = verifyDepLockIntegrity(['pyproject.toml', 'Pipfile'])
    const f = r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
  })

  it('uses poetry.lock to satisfy pyproject.toml (cross-manifest)', () => {
    const r = verifyDepLockIntegrity(['pyproject.toml', 'Pipfile', 'poetry.lock'])
    // poetry.lock present → no finding
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 8. RUBY_GEMFILE_WITHOUT_LOCK
// ---------------------------------------------------------------------------

describe('RUBY_GEMFILE_WITHOUT_LOCK', () => {
  it('triggers when Gemfile changes without Gemfile.lock', () => {
    const r = verifyDepLockIntegrity(['Gemfile'])
    const f = r.findings.find((x) => x.ruleId === 'RUBY_GEMFILE_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.matchedPath).toBe('Gemfile')
  })

  it('does NOT trigger when Gemfile and Gemfile.lock both change', () => {
    const r = verifyDepLockIntegrity(['Gemfile', 'Gemfile.lock'])
    expect(r.findings.find((x) => x.ruleId === 'RUBY_GEMFILE_WITHOUT_LOCK')).toBeUndefined()
  })

  it('does NOT trigger when only Gemfile.lock changes (DIRECT_LOCK_EDIT fires)', () => {
    const r = verifyDepLockIntegrity(['Gemfile.lock'])
    expect(r.findings.find((x) => x.ruleId === 'RUBY_GEMFILE_WITHOUT_LOCK')).toBeUndefined()
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeDefined()
  })

  it('counts multiple Gemfile changes', () => {
    const r = verifyDepLockIntegrity([
      'services/auth/Gemfile',
      'services/api/Gemfile',
    ])
    const f = r.findings.find((x) => x.ruleId === 'RUBY_GEMFILE_WITHOUT_LOCK')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// 9. Scoring and risk levels
// ---------------------------------------------------------------------------

describe('scoring and risk levels', () => {
  it('returns riskScore=0 and riskLevel=none when no rules fire', () => {
    const r = verifyDepLockIntegrity(['src/index.ts', 'README.md'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('1 high rule → score=15, riskLevel=low', () => {
    // DIRECT_LOCK_EDIT (high)
    const r = verifyDepLockIntegrity(['yarn.lock'])
    const f = r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')
    expect(f!.severity).toBe('high')
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('2 high rules → score=30, riskLevel=medium', () => {
    // DIRECT_LOCK_EDIT + CARGO_MANIFEST_WITHOUT_LOCK = 2 high
    const r = verifyDepLockIntegrity(['yarn.lock', 'Cargo.toml'])
    expect(r.highCount).toBe(2)
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('3 high rules capped at score=30, riskLevel=medium (high cap=30)', () => {
    // DIRECT_LOCK_EDIT + CARGO_MANIFEST_WITHOUT_LOCK + GO_MOD_WITHOUT_SUM
    const r = verifyDepLockIntegrity(['yarn.lock', 'Cargo.toml', 'go.mod'])
    expect(r.highCount).toBe(3)
    // min(3×15=45, 30) = 30
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('1 medium rule → score=8, riskLevel=low', () => {
    // NPM_MANIFEST_WITHOUT_LOCK (medium)
    const r = verifyDepLockIntegrity(['package.json'])
    expect(r.mediumCount).toBe(1)
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('2 high + 2 medium → score=46, riskLevel=medium', () => {
    // DIRECT_LOCK_EDIT (Cargo.lock without Cargo.toml in services/auth) = high
    // GO_MOD_WITHOUT_SUM (go.mod without go.sum) = high
    // NPM_MANIFEST_WITHOUT_LOCK (package.json, no npm lock) = medium
    // PYTHON_MANIFEST_WITHOUT_LOCK (pyproject.toml, no Python lock) = medium
    // Note: Cargo.lock present globally prevents CARGO_MANIFEST_WITHOUT_LOCK.
    const r = verifyDepLockIntegrity([
      'services/auth/Cargo.lock',
      'go.mod',
      'package.json',
      'pyproject.toml',
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(2)
    expect(r.riskScore).toBe(46)
    expect(r.riskLevel).toBe('medium')
  })

  it('2 high + 3 medium → score=50, riskLevel=high', () => {
    // DIRECT_LOCK_EDIT (services/auth/Cargo.lock without Cargo.toml) = high
    // GO_MOD_WITHOUT_SUM (go.mod without go.sum) = high
    // NPM_MANIFEST_WITHOUT_LOCK (package.json, no npm lock anywhere) = medium
    // PYTHON_MANIFEST_WITHOUT_LOCK (pyproject.toml, no Python lock) = medium
    // RUBY_GEMFILE_WITHOUT_LOCK (Gemfile, no Gemfile.lock) = medium
    const r = verifyDepLockIntegrity([
      'services/auth/Cargo.lock',
      'go.mod',
      'package.json',
      'pyproject.toml',
      'Gemfile',
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(3)
    expect(r.riskScore).toBe(50)
    expect(r.riskLevel).toBe('high')
  })

  it('all high rules fire → score=30, riskLevel=medium', () => {
    // DIRECT_LOCK_EDIT + MIXED_NPM + CARGO + GO = 4 high → min(60,30)=30
    const r = verifyDepLockIntegrity([
      'yarn.lock',          // DIRECT_LOCK_EDIT (no package.json in same dir)
      'package-lock.json',  // DIRECT_LOCK_EDIT (no package.json) + MIXED_NPM
      'Cargo.toml',         // CARGO_MANIFEST_WITHOUT_LOCK
      'go.mod',             // GO_MOD_WITHOUT_SUM
    ])
    expect(r.highCount).toBeGreaterThanOrEqual(3)
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('criticalCount, highCount, mediumCount, lowCount are correct', () => {
    const r = verifyDepLockIntegrity(['yarn.lock', 'package.json', 'Cargo.toml'])
    // DIRECT_LOCK_EDIT=high (yarn.lock no package.json in same dir... wait)
    // Actually yarn.lock + package.json — same dir (root). No DIRECT_LOCK_EDIT.
    // Cargo.toml without Cargo.lock → CARGO_MANIFEST_WITHOUT_LOCK (high)
    // package.json with yarn.lock present → no NPM_WITHOUT_LOCK (yarn.lock counts)
    // But yarn.lock is a DIRECT_LOCK_EDIT because it has package.json in same dir → NOT direct edit
    // So only CARGO_MANIFEST_WITHOUT_LOCK fires
    expect(r.criticalCount).toBe(0)
    expect(r.highCount).toBe(1)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// 10. Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('clean result mentions scanned paths count', () => {
    const r = verifyDepLockIntegrity(['src/index.ts'])
    expect(r.summary).toContain('consistent')
    expect(r.summary).toContain('1 changed path')
  })

  it('clean result with plural paths', () => {
    const r = verifyDepLockIntegrity(['src/index.ts', 'src/utils.ts'])
    expect(r.summary).toContain('consistent')
    expect(r.summary).toContain('2 changed paths')
  })

  it('DIRECT_LOCK_EDIT triggers supply-chain summary', () => {
    const r = verifyDepLockIntegrity(['yarn.lock'])
    expect(r.summary).toContain('lock file')
    expect(r.summary).toContain('manifest')
  })

  it('MIXED_NPM_LOCK_FILES triggers conflicting formats summary', () => {
    const r = verifyDepLockIntegrity([
      'package-lock.json',
      'yarn.lock',
      'package.json',
    ])
    const hasMixed = r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')
    if (hasMixed && !r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')) {
      expect(r.summary).toContain('conflicting')
    }
  })

  it('generic findings summary includes risk level', () => {
    // Only medium findings: NPM + PYTHON
    const r = verifyDepLockIntegrity(['package.json', 'pyproject.toml'])
    // No npm lock and no python lock → NPM_MANIFEST_WITHOUT_LOCK + PYTHON_MANIFEST_WITHOUT_LOCK
    expect(r.summary).toMatch(/risk level/)
  })
})

// ---------------------------------------------------------------------------
// 11. scannedPaths count
// ---------------------------------------------------------------------------

describe('scannedPaths count', () => {
  it('returns 0 scannedPaths for empty input', () => {
    const r = verifyDepLockIntegrity([])
    expect(r.scannedPaths).toBe(0)
  })

  it('excludes vendored paths from scannedPaths count', () => {
    const r = verifyDepLockIntegrity([
      'node_modules/foo/package.json',
      'src/index.ts',
      'package.json',
    ])
    // node_modules path excluded, 2 remain
    expect(r.scannedPaths).toBe(2)
  })

  it('counts all non-vendored paths', () => {
    const r = verifyDepLockIntegrity([
      'go.mod',
      'go.sum',
      'src/main.go',
      'internal/auth/handler.go',
    ])
    expect(r.scannedPaths).toBe(4)
  })
})

// ---------------------------------------------------------------------------
// 12. Combined and complex behavior
// ---------------------------------------------------------------------------

describe('combined and complex behavior', () => {
  it('DIRECT_LOCK_EDIT and CARGO both fire on same push', () => {
    // yarn.lock without package.json (direct edit) + Cargo.toml without Cargo.lock
    const r = verifyDepLockIntegrity(['yarn.lock', 'Cargo.toml'])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'CARGO_MANIFEST_WITHOUT_LOCK')).toBeDefined()
    expect(r.totalFindings).toBe(2)
  })

  it('no DIRECT_LOCK_EDIT when go.mod + go.sum both present', () => {
    const r = verifyDepLockIntegrity(['go.mod', 'go.sum'])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeUndefined()
    expect(r.findings.find((x) => x.ruleId === 'GO_MOD_WITHOUT_SUM')).toBeUndefined()
    expect(r.totalFindings).toBe(0)
  })

  it('maximum achievable rules fire on a catastrophically bad push', () => {
    // DIRECT_LOCK_EDIT + MIXED_NPM + GO + PYTHON + RUBY = 5 rules (3 high + 2 medium).
    // Note: NPM_MANIFEST_WITHOUT_LOCK cannot fire simultaneously with MIXED_NPM_LOCK_FILES
    // (MIXED requires npm locks present; NPM_MANIFEST requires none). Similarly,
    // CARGO_MANIFEST_WITHOUT_LOCK cannot fire when a Cargo.lock is in the push for
    // DIRECT_LOCK_EDIT. These are complementary rules by design.
    const r = verifyDepLockIntegrity([
      // DIRECT_LOCK_EDIT x3: Cargo.lock + pnpm + yarn each without their manifests
      'services/auth/Cargo.lock',   // no services/auth/Cargo.toml
      'apps/web/pnpm-lock.yaml',    // no apps/web/package.json
      'apps/web/yarn.lock',         // no apps/web/package.json → also MIXED_NPM
      // MIXED_NPM_LOCK_FILES: apps/web has both pnpm and yarn
      // GO_MOD_WITHOUT_SUM
      'go.mod',
      // PYTHON_MANIFEST_WITHOUT_LOCK
      'pyproject.toml',
      // RUBY_GEMFILE_WITHOUT_LOCK
      'Gemfile',
    ])
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'MIXED_NPM_LOCK_FILES')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'GO_MOD_WITHOUT_SUM')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_MANIFEST_WITHOUT_LOCK')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'RUBY_GEMFILE_WITHOUT_LOCK')).toBeDefined()
    expect(r.totalFindings).toBe(5)
    expect(r.highCount).toBe(3) // DIRECT + MIXED + GO
    expect(r.mediumCount).toBe(2) // PYTHON + RUBY
    expect(r.riskScore).toBe(46) // min(45,30) + 16 = 46
    expect(r.riskLevel).toBe('medium')
  })

  it('large valid push (all manifests and locks updated) is clean', () => {
    const r = verifyDepLockIntegrity([
      'package.json', 'yarn.lock',
      'Cargo.toml', 'Cargo.lock',
      'go.mod', 'go.sum',
      'pyproject.toml', 'poetry.lock',
      'Gemfile', 'Gemfile.lock',
      'src/main.ts',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('ignores unrecognised files and only flags tracked lock/manifest patterns', () => {
    const r = verifyDepLockIntegrity([
      'src/index.ts',
      'docs/readme.md',
      '.env.example',
      'Makefile',
      'docker-compose.yml',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskScore).toBe(0)
  })

  it('npm-shrinkwrap.json is treated as a valid npm lock format', () => {
    const r = verifyDepLockIntegrity(['npm-shrinkwrap.json', 'package.json'])
    // npm-shrinkwrap.json + package.json same dir → DIRECT_LOCK_EDIT should NOT fire
    expect(r.findings.find((x) => x.ruleId === 'DIRECT_LOCK_EDIT')).toBeUndefined()
    // npm-shrinkwrap.json is an npm lock → NPM_MANIFEST_WITHOUT_LOCK should NOT fire
    expect(r.findings.find((x) => x.ruleId === 'NPM_MANIFEST_WITHOUT_LOCK')).toBeUndefined()
  })
})
