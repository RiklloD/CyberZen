import { describe, expect, it } from 'vitest'
import { type GitIntegrityRuleId, scanGitIntegrity } from './gitIntegrityScanner'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ruleIds(files: string[]): GitIntegrityRuleId[] {
  return scanGitIntegrity({ changedFiles: files }).findings.map((f) => f.ruleId)
}

function hasRule(files: string[], rule: GitIntegrityRuleId): boolean {
  return ruleIds(files).includes(rule)
}

// ---------------------------------------------------------------------------
// SHADOW_SYSTEM_BINARY rule
// ---------------------------------------------------------------------------

describe('SHADOW_SYSTEM_BINARY rule', () => {
  it('fires on root-level "node" (no extension)', () => {
    expect(hasRule(['node'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('fires on root-level "python3"', () => {
    expect(hasRule(['python3'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('fires on root-level "git"', () => {
    expect(hasRule(['git'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('fires on "bin/bash"', () => {
    expect(hasRule(['bin/bash'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('fires on "usr/bin/python3"', () => {
    expect(hasRule(['usr/bin/python3'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('fires on "bin/curl"', () => {
    expect(hasRule(['bin/curl'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('does NOT fire on "node.js" (has extension)', () => {
    expect(hasRule(['node.js'], 'SHADOW_SYSTEM_BINARY')).toBe(false)
  })

  it('does NOT fire on "src/node" (nested, not root/bin)', () => {
    expect(hasRule(['src/node'], 'SHADOW_SYSTEM_BINARY')).toBe(false)
  })

  it('does NOT fire on "nodejs" (not a known binary name)', () => {
    expect(hasRule(['nodejs'], 'SHADOW_SYSTEM_BINARY')).toBe(false)
  })

  it('does NOT fire on "lib/bin/bash" (too deeply nested)', () => {
    expect(hasRule(['lib/bin/bash'], 'SHADOW_SYSTEM_BINARY')).toBe(false)
  })

  it('has severity=critical', () => {
    const result = scanGitIntegrity({ changedFiles: ['node'] })
    const f = result.findings.find((x) => x.ruleId === 'SHADOW_SYSTEM_BINARY')
    expect(f?.severity).toBe('critical')
  })

  it('is case-insensitive', () => {
    expect(hasRule(['NODE'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
    expect(hasRule(['Python3'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// SUBMODULE_MANIPULATION rule
// ---------------------------------------------------------------------------

describe('SUBMODULE_MANIPULATION rule', () => {
  it('fires on ".gitmodules" at root', () => {
    expect(hasRule(['.gitmodules'], 'SUBMODULE_MANIPULATION')).toBe(true)
  })

  it('fires on "packages/app/.gitmodules" (nested)', () => {
    expect(hasRule(['packages/app/.gitmodules'], 'SUBMODULE_MANIPULATION')).toBe(true)
  })

  it('does NOT fire on ".gitattributes"', () => {
    expect(hasRule(['.gitattributes'], 'SUBMODULE_MANIPULATION')).toBe(false)
  })

  it('does NOT fire on ".gitignore"', () => {
    expect(hasRule(['.gitignore'], 'SUBMODULE_MANIPULATION')).toBe(false)
  })

  it('has severity=high', () => {
    const result = scanGitIntegrity({ changedFiles: ['.gitmodules'] })
    const f = result.findings.find((x) => x.ruleId === 'SUBMODULE_MANIPULATION')
    expect(f?.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// EXECUTABLE_BINARY_COMMITTED rule
// ---------------------------------------------------------------------------

describe('EXECUTABLE_BINARY_COMMITTED rule', () => {
  it('fires on "malware.exe"', () => {
    expect(hasRule(['malware.exe'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })

  it('fires on "helper.dll"', () => {
    expect(hasRule(['helper.dll'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })

  it('fires on "lib.so"', () => {
    expect(hasRule(['lib.so'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })

  it('fires on "extension.dylib"', () => {
    expect(hasRule(['extension.dylib'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })

  it('fires on "payload.elf"', () => {
    expect(hasRule(['payload.elf'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })

  it('fires on "tool.bin"', () => {
    expect(hasRule(['tool.bin'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })

  it('does NOT fire on "config.json"', () => {
    expect(hasRule(['config.json'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(false)
  })

  it('does NOT fire on "styles.css"', () => {
    expect(hasRule(['styles.css'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(false)
  })

  it('does NOT fire on "README.md"', () => {
    expect(hasRule(['README.md'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(false)
  })

  it('has severity=high', () => {
    const result = scanGitIntegrity({ changedFiles: ['tool.exe'] })
    const f = result.findings.find((x) => x.ruleId === 'EXECUTABLE_BINARY_COMMITTED')
    expect(f?.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// GIT_HOOK_TAMPERING rule
// ---------------------------------------------------------------------------

describe('GIT_HOOK_TAMPERING rule', () => {
  it('fires on ".husky/pre-commit"', () => {
    expect(hasRule(['.husky/pre-commit'], 'GIT_HOOK_TAMPERING')).toBe(true)
  })

  it('fires on ".husky/pre-push"', () => {
    expect(hasRule(['.husky/pre-push'], 'GIT_HOOK_TAMPERING')).toBe(true)
  })

  it('fires on root-level "pre-commit"', () => {
    expect(hasRule(['pre-commit'], 'GIT_HOOK_TAMPERING')).toBe(true)
  })

  it('fires on root-level "pre-push"', () => {
    expect(hasRule(['pre-push'], 'GIT_HOOK_TAMPERING')).toBe(true)
  })

  it('fires on ".git-hooks/update"', () => {
    expect(hasRule(['.git-hooks/update'], 'GIT_HOOK_TAMPERING')).toBe(true)
  })

  it('fires on "git-hooks/post-receive"', () => {
    expect(hasRule(['git-hooks/post-receive'], 'GIT_HOOK_TAMPERING')).toBe(true)
  })

  it('does NOT fire on ".github/pre-commit-config.yaml" (pre-commit framework config)', () => {
    expect(hasRule(['.github/pre-commit-config.yaml'], 'GIT_HOOK_TAMPERING')).toBe(false)
  })

  it('does NOT fire on "docs/pre-commit.md"', () => {
    expect(hasRule(['docs/pre-commit.md'], 'GIT_HOOK_TAMPERING')).toBe(false)
  })

  it('has severity=high', () => {
    const result = scanGitIntegrity({ changedFiles: ['.husky/pre-commit'] })
    const f = result.findings.find((x) => x.ruleId === 'GIT_HOOK_TAMPERING')
    expect(f?.severity).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// DEPENDENCY_REGISTRY_OVERRIDE rule
// ---------------------------------------------------------------------------

describe('DEPENDENCY_REGISTRY_OVERRIDE rule', () => {
  it('fires on ".npmrc"', () => {
    expect(hasRule(['.npmrc'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(true)
  })

  it('fires on ".yarnrc.yml"', () => {
    expect(hasRule(['.yarnrc.yml'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(true)
  })

  it('fires on ".pypirc"', () => {
    expect(hasRule(['.pypirc'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(true)
  })

  it('fires on "pip.conf"', () => {
    expect(hasRule(['pip.conf'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(true)
  })

  it('fires on ".gemrc"', () => {
    expect(hasRule(['.gemrc'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(true)
  })

  it('fires on "bunfig.toml"', () => {
    expect(hasRule(['bunfig.toml'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(true)
  })

  it('does NOT fire on "package.json"', () => {
    expect(hasRule(['package.json'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(false)
  })

  it('does NOT fire on ".env"', () => {
    expect(hasRule(['.env'], 'DEPENDENCY_REGISTRY_OVERRIDE')).toBe(false)
  })

  it('has severity=medium', () => {
    const result = scanGitIntegrity({ changedFiles: ['.npmrc'] })
    const f = result.findings.find((x) => x.ruleId === 'DEPENDENCY_REGISTRY_OVERRIDE')
    expect(f?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// GITCONFIG_MODIFIED rule
// ---------------------------------------------------------------------------

describe('GITCONFIG_MODIFIED rule', () => {
  it('fires on ".gitconfig" at root', () => {
    expect(hasRule(['.gitconfig'], 'GITCONFIG_MODIFIED')).toBe(true)
  })

  it('fires on "user.gitconfig" (ends with .gitconfig)', () => {
    expect(hasRule(['user.gitconfig'], 'GITCONFIG_MODIFIED')).toBe(true)
  })

  it('does NOT fire on ".gitignore"', () => {
    expect(hasRule(['.gitignore'], 'GITCONFIG_MODIFIED')).toBe(false)
  })

  it('does NOT fire on ".gitattributes"', () => {
    expect(hasRule(['.gitattributes'], 'GITCONFIG_MODIFIED')).toBe(false)
  })

  it('does NOT fire on ".gitmodules"', () => {
    // .gitmodules fires SUBMODULE_MANIPULATION, not GITCONFIG_MODIFIED
    expect(hasRule(['.gitmodules'], 'GITCONFIG_MODIFIED')).toBe(false)
  })

  it('has severity=medium', () => {
    const result = scanGitIntegrity({ changedFiles: ['.gitconfig'] })
    const f = result.findings.find((x) => x.ruleId === 'GITCONFIG_MODIFIED')
    expect(f?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// LARGE_BLIND_PUSH rule
// ---------------------------------------------------------------------------

describe('LARGE_BLIND_PUSH rule', () => {
  it('fires when changedFiles.length > 200', () => {
    const files = Array.from({ length: 201 }, (_, i) => `src/file${i}.ts`)
    expect(hasRule(files, 'LARGE_BLIND_PUSH')).toBe(true)
  })

  it('fires when totalFileCount > 200 even if changedFiles is smaller', () => {
    const result = scanGitIntegrity({
      changedFiles: ['src/file1.ts', 'src/file2.ts'],
      totalFileCount: 350,
    })
    expect(result.findings.some((f) => f.ruleId === 'LARGE_BLIND_PUSH')).toBe(true)
  })

  it('does NOT fire when changedFiles.length === 200 (at threshold)', () => {
    const files = Array.from({ length: 200 }, (_, i) => `src/file${i}.ts`)
    expect(hasRule(files, 'LARGE_BLIND_PUSH')).toBe(false)
  })

  it('does NOT fire for small pushes', () => {
    expect(hasRule(['src/app.ts', 'src/utils.ts'], 'LARGE_BLIND_PUSH')).toBe(false)
  })

  it('fires at most once regardless of file count', () => {
    const files = Array.from({ length: 500 }, (_, i) => `src/file${i}.ts`)
    const result = scanGitIntegrity({ changedFiles: files })
    const largeFindings = result.findings.filter((f) => f.ruleId === 'LARGE_BLIND_PUSH')
    expect(largeFindings.length).toBe(1)
  })

  it('has severity=medium', () => {
    const files = Array.from({ length: 201 }, (_, i) => `src/file${i}.ts`)
    const result = scanGitIntegrity({ changedFiles: files })
    const f = result.findings.find((x) => x.ruleId === 'LARGE_BLIND_PUSH')
    expect(f?.severity).toBe('medium')
  })

  it('includes the file count in matchedPath', () => {
    const files = Array.from({ length: 250 }, (_, i) => `src/file${i}.ts`)
    const result = scanGitIntegrity({ changedFiles: files })
    const f = result.findings.find((x) => x.ruleId === 'LARGE_BLIND_PUSH')
    expect(f?.matchedPath).toMatch(/250/)
  })
})

// ---------------------------------------------------------------------------
// ARCHIVE_COMMITTED rule
// ---------------------------------------------------------------------------

describe('ARCHIVE_COMMITTED rule', () => {
  it('fires on "backup.zip"', () => {
    expect(hasRule(['backup.zip'], 'ARCHIVE_COMMITTED')).toBe(true)
  })

  it('fires on "data.tar.gz" (compound extension)', () => {
    expect(hasRule(['data.tar.gz'], 'ARCHIVE_COMMITTED')).toBe(true)
  })

  it('fires on "app.jar"', () => {
    expect(hasRule(['app.jar'], 'ARCHIVE_COMMITTED')).toBe(true)
  })

  it('fires on "package.whl"', () => {
    expect(hasRule(['package.whl'], 'ARCHIVE_COMMITTED')).toBe(true)
  })

  it('fires on "release.tar.bz2" (compound extension)', () => {
    expect(hasRule(['release.tar.bz2'], 'ARCHIVE_COMMITTED')).toBe(true)
  })

  it('fires on "module.gem"', () => {
    expect(hasRule(['module.gem'], 'ARCHIVE_COMMITTED')).toBe(true)
  })

  it('does NOT fire on "styles.css"', () => {
    expect(hasRule(['styles.css'], 'ARCHIVE_COMMITTED')).toBe(false)
  })

  it('does NOT fire on "README.md"', () => {
    expect(hasRule(['README.md'], 'ARCHIVE_COMMITTED')).toBe(false)
  })

  it('does NOT fire on "schema.ts"', () => {
    expect(hasRule(['schema.ts'], 'ARCHIVE_COMMITTED')).toBe(false)
  })

  it('has severity=medium', () => {
    const result = scanGitIntegrity({ changedFiles: ['backup.zip'] })
    const f = result.findings.find((x) => x.ruleId === 'ARCHIVE_COMMITTED')
    expect(f?.severity).toBe('medium')
  })
})

// ---------------------------------------------------------------------------
// Clean inputs
// ---------------------------------------------------------------------------

describe('clean changed files', () => {
  const clean = [
    'src/app.ts',
    'src/components/Button.tsx',
    'package.json',
    'README.md',
    'convex/schema.ts',
  ]

  it('returns riskScore=0', () => {
    expect(scanGitIntegrity({ changedFiles: clean }).riskScore).toBe(0)
  })

  it('returns riskLevel=none', () => {
    expect(scanGitIntegrity({ changedFiles: clean }).riskLevel).toBe('none')
  })

  it('returns 0 findings', () => {
    expect(scanGitIntegrity({ changedFiles: clean }).totalFindings).toBe(0)
  })

  it('empty array returns riskLevel=none', () => {
    expect(scanGitIntegrity({ changedFiles: [] }).riskLevel).toBe('none')
  })

  it('whitespace-only paths are skipped', () => {
    expect(scanGitIntegrity({ changedFiles: ['   ', '', '\t'] }).totalFindings).toBe(0)
  })

  it('clean summary mentions "no repository integrity signals"', () => {
    const result = scanGitIntegrity({ changedFiles: clean })
    expect(result.summary).toMatch(/no repository integrity signals/i)
  })
})

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('1 critical finding → riskScore=30, riskLevel=medium', () => {
    // shadow binary: critical +30 → score=30 → medium (25 ≤ 30 < 50)
    const result = scanGitIntegrity({ changedFiles: ['node'] })
    expect(result.riskScore).toBe(30)
    expect(result.riskLevel).toBe('medium')
    expect(result.criticalCount).toBe(1)
  })

  it('2 critical findings → riskScore=60, riskLevel=high', () => {
    const result = scanGitIntegrity({ changedFiles: ['node', 'python3'] })
    expect(result.riskScore).toBe(60)
    expect(result.riskLevel).toBe('high')
    expect(result.criticalCount).toBe(2)
  })

  it('3 critical findings → riskScore=75 (cap), riskLevel=critical', () => {
    const result = scanGitIntegrity({ changedFiles: ['node', 'python3', 'bash'] })
    expect(result.riskScore).toBe(75)
    expect(result.riskLevel).toBe('critical')
  })

  it('1 high finding → riskScore=15, riskLevel=low', () => {
    const result = scanGitIntegrity({ changedFiles: ['.gitmodules'] })
    expect(result.riskScore).toBe(15)
    expect(result.riskLevel).toBe('low')
  })

  it('2 high findings → riskScore=30, riskLevel=medium', () => {
    const result = scanGitIntegrity({ changedFiles: ['.gitmodules', 'tool.exe'] })
    expect(result.riskScore).toBe(30)
    expect(result.riskLevel).toBe('medium')
  })

  it('high cap: 3 high findings → riskScore=30 (capped), riskLevel=medium', () => {
    const result = scanGitIntegrity({
      changedFiles: ['.gitmodules', 'tool.exe', 'pre-commit'],
    })
    // 3×15=45, cap=30; 0 medium
    expect(result.highCount).toBe(3)
    expect(result.riskScore).toBe(30)
  })

  it('medium cap: 4 medium findings → riskScore=20 (capped)', () => {
    const result = scanGitIntegrity({
      changedFiles: ['.npmrc', '.pypirc', '.gitconfig', 'backup.zip'],
    })
    // 4×8=32, cap=20
    expect(result.mediumCount).toBe(4)
    expect(result.riskScore).toBe(20)
  })

  it('mixed findings score correctly', () => {
    // 1 critical (node) + 1 high (.gitmodules) + 1 medium (.npmrc)
    const result = scanGitIntegrity({ changedFiles: ['node', '.gitmodules', '.npmrc'] })
    // critical: 30; high: 15; medium: 8 → total=53
    expect(result.riskScore).toBe(53)
    expect(result.riskLevel).toBe('high')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('handles backslash paths for shadow binary', () => {
    expect(hasRule(['bin\\bash'], 'SHADOW_SYSTEM_BINARY')).toBe(true)
  })

  it('handles backslash paths for submodule', () => {
    expect(hasRule(['packages\\app\\.gitmodules'], 'SUBMODULE_MANIPULATION')).toBe(true)
  })

  it('handles backslash paths for binary', () => {
    expect(hasRule(['dist\\app.exe'], 'EXECUTABLE_BINARY_COMMITTED')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Summary text
// ---------------------------------------------------------------------------

describe('summary', () => {
  it('critical summary mentions "supply-chain attack"', () => {
    const result = scanGitIntegrity({ changedFiles: ['node'] })
    expect(result.summary).toMatch(/supply-chain attack/i)
  })

  it('high summary mentions "high-risk"', () => {
    const result = scanGitIntegrity({ changedFiles: ['.gitmodules'] })
    expect(result.summary).toMatch(/high-risk/i)
  })

  it('medium summary mentions findings count', () => {
    const result = scanGitIntegrity({ changedFiles: ['.npmrc'] })
    expect(result.summary).toMatch(/1 repository integrity signal/)
  })
})
