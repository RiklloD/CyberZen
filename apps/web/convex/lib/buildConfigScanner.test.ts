/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import { scanBuildConfigChanges } from './buildConfigScanner'

// ---------------------------------------------------------------------------
// 1. Vendor path filtering
// ---------------------------------------------------------------------------

describe('vendor path filtering', () => {
  it('returns clean result for empty paths array', () => {
    const r = scanBuildConfigChanges([])
    expect(r.totalFindings).toBe(0)
    expect(r.riskLevel).toBe('none')
    expect(r.riskScore).toBe(0)
  })

  it('excludes Makefile inside node_modules', () => {
    const r = scanBuildConfigChanges(['node_modules/some-pkg/Makefile'])
    expect(r.totalFindings).toBe(0)
  })

  it('excludes webpack.config.js inside dist/', () => {
    const r = scanBuildConfigChanges(['dist/webpack.config.js'])
    expect(r.totalFindings).toBe(0)
  })

  it('excludes build.sh inside vendor/', () => {
    const r = scanBuildConfigChanges(['vendor/scripts/build.sh'])
    expect(r.totalFindings).toBe(0)
  })

  it('excludes .babelrc inside .yarn/', () => {
    const r = scanBuildConfigChanges(['.yarn/cache/.babelrc'])
    expect(r.totalFindings).toBe(0)
  })

  it('skips blank and whitespace-only entries', () => {
    const r = scanBuildConfigChanges(['', '   ', '\t'])
    expect(r.totalFindings).toBe(0)
  })

  it('normalises Windows backslash paths', () => {
    const r = scanBuildConfigChanges(['node_modules\\pkg\\Makefile'])
    expect(r.totalFindings).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// 2. MAKEFILE_MODIFIED
// ---------------------------------------------------------------------------

describe('MAKEFILE_MODIFIED', () => {
  it('triggers on Makefile', () => {
    const r = scanBuildConfigChanges(['Makefile'])
    const f = r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchedPath).toBe('Makefile')
    expect(f!.matchCount).toBe(1)
  })

  it('triggers on GNUmakefile', () => {
    const r = scanBuildConfigChanges(['GNUmakefile'])
    expect(r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')).toBeDefined()
  })

  it('triggers on Taskfile.yml', () => {
    const r = scanBuildConfigChanges(['Taskfile.yml'])
    expect(r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')).toBeDefined()
  })

  it('triggers on Justfile', () => {
    const r = scanBuildConfigChanges(['Justfile'])
    expect(r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')).toBeDefined()
  })

  it('triggers on Makefile.am', () => {
    const r = scanBuildConfigChanges(['Makefile.am'])
    expect(r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')).toBeDefined()
  })

  it('does NOT trigger on Makefile inside vendor', () => {
    const r = scanBuildConfigChanges(['vendor/Makefile'])
    expect(r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')).toBeUndefined()
  })

  it('counts multiple Makefile-family files in matchCount', () => {
    const r = scanBuildConfigChanges(['Makefile', 'Taskfile.yml'])
    const f = r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
    expect(f!.matchedPath).toBe('Makefile')
  })
})

// ---------------------------------------------------------------------------
// 3. SHELL_BUILD_SCRIPT
// ---------------------------------------------------------------------------

describe('SHELL_BUILD_SCRIPT', () => {
  it('triggers on build.sh', () => {
    const r = scanBuildConfigChanges(['build.sh'])
    const f = r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchedPath).toBe('build.sh')
  })

  it('triggers on install.sh', () => {
    const r = scanBuildConfigChanges(['install.sh'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeDefined()
  })

  it('triggers on setup.sh', () => {
    const r = scanBuildConfigChanges(['setup.sh'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeDefined()
  })

  it('triggers on scripts/release.sh', () => {
    const r = scanBuildConfigChanges(['scripts/release.sh'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeDefined()
  })

  it('triggers on bootstrap.bash', () => {
    const r = scanBuildConfigChanges(['bootstrap.bash'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeDefined()
  })

  it('triggers on prebuild.sh', () => {
    const r = scanBuildConfigChanges(['prebuild.sh'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeDefined()
  })

  it('does NOT trigger on an unrelated script like test.sh', () => {
    const r = scanBuildConfigChanges(['test.sh'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeUndefined()
  })

  it('does NOT trigger on a non-shell file named build.py', () => {
    // .py extension not in SHELL_EXTENSIONS
    const r = scanBuildConfigChanges(['build.py'])
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeUndefined()
  })

  it('counts multiple shell build scripts in matchCount', () => {
    const r = scanBuildConfigChanges(['build.sh', 'install.sh', 'scripts/setup.sh'])
    const f = r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// 4. JS_BUNDLER_CONFIG
// ---------------------------------------------------------------------------

describe('JS_BUNDLER_CONFIG', () => {
  it('triggers on webpack.config.js', () => {
    const r = scanBuildConfigChanges(['webpack.config.js'])
    const f = r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
    expect(f!.matchedPath).toBe('webpack.config.js')
  })

  it('triggers on webpack.config.ts', () => {
    const r = scanBuildConfigChanges(['webpack.config.ts'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
  })

  it('triggers on rollup.config.mjs', () => {
    const r = scanBuildConfigChanges(['rollup.config.mjs'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
  })

  it('triggers on vite.config.ts', () => {
    const r = scanBuildConfigChanges(['vite.config.ts'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
  })

  it('triggers on esbuild.config.js', () => {
    const r = scanBuildConfigChanges(['esbuild.config.js'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
  })

  it('triggers on turbo.json', () => {
    const r = scanBuildConfigChanges(['turbo.json'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
  })

  it('triggers on nx.json', () => {
    const r = scanBuildConfigChanges(['nx.json'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
  })

  it('does NOT trigger on tsconfig.json (not a bundler)', () => {
    const r = scanBuildConfigChanges(['tsconfig.json'])
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeUndefined()
  })

  it('counts multiple bundler configs in matchCount', () => {
    const r = scanBuildConfigChanges([
      'webpack.config.js',
      'rollup.config.ts',
      'vite.config.ts',
    ])
    const f = r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// 5. CODE_TRANSFORM_CONFIG
// ---------------------------------------------------------------------------

describe('CODE_TRANSFORM_CONFIG', () => {
  it('triggers on .babelrc', () => {
    const r = scanBuildConfigChanges(['.babelrc'])
    const f = r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('high')
  })

  it('triggers on .babelrc.js', () => {
    const r = scanBuildConfigChanges(['.babelrc.js'])
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeDefined()
  })

  it('triggers on babel.config.json', () => {
    const r = scanBuildConfigChanges(['babel.config.json'])
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeDefined()
  })

  it('triggers on babel.config.ts', () => {
    const r = scanBuildConfigChanges(['babel.config.ts'])
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeDefined()
  })

  it('triggers on .swcrc', () => {
    const r = scanBuildConfigChanges(['.swcrc'])
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeDefined()
  })

  it('triggers on swc.config.js', () => {
    const r = scanBuildConfigChanges(['swc.config.js'])
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeDefined()
  })

  it('does NOT trigger on tsconfig.json', () => {
    const r = scanBuildConfigChanges(['tsconfig.json'])
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// 6. JAVA_BUILD_CONFIG
// ---------------------------------------------------------------------------

describe('JAVA_BUILD_CONFIG', () => {
  it('triggers on build.gradle', () => {
    const r = scanBuildConfigChanges(['build.gradle'])
    const f = r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.matchedPath).toBe('build.gradle')
  })

  it('triggers on build.gradle.kts', () => {
    const r = scanBuildConfigChanges(['build.gradle.kts'])
    expect(r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')).toBeDefined()
  })

  it('triggers on settings.gradle', () => {
    const r = scanBuildConfigChanges(['settings.gradle'])
    expect(r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')).toBeDefined()
  })

  it('triggers on pom.xml', () => {
    const r = scanBuildConfigChanges(['pom.xml'])
    expect(r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')).toBeDefined()
  })

  it('triggers on gradle.properties', () => {
    const r = scanBuildConfigChanges(['gradle.properties'])
    expect(r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')).toBeDefined()
  })

  it('counts multiple Gradle files in matchCount', () => {
    const r = scanBuildConfigChanges([
      'app/build.gradle',
      'app/settings.gradle',
      'app/gradle.properties',
    ])
    const f = r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// 7. PYTHON_SETUP_MODIFIED
// ---------------------------------------------------------------------------

describe('PYTHON_SETUP_MODIFIED', () => {
  it('triggers on setup.py', () => {
    const r = scanBuildConfigChanges(['setup.py'])
    const f = r.findings.find((x) => x.ruleId === 'PYTHON_SETUP_MODIFIED')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.matchedPath).toBe('setup.py')
  })

  it('triggers on setup.cfg', () => {
    const r = scanBuildConfigChanges(['setup.cfg'])
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_SETUP_MODIFIED')).toBeDefined()
  })

  it('triggers on MANIFEST.in', () => {
    const r = scanBuildConfigChanges(['MANIFEST.in'])
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_SETUP_MODIFIED')).toBeDefined()
  })

  it('does NOT trigger on requirements.txt (dependency manifest)', () => {
    const r = scanBuildConfigChanges(['requirements.txt'])
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_SETUP_MODIFIED')).toBeUndefined()
  })

  it('counts setup.py + setup.cfg together', () => {
    const r = scanBuildConfigChanges(['setup.py', 'setup.cfg', 'MANIFEST.in'])
    const f = r.findings.find((x) => x.ruleId === 'PYTHON_SETUP_MODIFIED')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// 8. RUBY_BUILD_CONFIG
// ---------------------------------------------------------------------------

describe('RUBY_BUILD_CONFIG', () => {
  it('triggers on my_gem.gemspec', () => {
    const r = scanBuildConfigChanges(['my_gem.gemspec'])
    const f = r.findings.find((x) => x.ruleId === 'RUBY_BUILD_CONFIG')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('medium')
    expect(f!.matchedPath).toBe('my_gem.gemspec')
  })

  it('triggers on deeply nested *.gemspec', () => {
    const r = scanBuildConfigChanges(['gems/auth/auth.gemspec'])
    expect(r.findings.find((x) => x.ruleId === 'RUBY_BUILD_CONFIG')).toBeDefined()
  })

  it('does NOT trigger on Gemfile or Gemfile.lock', () => {
    const r = scanBuildConfigChanges(['Gemfile', 'Gemfile.lock'])
    expect(r.findings.find((x) => x.ruleId === 'RUBY_BUILD_CONFIG')).toBeUndefined()
  })

  it('counts multiple gemspec files in matchCount', () => {
    const r = scanBuildConfigChanges(['auth.gemspec', 'core.gemspec'])
    const f = r.findings.find((x) => x.ruleId === 'RUBY_BUILD_CONFIG')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// 9. Scoring and risk levels
// ---------------------------------------------------------------------------

describe('scoring and risk levels', () => {
  it('returns riskScore=0 and riskLevel=none for unrelated files', () => {
    const r = scanBuildConfigChanges(['src/index.ts', 'README.md', 'package.json'])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('1 high rule → score=15, riskLevel=low', () => {
    const r = scanBuildConfigChanges(['Makefile'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('2 high rules → score=30, riskLevel=medium', () => {
    const r = scanBuildConfigChanges(['Makefile', 'webpack.config.js'])
    expect(r.highCount).toBe(2)
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('3 high rules capped at score=30 (high cap=30), riskLevel=medium', () => {
    const r = scanBuildConfigChanges(['Makefile', 'webpack.config.js', 'babel.config.json'])
    expect(r.highCount).toBe(3)
    // min(3×15=45, 30) = 30
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('1 medium rule → score=8, riskLevel=low', () => {
    const r = scanBuildConfigChanges(['pom.xml'])
    expect(r.mediumCount).toBe(1)
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('4 high + 2 medium → score=46, riskLevel=medium', () => {
    // MAKEFILE + SHELL + BUNDLER + TRANSFORM (4 high, capped at 30)
    // + JAVA + PYTHON (2 medium = 16)
    const r = scanBuildConfigChanges([
      'Makefile',
      'build.sh',
      'webpack.config.js',
      'babel.config.json',
      'pom.xml',
      'setup.py',
    ])
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(2)
    expect(r.riskScore).toBe(46)
    expect(r.riskLevel).toBe('medium')
  })

  it('4 high + 3 medium → score=50, riskLevel=high', () => {
    const r = scanBuildConfigChanges([
      'Makefile',
      'build.sh',
      'webpack.config.js',
      'babel.config.json',
      'pom.xml',
      'setup.py',
      'auth.gemspec',
    ])
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    // min(60, 30) + min(24, 20) = 30 + 20 = 50
    expect(r.riskScore).toBe(50)
    expect(r.riskLevel).toBe('high')
  })

  it('criticalCount, highCount, mediumCount, lowCount are correct', () => {
    const r = scanBuildConfigChanges(['Makefile', 'pom.xml'])
    expect(r.criticalCount).toBe(0)
    expect(r.highCount).toBe(1)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// 10. Summary text
// ---------------------------------------------------------------------------

describe('summary text', () => {
  it('clean result mentions no build toolchain changes', () => {
    const r = scanBuildConfigChanges(['src/index.ts'])
    expect(r.summary).toContain('no build toolchain')
  })

  it('high-severity result mentions mandatory review', () => {
    const r = scanBuildConfigChanges(['Makefile'])
    expect(r.summary).toContain('mandatory security review')
  })

  it('high result mentions file type label (Makefile)', () => {
    const r = scanBuildConfigChanges(['Makefile'])
    expect(r.summary).toContain('Makefile')
  })

  it('high result mentions bundler config type', () => {
    const r = scanBuildConfigChanges(['webpack.config.js'])
    expect(r.summary).toContain('bundler config')
  })

  it('generic medium-only result mentions risk level', () => {
    const r = scanBuildConfigChanges(['pom.xml', 'setup.py'])
    expect(r.summary).toMatch(/risk level/)
  })
})

// ---------------------------------------------------------------------------
// 11. Combined and complex behavior
// ---------------------------------------------------------------------------

describe('combined and complex behavior', () => {
  it('all 7 rules fire together', () => {
    const r = scanBuildConfigChanges([
      'Makefile',
      'build.sh',
      'webpack.config.js',
      'babel.config.json',
      'build.gradle',
      'setup.py',
      'my_gem.gemspec',
    ])
    expect(r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'CODE_TRANSFORM_CONFIG')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'JAVA_BUILD_CONFIG')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'PYTHON_SETUP_MODIFIED')).toBeDefined()
    expect(r.findings.find((x) => x.ruleId === 'RUBY_BUILD_CONFIG')).toBeDefined()
    expect(r.totalFindings).toBe(7)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.riskScore).toBe(50)
    expect(r.riskLevel).toBe('high')
  })

  it('findings are returned in rule definition order', () => {
    const r = scanBuildConfigChanges([
      'setup.py',
      'Makefile',
      'babel.config.json',
      'webpack.config.js',
    ])
    const ids = r.findings.map((f) => f.ruleId)
    const makefileIdx = ids.indexOf('MAKEFILE_MODIFIED')
    const bundlerIdx = ids.indexOf('JS_BUNDLER_CONFIG')
    const transformIdx = ids.indexOf('CODE_TRANSFORM_CONFIG')
    const pythonIdx = ids.indexOf('PYTHON_SETUP_MODIFIED')
    expect(makefileIdx).toBeLessThan(bundlerIdx)
    expect(bundlerIdx).toBeLessThan(transformIdx)
    expect(transformIdx).toBeLessThan(pythonIdx)
  })

  it('clean push with only app source files produces no findings', () => {
    const r = scanBuildConfigChanges([
      'src/auth/login.ts',
      'src/api/handler.ts',
      'tests/auth.test.ts',
      'docs/README.md',
      'package.json',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('multiple files from the same rule produce correct matchCount', () => {
    const r = scanBuildConfigChanges([
      'Makefile',
      'Taskfile.yml',
      'Justfile',
    ])
    const f = r.findings.find((x) => x.ruleId === 'MAKEFILE_MODIFIED')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
    expect(r.totalFindings).toBe(1) // one finding (same rule)
  })

  it('turbo.json and nx.json both trigger JS_BUNDLER_CONFIG once (dedup)', () => {
    const r = scanBuildConfigChanges(['turbo.json', 'nx.json', 'package.json'])
    const f = r.findings.find((x) => x.ruleId === 'JS_BUNDLER_CONFIG')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(2)
    expect(r.totalFindings).toBe(1)
  })

  it('preserves original raw path in matchedPath (not normalised)', () => {
    const rawPath = 'tools\\build.sh' // Windows-style path
    const r = scanBuildConfigChanges([rawPath])
    const f = r.findings.find((x) => x.ruleId === 'SHELL_BUILD_SCRIPT')
    expect(f).toBeDefined()
    expect(f!.matchedPath).toBe(rawPath)
  })
})
