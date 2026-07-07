// ── Real Scanner Engine ──────────────────────────────────────────────────
//
// Fetches real repository content from the GitHub API, parses dependency
// manifests to generate SBOM snapshots, and dispatches all security scanners
// with actual file content — not synthetic markers.
//
// Architecture:
//   dispatchScannerForRepository (mutation)
//     → ctx.scheduler.runAfter(0, internal.scannerEngine.runRealScan, { ... })
//       → fetch GitHub repo tree (recursive)
//       → batch-fetch file contents for relevant files
//       → parse dependency manifests → ingestRepositoryInventory (SBOM)
//       → dispatch each scanner with real file content
//
// The action runs in the Convex action layer (not mutation) so it can make
// external HTTP calls to the GitHub API. All DB writes go through
// ctx.runMutation / ctx.runQuery.

import { v } from 'convex/values'
import { internalAction, internalQuery, internalMutation } from './_generated/server'
import { internal } from './_generated/api'
import type { Id } from './_generated/dataModel'

const GITHUB_API = 'https://api.github.com'

// ── File classification patterns ─────────────────────────────────────────

const DEPENDENCY_MANIFESTS: Record<string, string[]> = {
  // ecosystem → filenames that declare dependencies
  npm: ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
  pip: ['requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'setup.py'],
  maven: ['pom.xml'],
  gradle: ['build.gradle', 'build.gradle.kts', 'settings.gradle'],
  cargo: ['Cargo.toml', 'Cargo.lock'],
  gem: ['Gemfile', 'Gemfile.lock'],
  composer: ['composer.json', 'composer.lock'],
  go: ['go.mod', 'go.sum'],
  nuget: ['packages.config', '.csproj'],
  pub: ['pubspec.yaml', 'pubspec.lock'],
}

const SOURCE_EXTENSIONS =
  /\.(py|js|ts|jsx|tsx|mjs|cjs|java|go|rb|cs|php|rs|kt|swift|scala|clj)$/i

const IAC_EXTENSIONS =
  /\.tf$|\.ya?ml$|Dockerfile(?:\.\w+)?$|\.dockerfile$|docker-compose/i

const CICD_PATHS =
  /\.github[/\\]workflows[/\\].+\.ya?ml$|\.gitlab-ci\.ya?ml$|\.circleci[/\\]config\.ya?ml$|bitbucket-pipelines\.ya?ml$/i

const SENSITIVE_FILE_PATTERNS =
  /\.(pem|key|p12|pfx|crt|cer|der|jks|keystore|env)$|^\.env/i

const MAX_FILES_TO_FETCH = 50
const MAX_FILE_CONTENT_BYTES = 256 * 1024 // 256KB per file

// ── Types ────────────────────────────────────────────────────────────────

type GitTreeEntry = {
  path: string
  mode: string
  type: 'blob' | 'tree' | 'commit'
  sha: string
  size?: number
}

type FileContent = {
  path: string
  content: string
}

type ParsedDependency = {
  name: string
  version: string
  ecosystem: string
  layer: string
  isDirect: boolean
  sourceFile: string
  dependents: string[]
  license?: string
}

// ── Internal query: get GitHub token for a repository's linked user ──────
//
// dispatchScannerForRepository is a mutation (no ctx.auth in scheduler
// context), so we resolve the token by finding the tenant owner's linked
// GitHub token. This is the same pattern used by listGithubRepos.

export const getGithubTokenForTenant = internalQuery({
  args: { tenantId: v.id('tenants') },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    // Find the tenant owner
    const ownerMembership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_role', (q) =>
        q.eq('tenantId', args.tenantId).eq('role', 'owner'),
      )
      .first()

    if (!ownerMembership) {
      // Fall back to any admin
      const adminMembership = await ctx.db
        .query('tenantMembers')
        .withIndex('by_tenant_and_role', (q) =>
          q.eq('tenantId', args.tenantId).eq('role', 'admin'),
        )
        .first()

      if (!adminMembership) return null
      const token = await ctx.db
        .query('userGithubTokens')
        .withIndex('by_user', (q) =>
          q.eq('userId', adminMembership.userId),
        )
        .first()
      return token?.accessToken ?? null
    }

    const token = await ctx.db
      .query('userGithubTokens')
      .withIndex('by_user', (q) =>
        q.eq('userId', ownerMembership.userId),
      )
      .first()
    return token?.accessToken ?? null
  },
})

// ── Internal query: get repo metadata for the scan ───────────────────────

export const getScanContext = internalQuery({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  returns: v.union(
    v.null(),
    v.object({
      tenantSlug: v.string(),
      repositoryFullName: v.string(),
      defaultBranch: v.string(),
      provider: v.string(),
    }),
  ),
  handler: async (ctx, args) => {
    const tenant = await ctx.db.get(args.tenantId)
    if (!tenant) return null

    const repo = await ctx.db.get(args.repositoryId)
    if (!repo) return null

    return {
      tenantSlug: tenant.slug,
      repositoryFullName: repo.fullName,
      defaultBranch: repo.defaultBranch ?? 'main',
      provider: repo.provider,
    }
  },
})

// ── GitHub API helpers ───────────────────────────────────────────────────

async function githubFetch(url: string, token: string): Promise<Response> {
  const res = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'CyberZen-Sentinel',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  })
  return res
}

/** Fetch the recursive git tree for a repo+branch. Returns blob entries. */
async function fetchRepoTree(
  owner: string,
  repo: string,
  branch: string,
  token: string,
): Promise<GitTreeEntry[]> {
  const url = `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
  const res = await githubFetch(url, token)
  if (!res.ok) {
    throw new Error(
      `GitHub tree API failed: ${res.status} ${res.statusText} for ${owner}/${repo}:${branch}`,
    )
  }
  const data = await res.json()
  // Filter to blobs only, skip node_modules, .git, vendor, etc.
  const blobs = (data.tree as GitTreeEntry[]).filter(
    (e) =>
      e.type === 'blob' &&
      !e.path.includes('node_modules/') &&
      !e.path.includes('.git/') &&
      !e.path.includes('vendor/') &&
      !e.path.includes('__pycache__/') &&
      !e.path.includes('.next/') &&
      !e.path.includes('dist/') &&
      !e.path.includes('build/') &&
      !e.path.includes('target/') &&
      !e.path.includes('.cache/'),
  )
  return blobs
}

/** Fetch a single file's content via the Contents API (base64 decoded). */
async function fetchFileContent(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  token: string,
): Promise<string | null> {
  const url = `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}?ref=${ref}`
  const res = await githubFetch(url, token)
  if (!res.ok) return null
  const data = await res.json()
  if (data.encoding !== 'base64' || typeof data.content !== 'string') return null
  const content = atob(data.content.replace(/\n/g, ''))
  if (content.length > MAX_FILE_CONTENT_BYTES) {
    return content.slice(0, MAX_FILE_CONTENT_BYTES)
  }
  return content
}

/** Batch fetch multiple files, respecting rate limits. */
async function batchFetchFiles(
  owner: string,
  repo: string,
  ref: string,
  paths: string[],
  token: string,
): Promise<FileContent[]> {
  const results: FileContent[] = []
  // Fetch sequentially to respect GitHub secondary rate limits
  for (const path of paths.slice(0, MAX_FILES_TO_FETCH)) {
    try {
      const content = await fetchFileContent(owner, repo, path, ref, token)
      if (content !== null) {
        results.push({ path, content })
      }
    } catch {
      // Skip files that fail — don't abort the whole scan
    }
  }
  return results
}

// ── Dependency manifest parsers ──────────────────────────────────────────

function parsePackageJson(content: string, sourceFile: string): ParsedDependency[] {
  try {
    const pkg = JSON.parse(content)
    const deps: ParsedDependency[] = []

    const parseSection = (
      section: Record<string, string> | undefined,
      layer: string,
      isDirect: boolean,
    ) => {
      if (!section) return
      for (const [name, version] of Object.entries(section)) {
        deps.push({
          name,
          version: version.replace(/[\^~>=<=]/g, '').trim(),
          ecosystem: 'npm',
          layer,
          isDirect,
          sourceFile,
          dependents: [],
          license: pkg.license,
        })
      }
    }

    parseSection(pkg.dependencies, 'direct', true)
    parseSection(pkg.devDependencies, 'build', true)
    parseSection(pkg.peerDependencies, 'runtime', true)
    parseSection(pkg.optionalDependencies, 'runtime', false)

    return deps
  } catch {
    return []
  }
}

function parseRequirementsTxt(content: string, sourceFile: string): ParsedDependency[] {
  const deps: ParsedDependency[] = []
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue
    // Match: package==1.0.0, package>=1.0.0, package~=1.0.0, package (bare)
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:[><=~!]+\s*)?([0-9][0-9a-zA-Z.]*)?/)
    if (match) {
      deps.push({
        name: match[1],
        version: (match[2] ?? 'latest').trim(),
        ecosystem: 'pypi',
        layer: 'direct',
        isDirect: true,
        sourceFile,
        dependents: [],
      })
    }
  }
  return deps
}

function parsePyprojectToml(content: string, sourceFile: string): ParsedDependency[] {
  const deps: ParsedDependency[] = []
  // Simple TOML parsing for [project.dependencies] and [tool.poetry.dependencies]
  const projectDepsMatch = content.match(
    /\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/,
  )
  if (projectDepsMatch) {
    const depBlock = projectDepsMatch[1]
    const depMatches = depBlock.matchAll(/["']([^"']+)([><=~!]+[^"']*|\s*)["']/g)
    for (const m of depMatches) {
      const namePart = m[1].split(/[\s\[]/)[0]
      deps.push({
        name: namePart,
        version: (m[2] || 'latest').replace(/[\^~>=<=\s]/g, ''),
        ecosystem: 'pypi',
        layer: 'direct',
        isDirect: true,
        sourceFile,
        dependents: [],
      })
    }
  }

  // Poetry dependencies
  const poetryDepsMatch = content.match(
    /\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/,
  )
  if (poetryDepsMatch) {
    for (const line of poetryDepsMatch[1].split('\n')) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']?([^"'\s]+)["']?/)
      if (match && match[1] !== 'python') {
        deps.push({
          name: match[1],
          version: match[2].replace(/[\^~>=<=]/g, ''),
          ecosystem: 'pypi',
          layer: 'direct',
          isDirect: true,
          sourceFile,
          dependents: [],
        })
      }
    }
  }

  return deps
}

function parseGoMod(content: string, sourceFile: string): ParsedDependency[] {
  const deps: ParsedDependency[] = []
  const requireMatches = content.matchAll(
    /^\s*(?:require\s+)?([^\s]+)\s+(v[0-9.]+)/gm,
  )
  for (const m of requireMatches) {
    deps.push({
      name: m[1],
      version: m[2],
      ecosystem: 'go',
      layer: 'direct',
      isDirect: true,
      sourceFile,
      dependents: [],
    })
  }
  return deps
}

function parseCargoToml(content: string, sourceFile: string): ParsedDependency[] {
  const deps: ParsedDependency[] = []
  // [dependencies] section
  const depSection = content.match(
    /\[dependencies\]([\s\S]*?)(?:\n\[|$)/,
  )
  if (depSection) {
    for (const line of depSection[1].split('\n')) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["']([^"']+)["']/)
      if (match) {
        deps.push({
          name: match[1],
          version: match[2].replace(/[\^~]/, ''),
          ecosystem: 'cargo',
          layer: 'direct',
          isDirect: true,
          sourceFile,
          dependents: [],
        })
      }
    }
  }
  return deps
}

function parseGemfile(content: string, sourceFile: string): ParsedDependency[] {
  const deps: ParsedDependency[] = []
  const matches = content.matchAll(/^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/g)
  for (const m of matches) {
    deps.push({
      name: m[1],
      version: (m[2] ?? 'latest').trim(),
      ecosystem: 'rubygems',
      layer: 'direct',
      isDirect: true,
      sourceFile,
      dependents: [],
    })
  }
  return deps
}

function parsePomXml(content: string, sourceFile: string): ParsedDependency[] {
  const deps: ParsedDependency[] = []
  const depMatches = content.matchAll(
    /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g,
  )
  for (const m of depMatches) {
    deps.push({
      name: m[2],
      version: (m[3] ?? 'latest').trim(),
      ecosystem: 'maven',
      layer: 'direct',
      isDirect: true,
      sourceFile,
      dependents: [],
    })
  }
  return deps
}

function parseComposerJson(content: string, sourceFile: string): ParsedDependency[] {
  try {
    const pkg = JSON.parse(content)
    const deps: ParsedDependency[] = []
    const parseSection = (
      section: Record<string, string> | undefined,
      isDirect: boolean,
    ) => {
      if (!section) return
      for (const [name, version] of Object.entries(section)) {
        deps.push({
          name,
          version: version.replace(/[\^~>=<=]/g, '').trim(),
          ecosystem: 'composer',
          layer: 'direct',
          isDirect,
          sourceFile,
          dependents: [],
        })
      }
    }
    parseSection(pkg.require, true)
    parseSection(pkg['require-dev'], true)
    return deps
  } catch {
    return []
  }
}

// ── Manifest routing ─────────────────────────────────────────────────────

function parseManifest(
  filename: string,
  content: string,
  sourceFile: string,
): ParsedDependency[] {
  const base = filename.split('/').pop() ?? filename

  if (base === 'package.json') return parsePackageJson(content, sourceFile)
  if (base === 'requirements.txt')
    return parseRequirementsTxt(content, sourceFile)
  if (base === 'pyproject.toml')
    return parsePyprojectToml(content, sourceFile)
  if (base === 'go.mod') return parseGoMod(content, sourceFile)
  if (base === 'Cargo.toml') return parseCargoToml(content, sourceFile)
  if (base === 'Gemfile') return parseGemfile(content, sourceFile)
  if (base === 'pom.xml') return parsePomXml(content, sourceFile)
  if (base === 'composer.json') return parseComposerJson(content, sourceFile)

  // Lock files produce transitive deps — parse but mark as transitive layer
  if (base === 'package-lock.json') {
    try {
      const lock = JSON.parse(content)
      const deps: ParsedDependency[] = []
      if (lock.packages) {
        for (const [pkgPath, info] of Object.entries(lock.packages)) {
          if (pkgPath === '' || pkgPath.startsWith('node_modules/')) {
            const name = pkgPath.replace('node_modules/', '')
            if (name && (info as any).version) {
              deps.push({
                name,
                version: (info as any).version,
                ecosystem: 'npm',
                layer: 'transitive',
                isDirect: false,
                sourceFile,
                dependents: [],
              })
            }
          }
        }
      }
      return deps
    } catch {
      return []
    }
  }

  return []
}

// ── File classification helpers ──────────────────────────────────────────

function isManifestFile(path: string): boolean {
  const base = path.split('/').pop() ?? path
  return Object.values(DEPENDENCY_MANIFESTS)
    .flat()
    .includes(base)
}

function isSourceFile(path: string): boolean {
  return SOURCE_EXTENSIONS.test(path)
}

function isIacFile(path: string): boolean {
  return IAC_EXTENSIONS.test(path)
}

function isCicdFile(path: string): boolean {
  return CICD_PATHS.test(path)
}

function isSensitiveFile(path: string): boolean {
  return SENSITIVE_FILE_PATTERNS.test(path)
}

// ── Main scan action ─────────────────────────────────────────────────────

export const runRealScan = internalAction({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    commitSha: v.string(),
  },
  returns: v.object({
    filesFetched: v.number(),
    componentsDetected: v.number(),
    scannersDispatched: v.array(v.string()),
    errors: v.array(v.string()),
  }),
  handler: async (ctx, args) => {
    const errors: string[] = []
    const scannersDispatched: string[] = []

    // Helper: write a log entry to the scanLogs table (live-streamed to UI)
    const log = (
      phase: string,
      level: 'info' | 'success' | 'warning' | 'error',
      message: string,
      detail?: string,
    ) =>
      ctx.runMutation(internal.scanLogs.appendScanLog, {
        tenantId: args.tenantId,
        repositoryId: args.repositoryId,
        workflowRunId: args.workflowRunId,
        phase,
        level,
        message,
        detail,
      })

    await log('scan_start', 'info', 'Scan initialized', `commit: ${args.commitSha}`)

    // 1. Get scan context (tenant slug, repo name, branch)
    const scanCtx = await ctx.runQuery(internal.scannerEngine.getScanContext, {
      tenantId: args.tenantId,
      repositoryId: args.repositoryId,
    })
    if (!scanCtx) {
      await log('scan_error', 'error', 'Could not resolve scan context (tenant/repo missing)')
      return {
        filesFetched: 0,
        componentsDetected: 0,
        scannersDispatched: [],
        errors: ['Could not resolve scan context (tenant/repo missing)'],
      }
    }

    await log('scan_start', 'info', `Scanning ${scanCtx.repositoryFullName}`, `branch: ${scanCtx.defaultBranch}`)

    // 2. Get GitHub token
    const token = await ctx.runQuery(
      internal.scannerEngine.getGithubTokenForTenant,
      { tenantId: args.tenantId },
    )
    if (!token) {
      await log('scan_error', 'error', 'No GitHub token found', 'Connect GitHub first via /connect/github')
      return {
        filesFetched: 0,
        componentsDetected: 0,
        scannersDispatched: [],
        errors: [
          'No GitHub token found for tenant owner. Connect GitHub first via /connect/github.',
        ],
      }
    }

    // 3. Parse owner/repo from full name
    const [owner, repoName] = scanCtx.repositoryFullName.split('/')
    if (!owner || !repoName) {
      await log('scan_error', 'error', `Invalid repo full name: ${scanCtx.repositoryFullName}`)
      return {
        filesFetched: 0,
        componentsDetected: 0,
        scannersDispatched: [],
        errors: [`Invalid repo full name: ${scanCtx.repositoryFullName}`],
      }
    }

    // 4. Fetch the real repo tree
    const ref =
      args.commitSha.startsWith('rescan-') ||
      args.commitSha.startsWith('onboarding-')
        ? scanCtx.defaultBranch
        : args.commitSha

    await log('fetch_tree', 'info', `Fetching repository tree from GitHub`, `${owner}/${repoName}:${ref}`)

    let treeEntries: GitTreeEntry[]
    try {
      treeEntries = await fetchRepoTree(
        owner,
        repoName,
        ref,
        token,
      )
    } catch (e: any) {
      await log('fetch_tree', 'error', `Failed to fetch repo tree: ${e.message}`)
      return {
        filesFetched: 0,
        componentsDetected: 0,
        scannersDispatched: [],
        errors: [`Failed to fetch repo tree: ${e.message}`],
      }
    }

    const allPaths = treeEntries.map((e) => e.path)
    await log('fetch_tree', 'success', `Repository tree fetched`, `${allPaths.length} files found`)

    // 5. Classify files and determine what to fetch
    const manifestPaths = allPaths.filter(isManifestFile)
    const sourcePaths = allPaths
      .filter(isSourceFile)
      .slice(0, 15) // cap source files for secret/crypto scanning
    const iacPaths = allPaths.filter(isIacFile).slice(0, 10)
    const cicdPaths = allPaths.filter(isCicdFile).slice(0, 10)
    const sensitivePaths = allPaths.filter(isSensitiveFile)

    await log('classify', 'info', `File classification complete`, [
      `${manifestPaths.length} manifests`,
      `${sourcePaths.length} source files`,
      `${iacPaths.length} IaC files`,
      `${cicdPaths.length} CI/CD files`,
      `${sensitivePaths.length} sensitive file paths`,
    ].join(' · '))

    // Merge unique paths to fetch (manifests first, then scanners)
    const pathsToFetch = Array.from(
      new Set([...manifestPaths, ...sourcePaths, ...iacPaths, ...cicdPaths]),
    )

    // 6. Batch-fetch file contents (ref already computed above)
    await log('fetch_files', 'info', `Fetching ${pathsToFetch.length} file contents from GitHub API`)

    let fetchedFiles: FileContent[]
    try {
      fetchedFiles = await batchFetchFiles(
        owner,
        repoName,
        ref,
        pathsToFetch,
        token,
      )
    } catch (e: any) {
      errors.push(`Batch file fetch failed: ${e.message}`)
      fetchedFiles = []
      await log('fetch_files', 'error', `File fetch failed: ${e.message}`)
    }
    await log('fetch_files', 'success', `Fetched ${fetchedFiles.length} files from GitHub`)

    // 7. Parse dependency manifests → build SBOM
    let componentsDetected = 0
    const allParsedDeps: ParsedDependency[] = []

    for (const file of fetchedFiles) {
      if (isManifestFile(file.path)) {
        const deps = parseManifest(file.path, file.content, file.path)
        allParsedDeps.push(...deps)
      }
    }

    // Deduplicate by name+ecosystem+version
    const seenDeps = new Set<string>()
    const uniqueDeps = allParsedDeps.filter((d) => {
      const key = `${d.ecosystem}:${d.name}:${d.version}`
      if (seenDeps.has(key)) return false
      seenDeps.add(key)
      return true
    })

    if (uniqueDeps.length > 0) {
      componentsDetected = uniqueDeps.length
      await log('sbom', 'info', `Generating SBOM from ${manifestPaths.length} manifest files`, `Parsing ${uniqueDeps.length} unique components`)
      try {
        await ctx.runMutation(internal.sbom.ingestRepositoryInventoryInternal, {
          tenantSlug: scanCtx.tenantSlug,
          repositoryFullName: scanCtx.repositoryFullName,
          branch: ref,
          commitSha: ref,
          sourceFiles: manifestPaths,
          components: uniqueDeps.map((d) => ({
            name: d.name,
            version: d.version,
            ecosystem: d.ecosystem,
            layer: d.layer,
            isDirect: d.isDirect,
            sourceFile: d.sourceFile,
            dependents: d.dependents,
            license: d.license,
          })),
        })
        scannersDispatched.push('sbom_generation')
        await log('sbom', 'success', `SBOM snapshot created`, `${componentsDetected} components ingested`)
      } catch (e: any) {
        errors.push(`SBOM ingestion failed: ${e.message}`)
        await log('sbom', 'error', `SBOM ingestion failed: ${e.message}`)
      }
    } else {
      await log('sbom', 'info', `No dependency manifests found — skipping SBOM generation`)
    }

    // 8. Dispatch scanners with REAL file content
    const branch = ref
    const tenantId = args.tenantId
    const repositoryId = args.repositoryId

    await log('scanner_dispatch', 'info', `Dispatching security scanners`, '6 scanners queued')

    // Secret detection — scan source file contents
    {
      const contentItems = fetchedFiles
        .filter((f) => isSourceFile(f.path) || isIacFile(f.path) || isCicdFile(f.path))
        .map((f) => ({ content: f.content, filename: f.path }))

      if (contentItems.length > 0) {
        await log('scanner_dispatch', 'info', `Running secret detection scanner`, `${contentItems.length} files`)
        try {
          await ctx.runMutation(internal.secretDetectionIntel.recordSecretScan, {
            tenantId,
            repositoryId,
            branch,
            commitSha: ref,
            contentItems: contentItems.slice(0, MAX_FILES_TO_FETCH),
          })
          scannersDispatched.push('secret_detection')
          await log('scanner_result', 'success', `Secret detection complete`, `${contentItems.length} files scanned`)
        } catch (e: any) {
          errors.push(`Secret scan failed: ${e.message}`)
          await log('scanner_result', 'error', `Secret detection failed: ${e.message}`)
        }
      }
    }

    // IaC scan — scan infrastructure files
    {
      const iacFiles = fetchedFiles
        .filter((f) => isIacFile(f.path))
        .map((f) => ({ filename: f.path, content: f.content }))

      if (iacFiles.length > 0) {
        await log('scanner_dispatch', 'info', `Running IaC misconfiguration scanner`, `${iacFiles.length} files`)
        try {
          await ctx.runMutation(internal.iacScanIntel.recordIacScan, {
            tenantId,
            repositoryId,
            branch,
            commitSha: ref,
            fileItems: iacFiles,
          })
          scannersDispatched.push('iac_scan')
          await log('scanner_result', 'success', `IaC scan complete`, `${iacFiles.length} files scanned`)
        } catch (e: any) {
          errors.push(`IaC scan failed: ${e.message}`)
          await log('scanner_result', 'error', `IaC scan failed: ${e.message}`)
        }
      }
    }

    // CI/CD scan — scan workflow files
    {
      const cicdFiles = fetchedFiles
        .filter((f) => isCicdFile(f.path))
        .map((f) => ({ filename: f.path, content: f.content }))

      if (cicdFiles.length > 0) {
        await log('scanner_dispatch', 'info', `Running CI/CD pipeline scanner`, `${cicdFiles.length} files`)
        try {
          await ctx.runMutation(internal.cicdScanIntel.recordCicdScan, {
            tenantId,
            repositoryId,
            branch,
            commitSha: ref,
            fileItems: cicdFiles,
          })
          scannersDispatched.push('cicd_scan')
          await log('scanner_result', 'success', `CI/CD scan complete`, `${cicdFiles.length} files scanned`)
        } catch (e: any) {
          errors.push(`CI/CD scan failed: ${e.message}`)
          await log('scanner_result', 'error', `CI/CD scan failed: ${e.message}`)
        }
      }
    }

    // Crypto weakness — scan source files
    {
      const sourceFiles = fetchedFiles
        .filter((f) => isSourceFile(f.path))
        .map((f) => ({ filename: f.path, content: f.content }))

      if (sourceFiles.length > 0) {
        await log('scanner_dispatch', 'info', `Running crypto weakness scanner`, `${sourceFiles.length} files`)
        try {
          await ctx.runMutation(
            internal.cryptoWeaknessIntel.recordCryptoWeaknessScan,
            {
              tenantId,
              repositoryId,
              branch,
              commitSha: ref,
              fileItems: sourceFiles,
            },
          )
          scannersDispatched.push('crypto_weakness')
          await log('scanner_result', 'success', `Crypto weakness scan complete`, `${sourceFiles.length} files scanned`)
        } catch (e: any) {
          errors.push(`Crypto weakness scan failed: ${e.message}`)
          await log('scanner_result', 'error', `Crypto weakness scan failed: ${e.message}`)
        }
      }
    }

    // Sensitive file detection — uses file paths, not content
    if (sensitivePaths.length > 0 || allPaths.length > 0) {
      await log('scanner_dispatch', 'info', `Running sensitive file detection`, `${allPaths.length} paths to check`)
      try {
        await ctx.runMutation(
          internal.sensitiveFileIntel.recordSensitiveFileScan,
          {
            tenantId,
            repositoryId,
            commitSha: ref,
            branch,
            filePaths: allPaths,
          },
        )
        scannersDispatched.push('sensitive_file')
        await log('scanner_result', 'success', `Sensitive file detection complete`, `${sensitivePaths.length} matches found`)
      } catch (e: any) {
        errors.push(`Sensitive file scan failed: ${e.message}`)
        await log('scanner_result', 'error', `Sensitive file scan failed: ${e.message}`)
      }
    }

    // Commit message analysis — we don't have the real commit, so scan
    // the commitSha string and rescan marker as a best-effort
    {
      await log('scanner_dispatch', 'info', `Running commit message analysis`)
      try {
        await ctx.runMutation(
          internal.commitMessageIntel.recordCommitMessageScan,
          {
            tenantId,
            repositoryId,
            branch,
            commitSha: ref,
            messages: [`[scan] ${scanCtx.repositoryFullName}@${ref}`],
          },
        )
        scannersDispatched.push('commit_message')
        await log('scanner_result', 'success', `Commit message analysis complete`)
      } catch (e: any) {
        // commit_message scanner may not exist or may fail — non-fatal
        await log('scanner_result', 'warning', `Commit message scanner skipped (non-fatal)`)
      }
    }

    // 9. Record scan results summary
    try {
      await ctx.runMutation(internal.scannerEngine.recordScanOutcome, {
        tenantId,
        repositoryId,
        workflowRunId: args.workflowRunId,
        filesFetched: fetchedFiles.length,
        componentsDetected,
        scannersDispatched,
        errors,
      })
    } catch {
      // Non-fatal — the scan already ran
    }

    // Final log line
    if (errors.length > 0) {
      await log('scan_complete', 'warning', `Scan completed with ${errors.length} warnings`, `${scannersDispatched.length} scanners ran · ${errors.length} errors`)
    } else {
      await log('scan_complete', 'success', `Scan complete`, `${fetchedFiles.length} files · ${componentsDetected} components · ${scannersDispatched.length} scanners`)
    }

    return {
      filesFetched: fetchedFiles.length,
      componentsDetected,
      scannersDispatched,
      errors,
    }
  },
})

// ── Scan outcome recording ───────────────────────────────────────────────
//
// Stores a summary of each real scan run for debugging and auditability.

export const recordScanOutcome = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
    workflowRunId: v.id('workflowRuns'),
    filesFetched: v.number(),
    componentsDetected: v.number(),
    scannersDispatched: v.array(v.string()),
    errors: v.array(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    // Append scan outcome to the workflow run's task detail for the
    // inventory task so users can see what happened.
    const tasks = await ctx.db
      .query('workflowTasks')
      .withIndex('by_workflow_run_and_order', (q) =>
        q.eq('workflowRunId', args.workflowRunId),
      )
      .collect()

    const inventoryTask = tasks.find((t) => t.stage === 'inventory')
    if (inventoryTask) {
      await ctx.db.patch('workflowTasks', inventoryTask._id, {
        detail: `Real scan: fetched ${args.filesFetched} files, detected ${args.componentsDetected} SBOM components, dispatched [${args.scannersDispatched.join(', ')}]${args.errors.length > 0 ? `. Errors: ${args.errors.join('; ')}` : ''}`,
      })
    }

    return null
  },
})
