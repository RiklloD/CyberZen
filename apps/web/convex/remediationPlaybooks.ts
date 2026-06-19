import { ConvexError, v } from 'convex/values'
import { mutation, query } from './_generated/server'
import type { MutationCtx, QueryCtx } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type PlaybookStep = {
  title: string
  description: string
  codeBefore?: string
  codeAfter?: string
  language?: string
}

type GeneratedPlaybook = {
  steps: PlaybookStep[]
  estimatedTime: string
  difficulty: 'easy' | 'medium' | 'hard'
  prerequisites: string[]
  verificationSteps: string[]
}

// ---------------------------------------------------------------------------
// Finding type classifier
// ---------------------------------------------------------------------------

function classifyFindingType(vulnClass: string, source: string): string {
  const cls = vulnClass.toLowerCase()
  const src = source.toLowerCase()
  if (
    src === 'dependency_cve' ||
    cls.includes('dependency') ||
    cls.includes('cve') ||
    cls.includes('outdated')
  ) {
    return 'dependency_cve'
  }
  if (
    src === 'secret_scan' ||
    cls.includes('secret') ||
    cls.includes('credential') ||
    cls.includes('hardcoded') ||
    cls.includes('exposure')
  ) {
    return 'secret_exposure'
  }
  if (
    cls.includes('misconfiguration') ||
    cls.includes('config') ||
    cls.includes('infrastructure') ||
    cls.includes('iac')
  ) {
    return 'misconfiguration'
  }
  return 'sast_finding'
}

// ---------------------------------------------------------------------------
// Template generators
// ---------------------------------------------------------------------------

function generateDependencyCvePlaybook(affectedPackages: string[]): GeneratedPlaybook {
  const pkg = affectedPackages[0] ?? 'the vulnerable package'
  return {
    estimatedTime: '15 minutes',
    difficulty: 'easy',
    prerequisites: [
      'Write access to the repository',
      'Ability to run the project test suite locally',
    ],
    verificationSteps: [
      `Run \`npm audit\` (or equivalent) and confirm the CVE is no longer listed`,
      'All existing tests pass after the version bump',
      'No breaking API changes in the patched version changelog',
    ],
    steps: [
      {
        title: 'Identify the patched version',
        description: `Check the package registry for \`${pkg}\` to find the minimum version that resolves the CVE. Cross-reference the advisory linked in the finding.`,
        codeBefore: `# Check installed version\nnpm list ${pkg}`,
        codeAfter: `# Find the patched version on npm\nnpm view ${pkg} versions --json`,
        language: 'bash',
      },
      {
        title: 'Update the package manifest',
        description: `Bump \`${pkg}\` to the patched version. Use a pinned range to prevent automatic regression.`,
        codeBefore: `"${pkg}": "^1.2.3"`,
        codeAfter: `"${pkg}": "^1.2.4"  // patched version`,
        language: 'json',
      },
      {
        title: 'Install and lock the updated dependency',
        description: 'Run the package manager to apply the update and commit both the manifest and lockfile.',
        codeBefore: `npm install\n# (old lockfile)`,
        codeAfter: `npm install\ngit add package.json package-lock.json\ngit commit -m "fix: bump ${pkg} to patched version (CVE fix)"`,
        language: 'bash',
      },
      {
        title: 'Run the test suite',
        description: 'Confirm no regressions were introduced by the dependency bump.',
        codeAfter: `npm test\n# or: yarn test | bun test | pnpm test`,
        language: 'bash',
      },
    ],
  }
}

function generateSecretExposurePlaybook(affectedFiles: string[]): GeneratedPlaybook {
  const fileList = affectedFiles.slice(0, 3).join(', ') || 'the affected files'
  return {
    estimatedTime: '30 minutes',
    difficulty: 'medium',
    prerequisites: [
      'Access to the secret management system (Vault, AWS Secrets Manager, etc.)',
      'Ability to update CI/CD pipeline secrets',
    ],
    verificationSteps: [
      'Old secret is revoked/rotated in the issuing system',
      'New secret works correctly in staging before deploying to production',
      `\`git grep -r\` returns no matches for the secret pattern in ${fileList}`,
      'Git history audit complete — confirm secret was never pushed to a public remote',
    ],
    steps: [
      {
        title: 'Immediately rotate the exposed secret',
        description: 'Treat the exposed credential as fully compromised. Rotate it in the issuing service before making any code changes.',
        codeBefore: `# Exposed value found in: ${fileList}`,
        codeAfter: `# Generate replacement in your secrets manager\n# (Vault, AWS SSM, 1Password, GitHub Secrets, etc.)`,
        language: 'bash',
      },
      {
        title: 'Remove the hardcoded value from source',
        description: 'Replace every occurrence with an environment variable reference. Never commit secret values to version control.',
        codeBefore: `const apiKey = "sk-abc123secret"  // REMOVE THIS`,
        codeAfter: `const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY env var is required')`,
        language: 'typescript',
      },
      {
        title: 'Update CI/CD secrets and deployment configs',
        description: 'Add the new secret value to every deployment environment (staging, production) via your secrets management interface — never in plaintext config files.',
        codeAfter: `# GitHub Actions example\n# Settings → Secrets → Actions → update the secret there\n# Never add it to .env files committed to the repo`,
        language: 'bash',
      },
      {
        title: 'Audit and optionally rewrite git history',
        description: `If this repository is public, a history rewrite is strongly recommended. For private repositories, rotation is sufficient.`,
        codeBefore: `# Scan history for the old secret pattern\ngit log -p | grep -i "api_key\\|token\\|password" | head -20`,
        codeAfter: `# If history rewrite is needed:\n# Use BFG Repo Cleaner or git filter-repo\n# https://rtyley.github.io/bfg-repo-cleaner/`,
        language: 'bash',
      },
    ],
  }
}

function generateMisconfigurationPlaybook(title: string, summary: string): GeneratedPlaybook {
  return {
    estimatedTime: '20 minutes',
    difficulty: 'easy',
    prerequisites: [
      'Write access to the repository',
      'Understanding of the service/framework being configured',
    ],
    verificationSteps: [
      'Configuration linter or security scanner no longer reports this issue',
      'Service behaves correctly after the configuration change',
      'No unintended side effects from the configuration update',
      'Peer review completed for the change',
    ],
    steps: [
      {
        title: 'Understand the misconfiguration',
        description: `Review the finding "${title}" and understand why the current configuration is insecure. The summary provides context: ${summary.slice(0, 200)}`,
      },
      {
        title: 'Locate the configuration file',
        description: 'Find the specific file and setting that needs to be changed. Check the finding\'s affected files list for the exact location.',
        codeBefore: `# Locate configuration files\nfind . -name "*.yaml" -o -name "*.yml" -o -name "*.json" | xargs grep -l "insecure-setting"`,
        language: 'bash',
      },
      {
        title: 'Apply the hardened configuration',
        description: 'Update the setting to follow security best practices. Refer to the finding summary for the specific recommended value.',
        codeBefore: `# Insecure configuration`,
        codeAfter: `# Hardened configuration — see finding details for specifics`,
        language: 'yaml',
      },
      {
        title: 'Test and commit',
        description: 'Deploy to staging, verify the service operates correctly, then commit with a clear message.',
        codeAfter: `git add <config-file>\ngit commit -m "fix: harden configuration — resolve security finding"\ngit push`,
        language: 'bash',
      },
    ],
  }
}

function generateSastFindingPlaybook(title: string, affectedFiles: string[]): GeneratedPlaybook {
  const file = affectedFiles[0] ?? 'the affected file'
  return {
    estimatedTime: '45 minutes',
    difficulty: 'medium',
    prerequisites: [
      'Local development environment set up',
      'Ability to run the project test suite',
      'Familiarity with the affected code path',
    ],
    verificationSteps: [
      `Re-run the static analysis scanner on \`${file}\` — the finding should no longer appear`,
      'All existing tests pass',
      'New regression test added covering the fixed code path',
      'Code review completed before merging',
    ],
    steps: [
      {
        title: 'Understand the vulnerability class',
        description: `This is a "${title}" finding. Review the full finding summary to understand the attack vector, the affected data flow, and the potential impact if exploited.`,
      },
      {
        title: `Locate the vulnerable code in ${file}`,
        description: 'Open the affected file(s) and identify the exact lines. Look for unsanitized input reaching a dangerous sink, missing validation, or unsafe API usage.',
        codeBefore: `// Example: unsafe string concatenation into SQL query\nconst query = "SELECT * FROM users WHERE id = " + userId`,
        codeAfter: `// Fixed: parameterized query\nconst query = "SELECT * FROM users WHERE id = ?"\nconst rows = await db.execute(query, [userId])`,
        language: 'typescript',
      },
      {
        title: 'Apply the fix',
        description: 'Implement the remediation. Common patterns: use parameterized queries, validate/sanitize inputs at trust boundaries, encode outputs, replace deprecated APIs with safe alternatives.',
      },
      {
        title: 'Write a regression test',
        description: 'Add a test that sends a malicious payload through the fixed code path to prevent future regression.',
        codeAfter: `it('should reject injection payload', async () => {\n  const malicious = "' OR '1'='1"\n  const result = await getUser(malicious)\n  expect(result).toBeNull()\n})`,
        language: 'typescript',
      },
    ],
  }
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

async function requireMembership(
  ctx: MutationCtx | QueryCtx,
  authToken: string,
  tenantSlug: string,
) {
  const { userId } = await requireSessionAuth(ctx, authToken)
  const tenant = await ctx.db
    .query('tenants')
    .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
    .unique()
  if (!tenant) throw new ConvexError(`Tenant not found: ${tenantSlug}`)

  const membership = await ctx.db
    .query('tenantMembers')
    .withIndex('by_tenant_and_user', (q) =>
      q.eq('tenantId', tenant._id).eq('userId', userId),
    )
    .unique()
  if (!membership) throw new ConvexError('Not a member of this workspace')

  return { tenant, userId }
}

// ---------------------------------------------------------------------------
// generatePlaybook — creates a remediation playbook for a finding
// ---------------------------------------------------------------------------

export const generatePlaybook = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    findingId: v.id('findings'),
  },
  returns: v.id('remediationPlaybooks'),
  handler: async (ctx, { authToken, tenantSlug, findingId }) => {
    const { tenant } = await requireMembership(ctx, authToken, tenantSlug)

    const finding = await ctx.db.get(findingId)
    if (!finding || finding.tenantId !== tenant._id) {
      throw new ConvexError('Finding not found')
    }

    // Return existing playbook rather than regenerating
    const existing = await ctx.db
      .query('remediationPlaybooks')
      .withIndex('by_finding', (q) => q.eq('findingId', findingId))
      .order('desc')
      .first()
    if (existing) return existing._id

    const findingType = classifyFindingType(finding.vulnClass, finding.source)

    let generated: GeneratedPlaybook
    switch (findingType) {
      case 'dependency_cve':
        generated = generateDependencyCvePlaybook(finding.affectedPackages)
        break
      case 'secret_exposure':
        generated = generateSecretExposurePlaybook(finding.affectedFiles)
        break
      case 'misconfiguration':
        generated = generateMisconfigurationPlaybook(finding.title, finding.summary)
        break
      default:
        generated = generateSastFindingPlaybook(finding.title, finding.affectedFiles)
    }

    return await ctx.db.insert('remediationPlaybooks', {
      tenantId: tenant._id,
      repositoryId: finding.repositoryId,
      findingId,
      title: `Remediation: ${finding.title}`,
      severity: finding.severity,
      findingType,
      steps: JSON.stringify(generated.steps),
      estimatedTime: generated.estimatedTime,
      difficulty: generated.difficulty,
      prerequisites: generated.prerequisites,
      verificationSteps: generated.verificationSteps,
      generatedAt: Date.now(),
    })
  },
})

// ---------------------------------------------------------------------------
// getPlaybookForFinding — returns the most recent playbook for a finding
// ---------------------------------------------------------------------------

export const getPlaybookForFinding = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    findingId: v.id('findings'),
  },
  handler: async (ctx, { authToken, tenantSlug, findingId }) => {
    const { userId } = await requireSessionAuth(
      ctx as Parameters<typeof requireSessionAuth>[0],
      authToken,
    )
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return null

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership) return null

    return await ctx.db
      .query('remediationPlaybooks')
      .withIndex('by_finding', (q) => q.eq('findingId', findingId))
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// markPlaybookUsed — track whether the playbook successfully resolved the finding
// ---------------------------------------------------------------------------

export const markPlaybookUsed = mutation({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
    playbookId: v.id('remediationPlaybooks'),
    wasEffective: v.boolean(),
  },
  returns: v.null(),
  handler: async (ctx, { authToken, tenantSlug, playbookId, wasEffective }) => {
    const { tenant } = await requireMembership(ctx, authToken, tenantSlug)

    const playbook = await ctx.db.get(playbookId)
    if (!playbook || playbook.tenantId !== tenant._id) {
      throw new ConvexError('Playbook not found')
    }

    await ctx.db.patch(playbookId, { usedAt: Date.now(), wasEffective })
    return null
  },
})

// ---------------------------------------------------------------------------
// getPlaybookEffectivenessStats — aggregate effectiveness across all playbooks
// ---------------------------------------------------------------------------

export const getPlaybookEffectivenessStats = query({
  args: {
    authToken: v.optional(v.string()),
    tenantSlug: v.string(),
  },
  handler: async (ctx, { authToken, tenantSlug }) => {
    const { userId } = await requireSessionAuth(
      ctx as Parameters<typeof requireSessionAuth>[0],
      authToken,
    )
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', tenantSlug))
      .unique()
    if (!tenant) return { total: 0, used: 0, effective: 0, effectivenessRate: 0 }

    const membership = await ctx.db
      .query('tenantMembers')
      .withIndex('by_tenant_and_user', (q) =>
        q.eq('tenantId', tenant._id).eq('userId', userId),
      )
      .unique()
    if (!membership) return { total: 0, used: 0, effective: 0, effectivenessRate: 0 }

    const playbooks = await ctx.db
      .query('remediationPlaybooks')
      .withIndex('by_tenant_and_generated_at', (q) => q.eq('tenantId', tenant._id))
      .take(500)

    const total = playbooks.length
    const used = playbooks.filter((p) => p.usedAt !== undefined).length
    const effective = playbooks.filter((p) => p.wasEffective === true).length
    const effectivenessRate = used > 0 ? Math.round((effective / used) * 100) : 0

    return { total, used, effective, effectivenessRate }
  },
})
