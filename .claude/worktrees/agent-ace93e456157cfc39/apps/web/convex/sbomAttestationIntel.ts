/**
 * WS-40 — SBOM Attestation: Convex entrypoints.
 *
 * Persists per-snapshot attestation records using the pure-library functions in
 * `lib/sbomAttestation.ts`. Triggered fire-and-forget from `sbom.ts` immediately
 * after each SBOM snapshot is written. Supports on-demand re-verification so
 * operators can audit whether a snapshot's component list has been tampered with.
 *
 * Entrypoints:
 *   recordSbomAttestation              — internalMutation: generate + store attestation for latest snapshot
 *   verifySnapshotAttestation          — internalMutation: re-verify an existing attestation record
 *   triggerAttestationForRepository    — public mutation: on-demand re-attest by slug+fullName
 *   getLatestAttestation               — public query: most recent attestation for a repository
 *   getAttestationBySnapshotId         — public query: attestation for a specific snapshot
 *   getAttestationSummaryByTenant      — public query: tenant-wide attestation health
 */
import { v } from 'convex/values'
import { internal } from './_generated/api'
import { internalMutation, mutation, query } from './_generated/server'
import { generateSbomAttestation, verifyAttestation } from './lib/sbomAttestation'

// ---------------------------------------------------------------------------
// recordSbomAttestation — internalMutation
// ---------------------------------------------------------------------------

/**
 * Generate an attestation for the latest SBOM snapshot belonging to the given
 * repository and persist it. Only creates an attestation if one does not already
 * exist for the latest snapshot.
 *
 * Triggered fire-and-forget from `sbom.ingestRepositoryInventory`.
 */
export const recordSbomAttestation = internalMutation({
  args: {
    tenantId: v.id('tenants'),
    repositoryId: v.id('repositories'),
  },
  handler: async (ctx, args) => {
    const { tenantId, repositoryId } = args

    // ── Resolve tenant slug (needed for the attestation hash) ────────────
    const tenant = await ctx.db.get(tenantId)
    if (!tenant) return null

    // ── Load latest SBOM snapshot ─────────────────────────────────────────
    const snapshot = await ctx.db
      .query('sbomSnapshots')
      .withIndex('by_repository_and_captured_at', (q) =>
        q.eq('repositoryId', repositoryId),
      )
      .order('desc')
      .first()

    if (!snapshot) return null

    // ── Guard: skip if an attestation already exists for this snapshot ────
    const existing = await ctx.db
      .query('sbomAttestationRecords')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .first()

    if (existing) return existing._id

    // ── Load components (cap at 500, same as other Intel modules) ─────────
    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshot._id))
      .take(500)

    const componentInputs = components.map((c) => ({
      name: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
    }))

    // ── Generate attestation record ───────────────────────────────────────
    const nowMs = Date.now()
    const record = generateSbomAttestation(
      snapshot._id,
      componentInputs,
      tenant.slug,
      snapshot.capturedAt,
      nowMs,
    )

    // ── Persist ───────────────────────────────────────────────────────────
    const id = await ctx.db.insert('sbomAttestationRecords', {
      tenantId,
      repositoryId,
      snapshotId: snapshot._id,
      contentHash: record.contentHash,
      attestationHash: record.attestationHash,
      componentCount: record.componentCount,
      capturedAt: record.capturedAt,
      attestedAt: record.attestedAt,
      attestationVersion: record.attestationVersion,
      status: 'unverified',
    })

    return id
  },
})

// ---------------------------------------------------------------------------
// verifySnapshotAttestation — internalMutation
// ---------------------------------------------------------------------------

/**
 * Re-load the components for a snapshot, recompute the attestation hash, and
 * compare it against the stored value.  Updates the `status` and `lastVerifiedAt`
 * fields in-place.
 *
 * Can be called by a cron or on-demand to audit a specific snapshot.
 */
export const verifySnapshotAttestation = internalMutation({
  args: {
    attestationRecordId: v.id('sbomAttestationRecords'),
  },
  handler: async (ctx, { attestationRecordId }) => {
    const rec = await ctx.db.get(attestationRecordId)
    if (!rec) return null

    const tenant = await ctx.db.get(rec.tenantId)
    if (!tenant) return null

    // ── Re-load components for the attested snapshot ──────────────────────
    const components = await ctx.db
      .query('sbomComponents')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', rec.snapshotId))
      .take(500)

    const componentInputs = components.map((c) => ({
      name: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
    }))

    // ── Re-verify ─────────────────────────────────────────────────────────
    const nowMs = Date.now()
    const result = verifyAttestation(
      componentInputs,
      tenant.slug,
      rec.snapshotId,
      rec.capturedAt,
      rec.attestationHash,
      nowMs,
    )

    await ctx.db.patch(attestationRecordId, {
      status: result.status,
      lastVerifiedAt: nowMs,
    })

    return result
  },
})

// ---------------------------------------------------------------------------
// triggerAttestationForRepository — public mutation
// ---------------------------------------------------------------------------

/**
 * On-demand re-attestation trigger. Resolves tenant + repository by slug and
 * full name, then schedules the internal mutation.
 */
export const triggerAttestationForRepository = mutation({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, args): Promise<void> => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), args.tenantSlug))
      .first()
    if (!tenant) throw new Error(`Tenant not found: ${args.tenantSlug}`)

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), args.repositoryFullName),
        ),
      )
      .first()
    if (!repository) throw new Error(`Repository not found: ${args.repositoryFullName}`)

    await ctx.scheduler.runAfter(
      0,
      internal.sbomAttestationIntel.recordSbomAttestation,
      { tenantId: tenant._id, repositoryId: repository._id },
    )
  },
})

// ---------------------------------------------------------------------------
// getLatestAttestation — public query
// ---------------------------------------------------------------------------

/**
 * Return the most recent attestation record for a repository, resolved by
 * tenant slug + repository full name.
 */
export const getLatestAttestation = query({
  args: {
    tenantSlug: v.string(),
    repositoryFullName: v.string(),
  },
  handler: async (ctx, { tenantSlug, repositoryFullName }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const repository = await ctx.db
      .query('repositories')
      .filter((q) =>
        q.and(
          q.eq(q.field('tenantId'), tenant._id),
          q.eq(q.field('fullName'), repositoryFullName),
        ),
      )
      .unique()
    if (!repository) return null

    return ctx.db
      .query('sbomAttestationRecords')
      .withIndex('by_repository_and_attested_at', (q) =>
        q.eq('repositoryId', repository._id),
      )
      .order('desc')
      .first()
  },
})

// ---------------------------------------------------------------------------
// getAttestationBySnapshotId — public query
// ---------------------------------------------------------------------------

/**
 * Return the attestation record for a specific snapshot ID, or null if none exists.
 */
export const getAttestationBySnapshotId = query({
  args: {
    snapshotId: v.id('sbomSnapshots'),
  },
  handler: async (ctx, { snapshotId }) => {
    return ctx.db
      .query('sbomAttestationRecords')
      .withIndex('by_snapshot', (q) => q.eq('snapshotId', snapshotId))
      .first()
  },
})

// ---------------------------------------------------------------------------
// getAttestationSummaryByTenant — public query
// ---------------------------------------------------------------------------

/**
 * Return tenant-wide attestation health: counts of valid/tampered/unverified
 * snapshots and the most recent tampered record (if any) for an alert banner.
 */
export const getAttestationSummaryByTenant = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, { tenantSlug }) => {
    const tenant = await ctx.db
      .query('tenants')
      .filter((q) => q.eq(q.field('slug'), tenantSlug))
      .unique()
    if (!tenant) return null

    const rows = await ctx.db
      .query('sbomAttestationRecords')
      .withIndex('by_tenant_and_attested_at', (q) =>
        q.eq('tenantId', tenant._id),
      )
      .order('desc')
      .take(200)

    // Keep only the most recent attestation per repository.
    const seen = new Set<string>()
    const latest: typeof rows = []
    for (const row of rows) {
      const key = row.repositoryId as string
      if (!seen.has(key)) {
        seen.add(key)
        latest.push(row)
      }
    }

    const validCount = latest.filter((r) => r.status === 'valid').length
    const tamperedCount = latest.filter((r) => r.status === 'tampered').length
    const unverifiedCount = latest.filter((r) => r.status === 'unverified').length
    const mostRecentTampered = latest.find((r) => r.status === 'tampered') ?? null

    return {
      validCount,
      tamperedCount,
      unverifiedCount,
      totalRepositories: latest.length,
      mostRecentTampered: mostRecentTampered
        ? {
            repositoryId: mostRecentTampered.repositoryId,
            snapshotId: mostRecentTampered.snapshotId,
            contentHash: mostRecentTampered.contentHash,
            attestationHash: mostRecentTampered.attestationHash,
            attestedAt: mostRecentTampered.attestedAt,
          }
        : null,
    }
  },
})
