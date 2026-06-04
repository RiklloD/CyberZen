# §7.8 — Convex Performance Audit (2026-05-16)

## Scope

Reviewed `apps/web/convex/dashboard.ts` (787 lines) and top query patterns for read amplification
and OCC conflict candidates.

## Critical Finding: `dashboard.overview` Mega-Query

**Location**: `apps/web/convex/dashboard.ts:295`

The single `overview` query fetches data from **15+ tables** in one handler:

1. `tenants` (by slug)
2. `repositories` (by tenant)
3. `sbomSnapshots` (per repository × 2)
4. `sbomComponents` (per snapshot)
5. `workflowRuns` (by tenant, latest 5)
6. `exploitValidationRuns` (by tenant, latest 5)
7. `workflowTasks` (per workflow run)
8. `findings` (ALL by tenant — **unbounded!**)
9. `gateDecisions` (latest 20)
10. `advisorySyncRuns` (latest 6)
11. `prProposals` (latest 8)
12. `breachDisclosures` (latest 4 + latest 40 filtered)
13. `vulnerabilities` (latest 10)
14. `crossRepoImpactRuns` (latest 5)
15. `securityTimelineEvents` (latest 20)

### Read Amplification

- **Per-repository fan-out**: For each repo, it fetches 2 snapshots + all components for each
  snapshot. With 50 repos × ~200 components each, this is 50 × 2 × 200 = 20,000 document reads.
- **`allFindings` is unbounded**: `ctx.db.query('findings').collect()` fetches ALL findings for the
  tenant. A tenant with 10,000 findings triggers 10,000 reads on every dashboard load.
- **Disclosure double-fetch**: `disclosureRows` (4) and `recentDisclosureRows` (40) query
  `breachDisclosures` twice with overlapping ranges.

### Recommendations

| Priority | Action | Impact |
|----------|--------|--------|
| P0 | Split into 6+ focused queries: `dashboard.kpiStats`, `dashboard.recentFindings`, `dashboard.repoSummaries`, `dashboard.workflowEvents`, `dashboard.gateDecisions`, `dashboard.escalations` | Reduces initial load from 15+ tables to 2-3 per route |
| P0 | Cap `allFindings` with `.take(200)` or use a count query instead | Prevents 10K+ reads on large tenants |
| P1 | Add `dashboard.repoSummaries` with pagination (take 20) | Limits per-repo fan-out |
| P1 | Merge the two disclosure queries into one with `.take(40)` then slice client-side | Eliminates redundant reads |
| P2 | Cache source-coverage aggregation in a materialized table updated by cron | Removes per-request aggregation |

## Other Query Patterns

### N+1 Patterns

Several routes exhibit N+1 patterns where a list query is followed by per-item lookups:

- `dashboard.overview` → `disclosures.map(db.get)` for repository names
- `dashboard.overview` → `advisorySyncRuns.map(db.get)` for repository names
- Panel routes: per-repo drift panels each query individually

**Fix**: Include `repositoryName` as a denormalized field on `breachDisclosures` and
`advisorySyncRuns` to avoid per-row `db.get()` calls.

### OCC Conflict Candidates

Tables likely to experience optimistic concurrency control conflicts under concurrent writes:

- `sbomComponents` — bulk inserted during scan runs; multiple concurrent scans on the same repo
  could conflict on the `by_snapshot` index
- `findings` — created by scanner actions; multiple scanners for the same repo could race
- `auditLog` — appended by many mutations simultaneously

**Mitigation**: Convex handles OCC automatically with retries, but very high write rates
(>100/s to the same document) should use batching.

### Unused Index Coverage

The schema at `convex/schema.ts` (5,235 lines) defines extensive indexes. Spot-check suggests
good coverage, but recommend running `npx convex index_usage` in production to identify
unused indexes consuming write amplification overhead.

## Action Items

1. **§7.1** — Split `dashboard.overview` (tracked separately, highest priority)
2. Cap `allFindings` collection to bounded limit
3. Denormalize `repositoryName` on disclosure and sync-run records
4. Merge duplicate breach disclosure queries
5. Consider materialized source-coverage table for the dashboard
6. Run index usage audit in production after deployment
