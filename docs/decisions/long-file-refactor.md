# §7.6 — Long File Refactor Audit (2026-05-16)

## Line Count Verification

| File | Lines | Status |
|------|-------|--------|
| `apps/web/src/routes/repositories.tsx` | 429 | ✅ Under 500 |
| `apps/web/src/routes/compliance.tsx` | 229 | ✅ Under 500 |
| `apps/web/src/routes/supply-chain.tsx` | 193 | ✅ Under 500 |
| `apps/web/src/routes/ci-cd.tsx` | 343 | ✅ Under 500 |
| `apps/web/src/routes/findings.tsx` | 86 | ✅ Under 500 |
| `apps/web/src/routes/agents.tsx` | 463 | ✅ Under 500 |
| `apps/web/src/routes/breach-intel.tsx` | 181 | ✅ Under 500 |
| `apps/web/src/routes/integrations.tsx` | 516 | ⚠️ Slightly over 500 |
| `apps/web/convex/dashboard.ts` | 787 | ⚠️ Known §7.1 mega-query target |
| `apps/web/convex/schema.ts` | 5,235 | ⚠️ Schema file, split into modules recommended |

## Findings

All route files are under 500 lines after §2 extraction work. The only route exceeding 500 lines is
`integrations.tsx` at 516 lines — within acceptable range.

Two backend files remain excessively long:
- **`convex/dashboard.ts` (787 lines)** — Already tracked as §7.1. Contains a single mega-query
  (`overview`) that fetches 15+ tables. Splitting into focused queries is recommended.
- **`convex/schema.ts` (5,235 lines)** — Monolithic schema file. Consider splitting into
  per-domain files re-exported from an `index.ts`.

## Recommendation

No immediate refactoring action needed for route files. Focus future efforts on §7.1 (dashboard
query split) and schema modularization as a later technical debt item.
