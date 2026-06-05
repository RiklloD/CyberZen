# CyberZen — Recurring Errors & Fixes

> Log of errors that come up repeatedly. Each entry has the error, root cause, and fix so we don't debug the same thing twice.

---

## 1. `git commit` fails — "Author identity unknown"

**Error:**
```
fatal: unable to auto-detect email address (got 'lorik@PC-RKL.(none)')
```

**Cause:** Fresh clone or new shell — `user.name` / `user.email` not set in the repo's git config.

**Fix:**
```bash
cd /c/Dev/CyberZen
git config user.name "lorik"
git config user.email "lorik@cyberzen.dev"
```

Then push as usual:
```bash
git add .
git commit -am "message"
git push origin master
```

---

## 2. `npx convex deploy` blocked by pre-existing TypeScript errors (129 errors, 22 files)

**Error:**
```
✖ TypeScript typecheck via `tsc` failed.
Found 129 errors in 22 files.
```

**Cause:** The repo has widespread pre-existing type errors across many files (dashboard.ts, neuralMemory.ts, onCall.ts, rbac.ts, etc.). These are NOT caused by your current change. They block `npx convex deploy` because it runs `tsc` by default.

**Fix:** Deploy with typecheck disabled:
```bash
npx convex deploy --typecheck=disable
```

To verify YOUR file compiles clean in isolation:
```bash
./node_modules/.bin/tsc --noEmit 2>&1 | grep "<your-file>"
```

No output = your file is clean.

---

## 3. GitHub OAuth connection fails — "Email not available in identity"

**Error (Convex logs):**
```
Uncaught Error: Email not available in identity.
subject=s97mr9hzha0chxjcs0tt032qy9881862|jx7k5z3cg8xrvb781q13vespg5881b1w,
keys=tokenIdentifier,issuer,subject.
Make sure the GitHub provider includes the email claim.
```

**File:** `apps/web/convex/githubOAuth.ts` — `startGithubConnect` action (line ~283)

**Cause:** `@convex-dev/auth` with the GitHub provider doesn't always include `identity.email` in the JWT. This happens when the GitHub user has a private email address. The code was doing:
```ts
if (!identity.email) {
    throw new Error("Email not available in identity...");
}
```

**Fix:** Replaced the direct `identity.email` check with a call to `_resolveUser` (internal query) that has two resolution paths:
1. If `identity.email` is present → look up by email index (fast path)
2. If `identity.email` is absent → extract `userId` from `identity.subject` (Convex Auth encodes it as `"userId|sessionId"`) and fetch the user document directly to get email from the DB

```ts
const resolved = await ctx.runQuery(internal.githubOAuth._resolveUser, {});
if (!resolved) {
    throw new Error("Could not resolve current user. Please sign in again.");
}
// Use resolved.email instead of identity.email
```

---

## 4. GitHub repos not loading / dropdown empty after OAuth connection

**Error:** No visible error — the repo dropdown stays as a plain text input instead of switching to a `<select>` with your repos. The `listGithubRepos` action silently fails with "No GitHub account is linked".

**File:** `apps/web/convex/githubIntegration.ts` — `getGithubAccessToken` (line ~53) and `listLinkedProviders` (lines ~217, ~225)

**Cause:** Same root cause as #3. Three lookups used `identity.subject as Id<"users">` but `@convex-dev/auth` encodes the subject as `"userId|sessionId"` (e.g., `"s97mr9hzha0chxjcs0tt032qy9881862|jx7k5z3cg8xrvb781q13vespg5881b1w"`). The full composite string doesn't match any document ID, so:
- `getGithubAccessToken` → can't find the `userGithubTokens` row → returns `null` → `listGithubRepos` throws
- `listLinkedProviders` → can't find `authAccounts` or `userGithubTokens` → returns `[]` → useEffect never triggers repo fetch

**Fix:** Extract the userId with `subject.split("|")[0]` before using it in queries:
```ts
function userIdFromSubject(subject: string): Id<"users"> {
    return subject.split("|")[0] as Id<"users">;
}
// Usage: q.eq("userId", userIdFromSubject(identity.subject))
```

---

## 5. getGithubConnectionStatus always returns `connected: false` after GitHub OAuth

**Error:** After completing GitHub OAuth successfully, the onboarding page still shows the "Connect GitHub" banner and never switches to the repo dropdown.

**File:** `apps/web/convex/githubOAuth.ts` — `getGithubConnectionStatus` (line ~232), `resolveCurrentUser` (line ~50)

**Cause:** `getGithubConnectionStatus` did `if (!identity?.email) return { connected: false }` at the top. Since `identity.email` is `undefined` for GitHub users with private emails, this query ALWAYS returned false — even after a successful OAuth connection stored the token. The `resolveCurrentUser` helper used by `disconnectGithub` had the same issue.

**Fix:** Same pattern as #3 and #4 — resolve user via `identity.subject` fallback when email is missing:
```ts
// Path 1: email index
if (identity.email) { /* lookup by email */ }
// Path 2: extract userId from subject
const userId = identity.subject.split("|")[0];
```

---

## 6. React minified error #310 on dashboard after onboarding

**Error:**
```
Error: Minified React error #310
Cannot update a component while rendering a different component
```

**File:** `apps/web/src/routes/index.tsx` — `DashboardPage` (line ~83)

**Cause:** `useQuery(api.securityEducation.getEducationStats)` was called AFTER two early returns (`overview === undefined` and `overview === null`). React hooks must always be called in the same order — you can't conditionally skip hooks. When `overview` loaded and the early returns stopped firing, the `eduStats` hook appeared for the first time mid-render, triggering React's "cannot update a component while rendering a different component" error.

**Fix:** Move all `useQuery` hooks to the top of the component, before any conditional returns:
```tsx
function DashboardPage() {
    const overview = useQuery(api.dashboard.overview, { tenantSlug });
    const eduStats = useQuery(api.securityEducation.getEducationStats, { tenantSlug });
    // ^^^ both hooks before any if/return

    if (overview === undefined) return <Loading />;
    if (overview === null) return <Empty />;
    // ...
}
```

---

## 7. Agents page crash — `can't access property "openCandidateCount", d is undefined`

**Error:**
```
TypeError: can't access property "openCandidateCount", d is undefined
```

**File:** `apps/web/src/routes/agents.tsx` — line ~113

**Cause:** The dashboard `overview` query returns `semanticFingerprint` and `exploitValidation` as nullable fields. When there's no scan data yet (fresh workspace), these are `null`/`undefined`. The agents page accessed `semanticFingerprint.openCandidateCount` and `exploitValidation.recentRuns` without null checks.

**Fix:** Wrap each section in a conditional render with an empty-state fallback:
```tsx
{semanticFingerprint ? (
    <div>...data...</div>
) : (
    <div className="empty-state">No data yet.</div>
)}
```

## 8. Compliance page server error — `getAllFrameworkEvidence` called with wrong args

**Error:**
```
Error: [CONVEX Q(complianceEvidenceIntel:getAllFrameworkEvidence)] Server Error
```

**File:** `apps/web/src/routes/compliance.tsx` — line ~37

**Cause:** The backend query `getAllFrameworkEvidence` expects `{ repositoryId: v.id('repositories') }`, but the compliance page was calling it with `{ tenantSlug: TENANT }`. Convex's argument validation rejected the mismatched args.

**Fix:** Track the active repo in state, use a `useEffect` to sync it, and pass the correct `repositoryId` to the query (using `"skip"` when no repo is selected).

---

## Template for new entries

```markdown
## N. <Short title>

**Error:**
\```
<paste the error message>
\```

**File:** `path/to/file.ts`

**Cause:** <what caused it>

**Fix:** <what fixed it, with code if relevant>
```
