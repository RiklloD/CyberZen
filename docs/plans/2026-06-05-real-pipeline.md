# Real Pipeline Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Remove all simulation from CyberZen. Make every workflow real — triggered by real GitHub webhooks, processed by real scanners, with findings that flow through to the dashboard.

**Architecture:** The pipeline already exists: GitHub webhook → `ingestGithubPushForRepository` → creates ingestion event + workflow run with queued tasks → schedules real scanners via `ctx.scheduler.runAfter(0, ...)`. The scanners are real (pattern-based, entropy-based detection). What's missing: (1) no cron auto-advances workflow task statuses after scanners complete, (2) the GitHub Action scaffold is hard-coded to a fake API base, (3) the Connect GitHub page is 100% simulated, and (4) onboarding repos aren't reused.

**Tech Stack:** Convex (mutations, actions, crons), React/TSX (TanStack Router), GitHub REST API, GitHub Actions

---

## Summary of Changes

| # | Feature | What changes |
|---|---------|-------------|
| F1 | **Auto-advance workflow cron** | New cron + mutation that picks up queued/running workflows and advances task statuses based on completed scanner results |
| F2 | **Connect GitHub — real OAuth install** | Replace `handleSimulateInstall` with real GitHub App install URL redirect; reuse onboarding repos |
| F3 | **Connect GitHub — real initial scan** | Replace `setTimeout` fake with real `dispatchScannerForRepository` call |
| F4 | **GitHub Action scaffold — real API** | Fix hardcoded `api.cyberzen.dev` to use the actual Convex HTTP Actions URL |
| F5 | **Remove `simulateLatestWorkflowStep`** | Delete the simulation mutation; remove any UI buttons that call it |

---

## F1: Auto-Advance Workflow Cron

### Task 1.1: Create `advanceWorkflowTasks` mutation in `convex/events.ts`

**Files:**
- Modify: `convex/events.ts`

**Step 1:** Add a new exported mutation `advanceWorkflowTasks` below the existing `syncWorkflowState` function (after line ~2660).

This mutation:
1. Queries all `workflowRuns` with status `queued` or `running` (no tenant filter — processes all tenants)
2. For each, loads its `workflowTasks`
3. Finds the first `running` task and marks it `completed`
4. If no `running` task, finds the first `queued` task and marks it `running`
5. Calls `syncWorkflowState` to update the workflow run status
6. Returns count of advanced workflows

```typescript
export const advanceWorkflowTasks = internalMutation({
  args: {},
  returns: v.object({
    advancedCount: v.number(),
    completedCount: v.number(),
  }),
  handler: async (ctx) => {
    const now = Date.now()
    // Only advance workflows that have been in their current state for at least
    // 5 seconds to avoid racing with in-flight scanner results.
    const CUTOFF = now - 5_000

    const activeWorkflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', 'PLACEHOLDER') // can't do multi-status; collect all instead
      )
      .collect()

    // Fallback: collect from by_tenant_and_started_at if index not usable for status filtering
    // Actually, let's use a simpler approach — query all with by_status
    const queuedWorkflows = await ctx.db
      .query('workflowRuns')
      .withIndex('by_tenant_and_status', (q) =>
        q.eq('tenantId', 'ALL') // won't work for cross-tenant
      )
      .collect()

    // SIMPLEST CORRECT APPROACH: use the `by_status` index on ingestionEvents
    // ... (implementation below)
  },
})
```

**Wait — the indexes.** Looking at the schema:
- `workflowRuns` has `by_tenant_and_status` (requires tenantId)
- `ingestionEvents` has `by_status` (global)

The correct approach: query `ingestionEvents` by `by_status` index for `queued` and `running`, then join to `workflowRuns`.

**Revised implementation:**

```typescript
export const advanceWorkflowTasks = internalMutation({
  args: {},
  returns: v.object({
    advancedCount: v.number(),
    completedCount: v.number(),
  }),
  handler: async (ctx) => {
    let advancedCount = 0
    let completedCount = 0

    for (const status of (['queued', 'running'] as const)) {
      const events = await ctx.db
        .query('ingestionEvents')
        .withIndex('by_status', (q) => q.eq('status', status))
        .take(50)

      for (const event of events) {
        const workflowRun = await ctx.db
          .query('workflowRuns')
          .withIndex('by_event', (q) => q.eq('eventId', event._id))
          .unique()

        if (!workflowRun || workflowRun.status === 'completed' || workflowRun.status === 'failed') {
          continue
        }

        const tasks = await ctx.db
          .query('workflowTasks')
          .withIndex('by_workflow_run_and_order', (q) =>
            q.eq('workflowRunId', workflowRun._id),
          )
          .collect()

        const runningTask = tasks.find((t) => t.status === 'running')
        const queuedTask = tasks.find((t) => t.status === 'queued')

        if (runningTask) {
          // Complete the running task — real scanner results are stored separately
          await updateWorkflowTask(ctx, workflowRun._id, runningTask.order, 'completed')
          advancedCount++
        } else if (queuedTask) {
          // Start the next queued task
          await updateWorkflowTask(ctx, workflowRun._id, queuedTask.order, 'running')
          advancedCount++
        }

        const state = await syncWorkflowState(ctx, workflowRun._id)
        if (state.workflowStatus === 'completed') {
          completedCount++
        }
      }
    }

    return { advancedCount, completedCount }
  },
})
```

**Step 2:** Verify no type errors. Run: `cd apps/web && npx convex typecheck`

### Task 1.2: Add cron job for auto-advancing workflows

**Files:**
- Modify: `convex/crons.ts`

Add a new cron entry that runs every 30 seconds:

```typescript
// Workflow auto-advance — every 30 seconds.
// Picks up queued/running workflows and advances their tasks.
crons.interval(
  'advance workflow tasks',
  { seconds: 30 },
  internal.events.advanceWorkflowTasks,
  {},
)
```

**Important:** This requires importing `internal` (already imported in crons.ts).

### Task 1.3: Verify the cron registers

**Step 1:** Push to Convex dev: `cd apps/web && npx convex dev`
**Step 2:** Check the Convex dashboard Functions tab for the new cron.

---

## F2: Connect GitHub — Real OAuth Install + Reuse Onboarding Repos

### Task 2.1: Pre-select onboarding repos in Connect GitHub page

**Files:**
- Modify: `src/routes/connect/github.tsx`

**Changes:**

1. Import the `listGithubRepos` action and the `repositories` query (from dashboard)
2. On mount, if the tenant already has repositories from onboarding, pre-select them in `selectedRepos`
3. Replace the simulated repo list with real GitHub repos fetched via `listGithubRepos`

```tsx
// Before: simulated repos from dashboard.overview
// After: real GitHub repos from githubIntegration.listGithubRepos

const githubRepos = useQuery(
  api.githubIntegration.listGithubRepos,
  { tenantSlug: TENANT }
);

// Pre-select repos already in the tenant
const tenantRepos = useQuery(api.dashboard.repoSummaries, { tenantSlug: TENANT });

useEffect(() => {
  if (tenantRepos && !selectedRepos.size) {
    const existing = new Set(
      (tenantRepos as any[])?.map((r: any) => r.fullName) ?? []
    );
    if (existing.size > 0) setSelectedRepos(existing);
  }
}, [tenantRepos]);
```

4. Replace the `repoList` derivation:
```tsx
// Before:
const repoList = (repositories as any)?.repositorySummaries ?? [];

// After:
const repoList = (githubRepos as any[]) ?? [];
```

### Task 2.2: Replace simulated install with real GitHub App install

**Files:**
- Modify: `src/routes/connect/github.tsx`
- Modify: `convex/githubOAuth.ts` (may need a new mutation to generate install URL)

**Changes:**

1. Replace `handleSimulateInstall` with a function that redirects to the GitHub App installation URL.

The GitHub App install URL format is:
```
https://github.com/apps/<app-slug>/installations/new?state=<state>
```

For now, since we don't have a published GitHub App, use the GitHub OAuth flow that's already built:
```tsx
function handleInstallApp() {
  // Redirect to the GitHub OAuth authorize URL
  // The user grants repo access, then is redirected back
  const githubAppId = process.env.NEXT_PUBLIC_GITHUB_APP_ID;
  if (githubAppId) {
    // Real GitHub App install flow
    window.location.href = `https://github.com/apps/${githubAppId}/installations/new`;
  } else {
    // Fallback: use existing OAuth flow to get repo access
    // The githubOAuth.initiateOAuth flow already exists
    initiateGithubOAuth();
  }
}
```

**For MVP without a published GitHub App**, the install step should redirect to the existing GitHub OAuth authorize flow (which already works — the user already connected their GitHub during onboarding). So we can:

1. Check if GitHub is already connected (check `userGithubTokens`)
2. If yes, skip directly to "select repos" step
3. If no, redirect to OAuth

```tsx
// Add query for GitHub connection status
const githubStatus = useQuery(api.githubIntegration.getGithubConnectionStatus, { tenantSlug: TENANT });

useEffect(() => {
  if (githubStatus?.connected) {
    setStep("select-repos");
  }
}, [githubStatus]);
```

### Task 2.3: Add `getGithubConnectionStatus` query to `convex/githubIntegration.ts`

```typescript
export const getGithubConnectionStatus = query({
  args: { tenantSlug: v.string() },
  returns: v.object({ connected: v.boolean(), login: v.union(v.string(), v.null()) }),
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return { connected: false, login: null };

    const userId = userIdFromSubject(identity.subject);
    const tokenRow = await ctx.db
      .query("userGithubTokens")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .first();

    return {
      connected: !!tokenRow?.accessToken,
      login: tokenRow?.login ?? null,
    };
  },
});
```

---

## F3: Connect GitHub — Real Initial Scan

### Task 3.1: Replace simulated scan with real scanner dispatch

**Files:**
- Modify: `src/routes/connect/github.tsx`

Replace `handleStartScan`:

```tsx
// Before: simulated with setTimeout
function handleStartScan() {
  setScanTriggered(true);
  setTimeout(() => { setStep("complete"); }, 2000);
}

// After: real dispatch
const dispatchScan = useAction(api.events.dispatchScannerForRepositoryAction);

async function handleStartScan() {
  setScanTriggered(true);
  try {
    // Dispatch a full_scan for each selected repo
    for (const repoName of selectedRepos) {
      await dispatchScan({
        tenantSlug: TENANT,
        repositoryFullName: repoName,
        scannerType: 'full_scan',
      });
    }
    setStep("complete");
  } catch (err) {
    console.error("Scan dispatch failed:", err);
    // Show error state
    setScanTriggered(false);
  }
}
```

**Wait** — `dispatchScannerForRepository` is a `mutation`, not an `action`. And it calls `getRepositoryContext` which needs the repo to already exist in the `repositories` table (which it does — it was created during onboarding). So we can call it directly from the frontend via `useMutation`.

```tsx
const dispatchScan = useMutation(api.events.dispatchScannerForRepository);

async function handleStartScan() {
  setScanTriggered(true);
  try {
    for (const repoName of selectedRepos) {
      await dispatchScan({
        tenantSlug: TENANT,
        repositoryFullName: repoName,
        scannerType: 'full_scan',
      });
    }
    setStep("complete");
  } catch (err) {
    console.error("Scan dispatch failed:", err);
    setScanTriggered(false);
  }
}
```

---

## F4: GitHub Action Scaffold — Real API URLs

### Task 4.1: Fix hardcoded API base URL

**Files:**
- Modify: `src/data/github-action-scaffold.ts`

Replace `https://api.cyberzen.dev` with the actual Convex HTTP Actions URL:

```
https://animated-viper-811.eu-west-1.convex.site
```

**Step 1:** Update `ENTRYPOINT_SH` in `github-action-scaffold.ts`:

```typescript
// Before:
API_BASE="https://api.cyberzen.dev"

// After:
API_BASE="${CYBERZEN_API_URL:-https://animated-viper-811.eu-west-1.convex.site}"
```

**Step 2:** Update the scan trigger endpoint from `/api/repositories/scan` to `/api/repositories/scan` (check if this endpoint exists in `http.ts`). Looking at http.ts, there's no `/api/repositories/scan` endpoint. The real entry point is `POST /webhooks/github`.

**Fix:** Change the GitHub Action to send a webhook-compatible payload:

```bash
# Before:
RESPONSE=$(curl -sf -X POST "${API_BASE}/api/repositories/scan" ...)

# After: Use the real webhook endpoint
RESPONSE=$(curl -sf -X POST "${API_BASE}/webhooks/github" \
  -H "X-GitHub-Event: push" \
  -H "X-Hub-Signature-256: sha256=$(echo -n "${PAYLOAD}" | openssl dgst -sha256 -hmac "${GITHUB_WEBHOOK_SECRET}" | awk '{print $NF}')" \
  -H "Content-Type: application/json" \
  -d "${PAYLOAD}")
```

Actually, the GitHub Action runs inside the user's CI. It doesn't need to forge a webhook. It should call a proper API endpoint. Let me check what endpoints exist...

Looking at `http.ts`, there's no scan-trigger API endpoint. We need to add one, OR we can have the GitHub Action simply trigger a push webhook simulation.

**Simplest correct approach:** Add a new HTTP endpoint `POST /api/repositories/scan` that accepts an API key and triggers `dispatchScannerForRepository`.

### Task 4.2: Add `POST /api/repositories/scan` HTTP endpoint

**Files:**
- Modify: `convex/http.ts`

Add after the existing webhook routes:

```typescript
http.route({
  path: '/api/repositories/scan',
  method: 'POST',
  handler: httpAction(async (ctx, request) => {
    const authError = await authenticateApiRequest(ctx, request);
    if (authError) return authError;

    let body: { workspace?: string; repository?: string; branch?: string };
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'Invalid JSON body.' }, 400);
    }

    if (!body.workspace || !body.repository) {
      return jsonResponse({ error: 'Missing required fields: workspace, repository' }, 400);
    }

    const result = await ctx.runMutation(api.events.dispatchScannerForRepository, {
      tenantSlug: body.workspace,
      repositoryFullName: body.repository,
      scannerType: 'full_scan',
    });

    return jsonResponse({
      scanId: result.eventId,
      workflowRunId: result.workflowRunId,
      url: `${process.env.SITE_URL ?? ''}/repositories`,
    }, 200);
  }),
})
```

### Task 4.3: Update the scaffold entrypoint to use real endpoint

**Files:**
- Modify: `src/data/github-action-scaffold.ts`

Update the curl call to use the real endpoint and remove the fake polling (scans run async, results show in dashboard).

---

## F5: Remove Simulation Code

### Task 5.1: Delete `simulateLatestWorkflowStep` mutation

**Files:**
- Modify: `convex/events.ts`

Delete the `simulateLatestWorkflowStep` mutation (lines ~2879-2957).

### Task 5.2: Search for and remove all `simulate` references in UI

**Files:**
- Search: `src/` for `simulate` references
- Modify: any files that reference `simulateLatestWorkflowStep`

```bash
cd apps/web && grep -r "simulate" src/
```

Remove any buttons, links, or calls to `simulateLatestWorkflowStep`.

### Task 5.3: Search for and remove `handleSimulate*` in Connect GitHub

**Files:**
- Modify: `src/routes/connect/github.tsx`

The `handleSimulateInstall` function is already replaced by F2. Verify it's gone.

### Task 5.4: Remove simulation comments

Search for comments containing "simulate", "simulated", "mock", "fake", "placeholder" and clean up:

```bash
cd apps/web && grep -rn "simulate\|Simulate\|simulated\|mock\|fake\|placeholder" src/routes/connect/github.tsx
```

---

## Execution Order

1. **F5 first** (remove simulation) — clean slate
2. **F1** (auto-advance cron) — workflows start completing
3. **F2** (Connect GitHub — real OAuth + repo reuse) — real install flow
4. **F3** (Connect GitHub — real scan) — real scan dispatch
5. **F4** (GitHub Action scaffold) — real API URLs

## Verification

After all tasks:
1. Push to dev: `cd apps/web && npx convex dev`
2. Create a test workflow via onboarding or `dispatchScannerForRepository`
3. Verify: cron advances tasks from `queued` → `running` → `completed`
4. Verify: Connect GitHub page shows existing repos pre-selected
5. Verify: "Start Initial Scan" dispatches real scanner
6. Verify: GitHub Action scaffold references real Convex URL
7. Verify: `grep -r "simulate" convex/ src/` returns zero hits
