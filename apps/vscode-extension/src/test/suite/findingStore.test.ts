import { describe, it, expect, mock, beforeEach } from "bun:test";
import { FindingStore } from "../../findingStore.js";
import type { SentinelClient } from "../../sentinelClient.js";
import type { SentinelFinding } from "../../types.js";

function mockFinding(id: string): SentinelFinding {
  return {
    _id: id,
    title: `Finding ${id}`,
    severity: "high",
    status: "validated",
    repositoryId: "r1",
    createdAt: Date.now(),
    affectedPackages: ["lodash"],
  };
}

function makeClient(overrides: Partial<SentinelClient> = {}): SentinelClient {
  return {
    getFindings: mock(async () => []),
    getPostureReport: mock(async () => null),
    triggerScan: mock(async () => {}),
    ...overrides,
  } as unknown as SentinelClient;
}

// ─── Initial state ────────────────────────────────────────────────────────────

describe("FindingStore initial state", () => {
  it("starts with empty findings and null posture", () => {
    const store = new FindingStore(makeClient(), 300_000);
    const snap = store.snapshot();
    expect(snap.findings).toHaveLength(0);
    expect(snap.posture).toBeNull();
    expect(snap.lastRefreshedAt).toBeNull();
    expect(snap.isLoading).toBe(false);
    expect(snap.error).toBeNull();
    store.dispose();
  });
});

// ─── refresh() ────────────────────────────────────────────────────────────────

describe("FindingStore.refresh", () => {
  it("loads findings from client on refresh", async () => {
    const findings = [mockFinding("f1"), mockFinding("f2")];
    const store = new FindingStore(
      makeClient({ getFindings: mock(async () => findings) }),
      300_000,
    );
    await store.refresh();
    expect(store.snapshot().findings).toHaveLength(2);
    store.dispose();
  });

  it("sets lastRefreshedAt after a successful refresh", async () => {
    const store = new FindingStore(makeClient(), 300_000);
    await store.refresh();
    expect(store.snapshot().lastRefreshedAt).not.toBeNull();
    store.dispose();
  });

  it("sets isLoading=true during fetch, false after", async () => {
    const states: boolean[] = [];
    let resolve!: () => void;
    const waitForFetch = new Promise<void>((r) => {
      resolve = r;
    });

    const store = new FindingStore(
      makeClient({
        getFindings: mock(async () => {
          await waitForFetch;
          return [];
        }),
      }),
      300_000,
    );

    const snap1 = store.snapshot();
    expect(snap1.isLoading).toBe(false); // before refresh starts

    const refreshPromise = store.refresh();
    // isLoading should be true right after calling refresh
    // (synchronously set before the async fetch)
    expect(store.snapshot().isLoading).toBe(true);

    resolve();
    await refreshPromise;
    expect(store.snapshot().isLoading).toBe(false);
    store.dispose();
  });

  it("records error on client failure", async () => {
    const store = new FindingStore(
      makeClient({ getFindings: mock(async () => { throw new Error("API down"); }) }),
      300_000,
    );
    await store.refresh();
    expect(store.snapshot().error).toContain("API down");
    store.dispose();
  });

  it("clears previous error on successful refresh", async () => {
    let shouldFail = true;
    const store = new FindingStore(
      makeClient({
        getFindings: mock(async () => {
          if (shouldFail) throw new Error("fail");
          return [];
        }),
      }),
      300_000,
    );
    await store.refresh();
    expect(store.snapshot().error).not.toBeNull();

    shouldFail = false;
    await store.refresh();
    expect(store.snapshot().error).toBeNull();
    store.dispose();
  });
});

// ─── subscribe() ──────────────────────────────────────────────────────────────

describe("FindingStore.subscribe", () => {
  it("immediately delivers current snapshot to new subscriber", () => {
    const received: unknown[] = [];
    const store = new FindingStore(makeClient(), 300_000);
    const unsub = store.subscribe((snap) => received.push(snap));
    expect(received).toHaveLength(1);
    unsub();
    store.dispose();
  });

  it("notifies subscribers on refresh", async () => {
    const received: unknown[] = [];
    const store = new FindingStore(
      makeClient({ getFindings: mock(async () => [mockFinding("x")]) }),
      300_000,
    );
    const unsub = store.subscribe((snap) => received.push(snap));
    await store.refresh();
    // At least 3 notifications: initial + isLoading=true + final
    expect(received.length).toBeGreaterThanOrEqual(3);
    unsub();
    store.dispose();
  });

  it("stops delivering after unsubscribe", async () => {
    const received: unknown[] = [];
    const store = new FindingStore(makeClient(), 300_000);
    const unsub = store.subscribe((snap) => received.push(snap));
    unsub();
    const before = received.length;
    await store.refresh();
    expect(received.length).toBe(before); // no new notifications after unsub
    store.dispose();
  });

  it("snapshot returns defensive copy of findings array", () => {
    const store = new FindingStore(makeClient(), 300_000);
    const snap1 = store.snapshot();
    const snap2 = store.snapshot();
    expect(snap1.findings).not.toBe(snap2.findings); // different array references
    store.dispose();
  });
});
