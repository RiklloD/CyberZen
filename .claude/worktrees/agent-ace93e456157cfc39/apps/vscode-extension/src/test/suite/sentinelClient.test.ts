import { describe, it, expect, mock, beforeEach, afterEach } from "bun:test";
import { SentinelClient } from "../../sentinelClient.js";
import type { SentinelConfig } from "../../config.js";

const BASE_CONFIG: SentinelConfig = {
  apiUrl: "https://api.example.com",
  apiKey: "test-key",
  tenantSlug: "acme",
  repositoryFullName: "acme/backend",
  minSeverity: "medium",
  refreshIntervalSeconds: 300,
  dashboardUrl: "",
  enableCodeLens: true,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function mockFetchOk(body: unknown): void {
  globalThis.fetch = mock(() =>
    Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(""),
    } as Response),
  );
}

function mockFetchError(status: number, body = "error"): void {
  globalThis.fetch = mock(() =>
    Promise.resolve({
      ok: false,
      status,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve(body),
    } as Response),
  );
}

// ─── getFindings ──────────────────────────────────────────────────────────────

describe("SentinelClient.getFindings", () => {
  it("returns findings array on success", async () => {
    mockFetchOk({ findings: [{ _id: "f1", title: "Test" }], total: 1, page: 1, pageSize: 200 });
    const client = new SentinelClient(BASE_CONFIG);
    const findings = await client.getFindings();
    expect(findings).toHaveLength(1);
    expect(findings[0]._id).toBe("f1");
  });

  it("sends correct API key header", async () => {
    let capturedHeaders: Record<string, string> = {};
    globalThis.fetch = mock((url, init) => {
      capturedHeaders = Object.fromEntries(
        Object.entries((init as RequestInit).headers as Record<string, string>),
      );
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ findings: [], total: 0, page: 1, pageSize: 200 }),
        text: () => Promise.resolve(""),
      } as Response);
    });
    const client = new SentinelClient(BASE_CONFIG);
    await client.getFindings();
    expect(capturedHeaders["X-Sentinel-Api-Key"]).toBe("test-key");
  });

  it("includes tenantSlug and repositoryFullName in query params", async () => {
    let capturedUrl = "";
    globalThis.fetch = mock((url) => {
      capturedUrl = url as string;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ findings: [], total: 0, page: 1, pageSize: 200 }),
        text: () => Promise.resolve(""),
      } as Response);
    });
    const client = new SentinelClient(BASE_CONFIG);
    await client.getFindings();
    expect(capturedUrl).toContain("tenantSlug=acme");
    expect(capturedUrl).toContain("repositoryFullName=acme%2Fbackend");
  });

  it("throws on non-ok HTTP status", async () => {
    mockFetchError(401, "Unauthorized");
    const client = new SentinelClient(BASE_CONFIG);
    await expect(client.getFindings()).rejects.toThrow("401");
  });

  it("returns empty array when findings key is missing", async () => {
    mockFetchOk({ total: 0, page: 1, pageSize: 200 });
    const client = new SentinelClient(BASE_CONFIG);
    const findings = await client.getFindings();
    expect(findings).toHaveLength(0);
  });
});

// ─── getPostureReport ─────────────────────────────────────────────────────────

describe("SentinelClient.getPostureReport", () => {
  it("returns posture report on success", async () => {
    const posture = { postureScore: 82, postureLevel: "healthy" };
    mockFetchOk(posture);
    const client = new SentinelClient(BASE_CONFIG);
    const result = await client.getPostureReport();
    expect(result?.postureScore).toBe(82);
  });

  it("returns null on API error (graceful degradation)", async () => {
    mockFetchError(404, "not found");
    const client = new SentinelClient(BASE_CONFIG);
    const result = await client.getPostureReport();
    expect(result).toBeNull();
  });

  it("returns null on network failure", async () => {
    globalThis.fetch = mock(() => Promise.reject(new Error("Network error")));
    const client = new SentinelClient(BASE_CONFIG);
    const result = await client.getPostureReport();
    expect(result).toBeNull();
  });
});

// ─── URL construction ─────────────────────────────────────────────────────────

describe("SentinelClient URL construction", () => {
  it("strips trailing slash from apiUrl", async () => {
    let capturedUrl = "";
    globalThis.fetch = mock((url) => {
      capturedUrl = url as string;
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ findings: [], total: 0, page: 1, pageSize: 200 }),
        text: () => Promise.resolve(""),
      } as Response);
    });
    const client = new SentinelClient({ ...BASE_CONFIG, apiUrl: "https://api.example.com/" });
    await client.getFindings();
    // Must not have a double-slash between the host and the /api/ path
    expect(capturedUrl).toMatch(/^https:\/\/api\.example\.com\/api\/findings/);
  });
});
