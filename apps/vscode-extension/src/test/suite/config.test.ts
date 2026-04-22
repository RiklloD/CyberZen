import { describe, it, expect } from "bun:test";
import { isConfigured } from "../../config.js";
import type { SentinelConfig } from "../../config.js";

const FULL_CONFIG: SentinelConfig = {
  apiUrl: "https://api.example.com",
  apiKey: "sk-test-key",
  tenantSlug: "acme",
  repositoryFullName: "acme/backend",
  minSeverity: "medium",
  refreshIntervalSeconds: 300,
  dashboardUrl: "",
  enableCodeLens: true,
};

describe("isConfigured", () => {
  it("returns true when all required fields are present", () => {
    expect(isConfigured(FULL_CONFIG)).toBe(true);
  });

  it("returns false when apiKey is empty", () => {
    expect(isConfigured({ ...FULL_CONFIG, apiKey: "" })).toBe(false);
  });

  it("returns false when tenantSlug is empty", () => {
    expect(isConfigured({ ...FULL_CONFIG, tenantSlug: "" })).toBe(false);
  });

  it("returns false when repositoryFullName is empty", () => {
    expect(isConfigured({ ...FULL_CONFIG, repositoryFullName: "" })).toBe(false);
  });

  it("returns false when apiUrl is empty", () => {
    expect(isConfigured({ ...FULL_CONFIG, apiUrl: "" })).toBe(false);
  });
});
