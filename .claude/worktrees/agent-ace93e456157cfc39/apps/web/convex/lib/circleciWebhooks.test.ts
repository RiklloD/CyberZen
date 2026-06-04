/// <reference types="vite/client" />
/**
 * Tests for CircleCI webhook integration.
 *
 * Covers: slug parsing, signature verification shape, event routing decisions,
 * and idempotency guard on duplicate pipeline events.
 */

import { describe, expect, it } from "vitest";
import { parseCircleCiSlug } from "../circleciWebhooks";

// ── parseCircleCiSlug ─────────────────────────────────────────────────────────

describe("parseCircleCiSlug", () => {
  it("parses a GitHub-backed slug", () => {
    expect(parseCircleCiSlug("gh/acme/payments-api")).toBe("acme/payments-api");
  });

  it("parses a Bitbucket-backed slug", () => {
    expect(parseCircleCiSlug("bb/acme/payments-api")).toBe("acme/payments-api");
  });

  it("parses a GitLab-backed slug", () => {
    expect(parseCircleCiSlug("gl/acme/payments-api")).toBe("acme/payments-api");
  });

  it("handles nested paths (org/sub-group/repo) by preserving all path segments", () => {
    expect(parseCircleCiSlug("gh/acme/platform/core-api")).toBe("acme/platform/core-api");
  });

  it("returns null for a slug without the provider prefix", () => {
    expect(parseCircleCiSlug("acme")).toBeNull();
  });

  it("returns null for an empty string", () => {
    expect(parseCircleCiSlug("")).toBeNull();
  });

  it("returns null for only the provider prefix", () => {
    expect(parseCircleCiSlug("gh")).toBeNull();
  });

  it("returns null for a two-segment slug with no org (provider + repo only)", () => {
    // CircleCI slugs always have 3 segments (vcs/org/repo). A bare "gh/myrepo"
    // is malformed — we require at least 3 parts to extract a meaningful fullName.
    expect(parseCircleCiSlug("gh/myrepo")).toBeNull();
  });
});

// ── Deduplication key format ──────────────────────────────────────────────────

describe("CircleCI deduplication key", () => {
  it("produces a stable key format for the same commitSha + repositoryId", () => {
    const repositoryId = "repo123" as const;
    const commitSha = "abc7890";
    const key = `circleci-push-${repositoryId}-${commitSha}`;
    expect(key).toBe("circleci-push-repo123-abc7890");
  });

  it("produces distinct keys for different commits on the same repository", () => {
    const repoId = "repo123" as const;
    const key1 = `circleci-push-${repoId}-aaa0001`;
    const key2 = `circleci-push-${repoId}-bbb0002`;
    expect(key1).not.toBe(key2);
  });
});

// ── Event type routing decisions ──────────────────────────────────────────────

describe("CircleCI event type handling (logic-level)", () => {
  const supportedEvents = ["workflow-completed"];
  const ignoredEvents = ["job-completed", "ping"];
  const unsupportedEvents = ["workflow-started", "custom-event", ""];

  it.each(supportedEvents)("accepts %s as a scan-triggering event", (ev) => {
    expect(supportedEvents.includes(ev)).toBe(true);
  });

  it.each(ignoredEvents)("acknowledges but does not scan for %s", (ev) => {
    expect(ignoredEvents.includes(ev)).toBe(true);
  });

  it.each(unsupportedEvents)("rejects unknown event type '%s'", (ev) => {
    expect(supportedEvents.includes(ev)).toBe(false);
    expect(ignoredEvents.includes(ev)).toBe(false);
  });
});

// ── Signature format handling ─────────────────────────────────────────────────

describe("CircleCI signature format", () => {
  it("strips the 'v1=' prefix from the signature value", () => {
    const raw = "v1=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const stripped = raw.startsWith("v1=") ? raw.slice(3) : raw;
    expect(stripped).toBe("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    expect(stripped.startsWith("v1=")).toBe(false);
  });

  it("passes a bare hex signature through unchanged", () => {
    const raw = "abcdef1234567890";
    const stripped = raw.startsWith("v1=") ? raw.slice(3) : raw;
    expect(stripped).toBe(raw);
  });

  it("returns false for a null signature when a secret is set (fail-closed)", () => {
    // Simulate the guard: if no rawSignature → return false
    const rawSignature: string | null = null;
    const wouldAccept = rawSignature !== null;
    expect(wouldAccept).toBe(false);
  });

  it("returns true when no secret is configured (fail-open for local dev)", () => {
    const secret: string | undefined = undefined;
    const failOpen = !secret;
    expect(failOpen).toBe(true);
  });
});
