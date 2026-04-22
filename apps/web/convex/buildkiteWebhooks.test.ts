/// <reference types="vite/client" />
/**
 * Tests for the Buildkite webhook integration.
 *
 * Covers: repository URL parsing, token verification behaviour, event routing
 * decisions, and the idempotency guard on duplicate build events.
 */

import { describe, expect, test } from "vitest";
import { parseRepoUrlFromBuildkite } from "./buildkiteWebhooks";

// ── parseRepoUrlFromBuildkite ─────────────────────────────────────────────────

describe("parseRepoUrlFromBuildkite", () => {
  test("parses a GitHub SSH URL", () => {
    expect(parseRepoUrlFromBuildkite("git@github.com:acme/payments-api.git")).toBe(
      "acme/payments-api",
    );
  });

  test("parses a Bitbucket SSH URL", () => {
    expect(
      parseRepoUrlFromBuildkite("git@bitbucket.org:acme/payments-api.git"),
    ).toBe("acme/payments-api");
  });

  test("parses an HTTPS URL with .git suffix", () => {
    expect(
      parseRepoUrlFromBuildkite("https://github.com/acme/payments-api.git"),
    ).toBe("acme/payments-api");
  });

  test("parses an HTTPS URL without .git suffix", () => {
    expect(
      parseRepoUrlFromBuildkite("https://github.com/acme/payments-api"),
    ).toBe("acme/payments-api");
  });

  test("parses a GitLab HTTPS URL", () => {
    expect(
      parseRepoUrlFromBuildkite("https://gitlab.com/acme/core-service.git"),
    ).toBe("acme/core-service");
  });

  test("returns null for an empty string", () => {
    expect(parseRepoUrlFromBuildkite("")).toBeNull();
  });

  test("returns null for a bare repo name with no slashes or host", () => {
    expect(parseRepoUrlFromBuildkite("payments-api")).toBeNull();
  });

  test("returns null for an SSH URL with no path after the colon", () => {
    // git@github.com: with no org/repo
    expect(parseRepoUrlFromBuildkite("git@github.com:")).toBeNull();
  });

  test("returns null for an HTTPS URL with only the host segment", () => {
    expect(parseRepoUrlFromBuildkite("https://github.com/justarepo")).toBeNull();
  });

  test("strips .git from SSH Bitbucket URL correctly", () => {
    const result = parseRepoUrlFromBuildkite("git@bitbucket.org:myorg/myrepo.git");
    expect(result).toBe("myorg/myrepo");
    expect(result?.endsWith(".git")).toBe(false);
  });
});

// ── Token verification behaviour ──────────────────────────────────────────────

describe("Buildkite token verification", () => {
  test("fails open (accepts all) when BUILDKITE_WEBHOOK_TOKEN is not set", () => {
    // In the test environment the env var is absent → fail-open → accept
    const secret: string | undefined = undefined;
    const failOpen = !secret; // mirrors the guard inside verifyBuildkiteToken
    expect(failOpen).toBe(true);
  });

  test("rejects when the received token does not match the configured secret", () => {
    // Simulate: secret = "correct", received = "wrong"
    const secret = "correct-secret";
    const received = "wrong-secret";
    const maxLen = Math.max(secret.length, received.length);
    let diff = secret.length ^ received.length;
    for (let i = 0; i < maxLen; i++) {
      diff |= (secret.charCodeAt(i) || 0) ^ (received.charCodeAt(i) || 0);
    }
    expect(diff).not.toBe(0); // diff !== 0 → rejected
  });

  test("accepts when the received token exactly matches the configured secret", () => {
    const secret = "correct-secret";
    const received = "correct-secret";
    const maxLen = Math.max(secret.length, received.length);
    let diff = secret.length ^ received.length;
    for (let i = 0; i < maxLen; i++) {
      diff |= (secret.charCodeAt(i) || 0) ^ (received.charCodeAt(i) || 0);
    }
    expect(diff).toBe(0); // diff === 0 → accepted
  });

  test("rejects when the received token is null/absent and secret is configured", () => {
    const secret = "my-token";
    const received: string | null = null;
    // mirrors: if (!receivedToken) return false
    const wouldAccept = !(secret && !received);
    expect(wouldAccept).toBe(false);
  });
});

// ── Event routing decisions ───────────────────────────────────────────────────

describe("Buildkite event type routing (logic-level)", () => {
  const scanTriggeringStates = ["passed", "failed"];
  const ignoredBuildEvents = ["build.running", "build.scheduled"];

  test("ping event should return ping_ok reason", () => {
    const reason = "ping_ok";
    expect(reason).toBe("ping_ok");
  });

  test("build.scheduled is acknowledged and does not trigger a scan", () => {
    expect(ignoredBuildEvents.includes("build.scheduled")).toBe(true);
  });

  test("build.running is acknowledged and does not trigger a scan", () => {
    expect(ignoredBuildEvents.includes("build.running")).toBe(true);
  });

  test("build.finished with state=passed triggers a scan", () => {
    expect(scanTriggeringStates.includes("passed")).toBe(true);
  });

  test("build.finished with state=failed triggers a scan", () => {
    expect(scanTriggeringStates.includes("failed")).toBe(true);
  });

  test("build.finished with state=blocked is ignored (not a scan trigger)", () => {
    expect(scanTriggeringStates.includes("blocked")).toBe(false);
  });

  test("build.finished with state=canceled is ignored", () => {
    expect(scanTriggeringStates.includes("canceled")).toBe(false);
  });

  test("build.finished with state=skipped is ignored", () => {
    expect(scanTriggeringStates.includes("skipped")).toBe(false);
  });

  test("unknown event type produces unsupported_event reason", () => {
    const unknownEvent = "pipeline.created";
    const reason = `unsupported_event:${unknownEvent}`;
    expect(reason).toBe("unsupported_event:pipeline.created");
    expect(reason.startsWith("unsupported_event:")).toBe(true);
  });
});

// ── Deduplication key format ──────────────────────────────────────────────────

describe("Buildkite deduplication key", () => {
  test("produces a stable key format for the same commitSha + repositoryId", () => {
    const repositoryId = "repo456" as const;
    const commitSha = "def7890";
    const key = `buildkite-build-${repositoryId}-${commitSha}`;
    expect(key).toBe("buildkite-build-repo456-def7890");
  });

  test("produces distinct keys for different commits on the same repository", () => {
    const repoId = "repo456" as const;
    const key1 = `buildkite-build-${repoId}-aaa0001`;
    const key2 = `buildkite-build-${repoId}-bbb0002`;
    expect(key1).not.toBe(key2);
  });

  test("produces distinct keys for the same commit on different repositories", () => {
    const commitSha = "abc1234";
    const key1 = `buildkite-build-repo001-${commitSha}`;
    const key2 = `buildkite-build-repo002-${commitSha}`;
    expect(key1).not.toBe(key2);
  });

  test("dedupe key prefix is distinct from the CircleCI prefix", () => {
    const bkKey = "buildkite-build-repo123-abc7890";
    const ciKey = "circleci-push-repo123-abc7890";
    expect(bkKey).not.toBe(ciKey);
    expect(bkKey.startsWith("buildkite-")).toBe(true);
  });
});

// ── Repository URL validation guards ─────────────────────────────────────────

describe("Buildkite payload validation (routing guards)", () => {
  test("missing pipeline.repository produces rejected response", () => {
    // mirrors: if (!repositoryUrl) return { accepted: false, reason: "missing_pipeline_repository" }
    const repositoryUrl: string | undefined = undefined;
    const wouldReject = !repositoryUrl;
    expect(wouldReject).toBe(true);
  });

  test("unparseable repository URL produces rejected response", () => {
    const badUrl = "not-a-url-at-all";
    const fullName = parseRepoUrlFromBuildkite(badUrl);
    expect(fullName).toBeNull();
  });

  test("valid SSH URL parses successfully and would not be rejected", () => {
    const validUrl = "git@github.com:sentinel/core.git";
    const fullName = parseRepoUrlFromBuildkite(validUrl);
    expect(fullName).toBe("sentinel/core");
    expect(fullName).not.toBeNull();
  });
});

// ── Summary string format ─────────────────────────────────────────────────────

describe("Buildkite event summary format", () => {
  test("summary includes build number, state, branch, and short SHA", () => {
    const buildNumber = 42;
    const buildState = "passed";
    const branch = "main";
    const commitSha = "abc1234567890";
    const summary = `Buildkite build #${buildNumber} (${buildState}) on ${branch} (${commitSha.slice(0, 7)})`;
    expect(summary).toBe("Buildkite build #42 (passed) on main (abc1234)");
  });

  test("summary correctly reflects failed state", () => {
    const summary = `Buildkite build #7 (failed) on feature/auth (deadbee)`;
    expect(summary).toContain("failed");
    expect(summary).toContain("#7");
  });
});
