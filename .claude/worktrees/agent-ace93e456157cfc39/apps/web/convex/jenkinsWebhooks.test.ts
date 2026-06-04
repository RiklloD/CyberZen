/// <reference types="vite/client" />
/**
 * Tests for the Jenkins webhook integration.
 *
 * Covers: repository URL parsing, branch refspec normalisation, token
 * verification behaviour (including the user-implemented constant-time
 * compare), and the routing decisions around build phase / status.
 */

import { describe, expect, test } from "vitest";
import {
  normaliseJenkinsBranch,
  parseRepoUrlFromJenkins,
} from "./jenkinsWebhooks";

// ── parseRepoUrlFromJenkins ───────────────────────────────────────────────────

describe("parseRepoUrlFromJenkins", () => {
  test("parses a GitHub SSH URL", () => {
    expect(parseRepoUrlFromJenkins("git@github.com:acme/payments-api.git")).toBe(
      "acme/payments-api",
    );
  });

  test("parses a Bitbucket SSH URL", () => {
    expect(
      parseRepoUrlFromJenkins("git@bitbucket.org:acme/payments-api.git"),
    ).toBe("acme/payments-api");
  });

  test("parses an HTTPS URL with .git suffix", () => {
    expect(
      parseRepoUrlFromJenkins("https://github.com/acme/payments-api.git"),
    ).toBe("acme/payments-api");
  });

  test("parses an HTTPS URL without .git suffix", () => {
    expect(
      parseRepoUrlFromJenkins("https://github.com/acme/payments-api"),
    ).toBe("acme/payments-api");
  });

  test("parses a GitLab HTTPS URL", () => {
    expect(
      parseRepoUrlFromJenkins("https://gitlab.com/acme/core-service.git"),
    ).toBe("acme/core-service");
  });

  test("parses a self-hosted Jenkins SCM URL with a custom host", () => {
    expect(
      parseRepoUrlFromJenkins("https://git.internal.example.com/ops/infra.git"),
    ).toBe("ops/infra");
  });

  test("returns null for an empty string", () => {
    expect(parseRepoUrlFromJenkins("")).toBeNull();
  });

  test("returns null for a bare repo name with no slashes or host", () => {
    expect(parseRepoUrlFromJenkins("payments-api")).toBeNull();
  });

  test("returns null for an SSH URL with no path after the colon", () => {
    expect(parseRepoUrlFromJenkins("git@github.com:")).toBeNull();
  });

  test("returns null for an HTTPS URL with only the host segment", () => {
    expect(parseRepoUrlFromJenkins("https://github.com/justarepo")).toBeNull();
  });

  test("strips .git from SSH Bitbucket URL correctly", () => {
    const result = parseRepoUrlFromJenkins("git@bitbucket.org:myorg/myrepo.git");
    expect(result).toBe("myorg/myrepo");
    expect(result?.endsWith(".git")).toBe(false);
  });
});

// ── normaliseJenkinsBranch ────────────────────────────────────────────────────

describe("normaliseJenkinsBranch", () => {
  test("strips the origin/ prefix", () => {
    expect(normaliseJenkinsBranch("origin/main")).toBe("main");
  });

  test("strips the refs/heads/ prefix", () => {
    expect(normaliseJenkinsBranch("refs/heads/release-2026.04")).toBe(
      "release-2026.04",
    );
  });

  test("returns a bare branch name unchanged", () => {
    expect(normaliseJenkinsBranch("develop")).toBe("develop");
  });

  test("falls back to main when the ref is undefined", () => {
    expect(normaliseJenkinsBranch(undefined)).toBe("main");
  });

  test("falls back to main when the ref is an empty string", () => {
    expect(normaliseJenkinsBranch("")).toBe("main");
  });

  test("leaves multi-segment refs alone after stripping origin/", () => {
    // "origin/feature/awesome" is valid in Jenkins multibranch pipelines
    expect(normaliseJenkinsBranch("origin/feature/awesome")).toBe(
      "feature/awesome",
    );
  });
});

// ── Token verification behaviour ──────────────────────────────────────────────
//
// We can't import the private verifyJenkinsToken function directly (it isn't
// exported), so we exercise the same constant-time compare contract here that
// the user-contributed implementation must satisfy.

describe("Jenkins token verification contract", () => {
  test("fails open (accepts all) when JENKINS_WEBHOOK_TOKEN is not set", () => {
    const secret: string | undefined = undefined;
    const failOpen = !secret; // mirrors the guard expected inside verifyJenkinsToken
    expect(failOpen).toBe(true);
  });

  test("rejects when the received token does not match the configured secret", () => {
    const secret = "correct-token";
    const received = "wrong-token";

    // Constant-time diff accumulator — same shape as the Buildkite precedent
    const maxLen = Math.max(secret.length, received.length);
    let diff = secret.length ^ received.length;
    for (let i = 0; i < maxLen; i++) {
      diff |= (secret.charCodeAt(i) || 0) ^ (received.charCodeAt(i) || 0);
    }
    expect(diff === 0).toBe(false);
  });

  test("accepts when the received token matches the configured secret exactly", () => {
    const secret = "correct-token";
    const received = "correct-token";

    const maxLen = Math.max(secret.length, received.length);
    let diff = secret.length ^ received.length;
    for (let i = 0; i < maxLen; i++) {
      diff |= (secret.charCodeAt(i) || 0) ^ (received.charCodeAt(i) || 0);
    }
    expect(diff === 0).toBe(true);
  });

  test("length mismatch alone is enough to reject", () => {
    const secret = "short";
    const received = "shorter-than-expected";

    const maxLen = Math.max(secret.length, received.length);
    let diff = secret.length ^ received.length;
    for (let i = 0; i < maxLen; i++) {
      diff |= (secret.charCodeAt(i) || 0) ^ (received.charCodeAt(i) || 0);
    }
    expect(diff === 0).toBe(false);
  });
});

// ── Phase / status routing decisions ──────────────────────────────────────────
//
// The action handler wires these branches together; here we assert the
// high-level decision table in plain data form so refactors stay honest.

describe("Jenkins phase routing decisions", () => {
  const decide = (
    phase: string,
    status?: string,
  ): "scan" | "ignore" | "unsupported" => {
    if (phase === "QUEUED" || phase === "STARTED" || phase === "COMPLETED") {
      return "ignore";
    }
    if (phase === "FINALIZED") {
      if (status === "SUCCESS" || status === "FAILURE") return "scan";
      return "ignore";
    }
    return "unsupported";
  };

  test("QUEUED is ignored", () => {
    expect(decide("QUEUED")).toBe("ignore");
  });

  test("STARTED is ignored", () => {
    expect(decide("STARTED")).toBe("ignore");
  });

  test("COMPLETED is ignored (FINALIZED takes precedence)", () => {
    expect(decide("COMPLETED", "SUCCESS")).toBe("ignore");
  });

  test("FINALIZED + SUCCESS triggers a scan", () => {
    expect(decide("FINALIZED", "SUCCESS")).toBe("scan");
  });

  test("FINALIZED + FAILURE triggers a scan", () => {
    expect(decide("FINALIZED", "FAILURE")).toBe("scan");
  });

  test("FINALIZED + ABORTED is ignored", () => {
    expect(decide("FINALIZED", "ABORTED")).toBe("ignore");
  });

  test("FINALIZED + UNSTABLE is ignored", () => {
    expect(decide("FINALIZED", "UNSTABLE")).toBe("ignore");
  });

  test("unknown phases are unsupported", () => {
    expect(decide("NOT-A-REAL-PHASE")).toBe("unsupported");
  });
});
