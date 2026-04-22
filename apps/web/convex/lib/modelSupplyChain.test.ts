/// <reference types="vite/client" />
/**
 * Tests for AI/ML Model Supply Chain Intelligence.
 *
 * Covers: empty SBOM, ML framework detection, pickle risk, remote weight
 * download signals, unpinned version detection, known CVE ranges, typosquat
 * detection, and aggregate risk scoring.
 */

import { describe, expect, it } from "vitest";
import { scanModelSupplyChain, isMlPackage, type MlComponentInput } from "./modelSupplyChain";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const base: MlComponentInput = {
  name: "numpy",
  version: "1.26.0",
  ecosystem: "pypi",
  isDirect: true,
  layer: "runtime",
  hasKnownVulnerabilities: false,
  trustScore: 85,
};

function makeComponent(overrides: Partial<MlComponentInput>): MlComponentInput {
  return { ...base, ...overrides };
}

// ── Empty SBOM ────────────────────────────────────────────────────────────────

describe("scanModelSupplyChain — empty", () => {
  it("returns a zero-risk scan for an empty component list", () => {
    const result = scanModelSupplyChain([]);
    expect(result.overallRiskScore).toBe(0);
    expect(result.riskLevel).toBe("low");
    expect(result.mlFrameworkCount).toBe(0);
    expect(result.flaggedComponents).toHaveLength(0);
  });
});

// ── isMlPackage ───────────────────────────────────────────────────────────────

describe("isMlPackage", () => {
  it("recognises torch as an ML package", () => {
    expect(isMlPackage("torch")).toBe(true);
  });

  it("recognises transformers as an ML package", () => {
    expect(isMlPackage("transformers")).toBe(true);
  });

  it("recognises huggingface_hub with underscore variant", () => {
    expect(isMlPackage("huggingface_hub")).toBe(true);
  });

  it("returns false for a generic utility package", () => {
    expect(isMlPackage("requests")).toBe(false);
  });

  it("returns false for an unknown package", () => {
    expect(isMlPackage("my-internal-library")).toBe(false);
  });
});

// ── Pickle serialisation risk ─────────────────────────────────────────────────

describe("pickle_serialization_risk", () => {
  it("flags torch for pickle risk", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "torch", version: "2.1.0" })]);
    expect(scan.hasPickleRisk).toBe(true);
    const flagged = scan.flaggedComponents.find((c) => c.name === "torch");
    expect(flagged).toBeDefined();
    expect(flagged?.signals.some((s) => s.kind === "pickle_serialization_risk")).toBe(true);
  });

  it("flags tensorflow for pickle risk", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "tensorflow", version: "2.13.0" })]);
    expect(scan.hasPickleRisk).toBe(true);
  });

  it("flags dill (explicit pickle library) for pickle risk", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "dill", version: "0.3.7" })]);
    expect(scan.hasPickleRisk).toBe(true);
  });

  it("does NOT flag requests (non-ML) for pickle risk", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "requests", version: "2.31.0" })]);
    expect(scan.hasPickleRisk).toBe(false);
  });
});

// ── Remote weight download risk ───────────────────────────────────────────────

describe("remote_weight_download", () => {
  it("flags transformers for downloading remote model weights", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "transformers", version: "4.38.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "transformers");
    expect(flagged?.signals.some((s) => s.kind === "remote_weight_download")).toBe(true);
  });

  it("flags huggingface_hub for remote weight downloads", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "huggingface_hub", version: "0.20.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "huggingface_hub");
    expect(flagged?.signals.some((s) => s.kind === "remote_weight_download")).toBe(true);
  });

  it("does NOT flag scikit-learn for remote weight downloads", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "scikit-learn", version: "1.3.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "scikit-learn");
    const hasRemote = flagged?.signals.some((s) => s.kind === "remote_weight_download");
    expect(hasRemote ?? false).toBe(false);
  });
});

// ── Unpinned ML framework ─────────────────────────────────────────────────────

describe("unpinned_ml_framework", () => {
  it("flags a torch dependency with a wildcard version", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "torch", version: "*" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "torch");
    expect(flagged?.signals.some((s) => s.kind === "unpinned_ml_framework")).toBe(true);
    expect(scan.hasUnpinnedFramework).toBe(true);
  });

  it("flags a transformers dep with a >= constraint", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "transformers", version: ">=4.30.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "transformers");
    expect(flagged?.signals.some((s) => s.kind === "unpinned_ml_framework")).toBe(true);
  });

  it("does NOT flag an exactly-pinned version", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "torch", version: "2.1.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "torch");
    const hasUnpinned = flagged?.signals.some((s) => s.kind === "unpinned_ml_framework");
    expect(hasUnpinned ?? false).toBe(false);
  });
});

// ── Known-vulnerable version detection ───────────────────────────────────────

describe("outdated_ml_framework", () => {
  it("flags torch <2.0.0 as containing a known RCE CVE", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "torch", version: "1.13.1" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "torch");
    expect(flagged?.signals.some((s) => s.kind === "outdated_ml_framework")).toBe(true);
    expect(flagged?.signals.find((s) => s.kind === "outdated_ml_framework")?.description).toContain("CVE-2022-45907");
  });

  it("does NOT flag torch ≥2.0.0 for the older CVE", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "torch", version: "2.0.1" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "torch");
    const hasVuln = flagged?.signals.some((s) => s.kind === "outdated_ml_framework");
    expect(hasVuln ?? false).toBe(false);
  });

  it("flags tensorflow <2.12.0", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "tensorflow", version: "2.11.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "tensorflow");
    expect(flagged?.signals.some((s) => s.kind === "outdated_ml_framework")).toBe(true);
  });
});

// ── Model typosquat detection ─────────────────────────────────────────────────

describe("model_typosquat_risk", () => {
  it("flags a package one edit away from 'torch'", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "troch", version: "1.0.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "troch");
    expect(flagged?.signals.some((s) => s.kind === "model_typosquat_risk")).toBe(true);
  });

  it("flags a package one edit away from 'keras'", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "keraz", version: "1.0.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "keraz");
    expect(flagged?.signals.some((s) => s.kind === "model_typosquat_risk")).toBe(true);
  });

  it("does NOT flag 'requests' (far from all ML packages)", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "requests", version: "2.31.0" })]);
    const flagged = scan.flaggedComponents.find((c) => c.name === "requests");
    const hasTypo = flagged?.signals.some((s) => s.kind === "model_typosquat_risk");
    expect(hasTypo ?? false).toBe(false);
  });
});

// ── Aggregate risk scoring ────────────────────────────────────────────────────

describe("aggregate risk scoring", () => {
  it("produces a non-zero overall risk score when ML packages are present", () => {
    const components = [
      makeComponent({ name: "torch", version: "1.12.0" }),      // pickle + known CVE
      makeComponent({ name: "transformers", version: "4.35.0" }), // remote weights
    ];
    const scan = scanModelSupplyChain(components);
    expect(scan.overallRiskScore).toBeGreaterThan(0);
    expect(scan.mlFrameworkCount).toBe(2);
  });

  it("counts ML frameworks correctly when multiple are present", () => {
    const components = [
      makeComponent({ name: "torch", version: "2.1.0" }),
      makeComponent({ name: "transformers", version: "4.38.0" }),
      makeComponent({ name: "huggingface_hub", version: "0.20.0" }),
      makeComponent({ name: "requests", version: "2.31.0" }),     // non-ML
    ];
    const scan = scanModelSupplyChain(components);
    expect(scan.mlFrameworkCount).toBe(3);
    expect(scan.mlFrameworks).toContain("torch");
    expect(scan.mlFrameworks).toContain("transformers");
    expect(scan.mlFrameworks).not.toContain("requests");
  });

  it("caps the overall risk score at 100", () => {
    // All worst-case signals on multiple ML packages
    const components = Array.from({ length: 10 }, () =>
      makeComponent({ name: "torch", version: "1.0.0" }),
    );
    const scan = scanModelSupplyChain(components);
    expect(scan.overallRiskScore).toBeLessThanOrEqual(100);
  });

  it("returns low risk when only non-ML packages exist", () => {
    const components = [
      makeComponent({ name: "requests", version: "2.31.0" }),
      makeComponent({ name: "boto3", version: "1.34.0" }),
    ];
    const scan = scanModelSupplyChain(components);
    expect(scan.mlFrameworkCount).toBe(0);
    expect(scan.riskLevel).toBe("low");
  });
});

// ── Summary text ──────────────────────────────────────────────────────────────

describe("summary text", () => {
  it("reports 'no AI/ML frameworks' when none are detected", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "requests", version: "2.31.0" })]);
    expect(scan.summary).toMatch(/no AI\/ML frameworks/i);
  });

  it("mentions pickle risk in summary when present", () => {
    const scan = scanModelSupplyChain([makeComponent({ name: "torch", version: "1.13.1" })]);
    expect(scan.summary.toLowerCase()).toMatch(/pickle|serialis/i);
  });
});
