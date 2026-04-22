/// <reference types="vite/client" />
/**
 * Tests for SOC 2 Automated Evidence Collection.
 *
 * Covers: empty findings, per-framework control mapping, evidence status
 * derivation (gap / remediated / compliant / risk_accepted), evidence type
 * selection priority, evidence score calculation, summary text, and the
 * gate-enforcement evidence trail.
 */

import { describe, expect, it } from "vitest";
import {
  generateComplianceEvidence,
  type ComplianceEvidenceInput,
  type EvidenceFinding,
  type EvidenceGateDecision,
} from "./complianceEvidence";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const NOW = 1_700_000_000_000;
const ONE_DAY = 86_400_000;

function openFinding(overrides: Partial<EvidenceFinding> = {}): EvidenceFinding {
  return {
    id: "f1",
    vulnClass: "injection",
    severity: "high",
    status: "open",
    validationStatus: "validated",
    affectedPackages: ["express"],
    createdAt: NOW - ONE_DAY * 5,
    ...overrides,
  };
}

function resolvedFinding(overrides: Partial<EvidenceFinding> = {}): EvidenceFinding {
  return {
    ...openFinding(),
    id: "f2",
    status: "resolved",
    resolvedAt: NOW - ONE_DAY * 2,
    prUrl: "https://github.com/acme/repo/pull/42",
    ...overrides,
  };
}

function makeInput(
  framework: ComplianceEvidenceInput["framework"],
  findings: EvidenceFinding[],
  gateDecisions: EvidenceGateDecision[] = [],
): ComplianceEvidenceInput {
  return {
    framework,
    findings,
    gateDecisions,
    repositoryName: "acme/payments-api",
    scanTimestamp: NOW,
  };
}

// ── Empty findings ────────────────────────────────────────────────────────────

describe("generateComplianceEvidence — empty findings", () => {
  it("returns 100/100 evidence score with no gaps when no findings exist", () => {
    const report = generateComplianceEvidence(makeInput("soc2", []));
    expect(report.evidenceScore).toBe(100);
    expect(report.openGapControlCount).toBe(0);
    expect(report.summary).toMatch(/no gaps/i);
  });

  it("sets frameworkLabel correctly for soc2", () => {
    const report = generateComplianceEvidence(makeInput("soc2", []));
    expect(report.frameworkLabel).toBe("SOC 2 Type II");
  });

  it("sets frameworkLabel correctly for gdpr", () => {
    const report = generateComplianceEvidence(makeInput("gdpr", []));
    expect(report.frameworkLabel).toBe("GDPR Art. 32");
  });
});

// ── Control mapping ───────────────────────────────────────────────────────────

describe("SOC 2 control mapping", () => {
  it("maps an injection finding to CC6.6 (Boundary Protection)", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "injection", severity: "high" })]),
    );
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66).toBeDefined();
    expect(cc66?.status).toBe("gap");
    expect(cc66?.findingCount).toBeGreaterThan(0);
  });

  it("maps an auth finding to CC6.1 (Access Controls)", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "auth", severity: "critical" })]),
    );
    const cc61 = report.evidenceItems.find((i) => i.controlId === "CC6.1");
    expect(cc61?.status).toBe("gap");
  });

  it("maps a supply_chain finding to CC8.1 (Change Management)", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "supply_chain", severity: "high" })]),
    );
    const cc81 = report.evidenceItems.find((i) => i.controlId === "CC8.1");
    expect(cc81?.status).toBe("gap");
  });

  it("returns compliant status for a control with no matching findings", () => {
    // anomaly vuln class → CC7.2, not CC6.6
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "anomaly", severity: "high" })]),
    );
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66?.status).toBe("compliant");
  });
});

describe("GDPR control mapping", () => {
  it("maps a pii finding to Art.32.1a (Pseudonymisation)", () => {
    const report = generateComplianceEvidence(
      makeInput("gdpr", [openFinding({ vulnClass: "pii", severity: "high" })]),
    );
    const art32a = report.evidenceItems.find((i) => i.controlId === "Art.32.1a");
    expect(art32a?.status).toBe("gap");
  });

  it("maps a credential finding to Art.33 (Breach Notification)", () => {
    const report = generateComplianceEvidence(
      makeInput("gdpr", [openFinding({ vulnClass: "credential", severity: "critical" })]),
    );
    const art33 = report.evidenceItems.find((i) => i.controlId === "Art.33");
    expect(art33?.status).toBe("gap");
  });
});

describe("PCI-DSS control mapping", () => {
  it("maps an outdated dependency finding to Req6.3 (Vulnerability Management)", () => {
    const report = generateComplianceEvidence(
      makeInput("pci_dss", [openFinding({ vulnClass: "outdated", severity: "high" })]),
    );
    const req63 = report.evidenceItems.find((i) => i.controlId === "Req6.3");
    expect(req63?.status).toBe("gap");
  });
});

// ── Evidence status derivation ────────────────────────────────────────────────

describe("evidence status derivation", () => {
  it("returns 'gap' when there is an open finding", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "injection", severity: "high" })]),
    );
    const item = report.evidenceItems.find((i) => i.status === "gap");
    expect(item).toBeDefined();
  });

  it("returns 'remediated' when a finding is resolved", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [resolvedFinding({ vulnClass: "injection", severity: "high" })]),
    );
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66?.status).toBe("remediated");
  });

  it("returns 'risk_accepted' when a finding has accepted_risk status", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "injection", severity: "high", status: "accepted_risk" })]),
    );
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66?.status).toBe("risk_accepted");
  });
});

// ── Evidence type priority ────────────────────────────────────────────────────

describe("evidence type selection", () => {
  it("prefers gate_enforcement evidence when a gate block exists for this finding", () => {
    const finding = openFinding({ id: "f1", vulnClass: "injection", severity: "high" });
    const gate: EvidenceGateDecision = {
      findingId: "f1",
      decision: "blocked",
      decidedAt: NOW,
    };
    const report = generateComplianceEvidence(makeInput("soc2", [finding], [gate]));
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66?.evidenceType).toBe("gate_enforcement");
  });

  it("uses pr_audit_trail when a fix PR exists but no gate block", () => {
    const finding = resolvedFinding({ vulnClass: "injection", severity: "high" });
    const report = generateComplianceEvidence(makeInput("soc2", [finding]));
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66?.evidenceType).toBe("pr_audit_trail");
  });

  it("falls back to finding_log when no gate or PR evidence exists", () => {
    const finding = openFinding({ vulnClass: "injection", severity: "high", status: "open" });
    const report = generateComplianceEvidence(makeInput("soc2", [finding]));
    const cc66 = report.evidenceItems.find((i) => i.controlId === "CC6.6");
    expect(cc66?.evidenceType).toBe("finding_log");
  });
});

// ── Evidence score calculation ────────────────────────────────────────────────

describe("evidence score", () => {
  it("returns 100 when all controls are compliant (no findings)", () => {
    const report = generateComplianceEvidence(makeInput("soc2", []));
    expect(report.evidenceScore).toBe(100);
  });

  it("returns a score below 100 when some controls have open gaps", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "injection", severity: "high" })]),
    );
    expect(report.evidenceScore).toBeLessThan(100);
    expect(report.evidenceScore).toBeGreaterThanOrEqual(0);
  });

  it("scores 100 when all matched controls are remediated", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [resolvedFinding({ vulnClass: "injection", severity: "high" })]),
    );
    // CC6.6 should be remediated → contributes to full score
    expect(report.evidenceScore).toBe(100);
  });
});

// ── Summary text ──────────────────────────────────────────────────────────────

describe("summary text", () => {
  it("mentions the framework name and score", () => {
    const report = generateComplianceEvidence(makeInput("hipaa", []));
    expect(report.summary).toContain("HIPAA");
  });

  it("mentions the number of open gap controls when gaps exist", () => {
    const report = generateComplianceEvidence(
      makeInput("nis2", [openFinding({ vulnClass: "supply_chain", severity: "high" })]),
    );
    expect(report.summary).toMatch(/\d+ control\(s\) with open gaps/);
  });
});

// ── Coverage counts ───────────────────────────────────────────────────────────

describe("coverage counts", () => {
  it("has the correct total evidence items (one per control in the catalogue)", () => {
    const report = generateComplianceEvidence(makeInput("soc2", []));
    // SOC 2 has 5 controls defined
    expect(report.totalEvidenceItems).toBe(5);
  });

  it("counts covered controls when at least one finding maps to them", () => {
    const report = generateComplianceEvidence(
      makeInput("soc2", [openFinding({ vulnClass: "injection", severity: "high" })]),
    );
    expect(report.coveredControlCount).toBeGreaterThan(0);
  });
});
