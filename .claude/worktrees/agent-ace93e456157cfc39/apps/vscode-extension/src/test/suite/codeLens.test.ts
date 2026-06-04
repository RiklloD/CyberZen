import { describe, it, expect } from "bun:test";
import {
  findPackageLine,
  groupFindingsByPackage,
  buildCodeLensTitle,
  stripPackageName,
} from "../../codeLensProvider.js";
import type { SentinelFinding } from "../../types.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function mockFinding(overrides: Partial<SentinelFinding> = {}): SentinelFinding {
  return {
    _id: "f1",
    title: "Test vuln",
    severity: "high",
    status: "validated",
    repositoryId: "r1",
    createdAt: Date.now(),
    affectedPackages: ["lodash"],
    ...overrides,
  };
}

// ─── stripPackageName ─────────────────────────────────────────────────────────

describe("stripPackageName", () => {
  it("strips version from unscoped package", () => {
    expect(stripPackageName("lodash@4.17.20")).toBe("lodash");
  });

  it("returns bare package name unchanged", () => {
    expect(stripPackageName("lodash")).toBe("lodash");
  });

  it("strips npm namespace prefix", () => {
    expect(stripPackageName("npm:lodash")).toBe("lodash");
  });

  it("strips namespace and preserves scoped package", () => {
    expect(stripPackageName("npm:@babel/core")).toBe("@babel/core");
  });

  it("strips version from scoped package", () => {
    expect(stripPackageName("@babel/core@7.0.0")).toBe("@babel/core");
  });

  it("strips pypi namespace", () => {
    expect(stripPackageName("pypi:requests")).toBe("requests");
  });

  it("strips cargo namespace", () => {
    expect(stripPackageName("cargo:serde@1.0.0")).toBe("serde");
  });
});

// ─── groupFindingsByPackage ───────────────────────────────────────────────────

describe("groupFindingsByPackage", () => {
  it("groups a single finding by its package name", () => {
    const f = mockFinding({ affectedPackages: ["lodash"] });
    const map = groupFindingsByPackage([f]);
    expect(map.get("lodash")).toEqual([f]);
  });

  it("strips version specifier from package names", () => {
    const f = mockFinding({ affectedPackages: ["lodash@4.17.20"] });
    const map = groupFindingsByPackage([f]);
    expect(map.has("lodash")).toBe(true);
    expect(map.has("lodash@4.17.20")).toBe(false);
  });

  it("strips scoped-package prefixes correctly", () => {
    const f = mockFinding({ affectedPackages: ["npm:@babel/core"] });
    const map = groupFindingsByPackage([f]);
    expect(map.has("@babel/core")).toBe(true);
  });

  it("merges multiple findings for the same package", () => {
    const f1 = mockFinding({ _id: "f1", affectedPackages: ["lodash"] });
    const f2 = mockFinding({ _id: "f2", affectedPackages: ["lodash"] });
    const map = groupFindingsByPackage([f1, f2]);
    expect(map.get("lodash")?.length).toBe(2);
  });

  it("handles a finding with multiple packages", () => {
    const f = mockFinding({ affectedPackages: ["axios", "node-fetch"] });
    const map = groupFindingsByPackage([f]);
    expect(map.has("axios")).toBe(true);
    expect(map.has("node-fetch")).toBe(true);
    expect(map.get("axios")).toEqual([f]);
  });

  it("returns empty map for empty input", () => {
    expect(groupFindingsByPackage([]).size).toBe(0);
  });

  it("ignores findings with no affectedPackages", () => {
    const f = mockFinding({ affectedPackages: undefined });
    expect(groupFindingsByPackage([f]).size).toBe(0);
  });
});

// ─── buildCodeLensTitle ───────────────────────────────────────────────────────

describe("buildCodeLensTitle", () => {
  it("returns empty string for empty findings", () => {
    expect(buildCodeLensTitle([])).toBe("");
  });

  it("shows singular 'vulnerability' for a single finding", () => {
    const title = buildCodeLensTitle([mockFinding({ severity: "high" })]);
    expect(title).toContain("1 vulnerabilit");
    expect(title).not.toContain("vulnerabilities");
  });

  it("shows plural 'vulnerabilities' for multiple findings", () => {
    const title = buildCodeLensTitle([
      mockFinding({ severity: "high" }),
      mockFinding({ severity: "medium" }),
    ]);
    expect(title).toContain("vulnerabilities");
  });

  it("includes critical count in parentheses", () => {
    const title = buildCodeLensTitle([mockFinding({ severity: "critical" })]);
    expect(title).toContain("1 critical");
  });

  it("includes high count in parentheses", () => {
    const title = buildCodeLensTitle([
      mockFinding({ severity: "critical" }),
      mockFinding({ severity: "high" }),
    ]);
    expect(title).toContain("1 critical");
    expect(title).toContain("1 high");
  });

  it("uses escalatedSeverity over base severity", () => {
    const title = buildCodeLensTitle([
      mockFinding({ severity: "medium", escalatedSeverity: "critical" }),
    ]);
    expect(title).toContain("1 critical");
    expect(title).not.toContain("medium");
  });

  it("appends confirmed exploit badge when validationStatus=validated", () => {
    const title = buildCodeLensTitle([
      mockFinding({ severity: "critical", validationStatus: "validated" }),
    ]);
    expect(title).toContain("⚡");
    expect(title).toContain("1 confirmed");
  });

  it("does not append exploit badge for non-validated findings", () => {
    const title = buildCodeLensTitle([mockFinding({ severity: "high" })]);
    expect(title).not.toContain("⚡");
  });
});

// ─── findPackageLine ──────────────────────────────────────────────────────────

describe("findPackageLine — package.json", () => {
  const content = `{\n  "dependencies": {\n    "lodash": "^4.17.20",\n    "axios": "^1.6.0"\n  }\n}`;
  it("finds lodash on line 2", () => expect(findPackageLine(content, "lodash", "package.json")).toBe(2));
  it("finds axios on line 3", () => expect(findPackageLine(content, "axios", "package.json")).toBe(3));
  it("returns -1 for missing package", () => expect(findPackageLine(content, "zod", "package.json")).toBe(-1));
});

describe("findPackageLine — requirements.txt", () => {
  const content = `flask==2.3.0\nrequests>=2.28.0\nnumpy\n`;
  it("finds flask", () => expect(findPackageLine(content, "flask", "requirements.txt")).toBe(0));
  it("finds requests with >= specifier", () => expect(findPackageLine(content, "requests", "requirements.txt")).toBe(1));
  it("finds bare numpy", () => expect(findPackageLine(content, "numpy", "requirements.txt")).toBe(2));
  it("returns -1 for missing dep", () => expect(findPackageLine(content, "django", "requirements.txt")).toBe(-1));
});

describe("findPackageLine — go.mod", () => {
  const content = `module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/crypto v0.14.0\n)\n`;
  it("finds gin", () => expect(findPackageLine(content, "gin-gonic/gin", "go.mod")).toBeGreaterThan(-1));
  it("returns -1 for missing dep", () => expect(findPackageLine(content, "chi", "go.mod")).toBe(-1));
});

describe("findPackageLine — Cargo.toml", () => {
  const content = `[package]\nname = "myapp"\n\n[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n`;
  it("finds serde", () => expect(findPackageLine(content, "serde", "Cargo.toml")).toBe(4));
  it("finds tokio with inline table", () => expect(findPackageLine(content, "tokio", "Cargo.toml")).toBe(5));
  it("returns -1 for missing dep", () => expect(findPackageLine(content, "rand", "Cargo.toml")).toBe(-1));
});
