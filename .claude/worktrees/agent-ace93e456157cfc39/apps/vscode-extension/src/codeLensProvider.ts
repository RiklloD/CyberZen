import type { SentinelFinding } from "./types.js";

/**
 * CodeLens provider for dependency manifest files.
 *
 * For each dependency line in package.json / requirements.txt / go.mod / Cargo.toml,
 * this provider shows a clickable overlay like:
 *
 *   "lodash": "^4.17.20"
 *   ⚠ Sentinel: 2 vulnerabilities (1 critical, 1 high)  · View findings
 *
 * The key challenge is **locating the exact line** in the manifest that corresponds
 * to a given finding's `affectedPackages` entry. Different manifest formats use
 * very different syntaxes (JSON, TOML, Python requirements, Go module DSL), so a
 * naive line scan produces different quality results for each format.
 */

// ─── Manifest line resolution ─────────────────────────────────────────────────

/**
 * Given a manifest file's text content and a package name, returns the 0-based
 * line number where that package is declared as a dependency.
 *
 * Returns -1 when the package cannot be located in this file.
 *
 * This function is called once per (package, manifest) pair on every CodeLens
 * refresh. It must be fast (synchronous) and accurate across these formats:
 *
 *   package.json     → "lodash": "^4.17.20"
 *   requirements.txt → lodash==4.17.20  /  lodash>=4.17.20  /  lodash
 *   go.mod           → require github.com/gin-gonic/gin v1.9.1
 *   Cargo.toml       → lodash = "4.17.20"  (under [dependencies])
 *   pom.xml          → <artifactId>spring-core</artifactId>
 *   Gemfile          → gem 'rails', '~> 7.0'
 *
 * Trade-offs to consider when implementing:
 *  - Pure line-by-line regex: fast, handles all formats, but may match comments
 *    or dev-dependency sections with false positives.
 *  - JSON.parse + character-offset tracking: precise for package.json but
 *    requires walking the parse tree to map keys back to line numbers.
 *  - TOML/YAML AST: most accurate for Cargo.toml/go.mod, but requires a parser.
 *
 * For a first pass, a well-crafted per-format regex on each line is the right
 * balance between accuracy and implementation complexity.
 */
export function findPackageLine(fileContent: string, packageName: string, _fileName: string): number {
  const lines = fileContent.split("\n");
  const base = _fileName.toLowerCase();

  let pattern: RegExp;
  if (base === "package.json" || base === "composer.json") {
    // JSON dependency blocks: "packageName": "..."
    pattern = new RegExp(`"${escapeRegex(packageName)}"\\s*:`);
  } else if (base === "requirements.txt") {
    // pip: packageName==x, packageName>=x, bare packageName
    pattern = new RegExp(`^\\s*${escapeRegex(packageName)}([=><![\\s]|$)`, "i");
  } else if (base === "pipfile") {
    // Pipfile TOML: packageName = "..."  or  packageName = {version = "..."}
    pattern = new RegExp(`^\\s*${escapeRegex(packageName)}\\s*=`, "i");
  } else if (base === "pyproject.toml") {
    // PEP 621: "packageName>=x" inside dependencies array
    pattern = new RegExp(`["']?${escapeRegex(packageName)}["']?\\s*[>=<!,\\[]`);
  } else if (base === "go.mod") {
    // require github.com/pkg/errors v0.9.0  or  pkg/errors v0.9.0
    pattern = new RegExp(`\\b${escapeRegex(packageName)}\\s+v`);
  } else if (base === "cargo.toml") {
    // [dependencies] section: name = "x"  or  name = { version = "x" }
    pattern = new RegExp(`^\\s*${escapeRegex(packageName)}\\s*=`);
  } else if (base === "pom.xml") {
    // Maven: <artifactId>spring-core</artifactId>
    pattern = new RegExp(`<artifactId>\\s*${escapeRegex(packageName)}\\s*</artifactId>`);
  } else if (base === "gemfile") {
    // gem 'rails', '~> 7.0'
    pattern = new RegExp(`gem\\s+['"]${escapeRegex(packageName)}['"]`);
  } else {
    // Generic fallback — match the bare name as a word boundary
    pattern = new RegExp(`\\b${escapeRegex(packageName)}\\b`);
  }

  return lines.findIndex((line) => pattern.test(line));
}

// ─── CodeLens builder ─────────────────────────────────────────────────────────

/**
 * Strips namespace prefix (e.g. "npm:", "pypi:") and version specifier from a
 * package reference, preserving scoped npm packages (@scope/name).
 *
 * Examples:
 *   "lodash@4.17.20"     → "lodash"
 *   "npm:@babel/core"    → "@babel/core"
 *   "@babel/core@7.0.0"  → "@babel/core"
 *   "pypi:requests"      → "requests"
 */
export function stripPackageName(pkg: string): string {
  // Remove namespace prefix like "npm:", "pypi:", "go:", "cargo:"
  const colonIdx = pkg.indexOf(":");
  const withoutNs = colonIdx >= 0 ? pkg.slice(colonIdx + 1) : pkg;
  // Scoped packages start with "@" — the version is after the second "@"
  if (withoutNs.startsWith("@")) {
    const inner = withoutNs.slice(1).split("@")[0]; // strip leading "@", take before first "@"
    return `@${inner}`;
  }
  return withoutNs.split("@")[0];
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Groups findings by package name for efficient lookup. */
export function groupFindingsByPackage(findings: SentinelFinding[]): Map<string, SentinelFinding[]> {
  const map = new Map<string, SentinelFinding[]>();
  for (const f of findings) {
    for (const pkg of f.affectedPackages ?? []) {
      const name = stripPackageName(pkg);
      const existing = map.get(name) ?? [];
      existing.push(f);
      map.set(name, existing);
    }
  }
  return map;
}

/** Formats a CodeLens title summarising the findings for one dependency line. */
export function buildCodeLensTitle(findings: SentinelFinding[]): string {
  if (findings.length === 0) return "";
  const critical = findings.filter((f) => (f.escalatedSeverity ?? f.severity) === "critical").length;
  const high = findings.filter((f) => (f.escalatedSeverity ?? f.severity) === "high").length;
  const other = findings.length - critical - high;

  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (other > 0) parts.push(`${other} other`);

  const validated = findings.filter((f) => f.validationStatus === "validated").length;
  const suffix = validated > 0 ? ` · ⚡ ${validated} confirmed` : "";
  return `⚠ Sentinel: ${findings.length} vulnerabilit${findings.length === 1 ? "y" : "ies"} (${parts.join(", ")})${suffix}`;
}

/** Creates all CodeLenses for a single manifest document. */
export function buildCodeLensesForDocument(
  vscode: typeof import("vscode"),
  doc: import("vscode").TextDocument,
  findingsByPackage: Map<string, SentinelFinding[]>,
): import("vscode").CodeLens[] {
  const lenses: import("vscode").CodeLens[] = [];
  const content = doc.getText();
  const fileName = doc.fileName.split(/[\\/]/).pop() ?? "";

  for (const [pkgName, findings] of findingsByPackage) {
    const active = findings.filter(
      (f) => f.status !== "resolved" && f.status !== "false_positive" && f.status !== "ignored",
    );
    if (active.length === 0) continue;

    const lineIdx = findPackageLine(content, pkgName, fileName);
    if (lineIdx < 0) continue;

    const range = new vscode.Range(lineIdx, 0, lineIdx, 0);
    const title = buildCodeLensTitle(active);

    lenses.push(
      new vscode.CodeLens(range, {
        title,
        command: "sentinel.viewFindings",
        arguments: [pkgName],
        tooltip: active
          .slice(0, 3)
          .map((f) => `${f.severity.toUpperCase()}: ${f.title}`)
          .join("\n"),
      }),
    );
  }

  return lenses;
}

/** VS Code CodeLensProvider implementation. */
export function createCodeLensProvider(
  vscode: typeof import("vscode"),
  getFindings: () => SentinelFinding[],
): import("vscode").CodeLensProvider {
  const changeEmitter = new vscode.EventEmitter<void>();
  return {
    onDidChangeCodeLenses: changeEmitter.event,
    provideCodeLenses(doc) {
      const byPackage = groupFindingsByPackage(getFindings());
      return buildCodeLensesForDocument(vscode, doc, byPackage);
    },
    _notifyChange() {
      changeEmitter.fire();
    },
  } as import("vscode").CodeLensProvider & { _notifyChange(): void };
}
