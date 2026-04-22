"""
Import Graph Analyzer — dead code + unused dependency detection.

Builds a directed import graph for JS/TS and Python repositories,
then finds:
  1. Unused packages (in package.json / requirements.txt but never imported)
  2. Import-only-in-tests packages (candidates for devDependency promotion)
  3. Entry-point unreachable modules (dead code — files with no in-edges)

Algorithm:
  - Nodes: source files
  - Edges: import/require statements (A imports B → A → B)
  - Sources: entry point files (index.js, main.py, etc.)
  - Dead code: files with in-degree 0 AND not entry points
  - Unused deps: packages declared in manifest but with 0 import edges

Spec §3.7.2 targets:
  - "Functions defined but never called across the entire codebase"
  - "Packages imported but only used in test files → devDependency candidates"
  - "Single-use imports in a location that could be replaced with native code"
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ── Constants ─────────────────────────────────────────────────────────────────

IGNORED_DIRS = {
    ".git", "node_modules", ".turbo", ".next", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".pytest_cache", "coverage",
}

TEST_PATH_INDICATORS = {
    "test", "tests", "spec", "specs", "__tests__", "e2e", "fixtures",
}

JS_IMPORT_PATTERNS = [
    re.compile(r"""(?:import|require)\s*(?:\(?\s*)?['"]([^'"]+)['"]"""),
    re.compile(r"""from\s+['"]([^'"]+)['"]"""),
]

ENTRY_POINT_NAMES = {
    "index.js", "index.ts", "index.jsx", "index.tsx",
    "main.js", "main.ts", "main.py", "app.js", "app.ts", "server.js",
    "cli.js", "cli.ts",
}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ImportEdge:
    source_file: str
    imported_module: str
    is_dynamic: bool = False   # import() or __import__


@dataclass
class AttackSurfaceReport:
    repository_path: str

    # Unused packages — in manifest but never imported anywhere
    unused_packages: list[str] = field(default_factory=list)
    # Packages only used in test files → devDependency candidates
    test_only_packages: list[str] = field(default_factory=list)
    # Source files with no inbound imports (possible dead code)
    unreachable_files: list[str] = field(default_factory=list)
    # Files with very few callers (low importance, high risk surface)
    low_connectivity_files: list[str] = field(default_factory=list)
    # Packages imported once from a non-test file (candidate for removal)
    single_use_packages: list[str] = field(default_factory=list)

    total_files_analyzed: int = 0
    total_packages_analyzed: int = 0
    edge_count: int = 0

    summary: str = ""

    def attack_surface_reduction_score(self) -> float:
        """
        0.0–1.0 estimate of how much attack surface could be reduced
        by acting on all findings. Higher = more potential reduction.
        """
        if self.total_packages_analyzed == 0:
            return 0.0
        reducible = len(self.unused_packages) + len(self.test_only_packages) + len(self.single_use_packages)
        return min(1.0, reducible / max(self.total_packages_analyzed, 1))


# ── JavaScript / TypeScript import extraction ────────────────────────────────

def _extract_js_imports(file_path: Path, root: Path) -> list[ImportEdge]:
    """Extract import/require statements from a JS/TS file."""
    edges: list[ImportEdge] = []
    source_rel = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return edges

    for pattern in JS_IMPORT_PATTERNS:
        for match in pattern.finditer(content):
            module = match.group(1)
            if not module:
                continue
            edges.append(ImportEdge(
                source_file=source_rel,
                imported_module=module,
                is_dynamic="import(" in content[max(0, match.start() - 8):match.start()],
            ))

    return edges


def _extract_python_imports(file_path: Path, root: Path) -> list[ImportEdge]:
    """Extract import statements from a Python file using AST."""
    edges: list[ImportEdge] = []
    source_rel = str(file_path.relative_to(root))

    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError):
        return edges

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                edges.append(ImportEdge(source_file=source_rel, imported_module=alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                edges.append(ImportEdge(source_file=source_rel, imported_module=node.module))
        elif isinstance(node, ast.Call):
            # __import__("mod") or importlib.import_module("mod")
            if (isinstance(node.func, ast.Name) and node.func.id == "__import__"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                edges.append(ImportEdge(
                    source_file=source_rel,
                    imported_module=str(node.args[0].value),
                    is_dynamic=True,
                ))

    return edges


# ── Package manifest readers ──────────────────────────────────────────────────

def _read_npm_packages(root: Path) -> dict[str, str]:
    """Read direct + dev dependencies from package.json."""
    pkg_path = root / "package.json"
    if not pkg_path.is_file():
        return {}
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    packages: dict[str, str] = {}
    for group in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in (data.get(group) or {}).items():
            packages[name.lower()] = str(version)
    return packages


def _read_python_packages(root: Path) -> dict[str, str]:
    """Read packages from requirements.txt / pyproject.toml."""
    packages: dict[str, str] = {}

    req_path = root / "requirements.txt"
    if req_path.is_file():
        for line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name = re.split(r"[>=<!\[;]", line)[0].strip().lower()
                if name:
                    packages[name] = "*"

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        # Simple TOML parsing for [project.dependencies]
        content = pyproject_path.read_text(encoding="utf-8", errors="ignore")
        in_deps = False
        for line in content.splitlines():
            if "[project.dependencies]" in line or "[tool.poetry.dependencies]" in line:
                in_deps = True
                continue
            if in_deps and line.startswith("["):
                in_deps = False
            if in_deps and "=" in line:
                name = line.split("=")[0].strip().strip('"').lower()
                if name and not name.startswith("#"):
                    packages[name] = "*"

    return packages


# ── File iterator ─────────────────────────────────────────────────────────────

def _iter_source_files(root: Path) -> Iterator[Path]:
    JS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
    PY_EXTS = {".py"}
    ALL_EXTS = JS_EXTS | PY_EXTS

    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in ALL_EXTS:
            yield path


def _is_test_file(relative_path: str) -> bool:
    parts = set(Path(relative_path).parts)
    if parts & TEST_PATH_INDICATORS:
        return True
    stem = Path(relative_path).stem.lower()
    return (
        stem.startswith("test_")
        or stem.endswith("_test")
        or stem.endswith(".test")
        or stem.endswith(".spec")
        or ".test." in relative_path
        or ".spec." in relative_path
    )


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_attack_surface(root_path: str | Path) -> AttackSurfaceReport:
    """
    Analyze the repository for attack surface reduction opportunities.

    Returns an AttackSurfaceReport with unused packages, dead code,
    test-only packages, and single-use imports.
    """
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root}")

    report = AttackSurfaceReport(repository_path=str(root))

    # Detect ecosystem
    has_npm = (root / "package.json").is_file()
    has_python = (root / "requirements.txt").is_file() or (root / "pyproject.toml").is_file()

    # Read declared packages
    declared: dict[str, str] = {}
    if has_npm:
        declared.update(_read_npm_packages(root))
    if has_python:
        declared.update(_read_python_packages(root))

    report.total_packages_analyzed = len(declared)

    # Collect all imports
    all_edges: list[ImportEdge] = []
    source_files: list[str] = []

    for file_path in _iter_source_files(root):
        rel = str(file_path.relative_to(root))
        source_files.append(rel)

        if file_path.suffix.lower() in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
            all_edges.extend(_extract_js_imports(file_path, root))
        elif file_path.suffix == ".py":
            all_edges.extend(_extract_python_imports(file_path, root))

    report.total_files_analyzed = len(source_files)
    report.edge_count = len(all_edges)

    # Normalize imported module names to package names
    def module_to_package(module: str) -> str:
        # Strip relative paths and sub-module paths
        if module.startswith("."):
            return ""  # relative import
        return module.split("/")[0].split(".")[0].lower()

    # Build: package → set of importing files (split by test/non-test)
    pkg_prod_importers: dict[str, set[str]] = {pkg: set() for pkg in declared}
    pkg_test_importers: dict[str, set[str]] = {pkg: set() for pkg in declared}

    for edge in all_edges:
        pkg = module_to_package(edge.imported_module)
        if not pkg or pkg not in declared:
            continue
        if _is_test_file(edge.source_file):
            pkg_test_importers[pkg].add(edge.source_file)
        else:
            pkg_prod_importers[pkg].add(edge.source_file)

    # Classify packages
    unused: list[str] = []
    test_only: list[str] = []
    single_use: list[str] = []

    for pkg in declared:
        prod_count = len(pkg_prod_importers[pkg])
        test_count = len(pkg_test_importers[pkg])

        if prod_count == 0 and test_count == 0:
            unused.append(pkg)
        elif prod_count == 0 and test_count > 0:
            test_only.append(pkg)
        elif prod_count == 1:
            single_use.append(pkg)

    report.unused_packages = sorted(unused)
    report.test_only_packages = sorted(test_only)
    report.single_use_packages = sorted(single_use)

    # Find unreachable files (in-degree 0, not entry points)
    all_imported_rels: set[str] = set()
    for edge in all_edges:
        if not edge.imported_module.startswith("."):
            continue  # only track relative imports for file-level reachability
        # Resolve relative import to file path
        src_dir = Path(edge.source_file).parent
        candidate = str((src_dir / edge.imported_module).resolve())
        all_imported_rels.add(candidate)

    # Mark files never imported and not entry points as potentially unreachable
    entry_points = {f for f in source_files if Path(f).name in ENTRY_POINT_NAMES}
    unreachable: list[str] = []
    for rel_file in source_files:
        if Path(rel_file).name in ENTRY_POINT_NAMES:
            continue
        if _is_test_file(rel_file):
            continue
        if rel_file not in all_imported_rels and not any(rel_file in imp for imp in all_imported_rels):
            unreachable.append(rel_file)

    # Limit to most impactful (not everything with 0 in-degree is dead code)
    report.unreachable_files = sorted(unreachable)[:50]

    # Build summary
    total_actionable = len(unused) + len(test_only) + len(single_use) + len(report.unreachable_files)
    if total_actionable == 0:
        report.summary = (
            f"No attack surface reduction opportunities found across "
            f"{len(source_files)} files and {len(declared)} packages."
        )
    else:
        parts = []
        if unused:
            parts.append(f"{len(unused)} unused package{'s' if len(unused) > 1 else ''}")
        if test_only:
            parts.append(f"{len(test_only)} test-only package{'s' if len(test_only) > 1 else ''}")
        if single_use:
            parts.append(f"{len(single_use)} single-use package{'s' if len(single_use) > 1 else ''}")
        if report.unreachable_files:
            parts.append(f"{len(report.unreachable_files)} potentially unreachable file{'s' if len(report.unreachable_files) > 1 else ''}")
        report.summary = f"Found {' · '.join(parts)} — reducing these shrinks the attack surface without changing functionality."

    return report
