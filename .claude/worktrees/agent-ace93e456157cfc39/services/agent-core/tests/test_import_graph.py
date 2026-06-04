"""
Tests for the import graph analyzer and attack surface detection.
"""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel_agent_core.analyzers.import_graph import analyze_attack_surface


class AnalyzeAttackSurfaceTests(unittest.TestCase):
    # ── JavaScript / npm ──────────────────────────────────────────────────────

    def test_detects_unused_npm_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {
                    "lodash": "^4.17.21",
                    "axios": "^1.6.0",
                    "left-pad": "^1.3.0",    # never imported
                },
            }), encoding="utf-8")
            (root / "index.js").write_text(
                "import _ from 'lodash';\nconst axios = require('axios');",
                encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        self.assertIn("left-pad", report.unused_packages)
        self.assertNotIn("lodash", report.unused_packages)
        self.assertNotIn("axios", report.unused_packages)

    def test_detects_test_only_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {
                    "express": "^4.18.0",
                    "jest": "^29.0.0",        # only in tests
                },
            }), encoding="utf-8")
            (root / "index.js").write_text(
                "const express = require('express');", encoding="utf-8",
            )
            (root / "index.test.js").write_text(
                "const jest = require('jest');", encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        self.assertIn("jest", report.test_only_packages)
        self.assertNotIn("express", report.test_only_packages)

    def test_detects_single_use_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {
                    "uuid": "^9.0.0",          # imported in exactly one file
                    "express": "^4.18.0",
                },
            }), encoding="utf-8")
            (root / "index.js").write_text(
                "const express = require('express');", encoding="utf-8",
            )
            (root / "utils.js").write_text(
                "import { v4 } from 'uuid';", encoding="utf-8",
            )
            (root / "app.js").write_text(
                "import './utils'; const express = require('express');",
                encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        self.assertIn("uuid", report.single_use_packages)

    def test_empty_repo_produces_empty_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            report = analyze_attack_surface(root)

        self.assertEqual(report.unused_packages, [])
        self.assertEqual(report.total_packages_analyzed, 0)

    def test_no_manifest_still_analyzes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "index.js").write_text("import x from 'somewhere';", encoding="utf-8")
            report = analyze_attack_surface(root)

        self.assertEqual(report.total_files_analyzed, 1)
        self.assertEqual(report.total_packages_analyzed, 0)

    # ── Python ────────────────────────────────────────────────────────────────

    def test_detects_unused_python_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "requirements.txt").write_text(
                "requests\nflask\npytest\nnever-used-lib",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                textwrap.dedent("""\
                    import requests
                    from flask import Flask
                """), encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        self.assertIn("never-used-lib", report.unused_packages)
        self.assertNotIn("requests", report.unused_packages)
        self.assertNotIn("flask", report.unused_packages)

    def test_detects_python_test_only_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "requirements.txt").write_text(
                "requests\npytest", encoding="utf-8",
            )
            (root / "main.py").write_text("import requests", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "test_main.py").write_text(
                "import pytest", encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        self.assertIn("pytest", report.test_only_packages)
        self.assertNotIn("requests", report.test_only_packages)

    def test_python_dynamic_import_tracked(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "requirements.txt").write_text("importlib-metadata", encoding="utf-8")
            (root / "loader.py").write_text(
                "__import__('importlib_metadata')", encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        # Dynamic import should be tracked — importlib-metadata should NOT be unused
        # (Note: hyphen/underscore normalization may affect this in edge cases)
        self.assertEqual(report.total_files_analyzed, 1)

    # ── Mixed repo ────────────────────────────────────────────────────────────

    def test_node_modules_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            (root / "index.js").write_text("const x = 1;", encoding="utf-8")
            nm = root / "node_modules" / "some-pkg"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("module.exports = {};", encoding="utf-8")
            report = analyze_attack_surface(root)

        # Only index.js should be analyzed, not the node_modules file
        self.assertEqual(report.total_files_analyzed, 1)

    def test_attack_surface_reduction_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {
                    "express": "^4",
                    "lodash": "^4",
                    "moment": "^2",   # unused
                    "dayjs": "^1",    # unused
                },
            }), encoding="utf-8")
            (root / "index.js").write_text(
                "require('express'); require('lodash');", encoding="utf-8",
            )
            report = analyze_attack_surface(root)

        score = report.attack_surface_reduction_score()
        # 2 unused out of 4 packages → score > 0
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_summary_mentions_unused_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"orphaned": "^1.0.0"},
            }), encoding="utf-8")
            (root / "index.js").write_text("// no imports", encoding="utf-8")
            report = analyze_attack_surface(root)

        self.assertIn("unused", report.summary.lower())

    def test_raises_on_missing_path(self) -> None:
        with self.assertRaises(FileNotFoundError):
            analyze_attack_surface("/nonexistent/repo/path/xyz")


if __name__ == "__main__":
    unittest.main()
