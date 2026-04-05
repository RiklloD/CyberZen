from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentinel_sbom_ingest.parser import analyze_repository


class AnalyzeRepositoryTests(unittest.TestCase):
    def test_parses_package_lock_and_pyproject_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {"react": "^19.2.0"},
                        "devDependencies": {"vitest": "^3.0.5"},
                    }
                ),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {
                                "dependencies": {"react": "^19.2.0"},
                                "devDependencies": {"vitest": "^3.0.5"},
                            },
                            "node_modules/react": {"version": "19.2.0"},
                            "node_modules/vitest": {
                                "version": "3.0.5",
                                "dev": True,
                            },
                            "node_modules/@types/node": {
                                "version": "22.10.2",
                                "dev": True,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                textwrap.dedent(
                    """
                    [project]
                    dependencies = ["fastapi>=0.117", "httpx==0.28.1"]

                    [project.optional-dependencies]
                    dev = ["pytest>=8.0"]
                    """
                ).strip(),
                encoding="utf-8",
            )

            snapshot = analyze_repository(root)

        component_index = {
            (component.ecosystem, component.name): component
            for component in snapshot.components
        }

        self.assertEqual(sorted(snapshot.source_files), ["package-lock.json", "package.json", "pyproject.toml"])
        self.assertEqual(component_index[("npm", "react")].version, "19.2.0")
        self.assertEqual(component_index[("npm", "react")].layer, "direct")
        self.assertEqual(component_index[("npm", "vitest")].layer, "build")
        self.assertEqual(component_index[("npm", "@types/node")].layer, "transitive")
        self.assertEqual(component_index[("pypi", "fastapi")].layer, "direct")
        self.assertEqual(component_index[("pypi", "pytest")].layer, "build")

    def test_parses_requirements_when_no_pyproject_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "requirements.txt").write_text(
                textwrap.dedent(
                    """
                    # runtime
                    requests==2.32.3
                    httpx>=0.28.0
                    """
                ).strip(),
                encoding="utf-8",
            )

            snapshot = analyze_repository(root)

        names = [component.name for component in snapshot.components]
        self.assertEqual(snapshot.source_files, ["requirements.txt"])
        self.assertEqual(names, ["httpx", "requests"])


if __name__ == "__main__":
    unittest.main()
