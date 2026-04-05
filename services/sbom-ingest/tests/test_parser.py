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
    def test_parses_package_lock_and_poetry_inventory(self) -> None:
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
                    [tool.poetry]
                    name = "demo"
                    version = "0.1.0"

                    [tool.poetry.dependencies]
                    python = "^3.12"
                    fastapi = "^0.117.1"
                    httpx = "0.28.1"

                    [tool.poetry.group.dev.dependencies]
                    pytest = "^8.3.4"
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "poetry.lock").write_text(
                textwrap.dedent(
                    """
                    version = "2.1"

                    [[package]]
                    name = "fastapi"
                    version = "0.117.1"

                    [[package]]
                    name = "httpx"
                    version = "0.28.1"

                    [[package]]
                    name = "pytest"
                    version = "8.3.4"

                    [[package]]
                    name = "starlette"
                    version = "0.38.6"
                    """
                ).strip(),
                encoding="utf-8",
            )

            snapshot = analyze_repository(root)

        component_index = {
            (component.ecosystem, component.name): component
            for component in snapshot.components
        }

        self.assertEqual(
            sorted(snapshot.source_files),
            ["package-lock.json", "package.json", "poetry.lock", "pyproject.toml"],
        )
        self.assertEqual(component_index[("npm", "react")].version, "19.2.0")
        self.assertEqual(component_index[("npm", "react")].layer, "direct")
        self.assertEqual(component_index[("npm", "vitest")].layer, "build")
        self.assertEqual(component_index[("npm", "@types/node")].layer, "transitive")
        self.assertEqual(component_index[("pypi", "fastapi")].layer, "direct")
        self.assertEqual(component_index[("pypi", "pytest")].layer, "build")
        self.assertEqual(component_index[("pypi", "starlette")].layer, "transitive")
        self.assertEqual(component_index[("pypi", "fastapi")].source_file, "poetry.lock")

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

    def test_parses_pipfile_lock_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Pipfile.lock").write_text(
                json.dumps(
                    {
                        "_meta": {"hash": {"sha256": "demo"}},
                        "default": {
                            "requests": {"version": "==2.32.3"},
                            "urllib3": {"version": "==2.2.3"},
                        },
                        "develop": {
                            "pytest": {"version": "==8.3.4"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            snapshot = analyze_repository(root)

        component_index = {
            (component.ecosystem, component.name): component
            for component in snapshot.components
        }

        self.assertEqual(snapshot.source_files, ["Pipfile.lock"])
        self.assertEqual(component_index[("pypi", "requests")].version, "2.32.3")
        self.assertEqual(component_index[("pypi", "requests")].layer, "direct")
        self.assertEqual(component_index[("pypi", "pytest")].layer, "build")

    def test_parses_go_and_cargo_lockfiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "go.mod").write_text(
                textwrap.dedent(
                    """
                    module example.com/demo

                    go 1.23

                    require (
                        github.com/gin-gonic/gin v1.10.0
                        golang.org/x/text v0.20.0 // indirect
                    )
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "go.sum").write_text(
                textwrap.dedent(
                    """
                    github.com/gin-gonic/gin v1.10.0 h1:abc
                    github.com/gin-gonic/gin v1.10.0/go.mod h1:def
                    golang.org/x/text v0.20.0 h1:ghi
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "Cargo.toml").write_text(
                textwrap.dedent(
                    """
                    [package]
                    name = "demo"
                    version = "0.1.0"
                    edition = "2021"

                    [dependencies]
                    serde = "1.0"

                    [dev-dependencies]
                    tokio = { version = "1.42", features = ["rt"] }
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                textwrap.dedent(
                    """
                    version = 3

                    [[package]]
                    name = "demo"
                    version = "0.1.0"

                    [[package]]
                    name = "serde"
                    version = "1.0.217"
                    source = "registry+https://github.com/rust-lang/crates.io-index"

                    [[package]]
                    name = "tokio"
                    version = "1.42.0"
                    source = "registry+https://github.com/rust-lang/crates.io-index"

                    [[package]]
                    name = "bytes"
                    version = "1.9.0"
                    source = "registry+https://github.com/rust-lang/crates.io-index"
                    """
                ).strip(),
                encoding="utf-8",
            )

            snapshot = analyze_repository(root)

        component_index = {
            (component.ecosystem, component.name): component
            for component in snapshot.components
        }

        self.assertEqual(
            sorted(snapshot.source_files),
            ["Cargo.lock", "Cargo.toml", "go.mod", "go.sum"],
        )
        self.assertEqual(component_index[("gomod", "github.com/gin-gonic/gin")].layer, "direct")
        self.assertEqual(component_index[("gomod", "golang.org/x/text")].layer, "transitive")
        self.assertEqual(component_index[("cargo", "serde")].layer, "direct")
        self.assertEqual(component_index[("cargo", "tokio")].layer, "build")
        self.assertEqual(component_index[("cargo", "bytes")].layer, "transitive")


if __name__ == "__main__":
    unittest.main()
