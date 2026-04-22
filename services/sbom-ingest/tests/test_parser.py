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

    def test_parses_pnpm_lock_inventory(self) -> None:
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
            (root / "pnpm-lock.yaml").write_text(
                textwrap.dedent(
                    """
                    lockfileVersion: '9.0'

                    importers:
                      .:
                        dependencies:
                          react:
                            specifier: ^19.2.0
                            version: 19.2.0
                        devDependencies:
                          vitest:
                            specifier: ^3.0.5
                            version: 3.0.5

                    packages:
                      react@19.2.0:
                        resolution: {integrity: sha512-demo}
                      vitest@3.0.5:
                        resolution: {integrity: sha512-demo}
                      '@types/node@22.10.2':
                        resolution: {integrity: sha512-demo}
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
            ["package.json", "pnpm-lock.yaml"],
        )
        self.assertEqual(component_index[("npm", "react")].version, "19.2.0")
        self.assertEqual(component_index[("npm", "react")].layer, "direct")
        self.assertEqual(component_index[("npm", "vitest")].layer, "build")
        self.assertEqual(component_index[("npm", "@types/node")].layer, "transitive")

    def test_parses_yarn_lock_inventory(self) -> None:
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
            (root / "yarn.lock").write_text(
                textwrap.dedent(
                    """
                    react@^19.2.0:
                      version "19.2.0"
                      resolved "https://registry.yarnpkg.com/react/-/react-19.2.0.tgz"

                    vitest@^3.0.5:
                      version "3.0.5"
                      resolved "https://registry.yarnpkg.com/vitest/-/vitest-3.0.5.tgz"

                    "@types/node@^22.10.2":
                      version "22.10.2"
                      resolved "https://registry.yarnpkg.com/@types/node/-/node-22.10.2.tgz"
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
            ["package.json", "yarn.lock"],
        )
        self.assertEqual(component_index[("npm", "react")].version, "19.2.0")
        self.assertEqual(component_index[("npm", "react")].layer, "direct")
        self.assertEqual(component_index[("npm", "vitest")].layer, "build")
        self.assertEqual(component_index[("npm", "@types/node")].layer, "transitive")

    def test_parses_bun_lock_inventory(self) -> None:
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
            (root / "bun.lock").write_text(
                textwrap.dedent(
                    """
                    {
                      "lockfileVersion": 1,
                      "workspaces": {
                        "": {
                          "dependencies": {
                            "react": "^19.2.0"
                          },
                          "devDependencies": {
                            "vitest": "^3.0.5"
                          }
                        }
                      },
                      "packages": {
                        "react": ["react@19.2.0", "", {}, "sha512-demo"],
                        "vitest": ["vitest@3.0.5", "", {}, "sha512-demo"],
                        "@types/node": ["@types/node@22.10.2", "", {}, "sha512-demo"]
                      }
                    }
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
            ["bun.lock", "package.json"],
        )
        self.assertEqual(component_index[("npm", "react")].version, "19.2.0")
        self.assertEqual(component_index[("npm", "react")].layer, "direct")
        self.assertEqual(component_index[("npm", "vitest")].layer, "build")
        self.assertEqual(component_index[("npm", "@types/node")].layer, "transitive")

    def test_parses_container_inventory_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Dockerfile").write_text(
                textwrap.dedent(
                    """
                    FROM node:22-alpine AS build
                    WORKDIR /app
                    FROM build AS test
                    RUN npm test
                    FROM ghcr.io/acme/runtime-base@sha256:deadbeef
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "infra").mkdir()
            (root / "infra" / "docker-compose.yml").write_text(
                textwrap.dedent(
                    """
                    services:
                      api:
                        image: ghcr.io/acme/api:2026.04.06
                    """
                ).strip(),
                encoding="utf-8",
            )
            (root / "k8s").mkdir()
            (root / "k8s" / "deployment.yaml").write_text(
                textwrap.dedent(
                    """
                    apiVersion: apps/v1
                    kind: Deployment
                    spec:
                      template:
                        spec:
                          containers:
                            - name: worker
                              image: registry.internal:5000/acme/worker:1.2.3
                    """
                ).strip(),
                encoding="utf-8",
            )

            snapshot = analyze_repository(root)

        container_components = [
            component
            for component in snapshot.components
            if component.ecosystem == "container"
        ]
        component_index = {
            (component.name, component.version): component
            for component in container_components
        }

        self.assertEqual(
            sorted(snapshot.source_files),
            ["Dockerfile", "infra/docker-compose.yml", "k8s/deployment.yaml"],
        )
        self.assertEqual(component_index[("node", "22-alpine")].layer, "container")
        self.assertEqual(component_index[("node", "22-alpine")].source_file, "Dockerfile")
        self.assertEqual(
            component_index[("ghcr.io/acme/runtime-base", "sha256:deadbeef")].source_file,
            "Dockerfile",
        )
        self.assertEqual(
            component_index[("ghcr.io/acme/api", "2026.04.06")].source_file,
            "infra/docker-compose.yml",
        )
        self.assertEqual(
            component_index[("registry.internal:5000/acme/worker", "1.2.3")].source_file,
            "k8s/deployment.yaml",
        )
        self.assertTrue(all(component.is_direct for component in container_components))


class MavenParserTests(unittest.TestCase):
    def test_parses_pom_xml_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "pom.xml").write_text(
                textwrap.dedent("""\
                    <?xml version="1.0"?>
                    <project>
                      <dependencies>
                        <dependency>
                          <groupId>org.springframework.boot</groupId>
                          <artifactId>spring-boot-starter-web</artifactId>
                          <version>3.2.0</version>
                        </dependency>
                        <dependency>
                          <groupId>com.fasterxml.jackson.core</groupId>
                          <artifactId>jackson-databind</artifactId>
                          <version>2.16.1</version>
                        </dependency>
                        <dependency>
                          <groupId>org.junit.jupiter</groupId>
                          <artifactId>junit-jupiter</artifactId>
                          <version>5.10.1</version>
                          <scope>test</scope>
                        </dependency>
                      </dependencies>
                    </project>
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        by_name = {c.name: c for c in snapshot.components}
        self.assertIn("org.springframework.boot:spring-boot-starter-web", by_name)
        self.assertEqual(
            by_name["org.springframework.boot:spring-boot-starter-web"].version, "3.2.0"
        )
        self.assertEqual(
            by_name["org.springframework.boot:spring-boot-starter-web"].ecosystem, "maven"
        )
        self.assertTrue(
            by_name["org.springframework.boot:spring-boot-starter-web"].is_direct
        )
        # Test scope should produce a build-layer component
        junit = by_name.get("org.junit.jupiter:junit-jupiter")
        self.assertIsNotNone(junit)
        self.assertEqual(junit.layer, "build")
        self.assertFalse(junit.is_direct)

    def test_pom_xml_with_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "pom.xml").write_text(
                textwrap.dedent("""\
                    <?xml version="1.0"?>
                    <project xmlns="http://maven.apache.org/POM/4.0.0">
                      <dependencies>
                        <dependency>
                          <groupId>io.jsonwebtoken</groupId>
                          <artifactId>jjwt-api</artifactId>
                          <version>0.12.3</version>
                        </dependency>
                      </dependencies>
                    </project>
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        self.assertTrue(
            any(c.name == "io.jsonwebtoken:jjwt-api" for c in snapshot.components)
        )

    def test_pom_xml_property_placeholder_becomes_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "pom.xml").write_text(
                textwrap.dedent("""\
                    <?xml version="1.0"?>
                    <project>
                      <dependencies>
                        <dependency>
                          <groupId>com.example</groupId>
                          <artifactId>my-lib</artifactId>
                          <version>${my.version}</version>
                        </dependency>
                      </dependencies>
                    </project>
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        comp = next(c for c in snapshot.components if "my-lib" in c.name)
        self.assertEqual(comp.version, "unknown")


class GradleParserTests(unittest.TestCase):
    def test_parses_gradle_groovy_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "build.gradle").write_text(
                textwrap.dedent("""\
                    dependencies {
                        implementation 'org.springframework.boot:spring-boot-starter:3.2.0'
                        testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1'
                        api 'com.google.guava:guava:32.1.3-jre'
                    }
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        by_name = {c.name: c for c in snapshot.components}
        spring = by_name.get("org.springframework.boot:spring-boot-starter")
        self.assertIsNotNone(spring)
        self.assertEqual(spring.version, "3.2.0")
        self.assertEqual(spring.ecosystem, "gradle")
        self.assertTrue(spring.is_direct)

        junit = by_name.get("org.junit.jupiter:junit-jupiter")
        self.assertIsNotNone(junit)
        self.assertEqual(junit.layer, "build")

    def test_parses_gradle_kotlin_dsl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "build.gradle.kts").write_text(
                textwrap.dedent("""\
                    dependencies {
                        implementation("io.ktor:ktor-server-core:2.3.6")
                        implementation("io.ktor:ktor-server-netty:2.3.6")
                        runtimeOnly("org.postgresql:postgresql:42.7.1")
                    }
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        names = {c.name for c in snapshot.components}
        self.assertIn("io.ktor:ktor-server-core", names)
        self.assertIn("io.ktor:ktor-server-netty", names)
        self.assertIn("org.postgresql:postgresql", names)


class GemfileParserTests(unittest.TestCase):
    def test_parses_gemfile_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Gemfile.lock").write_text(
                textwrap.dedent("""\
                    GEM
                      remote: https://rubygems.org/
                      specs:
                        rails (7.1.2)
                        activerecord (7.1.2)
                        actionmailer (7.1.2)
                        rack (3.0.8)

                    DEPENDENCIES
                      rails (~> 7.1)
                      rack (~> 3.0)
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        by_name = {c.name: c for c in snapshot.components}
        self.assertIn("rails", by_name)
        self.assertEqual(by_name["rails"].version, "7.1.2")
        self.assertEqual(by_name["rails"].ecosystem, "gem")
        self.assertTrue(by_name["rails"].is_direct)
        # Transitive gems (not in DEPENDENCIES) should not be direct
        activerecord = by_name.get("activerecord")
        self.assertIsNotNone(activerecord)
        self.assertFalse(activerecord.is_direct)

    def test_parses_bare_gemfile_when_lock_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Gemfile").write_text(
                textwrap.dedent("""\
                    source 'https://rubygems.org'

                    gem 'rails', '~> 7.1.0'
                    gem 'pg', '>= 1.5.4'
                    gem 'puma', '~> 6.4'
                    # Development-only
                    gem 'rspec-rails', '~> 6.1'
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        names = {c.name for c in snapshot.components}
        self.assertIn("rails", names)
        self.assertIn("pg", names)
        self.assertIn("puma", names)
        self.assertIn("rspec-rails", names)

    def test_gemfile_lock_takes_precedence_over_gemfile(self) -> None:
        """When both Gemfile and Gemfile.lock exist, lock takes precedence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "Gemfile").write_text("gem 'rails'", encoding="utf-8")
            (root / "Gemfile.lock").write_text(
                textwrap.dedent("""\
                    GEM
                      specs:
                        rails (7.1.2)
                    DEPENDENCIES
                      rails
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        rails_comps = [c for c in snapshot.components if c.name == "rails"]
        # Should have exactly one entry with resolved version
        self.assertEqual(len(rails_comps), 1)
        self.assertEqual(rails_comps[0].version, "7.1.2")
        self.assertTrue(rails_comps[0].source_file.endswith("Gemfile.lock"))


class NuGetParserTests(unittest.TestCase):
    def test_parses_csproj_package_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "MyApp.csproj").write_text(
                textwrap.dedent("""\
                    <Project Sdk="Microsoft.NET.Sdk">
                      <ItemGroup>
                        <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.1" />
                        <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                        <PackageReference Include="Serilog" Version="3.1.1" />
                      </ItemGroup>
                    </Project>
                """),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        by_name = {c.name: c for c in snapshot.components}
        self.assertIn("Newtonsoft.Json", by_name)
        self.assertEqual(by_name["Newtonsoft.Json"].version, "13.0.3")
        self.assertEqual(by_name["Newtonsoft.Json"].ecosystem, "nuget")
        self.assertTrue(by_name["Newtonsoft.Json"].is_direct)

    def test_parses_packages_lock_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "packages.lock.json").write_text(
                json.dumps({
                    "version": 2,
                    "dependencies": {
                        ".NETCoreApp,Version=v8.0": {
                            "Serilog": {"type": "Direct", "resolved": "3.1.1"},
                            "Serilog.Sinks.Console": {"type": "Transitive", "resolved": "5.0.1"},
                        }
                    }
                }),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        by_name = {c.name: c for c in snapshot.components}
        self.assertIn("Serilog", by_name)
        self.assertEqual(by_name["Serilog"].version, "3.1.1")
        self.assertTrue(by_name["Serilog"].is_direct)

        transitive = by_name.get("Serilog.Sinks.Console")
        self.assertIsNotNone(transitive)
        self.assertFalse(transitive.is_direct)
        self.assertEqual(transitive.layer, "transitive")

    def test_packages_lock_takes_precedence_over_csproj(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "MyApp.csproj").write_text(
                '<PackageReference Include="Serilog" Version="3.0.0" />',
                encoding="utf-8",
            )
            (root / "packages.lock.json").write_text(
                json.dumps({
                    "version": 2,
                    "dependencies": {
                        ".NETCoreApp,Version=v8.0": {
                            "Serilog": {"type": "Direct", "resolved": "3.1.1"},
                        }
                    }
                }),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        serilog = [c for c in snapshot.components if c.name == "Serilog"]
        # Should use lock file version
        self.assertEqual(len(serilog), 1)
        self.assertEqual(serilog[0].version, "3.1.1")
        self.assertTrue(serilog[0].source_file.endswith("packages.lock.json"))


class ComposerParserTests(unittest.TestCase):
    def test_parses_composer_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "composer.lock").write_text(
                json.dumps({
                    "packages": [
                        {"name": "symfony/http-kernel", "version": "v7.0.3"},
                        {"name": "laravel/framework", "version": "v10.48.0"},
                    ],
                    "packages-dev": [
                        {"name": "phpunit/phpunit", "version": "10.5.5"},
                    ]
                }),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        by_name = {c.name: c for c in snapshot.components}
        self.assertIn("symfony/http-kernel", by_name)
        self.assertEqual(by_name["symfony/http-kernel"].version, "v7.0.3")
        self.assertEqual(by_name["symfony/http-kernel"].ecosystem, "composer")
        self.assertTrue(by_name["symfony/http-kernel"].is_direct)

        phpunit = by_name.get("phpunit/phpunit")
        self.assertIsNotNone(phpunit)
        self.assertFalse(phpunit.is_direct)
        self.assertEqual(phpunit.layer, "build")

    def test_parses_bare_composer_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "composer.json").write_text(
                json.dumps({
                    "require": {
                        "php": "^8.2",
                        "ext-json": "*",
                        "guzzlehttp/guzzle": "^7.8",
                        "monolog/monolog": "^3.5",
                    },
                    "require-dev": {
                        "phpunit/phpunit": "^10.5",
                    }
                }),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        names = {c.name for c in snapshot.components}
        # php and extensions should be excluded
        self.assertNotIn("php", names)
        self.assertNotIn("ext-json", names)
        # Real packages should be included
        self.assertIn("guzzlehttp/guzzle", names)
        self.assertIn("monolog/monolog", names)
        self.assertIn("phpunit/phpunit", names)

    def test_composer_lock_takes_precedence_over_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "composer.json").write_text(
                json.dumps({"require": {"guzzlehttp/guzzle": "^7.0"}}),
                encoding="utf-8",
            )
            (root / "composer.lock").write_text(
                json.dumps({
                    "packages": [{"name": "guzzlehttp/guzzle", "version": "7.8.1"}],
                    "packages-dev": []
                }),
                encoding="utf-8",
            )
            snapshot = analyze_repository(root)

        guzzle = [c for c in snapshot.components if c.name == "guzzlehttp/guzzle"]
        self.assertEqual(len(guzzle), 1)
        self.assertEqual(guzzle[0].version, "7.8.1")
        self.assertTrue(guzzle[0].source_file.endswith("composer.lock"))


if __name__ == "__main__":
    unittest.main()
