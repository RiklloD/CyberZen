from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .models import InventoryComponent, InventorySnapshot

REQUIREMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*([<>=!~]{1,2}\s*[^;,\s]+)?"
)
GO_REQUIRE_PATTERN = re.compile(r"^([^\s]+)\s+([^\s]+?)(?:\s*//\s*(.+))?$")
NODE_DIRECT_GROUPS = ("dependencies", "optionalDependencies", "peerDependencies")
NODE_BUILD_GROUPS = ("devDependencies",)
CARGO_DIRECT_GROUPS = ("dependencies",)
CARGO_BUILD_GROUPS = ("dev-dependencies", "build-dependencies")


def _normalize_name(raw_name: str) -> str:
    return raw_name.strip().lower().replace("_", "-")


def _coerce_version(raw_version: object) -> str:
    if raw_version is None:
        return "unknown"

    version = str(raw_version).strip()
    return version if version else "unknown"


def _coerce_locked_version(raw_version: object) -> str:
    version = _coerce_version(raw_version)
    if version.startswith("=="):
        return version[2:]

    return version


def _parse_requirement_entry(entry: str) -> tuple[str, str] | None:
    line = entry.strip()

    if not line or line.startswith("#") or line.startswith(("-", ".")):
        return None

    match = REQUIREMENT_PATTERN.match(line)
    if not match:
        return None

    name = _normalize_name(match.group(1))
    version = _coerce_version(match.group(2).replace(" ", "") if match.group(2) else None)
    return name, version


def _iter_nested_lock_dependencies(
    dependency_map: dict[str, object],
    direct_names: set[str],
    seen: set[tuple[str, str, str]],
    source_file: str,
) -> list[InventoryComponent]:
    components: list[InventoryComponent] = []

    def visit(entries: dict[str, object], parent_name: str | None = None) -> None:
        for raw_name, raw_value in entries.items():
            if not isinstance(raw_value, dict):
                continue

            name = _normalize_name(raw_name)
            version = _coerce_version(raw_value.get("version"))
            is_direct = name in direct_names
            layer = "direct" if is_direct else "transitive"
            signature = ("npm", name, version)

            if signature not in seen:
                seen.add(signature)
                dependents = [parent_name] if parent_name else []
                components.append(
                    InventoryComponent(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        layer=layer,
                        is_direct=is_direct,
                        source_file=source_file,
                        dependents=dependents,
                    )
                )

            nested = raw_value.get("dependencies")
            if isinstance(nested, dict):
                visit(nested, name)

    visit(dependency_map)
    return components


def _parse_package_json(package_json_path: Path) -> tuple[list[InventoryComponent], set[str], set[str]]:
    package_data = json.loads(package_json_path.read_text(encoding="utf-8"))
    source_file = package_json_path.name
    components: list[InventoryComponent] = []
    direct_names: set[str] = set()
    build_names: set[str] = set()

    for group_name in NODE_DIRECT_GROUPS:
        entries = package_data.get(group_name, {})
        if not isinstance(entries, dict):
            continue

        for raw_name, raw_version in entries.items():
            name = _normalize_name(raw_name)
            direct_names.add(name)
            components.append(
                InventoryComponent(
                    name=name,
                    version=_coerce_version(raw_version),
                    ecosystem="npm",
                    layer="direct",
                    is_direct=True,
                    source_file=source_file,
                )
            )

    for group_name in NODE_BUILD_GROUPS:
        entries = package_data.get(group_name, {})
        if not isinstance(entries, dict):
            continue

        for raw_name, raw_version in entries.items():
            name = _normalize_name(raw_name)
            build_names.add(name)
            components.append(
                InventoryComponent(
                    name=name,
                    version=_coerce_version(raw_version),
                    ecosystem="npm",
                    layer="build",
                    is_direct=True,
                    source_file=source_file,
                )
            )

    return components, direct_names, build_names


def _derive_lock_package_name(package_path: str, package_data: dict[str, object]) -> str | None:
    if isinstance(package_data.get("name"), str):
        return _normalize_name(str(package_data["name"]))

    if "node_modules/" not in package_path:
        return None

    return _normalize_name(package_path.rsplit("node_modules/", maxsplit=1)[-1])


def _parse_package_lock(
    package_lock_path: Path,
    direct_names: set[str],
    build_names: set[str],
) -> list[InventoryComponent]:
    lock_data = json.loads(package_lock_path.read_text(encoding="utf-8"))
    source_file = package_lock_path.name
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()

    packages = lock_data.get("packages")
    if isinstance(packages, dict):
        for package_path, raw_package_data in packages.items():
            if package_path == "" or not isinstance(raw_package_data, dict):
                continue

            name = _derive_lock_package_name(package_path, raw_package_data)
            if not name:
                continue

            version = _coerce_version(raw_package_data.get("version"))
            is_direct = name in direct_names or name in build_names
            if name in build_names:
                layer = "build"
            elif is_direct:
                layer = "direct"
            else:
                layer = "transitive"

            signature = ("npm", name, version)
            if signature in seen:
                continue

            seen.add(signature)
            components.append(
                InventoryComponent(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    layer=layer,
                    is_direct=is_direct,
                    source_file=source_file,
                )
            )

        return components

    dependencies = lock_data.get("dependencies")
    if isinstance(dependencies, dict):
        return _iter_nested_lock_dependencies(
            dependencies,
            direct_names | build_names,
            seen,
            source_file,
        )

    return components


def _parse_requirements_txt(requirements_path: Path) -> list[InventoryComponent]:
    components: list[InventoryComponent] = []

    for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_requirement_entry(raw_line)
        if not parsed:
            continue

        name, version = parsed
        components.append(
            InventoryComponent(
                name=name,
                version=version,
                ecosystem="pypi",
                layer="direct",
                is_direct=True,
                source_file=requirements_path.name,
            )
        )

    return components


def _parse_pipfile_lock(pipfile_lock_path: Path) -> list[InventoryComponent]:
    lock_data = json.loads(pipfile_lock_path.read_text(encoding="utf-8"))
    source_file = pipfile_lock_path.name
    components: list[InventoryComponent] = []

    for group_name, layer in (("default", "direct"), ("develop", "build")):
        entries = lock_data.get(group_name, {})
        if not isinstance(entries, dict):
            continue

        for raw_name, raw_value in entries.items():
            if not isinstance(raw_value, dict):
                continue

            version = raw_value.get("version") or raw_value.get("ref")
            components.append(
                InventoryComponent(
                    name=_normalize_name(raw_name),
                    version=_coerce_locked_version(version),
                    ecosystem="pypi",
                    layer=layer,
                    is_direct=True,
                    source_file=source_file,
                )
            )

    return components


def _parse_pyproject_dependencies(
    pyproject_path: Path,
) -> tuple[list[InventoryComponent], set[str], set[str]]:
    pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    source_file = pyproject_path.name
    components: list[InventoryComponent] = []
    direct_names: set[str] = set()
    build_names: set[str] = set()
    project_table = pyproject_data.get("project", {})

    if isinstance(project_table, dict):
        for entry in project_table.get("dependencies", []):
            if not isinstance(entry, str):
                continue

            parsed = _parse_requirement_entry(entry)
            if not parsed:
                continue

            name, version = parsed
            direct_names.add(name)
            components.append(
                InventoryComponent(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    layer="direct",
                    is_direct=True,
                    source_file=source_file,
                )
            )

        optional_dependencies = project_table.get("optional-dependencies", {})
        if isinstance(optional_dependencies, dict):
            for group_entries in optional_dependencies.values():
                if not isinstance(group_entries, list):
                    continue

                for entry in group_entries:
                    if not isinstance(entry, str):
                        continue

                    parsed = _parse_requirement_entry(entry)
                    if not parsed:
                        continue

                    name, version = parsed
                    build_names.add(name)
                    components.append(
                        InventoryComponent(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            layer="build",
                            is_direct=True,
                            source_file=source_file,
                        )
                    )

    poetry_table = pyproject_data.get("tool", {}).get("poetry", {})
    if isinstance(poetry_table, dict):
        for group_name, layer in (("dependencies", "direct"), ("group", "build")):
            if group_name == "dependencies":
                entries = poetry_table.get(group_name, {})
                if not isinstance(entries, dict):
                    continue

                for raw_name, raw_value in entries.items():
                    if raw_name == "python":
                        continue

                    name = _normalize_name(raw_name)
                    version = raw_value.get("version") if isinstance(raw_value, dict) else raw_value
                    direct_names.add(name)
                    components.append(
                        InventoryComponent(
                            name=name,
                            version=_coerce_version(version),
                            ecosystem="pypi",
                            layer=layer,
                            is_direct=True,
                            source_file=source_file,
                        )
                    )
            else:
                groups = poetry_table.get("group", {})
                if not isinstance(groups, dict):
                    continue

                for raw_group in groups.values():
                    if not isinstance(raw_group, dict):
                        continue

                    dependencies = raw_group.get("dependencies", {})
                    if not isinstance(dependencies, dict):
                        continue

                    for raw_name, raw_value in dependencies.items():
                        if raw_name == "python":
                            continue

                        name = _normalize_name(raw_name)
                        version = (
                            raw_value.get("version")
                            if isinstance(raw_value, dict)
                            else raw_value
                        )
                        build_names.add(name)
                        components.append(
                            InventoryComponent(
                                name=name,
                                version=_coerce_version(version),
                                ecosystem="pypi",
                                layer=layer,
                                is_direct=True,
                                source_file=source_file,
                            )
                        )

    return components, direct_names, build_names


def _parse_poetry_lock(
    poetry_lock_path: Path,
    direct_names: set[str],
    build_names: set[str],
) -> list[InventoryComponent]:
    lock_data = tomllib.loads(poetry_lock_path.read_text(encoding="utf-8"))
    source_file = poetry_lock_path.name
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()

    packages = lock_data.get("package", [])
    if not isinstance(packages, list):
        return components

    for raw_package in packages:
        if not isinstance(raw_package, dict):
            continue

        raw_name = raw_package.get("name")
        if not isinstance(raw_name, str):
            continue

        name = _normalize_name(raw_name)
        version = _coerce_locked_version(raw_package.get("version"))
        is_direct = name in direct_names or name in build_names
        if name in build_names:
            layer = "build"
        elif name in direct_names:
            layer = "direct"
        else:
            layer = "transitive"

        signature = ("pypi", name, version)
        if signature in seen:
            continue

        seen.add(signature)
        components.append(
            InventoryComponent(
                name=name,
                version=version,
                ecosystem="pypi",
                layer=layer,
                is_direct=is_direct,
                source_file=source_file,
            )
        )

    return components


def _parse_go_mod(
    go_mod_path: Path,
) -> tuple[list[InventoryComponent], set[str], set[str]]:
    components: list[InventoryComponent] = []
    direct_names: set[str] = set()
    indirect_names: set[str] = set()
    in_require_block = False

    for raw_line in go_mod_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("//"):
            continue

        if line == "require (":
            in_require_block = True
            continue

        if in_require_block and line == ")":
            in_require_block = False
            continue

        entry = None
        if in_require_block:
            entry = line
        elif line.startswith("require "):
            entry = line.removeprefix("require ").strip()

        if not entry:
            continue

        match = GO_REQUIRE_PATTERN.match(entry)
        if not match:
            continue

        name = _normalize_name(match.group(1))
        version = _coerce_locked_version(match.group(2))
        comment = (match.group(3) or "").strip().lower()
        is_indirect = "indirect" in comment

        if is_indirect:
            indirect_names.add(name)
        else:
            direct_names.add(name)

        components.append(
            InventoryComponent(
                name=name,
                version=version,
                ecosystem="gomod",
                layer="transitive" if is_indirect else "direct",
                is_direct=not is_indirect,
                source_file=go_mod_path.name,
            )
        )

    return components, direct_names, indirect_names


def _parse_go_sum(
    go_sum_path: Path,
    direct_names: set[str],
) -> list[InventoryComponent]:
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()

    for raw_line in go_sum_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        name = _normalize_name(parts[0])
        version = _coerce_locked_version(parts[1].removesuffix("/go.mod"))
        signature = ("gomod", name, version)
        if signature in seen:
            continue

        seen.add(signature)
        is_direct = name in direct_names
        components.append(
            InventoryComponent(
                name=name,
                version=version,
                ecosystem="gomod",
                layer="direct" if is_direct else "transitive",
                is_direct=is_direct,
                source_file=go_sum_path.name,
            )
        )

    return components


def _extract_cargo_dependency_version(raw_value: object) -> object:
    if isinstance(raw_value, dict):
        for key in ("version", "tag", "branch", "rev", "path"):
            if key in raw_value:
                return raw_value[key]

        if raw_value.get("workspace") is True:
            return "workspace"

    return raw_value


def _parse_cargo_toml(
    cargo_toml_path: Path,
) -> tuple[list[InventoryComponent], set[str], set[str]]:
    cargo_data = tomllib.loads(cargo_toml_path.read_text(encoding="utf-8"))
    source_file = cargo_toml_path.name
    components: list[InventoryComponent] = []
    direct_names: set[str] = set()
    build_names: set[str] = set()

    for group_name in CARGO_DIRECT_GROUPS:
        entries = cargo_data.get(group_name, {})
        if not isinstance(entries, dict):
            continue

        for raw_name, raw_value in entries.items():
            name = _normalize_name(raw_name)
            direct_names.add(name)
            components.append(
                InventoryComponent(
                    name=name,
                    version=_coerce_version(_extract_cargo_dependency_version(raw_value)),
                    ecosystem="cargo",
                    layer="direct",
                    is_direct=True,
                    source_file=source_file,
                )
            )

    for group_name in CARGO_BUILD_GROUPS:
        entries = cargo_data.get(group_name, {})
        if not isinstance(entries, dict):
            continue

        for raw_name, raw_value in entries.items():
            name = _normalize_name(raw_name)
            build_names.add(name)
            components.append(
                InventoryComponent(
                    name=name,
                    version=_coerce_version(_extract_cargo_dependency_version(raw_value)),
                    ecosystem="cargo",
                    layer="build",
                    is_direct=True,
                    source_file=source_file,
                )
            )

    return components, direct_names, build_names


def _parse_cargo_lock(
    cargo_lock_path: Path,
    direct_names: set[str],
    build_names: set[str],
) -> list[InventoryComponent]:
    lock_data = tomllib.loads(cargo_lock_path.read_text(encoding="utf-8"))
    source_file = cargo_lock_path.name
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()
    packages = lock_data.get("package", [])

    if not isinstance(packages, list):
        return components

    for raw_package in packages:
        if not isinstance(raw_package, dict):
            continue

        raw_name = raw_package.get("name")
        if not isinstance(raw_name, str):
            continue

        name = _normalize_name(raw_name)
        if raw_package.get("source") is None and name not in direct_names and name not in build_names:
            continue

        version = _coerce_locked_version(raw_package.get("version"))
        is_direct = name in direct_names or name in build_names
        if name in build_names:
            layer = "build"
        elif name in direct_names:
            layer = "direct"
        else:
            layer = "transitive"

        signature = ("cargo", name, version)
        if signature in seen:
            continue

        seen.add(signature)
        components.append(
            InventoryComponent(
                name=name,
                version=version,
                ecosystem="cargo",
                layer=layer,
                is_direct=is_direct,
                source_file=source_file,
            )
        )

    return components


def _dedupe_components(components: list[InventoryComponent]) -> list[InventoryComponent]:
    deduped: dict[tuple[str, str, str, str], InventoryComponent] = {}

    for component in components:
        signature = (
            component.ecosystem,
            component.name,
            component.version,
            component.layer,
        )
        existing = deduped.get(signature)
        if not existing:
            deduped[signature] = component
            continue

        merged_dependents = sorted(
            {
                *existing.dependents,
                *component.dependents,
            }
        )
        deduped[signature] = InventoryComponent(
            name=existing.name,
            version=existing.version,
            ecosystem=existing.ecosystem,
            layer=existing.layer,
            is_direct=existing.is_direct or component.is_direct,
            source_file=existing.source_file,
            dependents=merged_dependents,
            license=existing.license or component.license,
        )

    return sorted(
        deduped.values(),
        key=lambda component: (
            component.ecosystem,
            component.layer,
            component.name,
            component.version,
        ),
    )


def analyze_repository(root_path: str | Path) -> InventorySnapshot:
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root}")

    components: list[InventoryComponent] = []
    source_files: list[str] = []

    package_json_path = root / "package.json"
    package_lock_path = root / "package-lock.json"
    requirements_path = root / "requirements.txt"
    pipfile_lock_path = root / "Pipfile.lock"
    pyproject_path = root / "pyproject.toml"
    poetry_lock_path = root / "poetry.lock"
    go_mod_path = root / "go.mod"
    go_sum_path = root / "go.sum"
    cargo_toml_path = root / "Cargo.toml"
    cargo_lock_path = root / "Cargo.lock"

    direct_names: set[str] = set()
    build_names: set[str] = set()
    python_direct_names: set[str] = set()
    python_build_names: set[str] = set()
    go_direct_names: set[str] = set()
    cargo_direct_names: set[str] = set()
    cargo_build_names: set[str] = set()

    if package_json_path.exists():
        source_files.append(package_json_path.name)
        package_components, direct_names, build_names = _parse_package_json(package_json_path)
        components.extend(package_components)

    if package_lock_path.exists():
        source_files.append(package_lock_path.name)
        lock_components = _parse_package_lock(package_lock_path, direct_names, build_names)
        if lock_components:
            components = [
                component
                for component in components
                if component.ecosystem != "npm"
            ]
            components.extend(lock_components)

    if requirements_path.exists():
        source_files.append(requirements_path.name)
        components.extend(_parse_requirements_txt(requirements_path))

    if pipfile_lock_path.exists():
        source_files.append(pipfile_lock_path.name)
        components = [
            component
            for component in components
            if component.ecosystem != "pypi"
        ]
        components.extend(_parse_pipfile_lock(pipfile_lock_path))

    if pyproject_path.exists():
        source_files.append(pyproject_path.name)
        pyproject_components, python_direct_names, python_build_names = _parse_pyproject_dependencies(pyproject_path)
        components.extend(pyproject_components)

    if poetry_lock_path.exists():
        source_files.append(poetry_lock_path.name)
        lock_components = _parse_poetry_lock(
            poetry_lock_path,
            python_direct_names,
            python_build_names,
        )
        if lock_components:
            components = [
                component
                for component in components
                if not (
                    component.ecosystem == "pypi"
                    and component.source_file == pyproject_path.name
                )
            ]
            components.extend(lock_components)

    if go_mod_path.exists():
        source_files.append(go_mod_path.name)
        go_components, go_direct_names, _ = _parse_go_mod(go_mod_path)
        components.extend(go_components)

    if go_sum_path.exists():
        source_files.append(go_sum_path.name)
        lock_components = _parse_go_sum(go_sum_path, go_direct_names)
        if lock_components:
            components = [
                component
                for component in components
                if component.ecosystem != "gomod"
            ]
            components.extend(lock_components)

    if cargo_toml_path.exists():
        source_files.append(cargo_toml_path.name)
        cargo_components, cargo_direct_names, cargo_build_names = _parse_cargo_toml(cargo_toml_path)
        components.extend(cargo_components)

    if cargo_lock_path.exists():
        source_files.append(cargo_lock_path.name)
        lock_components = _parse_cargo_lock(
            cargo_lock_path,
            cargo_direct_names,
            cargo_build_names,
        )
        if lock_components:
            components = [
                component
                for component in components
                if component.ecosystem != "cargo"
            ]
            components.extend(lock_components)

    return InventorySnapshot(
        root_path=str(root),
        source_files=sorted(set(source_files)),
        components=_dedupe_components(components),
    )
