from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import InventoryComponent, InventorySnapshot

REQUIREMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*([<>=!~]{1,2}\s*[^;,\s]+)?"
)
GO_REQUIRE_PATTERN = re.compile(r"^([^\s]+)\s+([^\s]+?)(?:\s*//\s*(.+))?$")
YARN_VERSION_PATTERN = re.compile(r'^\s+version\s+"?([^"]+)"?$')
DOCKERFILE_FROM_PATTERN = re.compile(
    r"^\s*FROM(?:\s+--platform=[^\s]+)?\s+([^\s]+)(?:\s+AS\s+([A-Za-z0-9._-]+))?\s*$",
    re.IGNORECASE,
)
CONTAINER_IMAGE_PATTERN = re.compile(r"^\s*image:\s*([^\s#]+)")
NODE_DIRECT_GROUPS = ("dependencies", "optionalDependencies", "peerDependencies")
NODE_BUILD_GROUPS = ("devDependencies",)
CARGO_DIRECT_GROUPS = ("dependencies",)
CARGO_BUILD_GROUPS = ("dev-dependencies", "build-dependencies")
IGNORED_REPOSITORY_DIRS = {
    ".git",
    "node_modules",
    ".turbo",
    ".next",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
}


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


def _strip_wrapping_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ('"', "'"):
        return stripped[1:-1]

    return stripped


def _split_node_package_identifier(raw_identifier: str) -> tuple[str, str] | None:
    identifier = _strip_wrapping_quotes(raw_identifier.strip().rstrip(":").lstrip("/"))
    identifier = identifier.split("(", maxsplit=1)[0]
    if "@" not in identifier[1:]:
        return None

    name, version = identifier.rsplit("@", maxsplit=1)
    if not name or not version:
        return None

    return _normalize_name(name), _coerce_locked_version(version)


def _replace_ecosystem_components(
    components: list[InventoryComponent],
    ecosystem: str,
) -> list[InventoryComponent]:
    return [
        component
        for component in components
        if component.ecosystem != ecosystem
    ]


def _parse_json_with_trailing_commas(raw_text: str) -> object:
    sanitized = re.sub(r",(\s*[}\]])", r"\1", raw_text)
    return json.loads(sanitized)


def _relative_source_file(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _iter_repository_files(root: Path) -> list[Path]:
    files: list[Path] = []

    for path in root.rglob("*"):
        if any(part in IGNORED_REPOSITORY_DIRS for part in path.parts):
            continue
        if path.is_file():
            files.append(path)

    return files


def _parse_container_image_reference(raw_reference: str) -> tuple[str, str] | None:
    reference = _strip_wrapping_quotes(raw_reference.strip())
    if not reference:
        return None

    reference = reference.split("#", maxsplit=1)[0].strip()
    if not reference or "${" in reference:
        return None

    if "@" in reference:
        name, digest = reference.split("@", maxsplit=1)
        if not name or not digest:
            return None
        return _normalize_name(name), digest

    last_slash = reference.rfind("/")
    last_colon = reference.rfind(":")
    if last_colon > last_slash:
        name = reference[:last_colon]
        version = reference[last_colon + 1 :]
        if name and version:
            return _normalize_name(name), version

    return _normalize_name(reference), "unknown"


def _make_container_component(
    root: Path,
    source_path: Path,
    raw_reference: str,
) -> InventoryComponent | None:
    parsed = _parse_container_image_reference(raw_reference)
    if not parsed:
        return None

    name, version = parsed
    return InventoryComponent(
        name=name,
        version=version,
        ecosystem="container",
        layer="container",
        is_direct=True,
        source_file=_relative_source_file(root, source_path),
    )


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


def _collect_node_workspace_groups(
    workspace_entries: dict[str, object],
) -> tuple[set[str], set[str]]:
    direct_names: set[str] = set()
    build_names: set[str] = set()

    for raw_workspace in workspace_entries.values():
        if not isinstance(raw_workspace, dict):
            continue

        for group_name in NODE_DIRECT_GROUPS:
            entries = raw_workspace.get(group_name, {})
            if not isinstance(entries, dict):
                continue

            for raw_name in entries:
                direct_names.add(_normalize_name(raw_name))

        for group_name in NODE_BUILD_GROUPS:
            entries = raw_workspace.get(group_name, {})
            if not isinstance(entries, dict):
                continue

            for raw_name in entries:
                build_names.add(_normalize_name(raw_name))

    return direct_names, build_names


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


def _parse_bun_lock(
    bun_lock_path: Path,
    direct_names: set[str],
    build_names: set[str],
) -> tuple[list[InventoryComponent], set[str], set[str]]:
    lock_data = _parse_json_with_trailing_commas(
        bun_lock_path.read_text(encoding="utf-8")
    )
    source_file = bun_lock_path.name
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()
    workspace_direct_names, workspace_build_names = _collect_node_workspace_groups(
        lock_data.get("workspaces", {}) if isinstance(lock_data.get("workspaces"), dict) else {}
    )
    all_direct_names = direct_names | workspace_direct_names
    all_build_names = build_names | workspace_build_names

    packages = lock_data.get("packages", {})
    if not isinstance(packages, dict):
        return components, all_direct_names, all_build_names

    for raw_name, raw_entry in packages.items():
        descriptor = raw_name
        if isinstance(raw_entry, list) and raw_entry and isinstance(raw_entry[0], str):
            descriptor = raw_entry[0]

        parsed = _split_node_package_identifier(descriptor)
        if not parsed:
            continue

        name, version = parsed
        is_direct = name in all_direct_names or name in all_build_names
        if name in all_build_names:
            layer = "build"
        elif name in all_direct_names:
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

    return components, all_direct_names, all_build_names


def _extract_yarn_package_name(raw_selector_line: str) -> str | None:
    selector_line = raw_selector_line.strip().rstrip(":")
    if selector_line.startswith("__metadata"):
        return None

    selectors = [
        _strip_wrapping_quotes(selector.strip())
        for selector in selector_line.split(",")
        if selector.strip()
    ]
    if not selectors:
        return None

    selector = selectors[0]
    if selector.startswith("@"):
        separator = selector.find("@", 1)
        if separator <= 1:
            return None
        return _normalize_name(selector[:separator])

    if "@" not in selector:
        return None

    return _normalize_name(selector.split("@", maxsplit=1)[0])


def _parse_yarn_lock(
    yarn_lock_path: Path,
    direct_names: set[str],
    build_names: set[str],
) -> list[InventoryComponent]:
    source_file = yarn_lock_path.name
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()
    current_name: str | None = None
    current_version: str | None = None

    def finalize_current_entry() -> None:
        nonlocal current_name, current_version

        if not current_name or not current_version:
            current_name = None
            current_version = None
            return

        signature = ("npm", current_name, current_version)
        if signature not in seen:
            seen.add(signature)
            is_direct = current_name in direct_names or current_name in build_names
            if current_name in build_names:
                layer = "build"
            elif current_name in direct_names:
                layer = "direct"
            else:
                layer = "transitive"

            components.append(
                InventoryComponent(
                    name=current_name,
                    version=current_version,
                    ecosystem="npm",
                    layer=layer,
                    is_direct=is_direct,
                    source_file=source_file,
                )
            )

        current_name = None
        current_version = None

    for raw_line in yarn_lock_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if line and not line.startswith(" "):
            finalize_current_entry()
            current_name = _extract_yarn_package_name(line)
            continue

        if current_name is None:
            continue

        version_match = YARN_VERSION_PATTERN.match(line)
        if version_match:
            current_version = _coerce_locked_version(version_match.group(1))

    finalize_current_entry()
    return components


def _parse_pnpm_lock(
    pnpm_lock_path: Path,
    direct_names: set[str],
    build_names: set[str],
) -> tuple[list[InventoryComponent], set[str], set[str]]:
    source_file = pnpm_lock_path.name
    components: list[InventoryComponent] = []
    seen: set[tuple[str, str, str]] = set()
    current_section: str | None = None
    current_importer_group: str | None = None
    importer_direct_names: set[str] = set()
    importer_build_names: set[str] = set()

    for raw_line in pnpm_lock_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            current_section = stripped[:-1]
            current_importer_group = None
            continue

        if current_section == "importers":
            if indent == 4 and stripped.endswith(":"):
                current_importer_group = _strip_wrapping_quotes(stripped[:-1])
                continue

            if indent == 6 and current_importer_group in (*NODE_DIRECT_GROUPS, *NODE_BUILD_GROUPS):
                dependency_name = _strip_wrapping_quotes(stripped.split(":", maxsplit=1)[0])
                if current_importer_group in NODE_BUILD_GROUPS:
                    importer_build_names.add(_normalize_name(dependency_name))
                else:
                    importer_direct_names.add(_normalize_name(dependency_name))
                continue

        if current_section != "packages" or indent != 2 or not stripped.endswith(":"):
            continue

        parsed = _split_node_package_identifier(stripped[:-1])
        if not parsed:
            continue

        name, version = parsed
        all_direct_names = direct_names | importer_direct_names
        all_build_names = build_names | importer_build_names
        is_direct = name in all_direct_names or name in all_build_names
        if name in all_build_names:
            layer = "build"
        elif name in all_direct_names:
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

    return components, direct_names | importer_direct_names, build_names | importer_build_names


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


def _parse_dockerfile(root: Path, dockerfile_path: Path) -> list[InventoryComponent]:
    components: list[InventoryComponent] = []
    stage_aliases: set[str] = set()

    for raw_line in dockerfile_path.read_text(encoding="utf-8").splitlines():
        match = DOCKERFILE_FROM_PATTERN.match(raw_line.strip())
        if not match:
            continue

        raw_reference = match.group(1)
        stage_alias = match.group(2)
        normalized_reference = _normalize_name(raw_reference)

        if normalized_reference in stage_aliases:
            if stage_alias:
                stage_aliases.add(_normalize_name(stage_alias))
            continue

        component = _make_container_component(root, dockerfile_path, raw_reference)
        if component:
            components.append(component)

        if stage_alias:
            stage_aliases.add(_normalize_name(stage_alias))

    return components


def _parse_container_manifest_images(root: Path, manifest_path: Path) -> list[InventoryComponent]:
    components: list[InventoryComponent] = []

    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        match = CONTAINER_IMAGE_PATTERN.match(raw_line.strip())
        if not match:
            continue

        component = _make_container_component(root, manifest_path, match.group(1))
        if component:
            components.append(component)

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


# ── Maven pom.xml ────────────────────────────────────────────────────────────

# Maven namespaces appear in some pom.xml files
_MVN_NS = "http://maven.apache.org/POM/4.0.0"


def _mvn_tag(tag: str) -> str:
    """Return a namespaced or non-namespaced tag for flexible parsing."""
    return f"{{{_MVN_NS}}}{tag}"


def _parse_pom_xml(pom_path: Path) -> list[InventoryComponent]:
    """Parse Maven pom.xml and extract dependency coordinates."""
    source_file = str(pom_path)
    components: list[InventoryComponent] = []

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
    except ET.ParseError:
        return components

    # Support both namespaced and non-namespaced pom.xml
    ns = _MVN_NS if root.tag.startswith("{") else ""
    prefix = f"{{{ns}}}" if ns else ""

    def find(node: ET.Element, *tags: str) -> ET.Element | None:
        for tag in tags:
            child = node.find(f"{prefix}{tag}")
            if child is not None:
                return child
        return None

    def findtext(node: ET.Element, *tags: str) -> str:
        el = find(node, *tags)
        return (el.text or "").strip() if el is not None else ""

    deps_node = find(root, "dependencies")
    if deps_node is None:
        return components

    for dep in deps_node.findall(f"{prefix}dependency"):
        group_id = findtext(dep, "groupId")
        artifact_id = findtext(dep, "artifactId")
        version = findtext(dep, "version")
        scope = findtext(dep, "scope") or "compile"
        optional = findtext(dep, "optional").lower() == "true"

        if not group_id or not artifact_id:
            continue

        # Maven coordinate format: groupId:artifactId
        name = f"{group_id}:{artifact_id}"

        # Resolve property placeholders like ${project.version}
        if version.startswith("${"):
            version = "unknown"

        is_build = scope in ("test", "provided") or optional
        layer = "build" if is_build else "direct"

        components.append(
            InventoryComponent(
                name=name,
                version=version or "unknown",
                ecosystem="maven",
                layer=layer,
                is_direct=not is_build,
                source_file=source_file,
            )
        )

    return components


# ── Gradle build files ────────────────────────────────────────────────────────
#
# Gradle files (.gradle / .gradle.kts) are Groovy/Kotlin scripts — there is no
# reliable full parser without executing them. We use a conservative regex approach
# that captures the most common dependency declaration forms.

_GRADLE_DEP_PATTERNS = [
    # Groovy: implementation 'group:artifact:version'
    # Kotlin DSL: implementation("group:artifact:version")
    re.compile(
        r"""(?:implementation|api|runtimeOnly|testImplementation|compileOnly|annotationProcessor)\s*[\s('"]+([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([^'")\s]+)"""
    ),
    # Kotlin: implementation(group = "...", name = "...", version = "...")
    re.compile(
        r"""(?:implementation|api)\s*\(\s*group\s*=\s*["']([^"']+)["']\s*,\s*name\s*=\s*["']([^"']+)["']\s*,\s*version\s*=\s*["']([^"']+)["']"""
    ),
]

_GRADLE_BUILD_SCOPES = {"testImplementation", "testRuntimeOnly", "testCompileOnly"}


def _parse_gradle(gradle_path: Path) -> list[InventoryComponent]:
    """Parse Gradle build file using conservative regex patterns."""
    source_file = str(gradle_path)
    components: list[InventoryComponent] = []

    try:
        content = gradle_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return components

    seen: set[str] = set()

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("//") or line.startswith("*"):
            continue

        # Check if this is a test scope declaration
        is_build = any(scope in line for scope in _GRADLE_BUILD_SCOPES)

        for pattern in _GRADLE_DEP_PATTERNS:
            match = pattern.search(line)
            if match:
                groups = match.groups()
                if len(groups) == 3:
                    group_id, artifact_id, version = groups
                elif len(groups) == 2:
                    group_id, artifact_id = groups
                    version = "unknown"
                else:
                    continue

                name = f"{group_id}:{artifact_id}"
                key = f"{name}:{version}"
                if key in seen:
                    continue
                seen.add(key)

                components.append(
                    InventoryComponent(
                        name=name,
                        version=version,
                        ecosystem="gradle",
                        layer="build" if is_build else "direct",
                        is_direct=not is_build,
                        source_file=source_file,
                    )
                )

    return components


# ── Ruby Gemfile.lock ─────────────────────────────────────────────────────────

_GEM_SPEC_PATTERN = re.compile(r"^\s{4}([a-zA-Z0-9_.-]+)\s+\(([^)]+)\)")
_GEM_DEPENDENCY_PATTERN = re.compile(r"^\s{2}([a-zA-Z0-9_.-]+)\s*\(([^)]*)\)")


def _parse_gemfile_lock(gemfile_lock_path: Path) -> list[InventoryComponent]:
    """
    Parse Gemfile.lock to extract gem dependencies.

    Gemfile.lock format:
        GEM
          remote: https://rubygems.org/
          specs:
            actioncable (7.0.8)
            actionmailer (7.0.8)
            ...
        DEPENDENCIES
          activesupport (~> 7.0)
          ...
    """
    source_file = str(gemfile_lock_path)
    components: list[InventoryComponent] = []

    try:
        content = gemfile_lock_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return components

    lines = content.splitlines()
    in_specs = False
    in_dependencies = False
    direct_gems: set[str] = set()
    all_gems: dict[str, str] = {}

    for line in lines:
        stripped = line.rstrip()

        if stripped.strip() in ("GEM", "PATH", "GIT"):
            in_specs = False
            in_dependencies = False
            continue

        if stripped.strip() == "DEPENDENCIES":
            in_specs = False
            in_dependencies = True
            continue

        if stripped.strip() == "specs:":
            in_specs = True
            in_dependencies = False
            continue

        if stripped and not stripped[0].isspace():
            # New section
            in_specs = False
            in_dependencies = False
            continue

        if in_specs:
            match = _GEM_SPEC_PATTERN.match(stripped)
            if match:
                name, version = match.group(1), match.group(2)
                # Take only the base version (ignore platform qualifiers like "x86_64-darwin")
                base_version = version.split("-")[0] if "-" in version and version[0].isdigit() else version
                all_gems[name.lower()] = base_version

        if in_dependencies:
            # Dependencies section lists direct gems
            dep_match = _GEM_DEPENDENCY_PATTERN.match(stripped)
            if dep_match:
                direct_gems.add(dep_match.group(1).lower())

    # Build components from resolved specs
    for name, version in all_gems.items():
        is_direct = name in direct_gems
        components.append(
            InventoryComponent(
                name=name,
                version=version,
                ecosystem="gem",
                layer="direct" if is_direct else "transitive",
                is_direct=is_direct,
                source_file=source_file,
            )
        )

    return components


# ── Gemfile (without lock) ────────────────────────────────────────────────────

_GEMFILE_GEM_PATTERN = re.compile(
    r"""^\s*gem\s+['"]([a-zA-Z0-9_.-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?"""
)


def _parse_gemfile(gemfile_path: Path) -> list[InventoryComponent]:
    """Parse bare Gemfile when Gemfile.lock is absent."""
    source_file = str(gemfile_path)
    components: list[InventoryComponent] = []

    try:
        content = gemfile_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return components

    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = _GEMFILE_GEM_PATTERN.match(stripped)
        if match:
            name = match.group(1)
            version = match.group(2) or "unknown"
            components.append(
                InventoryComponent(
                    name=name.lower(),
                    version=version,
                    ecosystem="gem",
                    layer="direct",
                    is_direct=True,
                    source_file=source_file,
                )
            )

    return components


# ── NuGet (.csproj / packages.lock.json) ─────────────────────────────────────

_CSPROJ_PACKAGE_REF = re.compile(
    r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
    re.IGNORECASE,
)
_CSPROJ_PACKAGE_REF_ALT = re.compile(
    r'<PackageReference\s+Include="([^"]+)"[^>]*>\s*<Version>([^<]+)</Version>',
    re.IGNORECASE | re.DOTALL,
)


def _parse_csproj(csproj_path: Path) -> list[InventoryComponent]:
    """Parse .csproj file for NuGet PackageReference entries."""
    source_file = str(csproj_path)
    components: list[InventoryComponent] = []

    try:
        content = csproj_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return components

    seen: set[str] = set()

    for pattern in (_CSPROJ_PACKAGE_REF, _CSPROJ_PACKAGE_REF_ALT):
        for match in pattern.finditer(content):
            name = match.group(1).strip()
            version = match.group(2).strip()
            key = f"{name.lower()}:{version}"
            if key in seen:
                continue
            seen.add(key)
            components.append(
                InventoryComponent(
                    name=name,
                    version=version,
                    ecosystem="nuget",
                    layer="direct",
                    is_direct=True,
                    source_file=source_file,
                )
            )

    return components


def _parse_nuget_lock(lock_path: Path) -> list[InventoryComponent]:
    """
    Parse packages.lock.json (NuGet lock file format).

    Format:
        {
          "version": 2,
          "dependencies": {
            ".NETCoreApp,Version=v8.0": {
              "PackageName": { "type": "Direct", "resolved": "1.2.3" },
              ...
            }
          }
        }
    """
    source_file = str(lock_path)
    components: list[InventoryComponent] = []

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return components

    dependencies = data.get("dependencies", {})
    seen: set[str] = set()

    # dependencies can be nested by target framework
    for framework_deps in dependencies.values():
        if not isinstance(framework_deps, dict):
            continue
        for pkg_name, pkg_data in framework_deps.items():
            if not isinstance(pkg_data, dict):
                continue
            version = str(pkg_data.get("resolved", "unknown"))
            dep_type = str(pkg_data.get("type", "Transitive")).lower()
            is_direct = dep_type == "direct"
            layer = "direct" if is_direct else "transitive"

            key = f"{pkg_name.lower()}:{version}"
            if key in seen:
                continue
            seen.add(key)

            components.append(
                InventoryComponent(
                    name=pkg_name,
                    version=version,
                    ecosystem="nuget",
                    layer=layer,
                    is_direct=is_direct,
                    source_file=source_file,
                )
            )

    return components


# ── PHP Composer ───────────────────────────────────────────────────────────────

def _parse_composer_json(composer_path: Path) -> list[InventoryComponent]:
    """Parse composer.json for direct PHP dependencies."""
    source_file = str(composer_path)
    components: list[InventoryComponent] = []

    try:
        data = json.loads(composer_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return components

    for section, is_direct, layer in [
        ("require", True, "direct"),
        ("require-dev", False, "build"),
    ]:
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for pkg_name, version_constraint in deps.items():
            # Skip PHP itself and extensions (e.g. "php", "ext-json")
            if pkg_name == "php" or pkg_name.startswith("ext-"):
                continue
            components.append(
                InventoryComponent(
                    name=pkg_name.lower(),
                    version=str(version_constraint),
                    ecosystem="composer",
                    layer=layer,
                    is_direct=is_direct,
                    source_file=source_file,
                )
            )

    return components


def _parse_composer_lock(lock_path: Path) -> list[InventoryComponent]:
    """
    Parse composer.lock for fully resolved PHP dependencies.

    Format:
        {
          "packages": [ { "name": "vendor/pkg", "version": "1.2.3" }, ... ],
          "packages-dev": [ ... ]
        }
    """
    source_file = str(lock_path)
    components: list[InventoryComponent] = []

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return components

    for section, is_direct, layer in [
        ("packages", True, "direct"),
        ("packages-dev", False, "build"),
    ]:
        for pkg in data.get(section, []):
            name = pkg.get("name", "").lower()
            version = str(pkg.get("version", "unknown"))
            if not name:
                continue
            components.append(
                InventoryComponent(
                    name=name,
                    version=version,
                    ecosystem="composer",
                    layer=layer,
                    is_direct=is_direct,
                    source_file=source_file,
                )
            )

    return components


def analyze_repository(root_path: str | Path) -> InventorySnapshot:
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Repository path does not exist: {root}")

    components: list[InventoryComponent] = []
    source_files: list[str] = []
    repository_files = _iter_repository_files(root)
    repository_file_set = {path.resolve() for path in repository_files}

    package_json_path = root / "package.json"
    package_lock_path = root / "package-lock.json"
    pnpm_lock_path = root / "pnpm-lock.yaml"
    yarn_lock_path = root / "yarn.lock"
    bun_lock_path = root / "bun.lock"
    requirements_path = root / "requirements.txt"
    pipfile_lock_path = root / "Pipfile.lock"
    pyproject_path = root / "pyproject.toml"
    poetry_lock_path = root / "poetry.lock"
    go_mod_path = root / "go.mod"
    go_sum_path = root / "go.sum"
    cargo_toml_path = root / "Cargo.toml"
    cargo_lock_path = root / "Cargo.lock"
    pom_xml_path = root / "pom.xml"
    gemfile_lock_path = root / "Gemfile.lock"
    gemfile_path = root / "Gemfile"
    nuget_lock_path = root / "packages.lock.json"
    composer_lock_path = root / "composer.lock"
    composer_json_path = root / "composer.json"

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
            components = _replace_ecosystem_components(components, "npm")
            components.extend(lock_components)

    if pnpm_lock_path.exists():
        source_files.append(pnpm_lock_path.name)
        lock_components, direct_names, build_names = _parse_pnpm_lock(
            pnpm_lock_path,
            direct_names,
            build_names,
        )
        if lock_components:
            components = _replace_ecosystem_components(components, "npm")
            components.extend(lock_components)

    if yarn_lock_path.exists():
        source_files.append(yarn_lock_path.name)
        lock_components = _parse_yarn_lock(yarn_lock_path, direct_names, build_names)
        if lock_components:
            components = _replace_ecosystem_components(components, "npm")
            components.extend(lock_components)

    if bun_lock_path.exists():
        source_files.append(bun_lock_path.name)
        lock_components, direct_names, build_names = _parse_bun_lock(
            bun_lock_path,
            direct_names,
            build_names,
        )
        if lock_components:
            components = _replace_ecosystem_components(components, "npm")
            components.extend(lock_components)

    if requirements_path.exists():
        source_files.append(requirements_path.name)
        components.extend(_parse_requirements_txt(requirements_path))

    if pipfile_lock_path.exists():
        source_files.append(pipfile_lock_path.name)
        components = _replace_ecosystem_components(components, "pypi")
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
            components = _replace_ecosystem_components(components, "gomod")
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
            components = _replace_ecosystem_components(components, "cargo")
            components.extend(lock_components)

    # ── Maven pom.xml ──────────────────────────────────────────────────────────
    if pom_xml_path.is_file():
        source_files.append(_relative_source_file(root, pom_xml_path))
        components.extend(_parse_pom_xml(pom_xml_path))

    # Also scan nested pom.xml files (multi-module Maven projects)
    for nested_pom in sorted(root.rglob("pom.xml")):
        if nested_pom.resolve() == pom_xml_path.resolve():
            continue
        if any(part in IGNORED_REPOSITORY_DIRS for part in nested_pom.parts):
            continue
        source_files.append(_relative_source_file(root, nested_pom))
        pom_components = _parse_pom_xml(nested_pom)
        for c in pom_components:
            c.source_file = _relative_source_file(root, nested_pom)
        components.extend(pom_components)

    # ── Gradle build.gradle / build.gradle.kts ────────────────────────────────
    for gradle_file in sorted(root.rglob("build.gradle")) + sorted(root.rglob("build.gradle.kts")):
        if any(part in IGNORED_REPOSITORY_DIRS for part in gradle_file.parts):
            continue
        gradle_components = _parse_gradle(gradle_file)
        if gradle_components:
            source_files.append(_relative_source_file(root, gradle_file))
            components.extend(gradle_components)

    # ── Ruby Gemfile.lock / Gemfile ────────────────────────────────────────────
    if gemfile_lock_path.is_file():
        source_files.append(_relative_source_file(root, gemfile_lock_path))
        components.extend(_parse_gemfile_lock(gemfile_lock_path))
    elif gemfile_path.is_file():
        source_files.append(_relative_source_file(root, gemfile_path))
        components.extend(_parse_gemfile(gemfile_path))

    # ── NuGet .csproj / packages.lock.json ────────────────────────────────────
    if nuget_lock_path.is_file():
        source_files.append(_relative_source_file(root, nuget_lock_path))
        components.extend(_parse_nuget_lock(nuget_lock_path))
    else:
        # Scan for .csproj files in the repo
        for csproj_file in sorted(root.rglob("*.csproj")):
            if any(part in IGNORED_REPOSITORY_DIRS for part in csproj_file.parts):
                continue
            csproj_components = _parse_csproj(csproj_file)
            if csproj_components:
                source_files.append(_relative_source_file(root, csproj_file))
                components.extend(csproj_components)

    # ── PHP Composer ──────────────────────────────────────────────────────────
    if composer_lock_path.is_file():
        source_files.append(_relative_source_file(root, composer_lock_path))
        components.extend(_parse_composer_lock(composer_lock_path))
    elif composer_json_path.is_file():
        source_files.append(_relative_source_file(root, composer_json_path))
        components.extend(_parse_composer_json(composer_json_path))

    dockerfiles = sorted(
        [
            path
            for path in repository_files
            if path.name == "Dockerfile" or path.name.startswith("Dockerfile.")
        ],
        key=lambda path: _relative_source_file(root, path),
    )
    seen_container_paths: set[Path] = set()

    for dockerfile_path in dockerfiles:
        source_files.append(_relative_source_file(root, dockerfile_path))
        seen_container_paths.add(dockerfile_path.resolve())
        components.extend(_parse_dockerfile(root, dockerfile_path))

    manifest_candidates = sorted(
        [
            path
            for path in repository_files
            if (
                path.resolve() not in seen_container_paths
                and (
                    path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
                    or any(
                        part in {"k8s", "helm", "infra", "deploy", "deployment", "manifests"}
                        for part in path.parts
                    )
                )
                and path.suffix.lower() in {".yml", ".yaml"}
            )
        ],
        key=lambda path: _relative_source_file(root, path),
    )

    for manifest_path in manifest_candidates:
        manifest_components = _parse_container_manifest_images(root, manifest_path)
        if not manifest_components:
            continue

        source_files.append(_relative_source_file(root, manifest_path))
        components.extend(manifest_components)

    return InventorySnapshot(
        root_path=str(root),
        source_files=sorted(set(source_files)),
        components=_dedupe_components(components),
    )
