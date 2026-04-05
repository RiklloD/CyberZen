from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class InventoryComponent:
    name: str
    version: str
    ecosystem: str
    layer: str
    is_direct: bool
    source_file: str
    dependents: list[str] = field(default_factory=list)
    license: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["isDirect"] = payload.pop("is_direct")
        payload["sourceFile"] = payload.pop("source_file")
        return payload


@dataclass(slots=True)
class InventorySnapshot:
    root_path: str
    source_files: list[str]
    components: list[InventoryComponent]

    def to_dict(self) -> dict[str, object]:
        layer_counts: dict[str, int] = {}

        for component in self.components:
            layer_counts[component.layer] = layer_counts.get(component.layer, 0) + 1

        return {
            "rootPath": self.root_path,
            "sourceFiles": self.source_files,
            "componentCount": len(self.components),
            "layerCounts": layer_counts,
            "components": [component.to_dict() for component in self.components],
        }

