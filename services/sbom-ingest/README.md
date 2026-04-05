# SBOM Ingest

Planned service boundary for:

- manifest and lockfile parsing
- multi-ecosystem dependency normalization
- snapshot diffing
- SBOM export generation

The first implementation starts here as a small Python worker and currently supports:

- `package.json`
- `package-lock.json`
- `requirements.txt`
- `pyproject.toml`

Current entrypoint:

```bash
python -m sentinel_sbom_ingest.cli /path/to/repository --pretty
```

It emits a normalized repository inventory that can be handed to the Convex control plane for snapshot storage.
