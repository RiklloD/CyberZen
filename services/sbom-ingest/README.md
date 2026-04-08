# SBOM Ingest

Planned service boundary for:

- manifest and lockfile parsing
- multi-ecosystem dependency normalization
- snapshot diffing
- SBOM export generation

The first implementation starts here as a small Python worker and currently supports:

- `package.json`
- `package-lock.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `bun.lock`
- `requirements.txt`
- `pyproject.toml`
- `Pipfile.lock`
- `poetry.lock`
- `go.mod`
- `go.sum`
- `Cargo.toml`
- `Cargo.lock`
- `Dockerfile`
- `docker-compose.yml` / `docker-compose.yaml`
- Kubernetes-style image manifests under paths like `k8s/`, `helm/`, and `infra/`

Current entrypoint:

```bash
python -m sentinel_sbom_ingest.cli /path/to/repository --pretty
```

It emits a normalized repository inventory that can be handed to the Convex control plane for snapshot storage.
