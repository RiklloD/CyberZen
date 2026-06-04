# CyberZen Shared Contracts

This package owns durable cross-service contracts shared by every CyberZen
backend service and the Convex application. The contracts are authored as
Protobuf 3 schemas under `contracts/` and compiled into Python, Go, and
TypeScript bindings under `generated/`.

## Contracts

| File                                | Purpose                                                        |
| ----------------------------------- | -------------------------------------------------------------- |
| `contracts/finding.proto`           | Normalized scanner finding (severity, location, scanner, rules). |
| `contracts/breach-event.proto`      | Breach / advisory disclosure event and correlation result.      |
| `contracts/gate-decision.proto`     | Policy gate decision rendered against a commit.                 |
| `contracts/sbom-snapshot.proto`     | SBOM snapshot for a repository commit.                          |

Every message lives under `package cyberzen.shared.v1`. Breaking changes
require a new package version (`v2`, etc.) — never edit `v1` in place.

## Layout

```
services/shared/
├── contracts/         # source-of-truth .proto files
├── generated/
│   ├── python/        # protoc --python_out target
│   ├── go/            # protoc --go_out target
│   └── ts/            # ts-proto target (consumed by Convex)
├── Makefile           # codegen entrypoint
└── README.md
```

## Regenerating bindings

Prerequisites:

- `protoc >= 25.0` on `PATH` (see [protoc-installation](https://grpc.io/docs/protoc-installation/))
- Python: `pip install grpcio-tools`
- Go: `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest`
- TypeScript: `npm install -g ts-proto`

Then from this directory:

```bash
make all      # python + go + ts
make python   # only Python
make go       # only Go
make ts       # only TypeScript
make lint     # validate proto definitions without writing output
make clean    # remove generated artifacts (keeps placeholders)
```

## Version compatibility

- Consumers MUST pin to a specific `v<N>` package directory.
- Adding new fields is backwards-compatible as long as the field number is
  unused — clients ignore unknown fields.
- Renaming or repurposing field numbers is a breaking change. Bump the
  package version.
- The `Severity` enum in `finding.proto` is shared by `breach-event.proto`;
  keep its numbering stable.
