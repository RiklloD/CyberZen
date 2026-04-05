# CyberZen

CyberZen is the implementation workspace for the Sentinel specification: an autonomous cybersecurity intelligence platform built in controlled layers instead of a single feature drop.

## What Exists Today

- A Bun-based TanStack Start application in [apps/web](/C:/Dev/CyberZen/apps/web)
- A Convex-backed control-plane schema for tenants, repositories, events, workflows, SBOM snapshots, breach disclosures, findings, and gate decisions
- Project-level architecture notes in [docs/foundation-decisions.md](/C:/Dev/CyberZen/docs/foundation-decisions.md)
- Service boundary placeholders in [services](/C:/Dev/CyberZen/services) for the Python and Go subsystems from the spec

## Chosen MVP Baseline

- Frontend: TanStack Start + React + Tailwind + Bun
- Control plane and dashboard state: Convex
- Product analytics: PostHog
- Intelligence and agent logic: Python
- High-throughput edge services and sandbox manager: Go when the local Go toolchain is added

## Commands

```bash
bun run dev
bun run check
bun run convex:dev
bun run convex:codegen
```

## Repository Shape

```text
apps/web            TanStack Start dashboard + Convex app
docs                Architecture and implementation decisions
services            Python and Go service boundaries for later slices
```

## Next Build Slice

1. Finish Convex-backed workflow ingestion and repository onboarding
2. Add GitHub webhook intake and the first SBOM ingestion path
3. Stand up the Python orchestration service for semantic fingerprinting and breach-intel normalization
4. Add a minimal operator dashboard for findings and SBOM drift
