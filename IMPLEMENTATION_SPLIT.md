# Sentinel Implementation Split

Reference spec: [sentinel-platform-spec.md](./sentinel-platform-spec.md)

This document breaks the platform into separate programming parts so we can build in controlled slices instead of trying to implement the entire specification at once.

## Recommended Build Order

1. Decision layer
2. Platform foundation
3. Data and workflow core
4. Phase 1 MVP features
5. Customer-facing surfaces
6. Advanced intelligence systems

## Part 1: Decision Layer

Goal: lock the technical direction before writing production code.

Deliverables:

- Monorepo structure
- Service list and boundaries
- Primary backend language and framework
- Frontend stack
- Local development orchestration
- Cloud and deployment baseline
- Testing strategy

Why first:

- Every later part depends on these choices.
- The spec describes capabilities, not implementation defaults.

## Part 2: Platform Foundation

Goal: create a repo that can support multiple services and agents cleanly.

Recommended scope:

- Shared config and environment loading
- Linting, formatting, type-checking, test runners
- CI baseline
- Package and dependency management
- Shared libraries for logging, config, errors, and IDs

Outputs:

- Bootstrapped services and apps
- Repeatable local setup
- Contributor conventions

## Part 3: Core Runtime

Goal: build the minimum platform that can ingest events, schedule work, and persist state.

Sub-parts:

- API service
- Auth and tenant model
- Event router
- Workflow engine or orchestration layer
- Agent task execution model
- Audit trail

Why this is a separate part:

- Most feature work becomes much easier once eventing and workflow execution are real.

## Part 4: Data Plane

Goal: establish the system of record for findings, SBOMs, embeddings, jobs, and artifacts.

Sub-parts:

- PostgreSQL schema and migrations
- pgvector integration
- Redis task/state usage
- Object storage abstraction
- Graph storage abstraction for blast radius
- Time-series storage strategy

Notes:

- The exact graph database can stay abstract at first.
- We should not block Phase 1 MVP on full multi-cloud graph modeling.

## Part 5: Integrations

Goal: connect Sentinel to the developer workflow.

Sub-parts:

- Source control integrations: GitHub first, GitLab second
- CI integrations: GitHub Actions and GitLab CI first
- Notification integrations: Slack first
- Webhook ingestion and webhook emission

Reason for isolation:

- Integrations are a delivery surface, not the core domain. They should sit on stable internal contracts.

## Part 6: Phase 1 MVP Feature Set

This is the first meaningful product slice and should be built feature-by-feature.

### 6.1 SBOM Living Registry

Build first because it gives immediate visibility and establishes dependency inventory.

Scope:

- Dependency parsers and lockfile ingestion
- Snapshot model
- Diff computation
- Export endpoint

### 6.2 Breach Intel Aggregator

Build early because it has clean inputs and creates actionable alerts fast.

Scope:

- Feed ingestion
- Entity normalization
- Package-to-customer matching
- Prioritization pipeline

### 6.3 Semantic Fingerprinting MVP

Build as an MVP, not the full end-state described in the spec.

Scope:

- Parse supported languages
- Function/module chunking
- Embedding pipeline abstraction
- Vector similarity search
- Candidate finding creation

Defer:

- Fine-tuned in-house model
- Full cross-language parity
- Mature zero-day anomaly detection

### 6.4 Exploit-First Validation MVP

Scope:

- Sandbox job model
- Validator task lifecycle
- Reproducible artifact capture
- Validation status transitions

Defer:

- Full autonomous exploit generation breadth
- Large multi-environment exploit libraries

### 6.5 CI/CD Gate Enforcement

Scope:

- Policy rules
- PR status reporting
- Deploy gate decisions
- Override audit trail

### 6.6 PR Generation MVP

Scope:

- Fix suggestion pipeline
- Pull request body generation
- Provider integration
- Evidence and audit attachments

## Part 7: Customer-Facing Surfaces

Goal: expose the platform in a usable way once the core pipelines exist.

Sub-parts:

- REST API
- Dashboard v1
- Findings views
- SBOM views
- Report generation

Rule:

- Do not build polished UI before the underlying models and workflows are stable.

## Part 8: Phase 2+ Intelligence

These should be treated as later modules, not startup blockers.

Modules:

- Supply Chain Social Layer Monitor
- Prompt Injection Shield
- Blast Radius Causality Graph
- Attack Surface Reduction Agent
- Regulatory Drift Detection
- Honeypot Code Auto-Injection
- Memory and Learning Loop
- Red Agent / Blue Agent self-play

Why later:

- These features depend on the core runtime, data plane, and customer-facing evidence model already existing.

## Suggested Team Split

Even if only one person is writing code at first, think in these ownership boundaries:

- Platform Core: repo, infra, auth, API, workflows
- Data and Intelligence: schemas, ingestion, embeddings, search, matching
- Execution and Sandbox: validation jobs, artifacts, safety boundaries
- Integrations and UX: Git providers, CI, webhooks, dashboard

## Recommended First Implementation Slice

If we want the fastest path to a real product skeleton, build this exact sequence:

1. Part 1 and Part 2
2. Minimal Part 3 and Part 4
3. GitHub integration from Part 5
4. SBOM Living Registry from Part 6
5. Breach Intel Aggregator from Part 6
6. Findings API and simple dashboard from Part 7

That sequence gives us a credible Phase 1 base without prematurely committing to the hardest research-heavy features.
