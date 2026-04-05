# Services

These directories mark the long-term service boundaries from the Sentinel spec.

- `agent-core`: Python orchestration and intelligence adapters
- `event-gateway`: webhook intake and event routing
- `sbom-ingest`: dependency and build inventory extraction
- `breach-intel`: disclosure aggregation and normalization
- `sandbox-manager`: sandbox lifecycle and exploit execution control
- `shared`: cross-service contracts and notes

The first runnable implementation lives in [apps/web](/C:/Dev/CyberZen/apps/web). These services are intentionally staged so we can keep the MVP on the control-plane path first.
