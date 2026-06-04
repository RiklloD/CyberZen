# Event Gateway

Planned Go service for:

- GitHub webhook intake
- CI/CD callback intake
- event validation, deduplication, and routing
- durable forwarding into the workflow layer

This stays separate from the dashboard so bursty external traffic does not couple directly to the operator UI.
