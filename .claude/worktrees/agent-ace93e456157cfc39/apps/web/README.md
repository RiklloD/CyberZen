# CyberZen Web

This app is the first runnable Sentinel foundation slice:

- TanStack Start frontend
- Convex-backed control plane
- Tailwind-driven operator dashboard
- PostHog analytics hooks

## Local Development

```bash
bun install
bun run convex:dev
bun run dev
```

If you have not initialized Convex on this machine yet:

```bash
bunx --bun convex init
```

Then set these values in `.env.local`:

```bash
VITE_APP_TITLE=CyberZen
VITE_CONVEX_URL=...
CONVEX_DEPLOYMENT=...
VITE_POSTHOG_KEY=...
VITE_POSTHOG_HOST=https://us.i.posthog.com
```

## Useful Scripts

```bash
bun run check
bun run test
bun run convex:codegen
```

## What The Current UI Covers

- tenant overview
- repository inventory
- workflow and event spine
- SBOM snapshot summary
- breach-intel watchlist
- findings and gate decisions

The next implementation step is GitHub-first event ingestion plus SBOM parsing from real manifests and lockfiles.
