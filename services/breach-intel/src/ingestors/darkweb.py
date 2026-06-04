"""Tor hidden-service crawler.

Real implementation will route through a Tor SOCKS proxy and pull listing
pages from a curated allowlist of marketplaces / leak sites. The crawler
runs on a separate worker pool and emits BreachEvents into this service
via callback; the path below covers the on-demand pull case used by the
HTTP endpoint.

TODO(breach-intel):
  - Route httpx via socks5h://tor:9050
  - Maintain allowlist + per-site parser registry under config
  - Persist site cursors so we can resume incremental crawls
  - Surface captcha / auth-wall events as health signals, not errors
"""

from __future__ import annotations

from ..models import BreachEvent, IngestRequest


class DarkwebIngestor:
    source_name = "darkweb"

    def __init__(self, tor_proxy: str = "socks5h://tor:9050") -> None:
        self.tor_proxy = tor_proxy

    async def fetch(self, request: IngestRequest) -> list[BreachEvent]:
        """Stub implementation — returns no events.

        Future flow:
          1. Connect httpx.AsyncClient(proxies={"all://": self.tor_proxy}).
          2. For each allowlisted site, GET the listing page.
          3. Parse with site-specific extractor; dedupe against cursor.
          4. Emit BreachEvents tagged with the originating site.
        """
        _ = request
        return []
