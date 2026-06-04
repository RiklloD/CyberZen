"""Telegram channel ingestor.

Real implementation will use a Telegram MTProto client (e.g. telethon) with
account credentials provisioned per-tenant in a secret manager. For now this
stub returns an empty list so the rest of the service can be exercised
end-to-end.

TODO(breach-intel):
  - Wire telethon client with session storage in S3/Convex
  - Resolve channel handles to telethon Entity objects
  - Page through messages since last cursor
  - Map message text → BreachEvent with regex-based CVE/package extraction
  - Honor per-tenant rate limits and FloodWait responses
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import BreachEvent, IngestRequest


class TelegramIngestor:
    source_name = "telegram"

    def __init__(self, channels: list[str] | None = None) -> None:
        # Comma-separated list of channel handles or invite links to monitor.
        self.channels: list[str] = channels or []

    async def fetch(self, request: IngestRequest) -> list[BreachEvent]:
        """Stub implementation — returns no events.

        Once the Telegram client is wired in, this should:
          1. Connect using the configured session.
          2. Read messages from each channel since `request.cursor`.
          3. Apply lightweight NLP to lift package/CVE references.
          4. Return one BreachEvent per usable message.
        """
        _ = (request, datetime.now(tz=timezone.utc))
        return []
