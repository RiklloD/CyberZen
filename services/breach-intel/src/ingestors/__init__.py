"""Source-specific breach ingestors.

Each ingestor exposes an async `fetch()` returning a list of `BreachEvent`s.
The HTTP layer dispatches on the `BreachSource` enum.
"""

from __future__ import annotations

from typing import Protocol

from ..models import BreachEvent, IngestRequest


class Ingestor(Protocol):
    """Common shape every ingestor implements."""

    source_name: str

    async def fetch(self, request: IngestRequest) -> list[BreachEvent]:
        ...


from .cisa_kev import CisaKevIngestor  # noqa: E402
from .darkweb import DarkwebIngestor  # noqa: E402
from .osv import OsvIngestor  # noqa: E402
from .telegram import TelegramIngestor  # noqa: E402

__all__ = [
    "Ingestor",
    "CisaKevIngestor",
    "DarkwebIngestor",
    "OsvIngestor",
    "TelegramIngestor",
]
