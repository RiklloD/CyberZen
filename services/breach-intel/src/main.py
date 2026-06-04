"""Service entrypoint.

`app` is the FastAPI instance uvicorn picks up via `uvicorn src.main:app`.
`main()` is the synchronous CLI wrapper used by the `breach-intel` script
defined in pyproject.toml.
"""

from __future__ import annotations

import logging
import os

import uvicorn

from .http_server import build_app

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = build_app()


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("src.main:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
