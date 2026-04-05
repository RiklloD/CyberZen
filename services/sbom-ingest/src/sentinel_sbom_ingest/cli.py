from __future__ import annotations

import argparse
import json
from pathlib import Path

from .parser import analyze_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract a normalized Sentinel inventory snapshot from a repository path."
    )
    parser.add_argument("path", type=Path, help="Repository root to inspect")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the extracted snapshot JSON",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    snapshot = analyze_repository(args.path)
    indent = 2 if args.pretty else None
    print(json.dumps(snapshot.to_dict(), indent=indent, sort_keys=args.pretty))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

