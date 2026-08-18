#!/usr/bin/env python3
"""Parse quoted TShark CSV into a shell-safe event stream."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


FIELD_COUNT = 10
SEPARATOR = "\x1f"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize CamSniff TShark CSV")
    parser.add_argument("--input", required=True, help="TShark CSV input path")
    return parser.parse_args()


def sanitize(value: str) -> str:
    return value.replace(SEPARATOR, " ").replace("\r", " ").replace("\n", " ")


def iter_events(path: Path):
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < FIELD_COUNT:
                row.extend([""] * (FIELD_COUNT - len(row)))
            elif len(row) > FIELD_COUNT:
                row = row[: FIELD_COUNT - 1] + [",".join(row[FIELD_COUNT - 1 :])]
            yield [sanitize(value) for value in row]


def main() -> int:
    args = parse_args()
    try:
        for event in iter_events(Path(args.input)):
            sys.stdout.write(SEPARATOR.join(event) + "\n")
    except OSError as exc:
        print(f"Unable to parse TShark capture: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
