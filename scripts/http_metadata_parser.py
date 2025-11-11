#!/usr/bin/env python3
#
# Copyright 2025 John Hauger Mitander
# Licensed under the MIT License
#
"""Extract structured HTTP metadata from captured headers/body."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract HTTP metadata for CamSniff"
    )
    parser.add_argument(
        "--headers", required=True, help="Path to raw HTTP headers"
    )
    parser.add_argument(
        "--body", required=True, help="Path to HTTP response body"
    )
    parser.add_argument(
        "--ip", required=True, help="Target IP address"
    )
    parser.add_argument(
        "--port", type=int, required=True, help="Target TCP port"
    )
    parser.add_argument(
        "--scheme", required=True, help="URL scheme (http/https)"
    )
    return parser.parse_args()


def read_text(path: Path, limit: int | None = None) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""
    if limit is not None:
        return data[:limit]
    return data


def extract_metadata(headers: str, body: str) -> dict:
    status_code = None
    server = ""
    www_auth = ""

    header_lines = headers.splitlines()
    if header_lines:
        first_line = header_lines[0]
        if first_line.startswith("HTTP/"):
            parts = first_line.split()
            if len(parts) > 1 and parts[1].isdigit():
                status_code = int(parts[1])

    for line in header_lines[1:]:
        lower = line.lower()
        if lower.startswith("server:") and not server:
            server = line.split(":", 1)[1].strip()
        elif lower.startswith("www-authenticate:") and not www_auth:
            www_auth = line.split(":", 1)[1].strip()

    title = ""
    match = re.search(
        r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL
    )
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()

    realm = ""
    realm_match = re.search(
        r"realm=\"([^\"]+)\"", www_auth, re.IGNORECASE
    )
    if realm_match:
        realm = realm_match.group(1)

    return {
        "status": status_code,
        "server": server,
        "realm": realm,
        "title": title,
        "www_authenticate": www_auth,
    }


def main() -> int:
    args = parse_args()

    headers = read_text(Path(args.headers))
    body = read_text(Path(args.body), limit=4096)
    metadata = extract_metadata(headers, body)

    payload = {
        "ip": args.ip,
        "port": args.port,
        "scheme": args.scheme,
        **metadata,
    }

    print(json.dumps(payload))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
