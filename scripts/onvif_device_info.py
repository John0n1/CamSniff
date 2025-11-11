#!/usr/bin/env python3
#
# Copyright 2025 John Hauger Mitander
# Licensed under the MIT License
#
"""Parse ONVIF GetDeviceInformation SOAP responses."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract ONVIF device information"
    )
    parser.add_argument(
        "--input", required=True, help="Path to SOAP response payload"
    )
    parser.add_argument(
        "--ip", required=True, help="Target IP address"
    )
    parser.add_argument(
        "--port", type=int, required=True, help="Target port"
    )
    parser.add_argument("--scheme", required=True, help="HTTP scheme")
    return parser.parse_args()


def read_payload(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def extract_field(payload: str, tag: str) -> str:
    pattern = rf"<tds:{tag}>(.*?)</tds:{tag}>"
    match = re.search(pattern, payload, re.IGNORECASE | re.DOTALL)
    if match:
        return re.sub(r"\s+", " ", match.group(1)).strip()
    return ""


def main() -> int:
    args = parse_args()
    payload = read_payload(Path(args.input))
    manufacturer = extract_field(payload, "Manufacturer")
    model = extract_field(payload, "Model")
    firmware = extract_field(payload, "FirmwareVersion")
    serial = extract_field(payload, "SerialNumber")

    result = {
        "ip": args.ip,
        "port": args.port,
        "scheme": args.scheme,
        "manufacturer": manufacturer,
        "model": model,
        "firmware": firmware,
        "serial": serial,
    }

    print(json.dumps(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
