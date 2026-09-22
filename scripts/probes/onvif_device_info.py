#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2026 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT
# shellcheck disable=SC2317

"""Parse ONVIF GetDeviceInformation SOAP responses."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from defusedxml import ElementTree


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract ONVIF device information")
    parser.add_argument("--input", required=True, help="Path to SOAP response payload")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, required=True, help="Target port")
    parser.add_argument("--scheme", required=True, help="HTTP scheme")
    return parser.parse_args()


def read_payload(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return ""


def extract_field(payload: str, tag: str) -> str:
    """Extract a SOAP value by local name, independent of namespace prefixes."""
    if not payload:
        return ""
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return ""
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]
        if local_name.lower() == tag.lower():
            return " ".join((element.text or "").split())
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
