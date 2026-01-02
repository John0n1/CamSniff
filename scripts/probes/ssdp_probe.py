#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

"""Perform a multicast SSDP discovery sweep."""
from __future__ import annotations

import argparse
import json
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET

MCAST_GRP = "239.255.255.250"
MCAST_PORT = 1900


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send SSDP M-SEARCH and capture responses"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="Listen window in seconds",
    )
    parser.add_argument(
        "--mx", type=int, default=2, help="MX header value"
    )
    parser.add_argument(
        "--st", default="ssdp:all", help="ST header value"
    )
    parser.add_argument(
        "--output",
        help="Optional file path to write newline-delimited JSON",
    )
    parser.add_argument(
        "--describe",
        action="store_true",
        help="Fetch and parse device descriptions from SSDP location URLs",
    )
    parser.add_argument(
        "--describe-timeout",
        type=float,
        default=3.0,
        help="Timeout in seconds for SSDP description fetch",
    )
    parser.add_argument(
        "--max-describe",
        type=int,
        default=24,
        help="Maximum number of SSDP description fetches",
    )
    return parser.parse_args()


def build_message(st: str, mx: int) -> bytes:
    lines = [
        "M-SEARCH * HTTP/1.1",
        f"HOST: {MCAST_GRP}:{MCAST_PORT}",
        'MAN: "ssdp:discover"',
        f"MX: {mx}",
        f"ST: {st}",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def collect_responses(
    timeout: float, message: bytes
) -> list[dict[str, str]]:
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(max(timeout, 0.1))

    try:
        sock.sendto(message, (MCAST_GRP, MCAST_PORT))
    except OSError:
        sock.close()
        return []

    responses: list[dict[str, str]] = []
    deadline = time.time() + timeout

    while time.time() < deadline:
        remaining = deadline - time.time()
        sock.settimeout(max(remaining, 0.1))
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            continue
        text = data.decode("utf-8", errors="ignore")
        headers = {}
        for line in text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        responses.append(
            {
                "ip": addr[0],
                "st": headers.get("st", ""),
                "usn": headers.get("usn", ""),
                "server": headers.get("server", ""),
                "location": headers.get("location", ""),
            }
        )

    sock.close()
    return responses


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def fetch_description(url: str, timeout: float) -> dict[str, str]:
    if not url:
        return {}
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            payload = resp.read()
    except Exception:
        return {}
    if not payload:
        return {}
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return {}
    fields = {
        "friendlyName": "friendly_name",
        "manufacturer": "manufacturer",
        "modelName": "model",
        "modelNumber": "model_number",
        "deviceType": "device_type",
        "serialNumber": "serial",
    }
    result: dict[str, str] = {}
    for elem in root.iter():
        tag = _strip_ns(elem.tag)
        if tag in fields and elem.text:
            result[fields[tag]] = elem.text.strip()
    return result


def enrich_with_descriptions(
    responses: list[dict[str, str]],
    timeout: float,
    max_fetches: int,
) -> list[dict[str, str]]:
    seen_locations: set[str] = set()
    count = 0
    for entry in responses:
        location = entry.get("location", "")
        if not location:
            continue
        if location in seen_locations:
            continue
        if count >= max_fetches:
            break
        seen_locations.add(location)
        details = fetch_description(location, timeout)
        if details:
            entry.update(details)
        count += 1
    return responses


def emit(responses: list[dict[str, str]], output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            for entry in responses:
                handle.write(json.dumps(entry) + "\n")
    else:
        for entry in responses:
            print(json.dumps(entry))


def main() -> int:
    args = parse_args()
    message = build_message(args.st, args.mx)
    responses = collect_responses(args.timeout, message)
    if args.describe:
        responses = enrich_with_descriptions(
            responses, args.describe_timeout, args.max_describe
        )
    emit(responses, args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
