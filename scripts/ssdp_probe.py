#!/usr/bin/env python3
#
# Copyright 2025 John Hauger Mitander
# Licensed under the MIT License
#
"""Perform a multicast SSDP discovery sweep."""
from __future__ import annotations

import argparse
import json
import socket
import time

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
    emit(responses, args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
