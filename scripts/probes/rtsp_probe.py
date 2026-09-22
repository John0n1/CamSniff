#!/usr/bin/env python3
"""Bounded RTSP OPTIONS/DESCRIBE identification for CamSniff."""

from __future__ import annotations

import argparse
import json
import re
import socket
from typing import Any, Dict, List, Tuple

MAX_RESPONSE = 65536


def parse_response(payload: bytes) -> Tuple[int, Dict[str, str], str]:
    text = payload.decode("utf-8", errors="replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status = 0
    if lines:
        match = re.match(r"RTSP/\d\.\d\s+(\d{3})", lines[0])
        if match:
            status = int(match.group(1))
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if separator:
            headers[key.strip().lower()] = value.strip()
    return status, headers, body


def parse_authentication(value: str) -> Dict[str, str]:
    if not value:
        return {}
    scheme = value.split(None, 1)[0]
    realm_match = re.search(r'realm="([^"]*)"', value, re.IGNORECASE)
    result = {"scheme": scheme}
    if realm_match:
        result["realm"] = realm_match.group(1)
    return result


def parse_sdp(body: str) -> Dict[str, Any]:
    session: Dict[str, Any] = {"media": [], "control": []}
    current: Dict[str, Any] | None = None
    payload_codecs: Dict[str, str] = {}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if line.startswith("s="):
            session["name"] = line[2:]
        elif line.startswith("m="):
            parts = line[2:].split()
            if len(parts) >= 4:
                current = {
                    "type": parts[0],
                    "port": int(parts[1]) if parts[1].isdigit() else parts[1],
                    "transport": parts[2],
                    "payload_types": parts[3:],
                }
                session["media"].append(current)
        elif line.lower().startswith("a=rtpmap:"):
            payload, _, encoding = line[9:].partition(" ")
            if payload and encoding:
                payload_codecs[payload] = encoding
        elif line.lower().startswith("a=control:"):
            control = line[10:]
            session["control"].append(control)
            if current is not None:
                current["control"] = control
    for medium in session["media"]:
        medium["codecs"] = [
            payload_codecs[payload]
            for payload in medium["payload_types"]
            if payload in payload_codecs
        ]
    return session


class RtspClient:
    def __init__(self, host: str, port: int, timeout: float = 3.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.cseq = 0

    def request(self, method: str, uri: str, accept: str = "") -> bytes:
        self.cseq += 1
        headers = [
            f"{method} {uri} RTSP/1.0",
            f"CSeq: {self.cseq}",
            "User-Agent: CamSniff/RTSP-Probe",
        ]
        if accept:
            headers.append(f"Accept: {accept}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        chunks: List[bytes] = []
        size = 0
        with socket.create_connection((self.host, self.port), self.timeout) as sock:
            sock.settimeout(self.timeout)
            sock.sendall(request)
            while size < MAX_RESPONSE:
                try:
                    chunk = sock.recv(min(4096, MAX_RESPONSE - size))
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                joined = b"".join(chunks)
                if b"\r\n\r\n" in joined:
                    head, body = joined.split(b"\r\n\r\n", 1)
                    length_match = re.search(
                        br"(?im)^Content-Length:\s*(\d+)\s*$", head
                    )
                    expected = int(length_match.group(1)) if length_match else 0
                    if len(body) >= expected:
                        break
        return b"".join(chunks)


def probe(host: str, port: int, path: str, timeout: float) -> Dict[str, Any]:
    uri = f"rtsp://{host}:{port}{path if path.startswith('/') else '/' + path}"
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "uri": uri,
        "state": "port-indicator",
        "verified": False,
    }
    client = RtspClient(host, port, timeout)
    try:
        options_status, options_headers, _ = parse_response(
            client.request("OPTIONS", uri)
        )
    except OSError as error:
        result["error"] = error.__class__.__name__
        return result
    if not options_status:
        return result
    result.update(
        {
            "state": "rtsp-responsive",
            "verified": True,
            "options_status": options_status,
            "server": options_headers.get("server", ""),
            "methods": [
                item.strip()
                for item in (
                    options_headers.get("public") or options_headers.get("allow") or ""
                ).split(",")
                if item.strip()
            ],
        }
    )
    auth = parse_authentication(options_headers.get("www-authenticate", ""))
    if auth:
        result["authentication"] = auth
    if options_status == 401:
        return result
    try:
        describe_status, describe_headers, body = parse_response(
            client.request("DESCRIBE", uri, "application/sdp")
        )
    except OSError:
        return result
    result["describe_status"] = describe_status
    describe_auth = parse_authentication(describe_headers.get("www-authenticate", ""))
    if describe_auth:
        result["authentication"] = describe_auth
    if describe_status == 200 and body.strip():
        result["state"] = "media-described"
        result["sdp"] = parse_sdp(body)
    elif describe_status:
        result["state"] = "rtsp-verified"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    print(json.dumps(probe(args.host, args.port, args.path, args.timeout)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
