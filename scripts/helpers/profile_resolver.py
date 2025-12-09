#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

"""Resolve camera/profile hints based on discovery artefacts."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class HostContext:
    ip: str
    mac: str = ""
    ports: Sequence[int] = field(default_factory=list)
    observed_paths: Sequence[str] = field(default_factory=list)
    http_metadata: Sequence[Dict[str, str]] = field(
        default_factory=list
    )

    @property
    def http_banners(self) -> List[str]:
        banners: List[str] = []
        for entry in self.http_metadata:
            for key in ("server", "realm", "title"):
                value = (entry.get(key) or "").strip()
                if value:
                    banners.append(value)
        return banners


@dataclass
class CatalogRow:
    raw: Dict[str, str]
    company: str
    model: str
    type: str
    oui_regex: str
    rtsp_url: str
    http_snapshot_url: str
    onvif_profile_path: str
    video_encoding: str
    port: Optional[int]
    streams: List[str]
    channels: List[str]
    username: str
    password: str
    is_digest_auth_supported: str
    cve_ids: List[str]
    user_manual_url: str


class ProfileResolver:
    def __init__(self, catalog: Sequence[CatalogRow]):
        self.catalog = catalog

    def resolve(
        self, host: HostContext
    ) -> Optional[Tuple[CatalogRow, str]]:
        matches = self.resolve_many(host, limit=1)
        if not matches:
            return None
        row, matched_by, _score = matches[0]
        return row, matched_by

    def resolve_many(
        self, host: HostContext, *, limit: int = 3
    ) -> List[Tuple[CatalogRow, str, int]]:
        ranked: List[Tuple[int, CatalogRow, str]] = []
        for row in self.catalog:
            score, matched_by = self._score_row(row, host)
            if score <= 0:
                continue
            ranked.append((score, row, matched_by))

        ranked.sort(key=lambda item: item[0], reverse=True)
        trimmed: List[Tuple[CatalogRow, str, int]] = []
        for score, row, matched_by in ranked[: max(limit, 0)]:
            trimmed.append((row, matched_by, score))
        return trimmed

    def _score_row(
        self, row: CatalogRow, host: HostContext
    ) -> Tuple[int, str]:
        score = 0
        matched_by = ""

        mac = host.mac.upper()
        pattern = row.oui_regex
        if mac and pattern:
            try:
                if re.search(pattern, mac, re.IGNORECASE):
                    score += 100
                    matched_by = "oui"
            except re.error:
                pass

        if row.port is not None and row.port in host.ports:
            score += 10
            if not matched_by:
                matched_by = "port"

        vendor = row.company.lower()
        model = row.model.lower()
        for banner in host.http_banners:
            entry = banner.lower()
            if vendor and vendor in entry:
                score += 5
                if not matched_by:
                    matched_by = "http"
                break
            if model and model in entry:
                score += 4
                if not matched_by:
                    matched_by = "http"
                break

        template_path = _extract_template_path(row.rtsp_url)
        if template_path:
            for observed in host.observed_paths:
                normalized = observed.lower()
                if template_path in normalized:
                    score += 2
                    if not matched_by:
                        matched_by = "path"
                    break

        return score, matched_by


def _extract_template_path(template: str) -> str:
    if not template:
        return ""
    lower = template.lower()
    if "rtsp://" in lower:
        stripped = lower.split("rtsp://", 1)[1]
    elif "http://" in lower:
        stripped = lower.split("http://", 1)[1]
    elif "https://" in lower:
        stripped = lower.split("https://", 1)[1]
    else:
        stripped = lower
    path = stripped.split("/", 1)
    if len(path) == 1:
        return ""
    return path[1]


def _parse_list(value: str) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(";") if part.strip()]


def _parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _load_catalog(path: Path) -> List[CatalogRow]:
    rows: List[CatalogRow] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            port = _parse_int(raw.get("port"))
            rows.append(
                CatalogRow(
                    raw=raw,
                    company=(raw.get("company") or "Unknown").strip(),
                    model=(raw.get("model") or "").strip(),
                    type=(raw.get("type") or "").strip(),
                    oui_regex=(raw.get("oui_regex") or "").strip(),
                    rtsp_url=(raw.get("rtsp_url") or "").strip(),
                    http_snapshot_url=(
                        raw.get("http_snapshot_url") or ""
                    ).strip(),
                    onvif_profile_path=(
                        raw.get("onvif_profile_path") or ""
                    ).strip(),
                    video_encoding=(
                        raw.get("video_encoding") or ""
                    ).strip(),
                    port=port,
                    streams=_parse_list(raw.get("streams") or ""),
                    channels=_parse_list(raw.get("channels") or ""),
                    username=(raw.get("username") or "").strip(),
                    password=(raw.get("password") or "").strip(),
                    is_digest_auth_supported=(
                        raw.get("is_digest_auth_supported") or ""
                    ).strip(),
                    cve_ids=_parse_list(raw.get("cve_ids") or ""),
                    user_manual_url=(
                        raw.get("user_manual_url") or ""
                    ).strip(),
                )
            )
    return rows


def _parse_ports(value: str) -> List[int]:
    if not value:
        return []
    result: List[int] = []
    for token in value.split():
        try:
            result.append(int(token.strip()))
        except ValueError:
            continue
    return result


def _parse_paths(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split() if item.strip()]


def _parse_http_json(value: str) -> List[Dict[str, str]]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    result: List[Dict[str, str]] = []
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                result.append(entry)
    return result


def _build_profile_payload(
    row: CatalogRow, matched_by: str, score: int = 0
) -> Dict[str, object]:
    def coerce_bool(flag: str) -> bool:
        lowered = (flag or "").strip().lower()
        return lowered in {"1", "true", "yes"}

    def build_rtsp_candidates() -> List[Dict[str, object]]:
        template = row.rtsp_url
        if not template:
            return []
        streams = row.streams or ["0"]
        channels = row.channels or ["1"]
        port = row.port if row.port is not None else 554
        candidates: List[Dict[str, object]] = []
        for channel in channels[:3]:
            for stream in streams[:3]:
                candidates.append(
                    {
                        "template": template,
                        "port": port,
                        "channel": channel,
                        "stream": stream,
                        "transport": "tcp",
                    }
                )
                if len(candidates) >= 6:
                    return candidates
        return candidates

    def build_http_candidates() -> List[Dict[str, object]]:
        template = row.http_snapshot_url
        if not template:
            return []
        streams = row.streams or ["0"]
        channels = row.channels or ["1"]
        port_guess = (
            row.port
            if row.port is not None
            else (443 if template.lower().startswith("https") else 80)
        )
        return [
            {
                "template": template,
                "port": port_guess,
                "channel": channels[0],
                "stream": streams[0],
            }
        ]

    return {
        "vendor": row.company or "Unknown",
        "model": row.model or "Unknown",
        "type": row.type or "Unknown",
        "matched_by": matched_by,
        "score": score,
        "default_username": row.username,
        "default_password": row.password,
        "digest_auth": coerce_bool(row.is_digest_auth_supported),
        "video_encoding": row.video_encoding,
        "rtsp_candidates": build_rtsp_candidates(),
        "http_snapshot_candidates": build_http_candidates(),
        "onvif_profiles": (
            row.onvif_profile_path.split(";")
            if row.onvif_profile_path
            else []
        ),
        "cve_ids": row.cve_ids,
        "reference": row.user_manual_url,
    }


def _render_text_profile(ip: str, profile: Dict[str, object]) -> str:
    lines: List[str] = []
    lines.append(
        f"  Profile match: {profile.get('vendor')} {profile.get('model')}"
    )
    match_flag = profile.get("matched_by")
    if match_flag:
        lines.append(f"    Matched via: {match_flag}")
    rtsp_candidates = profile.get("rtsp_candidates") or []
    if rtsp_candidates:
        first = rtsp_candidates[0]
        template = first.get("template") or ""
        port = first.get("port")
        channel = first.get("channel")
        stream = first.get("stream")
        url = template.replace("{{ip_address}}", ip)
        url = url.replace("{{port}}", str(port or 554))
        url = url.replace("{{channel}}", str(channel or "1"))
        url = url.replace("{{stream}}", str(stream or "0"))
        url = url.replace("{{username}}", "<username>")
        url = url.replace("{{password}}", "<password>")
        lines.append(f"    Suggested RTSP: {url}")
    if profile.get("default_username") or profile.get(
        "default_password"
    ):
        username = profile.get("default_username") or "<custom>"
        password = profile.get("default_password") or "<password>"
        lines.append(f"    Default creds: {username}/{password}")
    encoding = profile.get("video_encoding")
    if encoding:
        lines.append(f"    Encoding: {encoding}")
    snapshot = profile.get("http_snapshot_candidates") or []
    if snapshot:
        template = snapshot[0].get("template") or ""
        if template:
            lines.append(f"    Snapshot template: {template}")
    if profile.get("digest_auth"):
        lines.append("    Digest auth: true")
    cves = profile.get("cve_ids") or []
    if cves:
        lines.append(f"    CVEs: {', '.join(cves)}")
    reference = profile.get("reference")
    if reference:
        lines.append(f"    Reference: {reference}")
    return "\n".join(lines)


def command_match(args: argparse.Namespace) -> int:
    catalog = _load_catalog(Path(args.paths))
    resolver = ProfileResolver(catalog)
    context = HostContext(
        ip=args.ip,
        mac=args.mac or "",
        ports=_parse_ports(args.ports or ""),
        observed_paths=_parse_paths(args.observed or ""),
        http_metadata=_parse_http_json(args.http_json or ""),
    )
    matches = resolver.resolve_many(context, limit=args.limit)
    if not matches:
        if args.format == "json":
            if args.limit == 1:
                json.dump({}, sys.stdout)
            else:
                json.dump([], sys.stdout)
            return 0
        print("  No catalog profile matched.")
        return 0

    profiles = [
        _build_profile_payload(row, matched_by, score)
        for row, matched_by, score in matches
    ]

    if args.format == "json":
        if args.limit == 1:
            json.dump(profiles[0], sys.stdout, indent=2)
        else:
            json.dump(profiles, sys.stdout, indent=2)
        return 0

    for idx, profile in enumerate(profiles, start=1):
        if args.limit > 1:
            print(f"  Match {idx} of {len(profiles)}:")
        print(_render_text_profile(args.ip, profile))
        if args.limit > 1 and idx < len(profiles):
            print("")
    return 0


def command_enrich(args: argparse.Namespace) -> int:
    catalog = _load_catalog(Path(args.paths))
    resolver = ProfileResolver(catalog)
    input_path = Path(args.input)
    output_path = Path(args.output)

    try:
        with input_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        data = {"hosts": []}

    hosts = data.get("hosts") or []
    for host in hosts:
        ports = host.get("ports") or []
        observed = host.get("observed_paths") or []
        http_meta = host.get("http_metadata") or []
        mac = host.get("mac") or ""
        context = HostContext(
            ip=host.get("ip") or "",
            mac=mac,
            ports=[
                value for value in ports if isinstance(value, int)
            ],
            observed_paths=[
                value for value in observed if isinstance(value, str)
            ],
            http_metadata=[
                value
                for value in http_meta
                if isinstance(value, dict)
            ],
        )
        matches = resolver.resolve_many(context, limit=args.limit)
        if not matches:
            continue
        payloads = [
            _build_profile_payload(row, matched_by, score)
            for row, matched_by, score in matches
        ]
        host["profile_matches"] = payloads
        host["profile_match"] = payloads[0]

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)

    return 0

def command_catalog(args: argparse.Namespace) -> int:
    catalog = _load_catalog(Path(args.paths))
    generated = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    entries: List[Dict[str, Any]] = []
    for row in catalog:
        entries.append(
            {
                "vendor": row.company,
                "model": row.model,
                "type": row.type,
                "oui_regex": row.oui_regex,
                "rtsp_url": row.rtsp_url,
                "http_snapshot_url": row.http_snapshot_url,
                "onvif_profile_path": row.onvif_profile_path,
                "video_encoding": row.video_encoding,
                "port": row.port,
                "streams": row.streams,
                "channels": row.channels,
                "default_username": row.username,
                "default_password": row.password,
                "digest_auth": row.is_digest_auth_supported,
                "cve_ids": row.cve_ids,
                "reference": row.user_manual_url,
            }
        )

    payload = {
        "generated_at": generated,
        "count": len(entries),
        "entries": entries,
    }

    output = Path(args.output) if args.output else None
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    else:
        json.dump(payload, sys.stdout, indent=2)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve CamSniff profile matches"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    match_parser = subparsers.add_parser(
        "match", help="Resolve a single host profile"
    )
    match_parser.add_argument(
        "--paths", required=True, help="Path to paths.csv catalog"
    )
    match_parser.add_argument(
        "--ip", required=True, help="Host IP address"
    )
    match_parser.add_argument(
        "--mac", default="", help="Host MAC address"
    )
    match_parser.add_argument(
        "--ports", default="", help="Whitespace-separated port list"
    )
    match_parser.add_argument(
        "--observed",
        default="",
        help="Whitespace-separated observed paths",
    )
    match_parser.add_argument(
        "--http-json", default="", help="HTTP metadata JSON array"
    )
    match_parser.add_argument(
        "--format", choices=("text", "json"), default="text"
    )
    match_parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Return up to N catalog matches (default: 1)",
    )
    match_parser.set_defaults(func=command_match)

    enrich_parser = subparsers.add_parser(
        "enrich", help="Enrich discovery.json with profile data"
    )
    enrich_parser.add_argument(
        "--paths", required=True, help="Path to paths.csv catalog"
    )
    enrich_parser.add_argument(
        "--input", required=True, help="Discovery JSON input path"
    )
    enrich_parser.add_argument(
        "--output", required=True, help="Discovery JSON output path"
    )
    enrich_parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Attach up to N catalog matches per host (default: 1)",
    )
    enrich_parser.set_defaults(func=command_enrich)

    catalog_parser = subparsers.add_parser(
        "catalog", help="Export the profile catalog as JSON"
    )
    catalog_parser.add_argument(
        "--paths", required=True, help="Path to paths.csv catalog"
    )
    catalog_parser.add_argument(
        "--output", help="Optional output file (defaults to stdout)"
    )
    catalog_parser.set_defaults(func=command_catalog)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
