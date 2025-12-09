#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

"""CamSniff to IVRE integration bridge."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sync CamSniff discovery data into IVRE"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to CamSniff discovery.json",
    )
    parser.add_argument(
        "--mode", required=True, help="CamSniff mode label"
    )
    parser.add_argument(
        "--network", required=True, help="Network scope string"
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Run directory for this execution",
    )
    parser.add_argument(
        "--timestamp",
        required=True,
        help="UTC timestamp in YYYYMMDDTHHMMSSZ format",
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Log file to append integration status",
    )
    parser.add_argument(
        "--credentials",
        help="Path to CamSniff credentials.json (optional)",
    )
    parser.add_argument(
        "--paths-csv",
        help="Path to paths.csv for vendor mapping (optional)",
    )
    return parser


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def log_line(log_path: Path, message: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"{utc_now()} {message}\n")


def normalise_port(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        if 0 <= value <= 65535:
            return value
        return None
    if isinstance(value, float):
        value_int = int(value)
        if 0 <= value_int <= 65535:
            return value_int
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            value_int = int(stripped, 10)
        except ValueError:
            return None
        if 0 <= value_int <= 65535:
            return value_int
    return None


def load_vendor_database(
    paths_csv: Optional[Path],
) -> Dict[str, Dict[str, str]]:
    vendor_db: Dict[str, Dict[str, str]] = {}

    if not paths_csv or not paths_csv.is_file():
        return vendor_db

    try:
        with paths_csv.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                company = row.get("company", "").strip()
                model = row.get("model", "").strip()
                oui_regex = row.get("oui_regex", "").strip()

                if not company or not oui_regex:
                    continue

                oui_list = oui_regex.strip("()").split("|")
                for oui in oui_list:
                    oui_clean = oui.strip().upper()
                    if oui_clean:
                        vendor_db[oui_clean] = {
                            "company": company,
                            "model": model,
                            "cve_ids": row.get("cve_ids", ""),
                        }
    except Exception:
        pass

    return vendor_db


def match_vendor_by_mac(
    mac: Optional[str], vendor_db: Dict[str, Dict[str, str]]
) -> Optional[Dict[str, str]]:
    if not mac or not vendor_db:
        return None

    mac_upper = mac.strip().upper().replace("-", ":")
    oui = ":".join(mac_upper.split(":")[:3])

    return vendor_db.get(oui)


def load_credentials(
    credentials_json: Optional[Path],
) -> Dict[str, Dict[str, Any]]:
    creds_db: Dict[str, Dict[str, Any]] = {}

    if not credentials_json or not credentials_json.is_file():
        return creds_db

    try:
        with credentials_json.open("r", encoding="utf-8") as handle:
            creds_list = json.load(handle)

        for entry in creds_list:
            ip_addr = entry.get("ip")
            if not ip_addr:
                continue

            creds_db[ip_addr] = {
                "success": entry.get("success", False),
                "username": entry.get("username", ""),
                "password": entry.get("password", ""),
                "method": entry.get("method", ""),
                "vendor": entry.get("vendor", "Unknown"),
                "model": entry.get("model", "Unknown"),
                "protocols": entry.get("protocols", []),
                "rtsp_url": entry.get("rtsp_url", ""),
                "http_url": entry.get("http_url", ""),
                "thumbnail": entry.get("thumbnail", ""),
            }
    except Exception:
        pass

    return creds_db


def build_host_documents(
    data: Dict[str, Any],
    *,
    mode: str,
    network: str,
    run_dir: str,
    timestamp: dt.datetime,
    vendor_db: Dict[str, Dict[str, str]],
    creds_db: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    from ivre import xmlnmap  # type: ignore

    hosts = data.get("hosts", []) or []
    documents: List[Dict[str, Any]] = []
    ts_rendered = timestamp.strftime("%Y-%m-%d %H:%M:%S")

    for host in hosts:
        ip_addr = host.get("ip")
        if not ip_addr:
            continue

        ports_field = host.get("ports", []) or []
        ports_seen: Set[tuple[str, int]] = set()
        port_documents: List[Dict[str, Any]] = []

        for port_candidate in ports_field:
            port_number = normalise_port(port_candidate)
            if port_number is None:
                continue
            key = ("tcp", port_number)
            if key in ports_seen:
                continue
            ports_seen.add(key)
            entry: Dict[str, Any] = {
                "protocol": "tcp",
                "port": port_number,
                "state_state": "open",
                "state_reason": "script",
            }
            if port_number in {
                80,
                81,
                88,
                8000,
                8001,
                8080,
                8081,
                8443,
            }:
                entry["service_name"] = "http"
            if port_number in {443, 7443, 8443, 9443, 10443}:
                entry["service_name"] = "http"
                entry["service_tunnel"] = "ssl"
            if port_number == 554:
                entry["service_name"] = "rtsp"
            port_documents.append(entry)

        rtsp_data = host.get("rtsp_bruteforce", {}) or {}
        observed_paths = host.get("observed_paths", []) or []
        additional_protocols = (
            host.get("additional_protocols", []) or []
        )
        sources = host.get("sources", []) or []

        mac_addr = host.get("mac")
        vendor_info = (
            match_vendor_by_mac(mac_addr, vendor_db)
            if mac_addr
            else None
        )

        cred_info = creds_db.get(ip_addr)

        summary_lines = [
            f"mode={mode}",
            f"network={network}",
            f"sources={','.join(sources) if sources else 'n/a'}",
        ]

        if vendor_info:
            summary_lines.append(f"vendor={vendor_info['company']}")
            if vendor_info.get("model"):
                summary_lines.append(f"model={vendor_info['model']}")
            if vendor_info.get("cve_ids"):
                summary_lines.append(f"cves={vendor_info['cve_ids']}")
        elif cred_info:
            summary_lines.append(
                f"vendor={cred_info.get('vendor', 'Unknown')}"
            )
            summary_lines.append(
                f"model={cred_info.get('model', 'Unknown')}"
            )

        if cred_info and cred_info.get("success"):
            summary_lines.append("credentials=FOUND")
            summary_lines.append(
                f"  username={cred_info['username']}"
            )
            summary_lines.append(
                f"  password={cred_info['password']}"
            )
            summary_lines.append(f"  method={cred_info['method']}")
            if cred_info.get("rtsp_url"):
                summary_lines.append(
                    f"  rtsp_url={cred_info['rtsp_url']}"
                )
            if cred_info.get("http_url"):
                summary_lines.append(
                    f"  http_url={cred_info['http_url']}"
                )
            if cred_info.get("thumbnail"):
                summary_lines.append(
                    f"  thumbnail={cred_info['thumbnail']}"
                )

        if ports_seen:
            summary_lines.append(
                "ports="
                + ",".join(
                    str(port)
                    for _, port in sorted(
                        ports_seen, key=lambda item: item[1]
                    )
                )
            )
        if observed_paths:
            summary_lines.append("observed_paths:")
            for path in observed_paths[:10]:
                summary_lines.append(f"  - {path}")
        if rtsp_data.get("discovered"):
            summary_lines.append("rtsp_found:")
            for url in rtsp_data["discovered"][:10]:
                summary_lines.append(f"  - {url}")
        if additional_protocols:
            summary_lines.append("protocol_hits:")
            for proto in additional_protocols:
                proto_name = proto.get("protocol", "unknown")
                detail = proto.get("detail", "")
                summary_lines.append(f"  - {proto_name}: {detail}")

        host_scripts: List[Dict[str, Any]] = []

        summary_data = {
            "mode": mode,
            "network": network,
            "run_dir": run_dir,
            "sources": sources,
            "observed_paths": observed_paths,
            "rtsp": rtsp_data,
            "additional_protocols": additional_protocols,
        }

        if vendor_info:
            summary_data["vendor"] = vendor_info["company"]
            summary_data["model"] = vendor_info.get("model", "")
            summary_data["cves"] = vendor_info.get("cve_ids", "")

        if cred_info:
            summary_data["credentials"] = {
                "success": cred_info.get("success", False),
                "username": cred_info.get("username", ""),
                "password": cred_info.get("password", ""),
                "method": cred_info.get("method", ""),
                "rtsp_url": cred_info.get("rtsp_url", ""),
                "http_url": cred_info.get("http_url", ""),
                "thumbnail": cred_info.get("thumbnail", ""),
            }

        host_scripts.append(
            {
                "id": "camsniff-summary",
                "output": "\n".join(summary_lines),
                "camsniff-summary": summary_data,
            }
        )

        if additional_protocols:
            host_scripts.append(
                {
                    "id": "camsniff-protocols",
                    "output": "\n".join(
                        f" {entry.get('detail', '')}"
                        for entry in additional_protocols
                    ),
                    "camsniff-protocols": additional_protocols,
                }
            )

        if rtsp_data.get("other_responses"):
            formatted = []
            for status, urls in sorted(
                rtsp_data["other_responses"].items()
            ):
                for url in urls:
                    formatted.append(f"{status}: {url}")
            host_scripts.append(
                {
                    "id": "camsniff-rtsp-responses",
                    "output": "\n".join(formatted),
                    "camsniff-rtsp-responses": rtsp_data[
                        "other_responses"
                    ],
                }
            )

        if vendor_info or cred_info:
            vendor_script_output = []
            vendor_script_data = {}

            if vendor_info:
                vendor_script_output.append(
                    f"Company: {vendor_info['company']}"
                )
                vendor_script_output.append(
                    f"Model: {vendor_info.get('model', 'N/A')}"
                )
                if vendor_info.get("cve_ids"):
                    vendor_script_output.append(
                        f"CVEs: {vendor_info['cve_ids']}"
                    )
                vendor_script_data["company"] = vendor_info["company"]
                vendor_script_data["model"] = vendor_info.get(
                    "model", ""
                )
                vendor_script_data["cves"] = vendor_info.get(
                    "cve_ids", ""
                )
            elif cred_info:
                vendor_script_output.append(
                    f"Company: {cred_info.get('vendor', 'Unknown')}"
                )
                vendor_script_output.append(
                    f"Model: {cred_info.get('model', 'Unknown')}"
                )
                vendor_script_data["company"] = cred_info.get(
                    "vendor", "Unknown"
                )
                vendor_script_data["model"] = cred_info.get(
                    "model", "Unknown"
                )

            if cred_info and cred_info.get("success"):
                vendor_script_output.append("Credentials: SUCCESS")
                vendor_script_output.append(
                    f"  Username: {cred_info['username']}"
                )
                vendor_script_output.append(
                    f"  Password: {cred_info['password']}"
                )
                vendor_script_output.append(
                    f"  Method: {cred_info['method']}"
                )
                vendor_script_data["credentials_found"] = True
                vendor_script_data["username"] = cred_info["username"]
                vendor_script_data["password"] = cred_info["password"]

                if cred_info.get("thumbnail"):
                    vendor_script_output.append(
                        f"  Thumbnail: {cred_info['thumbnail']}"
                    )
                    vendor_script_data["thumbnail"] = cred_info[
                        "thumbnail"
                    ]

            host_scripts.append(
                {
                    "id": "camsniff-vendor",
                    "output": "\n".join(vendor_script_output),
                    "camsniff-vendor": vendor_script_data,
                }
            )

        if host_scripts:
            port_documents.append(
                {
                    "protocol": "tcp",
                    "port": -1,
                    "state_state": "open",
                    "state_reason": "script",
                    "scripts": host_scripts,
                }
            )

        document: Dict[str, Any] = {
            "addr": ip_addr,
            "state": "up",
            "schema_version": xmlnmap.SCHEMA_VERSION,
            "starttime": ts_rendered,
            "endtime": ts_rendered,
            "source": "CamSniff",
            "categories": [
                "camsniff",
                f"camsniff-mode:{mode.lower()}",
            ],
            "ports": port_documents,
        }

        if vendor_info:
            document["categories"].append(
                f"vendor:{vendor_info['company'].lower().replace(' ', '-')}"
            )
        elif cred_info:
            vendor_name = cred_info.get("vendor", "unknown")
            document["categories"].append(
                f"vendor:{vendor_name.lower().replace(' ', '-')}"
            )

        if cred_info and cred_info.get("success"):
            document["categories"].append("credentials-found")

        if mac_addr:
            document["addresses"] = [
                {
                    "addrtype": "mac",
                    "addr": str(mac_addr).strip(),
                }
            ]

        documents.append(document)

    return documents


def main() -> int:
    args = build_parser().parse_args()
    log_path = Path(args.log)
    input_path = Path(args.input)

    if not input_path.is_file():
        log_line(log_path, f"input file not found: {input_path}")
        return 1

    try:
        run_timestamp = dt.datetime.strptime(
            args.timestamp, "%Y%m%dT%H%M%SZ"
        ).replace(tzinfo=dt.UTC)
    except ValueError as exc:
        log_line(
            log_path, f"invalid timestamp '{args.timestamp}': {exc}"
        )
        return 1

    try:
        with input_path.open("r", encoding="utf-8") as handle:
            discovery_data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        log_line(log_path, f"failed to read discovery payload: {exc}")
        return 1

    paths_csv_path = Path(args.paths_csv) if args.paths_csv else None
    vendor_db = load_vendor_database(paths_csv_path)
    log_line(
        log_path,
        f"loaded {len(vendor_db)} vendor entries from paths.csv",
    )

    credentials_path = (
        Path(args.credentials) if args.credentials else None
    )
    creds_db = load_credentials(credentials_path)
    log_line(log_path, f"loaded {len(creds_db)} credential entries")

    try:
        from ivre.db import db  # type: ignore
    except ImportError as exc:
        log_line(log_path, f"IVRE not available: {exc}")
        return 2

    dbase = getattr(db, "nmap", None)
    if dbase is None:
        log_line(log_path, "IVRE nmap database backend unavailable")
        return 2

    documents = build_host_documents(
        discovery_data,
        mode=args.mode,
        network=args.network,
        run_dir=args.run_dir,
        timestamp=run_timestamp,
        vendor_db=vendor_db,
        creds_db=creds_db,
    )

    if not documents:
        log_line(log_path, "no hosts to sync – skipping IVRE import")
        return 0

    try:
        ips_to_update = [
            doc["addr"] for doc in documents if doc.get("addr")
        ]
        if ips_to_update:
            removed_count = 0
            for ip_addr in ips_to_update:
                host_filter = dbase.searchhost(ip_addr)
                source_filter = dbase.searchsource("CamSniff")
                combined_filter = dbase.flt_and(
                    host_filter, source_filter
                )

                existing_scans = list(dbase.get(combined_filter))

                for scan in existing_scans:
                    dbase.remove(scan)
                    removed_count += 1

            if removed_count > 0:
                log_line(
                    log_path,
                    f"removed {removed_count} hosts before re-ingestion",
                )
    except Exception as exc:
        log_line(
            log_path, f"warning: failed to remove old scans: {exc}"
        )

    try:
        stored_count = 0
        for doc in documents:
            dbase.store_host(doc)
            stored_count += 1
        log_line(log_path, f"synced {stored_count} hosts into IVRE")
    except Exception as exc:
        log_line(log_path, f"IVRE ingestion failed: {exc}")
        return 1

    vendor_count = sum(
        1
        for doc in documents
        if any("vendor:" in cat for cat in doc.get("categories", []))
    )
    creds_count = sum(
        1
        for doc in documents
        if "credentials-found" in doc.get("categories", [])
    )
    log_line(log_path, f"  - {vendor_count} hosts with vendor info")
    log_line(log_path, f"  - {creds_count} hosts with credentials")

    return 0


if __name__ == "__main__":
    sys.exit(main())
