#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2026 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

"""Generate markdown or HTML reports from CamSniff output."""
from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate reports from CamSniff JSON output"
    )
    parser.add_argument(
        "--discovery",
        required=True,
        help="Path to discovery.json",
    )
    parser.add_argument(
        "--credentials",
        help="Optional path to credentials.json",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "html"),
        required=True,
        help="Report format",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output report file path",
    )
    parser.add_argument(
        "--run-dir",
        default="",
        help="Optional run directory for context",
    )
    parser.add_argument(
        "--run-label",
        default="",
        help="Optional label for the run",
    )
    return parser.parse_args()


def load_json(path: Path) -> Optional[Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def get_metadata(discovery: Dict[str, Any]) -> Dict[str, str]:
    meta = discovery.get("metadata") or {}
    return {
        "mode": str(meta.get("mode") or ""),
        "generated_at": str(meta.get("generated_at") or ""),
        "network": str(meta.get("network") or ""),
    }


def summarize_credentials(
    creds: Optional[List[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not creds:
        return [], []
    successes: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for entry in creds:
        if entry.get("success") is False:
            failures.append(entry)
        elif entry.get("method"):
            successes.append(entry)
    return successes, failures


def safe_join(values: List[str]) -> str:
    return ", ".join([value for value in values if value])


def build_host_rows(
    hosts: List[Dict[str, Any]],
    success_ips: set[str],
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for host in hosts:
        ip = str(host.get("ip") or "")
        profile = host.get("profile_match") or {}
        vendor = str(profile.get("vendor") or "Unknown")
        model = str(profile.get("model") or "Unknown")
        matched_by = str(profile.get("matched_by") or "")
        confidence = host.get("confidence") or {}
        confidence_score = str(confidence.get("score") or "")
        confidence_level = str(confidence.get("level") or "")
        confidence_class = str(confidence.get("classification") or "")
        ports = [
            str(port)
            for port in host.get("ports") or []
            if port is not None
        ]
        protocols = [
            str(entry.get("protocol") or "")
            for entry in host.get("additional_protocols") or []
            if isinstance(entry, dict)
        ]
        sources = [
            str(source)
            for source in host.get("sources") or []
            if source
        ]
        rows.append(
            {
                "ip": ip,
                "vendor": vendor,
                "model": model,
                "confidence_score": confidence_score,
                "confidence_level": confidence_level,
                "confidence_class": confidence_class,
                "matched_by": matched_by,
                "ports": safe_join(ports),
                "protocols": safe_join(sorted(set(protocols))),
                "sources": safe_join(sorted(set(sources))),
                "credentials": "yes" if ip in success_ips else "no",
            }
        )
    return rows


def build_summary(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    vendor_counter = Counter()
    port_counter = Counter()
    protocol_counter = Counter()
    source_counter = Counter()

    for host in hosts:
        profile = host.get("profile_match") or {}
        vendor = str(profile.get("vendor") or "Unknown")
        vendor_counter[vendor] += 1

        for port in host.get("ports") or []:
            if port is not None:
                port_counter[str(port)] += 1

        for entry in host.get("additional_protocols") or []:
            if isinstance(entry, dict):
                name = str(entry.get("protocol") or "")
                if name:
                    protocol_counter[name] += 1

        for source in host.get("sources") or []:
            if source:
                source_counter[str(source)] += 1

    return {
        "host_count": len(hosts),
        "vendors": vendor_counter,
        "ports": port_counter,
        "protocols": protocol_counter,
        "sources": source_counter,
    }


def render_markdown(
    metadata: Dict[str, str],
    summary: Dict[str, Any],
    host_rows: List[Dict[str, str]],
    confidence_rows: List[Dict[str, str]],
    successes: List[Dict[str, Any]],
    failures: List[Dict[str, Any]],
    run_dir: str,
    run_label: str,
) -> str:
    lines: List[str] = []
    lines.append("# CamSniff Report")
    lines.append("")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"Generated: {now}")
    if run_label:
        lines.append(f"Run: {run_label}")
    if run_dir:
        lines.append(f"Run directory: {run_dir}")
    if metadata.get("mode"):
        lines.append(f"Mode: {metadata.get('mode')}")
    if metadata.get("network"):
        lines.append(f"Network: {metadata.get('network')}")
    if metadata.get("generated_at"):
        lines.append(f"Discovery timestamp: {metadata.get('generated_at')}")

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Hosts: {summary['host_count']}")
    lines.append(f"- Vendors: {len(summary['vendors'])}")
    lines.append(f"- Protocols: {len(summary['protocols'])}")
    lines.append(f"- Credential successes: {len(successes)}")
    lines.append(f"- Credential failures: {len(failures)}")

    if summary["ports"]:
        lines.append("")
        lines.append("## Top Ports")
        lines.append("")
        lines.append("| Port | Count |")
        lines.append("| --- | --- |")
        for port, count in summary["ports"].most_common(10):
            lines.append(f"| {port} | {count} |")

    if summary["protocols"]:
        lines.append("")
        lines.append("## Protocol Hits")
        lines.append("")
        lines.append("| Protocol | Count |")
        lines.append("| --- | --- |")
        for name, count in summary["protocols"].most_common(10):
            lines.append(f"| {name} | {count} |")

    if confidence_rows:
        lines.append("")
        lines.append("## Top Confidence")
        lines.append("")
        lines.append(
            "| IP | Score | Level | Class | Reasons |"
        )
        lines.append(
            "| --- | --- | --- | --- | --- |"
        )
        for row in confidence_rows:
            lines.append(
                f"| {row['ip']} | {row['score']} | {row['level']} | "
                f"{row['classification']} | {row['reasons']} |"
            )

    if host_rows:
        lines.append("")
        lines.append("## Hosts")
        lines.append("")
        lines.append(
            "| IP | Vendor | Model | Confidence | Class | Ports | Protocols | Credentials |"
        )
        lines.append(
            "| --- | --- | --- | --- | --- | --- | --- | --- |"
        )
        for row in host_rows:
            lines.append(
                f"| {row['ip']} | {row['vendor']} | {row['model']} | "
                f"{row['confidence_score']} {row['confidence_level']} | "
                f"{row['confidence_class']} | {row['ports']} | "
                f"{row['protocols']} | {row['credentials']} |"
            )

    if successes:
        lines.append("")
        lines.append("## Credential Successes")
        lines.append("")
        for entry in successes:
            ip = entry.get("ip") or ""
            method = entry.get("method") or ""
            user = entry.get("credentials", {}).get("username") or ""
            password = entry.get("credentials", {}).get("password") or ""
            url = entry.get("url") or ""
            lines.append(
                f"- {ip} ({method}): `{user}` / `{password}` -> {url}"
            )

    return "\n".join(lines) + "\n"


def render_html(
    metadata: Dict[str, str],
    summary: Dict[str, Any],
    host_rows: List[Dict[str, str]],
    confidence_rows: List[Dict[str, str]],
    successes: List[Dict[str, Any]],
    failures: List[Dict[str, Any]],
    run_dir: str,
    run_label: str,
) -> str:
    def esc(value: str) -> str:
        return html.escape(value or "")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    head = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CamSniff Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #1f1f1f; }
    h1 { margin-bottom: 0.2em; }
    .meta { color: #555; font-size: 0.95em; }
    table { border-collapse: collapse; margin: 12px 0 24px; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f3f3f3; }
    .chip { display: inline-block; padding: 2px 8px; border-radius: 12px; background: #eef2f7; }
    .section { margin-top: 24px; }
    code { background: #f6f6f6; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
"""
    meta_lines = [
        f"<div class='meta'>Generated: {esc(now)}</div>"
    ]
    if run_label:
        meta_lines.append(
            f"<div class='meta'>Run: {esc(run_label)}</div>"
        )
    if run_dir:
        meta_lines.append(
            f"<div class='meta'>Run directory: {esc(run_dir)}</div>"
        )
    if metadata.get("mode"):
        meta_lines.append(
            f"<div class='meta'>Mode: {esc(metadata['mode'])}</div>"
        )
    if metadata.get("network"):
        meta_lines.append(
            f"<div class='meta'>Network: {esc(metadata['network'])}</div>"
        )
    if metadata.get("generated_at"):
        meta_lines.append(
            f"<div class='meta'>Discovery timestamp: "
            f"{esc(metadata['generated_at'])}</div>"
        )

    summary_html = f"""
<div class="section">
  <h2>Summary</h2>
  <div class="meta">Hosts: {summary['host_count']}</div>
  <div class="meta">Vendors: {len(summary['vendors'])}</div>
  <div class="meta">Protocols: {len(summary['protocols'])}</div>
  <div class="meta">Credential successes: {len(successes)}</div>
  <div class="meta">Credential failures: {len(failures)}</div>
</div>
"""

    def table_from_counter(
        title: str, counter: Counter
    ) -> str:
        if not counter:
            return ""
        rows = "\n".join(
            f"<tr><td>{esc(key)}</td><td>{count}</td></tr>"
            for key, count in counter.most_common(10)
        )
        return f"""
<div class="section">
  <h2>{esc(title)}</h2>
  <table>
    <thead><tr><th>Item</th><th>Count</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
"""

    hosts_html = ""
    if host_rows:
        rows = "\n".join(
            "<tr>"
            f"<td>{esc(row['ip'])}</td>"
            f"<td>{esc(row['vendor'])}</td>"
            f"<td>{esc(row['model'])}</td>"
            f"<td>{esc(row['confidence_score'])} {esc(row['confidence_level'])}</td>"
            f"<td>{esc(row['confidence_class'])}</td>"
            f"<td>{esc(row['ports'])}</td>"
            f"<td>{esc(row['protocols'])}</td>"
            f"<td><span class='chip'>{esc(row['credentials'])}</span></td>"
            "</tr>"
            for row in host_rows
        )
        hosts_html = f"""
<div class="section">
  <h2>Hosts</h2>
  <table>
    <thead>
      <tr>
        <th>IP</th><th>Vendor</th><th>Model</th><th>Confidence</th>
        <th>Class</th><th>Ports</th><th>Protocols</th><th>Credentials</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</div>
"""

    confidence_html = ""
    if confidence_rows:
        rows = "\n".join(
            "<tr>"
            f"<td>{esc(row['ip'])}</td>"
            f"<td>{esc(row['score'])}</td>"
            f"<td>{esc(row['level'])}</td>"
            f"<td>{esc(row['classification'])}</td>"
            f"<td>{esc(row['reasons'])}</td>"
            "</tr>"
            for row in confidence_rows
        )
        confidence_html = f"""
<div class="section">
  <h2>Top Confidence</h2>
  <table>
    <thead>
      <tr>
        <th>IP</th><th>Score</th><th>Level</th>
        <th>Class</th><th>Reasons</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</div>
"""

    cred_html = ""
    if successes:
        entries = []
        for entry in successes:
            ip = esc(str(entry.get("ip") or ""))
            method = esc(str(entry.get("method") or ""))
            user = esc(str(entry.get("credentials", {}).get("username") or ""))
            password = esc(str(entry.get("credentials", {}).get("password") or ""))
            url = esc(str(entry.get("url") or ""))
            entries.append(
                f"<li>{ip} ({method}): "
                f"<code>{user}</code> / <code>{password}</code> "
                f"-> {url}</li>"
            )
        cred_html = f"""
<div class="section">
  <h2>Credential Successes</h2>
  <ul>
    {''.join(entries)}
  </ul>
</div>
"""

    tail = "</body></html>"

    return (
        head
        + "<h1>CamSniff Report</h1>"
        + "".join(meta_lines)
        + summary_html
        + table_from_counter("Top Ports", summary["ports"])
        + table_from_counter("Protocol Hits", summary["protocols"])
        + confidence_html
        + hosts_html
        + cred_html
        + tail
    )


def main() -> int:
    args = parse_args()
    discovery_path = Path(args.discovery)
    discovery = load_json(discovery_path) or {}
    if not isinstance(discovery, dict):
        discovery = {}
    hosts = discovery.get("hosts") or []
    if not isinstance(hosts, list):
        hosts = []

    creds_data = None
    if args.credentials:
        creds = load_json(Path(args.credentials))
        if isinstance(creds, list):
            creds_data = creds

    successes, failures = summarize_credentials(creds_data)
    success_ips = {
        str(entry.get("ip") or "")
        for entry in successes
        if entry.get("ip")
    }

    metadata = get_metadata(discovery)
    summary = build_summary(hosts)
    host_rows = build_host_rows(hosts, success_ips)
    confidence_rows: List[Dict[str, str]] = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        conf = host.get("confidence") or {}
        if not isinstance(conf, dict):
            continue
        score = conf.get("score", 0)
        try:
            score_int = int(score)
        except (TypeError, ValueError):
            score_int = 0
        reasons = conf.get("reasons") or []
        if isinstance(reasons, list):
            reasons_text = ", ".join(
                str(item) for item in reasons if item
            )
        else:
            reasons_text = str(reasons)
        confidence_rows.append(
            {
                "ip": str(host.get("ip") or ""),
                "score": str(score_int),
                "level": str(conf.get("level") or ""),
                "classification": str(conf.get("classification") or ""),
                "reasons": reasons_text,
            }
        )
    confidence_rows.sort(
        key=lambda row: int(row.get("score") or 0), reverse=True
    )
    confidence_rows = confidence_rows[:10]

    if args.format == "markdown":
        output = render_markdown(
            metadata,
            summary,
            host_rows,
            confidence_rows,
            successes,
            failures,
            args.run_dir,
            args.run_label,
        )
    else:
        output = render_html(
            metadata,
            summary,
            host_rows,
            confidence_rows,
            successes,
            failures,
            args.run_dir,
            args.run_label,
        )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
