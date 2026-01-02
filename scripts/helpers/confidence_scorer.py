#!/usr/bin/env python3
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2026 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

"""Compute confidence scores for CamSniff discovery results."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

SOURCE_WEIGHTS = {
    "SSDP": 25,
    "Avahi": 15,
    "TShark": 20,
    "Nmap": 5,
    "Masscan": 4,
    "CoAP": 8,
}

PORT_WEIGHTS = {
    554: 35,
    8554: 30,
    10554: 30,
    5544: 25,
    1935: 12,
    1936: 12,
    37777: 20,
    37778: 20,
    37779: 20,
    8000: 18,
    8001: 18,
    8899: 12,
    9000: 10,
    7001: 10,
    5000: 10,
    5001: 10,
}

HTTP_PORTS = {80, 81, 82, 88, 443, 7443, 8000, 8080, 8081, 8088, 8443}

PROTOCOL_WEIGHTS = {
    "ONVIF": 30,
    "RTSP": 25,
    "HLS": 15,
    "RTMP": 12,
    "WebRTC": 12,
    "SRT": 8,
    "HTTP": 8,
    "SSDP": 10,
    "CoAP": 8,
}

CAMERA_KEYWORDS = [
    "camera",
    "ipcam",
    "ip cam",
    "webcam",
    "mjpeg",
    "snapshot",
    "onvif",
    "rtsp",
    "surveillance",
    "live view",
    "liveview",
    "stream",
    "cctv",
]

VENDOR_KEYWORDS = [
    "hikvision",
    "dahua",
    "axis",
    "hanwha",
    "bosch",
    "uniview",
    "vivotek",
    "amcrest",
    "lorex",
    "reolink",
    "flir",
    "mobotix",
    "sony",
    "panasonic",
    "geovision",
    "tiandy",
    "avigilon",
    "ezviz",
]

RECORDER_KEYWORDS = [
    "nvr",
    "dvr",
    "recorder",
    "cms",
]

OBSERVED_PATH_HINTS = [
    "rtsp",
    "onvif",
    "snapshot",
    "mjpeg",
    "mjpg",
    "stream",
    "live",
]

PATH_PATTERNS = [
    r"/Streaming/Channels/",
    r"/cam/realmonitor",
    r"/live\.sdp",
    r"/live\.m3u8",
    r"/streaming/",
    r"/video\.mjpg",
    r"/mjpeg",
    r"/mjpg",
    r"/snapshot\.cgi",
    r"/cgi-bin/.+snapshot",
    r"/onvif/",
    r"/ISAPI/",
    r"/axis-cgi/",
    r"/h264",
    r"/video\.cgi",
    r"/image\.jpg",
]

SSDP_LOCATION_HINTS = [
    "onvif",
    "device",
    "desc",
    "upnp",
    "camera",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score CamSniff discovery hosts"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input discovery JSON path",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output discovery JSON path",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return {"hosts": []}


def sanitize_text(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()


def contains_keyword(text: str, keywords: List[str]) -> bool:
    lowered = text.lower()
    for keyword in keywords:
        if keyword in lowered:
            return True
    return False


def flatten_metadata(host: Dict[str, Any]) -> str:
    parts: List[str] = []
    for entry in host.get("http_metadata") or []:
        if isinstance(entry, dict):
            for key in ("server", "realm", "title", "www_authenticate"):
                value = sanitize_text(entry.get(key))
                if value:
                    parts.append(value)
    for entry in host.get("ssdp") or []:
        if isinstance(entry, dict):
            for key in (
                "server",
                "st",
                "usn",
                "location",
                "friendly_name",
                "manufacturer",
                "model",
                "model_number",
                "device_type",
                "serial",
            ):
                value = sanitize_text(entry.get(key))
                if value:
                    parts.append(value)
    for entry in host.get("onvif") or []:
        if isinstance(entry, dict):
            for key in entry.values():
                value = sanitize_text(key)
                if value:
                    parts.append(value)
    observed = host.get("observed_paths") or []
    if isinstance(observed, list):
        parts.extend([sanitize_text(item) for item in observed])
    return " ".join(parts)


def score_host(host: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    signals = set()

    def add(points: int, reason: str, signal: Optional[str] = None) -> None:
        nonlocal score
        score += points
        if reason and reason not in reasons:
            reasons.append(reason)
        if signal:
            signals.add(signal)

    sources = host.get("sources") or []
    for source in sources:
        name = sanitize_text(source)
        if name in SOURCE_WEIGHTS:
            add(SOURCE_WEIGHTS[name], f"{name.lower()} signal", "source")

    ports = host.get("ports") or []
    for port in ports:
        if isinstance(port, int) and port in PORT_WEIGHTS:
            add(PORT_WEIGHTS[port], f"port {port} open", "port")
    if any(isinstance(port, int) and port in HTTP_PORTS for port in ports):
        add(8, "http port open", "port")

    protocols = host.get("additional_protocols") or []
    for entry in protocols:
        if isinstance(entry, dict):
            name = sanitize_text(entry.get("protocol"))
            if name in PROTOCOL_WEIGHTS:
                signal = "protocol"
                if name == "RTSP":
                    signal = "rtsp"
                elif name == "ONVIF":
                    signal = "onvif"
                add(PROTOCOL_WEIGHTS[name], f"{name.lower()} detected", signal)

    rtsp = host.get("rtsp_bruteforce") or {}
    discovered = rtsp.get("discovered") or []
    if isinstance(discovered, list) and discovered:
        add(35, "rtsp url discovered", "rtsp")
    other = rtsp.get("other_responses") or {}
    if isinstance(other, dict) and other:
        add(10, "rtsp response observed", "rtsp")

    observed_paths = host.get("observed_paths") or []
    observed_blob = " ".join(
        sanitize_text(item) for item in observed_paths if item
    )
    if observed_blob and contains_keyword(observed_blob, OBSERVED_PATH_HINTS):
        add(18, "observed stream path", "path")
    if observed_paths:
        path_hits = 0
        for path in observed_paths:
            if not path:
                continue
            for pattern in PATH_PATTERNS:
                if re.search(pattern, str(path), re.IGNORECASE):
                    path_hits += 1
                    add(12, "camera path signature", "path")
                    break
        if path_hits >= 2:
            add(6, "multiple camera paths", "path")

    profile = host.get("profile_match") or {}
    vendor = sanitize_text(profile.get("vendor"))
    if vendor and vendor.lower() != "unknown":
        add(10, "vendor match", "profile")
    matched_by = sanitize_text(profile.get("matched_by"))
    if matched_by.lower() == "oui":
        add(15, "mac oui match", "profile")

    meta_blob = flatten_metadata(host)
    if meta_blob and contains_keyword(meta_blob, CAMERA_KEYWORDS):
        add(20, "camera keyword in banners", "banner")
    if meta_blob and contains_keyword(meta_blob, VENDOR_KEYWORDS):
        add(12, "vendor keyword in banners", "banner")
    elif meta_blob:
        add(5, "banner metadata present", "banner")

    onvif_entries = host.get("onvif") or []
    if onvif_entries:
        add(10, "onvif metadata", "onvif")
        for entry in onvif_entries:
            if not isinstance(entry, dict):
                continue
            manufacturer = sanitize_text(entry.get("manufacturer"))
            model = sanitize_text(entry.get("model"))
            firmware = sanitize_text(entry.get("firmware"))
            serial = sanitize_text(entry.get("serial"))
            if manufacturer or model:
                add(25, "onvif device info", "onvif")
            if firmware or serial:
                add(8, "onvif firmware/serial", "onvif")

    ssdp_entries = host.get("ssdp") or []
    if ssdp_entries:
        add(10, "ssdp metadata", "ssdp")
        for entry in ssdp_entries:
            if not isinstance(entry, dict):
                continue
            location = sanitize_text(entry.get("location"))
            if location and contains_keyword(location, SSDP_LOCATION_HINTS):
                add(10, "ssdp device description", "ssdp")
            manufacturer = sanitize_text(entry.get("manufacturer"))
            model = sanitize_text(entry.get("model"))
            if manufacturer or model:
                add(12, "ssdp device info", "ssdp")

    if host.get("mac"):
        add(3, "mac address observed", "mac")

    if len(signals) >= 3:
        add(10, "multi-signal confirmation", "boost")
    if "rtsp" in signals and "onvif" in signals:
        add(10, "rtsp + onvif alignment", "boost")

    if score > 100:
        score = 100

    level = "low"
    if score >= 70:
        level = "very_high"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"

    classification = "camera"
    model_hint = sanitize_text(profile.get("model"))
    vendor_hint = vendor
    onvif_hint = ""
    if onvif_entries:
        for entry in onvif_entries:
            if isinstance(entry, dict):
                onvif_hint += " " + sanitize_text(entry.get("manufacturer"))
                onvif_hint += " " + sanitize_text(entry.get("model"))
    recorder_blob = f"{meta_blob} {model_hint} {vendor_hint} {onvif_hint}"
    if recorder_blob and contains_keyword(recorder_blob, RECORDER_KEYWORDS):
        classification = "recorder"
    else:
        protocol_names = {
            sanitize_text(entry.get("protocol"))
            for entry in protocols
            if isinstance(entry, dict)
        }
        if "WebRTC" in protocol_names and "RTSP" not in protocol_names:
            classification = "webrtc-camera"
        elif "SRT" in protocol_names:
            classification = "streamer"

    return {
        "score": score,
        "level": level,
        "classification": classification,
        "reasons": reasons[:6],
        "signals": sorted(signals),
    }


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    data = load_json(input_path)

    hosts = data.get("hosts") or []
    if not isinstance(hosts, list):
        hosts = []

    for host in hosts:
        if isinstance(host, dict):
            host["confidence"] = score_host(host)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
