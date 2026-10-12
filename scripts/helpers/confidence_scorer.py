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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

SOURCE_WEIGHTS = {
    # Discovery sources answer "we know this host exists", not "this is a camera".
    # Keep them intentionally weak so repeated generic discovery cannot dominate.
    "SSDP": 3,
    "Avahi": 4,
    "TShark": 3,
    "Nmap": 1,
    "Masscan": 1,
    "CoAP": 2,
}

PORT_WEIGHTS = {
    # Ports are hints only. Even RTSP-adjacent ports are not identity evidence.
    554: 8,
    8554: 7,
    10554: 7,
    5544: 6,
    1935: 3,
    1936: 3,
    37777: 5,
    37778: 5,
    37779: 5,
    8000: 2,
    8001: 2,
    8899: 2,
    9000: 2,
    7001: 2,
    5000: 2,
    5001: 2,
}

HTTP_PORTS = {80, 81, 82, 88, 443, 7443, 8000, 8080, 8081, 8088, 8443}
STREAM_PORTS = {554, 8554, 10554, 5544, 1935, 1936, 3478, 5349, 9710, 9999}

PROTOCOL_WEIGHTS = {
    "ONVIF": 32,
    "RTSP": 24,
    "HLS": 8,
    "RTMP": 6,
    "WebRTC": 6,
    "SRT": 4,
    "HTTP": 2,
    "SSDP": 2,
    "CoAP": 2,
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

# Strong application fingerprints that contradict the generic camera hypothesis.
# Keep these narrow: a negative match can suppress an otherwise plausible host.
NON_CAMERA_KEYWORDS = {
    "home assistant": "home automation controller",
    "openwrt": "network router",
    "pfsense": "network firewall",
    "opnsense": "network firewall",
    "router": "network router",
    "wireless gateway": "network gateway",
    "proxmox": "virtualization host",
    "printer": "network printer",
    "cups": "print server",
    "chromecast": "casting device",
    "google tv": "television/streaming device",
    "android tv": "television/streaming device",
    "dial-multiscreen-org": "DIAL casting device",
    "roku": "television/streaming device",
    "smart tv": "television",
}

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


@dataclass(frozen=True)
class Evidence:
    """One inspectable contribution to a host classification."""

    kind: str
    source: str
    weight: int
    reason: str
    polarity: str = "positive"
    value: Optional[str] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score CamSniff discovery hosts")
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


def _unique_protocol_names(host: Dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for entry in host.get("additional_protocols") or []:
        if not isinstance(entry, dict):
            continue
        name = sanitize_text(entry.get("protocol"))
        if name:
            names.add(name)
    return names


def _dedupe_entries(entries: Any) -> List[Dict[str, Any]]:
    """Deduplicate repeated discovery responses before they contribute evidence."""
    if not isinstance(entries, list):
        return []
    unique: List[Dict[str, Any]] = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        marker = json.dumps(entry, sort_keys=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(entry)
    return unique


def _camera_anchors(host: Dict[str, Any], meta_blob: str) -> set[str]:
    """Return independent camera-specific anchors, excluding generic discovery."""
    anchors: set[str] = set()
    protocol_names = _unique_protocol_names(host)
    if "ONVIF" in protocol_names or host.get("onvif"):
        anchors.add("onvif")
    if "RTSP" in protocol_names:
        anchors.add("rtsp")

    rtsp = host.get("rtsp_bruteforce") or {}
    if isinstance(rtsp, dict) and (rtsp.get("discovered") or rtsp.get("other_responses")):
        anchors.add("rtsp")

    for native in host.get("rtsp_probe") or []:
        if isinstance(native, dict) and native.get("verified"):
            anchors.add("rtsp")

    observed_paths = host.get("observed_paths") or []
    for path in observed_paths:
        if not path:
            continue
        if any(re.search(pattern, str(path), re.IGNORECASE) for pattern in PATH_PATTERNS):
            anchors.add("camera_path")
            break

    if meta_blob and contains_keyword(meta_blob, CAMERA_KEYWORDS):
        anchors.add("camera_banner")

    profile = host.get("profile_match") or {}
    matched_by = {
        part.strip().lower()
        for part in sanitize_text(profile.get("matched_by")).split("+")
        if part.strip()
    }
    # A profile is an anchor only when backed by identity/protocol evidence.
    if matched_by & {"oui", "http", "onvif", "rtsp", "ssdp", "path"}:
        anchors.add("profile")

    return anchors


def plan_probes(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Choose follow-up phases without escalating generic devices by default."""
    ports = {port for port in host.get("ports") or [] if isinstance(port, int)}
    paths = " ".join(
        sanitize_text(path).lower() for path in host.get("observed_paths") or []
    )
    meta_blob = flatten_metadata(host)
    anchors = _camera_anchors(host, meta_blob)
    plan: List[Dict[str, Any]] = []

    # HTTP metadata is low impact and useful for classification, so generic web
    # endpoints may receive this one shallow follow-up.
    if ports & HTTP_PORTS:
        plan.append(
            {
                "probe": "http_metadata",
                "priority": 40,
                "reason": "HTTP service available for device classification",
            }
        )

    # ONVIF/stream probing requires at least one camera-specific anchor, or a
    # dedicated stream port/path. Generic SSDP/HTTP alone is deliberately insufficient.
    if ports & HTTP_PORTS and (
        anchors
        or "onvif" in paths
        or any(port in {3702, 8899} for port in ports)
    ):
        plan.append(
            {
                "probe": "onvif_metadata",
                "priority": 80,
                "reason": "camera-specific evidence justifies ONVIF follow-up",
            }
        )
    if anchors or ports & STREAM_PORTS or contains_keyword(paths, OBSERVED_PATH_HINTS):
        plan.append(
            {
                "probe": "stream_protocols",
                "priority": 70,
                "reason": "camera/stream evidence justifies protocol verification",
            }
        )
    return plan


def score_host(host: Dict[str, Any]) -> Dict[str, Any]:
    camera_score = 0
    device_score = 0
    reasons: List[str] = []
    evidence: List[Evidence] = []
    signals = set()

    def add_camera(
        points: int,
        reason: str,
        signal: Optional[str] = None,
        *,
        kind: str = "observation",
        source: str = "discovery",
        value: Optional[str] = None,
    ) -> None:
        nonlocal camera_score
        camera_score += points
        evidence.append(Evidence(kind, source, points, reason, "positive", value))
        if reason and reason not in reasons:
            reasons.append(reason)
        if signal:
            signals.add(signal)

    def add_device(points: int) -> None:
        nonlocal device_score
        device_score += points

    def subtract(
        points: int,
        reason: str,
        *,
        kind: str = "application_fingerprint",
        source: str = "metadata",
        value: Optional[str] = None,
    ) -> None:
        nonlocal camera_score
        camera_score -= points
        evidence.append(Evidence(kind, source, points, reason, "negative", value))
        if reason and reason not in reasons:
            reasons.append(reason)

    # Generic discovery contributes primarily to device confidence.
    for source in sorted({sanitize_text(item) for item in host.get("sources") or []}):
        if source in SOURCE_WEIGHTS:
            add_device(8)
            add_camera(SOURCE_WEIGHTS[source], f"{source.lower()} discovery", "source")

    ports = sorted({port for port in host.get("ports") or [] if isinstance(port, int)})
    if ports:
        add_device(min(20, 4 + len(ports) * 2))
    for port in ports:
        if port in PORT_WEIGHTS:
            add_camera(PORT_WEIGHTS[port], f"camera-adjacent port {port}", "port")
    if any(port in HTTP_PORTS for port in ports):
        add_camera(1, "http service present", "port")

    protocol_names = _unique_protocol_names(host)
    for name in sorted(protocol_names):
        add_device(10)
        if name in PROTOCOL_WEIGHTS:
            signal = "protocol"
            if name == "RTSP":
                signal = "rtsp"
            elif name == "ONVIF":
                signal = "onvif"
            add_camera(PROTOCOL_WEIGHTS[name], f"{name.lower()} verified", signal, source="protocol")

    rtsp = host.get("rtsp_bruteforce") or {}
    discovered = rtsp.get("discovered") or [] if isinstance(rtsp, dict) else []
    other = rtsp.get("other_responses") or {} if isinstance(rtsp, dict) else {}
    if isinstance(discovered, list) and discovered:
        add_camera(30, "rtsp url discovered", "rtsp", source="rtsp_bruteforce")
    elif isinstance(other, dict) and other:
        add_camera(14, "rtsp response observed", "rtsp", source="rtsp_bruteforce")

    native_verified = False
    native_media = False
    for native in _dedupe_entries(host.get("rtsp_probe")):
        if not native.get("verified"):
            continue
        native_verified = True
        state = sanitize_text(native.get("state"))
        if state == "media-described":
            native_media = True
    if native_media:
        add_camera(45, "rtsp media described", "rtsp", source="rtsp_probe")
    elif native_verified:
        add_camera(30, "rtsp protocol verified", "rtsp", source="rtsp_probe")

    observed_paths = host.get("observed_paths") or []
    unique_paths = sorted({sanitize_text(item) for item in observed_paths if sanitize_text(item)})
    path_hits = 0
    for path in unique_paths:
        if any(re.search(pattern, path, re.IGNORECASE) for pattern in PATH_PATTERNS):
            path_hits += 1
    if path_hits:
        add_camera(min(24, 12 + (path_hits - 1) * 4), "camera path signature", "path")
    elif unique_paths and contains_keyword(" ".join(unique_paths), OBSERVED_PATH_HINTS):
        add_camera(8, "stream-like path observed", "path")

    profile = host.get("profile_match") or {}
    vendor = sanitize_text(profile.get("vendor"))
    matched_by = {
        part.strip().lower()
        for part in sanitize_text(profile.get("matched_by")).split("+")
        if part.strip()
    }
    profile_strength = 0
    if matched_by & {"onvif", "rtsp"}:
        profile_strength = 24
    elif matched_by & {"oui", "http", "ssdp"}:
        profile_strength = 12
    elif "path" in matched_by:
        profile_strength = 8
    # Never award camera confidence for a port-only profile.
    if vendor and vendor.lower() != "unknown" and profile_strength:
        add_camera(profile_strength, "evidence-backed vendor profile", "profile")
        add_device(12)

    meta_blob = flatten_metadata(host)
    if meta_blob:
        add_device(18)
    if meta_blob and contains_keyword(meta_blob, CAMERA_KEYWORDS):
        add_camera(22, "camera keyword in metadata", "banner")
    if meta_blob and contains_keyword(meta_blob, VENDOR_KEYWORDS):
        add_camera(10, "camera-vendor keyword in metadata", "banner")

    negative_matches: List[str] = []
    lowered_metadata = meta_blob.lower()
    for keyword, identity in NON_CAMERA_KEYWORDS.items():
        if keyword in lowered_metadata and identity not in negative_matches:
            negative_matches.append(identity)
            subtract(55, f"identified as {identity}", value=keyword)

    onvif_entries = _dedupe_entries(host.get("onvif"))
    if onvif_entries:
        add_device(20)
        add_camera(18, "onvif service verified", "onvif", source="onvif")
        if any(
            sanitize_text(entry.get("manufacturer")) or sanitize_text(entry.get("model"))
            for entry in onvif_entries
        ):
            add_camera(22, "onvif device identity", "onvif", source="onvif")

    ssdp_entries = _dedupe_entries(host.get("ssdp"))
    if ssdp_entries:
        # SSDP richness identifies a device, not a camera. Count the whole SSDP
        # family once instead of rewarding every repeated response/URN.
        add_device(min(24, 10 + len(ssdp_entries) * 2))
        if any(
            contains_keyword(
                " ".join(sanitize_text(value) for value in entry.values()),
                CAMERA_KEYWORDS,
            )
            for entry in ssdp_entries
        ):
            add_camera(12, "camera-specific ssdp metadata", "ssdp", source="ssdp")

    if host.get("mac"):
        add_device(8)

    meta_blob = flatten_metadata(host)
    anchors = _camera_anchors(host, meta_blob)
    independent_anchors = len(anchors)
    if independent_anchors >= 2:
        add_camera(10, "independent camera evidence agrees", "boost")
    if "rtsp" in anchors and "onvif" in anchors:
        add_camera(12, "rtsp + onvif alignment", "boost")

    camera_score = max(0, min(camera_score, 100))
    device_score = max(0, min(device_score, 100))

    # Classification is gated by camera-specific anchors, not raw score alone.
    if negative_matches and not ({"rtsp", "onvif"} <= anchors):
        classification = "non-camera"
    elif not anchors:
        classification = "network-device" if device_score >= 20 else "unknown"
    elif (
        "rtsp" in anchors
        and ("onvif" in anchors or native_media)
        and camera_score >= 70
    ):
        classification = "confirmed-camera"
    elif independent_anchors >= 2 and camera_score >= 50:
        classification = "probable-camera"
    else:
        classification = "camera-candidate"

    model_hint = sanitize_text(profile.get("model"))
    vendor_hint = vendor
    onvif_hint = " ".join(
        f"{sanitize_text(entry.get('manufacturer'))} {sanitize_text(entry.get('model'))}"
        for entry in onvif_entries
    )
    recorder_blob = f"{meta_blob} {model_hint} {vendor_hint} {onvif_hint}"
    if recorder_blob and contains_keyword(recorder_blob, RECORDER_KEYWORDS):
        classification = "recorder"

    level = "low"
    if camera_score >= 70:
        level = "very_high"
    elif camera_score >= 50:
        level = "high"
    elif camera_score >= 25:
        level = "medium"

    return {
        # score remains the camera-likelihood score for schema compatibility.
        "score": camera_score,
        "camera_score": camera_score,
        "device_score": device_score,
        "level": level,
        "classification": classification,
        "reasons": reasons[:8],
        "signals": sorted(signals),
        "camera_anchors": sorted(anchors),
        "evidence": [asdict(item) for item in evidence],
        "positive_score": min(
            100, sum(item.weight for item in evidence if item.polarity == "positive")
        ),
        "negative_score": min(
            100, sum(item.weight for item in evidence if item.polarity == "negative")
        ),
        "probe_plan": plan_probes(host),
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
