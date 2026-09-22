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
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

from defusedxml import ElementTree

MAX_RESPONSE = 131072
DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"

ACTIONS = {
    "device_information": "GetDeviceInformation",
    "services": "GetServices",
    "capabilities": "GetCapabilities",
    "scopes": "GetScopes",
    "network_interfaces": "GetNetworkInterfaces",
    "system_date_time": "GetSystemDateAndTime",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract ONVIF device information")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="Path to one SOAP response payload")
    source.add_argument("--url", help="ONVIF device-service URL to enumerate")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, required=True, help="Target port")
    parser.add_argument("--scheme", required=True, help="HTTP scheme")
    parser.add_argument("--timeout", type=float, default=4.0)
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


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def elements(payload: str, tag: str) -> List[Any]:
    if not payload:
        return []
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return []
    return [item for item in root.iter() if local_name(item.tag) == tag]


def soap_envelope(operation: str) -> bytes:
    extra = "<tds:IncludeCapability>false</tds:IncludeCapability>" if operation == "GetServices" else ""
    if operation == "GetCapabilities":
        extra = "<tds:Category>All</tds:Category>"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        f'xmlns:tds="{DEVICE_NS}"><s:Body><tds:{operation}>'
        f"{extra}</tds:{operation}></s:Body></s:Envelope>"
    ).encode("utf-8")


def request_action(url: str, operation: str, timeout: float) -> Dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=soap_envelope(operation),
        headers={
            "Content-Type": "application/soap+xml; charset=utf-8",
            "SOAPAction": f'"{DEVICE_NS}/{operation}"',
            "User-Agent": "CamSniff/ONVIF-Probe",
        },
        method="POST",
    )
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return {
                "status": response.status,
                "payload": response.read(MAX_RESPONSE + 1)[:MAX_RESPONSE].decode(
                    "utf-8", errors="replace"
                ),
            }
    except urllib.error.HTTPError as error:
        return {
            "status": error.code,
            "payload": error.read(MAX_RESPONSE + 1)[:MAX_RESPONSE].decode(
                "utf-8", errors="replace"
            ),
        }
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return {"status": 0, "error": error.__class__.__name__, "payload": ""}


def parse_enumeration(payloads: Dict[str, str]) -> Dict[str, Any]:
    device = payloads.get("device_information", "")
    result: Dict[str, Any] = {
        "manufacturer": extract_field(device, "Manufacturer"),
        "model": extract_field(device, "Model"),
        "firmware": extract_field(device, "FirmwareVersion"),
        "serial": extract_field(device, "SerialNumber"),
        "hardware_id": extract_field(device, "HardwareId"),
    }
    result["services"] = sorted(
        {
            " ".join((item.text or "").split())
            for item in elements(payloads.get("services", ""), "Namespace")
            if (item.text or "").strip()
        }
    )
    result["scopes"] = sorted(
        {
            " ".join((item.text or "").split())
            for item in elements(payloads.get("scopes", ""), "ScopeItem")
            if (item.text or "").strip()
        }
    )
    result["capability_xaddrs"] = sorted(
        {
            " ".join((item.text or "").split())
            for item in elements(payloads.get("capabilities", ""), "XAddr")
            if (item.text or "").strip()
        }
    )
    result["network_interfaces"] = [
        {
            "token": item.attrib.get("token", ""),
            "enabled": extract_field(ElementTree.tostring(item, encoding="unicode"), "Enabled"),
        }
        for item in elements(payloads.get("network_interfaces", ""), "NetworkInterfaces")
    ]
    time_payload = payloads.get("system_date_time", "")
    result["system_date_time"] = {
        "type": extract_field(time_payload, "DateTimeType"),
        "daylight_savings": extract_field(time_payload, "DaylightSavings"),
        "timezone": extract_field(time_payload, "TZ"),
    }
    return result


def enumerate_device(url: str, timeout: float) -> Dict[str, Any]:
    payloads: Dict[str, str] = {}
    queries: Dict[str, Dict[str, Any]] = {}
    for key, operation in ACTIONS.items():
        response = request_action(url, operation, timeout)
        payloads[key] = response.pop("payload", "")
        queries[key] = response
        if response.get("status") == 401:
            break
    result = parse_enumeration(payloads)
    result["queries"] = queries
    result["verified"] = any(query.get("status") in {200, 400, 401, 500} for query in queries.values())
    return result


def main() -> int:
    args = parse_args()
    result: Dict[str, Any] = {
        "ip": args.ip,
        "port": args.port,
        "scheme": args.scheme,
    }
    if args.url:
        result.update(enumerate_device(args.url, args.timeout))
    else:
        payload = read_payload(Path(args.input))
        result.update(parse_enumeration({"device_information": payload}))

    print(json.dumps(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
