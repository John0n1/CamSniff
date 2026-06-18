#!/usr/bin/env python3
"""Convert IVRE JSON scan output to CSV format."""

import json
import sys

print("IP,MAC,Vendor,Model,Ports,Credentials,Protocols")
for line in sys.stdin:
    try:
        doc = json.loads(line)
        ip = doc.get("addr", "")
        mac = ""
        vendor = "Unknown"
        model = "Unknown"
        has_creds = "credentials-found" in doc.get("categories", [])

        for addr in doc.get("addresses", []):
            if addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                break

        ports: list[str] = []
        for port_info in doc.get("ports", []):
            port = port_info.get("port", -1)
            if port > 0:
                ports.append(str(port))

        protocols: list[str] = []
        for port_info in doc.get("ports", []):
            for script in port_info.get("scripts", []):
                if script.get("id") == "camsniff-vendor":
                    vendor_data = script.get("camsniff-vendor", {})
                    vendor = vendor_data.get("company", "Unknown")
                    model = vendor_data.get("model", "Unknown")
                elif script.get("id") == "camsniff-protocols":
                    proto_list = script.get("camsniff-protocols", [])
                    for proto in proto_list:
                        protocols.append(proto.get("protocol", ""))

        print(
            f"{ip},{mac},{vendor},{model},"
            f"{';'.join(ports)},{has_creds},{';'.join(set(protocols))}"
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
