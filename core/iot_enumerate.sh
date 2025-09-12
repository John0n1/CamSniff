#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# IoT enumeration and auxiliary discovery
# This file is intended to be sourced by camsniff.sh

log_iot(){ printf "\e[35m[IoT %s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"; }
log_debug_iot(){ printf "\e[34m[IoT-DEBUG %s]\e[0m %s\n" "$(date +'%H:%M:%S')" "$*"; }

# Globals expected from env_setup.sh / camsniff.sh
# - OUTPUT_DIR, SUBNET, IF

# Paths
IOT_REPORT_DIR="${OUTPUT_DIR:-.}/reports"
mkdir -p "$IOT_REPORT_DIR"

# ---------------------------------------------
# mDNS enumeration (via avahi-browse)
# ---------------------------------------------
enumerate_mdns(){
  if command -v avahi-browse >/dev/null 2>&1; then
    log_iot "Enumerating mDNS services"
    avahi-browse -art 2>/dev/null | tee "$IOT_REPORT_DIR/mdns_services.txt" >/dev/null || true
  else
    log_debug_iot "avahi-browse not found; skipping mDNS enumeration"
  fi
}

# ---------------------------------------------
# UPnP/SSDP discovery (multi-ST queries)
# ---------------------------------------------
enumerate_upnp(){
  log_iot "Enumerating UPnP/SSDP devices"
  local ssdp_req
  # Broad search targets
  local -a STS=(
    "ssdp:all"
    "upnp:rootdevice"
    "urn:schemas-upnp-org:device:Basic:1"
    "urn:schemas-upnp-org:service:WANIPConnection:1"
    "urn:schemas-upnp-org:service:AVTransport:1"
  )
  : >"$IOT_REPORT_DIR/ssdp_devices.txt"
  for st in "${STS[@]}"; do
    ssdp_req=$'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:2\r\nST:'"$st"$'\r\n\r\n'
    printf "%b" "$ssdp_req" | nc -u -w3 239.255.255.250 1900 \
      | sed "s/^/[ST=$st] /" | tee -a "$IOT_REPORT_DIR/ssdp_devices.txt" >/dev/null || true
  done
}

# ---------------------------------------------
# Bluetooth LE scan (if supported)
# ---------------------------------------------
enumerate_ble(){
  [[ "${ENABLE_BLE_SCAN:-1}" -eq 1 ]] || { log_debug_iot "BLE scan disabled"; return; }
  if command -v bluetoothctl >/dev/null 2>&1; then
    log_iot "Scanning Bluetooth LE devices (10s)"
    # Power on controller if off
    bluetoothctl <<<'power on' >/dev/null 2>&1 || true
    timeout 12 bash -c 'bluetoothctl --timeout 10 scan on' \
      | tee "$IOT_REPORT_DIR/ble_scan.txt" >/dev/null || true
  elif command -v hcitool >/dev/null 2>&1; then
    log_iot "Scanning Bluetooth LE devices with hcitool (10s)"
    timeout 10 hcitool lescan 2>&1 | tee "$IOT_REPORT_DIR/ble_scan.txt" >/dev/null || true
  else
    log_debug_iot "No BLE scan tool found"
  fi
}

# ---------------------------------------------
# Zigbee/Z-Wave detection (USB dongles)
# ---------------------------------------------
detect_zigbee_zwave(){
  [[ "${ENABLE_ZIGBEE_ZWAVE_SCAN:-1}" -eq 1 ]] || { log_debug_iot "Zigbee/Z-Wave detection disabled"; return; }
  log_iot "Detecting Zigbee/Z-Wave adapters"
  local out_file="$IOT_REPORT_DIR/zigbee_zwave_adapters.txt"
  : >"$out_file"
  # Prefer find over ls to handle unusual filenames
  find /dev -maxdepth 1 \( -name 'ttyACM*' -o -name 'ttyUSB*' \) -printf '%f\n' 2>/dev/null \
    | sed 's/^/[DEV] /' | tee -a "$out_file" >/dev/null || true
  dmesg | grep -iE 'zigbee|zwave|z-wave|ncp|silicon labs|cc2531|cc2652|zwave' \
    | tail -n 100 | tee -a "$out_file" >/dev/null || true
}

# ---------------------------------------------
# Wireless scan for camera OUIs (requires iw or nmcli)
# ---------------------------------------------
scan_wireless_cameras(){
  [[ "${ENABLE_WIFI_SCAN:-1}" -eq 1 ]] || { log_debug_iot "WiFi scan disabled"; return; }
  log_iot "Scanning WiFi for potential camera vendors"
  local out_file="$IOT_REPORT_DIR/wifi_scan.txt"
  : >"$out_file"

  # Build a small OUI regex set from RTSP data if available
  local -a OUIS
  if [[ -f "$SCRIPT_DIR/data/rtsp_paths.csv" ]]; then
    mapfile -t OUIS < <(awk -F',' 'NR>1 {print $4}' "$SCRIPT_DIR/data/rtsp_paths.csv" | tr -d '"' | tr '|' '\n' | sed 's/[() ]//g' | grep -E '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){2}$' | sort -u | head -n 100)
  fi
  local oui_regex
  if ((${#OUIS[@]})); then
    oui_regex="$(printf '%s|' "${OUIS[@]}" | sed 's/|$//')"
  else
    # Minimal fallback set
    oui_regex='00:40:8C|C4:2F:90|B0:C5:54|28:10:7B|AC:CC:8E'
  fi

  if command -v iw >/dev/null 2>&1; then
    iw dev 2>/dev/null | awk '/Interface/ {print $2}' | while read -r iface; do
      timeout 8 iw dev "$iface" scan 2>/dev/null | awk '/BSS /{print $2}' \
        | sed 's/(on.*)//' | tee -a "$out_file" >/dev/null || true
    done
  elif command -v nmcli >/dev/null 2>&1; then
    timeout 8 nmcli -f BSSID,SSID dev wifi list 2>/dev/null | tee -a "$out_file" >/dev/null || true
  else
    log_debug_iot "No WiFi scanner (iw/nmcli) available"
  fi

  # Highlight potential camera vendors by OUI
  if [[ -s "$out_file" ]]; then
    grep -Ei "$oui_regex" "$out_file" | sed 's/^/[CAM-OUI] /' | tee "$IOT_REPORT_DIR/wifi_camera_candidates.txt" >/dev/null || true
  fi
}

# ---------------------------------------------
# Custom protocol heuristics (quick banner checks)
# ---------------------------------------------
analyze_custom_protocols(){
  local targets=()
  # Collect known alive hosts from arp table as a base
  mapfile -t targets < <(arp -an 2>/dev/null | awk '{print $2}' | tr -d '()' | grep -E '^[0-9.]+$' | sort -u)
  ((${#targets[@]})) || return 0
  log_iot "Analyzing custom protocols on ${#targets[@]} hosts"
  local ports=(37777 5000 8000 8899 2000 10000)
  local out_json="$IOT_REPORT_DIR/custom_protocols.json"
  echo '[' >"$out_json"
  local first=1
  for ip in "${targets[@]}"; do
    for p in "${ports[@]}"; do
      if timeout 2 bash -c "</dev/tcp/$ip/$p" 2>/dev/null; then
        local banner
        banner=$(echo -ne "\n" | timeout 2 nc -nv "$ip" "$p" 2>/dev/null | head -n1 | tr -d '\r') || true
        # Escape double quotes in banner before embedding in JSON
        banner_escaped=${banner//\"/\\\"}
        (( first==0 )) && echo ',' >>"$out_json"
        printf '{"ip":"%s","port":%d,"banner":"%s"}' "$ip" "$p" "$banner_escaped" >>"$out_json"
        first=0
      fi
    done
  done
  echo ']' >>"$out_json"
}

# ---------------------------------------------
# Network topology map (ARP + ip neigh)
# ---------------------------------------------
build_topology(){
  log_iot "Building network topology snapshot"
  local out_json="$IOT_REPORT_DIR/topology.json"
  {
    echo '{'
    echo "  \"interface\": \"${IF}\","
    echo "  \"subnet\": \"${SUBNET}\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo '  "neighbors": ['
    local first=1
    ip neigh show dev "$IF" 2>/dev/null | awk '{print $1, $5}' | while read -r ip mac; do
      [[ -z "$ip" || -z "$mac" ]] && continue
      if [[ $first -eq 0 ]]; then echo ","; fi; first=0
      printf '    {"ip":"%s","mac":"%s"}' "$ip" "$mac"
    done
    echo
    echo '  ]'
    echo '}'
  } >"$out_json"
}

# ---------------------------------------------
# Traffic capture (pcap)
# ---------------------------------------------
start_pcap_capture(){
  [[ "${ENABLE_PCAP_CAPTURE:-0}" -eq 1 ]] || return 0
  if pgrep -f "tcpdump .* -i $IF .* -w .*camsniff_" >/dev/null 2>&1; then
    return 0
  fi
  log_iot "Starting tcpdump capture on $IF"
  local pcap_dir="$OUTPUT_DIR/logs"
  mkdir -p "$pcap_dir"
  nohup tcpdump -i "$IF" -U -n -w "$pcap_dir/camsniff_%Y%m%d_%H%M%S.pcap" \
    '(rtsp or port 554 or port 80 or port 3702 or port 1900 or port 8554)' \
    >/dev/null 2>&1 &
}

# ---------------------------------------------
# Single cycle to run after sweep
# ---------------------------------------------
iot_enumeration_cycle(){
  [[ "${ENABLE_IOT_ENUMERATION:-1}" -eq 1 ]] || { log_debug_iot "IoT enumeration disabled"; return; }
  start_pcap_capture
  enumerate_mdns
  enumerate_upnp
  scan_wireless_cameras
  enumerate_ble
  detect_zigbee_zwave
  analyze_custom_protocols
  build_topology
}

log_debug_iot "iot_enumerate.sh loaded"
