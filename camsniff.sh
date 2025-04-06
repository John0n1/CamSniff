#!/bin/bash
#
# camsniff.sh
#
# A stealthy IP camera & IoT device detection/monitoring script
# that avoids system-wide pip installation by using a local Python venv.
#
# Compatible with Debian 12 ("externally-managed-environment") and others.
#
# 1) Installs system packages with apt (if missing) – but no pip installs system-wide.
# 2) Sets up ./camsniff_venv for Python-based tasks (wsdiscovery, scapy, onvif-zeep).
# 3) Launches continuous passive + active scanning loop:
#    - Passive: tcpdump for ARP/DHCP, SSDP/mDNS/ONVIF, DNS queries
#    - Active: ARP sweep (arp-scan), stealthy Nmap on typical camera ports,
#              RTSP brute force (ffprobe), ONVIF WS-Discovery via local venv Python,
#              HTTP banner & screenshot (curl + cutycapt).
#
# Run as root (sudo ./camsniff.sh). It will create camsniff_venv/ if needed.
# Logs go to ./logs, captures to ./captures, screenshots to ./screenshots.
#

########################
# 1) Privilege check
########################
if [[ $EUID -ne 0 ]]; then
  echo "[-] Please run as root (sudo). Exiting."
  exit 1
fi

########################
# 2) APT-based dependencies
########################
echo "[+] Checking/installing required apt packages (no pip system-wide)..."
APT_PACKAGES=(
  tcpdump tshark nmap arp-scan avahi-utils ffmpeg curl jq
  cutycapt python3 python3-venv)

apt-get update -qq
for pkg in "${APT_PACKAGES[@]}"; do
  if ! dpkg -l | grep -q "^ii\s\+$pkg"; then
    echo "[+] Installing $pkg ..."
    apt-get install -y "$pkg"
  fi
done

########################
# 3) Local Python venv
########################
if [ ! -d "./camsniff_venv" ]; then
  echo "[+] Creating local Python venv in ./watchtower_venv..."
  python3 -m venv ./camsniff_venv
  echo "[+] Installing wsdiscovery, scapy, onvif-zeep in venv..."
  ./camsniff_venv/bin/pip install --upgrade pip
  ./camsniff_venv/bin/pip install wsdiscovery scapy onvif-zeep
fi

########################
# 4) Setup directories
########################
mkdir -p logs captures screenshots
touch logs/camsniff.log logs/arp_scan.log logs/live_hosts.txt \
      logs/found_streams.log logs/http_banners.log logs/onvif_devices.log \
      logs/mac_vendors.log logs/dns_suspicious.log

########################
# 5) Identify interface & subnet
########################
INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
if [[ -z "$INTERFACE" ]]; then
  echo "[-] Could not parse default interface from routing table. Using eth0."
  INTERFACE="eth0"
fi
SUBNET=$(ip route show dev "$INTERFACE" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' | head -n1)
if [[ -z "$SUBNET" ]]; then
  # fallback
  SUBNET="192.168.1.0/24"
fi

echo "[+] Using interface: $INTERFACE"
echo "[+] Using subnet:    $SUBNET"
echo "[+] Logs in ./logs/, captures in ./captures/, screenshots in ./screenshots/"

########################
# 6) Start Passive Sniffers
########################
echo "[+] Starting tcpdump for ARP & DHCP..."
tcpdump -i "$INTERFACE" -n -q \
  '(arp or (udp and (port 67 or 68)))' \
  -w captures/arp_dhcp.pcap 2>/dev/null &

echo "[+] Starting tcpdump for multicast (SSDP/mDNS/ONVIF)..."
tcpdump -i "$INTERFACE" -n -q \
  '(host 239.255.255.250 or udp port 5353 or udp port 3702)' \
  -w captures/multicast.pcap 2>/dev/null &

echo "[+] Starting tcpdump for DNS (udp 53)..."
tcpdump -i "$INTERFACE" -n -q \
  'udp port 53' \
  -w captures/dns_queries.pcap 2>/dev/null &

# Avahi daemon for mDNS announcements
avahi-daemon --daemonize &>/dev/null

########################
# 7) DNS Query Parser (Optional)
########################
function parse_dns_queries() {
  # Example suspicious domains: ring.com, ezvizlife.com, nest.com, etc.
  local suspicious=("ring.com" "ezvizlife.com" "nest.com" "cloud.p2pserver.com" "hik-connect.com" "dahuaddns.com")

  echo "--- [$(date)] DNS Parser Round ---" >> logs/dns_suspicious.log

  # Use tshark to parse the entire pcap for new DNS queries.
  while read -r domain; do
    domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]')
    for sdom in "${suspicious[@]}"; do
      if [[ "$domain" == *"$sdom" ]]; then
        echo "[!] Suspicious camera DNS query => $domain" | tee -a logs/dns_suspicious.log
      fi
    done
  done < <(tshark -r captures/dns_queries.pcap -T fields -e dns.qry.name -Y "dns.qry.type == 1" 2>/dev/null | sort -u)
}

########################
# 8) ONVIF WS-Discovery via venv Python
########################
function onvif_discovery() {
  # We call the local python in camsniff_venv, using the recommended ThreadedWSDiscovery
  ./camsniff_venv/bin/python <<EOF
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery

wsd = WSDiscovery()
wsd.start()

services = wsd.searchServices()
with open('logs/onvif_devices.log', 'a') as f:
    f.write("\\n--- ONVIF Discovery @ $(date) ---\\n")
    for svc in services:
        epr = svc.getEPR()
        scopes = svc.getScopes()
        xaddrs = svc.getXAddrs()
        f.write(f"Device EPR: {epr}\\n")
        f.write(f"Scopes: {scopes}\\n")
        f.write(f"XAddrs: {xaddrs}\\n\\n")

wsd.stop()
EOF
}

########################
# 9) Cleanup on exit
########################
trap cleanup INT TERM

function cleanup() {
  echo "[+] Stopping background processes..."
  kill $(jobs -p) &>/dev/null || true
  avahi-daemon --kill &>/dev/null || true
  exit 0
}

########################
# 10) Main Active Scan Loop
########################
SLEEP_SECONDS=300  # 5 minutes

while true; do
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[+] [$TIMESTAMP] Starting active sweep/scans..." | tee -a logs/camsniff.log

  # 10a) ARP Sweep
  echo "[+] ARP scan on $INTERFACE..."
  arp-scan -l -q --interface "$INTERFACE" | tee logs/arp_scan.log
  grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' logs/arp_scan.log > logs/live_hosts.txt

  # 10b) Stealthy Nmap
  echo "[+] Nmap scanning for camera ports on discovered hosts..."
  nmap -sS -T2 --open -p80,443,554,8080,8554,8000,37777,5000 \
       -iL logs/live_hosts.txt -oX logs/nmap_scan.xml

  # 10c) RTSP brute force
  echo "--- [$(date)] RTSP Brute Force Round ---" >> logs/found_streams.log
  COMMON_RTSP_PATHS=(
    "live.sdp" "stream1" "axis-media/media.amp" "video1" "video" "0"
    "cam/realmonitor" "h264" "mjpeg" "media.smp" "ch0_0.h264" "ch1.h264"
    "Streaming/Channels/101" "Streaming/Channels/102" "av0_0" "av1_0"
  )
  while read -r ip; do
    # If port 554 is open, attempt RTSP paths
    if grep -A10 "<address addr=\"$ip\"" logs/nmap_scan.xml | grep 'portid="554" state="open"' >/dev/null; then
      echo "[+] Checking RTSP paths on $ip..."
      for path in "${COMMON_RTSP_PATHS[@]}"; do
        url="rtsp://$ip:554/$path"
        ffprobe -v error -rtsp_transport tcp -timeout 3000000 -i "$url" 2>&1 | grep -Eq "Stream.*Video|Unauthorized"
        if [[ $? -eq 0 ]]; then
          echo "[FOUND] $ip => $url" | tee -a logs/found_streams.log
          break
        fi
      done
    fi
  done < logs/live_hosts.txt

  # 10d) HTTP banner & screenshot
  echo "--- [$(date)] HTTP Banner Round ---" >> logs/http_banners.log
  while read -r ip; do
    open_http=$(grep -A10 "<address addr=\"$ip\"" logs/nmap_scan.xml | \
                grep -E 'portid="80"|portid="8080"' | grep 'state="open"')
    if [[ -n "$open_http" ]]; then
      title=$(curl -s --connect-timeout 3 "http://$ip" | grep -oP '(?<=<title>).*?(?=</title>)' | head -n1)
      if [[ -n "$title" ]]; then
        echo "[$(date)] HTTP at $ip => $title" | tee -a logs/http_banners.log
      else
        echo "[$(date)] HTTP at $ip => No <title> found" | tee -a logs/http_banners.log
      fi
      cutycapt --url="http://$ip" --out="screenshots/${ip}_ui.png" \
        --min-width=800 --min-height=600 &>/dev/null || true
    fi
  done < logs/live_hosts.txt

  # 10e) ONVIF WS-Discovery
  echo "[+] Sending ONVIF WS-Discovery probe..."
  onvif_discovery

  # 10f) MAC vendor
  echo "--- [$(date)] MAC Vendor Round ---" >> logs/mac_vendors.log
  arp-scan -l --interface "$INTERFACE" >> logs/mac_vendors.log

  # 10g) Optional: parse DNS queries
  parse_dns_queries

  # 10h) Sleep
  echo "[+] Sleeping $SLEEP_SECONDS seconds before next cycle..."
  sleep "$SLEEP_SECONDS"

done
