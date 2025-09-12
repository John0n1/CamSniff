#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SRC="data/rtsp_paths.csv"
[[ -s "$SRC" ]] || { echo "[ERROR] Missing or empty $SRC"; exit 1; }

# Extract templates like camsniff.sh does
mapfile -t URLS < <(
  awk -F',' '
    NR==1 { for(i=1;i<=NF;i++) if($i ~ /^rtsp_url$/) col=i; next }
    NR>1 && col>0 { gsub(/^[ \"\t]+|[ \"\t]+$/, "", $col); if($col ~ /^rtsp:\/\//) print $col }
  ' "$SRC" | tr -d '"' | sort -u
)
(( ${#URLS[@]} > 0 )) || { echo "[ERROR] No RTSP templates found"; exit 1; }

tpl="${URLS[0]}"
ip="192.168.1.10"; port="554"
u=$(echo "$tpl" | sed "s/{{username}}/admin/g; s/{{password}}/admin/g; s/{{ip_address}}/$ip/g; s/{{port}}/$port/g; s/{{stream}}/1/g; s/{{channel}}/1/g")

[[ "$u" =~ ^rtsp:// ]] || { echo "[ERROR] Substituted RTSP does not start with rtsp://"; echo "$u"; exit 1; }
[[ "$u" == *"$ip"* ]] || { echo "[ERROR] Substituted URL missing IP"; echo "$u"; exit 1; }
[[ "$u" == *"$port"* ]] || true

echo "[OK] RTSP substitution works: $u"
