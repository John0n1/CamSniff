#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SRC="data/rtsp_paths.csv"
[[ -s "$SRC" ]] || { echo "[ERROR] Missing or empty $SRC"; exit 1; }

# Emulate camsniff.sh CSV parsing to extract RTSP URLs
mapfile -t URLS < <(
  awk -F',' '
    NR==1 { for(i=1;i<=NF;i++) if($i ~ /^rtsp_url$/) col=i; next }
    NR>1 && col>0 { gsub(/^[ \"\t]+|[ \"\t]+$/, "", $col); if($col ~ /^rtsp:\/\//) print $col }
  ' "$SRC" | tr -d '"' | sort -u
)
if (( ${#URLS[@]} == 0 )); then
  mapfile -t URLS < <(awk -F',' '{for(i=1;i<=NF;i++) if($i ~ /rtsp:\/\//) print $i}' "$SRC" | tr -d '"' | sort -u)
fi

if (( ${#URLS[@]} == 0 )); then
  echo "[ERROR] No RTSP URLs parsed from $SRC"
  exit 1
fi

bad=0
for u in "${URLS[@]}"; do
  [[ "$u" =~ ^rtsp:// ]] || { bad=1; break; }
  [[ "$u" == *"{{"*"}}"* ]] || true # allow templates to exist but not required for all
done

(( bad == 0 )) || { echo "[ERROR] Found malformed RTSP URL"; printf '%s\n' "${URLS[@]}" | head -5; exit 1; }

echo "[OK] Parsed ${#URLS[@]} RTSP URL patterns from $SRC"
printf '%s\n' "${URLS[@]:0:5}" | sed 's/^/[SAMPLE] /'
