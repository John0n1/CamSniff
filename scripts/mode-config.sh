#!/usr/bin/env bash
#
# CamSniff- Automated IP camera reconnaissance toolkit
# By John Hauger Mitander <john@on1.no>
# Copyright 2025 John Hauger Mitander
#
# SPDX-License-Identifier: MIT
# mode-config.sh

set -euo pipefail

MODE="medium"
FORMAT="export"

print_usage() {
    cat <<'EOF'
Usage: mode-config.sh [--mode <name>] [--format export|json]

Available modes:
  stealth
  stealth+
  medium
  aggressive
  war
  nuke
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)
            MODE="${2:-}"
            shift 2
            ;;
        -f|--format)
            FORMAT="${2:-}"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

norm_mode=$(printf '%s' "$MODE" | tr '[:upper:]' '[:lower:]')
norm_mode=${norm_mode// /-}

case "$norm_mode" in
    stealth)
        MASSCAN_ENABLE=false
        MASSCAN_RATE=0
        NMAP_SPEED="-T2"
        NMAP_EXTRA=""
        PORT_PROFILE="core"
        TSHARK_DURATION=20
        CURL_TIMEOUT=5
        FFMPEG_TIMEOUT=6
        MAX_CREDENTIALS=12
        HTTP_RETRIES=1
        BRUTE_WINDOW=60
        ;;
    stealth+|stealth+)
        MASSCAN_ENABLE=false
        MASSCAN_RATE=0
        NMAP_SPEED="-T1"
        NMAP_EXTRA="--scan-delay 200ms"
        PORT_PROFILE="minimal"
        TSHARK_DURATION=15
        CURL_TIMEOUT=6
        FFMPEG_TIMEOUT=8
        MAX_CREDENTIALS=8
        HTTP_RETRIES=1
        BRUTE_WINDOW=90
        norm_mode="stealth+"
        ;;
    medium|default)
        MASSCAN_ENABLE=true
        MASSCAN_RATE=1000
        NMAP_SPEED="-T4"
        NMAP_EXTRA=""
        PORT_PROFILE="standard"
        TSHARK_DURATION=35
        CURL_TIMEOUT=8
        FFMPEG_TIMEOUT=10
        MAX_CREDENTIALS=32
        HTTP_RETRIES=2
        BRUTE_WINDOW=120
        norm_mode="medium"
        ;;
    aggressive)
        MASSCAN_ENABLE=true
        MASSCAN_RATE=5000
        NMAP_SPEED="-T4"
        NMAP_EXTRA="-A"
        PORT_PROFILE="extended"
        TSHARK_DURATION=45
        CURL_TIMEOUT=10
        FFMPEG_TIMEOUT=12
        MAX_CREDENTIALS=64
        HTTP_RETRIES=2
        BRUTE_WINDOW=150
        ;;
    war)
        MASSCAN_ENABLE=true
        MASSCAN_RATE=12000
        NMAP_SPEED="-T5"
        NMAP_EXTRA="-A"
        PORT_PROFILE="war"
        TSHARK_DURATION=55
        CURL_TIMEOUT=12
        FFMPEG_TIMEOUT=15
        MAX_CREDENTIALS=96
        HTTP_RETRIES=3
        BRUTE_WINDOW=180
        ;;
    nuke|nuke)
        MASSCAN_ENABLE=true
        MASSCAN_RATE=20000
        NMAP_SPEED="-T5"
        NMAP_EXTRA="-A --script vuln"
        PORT_PROFILE="total"
        TSHARK_DURATION=75
        CURL_TIMEOUT=15
        FFMPEG_TIMEOUT=20
        MAX_CREDENTIALS=128
        HTTP_RETRIES=4
        BRUTE_WINDOW=240
        norm_mode="nuke"
        ;;
    *)
        echo "Unknown mode: $MODE" >&2
        print_usage >&2
        exit 1
        ;;
esac

case "$FORMAT" in
    export)
        CAM_MODE_RAW="$MODE"
        CAM_MODE_NORMALIZED="$norm_mode"
        CAM_MODE_MASSCAN_ENABLE="$MASSCAN_ENABLE"
        CAM_MODE_MASSCAN_RATE="$MASSCAN_RATE"
        CAM_MODE_NMAP_SPEED="$NMAP_SPEED"
        CAM_MODE_NMAP_EXTRA="$NMAP_EXTRA"
        CAM_MODE_PORT_PROFILE="$PORT_PROFILE"
        CAM_MODE_TSHARK_DURATION="$TSHARK_DURATION"
        CAM_MODE_CURL_TIMEOUT="$CURL_TIMEOUT"
        CAM_MODE_FFMPEG_TIMEOUT="$FFMPEG_TIMEOUT"
        CAM_MODE_MAX_CREDENTIALS="$MAX_CREDENTIALS"
        CAM_MODE_HTTP_RETRIES="$HTTP_RETRIES"
        CAM_MODE_BRUTE_WINDOW="$BRUTE_WINDOW"

        export \
            CAM_MODE_RAW \
            CAM_MODE_NORMALIZED \
            CAM_MODE_MASSCAN_ENABLE \
            CAM_MODE_MASSCAN_RATE \
            CAM_MODE_NMAP_SPEED \
            CAM_MODE_NMAP_EXTRA \
            CAM_MODE_PORT_PROFILE \
            CAM_MODE_TSHARK_DURATION \
            CAM_MODE_CURL_TIMEOUT \
            CAM_MODE_FFMPEG_TIMEOUT \
            CAM_MODE_MAX_CREDENTIALS \
            CAM_MODE_HTTP_RETRIES \
            CAM_MODE_BRUTE_WINDOW

        if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
            cat <<EOF
export CAM_MODE_RAW="$CAM_MODE_RAW"
export CAM_MODE_NORMALIZED="$CAM_MODE_NORMALIZED"
export CAM_MODE_MASSCAN_ENABLE="$CAM_MODE_MASSCAN_ENABLE"
export CAM_MODE_MASSCAN_RATE="$CAM_MODE_MASSCAN_RATE"
export CAM_MODE_NMAP_SPEED="$CAM_MODE_NMAP_SPEED"
export CAM_MODE_NMAP_EXTRA="$CAM_MODE_NMAP_EXTRA"
export CAM_MODE_PORT_PROFILE="$CAM_MODE_PORT_PROFILE"
export CAM_MODE_TSHARK_DURATION="$CAM_MODE_TSHARK_DURATION"
export CAM_MODE_CURL_TIMEOUT="$CAM_MODE_CURL_TIMEOUT"
export CAM_MODE_FFMPEG_TIMEOUT="$CAM_MODE_FFMPEG_TIMEOUT"
export CAM_MODE_MAX_CREDENTIALS="$CAM_MODE_MAX_CREDENTIALS"
export CAM_MODE_HTTP_RETRIES="$CAM_MODE_HTTP_RETRIES"
export CAM_MODE_BRUTE_WINDOW="$CAM_MODE_BRUTE_WINDOW"
EOF
        fi
        ;;
    json)
        jq -n \
            --arg raw "$MODE" \
            --arg normalized "$norm_mode" \
            --arg masscan_enable "$MASSCAN_ENABLE" \
            --argjson masscan_rate "$MASSCAN_RATE" \
            --arg nmap_speed "$NMAP_SPEED" \
            --arg nmap_extra "$NMAP_EXTRA" \
            --arg port_profile "$PORT_PROFILE" \
            --argjson tshark_duration "$TSHARK_DURATION" \
            --argjson curl_timeout "$CURL_TIMEOUT" \
            --argjson ffmpeg_timeout "$FFMPEG_TIMEOUT" \
            --argjson max_credentials "$MAX_CREDENTIALS" \
            --argjson http_retries "$HTTP_RETRIES" \
            --argjson brute_window "$BRUTE_WINDOW" \
            ' {
                mode: $raw,
                normalized: $normalized,
                masscan_enable: ($masscan_enable == "true"),
                masscan_rate: $masscan_rate,
                nmap_speed: $nmap_speed,
                nmap_extra: $nmap_extra,
                port_profile: $port_profile,
                tshark_duration: $tshark_duration,
                curl_timeout: $curl_timeout,
                ffmpeg_timeout: $ffmpeg_timeout,
                max_credentials: $max_credentials,
                http_retries: $http_retries,
                brute_window: $brute_window
            }'
        ;;
    *)
        echo "Unknown format: $FORMAT" >&2
        print_usage >&2
        exit 1
        ;;
 esac
