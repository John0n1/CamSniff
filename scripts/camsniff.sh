#!/usr/bin/env bash
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$SCRIPT_DIR/core"
HELPER_DIR="$SCRIPT_DIR/helpers"
PROBE_DIR="$SCRIPT_DIR/probes"
SETUP_DIR="$SCRIPT_DIR/setup"
INTEGRATION_DIR="$SCRIPT_DIR/integrations"
UI_DIR="$SCRIPT_DIR/ui"
PATHS_FILE="${PATHS_FILE:-"$ROOT_DIR/data/catalog/paths.csv"}"
MODE_CONFIG="$CORE_DIR/mode-config.sh"
DEPS_INSTALL="$SETUP_DIR/deps-install.sh"
CREDENTIAL_PROBE="$PROBE_DIR/credential-probe.sh"
NMAP_RTSP_SCRIPT="$ROOT_DIR/data/protocols/rtsp-url-brute.nse"
NMAP_RTSP_THREADS=10
RTSP_URL_DICT="$ROOT_DIR/data/dictionaries/rtsp-urls.txt"
PORT_PROFILE_DATA="$CORE_DIR/port-profiles.sh"
UI_HELPER="$UI_DIR/banner.sh"
PROFILE_RESOLVER="$HELPER_DIR/profile_resolver.py"
CONFIDENCE_SCORER="$HELPER_DIR/confidence_scorer.py"
HTTP_META_PARSER="$HELPER_DIR/http_metadata_parser.py"
ONVIF_PARSER="$PROBE_DIR/onvif_device_info.py"
SSDP_PROBE_HELPER="$PROBE_DIR/ssdp_probe.py"
REPORT_TOOL="$ROOT_DIR/scripts/tools/report.py"

MODE_DEFAULT="medium"
MODE_REQUESTED=""
AUTO_CONFIRM=false
declare -a EXTRA_OPTIONS=()
EXTRA_IVRE_ENABLED=false
TARGET_FILE=""
declare -a TARGET_IPS=()
OUTPUT_ROOT="${CAM_RESULTS_ROOT:-}"
RUN_LABEL="${CAM_RUN_LABEL:-}"
SKIP_CREDS=false
SKIP_INSTALL=false
REPORT_FORMAT="${CAM_REPORT_FORMAT:-}"
ENCRYPT_RESULTS=false
ENCRYPT_TOOL="${CAM_ENCRYPT_TOOL:-auto}"
ENCRYPT_RECIPIENT="${CAM_ENCRYPT_RECIPIENT:-}"
ENCRYPT_PASSPHRASE="${CAM_ENCRYPT_PASSPHRASE:-}"
SMART_MODE=false
SMART_MIN_SCORE="${CAM_SMART_MIN_SCORE:-30}"
SMART_MAX_TARGETS="${CAM_SMART_MAX_TARGETS:-64}"
SMART_DISPLAY_LIMIT="${CAM_SMART_DISPLAY_LIMIT:-10}"
CONFIDENCE_READY=false
SSDP_DESCRIBE=false
SSDP_DESCRIBE_TIMEOUT="${CAM_SSDP_DESCRIBE_TIMEOUT:-3}"
SSDP_DESCRIBE_MAX="${CAM_SSDP_DESCRIBE_MAX:-24}"
if [[ -n ${CAM_SKIP_CREDENTIALS:-} ]]; then
    case "${CAM_SKIP_CREDENTIALS,,}" in
        1|true|yes|y)
            SKIP_CREDS=true
            ;;
    esac
fi
if [[ -n ${CAM_SKIP_INSTALL:-} ]]; then
    case "${CAM_SKIP_INSTALL,,}" in
        1|true|yes|y)
            SKIP_INSTALL=true
            ;;
    esac
fi
if [[ -n ${CAM_ENCRYPT_RESULTS:-} ]]; then
    case "${CAM_ENCRYPT_RESULTS,,}" in
        1|true|yes|y)
            ENCRYPT_RESULTS=true
            ;;
    esac
fi
if [[ -n ${CAM_SMART_MODE:-} ]]; then
    case "${CAM_SMART_MODE,,}" in
        1|true|yes|y)
            SMART_MODE=true
            ;;
    esac
fi
if [[ -n ${CAM_SSDP_DESCRIBE:-} ]]; then
    case "${CAM_SSDP_DESCRIBE,,}" in
        1|true|yes|y)
            SSDP_DESCRIBE=true
            ;;
    esac
fi

RESULTS_ROOT_DEFAULT="$ROOT_DIR/dev/results"
RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
RUN_STAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR=""
LOG_DIR=""
THUMB_DIR=""
DISCOVERY_JSON=""
CREDS_JSON=""
NMAP_OUTPUT_FILE=""
NMAP_LOG_FILE=""
NMAP_UDP_OUTPUT_FILE=""
NMAP_UDP_LOG_FILE=""
MASSCAN_OUTPUT_FILE=""
MASSCAN_LOG_FILE=""
AVAHI_OUTPUT_FILE=""
TSHARK_OUTPUT_FILE=""
COAP_OUTPUT_FILE=""
COAP_LOG_FILE=""
COAP_PROBE_TIMEOUT="${COAP_PROBE_TIMEOUT:-5}"
IVRE_LOG_FILE=""
HTTP_META_LOG=""
SSDP_OUTPUT_FILE=""
ONVIF_OUTPUT_FILE=""
CATALOG_JSON=""
GEOIP_DIR="$ROOT_DIR/share/geoip"
GEOIP_CITY_DB="$GEOIP_DIR/dbip-city-lite.mmdb"
GEOIP_ASN_DB="$GEOIP_DIR/dbip-asn-lite.mmdb"

RED=""
GREEN=""
YELLOW=""
ORANGE=""
BLUE=""
CYAN=""
RESET=""
BLINK=""

SPINNER_FRAMES='-\|/'
PYTHON_BIN="$(command -v python3 || echo python3)"

declare -A ip_sources
declare -A ip_to_mac
declare -A ip_ports
declare -A ip_observed_paths
declare -A all_ips
declare -A ip_rtsp_discovered
declare -A ip_rtsp_other
declare -A ip_protocol_hits
declare -A ip_http_metadata
declare -A ip_onvif_info
declare -A ip_ssdp_info
declare -A protocol_seen
declare -A ip_pre_score
declare -A ip_pre_reasons
declare -a SMART_TARGETS

nmap_output=""
nmap_log=""
masscan_output=""
masscan_log=""
avahi_output=""
tshark_output=""
hosts_json_tmp=""
discovery_enriched_tmp=""
discovery_confidence_tmp=""
coap_output_tmp=""
coap_build_log=""

print_usage() {
    cat <<'EOF'
Usage: camsniff.sh [--mode <name>] [--yes] [--version] [--help] [--extra <name>] [--targets <file>]

Options:
  -m, --mode <name>      Specify scanning mode (stealth, stealth+, medium, aggressive, war, nuke)
  -y, --yes              Auto-confirm interactive prompts
  -v, --version          Show version information and exit
  -h, --help             Display this help message and exit
  -t, --targets <file>   Load target IP addresses/ranges from file (JSON or text format)
                         JSON format: {"targets": ["192.168.1.0/24", "10.0.0.1"]}
                         (Requires 'jq' for JSON parsing; if jq is missing, file is treated as plain text)
                         Text format: one IP address or CIDR range per line
      --output-root <dir> Store run artifacts under this directory (default: dev/results)
      --run-name <label>  Append a label to the run directory name
      --interface <iface> Set capture interface for tshark (default: auto-detect)
      --skip-credentials  Skip the credential probing phase
      --skip-install      Skip automatic dependency installation
      --report <format>   Generate a report (markdown or html) in the run directory
      --encrypt-results   Encrypt run artifacts (auto-select age/gpg)
      --encrypt-tool <t>  Force encryption tool (age or gpg)
      --encrypt-recipient <id> Recipient/key id for encryption tool
      --smart             Enable smart target shaping and confidence display
      --smart-min <score> Minimum smart score for deeper probes (default: 30)
      --smart-max <count> Max targets for deeper probes (default: 64)
      --ssdp-describe    Fetch SSDP device descriptions for richer fingerprints

Optional integrations:
    --extra <name>         Enable additional integrations (currently supported: ivre)

If no mode is provided, the balanced profile (medium) is used.
EOF
}

sanitize_run_label() {
    local raw="$1"
    raw=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')
    raw=${raw// /-}
    raw=$(printf '%s' "$raw" | sed 's/[^a-z0-9._-]/-/g; s/--*/-/g; s/^-//; s/-$//')
    printf '%s' "$raw"
}

configure_run_paths() {
    local base="${OUTPUT_ROOT:-$RESULTS_ROOT_DEFAULT}"
    if [[ $base == "~"* ]]; then
        base="${base/#\~/$HOME}"
    fi
    RESULTS_ROOT="$base"

    local label=""
    if [[ -n $RUN_LABEL ]]; then
        label=$(sanitize_run_label "$RUN_LABEL")
    fi

    if [[ -n $label ]]; then
        RUN_DIR="$RESULTS_ROOT/${RUN_STAMP}-${label}"
    else
        RUN_DIR="$RESULTS_ROOT/$RUN_STAMP"
    fi

    LOG_DIR="$RUN_DIR/logs"
    THUMB_DIR="$RUN_DIR/thumbnails"
    DISCOVERY_JSON="$RUN_DIR/discovery.json"
    CREDS_JSON="$RUN_DIR/credentials.json"
    NMAP_OUTPUT_FILE="$LOG_DIR/nmap-output.txt"
    NMAP_LOG_FILE="$LOG_DIR/nmap-command.log"
    NMAP_UDP_OUTPUT_FILE="$LOG_DIR/nmap-udp-output.txt"
    NMAP_UDP_LOG_FILE="$LOG_DIR/nmap-udp-command.log"
    MASSCAN_OUTPUT_FILE="$LOG_DIR/masscan-output.json"
    MASSCAN_LOG_FILE="$LOG_DIR/masscan-command.log"
    AVAHI_OUTPUT_FILE="$LOG_DIR/avahi-services.txt"
    TSHARK_OUTPUT_FILE="$LOG_DIR/tshark-traffic.csv"
    COAP_OUTPUT_FILE="$LOG_DIR/coap-discovery.txt"
    COAP_LOG_FILE="$LOG_DIR/coap-probe.log"
    IVRE_LOG_FILE="$LOG_DIR/ivre-sync.log"
    HTTP_META_LOG="$LOG_DIR/http-metadata.jsonl"
    SSDP_OUTPUT_FILE="$LOG_DIR/ssdp-discovery.jsonl"
    ONVIF_OUTPUT_FILE="$LOG_DIR/onvif-discovery.jsonl"
    CATALOG_JSON="$RUN_DIR/paths.json"
}

normalize_target_line() {
    local line="$1"
    line=${line%%#*}
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    printf '%s' "$line"
}

is_integer() {
    [[ ${1:-} =~ ^[0-9]+$ ]]
}

is_valid_ipv4() {
    local ip="$1"
    local o1 o2 o3 o4 extra
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [[ -n $extra || -z $o1 || -z $o2 || -z $o3 || -z $o4 ]] && return 1
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

is_valid_ipv4_cidr() {
    local value="$1"
    local ip="$value"
    local mask=""
    if [[ $value == */* ]]; then
        ip="${value%%/*}"
        mask="${value#*/}"
    fi
    is_valid_ipv4 "$ip" || return 1
    if [[ -n $mask ]]; then
        [[ $mask =~ ^[0-9]{1,2}$ ]] || return 1
        (( mask >= 0 && mask <= 32 )) || return 1
    fi
    return 0
}

parse_target_file() {
    local file="$1"
    local -a parsed_targets=()
    local -A seen=()

    add_target() {
        local target="$1"
        target=$(normalize_target_line "$target")
        [[ -z $target ]] && return
        if ! is_valid_ipv4_cidr "$target"; then
            echo "Warning: Skipping malformed target '$target'" >&2
            return
        fi
        if [[ -n ${seen[$target]+set} ]]; then
            return
        fi
        seen["$target"]=1
        parsed_targets+=("$target")
    }
    
    if [[ ! -f "$file" ]]; then
        echo "Error: Target file not found: $file" >&2
        return 1
    fi
    
    # Try to parse as JSON first
    if command -v jq >/dev/null 2>&1; then
        if jq empty "$file" 2>/dev/null; then
            # Valid JSON - extract targets array
            # Check if .targets key exists
            if ! jq -e 'has("targets")' "$file" >/dev/null 2>&1; then
                echo "Error: JSON file missing 'targets' key" >&2
                return 1
            fi
            # Check if .targets is an array
            if ! jq -e '.targets | type == "array"' "$file" >/dev/null 2>&1; then
                echo "Error: JSON file 'targets' key is not an array" >&2
                return 1
            fi
            # Check if .targets array is empty
            if [[ $(jq '.targets | length' "$file") -eq 0 ]]; then
                echo "Error: JSON file 'targets' array is empty" >&2
                return 1
            fi
            local targets_json
            targets_json=$(jq -r '.targets[]' "$file" 2>/dev/null)
            while IFS= read -r target; do
                add_target "$target"
            done <<< "$targets_json"
        else
            # Not valid JSON, treat as text file
            while IFS= read -r line || [[ -n $line ]]; do
                add_target "$line"
            done < "$file"
        fi
    else
        # No jq available, treat as text file
        while IFS= read -r line || [[ -n $line ]]; do
            add_target "$line"
        done < "$file"
    fi
    
    if (( ${#parsed_targets[@]} == 0 )); then
        echo "Error: No valid targets found in file: $file" >&2
        return 1
    fi
    
    # Return targets as newline-separated list
    printf '%s\n' "${parsed_targets[@]}"
    return 0
}

detect_capture_interface() {
    local iface=""
    if command -v ip >/dev/null 2>&1; then
        iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    fi
    if [[ -z $iface && -r /proc/net/route ]]; then
        iface=$(awk '($2 == "00000000") {print $1; exit}' /proc/net/route)
    fi
    printf '%s' "$iface"
}

detect_default_network() {
    local iface=""
    local cidr=""
    if command -v ip >/dev/null 2>&1; then
        iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
        if [[ -n $iface ]]; then
            cidr=$(ip -o -f inet addr show dev "$iface" 2>/dev/null | awk 'NR==1 {print $4; exit}')
        fi
    fi
    if [[ -z $cidr ]]; then
        cidr=$(ip route | awk '/default/ {print $3; exit}' | sed 's/\.[0-9]*$/.0\/24/')
    fi
    printf '%s' "$cidr"
}

record_protocol_hit() {
    local ip="$1"
    local proto="$2"
    local detail="$3"
    [[ -z $ip || -z $proto || -z $detail ]] && return
    local key="$ip|$proto|$detail"
    if [[ -n ${protocol_seen[$key]+set} ]]; then
        return
    fi
    protocol_seen["$key"]=1
    ip_protocol_hits["$ip"]+="$proto|$detail"$'\n'
}

port_in_list() {
    local ports_string="$1"
    local needle="$2"
    while IFS= read -r candidate; do
        [[ -z $candidate ]] && continue
        if [[ $candidate == "$needle" ]]; then
            return 0
        fi
    done <<< "$ports_string"
    return 1
}

check_tcp_connectivity() {
    local ip="$1"
    local port="$2"
    local timeout_s="${3:-3}"
    timeout "$timeout_s" bash -c "cat < /dev/null > /dev/tcp/$ip/$port" 2>/dev/null
}

http_scheme_for_port() {
    case "$1" in
        443|8443|7443|9443|10443)
            echo "https"
            ;;
        *)
            echo "http"
            ;;
    esac
}

detect_rtmp() {
    local ip="$1"
    local ports_string="$2"
    while IFS= read -r port; do
        [[ -z $port ]] && continue
        case "$port" in
            1935|1936|19350|2935|544|5544)
                if check_tcp_connectivity "$ip" "$port" 2; then
                    record_protocol_hit "$ip" "RTMP" "tcp/$port reachable"
                fi
                ;;
        esac
    done <<< "$ports_string"
}

detect_onvif() {
    local ip="$1"
    local ports_string="$2"
    local http_timeout="${CURL_TIMEOUT:-8}"
    if (( http_timeout < 4 )); then http_timeout=4; fi
    local ports=(80 81 88 8000 8080 8081 8088 8443 443 7443)
    local port
    for port in "${ports[@]}"; do
        port_in_list "$ports_string" "$port" || continue
        local scheme
        scheme=$(http_scheme_for_port "$port")
        local url="${scheme}://${ip}:${port}/onvif/device_service"
        local code
        code=$(http_status_for "$url" "$http_timeout")
        if [[ $code =~ ^(200|301|302|401|405|500)$ ]]; then
            record_protocol_hit "$ip" "ONVIF" "$url (HTTP $code)"
            continue
        fi
        url="${scheme}://${ip}:${port}/onvif/media_service"
        code=$(http_status_for "$url" "$http_timeout")
        if [[ $code =~ ^(200|301|302|401|405|500)$ ]]; then
            record_protocol_hit "$ip" "ONVIF" "$url (HTTP $code)"
        fi
    done
}

detect_hls() {
    local ip="$1"
    local ports_string="$2"
    local http_timeout="${CURL_TIMEOUT:-8}"
    (( http_timeout < 6 )) && http_timeout=6
    (( http_timeout > 12 )) && http_timeout=12
    local ports=(80 81 88 443 8000 8080 8081 8443)
    local paths=("/live.m3u8" "/playlist.m3u8" "/index.m3u8" "/stream.m3u8" "/hls/stream.m3u8" "/video.m3u8")
    local port
    for port in "${ports[@]}"; do
        port_in_list "$ports_string" "$port" || continue
        local scheme
        scheme=$(http_scheme_for_port "$port")
        local base="${scheme}://${ip}:${port}"
        local path
        for path in "${paths[@]}"; do
            local url="$base$path"
            local body
            body=$(http_body_snippet "$url" 10 "$http_timeout")
            if [[ $body == *"#EXTM3U"* ]]; then
                record_protocol_hit "$ip" "HLS" "$url"
                return
            fi
        done
    done
}

detect_webrtc() {
    local ip="$1"
    local ports_string="$2"
    local http_timeout="${CURL_TIMEOUT:-8}"
    (( http_timeout < 4 )) && http_timeout=4
    (( http_timeout > 10 )) && http_timeout=10
    local stun_ports=(3478 5349)
    local port
    for port in "${stun_ports[@]}"; do
        if port_in_list "$ports_string" "$port"; then
            record_protocol_hit "$ip" "WebRTC" "STUN/TURN port $port open"
        fi
    done

    local http_ports=(80 81 88 443 8443 8000 8080 8081)
    local paths=("/webrtc" "/webrtc/stream" "/webrtc/api" "/api/webrtc" "/rtc/stream" "/webrtc/config")
    local scheme
    for port in "${http_ports[@]}"; do
        port_in_list "$ports_string" "$port" || continue
        scheme=$(http_scheme_for_port "$port")
        local base="${scheme}://${ip}:${port}"
        local path
        for path in "${paths[@]}"; do
            local url="$base$path"
            local code
            code=$(http_status_for "$url" "$http_timeout")
            if [[ $code =~ ^(200|201|202|204|401|403)$ ]]; then
                record_protocol_hit "$ip" "WebRTC" "$url (HTTP $code)"
                return
            fi
        done
    done
}

collect_http_metadata_for_ip() {
    local ip="$1"
    local ports_string="$2"
    local max_ports=4
    local count=0
    local headers_tmp body_tmp
    headers_tmp=$(mktemp /tmp/camsniff-http-headers.XXXXXX)
    body_tmp=$(mktemp /tmp/camsniff-http-body.XXXXXX)
    local -a candidate_ports=()
    local known_http_ports=(80 81 82 88 443 7443 8000 8001 8080 8081 8088 8443 9000 10443)
    while IFS= read -r port; do
        [[ -z $port ]] && continue
        for known in "${known_http_ports[@]}"; do
            if [[ $port == "$known" ]]; then
                candidate_ports+=("$port")
                break
            fi
        done
    done <<< "$ports_string"

    (( ${#candidate_ports[@]} == 0 )) && { rm -f "$headers_tmp" "$body_tmp"; return; }

    for port in "${candidate_ports[@]}"; do
        (( count >= max_ports )) && break
        local scheme
        scheme=$(http_scheme_for_port "$port")
        local url="${scheme}://${ip}:${port}/"
        local log_path="$LOG_DIR/http-${ip//[^a-zA-Z0-9._-]/_}-${port}.log"
        local http_code=""
        http_code=$(curl -k -sS -m "$CURL_TIMEOUT" --connect-timeout "$CURL_TIMEOUT" \
            --retry "$HTTP_RETRIES" --retry-delay 1 --retry-connrefused \
            --location --dump-header "$headers_tmp" --output "$body_tmp" \
            -w "%{http_code}" "$url" 2>"$log_path" || true)
        if [[ -z $http_code ]]; then
            continue
        fi

        if command -v "$PYTHON_BIN" >/dev/null 2>&1 && [[ -f $HTTP_META_PARSER ]]; then
            local meta_json
            meta_json=$("$PYTHON_BIN" "$HTTP_META_PARSER" --headers "$headers_tmp" --body "$body_tmp" --ip "$ip" --port "$port" --scheme "$scheme" 2>/dev/null || true)
            if [[ -n $meta_json ]]; then
                ip_http_metadata["$ip"]+="$meta_json"$'\n'
                echo "$meta_json" >> "$HTTP_META_LOG"
                if [[ $http_code =~ ^(200|201|202|204|301|302|401|403|404)$ ]]; then
                    record_protocol_hit "$ip" "HTTP" "$url (HTTP $http_code)"
                fi
            fi
        fi
        ((count++))
    done
    rm -f "$headers_tmp" "$body_tmp"
}

probe_onvif_device_info() {
    local ip="$1"
    local ports_string="$2"
    local soap_payload
    soap_payload='<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>'
    local max_ports=3
    local count=0
    while IFS= read -r port; do
        [[ -z $port ]] && continue
        case "$port" in
            80|81|88|8000|8080|8081|8088|8443|443|7443)
                ;;
            *)
                continue
                ;;
        esac
        (( count >= max_ports )) && break
        local scheme
        scheme=$(http_scheme_for_port "$port")
        local url="${scheme}://${ip}:${port}/onvif/device_service"
        local body_tmp
        body_tmp=$(mktemp /tmp/camsniff-onvif.XXXXXX)
        local log_path="$LOG_DIR/onvif-${ip//[^a-zA-Z0-9._-]/_}-${port}.log"
        local http_code=""
        http_code=$(curl -k -sS -m "$CURL_TIMEOUT" --connect-timeout "$CURL_TIMEOUT" \
            -H "Content-Type: application/soap+xml; charset=utf-8" \
            -H "SOAPAction: \"http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation\"" \
            -d "$soap_payload" -o "$body_tmp" -w "%{http_code}" "$url" 2>"$log_path" || true)
        if [[ $http_code =~ ^(200|401|500)$ ]]; then
            record_protocol_hit "$ip" "ONVIF" "$url (HTTP $http_code)"
        fi
        if command -v "$PYTHON_BIN" >/dev/null 2>&1 && [[ -f $ONVIF_PARSER ]]; then
            local parsed
            parsed=$("$PYTHON_BIN" "$ONVIF_PARSER" --input "$body_tmp" --ip "$ip" --port "$port" --scheme "$scheme" 2>/dev/null || true)
            if [[ -n $parsed && $parsed != "{}" ]]; then
                ip_onvif_info["$ip"]+="$parsed"$'\n'
                echo "$parsed" >> "$ONVIF_OUTPUT_FILE"
            fi
        fi
        rm -f "$body_tmp"
        ((count++))
    done <<< "$ports_string"
}

detect_srt_from_ports() {
    local ip="$1"
    local ports_string="$2"
    while IFS= read -r port; do
        [[ -z $port ]] && continue
        case "$port" in
            9710|9999|60020|4200|2088|50000)
                record_protocol_hit "$ip" "SRT" "port $port open"
                ;;
        esac
    done <<< "$ports_string"
}

run_udp_service_scan() {
    local -a ip_list=("$@")
    (( ${#ip_list[@]} == 0 )) && return
    local udp_ports="3702,3478,5349,9710,9999"
    local udp_output
    udp_output=$(mktemp)
    local udp_log
    udp_log=$(mktemp)
    if nmap -sU -Pn -n -T4 --max-retries 2 --host-timeout 30s -p "$udp_ports" -oN "$udp_output" "${ip_list[@]}" > "$udp_log" 2>&1; then
        local current_ip=""
        while IFS= read -r line; do
            if [[ $line =~ ^Nmap\ scan\ report\ for\ ([^[:space:]]+) ]]; then
                current_ip=${BASH_REMATCH[1]}
            elif [[ $line =~ ^([0-9]+)/udp[[:space:]]+open ]]; then
                local port="${BASH_REMATCH[1]}"
                [[ -z $current_ip ]] && continue
                track_port "$current_ip" "$port"
                case "$port" in
                    3702)
                        record_protocol_hit "$current_ip" "ONVIF" "WS-Discovery UDP 3702 open"
                        ;;
                    3478|5349)
                        record_protocol_hit "$current_ip" "WebRTC" "STUN/TURN UDP $port open"
                        ;;
                    9710|9999)
                        record_protocol_hit "$current_ip" "SRT" "UDP port $port open"
                        ;;
                esac
            elif [[ $line =~ ^([0-9]+)/udp[[:space:]]+open/filtered ]]; then
                local port="${BASH_REMATCH[1]}"
                [[ -z $current_ip ]] && continue
                track_port "$current_ip" "$port"
                case "$port" in
                    3478|5349)
                        record_protocol_hit "$current_ip" "WebRTC" "STUN/TURN UDP $port open/filtered"
                        ;;
                    9710|9999)
                        record_protocol_hit "$current_ip" "SRT" "UDP port $port open/filtered"
                        ;;
                esac
            fi
        done < "$udp_output"
        if [[ -n ${NMAP_UDP_OUTPUT_FILE:-} ]]; then
            cp "$udp_output" "$NMAP_UDP_OUTPUT_FILE" 2>/dev/null || true
        fi
        if [[ -n ${NMAP_UDP_LOG_FILE:-} ]]; then
            cp "$udp_log" "$NMAP_UDP_LOG_FILE" 2>/dev/null || true
        fi
    else
        echo -e "${YELLOW}Warning: UDP protocol probe via nmap failed. See logs for details.${RESET}" >&2
    fi
    rm -f "$udp_output" "$udp_log"
}

probe_additional_protocols() {
    local ip
    local ports_string
    local ip_list=()
    if [[ ${CAM_MODE_FOLLOWUP_SERVICE_SCAN_ENABLE,,} != "true" ]]; then
        return
    fi
    mapfile -t ip_list < <(get_probe_targets)
    (( ${#ip_list[@]} == 0 )) && return

    : "${NMAP_UDP_OUTPUT_FILE:=$LOG_DIR/nmap-udp-output.txt}"
    : "${NMAP_UDP_LOG_FILE:=$LOG_DIR/nmap-udp-command.log}"

    run_udp_service_scan "${ip_list[@]}"

    for ip in "${ip_list[@]}"; do
        ports_string=$(printf "%s" "${ip_ports[$ip]}" | tr ' ' '\n' | sed '/^$/d' | sort -u)
        detect_srt_from_ports "$ip" "$ports_string"
        detect_rtmp "$ip" "$ports_string"
        detect_onvif "$ip" "$ports_string"
        detect_hls "$ip" "$ports_string"
        detect_webrtc "$ip" "$ports_string"
    done
}

collect_http_metadata() {
    [[ ${CAM_MODE_HTTP_METADATA_ENABLE,,} != "true" ]] && return
    (( ${#all_ips[@]} == 0 )) && return
    if [[ ! -f $HTTP_META_PARSER ]]; then
        echo -e "${YELLOW}Skipping HTTP metadata collection (missing helper: $HTTP_META_PARSER).${RESET}"
        return
    fi
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        echo -e "${YELLOW}Skipping HTTP metadata collection (python3 unavailable).${RESET}"
        return
    fi
    : > "$HTTP_META_LOG"
    local -a targets=()
    mapfile -t targets < <(get_probe_targets)
    local ip
    for ip in "${targets[@]}"; do
        local ports_string
        ports_string=$(printf "%s" "${ip_ports[$ip]}" | tr ' ' '\n' | sed '/^$/d' | sort -u)
        collect_http_metadata_for_ip "$ip" "$ports_string"
    done
}

run_onvif_metadata_probe() {
    [[ ${CAM_MODE_ONVIF_PROBE_ENABLE,,} != "true" ]] && return
    (( ${#all_ips[@]} == 0 )) && return
    if [[ ! -f $ONVIF_PARSER ]]; then
        echo -e "${YELLOW}Skipping ONVIF metadata probe (missing parser: $ONVIF_PARSER).${RESET}"
        return
    fi
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        echo -e "${YELLOW}Skipping ONVIF metadata probe (python3 unavailable).${RESET}"
        return
    fi
    : > "$ONVIF_OUTPUT_FILE"
    local -a targets=()
    mapfile -t targets < <(get_probe_targets)
    local ip
    for ip in "${targets[@]}"; do
        local ports_string
        ports_string=$(printf "%s" "${ip_ports[$ip]}" | tr ' ' '\n' | sed '/^$/d' | sort -u)
        probe_onvif_device_info "$ip" "$ports_string"
    done
}

run_ssdp_discovery() {
    [[ ${CAM_MODE_SSDP_ENABLE,,} != "true" ]] && return
    if [[ ! -f $SSDP_PROBE_HELPER ]]; then
        echo -e "${YELLOW}Skipping SSDP discovery (helper missing: $SSDP_PROBE_HELPER).${RESET}"
        return
    fi
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        echo -e "${YELLOW}Skipping SSDP discovery (python3 unavailable).${RESET}"
        return
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}Skipping SSDP discovery (jq unavailable).${RESET}"
        return
    fi
    local ssdp_tmp
    ssdp_tmp=$(mktemp /tmp/camsniff-ssdp.XXXXXX)
    local -a ssdp_args=(--timeout 4 --mx 2 --st "ssdp:all" --output "$ssdp_tmp")
    if [[ $SSDP_DESCRIBE == true ]]; then
        ssdp_args+=(--describe --describe-timeout "$SSDP_DESCRIBE_TIMEOUT" --max-describe "$SSDP_DESCRIBE_MAX")
    fi
    if "$PYTHON_BIN" "$SSDP_PROBE_HELPER" "${ssdp_args[@]}" >/dev/null 2>&1; then
        : > "$SSDP_OUTPUT_FILE"
        while IFS= read -r line; do
            [[ -z $line ]] && continue
            local ip
            ip=$(jq -r '.ip // empty' <<<"$line")
            [[ -z $ip ]] && continue
            append_source "$ip" "SSDP"
            ip_ssdp_info["$ip"]+="$line"$'\n'
            local st
            st=$(jq -r '.st // "ssdp:all"' <<<"$line")
            record_protocol_hit "$ip" "SSDP" "$st"
            local location
            location=$(jq -r '.location // empty' <<<"$line")
            if [[ $location =~ ^https?://[^/:]+:([0-9]+) ]]; then
                track_port "$ip" "${BASH_REMATCH[1]}"
            fi
            echo "$line" >> "$SSDP_OUTPUT_FILE"
        done < "$ssdp_tmp"
    else
        echo -e "${YELLOW}SSDP discovery failed to run successfully.${RESET}"
    fi
    rm -f "$ssdp_tmp"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode)
            MODE_REQUESTED="${2:-}"
            if [[ -z $MODE_REQUESTED ]]; then
                echo "--mode requires a value" >&2
                exit 1
            fi
            shift 2
            ;;
        -y|--yes|--assume-yes)
            AUTO_CONFIRM=true
            shift
            ;;
        -v|--version)
            if [[ -f "$ROOT_DIR/VERSION" ]]; then
                cat "$ROOT_DIR/VERSION"
            else
                echo "CamSniff version information unavailable"
            fi
            exit 0
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        -t|--targets|--target-file)
            TARGET_FILE="${2:-}"
            if [[ -z $TARGET_FILE ]]; then
                echo "--targets requires a file path" >&2
                exit 1
            fi
            shift 2
            ;;
        --output-root|--results-root)
            OUTPUT_ROOT="${2:-}"
            if [[ -z $OUTPUT_ROOT ]]; then
                echo "--output-root requires a directory path" >&2
                exit 1
            fi
            shift 2
            ;;
        --run-name|--run-label)
            RUN_LABEL="${2:-}"
            if [[ -z $RUN_LABEL ]]; then
                echo "--run-name requires a label value" >&2
                exit 1
            fi
            shift 2
            ;;
        --interface|--tshark-interface)
            TSHARK_INTERFACE="${2:-}"
            if [[ -z $TSHARK_INTERFACE ]]; then
                echo "--interface requires a capture interface name" >&2
                exit 1
            fi
            shift 2
            ;;
        --skip-credentials|--skip-creds|--no-credentials|--no-creds)
            SKIP_CREDS=true
            shift
            ;;
        --skip-install|--no-install|--no-deps)
            SKIP_INSTALL=true
            shift
            ;;
        --smart)
            SMART_MODE=true
            shift
            ;;
        --smart-min)
            SMART_MIN_SCORE="${2:-}"
            if [[ -z $SMART_MIN_SCORE ]]; then
                echo "--smart-min requires a numeric score" >&2
                exit 1
            fi
            shift 2
            ;;
        --smart-max)
            SMART_MAX_TARGETS="${2:-}"
            if [[ -z $SMART_MAX_TARGETS ]]; then
                echo "--smart-max requires a numeric count" >&2
                exit 1
            fi
            shift 2
            ;;
        --ssdp-describe)
            SSDP_DESCRIBE=true
            shift
            ;;
        --report)
            REPORT_FORMAT="${2:-}"
            if [[ -z $REPORT_FORMAT ]]; then
                echo "--report requires a format (markdown or html)" >&2
                exit 1
            fi
            shift 2
            ;;
        --encrypt-results)
            ENCRYPT_RESULTS=true
            if [[ -n ${2:-} && ${2:0:1} != "-" ]]; then
                ENCRYPT_TOOL="${2:-}"
                shift 2
            else
                shift
            fi
            ;;
        --encrypt-results=*)
            ENCRYPT_RESULTS=true
            ENCRYPT_TOOL="${1#*=}"
            shift
            ;;
        --encrypt-tool)
            ENCRYPT_TOOL="${2:-}"
            if [[ -z $ENCRYPT_TOOL ]]; then
                echo "--encrypt-tool requires a value (age or gpg)" >&2
                exit 1
            fi
            shift 2
            ;;
        --encrypt-recipient)
            ENCRYPT_RECIPIENT="${2:-}"
            if [[ -z $ENCRYPT_RECIPIENT ]]; then
                echo "--encrypt-recipient requires a recipient value" >&2
                exit 1
            fi
            shift 2
            ;;
        --extra)
            extra_value="${2:-}"
            if [[ -z $extra_value ]]; then
                echo "--extra requires a value" >&2
                exit 1
            fi
            EXTRA_OPTIONS+=("$extra_value")
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -* )
            echo "Unknown option: $1" >&2
            print_usage >&2
            exit 1
            ;;
        * )
            echo "Unexpected argument: $1" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

MODE_SELECTED=${MODE_REQUESTED:-$MODE_DEFAULT}

if (( ${#EXTRA_OPTIONS[@]} )); then
    for extra_flag in "${EXTRA_OPTIONS[@]}"; do
        case "${extra_flag,,}" in
            ivre)
                EXTRA_IVRE_ENABLED=true
                ;;
            *)
                echo "Unknown --extra integration: $extra_flag" >&2
                exit 1
                ;;
        esac
    done
fi

if [[ -n $RUN_LABEL ]]; then
    RUN_LABEL=$(sanitize_run_label "$RUN_LABEL")
fi
configure_run_paths

if [[ -n $REPORT_FORMAT ]]; then
    REPORT_FORMAT=$(normalize_report_format "$REPORT_FORMAT")
    if [[ -z $REPORT_FORMAT ]]; then
        echo "Unknown report format. Use markdown or html." >&2
        exit 1
    fi
fi

if ! is_integer "$SMART_MIN_SCORE"; then
    echo "Warning: Invalid smart-min score; defaulting to 30." >&2
    SMART_MIN_SCORE=30
fi
if (( SMART_MIN_SCORE > 100 )); then
    SMART_MIN_SCORE=100
fi
if ! is_integer "$SMART_MAX_TARGETS"; then
    echo "Warning: Invalid smart-max count; defaulting to 64." >&2
    SMART_MAX_TARGETS=64
fi
if ! is_integer "$SSDP_DESCRIBE_MAX"; then
    SSDP_DESCRIBE_MAX=24
fi
if [[ ! $SSDP_DESCRIBE_TIMEOUT =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    SSDP_DESCRIBE_TIMEOUT=3
fi

if [[ ! -f "$MODE_CONFIG" ]]; then
    echo "Missing mode configuration helper: $MODE_CONFIG" >&2
    exit 1
fi

if [[ ! -f "$RTSP_URL_DICT" ]]; then
    echo "Warning: Custom RTSP dictionary missing at $RTSP_URL_DICT. Built-in NSE defaults will be used." >&2
fi

if ! mode_env_output="$("$MODE_CONFIG" --mode "$MODE_SELECTED" --format export)"; then
    echo "Failed to resolve mode configuration via $MODE_CONFIG" >&2
    exit 1
fi
eval "$mode_env_output"
unset mode_env_output

CURL_TIMEOUT=${CAM_MODE_CURL_TIMEOUT:-8}
HTTP_RETRIES=${CAM_MODE_HTTP_RETRIES:-2}
FFMPEG_TIMEOUT=${CAM_MODE_FFMPEG_TIMEOUT:-10}
NMAP_OSSCAN_ENABLE=${CAM_MODE_NMAP_OSSCAN_ENABLE:-false}
NMAP_VERSION_ENABLE=${CAM_MODE_NMAP_VERSION_ENABLE:-true}
export FFMPEG_TIMEOUT CURL_TIMEOUT HTTP_RETRIES

if [[ ! -f "$PORT_PROFILE_DATA" ]]; then
    echo "Missing port profile data: $PORT_PROFILE_DATA" >&2
    exit 1
fi

# shellcheck source=core/port-profiles.sh
source "$PORT_PROFILE_DATA"

if [[ ! -f "$UI_HELPER" ]]; then
    echo "Missing UI helper: $UI_HELPER" >&2
    exit 1
fi

# shellcheck source=ui/banner.sh
source "$UI_HELPER"

cam_run_with_spinner() {
    local message="$1"
    shift
    local -a command=("$@")
    if (( ${#command[@]} == 0 )); then
        return 1
    fi

    echo -e "${CYAN}${message}...${RESET}"
    "${command[@]}" &
    local pid=$!
    local frame=0
    local frame_count=${#SPINNER_FRAMES}
    local blink_state=0

    while kill -0 "$pid" 2>/dev/null; do
        if (( blink_state % 5 == 0 )); then
            # Show spinner (visible for 0.5s out of each 1s cycle)
            printf "\r${RED}[%c]${RESET} %s...${RESET} " "${SPINNER_FRAMES:frame:1}" "$message"
        else
            # Hide spinner (invisible for 0.5s out of each 1s cycle)
            printf "\r${RED}[ ]${RESET} %s...${RESET} " "$message"
        fi
        frame=$(( (frame + 1) % frame_count ))
        blink_state=$(( (blink_state + 1) % 10 ))
        sleep 0.1
    done

    wait "$pid"
    local status=$?
    printf "\r%*s\r" 80 ""
    if (( status == 0 )); then
        echo -e "${GREEN}${message} complete!${RESET}"
    else
        echo -e "${RED}${message} failed (exit ${status}).${RESET}"
    fi
    return $status
}

cam_run_packinst() {
    local message="$1"
    shift
    local -a command=("$@")
    if (( ${#command[@]} == 0 )); then
        return 1
    fi

    echo -e "${CYAN}${message}...${RESET}"
    "${command[@]}" &
    local pid=$!
    local frame=0
    local packages=("📦")
    local frame_count=${#packages[@]}

    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${BLINK}${RED}%s${RESET} %s...${RESET} " "${packages[frame]}" "$message"
        frame=$(( (frame + 1) % frame_count ))
        sleep 0.3
    done

    wait "$pid"
    local status=$?
    printf "\r%*s\r" 80 ""
    if (( status == 0 )); then
        echo -e "${GREEN}${message} complete!${RESET}"
    else
        echo -e "${RED}${message} failed (exit ${status}).${RESET}"
    fi
    return $status
}

verify_required_tools() {
    local -a required=(nmap curl jq tshark avahi-browse python3)
    if [[ $SKIP_CREDS == false ]]; then
        required+=(ffmpeg)
    fi
    local -a missing=()
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if (( ${#missing[@]} )); then
        echo -e "${RED}Missing required tools: ${missing[*]}${RESET}" >&2
        if [[ $SKIP_INSTALL == true ]]; then
            echo -e "${YELLOW}Install dependencies or rerun without --skip-install.${RESET}" >&2
        else
            echo -e "${YELLOW}Dependency install may have failed. Review the install log.${RESET}" >&2
        fi
        return 1
    fi
    return 0
}

apply_optional_tool_overrides() {
    if [[ ${CAM_MODE_MASSCAN_ENABLE,,} == "true" ]] && ! command -v masscan >/dev/null 2>&1; then
        echo -e "${YELLOW}Masscan is unavailable; disabling masscan for this run.${RESET}"
        CAM_MODE_MASSCAN_ENABLE=false
    fi
}

normalize_report_format() {
    local raw="$1"
    raw=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')
    case "$raw" in
        md|markdown)
            echo "markdown"
            ;;
        html|htm)
            echo "html"
            ;;
        both|all)
            echo "both"
            ;;
        *)
            echo ""
            ;;
    esac
}

generate_reports() {
    local format="$1"
    [[ -z $format ]] && return 0
    if [[ ! -f "$REPORT_TOOL" ]]; then
        echo -e "${YELLOW}Report generator missing: $REPORT_TOOL${RESET}"
        return 1
    fi
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        echo -e "${YELLOW}Report generation skipped (python3 unavailable).${RESET}"
        return 1
    fi

    local creds_arg=()
    if [[ -f "$CREDS_JSON" ]]; then
        creds_arg=(--credentials "$CREDS_JSON")
    fi

    local run_label="$RUN_STAMP"
    if [[ -n $RUN_LABEL ]]; then
        run_label="${RUN_STAMP}-${RUN_LABEL}"
    fi

    if [[ $format == "both" ]]; then
        local md_out="$RUN_DIR/report.md"
        local html_out="$RUN_DIR/report.html"
        if "$PYTHON_BIN" "$REPORT_TOOL" --format "markdown" --discovery "$DISCOVERY_JSON" "${creds_arg[@]}" \
            --output "$md_out" --run-dir "$RUN_DIR" --run-label "$run_label" >/dev/null 2>&1; then
            echo -e "${CYAN}Report generated:${RESET} ${GREEN}$md_out${RESET}"
        else
            echo -e "${YELLOW}Failed to generate markdown report.${RESET}"
        fi
        if "$PYTHON_BIN" "$REPORT_TOOL" --format "html" --discovery "$DISCOVERY_JSON" "${creds_arg[@]}" \
            --output "$html_out" --run-dir "$RUN_DIR" --run-label "$run_label" >/dev/null 2>&1; then
            echo -e "${CYAN}Report generated:${RESET} ${GREEN}$html_out${RESET}"
        else
            echo -e "${YELLOW}Failed to generate HTML report.${RESET}"
        fi
        return 0
    fi

    local ext="md"
    [[ $format == "html" ]] && ext="html"
    local output="$RUN_DIR/report.$ext"
    if "$PYTHON_BIN" "$REPORT_TOOL" --format "$format" --discovery "$DISCOVERY_JSON" "${creds_arg[@]}" \
        --output "$output" --run-dir "$RUN_DIR" --run-label "$run_label" >/dev/null 2>&1; then
        echo -e "${CYAN}Report generated:${RESET} ${GREEN}$output${RESET}"
    else
        echo -e "${YELLOW}Report generation failed.${RESET}"
        return 1
    fi
    return 0
}

resolve_encrypt_tool() {
    local tool="$1"
    case "${tool,,}" in
        age|gpg)
            echo "${tool,,}"
            return 0
            ;;
        auto|"")
            if command -v age >/dev/null 2>&1; then
                echo "age"
                return 0
            fi
            if command -v gpg >/dev/null 2>&1; then
                echo "gpg"
                return 0
            fi
            ;;
    esac
    echo ""
    return 1
}

encrypt_results() {
    [[ $ENCRYPT_RESULTS == true ]] || return 0
    local tool
    tool=$(resolve_encrypt_tool "$ENCRYPT_TOOL")
    if [[ -z $tool ]]; then
        echo -e "${YELLOW}Encryption requested but no age/gpg tool found.${RESET}"
        return 1
    fi
    if ! command -v tar >/dev/null 2>&1; then
        echo -e "${YELLOW}Encryption requested but tar is missing.${RESET}"
        return 1
    fi

    local archive="$RUN_DIR.tar.gz"
    if ! tar -czf "$archive" -C "$RUN_DIR" .; then
        echo -e "${YELLOW}Failed to create archive for encryption.${RESET}"
        return 1
    fi

    local output=""
    if [[ $tool == "age" ]]; then
        if [[ -z $ENCRYPT_RECIPIENT ]]; then
            echo -e "${YELLOW}Age encryption requires --encrypt-recipient.${RESET}"
            rm -f "$archive"
            return 1
        fi
        output="${archive}.age"
        if age -r "$ENCRYPT_RECIPIENT" -o "$output" "$archive"; then
            echo -e "${CYAN}Encrypted archive:${RESET} ${GREEN}$output${RESET}"
        else
            echo -e "${YELLOW}Age encryption failed.${RESET}"
            rm -f "$archive"
            return 1
        fi
    else
        output="${archive}.gpg"
        if [[ -n $ENCRYPT_RECIPIENT ]]; then
            if gpg --yes --encrypt --recipient "$ENCRYPT_RECIPIENT" --output "$output" "$archive"; then
                echo -e "${CYAN}Encrypted archive:${RESET} ${GREEN}$output${RESET}"
            else
                echo -e "${YELLOW}GPG encryption failed.${RESET}"
                rm -f "$archive"
                return 1
            fi
        elif [[ -n $ENCRYPT_PASSPHRASE ]]; then
            if gpg --batch --yes --symmetric --passphrase "$ENCRYPT_PASSPHRASE" --output "$output" "$archive"; then
                echo -e "${CYAN}Encrypted archive:${RESET} ${GREEN}$output${RESET}"
            else
                echo -e "${YELLOW}GPG encryption failed.${RESET}"
                rm -f "$archive"
                return 1
            fi
        else
            if gpg --symmetric --output "$output" "$archive"; then
                echo -e "${CYAN}Encrypted archive:${RESET} ${GREEN}$output${RESET}"
            else
                echo -e "${YELLOW}GPG encryption failed.${RESET}"
                rm -f "$archive"
                return 1
            fi
        fi
    fi

    rm -f "$archive"
    return 0
}

compute_prelim_scores() {
    for ip in "${!all_ips[@]}"; do
        local score=0
        local -a reasons=()
        local signal_count=0
        local has_port_signal=false
        local has_source_signal=false
        local has_path_signal=false
        local has_rtsp_signal=false

        local ports_string
        ports_string=$(printf "%s" "${ip_ports[$ip]}" | tr ' ' '\n' | sed '/^$/d' | sort -u)

        if [[ -n ${ip_sources[$ip]:-} ]]; then
            if [[ ${ip_sources[$ip]} == *"SSDP"* ]]; then
                score=$((score + 25))
                reasons+=("ssdp response")
                has_source_signal=true
            fi
            if [[ ${ip_sources[$ip]} == *"TShark"* ]]; then
                score=$((score + 20))
                reasons+=("traffic hit")
                has_source_signal=true
            fi
            if [[ ${ip_sources[$ip]} == *"Avahi"* ]]; then
                score=$((score + 15))
                reasons+=("avahi service")
                has_source_signal=true
            fi
            if [[ ${ip_sources[$ip]} == *"Nmap"* ]]; then
                score=$((score + 8))
            fi
            if [[ ${ip_sources[$ip]} == *"Masscan"* ]]; then
                score=$((score + 5))
            fi
            if [[ ${ip_sources[$ip]} == *"CoAP"* ]]; then
                score=$((score + 8))
                reasons+=("coap response")
                has_source_signal=true
            fi
        fi

        if port_in_list "$ports_string" "554" || port_in_list "$ports_string" "8554" || port_in_list "$ports_string" "10554" || port_in_list "$ports_string" "5544"; then
            score=$((score + 35))
            reasons+=("rtsp port open")
            has_port_signal=true
        fi
        if port_in_list "$ports_string" "1935" || port_in_list "$ports_string" "1936"; then
            score=$((score + 12))
            reasons+=("rtmp port open")
            has_port_signal=true
        fi
        if port_in_list "$ports_string" "37777" || port_in_list "$ports_string" "37778" || port_in_list "$ports_string" "37779"; then
            score=$((score + 20))
            reasons+=("dahua port")
            has_port_signal=true
        fi
        if port_in_list "$ports_string" "8000" || port_in_list "$ports_string" "8001"; then
            score=$((score + 18))
            reasons+=("hikvision port")
            has_port_signal=true
        fi
        if port_in_list "$ports_string" "8899" || port_in_list "$ports_string" "9000" || port_in_list "$ports_string" "7001"; then
            score=$((score + 12))
            reasons+=("camera api port")
            has_port_signal=true
        fi
        if port_in_list "$ports_string" "80" || port_in_list "$ports_string" "81" || port_in_list "$ports_string" "88" || port_in_list "$ports_string" "443" || port_in_list "$ports_string" "8080" || port_in_list "$ports_string" "8081" || port_in_list "$ports_string" "8443"; then
            score=$((score + 8))
            reasons+=("http port open")
            has_port_signal=true
        fi

        if [[ -n ${ip_rtsp_discovered[$ip]:-} ]]; then
            score=$((score + 30))
            reasons+=("rtsp url discovered")
            has_rtsp_signal=true
        fi
        if [[ -n ${ip_rtsp_other[$ip]:-} ]]; then
            score=$((score + 10))
            reasons+=("rtsp response")
            has_rtsp_signal=true
        fi

        if [[ -n ${ip_observed_paths[$ip]:-} ]]; then
            if printf '%s' "${ip_observed_paths[$ip]}" | grep -Eqi "rtsp|onvif|snapshot|mjpg|mjpeg|stream|live"; then
                score=$((score + 18))
                reasons+=("observed stream uri")
                has_path_signal=true
            fi
        fi

        if [[ -n ${ip_to_mac[$ip]:-} ]]; then
            score=$((score + 5))
        fi

        if [[ $has_port_signal == true ]]; then
            signal_count=$((signal_count + 1))
        fi
        if [[ $has_source_signal == true ]]; then
            signal_count=$((signal_count + 1))
        fi
        if [[ $has_path_signal == true ]]; then
            signal_count=$((signal_count + 1))
        fi
        if [[ $has_rtsp_signal == true ]]; then
            signal_count=$((signal_count + 1))
        fi
        if (( signal_count >= 3 )); then
            score=$((score + 10))
            reasons+=("multi-signal")
        fi

        if (( score > 100 )); then
            score=100
        fi

        ip_pre_score["$ip"]=$score
        if (( ${#reasons[@]} > 0 )); then
            ip_pre_reasons["$ip"]=$(printf '%s\n' "${reasons[@]}" | head -3 | paste -sd '; ')
        else
            ip_pre_reasons["$ip"]=""
        fi
    done
}

select_smart_targets() {
    SMART_TARGETS=()
    local -a scored=()
    local ip
    for ip in "${!all_ips[@]}"; do
        local score=${ip_pre_score[$ip]:-0}
        scored+=("${score}\t${ip}")
    done
    mapfile -t sorted_scores < <(printf "%s\n" "${scored[@]}" | sort -nr -k1,1)

    local max_count="$SMART_MAX_TARGETS"
    local count=0
    local line
    for line in "${sorted_scores[@]}"; do
        [[ -z $line ]] && continue
        local score=${line%%$'\t'*}
        local ip_val=${line#*$'\t'}
        if ! is_integer "$score"; then
            continue
        fi
        if (( score < SMART_MIN_SCORE )); then
            continue
        fi
        SMART_TARGETS+=("$ip_val")
        count=$((count + 1))
        if (( max_count > 0 && count >= max_count )); then
            break
        fi
    done

    if (( ${#SMART_TARGETS[@]} == 0 )); then
        echo -e "${YELLOW}Smart targeting found no hosts above threshold; falling back to all targets.${RESET}"
        mapfile -t SMART_TARGETS < <(printf "%s\n" "${!all_ips[@]}" | sort -V)
    fi
}

render_smart_summary() {
    echo ""
    echo -e "${GREEN}========== Smart Targeting ==========${RESET}"
    echo -e "${CYAN}Total candidates:${RESET} ${GREEN}${#all_ips[@]}${RESET}"
    echo -e "${CYAN}Selected targets:${RESET} ${GREEN}${#SMART_TARGETS[@]}${RESET}"
    echo -e "${CYAN}Smart minimum score:${RESET} ${GREEN}${SMART_MIN_SCORE}${RESET}"
    if (( SMART_MAX_TARGETS > 0 )); then
        echo -e "${CYAN}Smart max targets:${RESET} ${GREEN}${SMART_MAX_TARGETS}${RESET}"
    fi
    echo -e "${CYAN}Top candidates:${RESET}"
    local shown=0
    local ip
    for ip in "${SMART_TARGETS[@]}"; do
        local score=${ip_pre_score[$ip]:-0}
        local reasons=${ip_pre_reasons[$ip]:-}
        printf "  %s%-15s%s score=%s" "$CYAN" "$ip" "$RESET" "$score"
        if [[ -n $reasons ]]; then
            printf " (%s)" "$reasons"
        fi
        echo ""
        shown=$((shown + 1))
        if (( shown >= SMART_DISPLAY_LIMIT )); then
            break
        fi
    done
    echo -e "${GREEN}====================================${RESET}"
}

get_probe_targets() {
    if [[ $SMART_MODE == true && ${#SMART_TARGETS[@]} -gt 0 ]]; then
        printf "%s\n" "${SMART_TARGETS[@]}"
        return 0
    fi
    printf "%s\n" "${!all_ips[@]}" | sort -V
}

render_confidence_ranking() {
    [[ $CONFIDENCE_READY == true ]] || return
    [[ -f "$DISCOVERY_JSON" ]] || return
    if ! command -v jq >/dev/null 2>&1; then
        return
    fi
    local limit="$SMART_DISPLAY_LIMIT"
    if ! is_integer "$limit" || (( limit <= 0 )); then
        limit=10
    fi
    echo ""
    echo -e "${GREEN}========== Confidence Ranking ==========${RESET}"
    jq -r --argjson limit "$limit" '
        [ .hosts[] | {
            ip: .ip,
            score: (.confidence.score // 0),
            level: (.confidence.level // "unknown"),
            classification: (.confidence.classification // ""),
            reasons: (.confidence.reasons // [])
        } ]
        | sort_by(.score) | reverse
        | .[:$limit]
        | .[]
        | [
            (.score | tostring),
            .level,
            .classification,
            .ip,
            (.reasons[0] // ""),
            (.reasons[1] // "")
        ]
        | @tsv
    ' "$DISCOVERY_JSON" | while IFS=$'\t' read -r score level classification ip reason1 reason2; do
        [[ -z $ip ]] && continue
        printf "  %s%-15s%s score=%s level=%s" "$CYAN" "$ip" "$RESET" "$score" "$level"
        if [[ -n $classification ]]; then
            printf " class=%s" "$classification"
        fi
        if [[ -n $reason1 ]]; then
            printf " | %s" "$reason1"
            if [[ -n $reason2 ]]; then
                printf "; %s" "$reason2"
            fi
        fi
        echo ""
    done
    echo -e "${GREEN}=======================================${RESET}"
}

# shellcheck disable=SC2317
build_coap_with_log() {
    [[ -z ${coap_build_log:-} ]] && return 1
    "$SETUP_DIR/build-coap.sh" &>> "$coap_build_log"
}

# shellcheck disable=SC2317
do_coap_probe() {
    local tshark_output="$1"
    rm -f "$COAP_OUTPUT_FILE"
    : > "$COAP_LOG_FILE"
    local coap_output_tmp
    coap_output_tmp=$(mktemp /tmp/camsniff-coap.XXXXXX)

    declare -a coap_targets=()
    declare -A coap_seen_targets=()

    for ip in "${!all_ips[@]}"; do
        [[ -z $ip ]] && continue
        coap_targets+=("$ip")
        coap_seen_targets["$ip"]=1
    done

    if [[ -s $tshark_output ]]; then
        while IFS=',' read -r _time_rel src dst _rest; do
            for candidate in "$src" "$dst"; do
                candidate=${candidate//\"/}
                if [[ $candidate =~ ^[0-9]+(\.[0-9]+){3}$ ]] && [[ -z ${coap_seen_targets[$candidate]+set} ]]; then
                    coap_targets+=("$candidate")
                    coap_seen_targets["$candidate"]=1
                fi
            done
        done < "$tshark_output"
    fi

    {
        printf '# CoAP probe log generated %s\n' "$(date -u +%FT%TZ)"
    } >> "$COAP_LOG_FILE"

    for ip in "${coap_targets[@]}"; do
        [[ -z $ip ]] && continue
        printf '%s probing coap://%s/.well-known/core\n' "$(date -u +%FT%TZ)" "$ip" >> "$COAP_LOG_FILE"
        if coap-client -m get -B "$COAP_PROBE_TIMEOUT" "coap://$ip/.well-known/core" > "$coap_output_tmp" 2>> "$COAP_LOG_FILE"; then
            if grep -q '<' "$coap_output_tmp"; then
                echo "$ip" >> "$COAP_OUTPUT_FILE"
                {
                    printf '%s success\n' "$(date -u +%FT%TZ)"
                    cat "$coap_output_tmp"
                } >> "$COAP_LOG_FILE"
                record_protocol_hit "$ip" "CoAP" '/.well-known/core responded'
            else
                printf '%s responded without resource directory\n' "$(date -u +%FT%TZ)" >> "$COAP_LOG_FILE"
            fi
        else
            printf '%s probe failed\n' "$(date -u +%FT%TZ)" >> "$COAP_LOG_FILE"
        fi
        : > "$coap_output_tmp"
    done

    rm -f "$coap_output_tmp"
}

resolve_port_profiles() {
    local profile="${CAM_MODE_PORT_PROFILE:-fallback}"
    profile="${profile// /-}"
    profile="${profile,,}"
    [[ -z ${CAM_PORT_PROFILES_NMAP[$profile]+set} ]] && profile="fallback"

    NMAP_PORT_LIST="${CAM_PORT_PROFILES_NMAP[$profile]}"
    MASSCAN_PORT_SPEC="${CAM_PORT_PROFILES_MASSCAN[$profile]}"
    PORT_SUMMARY_LABEL="${CAM_PORT_PROFILE_LABELS[$profile]:-${CAM_PORT_PROFILE_LABELS[fallback]}}"

    [[ -z $NMAP_PORT_LIST ]] && NMAP_PORT_LIST="${CAM_PORT_PROFILES_NMAP[fallback]}"
    [[ -z $MASSCAN_PORT_SPEC ]] && MASSCAN_PORT_SPEC="${CAM_PORT_PROFILES_MASSCAN[fallback]}"
}

resolve_port_profiles

configure_rtsp_bruteforce() {
    local key="${CAM_MODE_NORMALIZED// /-}"
    key="${key,,}"
    if [[ -n ${CAM_RTSP_THREAD_PROFILE[$key]+set} ]]; then
        NMAP_RTSP_THREADS="${CAM_RTSP_THREAD_PROFILE[$key]}"
    else
        NMAP_RTSP_THREADS=12
    fi
}

configure_rtsp_bruteforce

if command -v tput &> /dev/null; then
  RED=$(tput setaf 1)
  GREEN=$(tput setaf 2)
  YELLOW=$(tput setaf 3)
  ORANGE=$(tput setaf 3)
  BLUE=$(tput setaf 4)
  CYAN=$(tput setaf 6)
  BLINK=$(tput blink)
  RESET=$(tput sgr0)
fi
[[ -z $ORANGE ]] && ORANGE="$YELLOW"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Aborted. Try again with \"sudo camsniff\"${RESET}"
  exit 1
fi

if [[ -z ${TSHARK_INTERFACE:-} ]]; then
    detected_iface=$(detect_capture_interface)
    if [[ -n $detected_iface ]]; then
        TSHARK_INTERFACE="$detected_iface"
    else
        TSHARK_INTERFACE="any"
        echo -e "${YELLOW}Warning: Unable to auto-detect default interface. Falling back to 'any'.${RESET}"
    fi
fi
export TSHARK_INTERFACE

mkdir -p "$RESULTS_ROOT" "$RUN_DIR" "$LOG_DIR" "$THUMB_DIR"
if [[ $EXTRA_IVRE_ENABLED == true ]]; then
    : > "$IVRE_LOG_FILE"
    
    if ! "$INTEGRATION_DIR/ivre-manager.sh" check >/dev/null 2>&1; then
        if cam_run_with_spinner "Setting up IVRE integration" sudo "$INTEGRATION_DIR/ivre-manager.sh" auto-setup --quiet; then
            echo -e "${GREEN}✓ IVRE integration ready${RESET}"
        else
            echo -e "${YELLOW}Warning: IVRE setup incomplete, disabling integration${RESET}"
            EXTRA_IVRE_ENABLED=false
        fi
    fi
fi

if [[ -f "$GEOIP_CITY_DB" ]]; then
    export IVRE_GEOIP_CITY_DB="$GEOIP_CITY_DB"
fi
if [[ -f "$GEOIP_ASN_DB" ]]; then
    export IVRE_GEOIP_ASN_DB="$GEOIP_ASN_DB"
fi

clear

TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

cam_ui_matrix_rain "$TERM_WIDTH" 12 24 0.045 "$GREEN" "$RESET"
clear
extras_label="None"
extras_label=""
if [[ $EXTRA_IVRE_ENABLED == true ]]; then
    extras_label="Ivre"
fi
if [[ $SMART_MODE == true ]]; then
    if [[ -n $extras_label ]]; then
        extras_label+=", "
    fi
    extras_label+="Smart"
fi
if [[ -z $extras_label ]]; then
    extras_label="None"
fi
cam_ui_render_banner "$TERM_WIDTH" "$CYAN" "$GREEN" "$YELLOW" "$BLUE" "$RESET" "$CAM_MODE_NORMALIZED" "$PORT_SUMMARY_LABEL" "$RUN_DIR" "$extras_label"

append_source() {
    local ip="$1"
    local source="$2"
    [[ -z "$ip" ]] && return
    all_ips["$ip"]=1
    if [[ -z ${ip_sources[$ip]+set} ]]; then
        ip_sources["$ip"]="$source"
    elif [[ ${ip_sources[$ip]} != *"$source"* ]]; then
        ip_sources["$ip"]+=", $source"
    fi
}

track_port() {
    local ip="$1"
    local port="$2"
    [[ -z $ip || -z $port ]] && return
    local current=" ${ip_ports[$ip]} "
    if [[ $current == *" $port "* ]]; then
        return
    fi
    ip_ports["$ip"]+="$port "
}

http_status_for() {
    local url="$1"
    local timeout_s="${2:-${CURL_TIMEOUT:-8}}"
    curl -k -s -o /dev/null -w "%{http_code}" --max-time "$timeout_s" "$url" 2>/dev/null || echo ""
}

http_body_snippet() {
    local url="$1"
    local lines="${2:-10}"
    local timeout_s="${3:-${CURL_TIMEOUT:-8}}"
    curl -k -s --max-time "$timeout_s" "$url" 2>/dev/null | head -n "$lines"
}

build_rtsp_url() {
    local template="$1"
    local ip="$2"
    local username="$3"
    local password="$4"
    local port="$5"
    local stream="$6"
    local channel="$7"

    local url="$template"
    url="${url//\{\{ip_address\}\}/$ip}"
    url="${url//\{\{username\}\}/${username:-<username>}}"
    url="${url//\{\{password\}\}/${password:-<password>}}"
    url="${url//\{\{port\}\}/${port:-554}}"
    url="${url//\{\{stream\}\}/${stream:-0}}"
    url="${url//\{\{channel\}\}/${channel:-1}}"
    echo "$url"
}

match_device_profile() {
    local ip="$1"
    local mac="$2"
    local ports_string="$3"
    local observed_paths="$4"

    [[ ! -f "$PATHS_FILE" ]] && return

    local mac_upper="${mac^^}"
    local port_list
    port_list=$(printf "%s" "$ports_string" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')
    local first_port
    first_port=${port_list%% *}
    if [[ -z $first_port || ! $first_port =~ ^[0-9]+$ ]]; then
        first_port="554"
    fi

    local results=""

    while IFS=',' read -r company _type model oui_regex rtsp_url http_snapshot_url onvif_profile_path video_encoding csv_port streams channels _stream_names _channel_names _low_res_stream _high_res_stream username password is_digest_auth_supported cve_ids user_manual_url; do
        [[ $company == "company" ]] && continue
        local matched=false
        local match_reason=""

        if [[ -n $mac_upper && -n $oui_regex && $mac_upper =~ $oui_regex ]]; then
            matched=true
            match_reason="OUI"
        elif [[ -n $csv_port && $csv_port =~ ^[0-9]+$ && $port_list =~ (^|[[:space:]])$csv_port($|[[:space:]]) ]]; then
            matched=true
            match_reason="port"
        fi

        [[ $matched == false ]] && continue

    local stream
    stream=$(printf "%s" "$streams" | cut -d';' -f1)
        [[ -z $stream ]] && stream="0"
    local channel
    channel=$(printf "%s" "$channels" | cut -d';' -f1)
        [[ -z $channel ]] && channel="1"

    local effective_port
    effective_port="$csv_port"
        [[ -z $effective_port ]] && effective_port="$first_port"

    local prepared_url
    prepared_url="$(build_rtsp_url "$rtsp_url" "$ip" "$username" "$password" "$effective_port" "$stream" "$channel")"

        results+="  Profile match: ${company} ${model}\n"
        results+="    Suggested RTSP: ${prepared_url}\n"
        [[ -n $match_reason ]] && results+="    Matched via: ${match_reason}\n"
        if [[ -n $username || -n $password ]]; then
            results+="    Default creds: ${username:-<custom>}/${password:-<password>}\n"
        fi
        if [[ -n $video_encoding ]]; then
            results+="    Encoding: ${video_encoding}\n"
        fi
        if [[ -n $http_snapshot_url ]]; then
            results+="    Snapshot template: ${http_snapshot_url}\n"
        fi
        if [[ -n $onvif_profile_path ]]; then
            results+="    ONVIF profile: ${onvif_profile_path}\n"
        fi
        if [[ -n $is_digest_auth_supported ]]; then
            results+="    Digest auth: ${is_digest_auth_supported}\n"
        fi
        if [[ -n $cve_ids ]]; then
            local formatted_cves
            formatted_cves=$(printf "%s" "$cve_ids" | sed 's/;/, /g')
            results+="    CVEs: ${formatted_cves}\n"
        fi
        if [[ -n $user_manual_url ]]; then
            results+="    Reference: ${user_manual_url}\n"
        fi
    done < "$PATHS_FILE"

    if [[ -n $results ]]; then
        printf "%s" "$results"
    elif [[ -n $observed_paths ]]; then
    local unique_paths
    unique_paths=$(printf "%s" "$observed_paths" | tr ' ' '\n' | sed '/^$/d' | sort -u | head -3 | tr '\n' ', ')
        [[ -n $unique_paths ]] && printf "  Observed paths: %s\n" "$unique_paths"
    fi
}
if [[ $AUTO_CONFIRM == true ]]; then
    answer="y"
    cam_ui_center_line "$TERM_WIDTH" "${GREEN}Auto-confirm enabled. Proceeding with CamSniff.${RESET}"
    cam_ui_center_line "$TERM_WIDTH" ""
else
    prompt=$(cam_ui_build_centered "$TERM_WIDTH" "Proceed with CamSniff setup and scan? ${GREEN}Yes [Y]${RESET} | ${RED}No [N]${RESET} ")
    read -r -p "$prompt" answer && clear
fi
case ${answer:0:1} in
    y|Y|"" )
        echo -e "${GREEN}Starting setup process...${RESET}"
        if [[ $SKIP_INSTALL == true ]]; then
            echo -e "${YELLOW}Skipping dependency installation (--skip-install).${RESET}"
        else
            if [[ -f "$DEPS_INSTALL" ]]; then
                install_log_tmp=$(mktemp)
                echo -e "${CYAN}Installing dependencies (verbose)...${RESET}"
                if env CAM_INSTALL_LOG_EXPORT="$install_log_tmp" CAM_REQUIRE_IVRE="$EXTRA_IVRE_ENABLED" "$DEPS_INSTALL"; then
                    if [[ -s $install_log_tmp ]]; then
                        install_log_path=$(<"$install_log_tmp")
                        [[ -n $install_log_path ]] && echo -e "${CYAN}Install log saved to:${RESET} ${GREEN}$install_log_path${RESET}"
                    fi
                else
                    install_log_path=""
                    if [[ -s $install_log_tmp ]]; then
                        install_log_path=$(<"$install_log_tmp")
                    fi
                    [[ -n $install_log_path ]] && echo -e "${YELLOW}Dependency install log:${RESET} ${install_log_path}"
                    echo -e "${RED}Dependency installation failed; aborting.${RESET}"
                    rm -f "$install_log_tmp"
                    exit 1
                fi
                rm -f "$install_log_tmp"
            else
                echo -e "${YELLOW}Warning: deps-install.sh not found. Continuing without installing dependencies.${RESET}"
            fi
        fi

        if ! verify_required_tools; then
            exit 1
        fi
        apply_optional_tool_overrides

        if [[ -x "$ROOT_DIR/venv/bin/python3" ]]; then
            PYTHON_BIN="$ROOT_DIR/venv/bin/python3"
        fi

        if [[ -f "$PATHS_FILE" ]]; then
            if command -v "$PYTHON_BIN" >/dev/null 2>&1 && "$PYTHON_BIN" "$PROFILE_RESOLVER" catalog --paths "$PATHS_FILE" --output "$CATALOG_JSON" >/dev/null 2>&1; then
                echo -e "${CYAN}Exported catalog to:${RESET} ${GREEN}$CATALOG_JSON${RESET}"
            else
                echo -e "${YELLOW}Warning: Failed to export catalog JSON. Verify Python availability and $PATHS_FILE formatting.${RESET}"
            fi
        fi

        # Build coap-client on demand using the shared spinner helper
        if ! command -v coap-client &> /dev/null; then
            coap_build_log="$LOG_DIR/coap-build.log"
            : > "$coap_build_log"
            if cam_run_packinst "Building coap-client (libcoap)" build_coap_with_log; then
                echo -e "${CYAN}CoAP build log:${RESET} ${GREEN}$coap_build_log${RESET}"
            else
                echo -e "${RED}Failed to build coap-client; see ${coap_build_log}.${RESET}"
                exit 1
            fi
        fi

        # IVRE integration check is handled earlier during setup
        if [[ $EXTRA_IVRE_ENABLED == true ]]; then
            echo -e "${GREEN}IVRE integration enabled. Results will sync to IVRE after discovery.${RESET}"
        fi
        
        # Load targets from file if provided
        declare -a scan_targets=()
        scan_scope="auto"
        if [[ -n $TARGET_FILE ]]; then
            echo -e "${CYAN}Loading targets from file: ${GREEN}$TARGET_FILE${RESET}"
            if ! target_list=$(parse_target_file "$TARGET_FILE"); then
                echo -e "${RED}Failed to parse target file${RESET}"
                exit 1
            fi
            while IFS= read -r target; do
                [[ -z $target ]] && continue
                TARGET_IPS+=("$target")
            done <<< "$target_list"
            
            if (( ${#TARGET_IPS[@]} == 0 )); then
                echo -e "${RED}No valid targets loaded from file${RESET}"
                exit 1
            fi
            
            echo ""
            echo -e "${CYAN}Loaded ${GREEN}${#TARGET_IPS[@]}${CYAN} target(s) from file${RESET}"
            echo -e "${CYAN}Scanning targets: ${GREEN}${TARGET_IPS[*]}${RESET}"
            echo ""
            scan_targets=("${TARGET_IPS[@]}")
            scan_scope="${TARGET_IPS[*]}"
        else
            current_ip=$(ip route get 1 | awk '{print $7;exit}')
            default_net=$(detect_default_network)
            scan_scope="$default_net"
            scan_targets=("$default_net")
            
            echo ""
            echo -e "${CYAN}Your IP address: ${GREEN}$current_ip${RESET}"
            echo -e "${CYAN}Scanning network: ${GREEN}$scan_scope${RESET}"
            echo ""
        fi

        if (( ${#scan_targets[@]} == 0 )) || [[ -z ${scan_targets[0]} ]]; then
            echo -e "${RED}No valid scan targets resolved.${RESET}"
            exit 1
        fi
        
        echo -e "${BLUE}Network scanning in progress...${RESET}"

        nmap_output=$(mktemp)
        nmap_log=$(mktemp)

        nmap_cmd=(nmap)
        nmap_rtsp_enabled=false
        if [[ -n ${CAM_MODE_NMAP_SPEED:-} ]]; then
            read -r -a __speed <<< "$CAM_MODE_NMAP_SPEED"
            nmap_cmd+=("${__speed[@]}")
        fi
        if [[ -n ${CAM_MODE_NMAP_EXTRA:-} ]]; then
            read -r -a __extra <<< "$CAM_MODE_NMAP_EXTRA"
            nmap_cmd+=("${__extra[@]}")
        fi
        if [[ ${NMAP_OSSCAN_ENABLE,,} == "true" ]]; then
            nmap_cmd+=(-O --osscan-guess --fuzzy)
        fi
        if [[ ${NMAP_VERSION_ENABLE,,} == "true" ]]; then
            nmap_cmd+=(-sV --version-all)
        fi
        nmap_cmd+=(-p "$NMAP_PORT_LIST" --open "${scan_targets[@]}" -oN "$nmap_output")
        if [[ -f "$NMAP_RTSP_SCRIPT" ]]; then
            nmap_cmd+=(--script "$NMAP_RTSP_SCRIPT")
            rtsp_script_args="rtsp-url-brute.threads=$NMAP_RTSP_THREADS"
            if [[ -f "$RTSP_URL_DICT" ]]; then
                rtsp_script_args="${rtsp_script_args},rtsp-url-brute.urlfile=$RTSP_URL_DICT"
            fi
            nmap_cmd+=(--script-args "$rtsp_script_args")
            nmap_rtsp_enabled=true
        else
            echo -e "${YELLOW}RTSP brute script not found at $NMAP_RTSP_SCRIPT; continuing without NSE integration.${RESET}"
        fi
        unset __speed __extra rtsp_script_args

        "${nmap_cmd[@]}" > "$nmap_log" 2>&1 &
        pid=$!
        
        spin='-\|/'
        i=0
        estimated_time=$(( 30 + CAM_MODE_TSHARK_DURATION / 2 ))
        start_time=$(date +%s)
        
        while kill -0 $pid 2>/dev/null; do
            i=$(( (i+1) % 4 ))
            elapsed=$(($(date +%s) - start_time))
            remaining=$((estimated_time - elapsed))
            
            if (( remaining > 0 )); then
                printf "\r${CYAN}[%c] Scanning network for cameras... ETA: ${YELLOW}%ds${RESET} " "${spin:$i:1}" "$remaining"
            else
                printf "\r${CYAN}[%c] Scanning network for cameras...${RESET} " "${spin:$i:1}"
            fi
            
            sleep 0.2
        done
        
    printf "\r%sNmap scan completed!%s                                  \n" "$GREEN" "$RESET"
        wait $pid
        
    hosts_found=$(grep -c "Nmap scan report" "$nmap_output" || echo "0")
    open_ports=$(grep -c "open" "$nmap_output" || echo "0")
        
        echo ""
        echo -e "${GREEN}========== Nmap Scan Summary ==========${RESET}"
        echo -e "${CYAN}Hosts found:    ${GREEN}$hosts_found${RESET}"
        echo -e "${CYAN}Port profile:   ${GREEN}$PORT_SUMMARY_LABEL${RESET}"
        echo -e "${CYAN}Port spec:      ${GREEN}$NMAP_PORT_LIST${RESET}"
        if [[ $nmap_rtsp_enabled == true ]]; then
            echo -e "${CYAN}RTSP brute script:${GREEN} $NMAP_RTSP_SCRIPT${RESET}"
            echo -e "${CYAN}RTSP brute threads:${GREEN} $NMAP_RTSP_THREADS${RESET}"
        fi
        echo -e "${CYAN}Open ports:     ${GREEN}$open_ports${RESET}"
        echo -e "${GREEN}=====================================${RESET}"

        current_nmap_ip=""
        rtsp_section=false
        rtsp_section_ip=""
        rtsp_current_category=""
        rtsp_current_status=""
        while IFS= read -r nmap_line; do
            if [[ $rtsp_section == true && ! $nmap_line =~ ^\| ]]; then
                rtsp_section=false
                rtsp_section_ip=""
                rtsp_current_category=""
                rtsp_current_status=""
            fi
            if [[ $nmap_line =~ ^Nmap\ scan\ report\ for\ ([^[:space:]]+) ]]; then
                current_nmap_ip=${BASH_REMATCH[1]}
                append_source "$current_nmap_ip" "Nmap"
                rtsp_section=false
                rtsp_section_ip="$current_nmap_ip"
                rtsp_current_category=""
                rtsp_current_status=""
            elif [[ $nmap_line =~ MAC\ Address:\ ([0-9A-Fa-f:]+) ]]; then
                ip_to_mac["$current_nmap_ip"]=${BASH_REMATCH[1]^^}
            elif [[ $nmap_line =~ ^([0-9]+)/tcp[[:space:]]+open ]]; then
                port_open=${BASH_REMATCH[1]}
                [[ -n $current_nmap_ip ]] && track_port "$current_nmap_ip" "$port_open"
            elif [[ $nmap_line =~ ^\|[[:space:]_]*rtsp-url-brute: ]]; then
                rtsp_section=true
                rtsp_section_ip="$current_nmap_ip"
                rtsp_current_category=""
                rtsp_current_status=""
            elif [[ $rtsp_section == true ]]; then
                inner="${nmap_line#|}"
                inner="${inner#_}"
                inner="${inner#"${inner%%[![:space:]]*}"}"
                [[ -z $inner ]] && continue
                if [[ $inner == "rtsp-url-brute:" ]]; then
                    continue
                elif [[ $inner == "discovered:" ]]; then
                    rtsp_current_category="discovered"
                    rtsp_current_status=""
                    continue
                elif [[ $inner == "other responses:" ]]; then
                    rtsp_current_category="other"
                    rtsp_current_status=""
                    continue
                elif [[ $rtsp_current_category == "other" && $inner =~ ^([0-9]{3}): ]]; then
                    rtsp_current_status=${BASH_REMATCH[1]}
                    continue
                elif [[ $rtsp_current_category == "discovered" && $inner =~ ^rtsp:// ]]; then
                    if [[ -n $rtsp_section_ip ]]; then
                        ip_rtsp_discovered["$rtsp_section_ip"]+="$inner"$'\n'
                        ip_observed_paths["$rtsp_section_ip"]+="$inner "
                    fi
                    continue
                elif [[ $rtsp_current_category == "other" && $inner =~ ^rtsp:// ]]; then
                    status_key=${rtsp_current_status:-unknown}
                    if [[ -n $rtsp_section_ip ]]; then
                        ip_rtsp_other["$rtsp_section_ip"]+="$status_key|$inner"$'\n'
                    fi
                    continue
                fi
            fi
        done < "$nmap_output"

        cp -f "$nmap_output" "$NMAP_OUTPUT_FILE" 2>/dev/null || true
        cp -f "$nmap_log" "$NMAP_LOG_FILE" 2>/dev/null || true
        
        echo ""
        if [[ ${CAM_MODE_MASSCAN_ENABLE,,} == "true" ]]; then
            echo -e "${BLUE}Starting more comprehensive scan with masscan...${RESET}"
            masscan_output=$(mktemp)
            masscan_log=$(mktemp)
            masscan_cmd=(masscan -p "$MASSCAN_PORT_SPEC" --rate "$CAM_MODE_MASSCAN_RATE" "${scan_targets[@]}" -oJ "$masscan_output")
            "${masscan_cmd[@]}" > "$masscan_log" 2>&1 &
            pid=$!

            i=0
            estimated_time=$(( 60 + CAM_MODE_TSHARK_DURATION ))
            start_time=$(date +%s)

            while kill -0 $pid 2>/dev/null; do
                i=$(( (i+1) % 4 ))
                elapsed=$(($(date +%s) - start_time))
                remaining=$((estimated_time - elapsed))

                if (( remaining > 0 )); then
                    minutes=$((remaining / 60))
                    seconds=$((remaining % 60))
                    printf "\r${CYAN}[%c] Masscan in progress... ETA: ${YELLOW}%dm %ds${RESET} " "${spin:$i:1}" "$minutes" "$seconds"
                else
                    printf "\r${CYAN}[%c] Masscan in progress...${RESET} " "${spin:$i:1}"
                fi

                sleep 0.2
            done

            printf "\r%sMasscan completed!%s                                  \n" "$GREEN" "$RESET"
            wait $pid

            hosts_found_masscan=$(grep -c "\"ip\"" "$masscan_output" || echo "0")
            open_ports_masscan=$(grep -c "\"port\"" "$masscan_output" || echo "0")

            echo ""
            echo -e "${GREEN}========== Masscan Summary ==========${RESET}"
            echo -e "${CYAN}Hosts found:    ${GREEN}$hosts_found_masscan${RESET}"
            echo -e "${CYAN}Port spec:      ${GREEN}$MASSCAN_PORT_SPEC${RESET}"
            echo -e "${CYAN}Scan rate:      ${GREEN}$CAM_MODE_MASSCAN_RATE pkts/s${RESET}"
            echo -e "${CYAN}Open ports:     ${GREEN}$open_ports_masscan${RESET}"
            echo -e "${GREEN}=====================================${RESET}"

            current_masscan_ip=""
            while IFS= read -r masscan_line; do
                if [[ $masscan_line =~ "ip"\:\ "([0-9\.]+)" ]]; then
                    current_masscan_ip=${BASH_REMATCH[1]}
                    append_source "$current_masscan_ip" "Masscan"
                elif [[ $masscan_line =~ "port"\:\ ([0-9]+) ]]; then
                    port_val=${BASH_REMATCH[1]}
                    [[ -n $current_masscan_ip ]] && track_port "$current_masscan_ip" "$port_val"
                fi
            done < "$masscan_output"
            cp -f "$masscan_output" "$MASSCAN_OUTPUT_FILE" 2>/dev/null || true
            cp -f "$masscan_log" "$MASSCAN_LOG_FILE" 2>/dev/null || true
        else
            echo -e "${YELLOW}Masscan disabled in ${CAM_MODE_NORMALIZED} mode.${RESET}"
            masscan_output=""
            masscan_log=""
        fi

        if [[ ${CAM_MODE_SSDP_ENABLE,,} == "true" ]]; then
            echo ""
            echo -e "${BLUE}Running SSDP discovery sweep...${RESET}"
            run_ssdp_discovery
            if [[ -s $SSDP_OUTPUT_FILE ]]; then
                ssdp_count=$(wc -l < "$SSDP_OUTPUT_FILE" | tr -d ' ')
                echo -e "${CYAN}SSDP responses recorded: ${GREEN}$ssdp_count${RESET}"
            fi
        fi
        
        echo ""
        echo -e "${BLUE}Starting Avahi service discovery for cameras...${RESET}"
        
        avahi_output=$(mktemp)
        avahi_duration=$(( CAM_MODE_TSHARK_DURATION / 2 ))
        (( avahi_duration < 15 )) && avahi_duration=15
        timeout "${avahi_duration}s" avahi-browse -art | grep -i -e camera -e webcam -e rtsp -e onvif -e axis > "$avahi_output" &
        pid=$!
        
        i=0
        estimated_time=$avahi_duration
        start_time=$(date +%s)
        
        while kill -0 $pid 2>/dev/null; do
            i=$(( (i+1) % 4 ))
            elapsed=$(($(date +%s) - start_time))
            remaining=$((estimated_time - elapsed))
            
            if (( remaining > 0 )); then
                printf "\r${CYAN}[%c] Discovering camera services... ETA: ${YELLOW}%ds${RESET} " "${spin:$i:1}" "$remaining"
            else
                printf "\r${CYAN}[%c] Discovering camera services...${RESET} " "${spin:$i:1}"
            fi
            
            sleep 0.2
        done
        
    printf "\r%sService discovery completed!%s                                  \n" "$GREEN" "$RESET"
        wait $pid
        
        if ! services_found=$(grep -c "=" "$avahi_output" 2>/dev/null); then
            services_found=0
        fi
        
        echo ""
        echo -e "${GREEN}========== Service Discovery Summary ==========${RESET}"
    echo -e "${CYAN}Camera services found: ${GREEN}$services_found${RESET}"
    if (( services_found > 0 )); then
            echo -e "${YELLOW}Service details:${RESET}"
            cat "$avahi_output"
        fi
        echo -e "${GREEN}=============================================${RESET}"

        if [[ -s "$avahi_output" ]]; then
            while IFS=';' read -r status _iface _proto _service _domain _host address port rest; do
                [[ -z $address ]] && continue
                [[ ${status:0:1} != "=" ]] && continue
                append_source "$address" "Avahi"
                [[ -n $port ]] && track_port "$address" "$port"
            done < "$avahi_output"
        fi
        cp -f "$avahi_output" "$AVAHI_OUTPUT_FILE" 2>/dev/null || true
        
        echo ""
        echo -e "${BLUE}Capturing network traffic for camera protocols...${RESET}"
        echo -e "${CYAN}Using interface:${RESET} ${GREEN}$TSHARK_INTERFACE${RESET}"
        
        tshark_output=$(mktemp)
        tshark_duration=${CAM_MODE_TSHARK_DURATION:-30}
        timeout "${tshark_duration}s" tshark -n -i "$TSHARK_INTERFACE" \
            -f "tcp port 80 or tcp port 554 or tcp port 8554 or udp portrange 5000-5010" \
            -Y "rtsp || http.request || udp.port == 3702" \
            -T fields -E header=n -E separator=, -E quote=d \
            -e frame.time_relative -e ip.src -e ip.dst -e tcp.port -e udp.port \
            -e http.host -e http.request.uri -e rtsp.request > "$tshark_output" &
        pid=$!
        
        i=0
        estimated_time=$tshark_duration
        start_time=$(date +%s)
        
        while kill -0 $pid 2>/dev/null; do
            i=$(( (i+1) % 4 ))
            elapsed=$(($(date +%s) - start_time))
            remaining=$((estimated_time - elapsed))
            
            if (( remaining > 0 )); then
                printf "\r${CYAN}[%c] Analyzing network traffic... ETA: ${YELLOW}%ds${RESET} " "${spin:$i:1}" "$remaining"
            else
                printf "\r${CYAN}[%c] Analyzing network traffic...${RESET} " "${spin:$i:1}"
            fi
            
            sleep 0.2
        done
        
    printf "\r%sTraffic analysis completed!%s                                  \n" "$GREEN" "$RESET"
        wait $pid
        
    if command -v coap-client &> /dev/null; then
        echo ""
        if cam_run_with_spinner "Probing for CoAP devices" do_coap_probe "$tshark_output"; then
            if [[ -s $COAP_OUTPUT_FILE ]]; then
                coap_hits=$(wc -l < "$COAP_OUTPUT_FILE" | tr -d ' ')
                echo -e "${GREEN}CoAP devices found: $coap_hits${RESET}"
                while IFS= read -r coap_ip; do
                    append_source "$coap_ip" "CoAP"
                done < "$COAP_OUTPUT_FILE"
            else
                echo -e "${YELLOW}No CoAP devices found.${RESET}"
                rm -f "$COAP_OUTPUT_FILE"
            fi
        fi
    else
        echo -e "${YELLOW}CoAP client (coap-client) not found; skipping CoAP discovery.${RESET}"
    fi  

    traffic_found=$(wc -l < "$tshark_output" | tr -d ' ')
        
        echo ""
        echo -e "${GREEN}========== Network Traffic Analysis ==========${RESET}"
        echo -e "${CYAN}Captured packets: ${GREEN}$traffic_found${RESET}"
    if [[ -n $traffic_found && $traffic_found =~ ^[0-9]+$ ]] && (( traffic_found > 0 )); then
            echo -e "${YELLOW}Potential camera streams detected:${RESET}"
            sort "$tshark_output" | uniq -c | sort -nr | head -10
            while IFS=',' read -r _time_rel src dst tcp_port udp_port _http_host http_uri rtsp_request; do
                src=${src//\"/}
                dst=${dst//\"/}
                tcp_port=${tcp_port//\"/}
                udp_port=${udp_port//\"/}
                http_uri=${http_uri//\"/}
                rtsp_request=${rtsp_request//\"/}
                rtsp_uri=""
                if [[ -n $rtsp_request ]]; then
                    rtsp_uri=$(printf '%s\n' "$rtsp_request" | awk '{print $2}' 2>/dev/null)
                    rtsp_uri=${rtsp_uri//\"/}
                fi

                if [[ -n $src ]]; then
                    append_source "$src" "TShark"
                    [[ -n $tcp_port ]] && track_port "$src" "$tcp_port"
                    [[ -n $udp_port ]] && track_port "$src" "$udp_port"
                fi
                if [[ -n $dst ]]; then
                    append_source "$dst" "TShark"
                    [[ -n $tcp_port ]] && track_port "$dst" "$tcp_port"
                    [[ -n $udp_port ]] && track_port "$dst" "$udp_port"
                fi

                if [[ -n $rtsp_uri ]]; then
                    target_ip=$dst
                    [[ -z $target_ip ]] && target_ip=$src
                    [[ -n $target_ip ]] && ip_observed_paths["$target_ip"]+="$rtsp_uri "
                elif [[ -n $http_uri ]]; then
                    target_ip=$dst
                    [[ -z $target_ip ]] && target_ip=$src
                    [[ -n $target_ip ]] && ip_observed_paths["$target_ip"]+="$http_uri "
                fi
            done < "$tshark_output"
        fi
        echo -e "${GREEN}=============================================${RESET}"
        cp -f "$tshark_output" "$TSHARK_OUTPUT_FILE" 2>/dev/null || true

        if [[ $SMART_MODE == true && ${#all_ips[@]} -gt 0 ]]; then
            compute_prelim_scores
            select_smart_targets
            render_smart_summary
        fi

        if (( ${#all_ips[@]} > 0 )); then
            echo ""
            echo -e "${BLUE}Collecting HTTP metadata and ONVIF fingerprints...${RESET}"
            collect_http_metadata
            run_onvif_metadata_probe
        fi

        if (( ${#all_ips[@]} > 0 )); then
            echo ""
            echo -e "${BLUE}Probing additional streaming protocols (SRT/WebRTC/ONVIF/RTMP/HLS)...${RESET}"
            probe_additional_protocols
        fi
        
        echo ""
        echo -e "${GREEN}========== Final Results ==========${RESET}"
        camera_count=${#all_ips[@]}
        echo -e "${CYAN}Potential camera devices found: ${GREEN}$camera_count${RESET}"

    if (( camera_count > 0 )); then
            echo -e "${CYAN}Summary:${RESET}"
            printf "${CYAN}%-18s %-24s %-24s${RESET}\n" "IP Address" "Sources" "Ports"
            printf "${CYAN}%-18s %-24s %-24s${RESET}\n" "------------------" "------------------------" "------------------------"
            echo ""
        fi

    if (( camera_count > 0 )); then
            echo -e "${YELLOW}Discovered endpoints:${RESET}"
            hosts_json_tmp=$(mktemp)
            while IFS= read -r ip; do
                sources=${ip_sources[$ip]:-Unknown}
                mac=${ip_to_mac[$ip]:-Unknown}
                raw_ports=${ip_ports[$ip]}
                port_summary=$(printf "%s" "$raw_ports" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ')
                [[ -z $port_summary ]] && port_summary="Unknown"
                observed=${ip_observed_paths[$ip]}

                trimmed_sources=$(printf '%.24s' "$sources")
                trimmed_ports=$(printf '%.24s' "$port_summary")
                printf "%s%-18s %-24s %-24s%s\n" "$CYAN" "$ip" "$trimmed_sources" "$trimmed_ports" "$RESET"

                echo -e "${CYAN}$ip${RESET}"
                echo "  Sources: $sources"
                echo "  MAC: $mac"
                echo "  Ports: $port_summary"

                details=$(match_device_profile "$ip" "$mac" "$port_summary" "$observed")
                [[ -n $details ]] && printf "%b" "$details"
                if [[ -n ${ip_rtsp_discovered[$ip]} ]]; then
                    echo "  RTSP brute discovered URLs:"
                    while IFS= read -r rtsp_line; do
                        [[ -z $rtsp_line ]] && continue
                        echo "    - $rtsp_line"
                    done < <(printf '%s' "${ip_rtsp_discovered[$ip]}" | sed '/^$/d')
                fi
                if [[ -n ${ip_rtsp_other[$ip]} ]]; then
                    echo "  RTSP brute other responses:"
                    while IFS= read -r rtsp_other_line; do
                        [[ -z $rtsp_other_line ]] && continue
                        status="${rtsp_other_line%%|*}"
                        url="${rtsp_other_line#*|}"
                        echo "    $status: $url"
                    done < <(printf '%s' "${ip_rtsp_other[$ip]}" | sed '/^$/d')
                fi
                if [[ -n ${ip_protocol_hits[$ip]} ]]; then
                    echo "  Additional protocols detected:";
                    while IFS= read -r proto_line; do
                        [[ -z $proto_line ]] && continue
                        proto_name="${proto_line%%|*}"
                        proto_detail="${proto_line#*|}"
                        echo "    - ${proto_name}: ${proto_detail}"
                    done < <(printf '%s' "${ip_protocol_hits[$ip]}" | sed '/^$/d')
                fi
                if [[ -n ${ip_http_metadata[$ip]} ]]; then
                    http_meta_count=$(printf '%s' "${ip_http_metadata[$ip]}" | sed '/^$/d' | wc -l | tr -d ' ')
                    echo "  HTTP metadata entries: $http_meta_count"
                fi
                if [[ -n ${ip_onvif_info[$ip]} ]]; then
                    onvif_meta_count=$(printf '%s' "${ip_onvif_info[$ip]}" | sed '/^$/d' | wc -l | tr -d ' ')
                    echo "  ONVIF metadata entries: $onvif_meta_count"
                fi
                if [[ -n ${ip_ssdp_info[$ip]} ]]; then
                    ssdp_meta_count=$(printf '%s' "${ip_ssdp_info[$ip]}" | sed '/^$/d' | wc -l | tr -d ' ')
                    echo "  SSDP responses: $ssdp_meta_count"
                fi
                echo ""

                rtsp_discovered_json="[]"
                if [[ -n ${ip_rtsp_discovered[$ip]} ]]; then
                    rtsp_discovered_json=$(printf '%s' "${ip_rtsp_discovered[$ip]}" | sed '/^$/d' | jq -R -s 'split("\n") | map(select(length>0))')
                fi
                rtsp_other_json="{}"
                if [[ -n ${ip_rtsp_other[$ip]} ]]; then
                    rtsp_other_json=$(printf '%s' "${ip_rtsp_other[$ip]}" | sed '/^$/d' | jq -R -s 'split("\n") | map(select(length>0) | split("|")) | group_by(.[0]) | map({key: (.[0][0]), value: map(.[1])}) | from_entries')
                fi
                protocol_hits_json="[]"
                if [[ -n ${ip_protocol_hits[$ip]} ]]; then
                    protocol_hits_json=$(printf '%s' "${ip_protocol_hits[$ip]}" | sed '/^$/d' | jq -R -s 'split("\n") | map(select(length>0) | split("|") | {protocol: .[0], detail: ((.[1:] | join("|")) // "")} )')
                fi
                http_metadata_json="[]"
                if [[ -n ${ip_http_metadata[$ip]} ]]; then
                    http_metadata_json=$(printf '%s' "${ip_http_metadata[$ip]}" | sed '/^$/d' | jq -R -s 'split("\n") | map(select(length>0) | (try fromjson catch empty)) | map(select(. != null))')
                fi
                onvif_metadata_json="[]"
                if [[ -n ${ip_onvif_info[$ip]} ]]; then
                    onvif_metadata_json=$(printf '%s' "${ip_onvif_info[$ip]}" | sed '/^$/d' | jq -R -s 'split("\n") | map(select(length>0) | (try fromjson catch empty)) | map(select(. != null))')
                fi
                ssdp_metadata_json="[]"
                if [[ -n ${ip_ssdp_info[$ip]} ]]; then
                    ssdp_metadata_json=$(printf '%s' "${ip_ssdp_info[$ip]}" | sed '/^$/d' | jq -R -s 'split("\n") | map(select(length>0) | (try fromjson catch empty)) | map(select(. != null))')
                fi

                host_json=$(jq -n \
                    --arg ip "$ip" \
                    --arg sources "$sources" \
                    --arg mac "$mac" \
                    --arg ports "$port_summary" \
                    --arg observed "$observed" \
                    --argjson rtsp_discovered "$rtsp_discovered_json" \
                    --argjson rtsp_other "$rtsp_other_json" \
                    --argjson protocol_hits "$protocol_hits_json" \
                    --argjson http_metadata "$http_metadata_json" \
                    --argjson onvif_metadata "$onvif_metadata_json" \
                    --argjson ssdp_metadata "$ssdp_metadata_json" \
                    '{
                        ip: $ip,
                        mac: (if $mac == "Unknown" or $mac == "" then null else $mac end),
                        sources: ($sources | split(", ") | map(select(length>0))),
                        ports: ($ports | split(" ") | map(select(length>0) | (tonumber? // .))),
                        observed_paths: ($observed | split(" ") | map(select(length>0))),
                        rtsp_bruteforce: {
                            discovered: $rtsp_discovered,
                            other_responses: $rtsp_other
                        },
                        additional_protocols: $protocol_hits,
                        http_metadata: $http_metadata,
                        onvif: $onvif_metadata,
                        ssdp: $ssdp_metadata
                    }')
                printf '%s\n' "$host_json" >> "$hosts_json_tmp"
            done < <(printf "%s\n" "${!all_ips[@]}" | sort -V)
        fi
        echo -e "${GREEN}=================================${RESET}"

        if [[ -n $hosts_json_tmp && -s $hosts_json_tmp ]]; then
            jq -s '{hosts: .}' "$hosts_json_tmp" > "$DISCOVERY_JSON"
        else
            jq -n '{hosts: []}' > "$DISCOVERY_JSON"
        fi
        [[ -n $hosts_json_tmp ]] && rm -f "$hosts_json_tmp"

        jq --arg mode "$CAM_MODE_NORMALIZED" \
           --arg raw "$CAM_MODE_RAW" \
           --arg timestamp "$RUN_STAMP" \
           --arg network "$scan_scope" \
           '.metadata = {mode: $mode, mode_raw: $raw, generated_at: $timestamp, network: $network}' \
           "$DISCOVERY_JSON" > "$DISCOVERY_JSON.tmp"
        mv "$DISCOVERY_JSON.tmp" "$DISCOVERY_JSON"

        if [[ -f "$PATHS_FILE" && -s "$DISCOVERY_JSON" ]]; then
            discovery_enriched_tmp=$(mktemp)
            if "$PYTHON_BIN" "$PROFILE_RESOLVER" enrich --paths "$PATHS_FILE" --input "$DISCOVERY_JSON" --output "$discovery_enriched_tmp" --limit 3; then
                mv "$discovery_enriched_tmp" "$DISCOVERY_JSON"
            else
                echo -e "${YELLOW}Warning: Unable to enrich device profiles; see above for details.${RESET}"
                rm -f "$discovery_enriched_tmp"
            fi
        fi

        if [[ -f "$CONFIDENCE_SCORER" && -s "$DISCOVERY_JSON" ]]; then
            discovery_confidence_tmp=$(mktemp)
            if "$PYTHON_BIN" "$CONFIDENCE_SCORER" --input "$DISCOVERY_JSON" --output "$discovery_confidence_tmp"; then
                mv "$discovery_confidence_tmp" "$DISCOVERY_JSON"
                CONFIDENCE_READY=true
            else
                echo -e "${YELLOW}Warning: Unable to compute confidence scores.${RESET}"
                rm -f "$discovery_confidence_tmp"
            fi
        fi

        if [[ -f "$DISCOVERY_JSON" ]]; then
            echo -e "${CYAN}Discovery dataset saved to:${RESET} ${GREEN}$DISCOVERY_JSON${RESET}"
        fi

        render_confidence_ranking

        if [[ $EXTRA_IVRE_ENABLED == true && -f "$DISCOVERY_JSON" ]]; then
            echo ""
            echo -e "${BLUE}Syncing discovery dataset with IVRE...${RESET}"
            
            if "$INTEGRATION_DIR/ivre-manager.sh" ingest "$DISCOVERY_JSON" --quiet; then
                echo -e "${GREEN}IVRE sync complete.${RESET}"
            else
                echo -e "${YELLOW}IVRE sync encountered issues. Review ${IVRE_LOG_FILE} for details.${RESET}"
            fi
        fi

        if [[ $SKIP_CREDS == true ]]; then
            echo ""
            echo -e "${YELLOW}Credential probing disabled (--skip-credentials).${RESET}"
        elif [[ -f "$CREDENTIAL_PROBE" && -f "$DISCOVERY_JSON" ]]; then
            echo ""
            echo -e "${BLUE}Launching automated credential probe...${RESET}"
            cred_args=(--input "$DISCOVERY_JSON" --mode "$CAM_MODE_NORMALIZED" --output "$CREDS_JSON" --thumbnails "$THUMB_DIR" --log-dir "$LOG_DIR")
            if [[ $SMART_MODE == true && $CONFIDENCE_READY == true ]]; then
                cred_args+=(--min-confidence "$SMART_MIN_SCORE")
            fi
            if bash "$CREDENTIAL_PROBE" "${cred_args[@]}"; then
                success_count=$(jq 'map(select(.method? != null)) | length' "$CREDS_JSON" 2>/dev/null || echo 0)
                failure_count=$(jq 'map(select((.success? == false))) | length' "$CREDS_JSON" 2>/dev/null || echo 0)
                echo -e "${GREEN}Credential probe complete.${RESET}"
                echo -e "${CYAN}Successful captures: ${GREEN}$success_count${RESET}"
                echo -e "${CYAN}Failed attempts:     ${YELLOW}$failure_count${RESET}"
                echo -e "${CYAN}Artifacts directory:${RESET} ${GREEN}$THUMB_DIR${RESET}"
                echo -e "${CYAN}Detailed log path:${RESET} ${GREEN}$LOG_DIR${RESET}"
                echo -e "${CYAN}Credential report:${RESET} ${GREEN}$CREDS_JSON${RESET}"
            else
                echo -e "${YELLOW}Credential probe encountered an error. Review $LOG_DIR for details.${RESET}"
            fi
        else
            echo ""
            echo -e "${YELLOW}Credential probe helper unavailable or discovery data missing; skipping automated probing.${RESET}"
        fi

        if [[ -n $REPORT_FORMAT ]]; then
            echo ""
            echo -e "${BLUE}Generating report artifacts...${RESET}"
            generate_reports "$REPORT_FORMAT" || true
        fi

        if [[ $ENCRYPT_RESULTS == true ]]; then
            echo ""
            echo -e "${BLUE}Encrypting run artifacts...${RESET}"
            encrypt_results || echo -e "${YELLOW}Encryption failed; results remain unencrypted on disk.${RESET}"
        fi
        
        echo ""
        echo -e "${GREEN}All scans complete!${RESET}"
        echo -e "${YELLOW}Review the results above for potential IP cameras on your network.${RESET}"
        echo -e "${CYAN}Artifacts stored under:${RESET} ${GREEN}$RUN_DIR${RESET}"
        echo -e "${CYAN}Key logs:${RESET} ${GREEN}$NMAP_OUTPUT_FILE${RESET}, ${GREEN}$MASSCAN_OUTPUT_FILE${RESET}, ${GREEN}$AVAHI_OUTPUT_FILE${RESET}, ${GREEN}$TSHARK_OUTPUT_FILE${RESET}"
        if [[ -f "$COAP_LOG_FILE" ]]; then
            echo -e "${CYAN}CoAP probe log:${RESET} ${GREEN}$COAP_LOG_FILE${RESET}"
        fi
        if [[ -f "$COAP_OUTPUT_FILE" ]]; then
            echo -e "${CYAN}CoAP discovery list:${RESET} ${GREEN}$COAP_OUTPUT_FILE${RESET}"
        fi
        if [[ -f "$HTTP_META_LOG" ]]; then
            echo -e "${CYAN}HTTP metadata:${RESET} ${GREEN}$HTTP_META_LOG${RESET}"
        fi
        if [[ -f "$SSDP_OUTPUT_FILE" ]]; then
            echo -e "${CYAN}SSDP captures:${RESET} ${GREEN}$SSDP_OUTPUT_FILE${RESET}"
        fi
        if [[ -f "$ONVIF_OUTPUT_FILE" ]]; then
            echo -e "${CYAN}ONVIF captures:${RESET} ${GREEN}$ONVIF_OUTPUT_FILE${RESET}"
        fi
        if [[ -f "$CATALOG_JSON" ]]; then
            echo -e "${CYAN}Catalog snapshot:${RESET} ${GREEN}$CATALOG_JSON${RESET}"
        fi
        if [[ $EXTRA_IVRE_ENABLED == true && -s "$IVRE_LOG_FILE" ]]; then
            echo -e "${CYAN}IVRE sync log:${RESET} ${GREEN}$IVRE_LOG_FILE${RESET}"
        fi

        [[ -n ${nmap_output:-} ]] && rm -f "$nmap_output"
        [[ -n ${nmap_log:-} ]] && rm -f "$nmap_log"
        [[ -n ${masscan_output:-} ]] && rm -f "$masscan_output"
        [[ -n ${masscan_log:-} ]] && rm -f "$masscan_log"
        [[ -n ${avahi_output:-} ]] && rm -f "$avahi_output"
        [[ -n ${tshark_output:-} ]] && rm -f "$tshark_output"
        [[ -n ${hosts_json_tmp:-} ]] && rm -f "$hosts_json_tmp"
        [[ -n ${discovery_enriched_tmp:-} ]] && rm -f "$discovery_enriched_tmp"
        [[ -n ${discovery_confidence_tmp:-} ]] && rm -f "$discovery_confidence_tmp"
    [[ -n ${coap_output_tmp:-} ]] && rm -f "$coap_output_tmp"
        ;;
    * )
        echo -e "${RED}Setup cancelled.${RESET}"
        exit 1
        ;;
esac

exit 0
