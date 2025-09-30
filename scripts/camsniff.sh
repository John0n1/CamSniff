#!/usr/bin/env bash
#
# CamSniff- Automated IP camera reconnaissance toolkit
# By John Hauger Mitander <john@on1.no>
# Copyright 2025 John Hauger Mitander
#
# SPDX-License-Identifier: MIT
# camsniff.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PATHS_FILE="${PATHS_FILE:-"$ROOT_DIR/data/paths.csv"}"
MODE_CONFIG="$SCRIPT_DIR/mode-config.sh"
DEPS_INSTALL="$SCRIPT_DIR/deps-install.sh"
CREDENTIAL_PROBE="$SCRIPT_DIR/credential-probe.sh"
NMAP_RTSP_SCRIPT="$ROOT_DIR/data/rtsp-url-brute.nse"
NMAP_RTSP_THREADS=10
RTSP_URL_DICT="$ROOT_DIR/data/rtsp-urls.txt"
PORT_PROFILE_DATA="$ROOT_DIR/data/port-profiles.sh"
UI_HELPER="$ROOT_DIR/data/ui-banner.sh"

MODE_DEFAULT="unphantmoable"
MODE_REQUESTED=""
AUTO_CONFIRM=false

RESULTS_ROOT="$ROOT_DIR/dev/results"
RUN_STAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="$RESULTS_ROOT/$RUN_STAMP"
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

# Colors
RED=""
GREEN=""
YELLOW=""
BLUE=""
CYAN=""
RESET=""

declare -A ip_sources
declare -A ip_to_mac
declare -A ip_ports
declare -A ip_observed_paths
declare -A all_ips
declare -A ip_rtsp_discovered
declare -A ip_rtsp_other
declare -A ip_protocol_hits
declare -A protocol_seen

nmap_output=""
nmap_log=""
masscan_output=""
masscan_log=""
avahi_output=""
tshark_output=""
hosts_json_tmp=""
discovery_enriched_tmp=""

print_usage() {
    cat <<'EOF'
Usage: camsniff.sh [--mode <name>] [--yes] [--version] [--help]

Options:
  -m, --mode <name>      Specify scanning mode (stealth, ultra stealth, medium, aggressive, war, unphantmoable)
  -y, --yes              Auto-confirm interactive prompts
  -v, --version          Show version information and exit
  -h, --help             Display this help message and exit

If no mode is provided, the maximum profile (unphantmoable) is used.
EOF
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
    for ip in "${!all_ips[@]}"; do
        ip_list+=("$ip")
    done
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

if [[ ! -f "$MODE_CONFIG" ]]; then
    echo "Missing mode configuration helper: $MODE_CONFIG" >&2
    exit 1
fi

if [[ ! -f "$RTSP_URL_DICT" ]]; then
    echo "Warning: Custom RTSP dictionary missing at $RTSP_URL_DICT. Built-in NSE defaults will be used." >&2
fi

# Source mode configuration for downstream settings
# Load mode configuration exports for the selected profile
if ! mode_env_output="$("$MODE_CONFIG" --mode "$MODE_SELECTED" --format export)"; then
    echo "Failed to resolve mode configuration via $MODE_CONFIG" >&2
    exit 1
fi
eval "$mode_env_output"
unset mode_env_output

if [[ ! -f "$PORT_PROFILE_DATA" ]]; then
    echo "Missing port profile data: $PORT_PROFILE_DATA" >&2
    exit 1
fi

# shellcheck source=../data/port-profiles.sh
source "$PORT_PROFILE_DATA"

if [[ ! -f "$UI_HELPER" ]]; then
    echo "Missing UI helper: $UI_HELPER" >&2
    exit 1
fi

# shellcheck source=../data/ui-banner.sh
source "$UI_HELPER"

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
  BLUE=$(tput setaf 4)
  CYAN=$(tput setaf 6)
  ORANGE=$(tput setaf 214)
  RESET=$(tput sgr0)
fi

# Check if running as root/sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Aborted. Try again with \"sudo camsniff\"${RESET}"
  exit 1
fi

mkdir -p "$RESULTS_ROOT" "$RUN_DIR" "$LOG_DIR" "$THUMB_DIR"

# Clear the screen for a clean start
clear

# Get terminal width for centering
TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

cam_ui_matrix_rain "$TERM_WIDTH" 12 24 0.045 "$GREEN" "$RESET"
clear
cam_ui_render_banner "$TERM_WIDTH" "$CYAN" "$GREEN" "$YELLOW" "$BLUE" "$RESET" "$CAM_MODE_NORMALIZED" "$PORT_SUMMARY_LABEL" "$RUN_DIR"

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
# Ask for confirmation
if [[ $AUTO_CONFIRM == true ]]; then
    answer="y"
    cam_ui_center_line "$TERM_WIDTH" "${GREEN}Auto-confirm enabled. Proceeding with CamSniff.${RESET}"
else
    prompt=$(cam_ui_build_centered "$TERM_WIDTH" "Proceed with CamSniff setup and scan? ${GREEN}Yes [Y]${RESET} | ${RED}No [N]${RESET} ")
    read -r -p "$prompt" answer
fi
case ${answer:0:1} in
    y|Y|"" )
        echo -e "${GREEN}Starting setup process...${RESET}"
        
        # Source the dependency installation script
        if [[ -f "$DEPS_INSTALL" ]]; then
            "$DEPS_INSTALL"
        else
            echo -e "${YELLOW}Warning: deps-install.sh not found. Continuing without installing dependencies.${RESET}"
        fi

        required_tools=(nmap jq python3 curl ffmpeg tshark avahi-browse)
        if [[ ${CAM_MODE_MASSCAN_ENABLE,,} == "true" ]]; then
            required_tools+=(masscan)
        fi
        missing_tools=()
        for tool in "${required_tools[@]}"; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                missing_tools+=("$tool")
            fi
        done
        if (( ${#missing_tools[@]} > 0 )); then
            echo -e "${YELLOW}Warning: Missing helper tools: ${missing_tools[*]}. Some stages may be skipped.${RESET}"
        fi
        
        # Get the current IP and network
        current_ip=$(ip route get 1 | awk '{print $7;exit}')
        network=$(ip route | grep -m1 ^default | awk '{print $3}' | sed 's/\.[0-9]*$/.0\/24/')
        
        echo ""
        echo -e "${CYAN}Your IP address: ${GREEN}$current_ip${RESET}"
        echo -e "${CYAN}Scanning network: ${GREEN}$network${RESET}"
        echo ""
        
        # Common ports for IP cameras: HTTP, HTTPS, RTSP, and vendor-specific
        echo -e "${BLUE}Network scanning in progress...${RESET}"

        # Store nmap results for reporting and hide verbose output
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
        nmap_cmd+=(-p "$NMAP_PORT_LIST" --open "$network" -oN "$nmap_output")
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
        
        # Display a loading animation
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
        
        # Generate nmap report
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
            masscan_cmd=(masscan -p "$MASSCAN_PORT_SPEC" --rate "$CAM_MODE_MASSCAN_RATE" "$network" -oJ "$masscan_output")
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
        
        echo ""
        echo -e "${BLUE}Starting Avahi service discovery for cameras...${RESET}"
        
        # Use Avahi to discover camera services on the network
        avahi_output=$(mktemp)
        avahi_duration=$(( CAM_MODE_TSHARK_DURATION / 2 ))
        (( avahi_duration < 15 )) && avahi_duration=15
        timeout "${avahi_duration}s" avahi-browse -art | grep -i -e camera -e webcam -e rtsp -e onvif -e axis > "$avahi_output" &
        pid=$!
        
        # Display a loading animation for Avahi discovery
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
        
        # Generate Avahi report
    services_found=$(grep -c "=" "$avahi_output" || echo "0")
        
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
        
        # Capture network traffic with TShark for camera protocols
        tshark_output=$(mktemp)
        tshark_duration=${CAM_MODE_TSHARK_DURATION:-30}
        timeout "${tshark_duration}s" tshark -n -i any \
            -f "tcp port 80 or tcp port 554 or tcp port 8554 or udp port 5000-5010" \
            -Y "rtsp || http.request || onvif" \
            -T fields -E header=n -E separator=, -E quote=d \
            -e frame.time_relative -e ip.src -e ip.dst -e tcp.port -e udp.port \
            -e http.host -e http.request.uri -e rtsp.request -e rtsp.uri > "$tshark_output" &
        pid=$!
        
        # Display a loading animation for TShark capture
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
        
        # Process results and identify potential camera streams
    traffic_found=$(wc -l < "$tshark_output" | tr -d ' ')
        
        echo ""
        echo -e "${GREEN}========== Network Traffic Analysis ==========${RESET}"
        echo -e "${CYAN}Captured packets: ${GREEN}$traffic_found${RESET}"
    if [[ -n $traffic_found && $traffic_found =~ ^[0-9]+$ ]] && (( traffic_found > 0 )); then
            echo -e "${YELLOW}Potential camera streams detected:${RESET}"
            sort "$tshark_output" | uniq -c | sort -nr | head -10
            while IFS=',' read -r _time_rel src dst tcp_port udp_port _http_host http_uri _rtsp_request rtsp_uri; do
                src=${src//\"/}
                dst=${dst//\"/}
                tcp_port=${tcp_port//\"/}
                udp_port=${udp_port//\"/}
                http_uri=${http_uri//\"/}
                rtsp_uri=${rtsp_uri//\"/}

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

                host_json=$(jq -n \
                    --arg ip "$ip" \
                    --arg sources "$sources" \
                    --arg mac "$mac" \
                    --arg ports "$port_summary" \
                    --arg observed "$observed" \
                    --argjson rtsp_discovered "$rtsp_discovered_json" \
                    --argjson rtsp_other "$rtsp_other_json" \
                    --argjson protocol_hits "$protocol_hits_json" \
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
                        additional_protocols: $protocol_hits
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
           --arg network "$network" \
           '.metadata = {mode: $mode, mode_raw: $raw, generated_at: $timestamp, network: $network}' \
           "$DISCOVERY_JSON" > "$DISCOVERY_JSON.tmp"
        mv "$DISCOVERY_JSON.tmp" "$DISCOVERY_JSON"

        if [[ -f "$PATHS_FILE" && -s "$DISCOVERY_JSON" ]]; then
            discovery_enriched_tmp=$(mktemp)
            if ! python3 - "$PATHS_FILE" "$DISCOVERY_JSON" "$discovery_enriched_tmp" <<'PY'
import csv
import json
import re
import sys

paths_file, discovery_file, output_file = sys.argv[1:4]

try:
    with open(discovery_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except FileNotFoundError:
    data = {"hosts": []}

try:
    with open(paths_file, "r", encoding="utf-8") as handle:
        catalog = list(csv.DictReader(handle))
except FileNotFoundError:
    catalog = []

def parse_list(value):
    if not value:
        return []
    parts = [item.strip() for item in value.split(';') if item.strip()]
    return parts

def coerce_port(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None

for host in data.get("hosts", []):
    ports = set()
    for entry in host.get("ports", []):
        converted = coerce_port(entry)
        if converted is not None:
            ports.add(converted)
    mac = (host.get("mac") or "").upper()
    best = None
    best_score = -1
    for row in catalog:
        matched_by = None
        pattern = (row.get("oui_regex") or "").strip()
        if mac and pattern:
            try:
                if re.search(pattern, mac, re.IGNORECASE):
                    matched_by = "oui"
            except re.error:
                pass
        if not matched_by:
            candidate_port = coerce_port(row.get("port"))
            if candidate_port is not None and candidate_port in ports:
                matched_by = "port"
        if not matched_by:
            continue
        score = 2 if matched_by == "oui" else 1
        if score <= best_score:
            continue
        best = (row, matched_by)
        best_score = score

    if not best:
        continue

    row, matched_by = best

    def build_rtsp_candidates():
        template = row.get("rtsp_url") or ""
        if not template:
            return []
        port_val = coerce_port(row.get("port"))
        streams = parse_list(row.get("streams")) or ["0"]
        channels = parse_list(row.get("channels")) or ["1"]
        candidates = []
        for channel in channels[:3]:
            for stream in streams[:3]:
                candidates.append({
                    "template": template,
                    "port": port_val if port_val is not None else (row.get("port") or 554),
                    "channel": channel,
                    "stream": stream,
                    "transport": "tcp"
                })
                if len(candidates) >= 6:
                    return candidates
        return candidates

    def build_http_candidates():
        template = row.get("http_snapshot_url") or ""
        if not template:
            return []
        port_val = coerce_port(row.get("port"))
        streams = parse_list(row.get("streams")) or ["0"]
        channels = parse_list(row.get("channels")) or ["1"]
        port_guess = port_val if port_val is not None else (443 if template.lower().startswith("https") else 80)
        return [{
            "template": template,
            "port": port_guess,
            "channel": channels[0],
            "stream": streams[0]
        }]

    profile = {
        "vendor": row.get("company") or "Unknown",
        "model": row.get("model") or "Unknown",
        "type": row.get("type") or "Unknown",
        "matched_by": matched_by,
        "default_username": row.get("username") or "",
        "default_password": row.get("password") or "",
        "digest_auth": str(row.get("is_digest_auth_supported") or "").lower() in {"true", "yes", "1"},
        "video_encoding": row.get("video_encoding") or "",
        "rtsp_candidates": build_rtsp_candidates(),
        "http_snapshot_candidates": build_http_candidates(),
        "onvif_profiles": parse_list(row.get("onvif_profile_path")),
        "cve_ids": parse_list(row.get("cve_ids")),
        "reference": row.get("user_manual_url") or ""
    }

    host["profile_match"] = profile

with open(output_file, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
PY
            then
                mv "$discovery_enriched_tmp" "$DISCOVERY_JSON"
            else
                echo -e "${YELLOW}Warning: Unable to enrich device profiles; see above for details.${RESET}"
                rm -f "$discovery_enriched_tmp"
            fi
        fi

        if [[ -f "$DISCOVERY_JSON" ]]; then
            echo -e "${CYAN}Discovery dataset saved to:${RESET} ${GREEN}$DISCOVERY_JSON${RESET}"
        fi

        if [[ -f "$CREDENTIAL_PROBE" && -f "$DISCOVERY_JSON" ]]; then
            echo ""
            echo -e "${BLUE}Launching automated credential probe...${RESET}"
            if bash "$CREDENTIAL_PROBE" --input "$DISCOVERY_JSON" --mode "$CAM_MODE_NORMALIZED" --output "$CREDS_JSON" --thumbnails "$THUMB_DIR" --log-dir "$LOG_DIR"; then
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
        
        echo ""
        echo -e "${GREEN}All scans complete!${RESET}"
        echo -e "${YELLOW}Review the results above for potential IP cameras on your network.${RESET}"
        echo -e "${CYAN}Artifacts stored under:${RESET} ${GREEN}$RUN_DIR${RESET}"
        echo -e "${CYAN}Key logs:${RESET} ${GREEN}$NMAP_OUTPUT_FILE${RESET}, ${GREEN}$MASSCAN_OUTPUT_FILE${RESET}, ${GREEN}$AVAHI_OUTPUT_FILE${RESET}, ${GREEN}$TSHARK_OUTPUT_FILE${RESET}"

        # Clean up temporary files
        [[ -n ${nmap_output:-} ]] && rm -f "$nmap_output"
        [[ -n ${nmap_log:-} ]] && rm -f "$nmap_log"
        [[ -n ${masscan_output:-} ]] && rm -f "$masscan_output"
        [[ -n ${masscan_log:-} ]] && rm -f "$masscan_log"
        [[ -n ${avahi_output:-} ]] && rm -f "$avahi_output"
        [[ -n ${tshark_output:-} ]] && rm -f "$tshark_output"
        [[ -n ${hosts_json_tmp:-} ]] && rm -f "$hosts_json_tmp"
        [[ -n ${discovery_enriched_tmp:-} ]] && rm -f "$discovery_enriched_tmp"
        ;;
    * )
        echo -e "${RED}Setup cancelled.${RESET}"
        exit 1
        ;;
esac

exit 0