#!/usr/bin/env bash
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

INPUT_JSON=""
USERNAMES_FILE="$ROOT_DIR/data/dictionaries/usernames.txt"
PASSWORDS_FILE="$ROOT_DIR/data/dictionaries/passwords.txt"
HTTP_PATHS_FILE="$ROOT_DIR/data/dictionaries/http-paths.txt"
MODE="medium"
OUTPUT_JSON="$ROOT_DIR/dev/results/credentials.json"
THUMB_DIR="$ROOT_DIR/dev/results/thumbnails"
LOG_DIR="$ROOT_DIR/dev/results/logs"
MIN_CONFIDENCE=0
VENDOR_DATA_DIR="$ROOT_DIR/data/vendors"
VENDOR_HTTP_LIMIT=10
VENDOR_RTSP_LIMIT=8
declare -A vendor_http_cache
declare -A vendor_rtsp_cache

print_usage() {
    cat <<'EOF'
Usage: credential-probe.sh --input devices.json [--mode <mode>] [--usernames file] [--passwords file] \
                           [--output credentials.json] [--thumbnails dir] [--min-confidence <score>]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input)
            INPUT_JSON="${2:-}"
            shift 2
            ;;
        --mode|-m)
            MODE="${2:-}"
            shift 2
            ;;
        --usernames)
            USERNAMES_FILE="${2:-}"
            shift 2
            ;;
        --passwords)
            PASSWORDS_FILE="${2:-}"
            shift 2
            ;;
        --http-paths)
            HTTP_PATHS_FILE="${2:-}"
            shift 2
            ;;
        --output)
            OUTPUT_JSON="${2:-}"
            shift 2
            ;;
        --thumbnails)
            THUMB_DIR="${2:-}"
            shift 2
            ;;
        --log-dir)
            LOG_DIR="${2:-}"
            shift 2
            ;;
        --min-confidence)
            MIN_CONFIDENCE="${2:-}"
            if [[ -z $MIN_CONFIDENCE || ! $MIN_CONFIDENCE =~ ^[0-9]+$ ]]; then
                echo "--min-confidence requires a numeric score" >&2
                exit 1
            fi
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

[[ -f "$INPUT_JSON" ]] || { echo "Input JSON not found: $INPUT_JSON" >&2; exit 1; }
[[ -f "$USERNAMES_FILE" ]] || { echo "Username list missing: $USERNAMES_FILE" >&2; exit 1; }
[[ -f "$PASSWORDS_FILE" ]] || { echo "Password list missing: $PASSWORDS_FILE" >&2; exit 1; }

HTTP_FALLBACKS=()
if [[ -f "$HTTP_PATHS_FILE" ]]; then
    while IFS= read -r line; do
        line=${line%%#*}
        line=$(printf '%s' "$line" | sed 's/^\s*//;s/\s*$//')
        [[ -z $line ]] && continue
        HTTP_FALLBACKS+=("$line")
    done < "$HTTP_PATHS_FILE"
else
    HTTP_FALLBACKS=(
        "http://{{username}}:{{password}}@{{ip_address}}/snapshot.jpg|80|1|0|generic snapshot"
        "http://{{username}}:{{password}}@{{ip_address}}/image.jpg|80|1|0|generic image"
        "http://{{username}}:{{password}}@{{ip_address}}/cgi-bin/snapshot.cgi|80|1|0|generic cgi"
    )
fi

mkdir -p "$(dirname "$OUTPUT_JSON")" "$THUMB_DIR" "$LOG_DIR"

if ! mode_env_output="$("$ROOT_DIR/scripts/core/mode-config.sh" --mode "$MODE" --format export)"; then
    echo "Failed to resolve mode configuration" >&2
    exit 1
fi
eval "$mode_env_output"
unset mode_env_output

readarray -t USERNAME_LIST < <(grep -vE '^\s*(#|$)' "$USERNAMES_FILE" | sed 's/\r$//')
readarray -t PASSWORD_LIST < <(grep -vE '^\s*(#|$)' "$PASSWORDS_FILE" | sed 's/\r$//')

MAX_CREDENTIALS=${CAM_MODE_MAX_CREDENTIALS:-32}
CURL_TIMEOUT=${CAM_MODE_CURL_TIMEOUT:-8}
FFMPEG_TIMEOUT=${CAM_MODE_FFMPEG_TIMEOUT:-10}
HTTP_RETRIES=${CAM_MODE_HTTP_RETRIES:-2}
FALLBACK_HTTP_CRED_LIMIT=6

normalize_vendor_key() {
    local raw="$1"
    raw=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')
    raw=${raw// /}
    raw=$(printf '%s' "$raw" | sed 's/[^a-z0-9]//g')
    if [[ -z $raw ]]; then
        echo ""
        return
    fi
    case "$raw" in
        hikvision*|hikvisiondigitaltechnology*|hik*)
            echo "hikvision"
            ;;
        dahua*|dahuatechnology*)
            echo "dahua"
            ;;
        axis*|axiscommunications*)
            echo "axis"
            ;;
        hanwha*|samsung*)
            echo "hanwha"
            ;;
        uniview*|unv*)
            echo "uniview"
            ;;
        vivotek*)
            echo "vivotek"
            ;;
        reolink*)
            echo "reolink"
            ;;
        amcrest*)
            echo "amcrest"
            ;;
        lorex*)
            echo "lorex"
            ;;
        bosch*)
            echo "bosch"
            ;;
        panasonic*)
            echo "panasonic"
            ;;
        sony*)
            echo "sony"
            ;;
        geovision*)
            echo "geovision"
            ;;
        tiandy*)
            echo "tiandy"
            ;;
        avigilon*)
            echo "avigilon"
            ;;
        ezviz*)
            echo "ezviz"
            ;;
        *)
            echo "$raw"
            ;;
    esac
}

detect_vendor_key() {
    local vendor="$1"
    local http_json="$2"
    local onvif_json="$3"
    local ssdp_json="$4"
    local candidate=""
    if [[ -n $vendor && ${vendor,,} != "unknown" ]]; then
        candidate=$(normalize_vendor_key "$vendor")
    fi

    if [[ -z $candidate && -n $onvif_json ]]; then
        candidate=$(jq -r '.[]? | .manufacturer? // empty' <<<"$onvif_json" | head -n1)
        candidate=$(normalize_vendor_key "$candidate")
    fi

    if [[ -z $candidate && -n $ssdp_json ]]; then
        candidate=$(jq -r '.[]? | .manufacturer? // empty' <<<"$ssdp_json" | head -n1)
        candidate=$(normalize_vendor_key "$candidate")
    fi

    if [[ -z $candidate && -n $http_json ]]; then
        local banner
        banner=$(jq -r '.[]? | [.server, .realm, .title] | map(select(. != null)) | join(" ")' <<<"$http_json" | tr '\n' ' ')
        banner=${banner,,}
        case "$banner" in
            *hikvision*) candidate="hikvision" ;;
            *dahua*) candidate="dahua" ;;
            *axis*) candidate="axis" ;;
            *hanwha*|*samsung*) candidate="hanwha" ;;
            *uniview*) candidate="uniview" ;;
            *vivotek*) candidate="vivotek" ;;
            *reolink*) candidate="reolink" ;;
            *amcrest*) candidate="amcrest" ;;
            *lorex*) candidate="lorex" ;;
            *bosch*) candidate="bosch" ;;
            *panasonic*) candidate="panasonic" ;;
            *sony*) candidate="sony" ;;
            *geovision*) candidate="geovision" ;;
            *tiandy*) candidate="tiandy" ;;
            *avigilon*) candidate="avigilon" ;;
            *ezviz*) candidate="ezviz" ;;
        esac
    fi

    if [[ -n $candidate && -d "$VENDOR_DATA_DIR/$candidate" ]]; then
        echo "$candidate"
    else
        echo ""
    fi
}

load_vendor_http_lines() {
    local key="$1"
    local cache="${vendor_http_cache[$key]:-}"
    VENDOR_HTTP_LINES=()
    if [[ -n $cache ]]; then
        readarray -t VENDOR_HTTP_LINES <<< "$cache"
        return
    fi
    local file="$VENDOR_DATA_DIR/$key/http-paths.txt"
    if [[ -f $file ]]; then
        while IFS= read -r line; do
            line=${line%%#*}
            line=$(printf '%s' "$line" | sed 's/^\s*//;s/\s*$//')
            [[ -z $line ]] && continue
            VENDOR_HTTP_LINES+=("$line")
        done < "$file"
    fi
    vendor_http_cache["$key"]=$(printf '%s\n' "${VENDOR_HTTP_LINES[@]}")
}

load_vendor_rtsp_lines() {
    local key="$1"
    local cache="${vendor_rtsp_cache[$key]:-}"
    VENDOR_RTSP_LINES=()
    if [[ -n $cache ]]; then
        readarray -t VENDOR_RTSP_LINES <<< "$cache"
        return
    fi
    local file="$VENDOR_DATA_DIR/$key/rtsp-paths.txt"
    if [[ -f $file ]]; then
        while IFS= read -r line; do
            line=${line%%#*}
            line=$(printf '%s' "$line" | sed 's/^\s*//;s/\s*$//')
            [[ -z $line ]] && continue
            VENDOR_RTSP_LINES+=("$line")
        done < "$file"
    fi
    vendor_rtsp_cache["$key"]=$(printf '%s\n' "${VENDOR_RTSP_LINES[@]}")
}

build_vendor_http_candidates() {
    local key="$1"
    VENDOR_HTTP_CANDIDATES=()
    load_vendor_http_lines "$key"
    local count=0
    local entry
    for entry in "${VENDOR_HTTP_LINES[@]}"; do
        IFS='|' read -r template port channel stream label <<<"$entry"
        [[ -z $template ]] && continue
        port=${port:-80}
        channel=${channel:-1}
        stream=${stream:-0}
        label=${label:-$key}
        local json
        json=$(jq -n \
            --arg template "$template" \
            --argjson port "$port" \
            --arg channel "$channel" \
            --arg stream "$stream" \
            --arg label "$label" \
            --arg origin "vendor" \
            '{template: $template, port: $port, channel: $channel, stream: $stream, label: $label, origin: $origin}')
        VENDOR_HTTP_CANDIDATES+=("$json")
        count=$((count + 1))
        if (( count >= VENDOR_HTTP_LIMIT )); then
            break
        fi
    done
}

build_vendor_rtsp_candidates() {
    local key="$1"
    VENDOR_RTSP_CANDIDATES=()
    load_vendor_rtsp_lines "$key"
    local count=0
    local entry
    for entry in "${VENDOR_RTSP_LINES[@]}"; do
        IFS='|' read -r template port channel stream transport label <<<"$entry"
        [[ -z $template ]] && continue
        port=${port:-554}
        channel=${channel:-1}
        stream=${stream:-0}
        transport=${transport:-tcp}
        label=${label:-$key}
        local json
        json=$(jq -n \
            --arg template "$template" \
            --argjson port "$port" \
            --arg channel "$channel" \
            --arg stream "$stream" \
            --arg transport "$transport" \
            --arg label "$label" \
            --arg origin "vendor" \
            '{template: $template, port: $port, channel: $channel, stream: $stream, transport: $transport, label: $label, origin: $origin}')
        VENDOR_RTSP_CANDIDATES+=("$json")
        count=$((count + 1))
        if (( count >= VENDOR_RTSP_LIMIT )); then
            break
        fi
    done
}

render_template() {
    local template="$1"
    local ip="$2"
    local username="$3"
    local password="$4"
    local port="$5"
    local channel="$6"
    local stream="$7"
    local result="$template"
    result="${result//\{\{ip_address\}\}/$ip}"
    result="${result//\{\{username\}\}/${username}}"
    result="${result//\{\{password\}\}/${password}}"
    result="${result//\{\{port\}\}/${port}}"
    result="${result//\{\{channel\}\}/${channel}}"
    result="${result//\{\{stream\}\}/${stream}}"
    echo "$result"
}

apply_credentials_to_url() {
    local url="$1"
    local username="$2"
    local password="$3"

    [[ -z $username ]] && { echo "$url"; return; }
    [[ $url != *"://"* ]] && { echo "$url"; return; }

    local scheme="${url%%://*}"
    local rest="${url#*://}"
    local host_part="${rest%%/*}"
    if [[ $host_part == *"@"* ]]; then
        echo "$url"
        return
    fi

    local auth="$username"
    [[ -n $password ]] && auth+=":$password"
    echo "${scheme}://${auth}@${rest}"
}

trim_auth_in_url() {
    local url="$1"
    if [[ $url =~ ^rtsp://:@ ]]; then
        echo "rtsp://${url#rtsp://:@}"
    elif [[ $url =~ ^http://:@ ]]; then
        echo "http://${url#http://:@}"
    else
        echo "$url"
    fi
}

build_credentials() {
    local defaults_user="$1"
    local defaults_pass="$2"
    local max_entries="$3"
    declare -A seen=()
    local -a creds=()

    add_cred() {
        local user="$1"
        local pass="$2"
        local key="$user|$pass"
        if [[ -z ${seen[$key]+set} ]]; then
            seen[$key]=1
            creds+=("$user|$pass")
        fi
    }

    if [[ -n $defaults_user || -n $defaults_pass ]]; then
        add_cred "$defaults_user" "$defaults_pass"
        add_cred "$defaults_user" ""
    fi
    add_cred "" ""

    for pass in "${PASSWORD_LIST[@]}"; do
        [[ ${#creds[@]} -ge $max_entries ]] && break
        if [[ -n $defaults_user ]]; then
            add_cred "$defaults_user" "$pass"
        fi
    done

    for user in "${USERNAME_LIST[@]}"; do
        [[ ${#creds[@]} -ge $max_entries ]] && break
        if [[ -n $defaults_pass ]]; then
            add_cred "$user" "$defaults_pass"
        fi
    done

    for user in "${USERNAME_LIST[@]}"; do
        for pass in "${PASSWORD_LIST[@]}"; do
            [[ ${#creds[@]} -ge $max_entries ]] && break 2
            add_cred "$user" "$pass"
        done
    done

    printf '%s\n' "${creds[@]}"
}

attempt_http_snapshot() {
    local url="$1"
    local username="$2"
    local password="$3"
    local ip="$4"
    local out_file="$5"
    local log_file="$6"

    local auth_opts=()
    if [[ -n $username || -n $password ]]; then
        auth_opts+=("--user" "$username:$password")
    fi

    local http_code
    http_code=$(curl -m "$CURL_TIMEOUT" --connect-timeout "$CURL_TIMEOUT" --retry "$HTTP_RETRIES" --retry-delay 1 \
        --retry-connrefused --silent --show-error --output "$out_file" --write-out '%{http_code}' \
        "${auth_opts[@]}" "$url" 2>"$log_file") || return 1

    [[ $http_code == "200" ]] || return 1
    local size
    size=$(stat -c%s "$out_file" 2>/dev/null || echo 0)
    [[ $size -gt 512 ]] || return 1
    return 0
}

attempt_rtsp_snapshot() {
    local url="$1"
    local ip="$2"
    local out_file="$3"
    local log_file="$4"

    ffmpeg -loglevel error -nostdin -rtsp_transport tcp -stimeout "$((FFMPEG_TIMEOUT * 1000000))" \
        -y -i "$url" -frames:v 1 "$out_file" >"$log_file" 2>&1 || return 1
    local size
    size=$(stat -c%s "$out_file" 2>/dev/null || echo 0)
    [[ $size -gt 1024 ]]
}

make_ascii_preview() {
    local image="$1"
    local output_txt="$2"
    if command -v chafa >/dev/null 2>&1; then
        chafa --size=80x24 "$image" > "$output_txt" 2>/dev/null || true
    fi
}

HOSTS_TMP=$(mktemp)
RESULTS_TMP=$(mktemp)
trap 'rm -f "$HOSTS_TMP" "$RESULTS_TMP"' EXIT

jq -c '.hosts[]' "$INPUT_JSON" > "$HOSTS_TMP"

while IFS= read -r host_json; do
    ip=$(jq -r '.ip' <<<"$host_json")
    confidence_score=$(jq -r '.confidence.score // 0' <<<"$host_json")
    if [[ -z $confidence_score || ! $confidence_score =~ ^[0-9]+$ ]]; then
        confidence_score=0
    fi
    if (( confidence_score < MIN_CONFIDENCE )); then
        continue
    fi
    vendor=$(jq -r '.profile_match.vendor // "Unknown"' <<<"$host_json")
    model=$(jq -r '.profile_match.model // "Unknown"' <<<"$host_json")
    matched_by=$(jq -r '.profile_match.matched_by // "unknown"' <<<"$host_json")
    default_user=$(jq -r '.profile_match.default_username // ""' <<<"$host_json")
    default_pass=$(jq -r '.profile_match.default_password // ""' <<<"$host_json")

    protocols_json=$(jq -c '.additional_protocols // []' <<<"$host_json")
    [[ -z $protocols_json ]] && protocols_json='[]'

    profile_matches_json=$(jq -c '.profile_matches // []' <<<"$host_json")
    [[ -z $profile_matches_json ]] && profile_matches_json='[]'
    sources_json=$(jq -c '.sources // []' <<<"$host_json")
    [[ -z $sources_json ]] && sources_json='[]'
    ports_json=$(jq -c '.ports // []' <<<"$host_json")
    [[ -z $ports_json ]] && ports_json='[]'
    observed_paths_json=$(jq -c '.observed_paths // []' <<<"$host_json")
    [[ -z $observed_paths_json ]] && observed_paths_json='[]'
    rtsp_bruteforce_json=$(jq -c '.rtsp_bruteforce // {}' <<<"$host_json")
    [[ -z $rtsp_bruteforce_json ]] && rtsp_bruteforce_json='{}'

    readarray -t rtsp_candidates < <(jq -c '.profile_match.rtsp_candidates[]?' <<<"$host_json")
    readarray -t http_candidates < <(jq -c '.profile_match.http_snapshot_candidates[]?' <<<"$host_json")
    readarray -t brute_rtsp_hits < <(jq -r '.rtsp_bruteforce.discovered[]?' <<<"$host_json")

    http_metadata_json=$(jq -c '.http_metadata // []' <<<"$host_json")
    onvif_json=$(jq -c '.onvif // []' <<<"$host_json")
    ssdp_json=$(jq -c '.ssdp // []' <<<"$host_json")
    vendor_key=$(detect_vendor_key "$vendor" "$http_metadata_json" "$onvif_json" "$ssdp_json")

    if [[ -n $vendor_key ]]; then
        build_vendor_http_candidates "$vendor_key"
        build_vendor_rtsp_candidates "$vendor_key"
        if (( ${#VENDOR_HTTP_CANDIDATES[@]} > 0 )); then
            http_candidates+=("${VENDOR_HTTP_CANDIDATES[@]}")
        fi
        if (( ${#VENDOR_RTSP_CANDIDATES[@]} > 0 )); then
            rtsp_candidates+=("${VENDOR_RTSP_CANDIDATES[@]}")
        fi
    fi

    if [[ ${#rtsp_candidates[@]} -eq 0 && ${#http_candidates[@]} -eq 0 && ${#brute_rtsp_hits[@]} -eq 0 && ${#HTTP_FALLBACKS[@]} -eq 0 ]]; then
        continue
    fi

    readarray -t credentials < <(build_credentials "$default_user" "$default_pass" "$MAX_CREDENTIALS")

    declare -A attempted_http=()
    declare -A attempted_rtsp=()

    success=false
    success_payload=""
    attempt=0

    for credential in "${credentials[@]}"; do
        IFS='|' read -r cred_user cred_pass <<<"$credential"
        (( attempt += 1 ))

        for http_candidate in "${http_candidates[@]}"; do
            channel=$(jq -r '.channel // "1"' <<<"$http_candidate")
            stream=$(jq -r '.stream // "0"' <<<"$http_candidate")
            template=$(jq -r '.template' <<<"$http_candidate")
            port=$(jq -r '.port // 80' <<<"$http_candidate")
            origin=$(jq -r '.origin // "profile"' <<<"$http_candidate")
            label=$(jq -r '.label // ""' <<<"$http_candidate")
            key="http|$template|$port|$channel|$stream"
            if [[ -n ${attempted_http[$key]+set} ]]; then
                continue
            fi
            attempted_http[$key]=1
            url=$(render_template "$template" "$ip" "$cred_user" "$cred_pass" "$port" "$channel" "$stream")
            url=$(trim_auth_in_url "$url")
            suffix="http"
            if [[ -n $label ]]; then
                suffix="http_${label//[^a-zA-Z0-9]/_}"
            elif [[ $origin != "profile" ]]; then
                suffix="http_${origin//[^a-zA-Z0-9]/_}"
            fi
            snapshot_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_${suffix}.jpg"
            log_file="$LOG_DIR/${ip//[^a-zA-Z0-9._-]/_}_${suffix}.log"
            if attempt_http_snapshot "$url" "$cred_user" "$cred_pass" "$ip" "$snapshot_file" "$log_file"; then
                ascii_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_${suffix}.txt"
                make_ascii_preview "$snapshot_file" "$ascii_file"
                timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                success_payload=$(jq -n \
                    --arg ip "$ip" \
                    --arg method "http_snapshot" \
                    --arg origin "$origin" \
                    --arg url "$url" \
                    --arg username "$cred_user" \
                    --arg password "$cred_pass" \
                    --arg vendor "$vendor" \
                    --arg model "$model" \
                    --arg matched_by "$matched_by" \
                    --arg snapshot "$snapshot_file" \
                    --arg ascii "$ascii_file" \
                    --arg timestamp "$timestamp" \
                    --arg attempt "$attempt" \
                    --arg channel "$channel" \
                    --arg stream "$stream" \
                    --arg port "$port" \
                    --arg protocol "http" \
                    --argjson sources "$sources_json" \
                    --argjson ports "$ports_json" \
                    --argjson observed "$observed_paths_json" \
                    --argjson rtsp_bruteforce "$rtsp_bruteforce_json" \
                    --argjson profile_matches "$profile_matches_json" \
                    --argjson protocols "$protocols_json" \
                    '{
                        ip: $ip,
                        method: $method,
                        origin: $origin,
                        vendor: $vendor,
                        model: $model,
                        matched_by: $matched_by,
                        attempt_index: ($attempt | tonumber? // null),
                        credentials: {username: $username, password: $password},
                        artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                        url: $url,
                        request: {
                            protocol: $protocol,
                            origin: $origin,
                            port: ($port | tonumber? // null),
                            channel: $channel,
                            stream: $stream,
                            url: $url
                        },
                        sources: $sources,
                        ports: $ports,
                        observed_paths: $observed,
                        rtsp_bruteforce: $rtsp_bruteforce,
                        profile_matches: $profile_matches,
                        timestamp: $timestamp,
                        protocols: $protocols
                    }')
                success=true
                break 2
            fi
        done

        if (( attempt <= FALLBACK_HTTP_CRED_LIMIT )); then
            for fallback in "${HTTP_FALLBACKS[@]}"; do
                IFS='|' read -r fallback_template fallback_port fallback_channel fallback_stream fallback_label <<<"$fallback"
                [[ -z $fallback_template ]] && continue
                fallback_port=${fallback_port:-80}
                fallback_channel=${fallback_channel:-1}
                fallback_stream=${fallback_stream:-0}
                key="http|$fallback_template|$fallback_port|$fallback_channel|$fallback_stream"
                if [[ -n ${attempted_http[$key]+set} ]]; then
                    continue
                fi
                attempted_http[$key]=1
                origin="fallback${fallback_label:+:$fallback_label}"
                url=$(render_template "$fallback_template" "$ip" "$cred_user" "$cred_pass" "$fallback_port" "$fallback_channel" "$fallback_stream")
                url=$(trim_auth_in_url "$url")
                suffix=${fallback_label//[^a-zA-Z0-9]/_}
                suffix=${suffix:-generic}
                snapshot_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_http_${suffix}.jpg"
                log_file="$LOG_DIR/${ip//[^a-zA-Z0-9._-]/_}_http_${suffix}.log"
                if attempt_http_snapshot "$url" "$cred_user" "$cred_pass" "$ip" "$snapshot_file" "$log_file"; then
                    ascii_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_http_${suffix}.txt"
                    make_ascii_preview "$snapshot_file" "$ascii_file"
                    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                    success_payload=$(jq -n \
                        --arg ip "$ip" \
                        --arg method "http_snapshot" \
                        --arg origin "$origin" \
                        --arg url "$url" \
                        --arg username "$cred_user" \
                        --arg password "$cred_pass" \
                        --arg vendor "$vendor" \
                        --arg model "$model" \
                        --arg matched_by "$matched_by" \
                        --arg snapshot "$snapshot_file" \
                        --arg ascii "$ascii_file" \
                        --arg timestamp "$timestamp" \
                        --arg attempt "$attempt" \
                        --arg channel "$fallback_channel" \
                        --arg stream "$fallback_stream" \
                        --arg port "$fallback_port" \
                        --arg protocol "http" \
                        --argjson sources "$sources_json" \
                        --argjson ports "$ports_json" \
                        --argjson observed "$observed_paths_json" \
                        --argjson rtsp_bruteforce "$rtsp_bruteforce_json" \
                        --argjson profile_matches "$profile_matches_json" \
                        --argjson protocols "$protocols_json" \
                        '{
                            ip: $ip,
                            method: $method,
                            origin: $origin,
                            vendor: $vendor,
                            model: $model,
                            matched_by: $matched_by,
                            attempt_index: ($attempt | tonumber? // null),
                            credentials: {username: $username, password: $password},
                            artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                            url: $url,
                            request: {
                                protocol: $protocol,
                                origin: $origin,
                                port: ($port | tonumber? // null),
                                channel: $channel,
                                stream: $stream,
                                url: $url
                            },
                            sources: $sources,
                            ports: $ports,
                            observed_paths: $observed,
                            rtsp_bruteforce: $rtsp_bruteforce,
                            profile_matches: $profile_matches,
                            timestamp: $timestamp,
                            protocols: $protocols
                        }')
                    success=true
                    break 2
                fi
            done
        fi

        for rtsp_candidate in "${rtsp_candidates[@]}"; do
            channel=$(jq -r '.channel // "1"' <<<"$rtsp_candidate")
            stream=$(jq -r '.stream // "0"' <<<"$rtsp_candidate")
            template=$(jq -r '.template' <<<"$rtsp_candidate")
            port=$(jq -r '.port // 554' <<<"$rtsp_candidate")
            transport=$(jq -r '.transport // "tcp"' <<<"$rtsp_candidate")
            key="rtsp|$template|$port|$channel|$stream"
            if [[ -n ${attempted_rtsp[$key]+set} ]]; then
                continue
            fi
            attempted_rtsp[$key]=1
            url=$(render_template "$template" "$ip" "$cred_user" "$cred_pass" "$port" "$channel" "$stream")
            url=$(trim_auth_in_url "$url")
            snapshot_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_rtsp.jpg"
            log_file="$LOG_DIR/${ip//[^a-zA-Z0-9._-]/_}_rtsp.log"
            if attempt_rtsp_snapshot "$url" "$ip" "$snapshot_file" "$log_file"; then
                ascii_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_rtsp.txt"
                make_ascii_preview "$snapshot_file" "$ascii_file"
                timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                success_payload=$(jq -n \
                    --arg ip "$ip" \
                    --arg method "rtsp_stream" \
                    --arg origin "profile" \
                    --arg url "$url" \
                    --arg username "$cred_user" \
                    --arg password "$cred_pass" \
                    --arg vendor "$vendor" \
                    --arg model "$model" \
                    --arg matched_by "$matched_by" \
                    --arg snapshot "$snapshot_file" \
                    --arg ascii "$ascii_file" \
                    --arg transport "$transport" \
                    --arg timestamp "$timestamp" \
                    --arg attempt "$attempt" \
                    --arg channel "$channel" \
                    --arg stream "$stream" \
                    --arg port "$port" \
                    --arg protocol "rtsp" \
                    --argjson sources "$sources_json" \
                    --argjson ports "$ports_json" \
                    --argjson observed "$observed_paths_json" \
                    --argjson rtsp_bruteforce "$rtsp_bruteforce_json" \
                    --argjson profile_matches "$profile_matches_json" \
                    --argjson protocols "$protocols_json" \
                    '{
                        ip: $ip,
                        method: $method,
                        origin: $origin,
                        vendor: $vendor,
                        model: $model,
                        matched_by: $matched_by,
                        transport: $transport,
                        attempt_index: ($attempt | tonumber? // null),
                        credentials: {username: $username, password: $password},
                        artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                        url: $url,
                        request: {
                            protocol: $protocol,
                            origin: $origin,
                            transport: $transport,
                            port: ($port | tonumber? // null),
                            channel: $channel,
                            stream: $stream,
                            url: $url
                        },
                        sources: $sources,
                        ports: $ports,
                        observed_paths: $observed,
                        rtsp_bruteforce: $rtsp_bruteforce,
                        profile_matches: $profile_matches,
                        timestamp: $timestamp,
                        protocols: $protocols
                    }')
                success=true
                break 2
            fi
        done

        for discovered_url in "${brute_rtsp_hits[@]}"; do
            [[ -z $discovered_url ]] && continue
            key="rtsp|discovered|$discovered_url"
            if [[ -n ${attempted_rtsp[$key]+set} ]]; then
                continue
            fi
            attempted_rtsp[$key]=1
            url=$(apply_credentials_to_url "$discovered_url" "$cred_user" "$cred_pass")
            url=$(trim_auth_in_url "$url")
            suffix=$(printf '%s' "$discovered_url" | sha1sum | awk '{print $1}' | cut -c1-10)
            snapshot_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_rtsp_${suffix}.jpg"
            log_file="$LOG_DIR/${ip//[^a-zA-Z0-9._-]/_}_rtsp_${suffix}.log"
            if attempt_rtsp_snapshot "$url" "$ip" "$snapshot_file" "$log_file"; then
                ascii_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_rtsp_${suffix}.txt"
                make_ascii_preview "$snapshot_file" "$ascii_file"
                timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
                success_payload=$(jq -n \
                    --arg ip "$ip" \
                    --arg method "rtsp_stream" \
                    --arg origin "rtsp-bruteforce" \
                    --arg url "$url" \
                    --arg username "$cred_user" \
                    --arg password "$cred_pass" \
                    --arg vendor "$vendor" \
                    --arg model "$model" \
                    --arg matched_by "$matched_by" \
                    --arg snapshot "$snapshot_file" \
                    --arg ascii "$ascii_file" \
                    --arg timestamp "$timestamp" \
                    --arg discovered "$discovered_url" \
                    --arg attempt "$attempt" \
                    --arg protocol "rtsp" \
                    --arg transport "unknown" \
                    --arg channel "" \
                    --arg stream "" \
                    --arg port "" \
                    --argjson sources "$sources_json" \
                    --argjson ports "$ports_json" \
                    --argjson observed "$observed_paths_json" \
                    --argjson rtsp_bruteforce "$rtsp_bruteforce_json" \
                    --argjson profile_matches "$profile_matches_json" \
                    --argjson protocols "$protocols_json" \
                    '{
                        ip: $ip,
                        method: $method,
                        origin: $origin,
                        vendor: $vendor,
                        model: $model,
                        matched_by: $matched_by,
                        transport: $transport,
                        attempt_index: ($attempt | tonumber? // null),
                        credentials: {username: $username, password: $password},
                        artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                        url: $url,
                        discovered_url: $discovered,
                        request: {
                            protocol: $protocol,
                            origin: $origin,
                            transport: $transport,
                            port: ($port | tonumber? // null),
                            channel: ($channel | select(length > 0)),
                            stream: ($stream | select(length > 0)),
                            url: $url,
                            seed: $discovered
                        },
                        sources: $sources,
                        ports: $ports,
                        observed_paths: $observed,
                        rtsp_bruteforce: $rtsp_bruteforce,
                        profile_matches: $profile_matches,
                        timestamp: $timestamp,
                        protocols: $protocols
                    }')
                success=true
                break 2
            fi
        done

        [[ $attempt -ge $MAX_CREDENTIALS ]] && break
    done

    if [[ $success == true ]]; then
        printf '%s\n' "$success_payload" >> "$RESULTS_TMP"
    else
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        failure_payload=$(jq -n \
            --arg ip "$ip" \
            --arg vendor "$vendor" \
            --arg model "$model" \
            --arg matched_by "$matched_by" \
            --arg attempts "$attempt" \
            --arg timestamp "$timestamp" \
            --argjson protocols "$protocols_json" \
            --argjson sources "$sources_json" \
            --argjson ports "$ports_json" \
            --argjson observed "$observed_paths_json" \
            --argjson rtsp_bruteforce "$rtsp_bruteforce_json" \
            --argjson profile_matches "$profile_matches_json" \
            '{
                ip: $ip,
                success: false,
                vendor: $vendor,
                model: $model,
                matched_by: $matched_by,
                attempts: ($attempts|tonumber),
                attempt_index: ($attempts|tonumber),
                timestamp: $timestamp,
                protocols: $protocols,
                sources: $sources,
                ports: $ports,
                observed_paths: $observed,
                rtsp_bruteforce: $rtsp_bruteforce,
                profile_matches: $profile_matches
            }')
        printf '%s\n' "$failure_payload" >> "$RESULTS_TMP"
    fi

done < "$HOSTS_TMP"

if [[ -s "$RESULTS_TMP" ]]; then
    jq -s '.' "$RESULTS_TMP" > "$OUTPUT_JSON"
else
    echo '[]' > "$OUTPUT_JSON"
fi

exit 0
