#!/usr/bin/env bash
#
# https://github.com/John0n1/CamSniff
#
# Copyright (c) 2025 John Hauger Mitander
# License: MIT License https://opensource.org/license/MIT

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
VENV_DIR="$ROOT_DIR/venv"

# ANSI fallbacks if not provided by the caller
RED=${RED:-"\033[31m"}
GREEN=${GREEN:-"\033[32m"}
YELLOW=${YELLOW:-"\033[33m"}
CYAN=${CYAN:-"\033[36m"}
BLUE=${BLUE:-"\033[34m"}
RESET=${RESET:-"\033[0m"}

QUIET=false
LOG_FILE=$(mktemp /tmp/camsniff-install.XXXXXX.log)
PACKAGE_MANAGER=""

print_usage() {
    cat <<'USAGE'
Usage: deps-install.sh [--quiet]

Options:
  -q, --quiet    Suppress progress output (errors still print to stderr)
  -h, --help     Show this help message
USAGE
}

log_info() {
    [[ $QUIET == true ]] && return
    echo -e "$1"
}

log_success() {
    [[ $QUIET == true ]] && return
    echo -e "$1"
}

log_warn() {
    echo -e "$1" >&2
}

log_error() {
    echo -e "$1" >&2
}

fail_and_exit() {
    local message="$1"
    local code="${2:-1}"
    log_error "${RED}${message}${RESET}"
    log_warn "${YELLOW}Check the log file for details: ${LOG_FILE}${RESET}"
    exit "$code"
}

SPINNER_FRAMES='-\|/'
spinner_loop() {
    local pid=$1
    local message=$2
    local frame=0
    local frame_count=${#SPINNER_FRAMES}
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}[%c] %s...${RESET}" "${SPINNER_FRAMES:frame:1}" "$message"
        frame=$(((frame + 1) % frame_count))
        sleep 0.2
    done
    printf "\r%*s\r" 70 ""
}

wait_with_spinner() {
    local pid=$1
    local message=$2
    if [[ $QUIET == true ]]; then
        wait "$pid"
        return $?
    fi
    spinner_loop "$pid" "$message"
    wait "$pid"
}

run_apt_modernize_sources() {
    if command -v apt >/dev/null 2>&1; then
        apt modernize-sources -y &>>"$LOG_FILE" || true
    fi
}

start_mongodb_service() {
    if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet mongod 2>/dev/null; then
            systemctl enable --now mongod &>>"$LOG_FILE" || systemctl restart mongod &>>"$LOG_FILE" || true
        fi
    elif command -v service >/dev/null 2>&1; then
        service mongod start &>>"$LOG_FILE" || true
    fi
}

install_mongodb_from_tgz() {
    local distro_codename="${1:-trixie}"
    local arch_tag=""
    case "$(uname -m)" in
        x86_64|amd64)
            arch_tag="x86_64"
            ;;
        aarch64|arm64)
            arch_tag="aarch64"
            ;;
        *)
            log_warn "${YELLOW}Unsupported architecture $(uname -m) for MongoDB binary installation.${RESET}"
            return 1
            ;;
    esac

    local distro_tag=""
    case "${distro_codename}" in
        trixie|bookworm|testing|sid)
            distro_tag="debian12"
            ;;
        bullseye)
            distro_tag="debian11"
            ;;
        buster)
            distro_tag="debian10"
            ;;
        focal|jammy)
            distro_tag="ubuntu2204"
            ;;
        *)
            distro_tag="debian12"
            log_warn "${YELLOW}Using generic MongoDB binary for debian12; unrecognized codename '${distro_codename}'.${RESET}"
            ;;
    esac

    local version="7.0.14"
    local tgz_url="https://fastdl.mongodb.org/linux/mongodb-linux-${arch_tag}-${distro_tag}-${version}.tgz"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    if [[ ! -d $tmp_dir ]]; then
        log_warn "${YELLOW}Failed to allocate temp directory for MongoDB download.${RESET}"
        return 1
    fi

    log_info "${CYAN}Downloading MongoDB ${version} binaries...${RESET}"
    if ! curl -fsSL "$tgz_url" -o "$tmp_dir/mongodb.tgz"; then
        log_warn "${YELLOW}Unable to download MongoDB archive from ${tgz_url}.${RESET}"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! tar -xzf "$tmp_dir/mongodb.tgz" -C "$tmp_dir"; then
        log_warn "${YELLOW}Failed to extract MongoDB archive.${RESET}"
        rm -rf "$tmp_dir"
        return 1
    fi

    local extracted_dir
    extracted_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name 'mongodb-linux-*' | head -n1)
    if [[ -z $extracted_dir ]]; then
        log_warn "${YELLOW}MongoDB archive layout unexpected; aborting binary install.${RESET}"
        rm -rf "$tmp_dir"
        return 1
    fi

    local install_dir="/opt/mongodb-${version}"
    rm -rf "$install_dir"
    mkdir -p "$install_dir"
    if ! cp -a "$extracted_dir"/. "$install_dir"/; then
        log_warn "${YELLOW}Failed to stage MongoDB binaries into ${install_dir}.${RESET}"
        rm -rf "$tmp_dir"
        return 1
    fi

    ln -sfn "$install_dir" /opt/mongodb
    mkdir -p /usr/local/bin
    find /usr/local/bin -maxdepth 1 -type l -name 'mongo*' -delete
    for bin_path in "$install_dir"/bin/*; do
        bin_name=$(basename "$bin_path")
        ln -sfn "$bin_path" "/usr/local/bin/$bin_name"
    done

    if ! id -u mongodb >/dev/null 2>&1; then
        useradd --system --home /var/lib/mongodb --no-create-home --shell /usr/sbin/nologin mongodb &>>"$LOG_FILE" || true
    fi

    mkdir -p /var/lib/mongodb /var/log/mongodb
    chown -R mongodb:mongodb /var/lib/mongodb /var/log/mongodb

    local mongo_conf="/etc/mongod.conf"
    if [[ ! -f $mongo_conf ]]; then
        cat <<'EOF' >"$mongo_conf"
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  logAppend: true
processManagement:
  fork: false
net:
  bindIp: 127.0.0.1
  port: 27017
EOF
    fi

    local service_file="/etc/systemd/system/mongod.service"
    cat <<'EOF' >"$service_file"
[Unit]
Description=MongoDB Database Server (CamSniff)
After=network.target

[Service]
User=mongodb
Group=mongodb
ExecStart=/opt/mongodb/bin/mongod --config /etc/mongod.conf
Restart=on-failure
RuntimeDirectory=mongodb
RuntimeDirectoryMode=0755
LimitNOFILE=64000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload &>>"$LOG_FILE" || true
    systemctl enable mongod &>>"$LOG_FILE" || true

    rm -rf "$tmp_dir"

    start_mongodb_service

    if ! command -v mongod >/dev/null 2>&1; then
        log_warn "${YELLOW}MongoDB binary installation completed but mongod was not detected in PATH.${RESET}"
        return 1
    fi

    return 0
}

ensure_mongodb_apt() {
    if command -v mongod >/dev/null 2>&1; then
        start_mongodb_service
        return
    fi

    local codename=""
    if [[ -r /etc/os-release ]]; then
        codename=$(grep -E '^VERSION_CODENAME=' /etc/os-release | cut -d'=' -f2)
    fi
    if [[ -z $codename ]]; then
        codename=$(lsb_release -sc 2>/dev/null || true)
    fi
    if [[ -z $codename ]]; then
        log_warn "${YELLOW}Unable to determine distribution codename; skipping MongoDB repo setup.${RESET}"
        return
    fi

    local repo_codename="$codename"
    local repo_supported=true
    case "$codename" in
        trixie|testing|sid)
            repo_supported=false
            log_warn "${YELLOW}MongoDB upstream repo does not support '${codename}'. Skipping upstream repository configuration.${RESET}"
            ;;
    esac

    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    local repo_version="7.0"
    local keyring="/usr/share/keyrings/mongodb-server-${repo_version}.gpg"
    if [[ ! -f $keyring ]]; then
        curl -fsSL "https://pgp.mongodb.com/server-${repo_version}.asc" | gpg --dearmor -o "$keyring" &>>"$LOG_FILE" || {
            log_warn "${YELLOW}Failed to import MongoDB GPG key; MongoDB will not be installed automatically.${RESET}"
            return
        }
    fi

    local repo_file="/etc/apt/sources.list.d/mongodb-org-${repo_version}.list"
    rm -f "${repo_file}" 2>/dev/null || true

    if [[ $repo_supported == true ]]; then
        cat <<EOF >"${repo_file}"
deb [ signed-by=${keyring} arch=${arch} ] https://repo.mongodb.org/apt/debian ${repo_codename}/mongodb-org/${repo_version} main
EOF
        run_apt_modernize_sources
        if ! apt-get update -qq &>>"$LOG_FILE"; then
            log_warn "${YELLOW}Failed to refresh apt after adding MongoDB repo. Removing repository entry.${RESET}"
            rm -f "${repo_file}"
            repo_supported=false
            run_apt_modernize_sources
            apt-get update -qq &>>"$LOG_FILE" || true
        fi
    else
        run_apt_modernize_sources
        apt-get update -qq &>>"$LOG_FILE" || true
    fi

    if [[ $repo_supported == true ]]; then
        if apt-get install -y -q mongodb-org &>>"$LOG_FILE"; then
            start_mongodb_service
            return
        fi
        log_warn "${YELLOW}MongoDB installation via mongodb-org failed; attempting fallback package.${RESET}"
        if apt-get install -y -q mongodb &>>"$LOG_FILE"; then
            start_mongodb_service
            return
        fi
        log_warn "${YELLOW}MongoDB fallback package installation failed; removing repository entry.${RESET}"
        rm -f "${repo_file}"
    fi

    if apt-get install -y -q mongodb &>>"$LOG_FILE"; then
        start_mongodb_service
        return
    fi

    log_warn "${YELLOW}MongoDB packages unavailable; attempting manual binary installation.${RESET}"
    if install_mongodb_from_tgz "$codename"; then
        return
    fi

    log_warn "${YELLOW}MongoDB manual installation failed.${RESET}"
}

ensure_mongodb_yum() {
    if command -v mongod >/dev/null 2>&1; then
        start_mongodb_service
        return
    fi

    curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg --dearmor -o /etc/pki/rpm-gpg/RPM-GPG-KEY-mongodb-server-7.0 &>>"$LOG_FILE" || true
    cat <<'EOF' >/etc/yum.repos.d/mongodb-org-7.0.repo
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/7.0/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/server-7.0.asc
EOF

    yum install -y mongodb-org &>>"$LOG_FILE" || yum install -y mongodb &>>"$LOG_FILE" || log_warn "${YELLOW}MongoDB installation failed on yum-based system.${RESET}"
    start_mongodb_service
}

ensure_mongodb_pacman() {
    if command -v mongod >/dev/null 2>&1; then
        start_mongodb_service
        return
    fi

    if ! pacman -S --noconfirm mongodb &>>"$LOG_FILE"; then
        log_warn "${YELLOW}MongoDB is not available in the default pacman repositories.${RESET}"
        return
    fi
    start_mongodb_service
}

ensure_mongodb() {
    case "$PACKAGE_MANAGER" in
        apt)
            ensure_mongodb_apt
            ;;
        yum)
            ensure_mongodb_yum
            ;;
        pacman)
            ensure_mongodb_pacman
            ;;
        *)
            if command -v mongod >/dev/null 2>&1; then
                start_mongodb_service
            else
                log_warn "${YELLOW}Automatic MongoDB provisioning is not supported on this platform.${RESET}"
            fi
            ;;
    esac
}

download_dbip_dataset() {
    local edition="$1"
    local destination="$2"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    if [[ ! -d $tmp_dir ]]; then
        log_warn "${YELLOW}Unable to stage temporary directory for ${edition} GeoIP download.${RESET}"
        return 1
    fi

    local success=false
    local offset
    for offset in 0 1 2; do
        local month
        month=$(date -u -d "${offset} month ago" +%Y-%m 2>/dev/null || date -u +%Y-%m)
        local url="https://download.db-ip.com/free/dbip-${edition}-lite-${month}.mmdb.gz"
        local archive="$tmp_dir/dbip-${edition}.mmdb.gz"
        if curl -fsSL "$url" -o "$archive"; then
            if gunzip -c "$archive" >"$tmp_dir/dbip-${edition}.mmdb"; then
                mv "$tmp_dir/dbip-${edition}.mmdb" "$destination"
                echo "$month" >"${destination}.version"
                success=true
                break
            fi
        fi
    done

    rm -rf "$tmp_dir"

    if [[ $success == true ]]; then
        log_success "${GREEN}GeoIP ${edition^} database refreshed.${RESET}"
        return 0
    fi

    log_warn "${YELLOW}Failed to download DB-IP ${edition} dataset.${RESET}"
    return 1
}

ensure_geoip_databases() {
    local geoip_dir="$ROOT_DIR/share/geoip"
    mkdir -p "$geoip_dir"

    local city_db="$geoip_dir/dbip-city-lite.mmdb"
    local asn_db="$geoip_dir/dbip-asn-lite.mmdb"

    local refresh_needed=false
    if [[ ! -f $city_db || $(find "$city_db" -mtime +30 -print -quit 2>/dev/null) ]]; then
        refresh_needed=true
    fi
    if [[ ! -f $asn_db || $(find "$asn_db" -mtime +30 -print -quit 2>/dev/null) ]]; then
        refresh_needed=true
    fi

    if [[ $refresh_needed == false ]]; then
        return
    fi

    log_info "${CYAN}Refreshing GeoIP datasets (DB-IP lite)…${RESET}"
    download_dbip_dataset "city" "$city_db" || true
    download_dbip_dataset "asn" "$asn_db" || true
}

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        export DEBCONF_NONINTERACTIVE_SEEN=true
        export APT_LISTCHANGES_FRONTEND=none

        PACKAGE_MANAGER="apt"

        log_info "${CYAN}Updating package lists...${RESET}"
        run_apt_modernize_sources
        if ! apt-get update -qq &>>"$LOG_FILE"; then
            local mongo_repo_file="/etc/apt/sources.list.d/mongodb-org-7.0.list"
            if [[ -f $mongo_repo_file ]]; then
                log_warn "${YELLOW}Initial apt update failed; removing stale MongoDB repository entry and retrying.${RESET}"
                rm -f "$mongo_repo_file"
                run_apt_modernize_sources
                if ! apt-get update -qq &>>"$LOG_FILE"; then
                    fail_and_exit "Failed to update package lists after cleaning MongoDB repository configuration."
                fi
            else
                fail_and_exit "Failed to update package lists."
            fi
        fi

        log_info "${CYAN}Installing dependencies...${RESET}"
        apt-get install -y -q python3 python3-venv python3-dev git build-essential cmake pkg-config nmap masscan tshark avahi-daemon avahi-utils libpcap-dev libchafa-dev chafa ffmpeg curl jq gnupg &>>"$LOG_FILE" &
        local pid=$!
        wait_with_spinner "$pid" "Installing dependencies" || fail_and_exit "Failed to install package dependencies."
        log_success "${GREEN}Dependencies installed successfully!${RESET}"
        return
    fi

    if command -v yum >/dev/null 2>&1; then
        log_info "${CYAN}Installing dependencies...${RESET}"
        PACKAGE_MANAGER="yum"
        yum install -y epel-release &>>"$LOG_FILE"
        yum install -y python3 git gcc gcc-c++ make cmake pkgconfig nmap masscan wireshark-cli avahi avahi-tools libpcap-devel ffmpeg curl jq &>>"$LOG_FILE" &
        local pid=$!
        wait_with_spinner "$pid" "Installing dependencies" || fail_and_exit "Failed to install package dependencies."
        log_success "${GREEN}Dependencies installed successfully!${RESET}"
        return
    fi

    if command -v pacman >/dev/null 2>&1; then
        log_info "${CYAN}Installing dependencies...${RESET}"
        PACKAGE_MANAGER="pacman"
        pacman -S --noconfirm python git base-devel cmake pkgconf nmap masscan wireshark-cli avahi libpcap ffmpeg curl jq &>>"$LOG_FILE" &
        local pid=$!
        wait_with_spinner "$pid" "Installing dependencies" || fail_and_exit "Failed to install package dependencies."
        log_success "${GREEN}Dependencies installed successfully!${RESET}"
        return
    fi

    fail_and_exit "Unsupported package manager. Please install required packages manually."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

log_info "${BLUE}Installing required dependencies...${RESET}"
install_packages

if [[ ${CAM_REQUIRE_IVRE:-false} == true || ${CAM_REQUIRE_IVRE:-false} == "true" ]]; then
    log_info "${CYAN}Ensuring MongoDB is installed for IVRE integration...${RESET}"
    ensure_mongodb
    log_info "${CYAN}Ensuring GeoIP datasets are available for IVRE integration...${RESET}"
    ensure_geoip_databases
fi

log_info "${CYAN}Setting up Python virtual environment...${RESET}"
python3 -m venv "$VENV_DIR" &>>"$LOG_FILE"
if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
    fail_and_exit "Virtual environment activation script missing."
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

pip install --upgrade pip &>>"$LOG_FILE"
if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    pip install -r "$SCRIPT_DIR/requirements.txt" &>>"$LOG_FILE"
fi

required_cmds=(
    nmap
    masscan
    tshark
    avahi-browse
    ffmpeg
    curl
    jq
    chafa
)

for cmd in "${required_cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        fail_and_exit "Failed to install $cmd. Please install it manually."
    fi
done

if ! command -v coap-client >/dev/null 2>&1; then
    log_info "${CYAN}Building and installing libcoap (coap-client)...${RESET}"
    bash "$SCRIPT_DIR/build-coap.sh" &>>"$LOG_FILE" &
    wait_with_spinner $! "Building coap-client" || fail_and_exit "Failed to build and install coap-client."
    if ! command -v coap-client >/dev/null 2>&1; then
        fail_and_exit "coap-client is still missing after build."
    fi
fi

log_success "${GREEN}Setup complete! All required tools are installed.${RESET}"

if command -v deactivate >/dev/null 2>&1; then
    deactivate || true
fi

if [[ -n ${CAM_INSTALL_LOG_EXPORT:-} ]]; then
    printf '%s\n' "$LOG_FILE" >"$CAM_INSTALL_LOG_EXPORT"
fi

log_info "${CYAN}Detailed install log:${RESET} ${LOG_FILE}"
