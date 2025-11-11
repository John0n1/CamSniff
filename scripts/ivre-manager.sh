#!/usr/bin/env bash
#
# Copyright 2025 John Hauger Mitander
# Licensed under the MIT License
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_ROOT="$ROOT_DIR/dev/results"
IVRE_SYNC="$SCRIPT_DIR/ivre-sync.py"
PATHS_FILE="$ROOT_DIR/data/paths.csv"
VENV_DIR="$ROOT_DIR/venv"
GEOIP_DIR="$ROOT_DIR/share/geoip"
PYTHON_BIN="${VENV_DIR}/bin/python3"
IVRE_CLI="${VENV_DIR}/bin/ivre"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

QUIET_MODE=false

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    [[ $QUIET_MODE == false ]] && echo -e "${CYAN}$*${RESET}" >&2
}

log_success() {
    [[ $QUIET_MODE == false ]] && echo -e "${GREEN}$*${RESET}" >&2
}

log_warn() {
    echo -e "${YELLOW}$*${RESET}" >&2
}

log_error() {
    echo -e "${RED}$*${RESET}" >&2
}

print_banner() {
    [[ $QUIET_MODE == true ]] && return
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              CamSniff IVRE Integration Manager                 ║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# ============================================================================
# SETUP FUNCTIONS
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Error: IVRE setup requires root privileges (use sudo)"
        return 1
    fi
    return 0
}

check_mongodb() {
    if command -v mongod >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

check_mongodb_running() {
    if pgrep -x mongod >/dev/null 2>&1; then
        return 0
    fi
    if mongosh --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
        return 0
    fi
    if mongo --eval "db.adminCommand('ping')" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

start_mongodb() {
    if check_mongodb_running; then
        return 0
    fi
    
    log_info "Starting MongoDB..."
    
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start mongod >/dev/null 2>&1 || true
        sleep 2
        if check_mongodb_running; then
            log_success "✓ MongoDB started"
            return 0
        fi
    fi
    
    log_warn "Could not start MongoDB automatically"
    return 1
}

install_mongodb_silent() {
    log_info "Installing MongoDB..."
    
    if [[ -f /etc/debian_version ]]; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq gnupg curl wget ca-certificates lsb-release >/dev/null 2>&1
        
        curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc 2>/dev/null | \
            gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor 2>/dev/null || true
        
        echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/7.0 multiverse" | \
            tee /etc/apt/sources.list.d/mongodb-org-7.0.list >/dev/null
        
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq mongodb-org >/dev/null 2>&1
        
    elif [[ -f /etc/redhat-release ]]; then
        cat > /etc/yum.repos.d/mongodb-org-7.0.repo <<'EOREPO'
[mongodb-org-7.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-7.0.asc
EOREPO
        yum install -y mongodb-org >/dev/null 2>&1
    else
        return 1
    fi
    
    log_success "✓ MongoDB installed"
    return 0
}

setup_python_venv() {
    if [[ -d "$VENV_DIR" ]] && [[ -x "$PYTHON_BIN" ]]; then
        return 0
    fi
    
    log_info "Setting up Python virtual environment..."
    
    if [[ -f /etc/debian_version ]]; then
        apt-get install -y -qq python3-venv python3-pip python3-dev >/dev/null 2>&1
    elif [[ -f /etc/redhat-release ]]; then
        yum install -y python3-virtualenv python3-pip python3-devel >/dev/null 2>&1
    fi
    
    python3 -m venv "$VENV_DIR" >/dev/null 2>&1
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    pip install --quiet --upgrade pip setuptools wheel >/dev/null 2>&1
    
    log_success "✓ Python environment ready"
    return 0
}

install_ivre() {
    if [[ -x "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c "import ivre" 2>/dev/null; then
        return 0
    fi
    
    log_info "Installing IVRE..."
    
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    pip install --quiet ivre pymongo >/dev/null 2>&1
    
    if "$PYTHON_BIN" -c "import ivre" 2>/dev/null; then
        log_success "✓ IVRE installed"
        return 0
    fi
    
    return 1
}

initialize_ivre_databases() {
    log_info "Initializing IVRE databases..."
    
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    
    export IVRE_GEOIP_CITY_DB="$GEOIP_DIR/dbip-city-lite.mmdb"
    export IVRE_GEOIP_ASN_DB="$GEOIP_DIR/dbip-asn-lite.mmdb"
    
    ivre ipinfo --init >/dev/null 2>&1 || true
    ivre scancli --init >/dev/null 2>&1 || true
    ivre scancli --ensure-indexes >/dev/null 2>&1 || true
    
    log_success "✓ IVRE databases initialized"
}

auto_setup_ivre() {
    if ! check_root; then
        log_warn "Skipping automatic IVRE setup (requires root)"
        return 1
    fi
    
    # Check MongoDB
    if ! check_mongodb; then
        if ! install_mongodb_silent; then
            log_error "Failed to install MongoDB"
            return 1
        fi
    fi
    
    # Start MongoDB
    if ! start_mongodb; then
        log_error "MongoDB is not running"
        return 1
    fi
    
    # Setup Python environment
    if ! setup_python_venv; then
        log_error "Failed to setup Python environment"
        return 1
    fi
    
    # Install IVRE
    if ! install_ivre; then
        log_error "Failed to install IVRE"
        return 1
    fi
    
    # Initialize databases
    initialize_ivre_databases
    
    log_success "✓ IVRE setup complete"
    return 0
}

# ============================================================================
# INGESTION FUNCTIONS
# ============================================================================

ingest_single_run() {
    local discovery_json="$1"
    local run_dir
    run_dir=$(dirname "$discovery_json")
    
    local credentials_json="$run_dir/credentials.json"
    local log_dir="$run_dir/logs"
    local ivre_log="$log_dir/ivre-sync.log"
    
    mkdir -p "$log_dir"
    
    # Extract metadata
    local mode network timestamp
    if command -v jq >/dev/null 2>&1; then
        mode=$(jq -r '.metadata.mode // "unknown"' "$discovery_json" 2>/dev/null || echo "unknown")
        network=$(jq -r '.metadata.network // "unknown"' "$discovery_json" 2>/dev/null || echo "unknown")
        timestamp=$(jq -r '.metadata.generated_at // ""' "$discovery_json" 2>/dev/null || echo "")
    else
        mode="unknown"
        network="unknown"
        timestamp=""
    fi
    
    if [[ -z "$timestamp" ]]; then
        local run_dir_name
        run_dir_name=$(basename "$run_dir")
        if [[ "$run_dir_name" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
            timestamp="$run_dir_name"
        else
            timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
        fi
    fi
    
    # Build sync command
    local sync_args=(
        --input "$discovery_json"
        --mode "$mode"
        --network "$network"
        --run-dir "$run_dir"
        --timestamp "$timestamp"
        --log "$ivre_log"
    )
    
    if [[ -f "$credentials_json" ]]; then
        sync_args+=(--credentials "$credentials_json")
    fi
    
    if [[ -f "$PATHS_FILE" ]]; then
        sync_args+=(--paths-csv "$PATHS_FILE")
    fi
    
    if "$PYTHON_BIN" "$IVRE_SYNC" "${sync_args[@]}" >>"$ivre_log" 2>&1; then
        date -u +%Y-%m-%dT%H:%M:%SZ > "$run_dir/.ivre-ingested"
        return 0
    else
        return 1
    fi
}

bulk_ingest_all() {
    if [[ ! -d "$RESULTS_ROOT" ]]; then
        log_warn "No results directory found"
        return 0
    fi
    
    local discovery_files
    discovery_files=$(find "$RESULTS_ROOT" -mindepth 2 -maxdepth 2 -name "discovery.json" -type f 2>/dev/null | sort)
    
    if [[ -z "$discovery_files" ]]; then
        log_info "No discovery files found to ingest"
        return 0
    fi
    
    local total=0
    local success=0
    local skipped=0
    
    while IFS= read -r discovery_json; do
        local run_dir
        run_dir=$(dirname "$discovery_json")
        
        # Skip if already ingested
        if [[ -f "$run_dir/.ivre-ingested" ]]; then
            ((skipped++)) || true
            continue
        fi
        
        ((total++)) || true
        
        if ingest_single_run "$discovery_json"; then
            ((success++)) || true
        fi
    done <<< "$discovery_files"
    
    if [[ $total -gt 0 ]]; then
        log_success "✓ Ingested $success/$total new runs ($skipped already ingested)"
    fi
}

# ============================================================================
# QUERY FUNCTIONS
# ============================================================================

query_summary() {
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    
    local total
    total=$("$IVRE_CLI" scancli --category camsniff --count 2>/dev/null || echo "0")
    
    echo "Total CamSniff hosts: $total"
    
    local creds
    creds=$("$IVRE_CLI" scancli --category credentials-found --count 2>/dev/null || echo "0")
    echo "Hosts with credentials: $creds"
}

query_export_json() {
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    "$IVRE_CLI" scancli --category camsniff --json 2>/dev/null
}

query_export_csv() {
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    echo "IP,MAC,Vendor,Model,Ports,Credentials,Protocols"
    "$IVRE_CLI" scancli --category camsniff --json 2>/dev/null | \
        "$PYTHON_BIN" -c '
import sys
import json

for line in sys.stdin:
    try:
        doc = json.loads(line)
        ip = doc.get("addr", "")
        mac = ""
        vendor = "Unknown"
        model = "Unknown"
        has_creds = "credentials-found" in doc.get("categories", [])
        
        for addr in doc.get("addresses", []):
            if addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                break
        
        ports = []
        for port_info in doc.get("ports", []):
            port = port_info.get("port", -1)
            if port > 0:
                ports.append(str(port))
        
        protocols = []
        for port_info in doc.get("ports", []):
            for script in port_info.get("scripts", []):
                if script.get("id") == "camsniff-vendor":
                    vendor_data = script.get("camsniff-vendor", {})
                    vendor = vendor_data.get("company", "Unknown")
                    model = vendor_data.get("model", "Unknown")
                elif script.get("id") == "camsniff-protocols":
                    proto_list = script.get("camsniff-protocols", [])
                    for proto in proto_list:
                        protocols.append(proto.get("protocol", ""))
        
        print(f"{ip},{mac},{vendor},{model},{\";\".join(ports)},{has_creds},{\";\".join(set(protocols))}")
    except:
        pass
'
}

# ============================================================================
# MAIN COMMAND DISPATCHER
# ============================================================================

print_usage() {
    cat <<'EOF'
Usage: ivre-manager.sh <command> [options]

Commands:
  setup                Manually install and configure IVRE (requires root)
  auto-setup           Automatic silent setup (used by camsniff.sh)
  ingest <file>        Ingest a specific discovery.json file
  bulk-ingest          Ingest all historical discovery.json files
  summary              Show summary statistics
  export <format>      Export results (json or csv)
  check                Check if IVRE is ready

Options:
  --quiet              Suppress informational output
  -h, --help           Display this help message

Examples:
  # Automatic setup (called by camsniff.sh --extra ivre)
  sudo ivre-manager.sh auto-setup

  # Manual setup
  sudo ivre-manager.sh setup

  # Ingest specific run
  ivre-manager.sh ingest dev/results/20251010T215139Z/discovery.json

  # Bulk ingest all runs
  ivre-manager.sh bulk-ingest

  # Export data
  ivre-manager.sh export json > cameras.json
  ivre-manager.sh export csv > cameras.csv

EOF
}

main() {
    if [[ $# -eq 0 ]]; then
        print_usage
        exit 0
    fi
    
    local command="$1"
    shift
    
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                break
                ;;
        esac
    done
    
    case "$command" in
        setup)
            print_banner
            check_root || exit 1
            auto_setup_ivre || exit 1
            ;;
        
        auto-setup)
            QUIET_MODE=true
            if auto_setup_ivre; then
                log_success "✓ IVRE ready"
                exit 0
            else
                log_error "✗ IVRE setup failed"
                exit 1
            fi
            ;;
        
        check)
            if [[ -x "$PYTHON_BIN" ]] && "$PYTHON_BIN" -c "import ivre" 2>/dev/null; then
                if check_mongodb_running; then
                    echo "ready"
                    exit 0
                else
                    echo "mongodb-not-running"
                    exit 1
                fi
            else
                echo "not-installed"
                exit 1
            fi
            ;;
        
        ingest)
            if [[ $# -eq 0 ]]; then
                log_error "Error: discovery.json file required"
                exit 1
            fi
            
            local discovery_file="$1"
            if [[ ! -f "$discovery_file" ]]; then
                log_error "Error: File not found: $discovery_file"
                exit 1
            fi
            
            if ingest_single_run "$discovery_file"; then
                log_success "✓ Ingested successfully"
            else
                log_error "✗ Ingestion failed"
                exit 1
            fi
            ;;
        
        bulk-ingest)
            print_banner
            bulk_ingest_all
            ;;
        
        summary)
            query_summary
            ;;
        
        export)
            if [[ $# -eq 0 ]]; then
                log_error "Error: format required (json or csv)"
                exit 1
            fi
            
            case "$1" in
                json)
                    query_export_json
                    ;;
                csv)
                    query_export_csv
                    ;;
                *)
                    log_error "Unknown format: $1"
                    exit 1
                    ;;
            esac
            ;;
        
        -h|--help)
            print_usage
            ;;
        
        *)
            log_error "Unknown command: $command"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
