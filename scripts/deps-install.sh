#!/usr/bin/env bash
#
# CamSniff- Automated IP camera reconnaissance toolkit
# By John Hauger Mitander <john@on1.no>
# Copyright 2025 John Hauger Mitander
#
# CamSniff is Licensed under the MIT License.
# deps-install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -z ${BLUE:=} ]]; then
    BLUE=""
    CYAN=""
    GREEN=""
    YELLOW=""
    RED=""
    RESET=""
fi

echo -e "${BLUE}Installing required dependencies...${RESET}"

log_file=$(mktemp /tmp/camsniff-install.XXXXXX.log)

spin='-\|/'

if command -v apt &> /dev/null; then
    echo -e "${CYAN}Updating package lists...${RESET}"
    apt update -qq &>> "$log_file"
    
    echo -e "${CYAN}Installing Dependencies...${RESET}"
    
    apt install -y python3 python3-venv python3-dev git build-essential cmake pkg-config nmap masscan tshark avahi-daemon avahi-utils libpcap-dev libchafa-dev chafa ffmpeg curl jq &>> "$log_file" &
    pid=$!
    
    i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${CYAN}[%c] Installing dependencies...${RESET}" "${spin:$i:1}"
        sleep 0.2
    done
    printf "\r%sDependencies installed successfully!%s                     \n" "$GREEN" "$RESET"
    
elif command -v yum &> /dev/null; then
    echo -e "${CYAN}Installing dependencies...${RESET}"
    
    yum install -y epel-release &>> "$log_file"
    yum install -y python3 git gcc gcc-c++ make cmake pkgconfig nmap masscan wireshark-cli avahi avahi-tools libpcap-devel ffmpeg curl jq &>> "$log_file" &
    pid=$!
    
    i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${CYAN}[%c] Installing dependencies...${RESET}" "${spin:$i:1}"
        sleep 0.2
    done
    printf "\r%sDependencies installed successfully!%s                     \n" "$GREEN" "$RESET"
    
elif command -v pacman &> /dev/null; then
    echo -e "${CYAN}Installing dependencies...${RESET}"
    
    pacman -S --noconfirm python git base-devel cmake pkgconf nmap masscan wireshark-cli avahi libpcap ffmpeg curl jq &>> "$log_file" &
    pid=$!
    
    i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % 4 ))
        printf "\r${CYAN}[%c] Installing dependencies...${RESET}" "${spin:$i:1}"
        sleep 0.2
    done
    printf "\r%sDependencies installed successfully!%s                     \n" "$GREEN" "$RESET"
    
else
    echo -e "${RED}Unsupported package manager. Please install required packages manually.${RESET}"
    exit 1
fi

echo -e "${CYAN}Setting up Python virtual environment...${RESET}"
VENV_DIR="$ROOT_DIR/venv"
python3 -m venv "$VENV_DIR" &>> "$log_file"
if [[ -f "$VENV_DIR/bin/activate" ]]; then
    source "$VENV_DIR/bin/activate"
else
    echo -e "${RED}Virtual environment activation script missing. Aborting.${RESET}"
    exit 1
fi
pip install --upgrade pip &>> "$log_file"
pip install -r "$SCRIPT_DIR/requirements.txt" &>> "$log_file"

for cmd in nmap masscan tshark avahi-browse ffmpeg curl jq chafa
do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}Failed to install $cmd. Please install it manually.${RESET}"
        echo -e "${YELLOW}Check the log file for details: ${log_file}${RESET}"
        exit 1
    fi
done

if ! command -v coap-client &> /dev/null; then
        echo -e "${CYAN}Building and installing libcoap (coap-client)...${RESET}"
        bash "$SCRIPT_DIR/build-coap.sh" &>> "$log_file"
        if ! command -v coap-client &> /dev/null; then
                echo -e "${RED}Failed to build and install coap-client. Please check the log file.${RESET}"
                echo -e "${YELLOW}Check the log file for details: ${log_file}${RESET}"
                exit 1
        fi
fi

echo -e "${GREEN}Setup complete! All required tools are installed.${RESET}"
if command -v deactivate >/dev/null 2>&1; then
    deactivate || true
fi
echo -e "${CYAN}Detailed install log:${RESET} ${log_file}"