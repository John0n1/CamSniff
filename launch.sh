#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

echo -e "${CYAN}CamSniff is a powerful tool designed to:${RESET}"
echo -e "${GREEN}- Discover and analyze network-connected cameras."
echo -e "- Perform RTSP, HTTP, CoAP, and RTMP scans."
echo -e "- Identify vulnerabilities and brute-force credentials."
echo -e "- Generate AI-based insights from camera streams.${RESET}"

____________________________________________________________________
cat << 'EOF'
.--------------. | .--------------. | .--------------. | .--------------. | .--------------. | .--------------. | .--------------. | .--------------. 
|     ______   | | |      __      | | | ____    ____ | | |    _______   | | | ____  _____  | | |     _____    | | |  _________   | | |  _________   |
|   .' ___  |  | | |     /  \     | | ||_   \  /   _|| | |   /  ___  |  | | ||_   \|_   _| | | |    |_   _|   | | | |_   ___  |  | | | |_   ___  |  |
|  / .'   \_|  | | |    / /\ \    | | |  |   \/   |  | | |  |  (__ \_|  | | |  |   \ | |   | | |      | |     | | |   | |_  \_|  | | |   | |_  \_|  |
|  | |         | | |   / ____ \   | | |  | |\  /| |  | | |   '.___`-.   | | |  | |\ \| |   | | |      | |     | | |   |  _|      | | |   |  _|      |
|  `.___.'\    | | | _/ /    \ \_ | | | _| |_\/_| |_ | | |  |`\____) |  | | | _| |_\   |_  | | |     _| |_    | | |  _| |_       | | |  _| |_       |
|   `._____.'  | | ||____|  |____|| | ||_____||_____|| | |  |_______.'  | | ||_____|\____| | | |    |_____|   | | | |_____|      | | | |_____|      |
|              | | |              | | |              | | |              | | |              | | |              | | |              | | |              |
'--------------' | '--------------' | '--------------' | '--------------' | '--------------' | '--------------' | '--------------' | '--------------'

EOF
echo -e "${YELLOW}CamSniff 5.15.25 – by @John0n1${RESET}"
echo -e "${YELLOW}What will happen:${RESET}"
echo -e "${CYAN}1.${RESET} Dependencies will be checked and installed if missing."
echo -e "${CYAN}2.${RESET} Network scanning will begin to identify active devices."
echo -e "   ${RED}- This can take some time depending on the network size (up to 15 minutes)."
echo -e "   - The scan is a very intensive process and may even affect the network.${RESET}"
echo -e "${CYAN}3.${RESET} Camera streams will be analyzed and displayed."
echo -e "${CYAN}4.${RESET} You can choose to start the scan or exit at any time (Ctrl+C)."
echo -e "   - This will clean up the environment and stop all processes."

echo -e "${YELLOW}Press 'Y' to start or 'N' to exit.${RESET}"

# Animation Function
loading_animation() {
  local msg="$1"
  local delay=0.1
  local frames=("|" "/" "-" "\\")
  echo -n "$msg"
  while :; do
    for frame in "${frames[@]}"; do
      printf "\r%s %s" "$msg" "$frame"
      sleep "$delay"
    done
  done
}

# Prompt user to start
while true; do
  read -rp "$(echo -e "${CYAN}Start CamSniff? (Y/N): ${RESET}")" yn
  case $yn in
    [Yy]*) 
      echo -e "${GREEN}Starting CamSniff...${RESET}"
      # Start animation in the background
      loading_animation "Preparing environment" &
      anim_pid=$!
      sleep 3  # Simulate preparation time
      kill "$anim_pid" >/dev/null 2>&1
      printf "\r\033[K"  # Clear the animation line
      exec "${BASH_SOURCE%/*}/camsniff.sh"
      ;;
    [Nn]*) 
      echo -e "${RED}Exiting. Goodbye!${RESET}"
      exit 0
      ;;
    *) 
      echo -e "${YELLOW}Please press 'Y' to start or 'N' to exit.${RESET}"
      ;;
  esac
done
