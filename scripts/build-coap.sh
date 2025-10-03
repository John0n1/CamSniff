#!/usr/bin/env bash
# Helper to build and install libcoap's coap-client binary for CamSniff.

set -euo pipefail

if [[ -z ${CYAN:=} ]]; then
    CYAN=""
    GREEN=""
    RED=""
    RESET=""
fi

REPO_URL=${COAP_REPO_URL:-https://github.com/obgm/libcoap.git}
PREFIX=${COAP_INSTALL_PREFIX:-/usr/local}
PREFIX_BIN="$PREFIX/bin"
BUILD_ROOT=$(mktemp -d /tmp/camsniff-libcoap.XXXXXX)
SRC_DIR="$BUILD_ROOT/src"
BUILD_DIR="$BUILD_ROOT/build"

cleanup() {
    rm -rf "$BUILD_ROOT"
}
trap cleanup EXIT

mkdir -p "$PREFIX_BIN"

echo -e "${CYAN}Building libcoap (coap-client)...${RESET}"

git clone --depth 1 "$REPO_URL" "$SRC_DIR" >/dev/null 2>&1
cmake -S "$SRC_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_DTLS=OFF \
    -DENABLE_SERVER_MODE=OFF \
    -DENABLE_CLIENT_MODE=ON \
    -DENABLE_PROXY_CODE=OFF \
    -DENABLE_EXAMPLES=ON \
    -DENABLE_DOCS=OFF \
    -DENABLE_TESTS=OFF \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" >/dev/null

cmake --build "$BUILD_DIR" --target coap-client -j"$(nproc)" >/dev/null
coap_binary=$(find "$BUILD_DIR" -type f -name coap-client -perm -u+x | head -n1 || true)
if [[ -z $coap_binary ]]; then
    echo -e "${RED}Unable to locate built coap-client binary.${RESET}" >&2
    exit 1
fi
install -m 0755 "$coap_binary" "$PREFIX_BIN/coap-client"

if ! command -v coap-client >/dev/null 2>&1; then
    echo -e "${RED}Failed to build and install coap-client.${RESET}" >&2
    exit 1
fi

echo -e "${GREEN}coap-client installed to ${PREFIX_BIN}/coap-client${RESET}"