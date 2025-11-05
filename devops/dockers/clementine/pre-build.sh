#!/bin/bash

# Usage: ./pre-build.sh <service_name> <network> <release> <platform>
# Example: ./pre-build.sh aggregator v0.5.0-rc.3 dev-net linux-amd64

set -euo pipefail

SERVICE="$1"
RELEASE="$2"
NETWORK="$3"
PLATFORM="$4"
SCRIPT_DIR="$(temp=$( realpath "$0"  ) && dirname "$temp")"
REPO="chainwayxyz/clementine"
BITVM_CACHE_BIN_DOWNLOAD_PATH="clementine/conf/bitvm_cache.bin"
BASE_URL="https://static.citrea.xyz"

# Validate service name
case "$SERVICE" in
  aggregator)
    AUTOMATION_SUFFIX="with-automation"
    ;;
  operator)
    AUTOMATION_SUFFIX="no-automation"
    ;;
  verifier)
    AUTOMATION_SUFFIX="with-automation"
    ;;
  *)
    echo "Unknown service name: $SERVICE (expected aggregator|operator|verifier)"
    exit 64  # EX_USAGE — bad command line argument
    ;;
esac

RELEASE_BINARY="${AUTOMATION_SUFFIX}-${PLATFORM}"
CA_PEM_DOWNLOAD_PATH="clementine/$SERVICE/certs/ca.pem"
SERVER_PEM_DOWNLOAD_PATH="clementine/$SERVICE/certs/server.pem"
AGGREGATOR_PEM_DOWNLOAD_PATH="clementine/$SERVICE/certs/aggregator.pem"
CLIENT_PEM_DOWNLOAD_PATH="clementine/$SERVICE/certs/client.pem"

## Check and Download Clementine-Core binary
cd "$SCRIPT_DIR"

download_binary() {
  local binary_name="$1"
  local binary_url="https://github.com/${REPO}/releases/download/${RELEASE}/${binary_name}-${RELEASE}-${RELEASE_BINARY}"

  echo "⬇️  Downloading binary from ${binary_url}"
  wget -q -O "$binary_name" "$binary_url"
  chmod +x "$binary_name"
  echo "✅ Downloaded and made executable: $binary_name"
}

# Example usage
download_binary "clementine-core"
download_binary "clementine-cli"

## Resolve Paths and Prepare Arguments
echo "Resolving paths for release: $RELEASE"
CA_PEM_FILENAME=$(basename "${CA_PEM_DOWNLOAD_PATH}")
SERVER_PEM_FILENAME=$(basename "${SERVER_PEM_DOWNLOAD_PATH}")
AGGREGATOR_PEM_FILENAME=$(basename "${AGGREGATOR_PEM_DOWNLOAD_PATH}")
CLIENT_PEM_FILENAME=$(basename "${CLIENT_PEM_DOWNLOAD_PATH}")
BITVM_CACHE_FILENAME=$(basename "${BITVM_CACHE_BIN_DOWNLOAD_PATH}")

echo "Downloading certificates and static files"
wget -O "$CA_PEM_FILENAME" "$BASE_URL/$NETWORK/$CA_PEM_DOWNLOAD_PATH"
wget -O "$SERVER_PEM_FILENAME" "$BASE_URL/$NETWORK/$SERVER_PEM_DOWNLOAD_PATH"
wget -O "$AGGREGATOR_PEM_FILENAME" "$BASE_URL/$NETWORK/$AGGREGATOR_PEM_DOWNLOAD_PATH"
wget -O "$CLIENT_PEM_FILENAME" "$BASE_URL/$NETWORK/$CLIENT_PEM_DOWNLOAD_PATH"
wget -O "$BITVM_CACHE_FILENAME" "$BASE_URL/$NETWORK/$BITVM_CACHE_BIN_DOWNLOAD_PATH"

## Create .build-args file in .env format
cat > "./.build-args" <<EOF
CA_PEM_PATH=$CA_PEM_FILENAME
SERVER_PEM_PATH=$SERVER_PEM_FILENAME
AGGREGATOR_PEM_PATH=$AGGREGATOR_PEM_FILENAME
CLIENT_PEM_PATH=$CLIENT_PEM_FILENAME
BITVM_CACHE_PATH=$BITVM_CACHE_FILENAME
DOCKER_APP_PATH=/srv/app
CLEMENTINE_CORE_PATH=clementine-core
CLEMENTINE_CLI_PATH=clementine-cli
PARAM=$SERVICE
EOF

chmod +x entrypoint.sh
