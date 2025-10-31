#!/usr/bin/env bash
# Download and verify BitVM cache files
# Ensures cache file integrity before use

set -e

# Cache file URLs
PROD_CACHE_URL="https://static.testnet.citrea.xyz/common/bitvm_cache_v3.bin"
DEV_CACHE_URL="https://static.testnet.citrea.xyz/common/bitvm_cache_dev.bin"

# Expected hashes (to be updated - see docs/cache-hashes.md)
# TODO: Update these hashes after downloading the actual cache files
PROD_CACHE_HASH="TO_BE_COMPUTED"
DEV_CACHE_HASH="TO_BE_COMPUTED"

# Output files
PROD_CACHE_FILE="bitvm_cache.bin"
DEV_CACHE_FILE="bitvm_cache_dev.bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 [production|prod|dev|development]"
    echo ""
    echo "Download and verify BitVM cache files for Clementine."
    echo ""
    echo "Arguments:"
    echo "  production, prod    Download and verify production cache file"
    echo "  development, dev    Download and verify development cache file"
    echo ""
    echo "Examples:"
    echo "  $0 production       # Download production cache"
    echo "  $0 dev              # Download development cache"
    echo ""
    exit 1
}

download_file() {
    local url=$1
    local output=$2

    echo "Downloading from: $url"

    if command -v wget &> /dev/null; then
        wget -O "$output" "$url"
    elif command -v curl &> /dev/null; then
        curl -L -o "$output" "$url"
    else
        echo -e "${RED}Error: Neither wget nor curl is installed${NC}"
        echo "Please install wget or curl to download cache files"
        exit 1
    fi
}

verify_hash() {
    local file=$1
    local expected_hash=$2
    local mode=$3

    echo "Verifying SHA256 hash..."

    # Check if file exists
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: File not found: $file${NC}"
        return 1
    fi

    # Compute actual hash
    if command -v sha256sum &> /dev/null; then
        actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
    elif command -v shasum &> /dev/null; then
        actual_hash=$(shasum -a 256 "$file" | cut -d' ' -f1)
    else
        echo -e "${RED}Error: No SHA256 tool found (sha256sum or shasum)${NC}"
        return 1
    fi

    # Check if hash is still placeholder
    if [ "$expected_hash" = "TO_BE_COMPUTED" ]; then
        echo -e "${YELLOW}Warning: Expected hash is not set in this script${NC}"
        echo ""
        echo "Computed hash: $actual_hash"
        echo ""
        echo "Please update the expected hash in:"
        echo "  1. This script: scripts/verify-cache-hashes.sh"
        echo "  2. Documentation: docs/cache-hashes.md"
        echo ""
        echo "Then run this script again to verify."
        return 2
    fi

    # Compare hashes
    if [ "$actual_hash" = "$expected_hash" ]; then
        echo -e "${GREEN}✓ Hash verification successful!${NC}"
        echo "File: $file"
        echo "Hash: $actual_hash"
        return 0
    else
        echo -e "${RED}✗ Hash mismatch!${NC}"
        echo "File: $file"
        echo "Expected: $expected_hash"
        echo "Actual:   $actual_hash"
        echo ""
        echo "WARNING: The cache file may be corrupted or tampered with!"
        echo "Do NOT use this file. Try downloading again, or contact the Clementine team."
        return 1
    fi
}

process_cache() {
    local mode=$1
    local url=$2
    local output=$3
    local expected_hash=$4

    echo "============================================"
    echo "BitVM Cache Verification - ${mode^} Mode"
    echo "============================================"
    echo ""

    # Check if file already exists
    if [ -f "$output" ]; then
        echo "File already exists: $output"
        read -p "Download again? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Using existing file..."
        else
            echo "Downloading fresh copy..."
            rm -f "$output"
            download_file "$url" "$output"
        fi
    else
        echo "File not found, downloading..."
        download_file "$url" "$output"
    fi

    echo ""

    # Verify the hash
    if verify_hash "$output" "$expected_hash" "$mode"; then
        echo ""
        echo "Cache file is ready to use!"
        echo ""
        echo "Set environment variable:"
        echo "  export BITVM_CACHE_PATH=$(pwd)/$output"

        if [ "$mode" = "development" ]; then
            echo "  export RISC0_DEV_MODE=1"
        fi

        echo ""
        return 0
    else
        verify_result=$?
        echo ""

        if [ $verify_result -eq 2 ]; then
            # Hash not set - warning but not critical
            echo "You can still use the file, but verification is recommended."
            echo ""
            echo "To use this file:"
            echo "  export BITVM_CACHE_PATH=$(pwd)/$output"
            if [ "$mode" = "development" ]; then
                echo "  export RISC0_DEV_MODE=1"
            fi
            echo ""
            return 0
        else
            # Hash mismatch - critical error
            return 1
        fi
    fi
}

# Main script
if [ $# -ne 1 ]; then
    usage
fi

case "$1" in
    production|prod)
        process_cache "production" "$PROD_CACHE_URL" "$PROD_CACHE_FILE" "$PROD_CACHE_HASH"
        ;;
    development|dev)
        process_cache "development" "$DEV_CACHE_URL" "$DEV_CACHE_FILE" "$DEV_CACHE_HASH"
        ;;
    *)
        echo -e "${RED}Error: Invalid argument '$1'${NC}"
        echo ""
        usage
        ;;
esac
