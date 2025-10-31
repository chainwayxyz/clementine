#!/usr/bin/env bash
# Verify that a build is reproducible by building twice and comparing hashes
# This script demonstrates that the same source produces identical binaries

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <target>"
    echo ""
    echo "Verify reproducibility of a Clementine build target."
    echo "This script builds the same target twice and compares the SHA256 hashes."
    echo ""
    echo "Common targets:"
    echo "  clementine-cli                      # Default build (no automation)"
    echo "  clementine-cli-automation           # With automation"
    echo "  clementine-cli-x86_64-linux         # Platform-specific"
    echo "  clementine-cli-x86_64-linux-automation"
    echo ""
    echo "Examples:"
    echo "  $0 clementine-cli"
    echo "  $0 clementine-cli-automation"
    echo ""
    exit 1
}

build_and_hash() {
    local target=$1
    local build_num=$2
    local result_link="result-verify-$build_num"

    echo -e "${BLUE}Building target: $target (build #$build_num)${NC}"

    # Remove old result if it exists
    rm -rf "$result_link"

    # Build
    if nix build ".#$target" -o "$result_link" 2>&1 | tee "/tmp/build-$build_num.log"; then
        # Get the binary path
        local binary_path="$result_link/bin/clementine-cli"

        if [ ! -f "$binary_path" ]; then
            echo -e "${RED}Error: Binary not found at $binary_path${NC}"
            return 1
        fi

        # Compute hash
        if command -v sha256sum &> /dev/null; then
            hash=$(sha256sum "$binary_path" | cut -d' ' -f1)
        elif command -v shasum &> /dev/null; then
            hash=$(shasum -a 256 "$binary_path" | cut -d' ' -f1)
        else
            echo -e "${RED}Error: No SHA256 tool found${NC}"
            return 1
        fi

        # Get file size
        size=$(du -h "$binary_path" | cut -f1)

        echo -e "${GREEN}✓ Build #$build_num complete${NC}"
        echo "  Hash: $hash"
        echo "  Size: $size"
        echo ""

        # Return the hash
        echo "$hash"
        return 0
    else
        echo -e "${RED}✗ Build #$build_num failed${NC}"
        echo "Check /tmp/build-$build_num.log for details"
        return 1
    fi
}

# Main script
if [ $# -ne 1 ]; then
    usage
fi

TARGET=$1

# Check if we're in the project root
if [ ! -f "flake.nix" ]; then
    echo -e "${RED}Error: flake.nix not found. Please run this script from the project root.${NC}"
    exit 1
fi

# Check if nix is installed
if ! command -v nix &> /dev/null; then
    echo -e "${RED}Error: nix is not installed.${NC}"
    echo "Visit: https://nixos.org/download.html"
    exit 1
fi

echo "============================================"
echo "Reproducible Build Verification"
echo "============================================"
echo ""
echo "Target: $TARGET"
echo "Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
echo "Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo ""
echo "This will build the target twice and compare hashes."
echo "For a truly reproducible build, hashes must match exactly."
echo ""

read -p "Continue? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Aborted."
    exit 0
fi

echo ""

# Build 1
echo "============================================"
echo "First Build"
echo "============================================"
echo ""

HASH1=$(build_and_hash "$TARGET" 1)
if [ $? -ne 0 ]; then
    echo -e "${RED}First build failed. Aborting.${NC}"
    exit 1
fi

# Small delay to ensure timestamp would be different if not reproducible
sleep 2

# Build 2
echo "============================================"
echo "Second Build"
echo "============================================"
echo ""

HASH2=$(build_and_hash "$TARGET" 2)
if [ $? -ne 0 ]; then
    echo -e "${RED}Second build failed. Aborting.${NC}"
    exit 1
fi

# Compare hashes
echo "============================================"
echo "Verification Result"
echo "============================================"
echo ""
echo "Build 1 hash: $HASH1"
echo "Build 2 hash: $HASH2"
echo ""

if [ "$HASH1" = "$HASH2" ]; then
    echo -e "${GREEN}✓ SUCCESS: Build is reproducible!${NC}"
    echo ""
    echo "The binary built from this source code is deterministic."
    echo "Anyone building from the same commit will get an identical binary."
    echo ""
    echo "SHA256: $HASH1"
    echo ""

    # Additional verification suggestions
    echo "Additional verification:"
    echo "  1. Build on a different machine and compare with this hash"
    echo "  2. Compare with published release hashes (if available)"
    echo "  3. Share this hash with other operators/verifiers for cross-verification"
    echo ""

    # Clean up
    rm -rf result-verify-1 result-verify-2
    rm -f /tmp/build-1.log /tmp/build-2.log

    exit 0
else
    echo -e "${RED}✗ FAILURE: Build is NOT reproducible${NC}"
    echo ""
    echo "The two builds produced different binaries!"
    echo "This should not happen with a proper reproducible build setup."
    echo ""
    echo "Possible causes:"
    echo "  1. Timestamps are not being normalized (SOURCE_DATE_EPOCH)"
    echo "  2. Random data is being included in the build"
    echo "  3. Build environment is not fully deterministic"
    echo "  4. Git worktree is dirty (uncommitted changes)"
    echo ""
    echo "Debugging steps:"
    echo "  1. Check git status: git status"
    echo "  2. Compare binaries: diff result-verify-1/bin/clementine-cli result-verify-2/bin/clementine-cli"
    echo "  3. Check build logs: diff /tmp/build-1.log /tmp/build-2.log"
    echo "  4. Review flake.nix for SOURCE_DATE_EPOCH and RUSTFLAGS settings"
    echo ""

    exit 1
fi
