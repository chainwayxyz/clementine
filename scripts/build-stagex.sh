#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Reproducible Build Script for Clementine Core
#
# This script builds clementine-core using StageX for bit-for-bit reproducible
# builds. Two developers building the same git commit with this script should
# produce binaries with identical SHA256 hashes.
#
# Requirements:
#   - Docker Buildx
#   - Git repository with committed changes
#   - Cargo.lock must be committed and up-to-date
#
# Output: ./dist/out/clementine-core
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Check for uncommitted changes that could affect reproducibility
if [[ -n $(git status --porcelain) ]]; then
    echo "  WARNING: You have uncommitted changes in your repository."
    echo "  For reproducible builds, commit all changes first."
    echo ""
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Get the commit timestamp for reproducible builds
COMMIT_TS=$(git log -1 --format=%ct)
COMMIT_SHA=$(git log -1 --format=%H)
echo "============================================="
echo "Reproducible Build Configuration"
echo "============================================="
echo "Commit SHA:          $COMMIT_SHA"
echo "SOURCE_DATE_EPOCH:   $COMMIT_TS"
echo "Target:              x86_64-unknown-linux-musl"
echo "Bitcoin Network:     mainnet"
echo "RISC0 Reproducible:  enabled"
echo "============================================="
echo ""

# Target architecture
TARGET=x86_64-unknown-linux-musl

# Output directory
OUTPUT_DIR="./dist"

# Clean previous build artifacts to ensure fresh build
if [ -d "$OUTPUT_DIR" ]; then
    echo "Cleaning previous build artifacts..."
    rm -rf "$OUTPUT_DIR"
fi

echo "Starting build..."
echo ""

# Build the artifact
docker buildx build \
  --platform=linux/amd64 \
  --build-arg SOURCE_DATE_EPOCH="$COMMIT_TS" \
  --build-arg TARGET="$TARGET" \
  --target artifact \
  --progress=plain \
  -o type=local,dest="$OUTPUT_DIR" \
  -f scripts/docker/Dockerfile.stagex \
  .

BINARY_PATH="$OUTPUT_DIR/out/clementine-core"
BINARY_HASH=$(sha256sum "$BINARY_PATH" | awk '{print $1}')

echo ""
echo "============================================="
echo "✓ Build Complete!"
echo "============================================="
echo "Binary location: $BINARY_PATH"
echo "SHA256 hash:     $BINARY_HASH"
echo ""
echo "Build details:"
echo "  Size:      $(stat -c%s "$BINARY_PATH" 2>/dev/null || stat -f%z "$BINARY_PATH") bytes"
echo "  Type:      $(file -b "$BINARY_PATH")"
echo ""
echo "Reproducibility verification:"
echo "  1. Share the commit SHA with another developer"
echo "  2. Have them checkout: git checkout $COMMIT_SHA"
echo "  3. Have them run: ./scripts/build-stagex.sh"
echo "  4. Compare SHA256 hashes - they should match!"
echo ""
echo "To save this build hash:"
echo "  echo \"$BINARY_HASH  $COMMIT_SHA\" >> build-hashes.txt"
echo "============================================="
