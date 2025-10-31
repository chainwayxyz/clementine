#!/usr/bin/env bash
# Build all target platform and feature combinations
# Generates SHA256 checksums and creates a release manifest

set -e

# Configuration
PLATFORMS=("x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin")
VARIANTS=("" "-automation")
OUTPUT_DIR="./build-output"
MANIFEST_FILE="$OUTPUT_DIR/release-manifest.txt"

echo "============================================"
echo "Building All Clementine Targets"
echo "============================================"
echo ""

# Check if we're in the project root
if [ ! -f "flake.nix" ]; then
    echo "Error: flake.nix not found. Please run this script from the project root."
    exit 1
fi

# Check if nix is installed
if ! command -v nix &> /dev/null; then
    echo "Error: nix is not installed. Please install Nix first."
    echo "Visit: https://nixos.org/download.html"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Get git commit info for the manifest
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")
BUILD_DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Initialize manifest
cat > "$MANIFEST_FILE" <<EOF
Clementine Build Manifest
=========================

Build Date: $BUILD_DATE
Git Commit: $GIT_COMMIT
Git Tag: ${GIT_TAG:-"(no tag)"}

Platform Builds:
----------------

EOF

# Function to build a specific target
build_target() {
    local platform=$1
    local variant=$2
    local target_name="clementine-cli-${platform}${variant}"

    echo "Building: $target_name"
    echo "----------------------------------------"

    # Build the target
    if nix build ".#${target_name}" -o "$OUTPUT_DIR/result-${platform}${variant}"; then
        # Get the binary path
        local binary_path="$OUTPUT_DIR/result-${platform}${variant}/bin/clementine-cli"
        local output_binary="$OUTPUT_DIR/clementine-cli-${platform}${variant//-automation/-with-automation}"

        # Copy binary to output directory with clear naming
        cp "$binary_path" "$output_binary"

        # Generate checksum
        cd "$OUTPUT_DIR"
        sha256sum "clementine-cli-${platform}${variant//-automation/-with-automation}" > "clementine-cli-${platform}${variant//-automation/-with-automation}.sha256"
        cd - > /dev/null

        # Get file size
        local file_size=$(du -h "$output_binary" | cut -f1)

        # Read the checksum
        local checksum=$(cat "$OUTPUT_DIR/clementine-cli-${platform}${variant//-automation/-with-automation}.sha256" | cut -d' ' -f1)

        # Append to manifest
        cat >> "$MANIFEST_FILE" <<EOF
Target: $platform${variant}
  Binary: clementine-cli-${platform}${variant//-automation/-with-automation}
  Size: $file_size
  SHA256: $checksum

EOF

        echo "✓ Success"
        echo ""
        return 0
    else
        echo "✗ Failed to build $target_name"
        echo ""

        # Append failure to manifest
        cat >> "$MANIFEST_FILE" <<EOF
Target: $platform${variant}
  Status: BUILD FAILED

EOF
        return 1
    fi
}

# Track successes and failures
SUCCESS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

# Build all combinations
for platform in "${PLATFORMS[@]}"; do
    for variant in "${VARIANTS[@]}"; do
        TOTAL_COUNT=$((TOTAL_COUNT + 1))

        if build_target "$platform" "$variant"; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    done
done

# Add summary to manifest
cat >> "$MANIFEST_FILE" <<EOF

Build Summary:
--------------
Total Targets: $TOTAL_COUNT
Successful: $SUCCESS_COUNT
Failed: $FAIL_COUNT

EOF

echo "============================================"
echo "Build Summary"
echo "============================================"
echo "Total Targets: $TOTAL_COUNT"
echo "Successful: $SUCCESS_COUNT"
echo "Failed: $FAIL_COUNT"
echo ""
echo "Output Location: $OUTPUT_DIR"
echo "Manifest: $MANIFEST_FILE"
echo ""

if [ $FAIL_COUNT -gt 0 ]; then
    echo "⚠ Some builds failed. Check the output above for details."
    echo ""
    exit 1
fi

# List all built binaries
echo "Built Binaries:"
echo "----------------------------------------"
ls -lh "$OUTPUT_DIR"/clementine-cli-* 2>/dev/null | grep -v ".sha256" || true
echo ""

echo "✓ All builds completed successfully!"
echo ""
echo "Next steps:"
echo "  1. Review the manifest: cat $MANIFEST_FILE"
echo "  2. Test the binaries on target platforms"
echo "  3. Verify reproducibility by building again and comparing hashes"
echo "  4. Upload binaries and manifest for release"
echo ""
