#!/usr/bin/env bash
# Update git dependency hashes in flake.nix
# Run this script when you update git dependencies in Cargo.toml

set -e

echo "============================================"
echo "Updating Nix Flake Dependencies"
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

# Check if flakes are enabled
if ! nix flake --version &> /dev/null 2>&1; then
    echo "Error: Nix flakes are not enabled."
    echo "Add this to ~/.config/nix/nix.conf:"
    echo "  experimental-features = nix-command flakes"
    exit 1
fi

echo "Step 1: Updating flake.lock..."
echo "This will update all input dependencies to their latest versions."
echo ""

nix flake update

echo ""
echo "Step 2: Attempting a test build..."
echo "This will fetch all dependencies and may take a while on first run."
echo ""

# Try to build, this will fail if hashes need updating but will show the correct hash
if nix build .#clementine-cli --rebuild 2>&1 | tee /tmp/nix-build-output.txt; then
    echo ""
    echo "✓ Build succeeded! All hashes are up to date."
    echo ""
else
    echo ""
    echo "Build failed. This is expected if git dependency hashes need updating."
    echo ""
    echo "If you see hash mismatch errors in the output above, you'll need to:"
    echo "  1. Note the correct hash from the error message"
    echo "  2. Update the corresponding outputHashes in flake.nix"
    echo "  3. Run this script again"
    echo ""
    echo "Example error message:"
    echo "  got:    sha256-XXXX..."
    echo "  wanted: sha256-YYYY..."
    echo ""
    echo "Update flake.nix cargoLock.outputHashes with the 'got' hash."
    echo ""

    # Try to extract hash mismatches from the output
    if grep -q "hash mismatch" /tmp/nix-build-output.txt; then
        echo "Hash mismatches found:"
        grep -A2 "hash mismatch" /tmp/nix-build-output.txt | grep -E "got:|wanted:" || true
    fi

    exit 1
fi

# Clean up
rm -f /tmp/nix-build-output.txt

echo "============================================"
echo "Update Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Test the build with: nix build .#clementine-cli"
echo "  2. Test with automation: nix build .#clementine-cli-automation"
echo "  3. If successful, commit flake.lock changes"
echo ""
