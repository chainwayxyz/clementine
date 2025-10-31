#!/usr/bin/env bash
# Automatically compute hashes for git dependencies

set -e

echo "Computing hashes for git dependencies..."
echo ""

# Try to build and capture hash mismatches
nix build .#clementine-cli 2>&1 | tee /tmp/nix-hash-output.txt || true

# Extract the correct hashes from error messages
echo ""
echo "Extracting correct hashes from Nix output..."
echo ""

# Parse the output for hash mismatches
grep -E "got:|wanted:" /tmp/nix-hash-output.txt | while read line; do
    echo "$line"
done

echo ""
echo "Update flake.nix outputHashes with the 'got:' hashes shown above."
