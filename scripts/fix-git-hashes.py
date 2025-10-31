#!/usr/bin/env python3
"""
Automatically fix git dependency hashes in flake.nix
"""

import subprocess
import re
import sys

print("Fetching correct hashes for all git dependencies...")
print("This may take a few minutes...\n")

hashes = {}
max_iterations = 20  # Safety limit

for i in range(max_iterations):
    # Try to build
    result = subprocess.run(
        ["nix", "build", ".#clementine-cli"],
        capture_output=True,
        text=True,
        cwd="/Users/ozankaymak/developer/chainway/clementine"
    )

    output = result.stderr

    # Look for hash mismatch errors
    match = re.search(r'error: hash mismatch.*?\n.*?specified: (sha256-[A-Za-z0-9+/=]+)\n.*?got:\s+(sha256-[A-Za-z0-9+/=]+)', output, re.DOTALL)

    if match:
        specified_hash = match.group(1)
        correct_hash = match.group(2)

        # Find which dependency this is for
        dep_match = re.search(r'Cannot build.*?/nix/store/[a-z0-9]+-([a-zA-Z0-9_-]+)\.drv', output)
        if dep_match:
            dep_name = dep_match.group(1)
            print(f"Found hash for {dep_name}: {correct_hash}")
            hashes[specified_hash] = correct_hash

            # Update flake.nix
            with open('/Users/ozankaymak/developer/chainway/clementine/flake.nix', 'r') as f:
                content = f.read()

            # Replace the fake hash with the correct one
            content = content.replace(f'"{specified_hash}"', f'"{correct_hash}"')
            content = content.replace(f'= {specified_hash};', f'= "{correct_hash}";')

            with open('/Users/ozankaymak/developer/chainway/clementine/flake.nix', 'w') as f:
                f.write(content)
        else:
            print(f"Warning: Could not identify dependency name")
            print(f"Specified: {specified_hash}")
            print(f"Correct: {correct_hash}")
            break
    elif "hash mismatch" in output:
        print("Hash mismatch found but couldn't parse")
        print(output[:500])
        break
    elif "error:" in output and "Cannot build" in output:
        print("Build error (not hash related):")
        print(output[:1000])
        break
    else:
        print("\n✓ All hashes fixed! Build should now proceed.")
        sys.exit(0)

print(f"\nProcessed {len(hashes)} hash corrections")
print("Run 'nix build .#clementine-cli' to continue the build")
