# Reproducible Builds for Clementine

This document explains how to build Clementine binaries in a reproducible manner, ensuring that anyone can verify that the published binaries match the source code exactly.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Build Variants](#build-variants)
- [Building for Different Platforms](#building-for-different-platforms)
- [Verifying Reproducibility](#verifying-reproducibility)
- [Runtime Dependencies](#runtime-dependencies)
- [Using the Binaries](#using-the-binaries)
- [Troubleshooting](#troubleshooting)

## Overview

Reproducible builds ensure that the same source code always produces bit-for-bit identical binaries, regardless of who builds them or where they build. This is crucial for security, especially for bridge operators and verifiers who need to trust the software they're running.

### What Makes Clementine Builds Reproducible?

- **Nix**: Uses Nix flakes for fully deterministic build environments
- **Pinned Dependencies**: All dependencies (Rust toolchain, nixpkgs, crates) are pinned to specific versions/hashes
- **Deterministic Timestamps**: Uses `SOURCE_DATE_EPOCH=1` to normalize build timestamps
- **Consistent Rust Version**: Locked to Rust 1.88 as specified in `rust-toolchain.toml`
- **Pre-compiled Circuits**: RISC0 circuits are treated as pre-compiled artifacts
- **Verifiable Cache**: BitVM cache files have documented SHA256 hashes

## Prerequisites

### Install Nix

1. Install Nix with flakes support:

```bash
# On Linux/macOS
sh <(curl -L https://nixos.org/nix/install) --daemon

# Enable flakes (add to ~/.config/nix/nix.conf or /etc/nix/nix.conf)
experimental-features = nix-command flakes
```

2. Verify installation:

```bash
nix --version  # Should show nix (Nix) 2.18 or later
```

That's it! Nix will handle all other dependencies automatically.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/chainwayxyz/clementine
cd clementine

# Build the default variant (without automation)
nix build .#clementine-cli

# The binary will be in result/bin/
./result/bin/clementine-cli --version

# Build with automation feature
nix build .#clementine-cli-automation

# Check the SHA256 hash
cat result/bin/clementine-cli.sha256
```

## Build Variants

Clementine provides two build variants:

### 1. Without Automation (Default)

```bash
nix build .#clementine-cli
```

This variant requires manual intervention for:
- State transitions (must be triggered manually via CLI)
- Transaction submission (must be submitted manually)
- Best for: Verifiers who want full control and oversight

### 2. With Automation

```bash
nix build .#clementine-cli-automation
```

This variant includes:
- State Manager: Automatically fulfills duties of verifier/operator/aggregator
- Transaction Sender: Automatically manages and sends transactions to Bitcoin network
- Best for: Operators who want automated operations

### Which Variant Should I Use?

| Role | Recommended Variant | Reason |
|------|-------------------|---------|
| **Verifier** | Without automation | Maintain full control over signing operations |
| **Operator** | With automation | Automate transaction handling |
| **Aggregator** | With automation | Automate coordination tasks |
| **Testing/Development** | Either | Choose based on testing needs |

## Building for Different Platforms

The flake supports building for multiple platforms:

```bash
# Linux x86_64 (most common)
nix build .#clementine-cli-x86_64-linux
nix build .#clementine-cli-x86_64-linux-automation

# Linux ARM64 (for ARM servers)
nix build .#clementine-cli-aarch64-linux
nix build .#clementine-cli-aarch64-linux-automation

# macOS Intel
nix build .#clementine-cli-x86_64-darwin
nix build .#clementine-cli-x86_64-darwin-automation

# macOS Apple Silicon (M1/M2/M3)
nix build .#clementine-cli-aarch64-darwin
nix build .#clementine-cli-aarch64-darwin-automation
```

**Note**: Cross-compilation from one platform to another is supported by Nix.

## Verifying Reproducibility

To verify that builds are reproducible:

### Method 1: Build Twice Locally

```bash
# Build once
nix build .#clementine-cli
sha256sum result/bin/clementine-cli > hash1.txt

# Remove the result
rm result

# Build again
nix build .#clementine-cli
sha256sum result/bin/clementine-cli > hash2.txt

# Compare hashes - they should be identical
diff hash1.txt hash2.txt
```

### Method 2: Build on Different Machines

```bash
# On machine 1
nix build .#clementine-cli
sha256sum result/bin/clementine-cli
# Example output: abc123... result/bin/clementine-cli

# On machine 2 (different computer, same commit)
nix build .#clementine-cli
sha256sum result/bin/clementine-cli
# Should output: abc123... result/bin/clementine-cli (identical)
```

### Method 3: Compare with Published Hashes

Official releases include SHA256 hashes. You can verify your build matches:

```bash
# Build the specific release version
git checkout v0.5.0  # or whatever version
nix build .#clementine-cli

# Check hash
sha256sum result/bin/clementine-cli

# Compare with the hash published in the release notes
```

### Automated Verification Script

Use the provided verification script:

```bash
./scripts/verify-reproducible-build.sh clementine-cli
```

This will build twice and automatically verify the hashes match.

## Runtime Dependencies

While the binary itself is self-contained, Clementine requires external services to run:

### Required Services

1. **Bitcoin Node** (v29.0+)
   - Full node with RPC enabled
   - Configured in bridge config or via environment variables

2. **PostgreSQL Database**
   - Database migrations are embedded in the binary
   - Will run automatically on first startup

3. **TLS Certificates**
   - Required for gRPC communication
   - Generate using `./scripts/generate_certs.sh`
   - See [Usage Guide](usage.md#rpc-authentication)

### Required Files

4. **BitVM Cache Files** (Runtime, not build-time)
   - Production: `bitvm_cache.bin`
   - Development: `bitvm_cache_dev.bin`
   - **Important**: Verify integrity using [cache-hashes.md](cache-hashes.md)
   - Download and verify:
     ```bash
     ./scripts/verify-cache-hashes.sh production
     # or
     ./scripts/verify-cache-hashes.sh dev
     ```

### Environment Setup

```bash
# Required
export RUST_MIN_STACK=33554432

# BitVM cache (choose based on mode)
export BITVM_CACHE_PATH=/path/to/bitvm_cache.bin
# or for dev mode
export RISC0_DEV_MODE=1
export BITVM_CACHE_PATH=/path/to/bitvm_cache_dev.bin

# Optional: Logging
export RUST_LOG=info
export RUST_BACKTRACE=1
```

## Using the Binaries

The `clementine-cli` binary serves as both Verifier and Operator through subcommands:

### As a Verifier

```bash
# Get verifier parameters
./result/bin/clementine-cli --node-url https://verifier.example.com verifier get-params

# Generate nonces
./result/bin/clementine-cli --node-url https://verifier.example.com verifier nonce-gen --num-nonces 100

# Check verifier status
./result/bin/clementine-cli --node-url https://verifier.example.com verifier get-entity-status

# Check build information (includes git commit hash)
./result/bin/clementine-cli --node-url https://verifier.example.com verifier vergen
```

### As an Operator

```bash
# Get operator parameters
./result/bin/clementine-cli --node-url https://operator.example.com operator get-params

# Check deposit keys
./result/bin/clementine-cli --node-url https://operator.example.com operator get-deposit-keys \
  --deposit-outpoint-txid <txid> \
  --deposit-outpoint-vout <vout>

# Check operator status
./result/bin/clementine-cli --node-url https://operator.example.com operator get-entity-status

# Check build information
./result/bin/clementine-cli --node-url https://operator.example.com operator vergen
```

### Configuration

See the [Usage Guide](usage.md) for detailed configuration instructions. You can use:
- Configuration files (TOML)
- Environment variables
- Mix of both

## Troubleshooting

### Build Fails with "hash mismatch"

This usually means git dependencies have changed. Update the flake lock:

```bash
nix flake update
nix build .#clementine-cli
```

### "experimental-features" Error

Enable Nix flakes:

```bash
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Out of Disk Space

Nix builds can use significant disk space. Clean up:

```bash
nix-collect-garbage -d
```

### Build is Very Slow

First build will be slow as Nix downloads and builds dependencies. Subsequent builds are much faster due to caching.

To speed up builds:
```bash
# Use binary cache (if available)
nix build .#clementine-cli --option substituters "https://cache.nixos.org"
```

### "cannot build on this system"

You're trying to build for a different platform. Either:
1. Build on the target platform, or
2. Enable cross-compilation (may require additional setup)

### Binary Runs but Crashes

Check runtime dependencies:

```bash
# Verify all required environment variables
echo $RUST_MIN_STACK  # Should be 33554432
echo $BITVM_CACHE_PATH  # Should point to valid cache file

# Verify cache file integrity
./scripts/verify-cache-hashes.sh [production|dev]

# Check if PostgreSQL is running
psql -h localhost -U clementine -d clementine -c "SELECT 1"

# Verify TLS certificates exist
ls -la certs/server/
```

### Hash Doesn't Match Published Release

Possible causes:
1. **Different git commit**: Ensure you're on the exact same commit as the release
   ```bash
   git checkout v0.5.0  # Use exact release tag
   ```

2. **Modified source**: Ensure no local modifications
   ```bash
   git status  # Should show "working tree clean"
   git diff    # Should show no differences
   ```

3. **Different Nix setup**: Ensure flake.lock is up to date
   ```bash
   git pull origin main  # Get latest flake.lock
   nix flake update      # Update if needed
   ```

## Development Shell

For development, enter the Nix shell:

```bash
nix develop

# This provides:
# - Rust 1.88 toolchain
# - All build dependencies
# - Proper environment variables
# - Development tools (rustfmt, clippy)

# Now you can use cargo normally
cargo build --release
cargo build --release --features automation
cargo test
```

## Helper Scripts

The repository includes several helper scripts in `scripts/`:

| Script | Purpose |
|--------|---------|
| `build-all-targets.sh` | Build all platform/feature combinations |
| `verify-reproducible-build.sh` | Verify a build is reproducible |
| `verify-cache-hashes.sh` | Download and verify BitVM cache files |
| `update-nix-hashes.sh` | Update git dependency hashes in flake.nix |

## Security Considerations

### Supply Chain Security

- **Verify Hashes**: Always verify SHA256 hashes match between builds
- **Pin Dependencies**: flake.lock ensures all dependencies are pinned
- **Audit Source**: Review source code before building
- **BitVM Cache**: Always verify cache file integrity using [cache-hashes.md](cache-hashes.md)

### Best Practices

1. **Build from source**: Don't trust pre-built binaries without verification
2. **Verify git tags**: Check GPG signatures on release tags
3. **Compare hashes**: Cross-check hashes with other operators/verifiers
4. **Keep updated**: Stay on latest secure versions
5. **Secure environment**: Build in a clean, secure environment

## Contributing

If you find issues with the reproducible build setup:

1. Check [GitHub Issues](https://github.com/chainwayxyz/clementine/issues)
2. Open a new issue with:
   - Your Nix version (`nix --version`)
   - Your OS and architecture
   - Complete build logs
   - Hash mismatches (if applicable)

## References

- [Clementine Usage Guide](usage.md)
- [BitVM Cache Hashes](cache-hashes.md)
- [Nix Flakes Documentation](https://nixos.wiki/wiki/Flakes)
- [Reproducible Builds](https://reproducible-builds.org/)

## License

Clementine is licensed under GPL-3.0. See [COPYING](../COPYING) for details.
