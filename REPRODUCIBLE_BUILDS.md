# Reproducible Builds for Clementine Core

This document describes the reproducible build setup for Clementine Core, which ensures that multiple developers can independently build the same binary from the same source code.

## What is a Reproducible Build?

A reproducible build is a build process that produces bit-for-bit identical binaries when given the same source code. This is critical for:

- **Security verification**: Allows anyone to verify that published binaries match the source code
- **Supply chain security**: Prevents backdoors or malicious code injection during the build process
- **Trust**: Enables independent verification by multiple parties

## Quick Start

To build a reproducible binary:

```bash
./scripts/build-stagex.sh
```

The script will:
1. Check for uncommitted changes (warn if found)
2. Get the current git commit timestamp
3. Build using Docker with StageX pallets
4. Output the binary to `./dist/out/clementine-core`
5. Display the SHA256 hash for verification

## Verification Process

To verify that the build is reproducible:

1. **Developer A builds:**
   ```bash
   git checkout <commit-sha>
   ./scripts/build-stagex.sh
   # Note the SHA256 hash
   ```

2. **Developer B independently builds:**
   ```bash
   git checkout <same-commit-sha>
   ./scripts/build-stagex.sh
   # Compare SHA256 hash with Developer A
   ```

3. **Both hashes should be identical!**

## How It Works

### 1. Deterministic Toolchain (StageX)

We use [StageX](https://github.com/stagex/stagex) pallets for reproducible build environments:

- `stagex/pallet-rust@sha256:...` - Rust toolchain pinned by digest
- All build tools are hermetically sealed and deterministic

### 2. Build Environment Variables

The Dockerfile sets these for reproducibility:

```dockerfile
SOURCE_DATE_EPOCH=$COMMIT_TS  # Git commit timestamp (not build time!)
CARGO_INCREMENTAL=0           # Disable incremental compilation
ZERO_AR_DATE=1               # Zero timestamps in archives
TZ=UTC                       # Consistent timezone
LANG=C.UTF-8                 # Consistent locale
REPR_GUEST_BUILD=true        # Reproducible RISC0 guest builds
```

### 3. Modified `build.rs`

The `core/build.rs` file detects `SOURCE_DATE_EPOCH` and:

- **When set**: Skips `BuildBuilder` and `SysinfoBuilder` (non-deterministic metadata)
- **When unset**: Includes all metadata for development builds

This ensures:
- Reproducible builds: No build timestamps embedded
- Dev builds: Full metadata for debugging

### 4. Compiler Flags

```
RUSTFLAGS="-C codegen-units=1
           -C target-feature=+crt-static
           -C debuginfo=0
           -C strip=symbols
           -Clink-arg=-Wl,--build-id=none"
```

- Single codegen unit for determinism
- Static linking (musl)
- No debug info or build IDs that could vary

### 5. Locked Dependencies

```bash
cargo build --locked --frozen --offline
```

- `--locked`: Use exact versions from Cargo.lock
- `--frozen`: Fail if Cargo.lock is outdated
- `--offline`: No network access during build

## What Makes This Reproducible?

### Sources of Non-Determinism (Eliminated)

| Source | Solution |
|--------|----------|
| Build timestamps | Use `SOURCE_DATE_EPOCH` from git commit |
| System information | Skip `SysinfoBuilder` in reproducible mode |
| Build machine info | Skip `BuildBuilder` in reproducible mode |
| Filesystem timestamps | Normalize with `touch -d "@$SOURCE_DATE_EPOCH"` |
| Toolchain version | Pin StageX pallet by SHA256 digest |
| Dependency versions | Use Cargo.lock with `--locked --frozen` |
| RISC0 guest builds | Enable `REPR_GUEST_BUILD=true` |
| Build IDs | Disable with `-Wl,--build-id=none` |
| Debug symbols | Strip with `strip=symbols` |

### What IS Embedded (Deterministically)

- Git commit SHA
- Git commit timestamp (from SOURCE_DATE_EPOCH)
- Cargo features and target triple
- Rustc version (deterministic via StageX)

## Requirements

1. **Docker Buildx**: Required for the multi-platform build syntax
   ```bash
   docker buildx version
   ```

2. **Committed Cargo.lock**: Must be in git and up-to-date
   ```bash
   git add Cargo.lock
   git commit -m "Update Cargo.lock"
   ```

3. **Clean working directory**: For best reproducibility
   ```bash
   git status  # Should show no uncommitted changes
   ```

## Troubleshooting

### Different hashes from the same commit?

Check:
1. **Cargo.lock differences**: Ensure both builders have the same Cargo.lock
2. **Uncommitted changes**: Both should build from a clean checkout
3. **Docker platform**: Both should use `--platform=linux/amd64`
4. **StageX pallet digest**: Verify the SHA256 in Dockerfile.stagex matches

### Build fails with dependency errors?

- Ensure Cargo.lock is committed and up-to-date:
  ```bash
  cargo update
  git add Cargo.lock
  git commit -m "Update dependencies"
  ```

### RISC0 circuit reproducibility issues?

- Verify `REPR_GUEST_BUILD=true` is set in the Dockerfile
- Check that Docker is available during the build
- Ensure `BITCOIN_NETWORK` is set consistently (default: mainnet)

## Advanced Usage

### Build for a specific commit

```bash
git checkout <commit-sha>
./scripts/build-stagex.sh
```

### Override Bitcoin network

Edit `scripts/docker/Dockerfile.stagex` and change:
```dockerfile
ENV BITCOIN_NETWORK=testnet  # or regtest
```

### Verify against published hash

```bash
# Build locally
./scripts/build-stagex.sh

# Compare with published hash
echo "<published-hash>  dist/out/clementine-core" | sha256sum -c
```

## Technical Details

### File Modifications for Reproducibility

1. **core/build.rs**
   - Added `SOURCE_DATE_EPOCH` detection
   - Conditional metadata inclusion

2. **scripts/docker/Dockerfile.stagex**
   - StageX-based build environment
   - Deterministic environment variables
   - Multi-stage build with artifact extraction

3. **scripts/build-stagex.sh**
   - Automated build process
   - Git commit timestamp extraction
   - Verification instructions

## References

- [Reproducible Builds Project](https://reproducible-builds.org/)
- [SOURCE_DATE_EPOCH Specification](https://reproducible-builds.org/specs/source-date-epoch/)
- [StageX Project](https://github.com/stagex/stagex)
- [Cargo Build Scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)

## Maintenance

### Updating the StageX Rust Pallet

To update the Rust version:

1. Find the latest digest:
   ```bash
   docker pull stagex/pallet-rust:latest
   docker inspect stagex/pallet-rust:latest | grep Id
   ```

2. Update in `scripts/docker/Dockerfile.stagex`:
   ```dockerfile
   ARG PALLET_RUST=stagex/pallet-rust@sha256:<new-digest>
   ```

3. Test reproducibility after updating

### Verifying Changes Don't Break Reproducibility

After modifying the build process:

1. Build twice from the same commit:
   ```bash
   ./scripts/build-stagex.sh
   mv dist/out/clementine-core build1
   rm -rf dist
   ./scripts/build-stagex.sh
   sha256sum build1 dist/out/clementine-core
   ```

2. Hashes should match if reproducibility is maintained
