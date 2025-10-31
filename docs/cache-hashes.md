# BitVM Cache File Hashes

Clementine requires BitVM cache files to operate. These files contain pre-computed data structures for BitVM operations. For security and reproducibility, you should verify the integrity of these cache files before using them.

## Cache File Locations

The BitVM cache files are hosted at:
- **Production mode**: https://static.testnet.citrea.xyz/common/bitvm_cache_v3.bin
- **Development mode**: https://static.testnet.citrea.xyz/common/bitvm_cache_dev.bin

## Expected SHA256 Hashes

### Production Mode Cache (`bitvm_cache.bin`)

```
# To be updated after downloading the file
# Run: sha256sum bitvm_cache.bin
SHA256: [TO BE COMPUTED]
```

### Development Mode Cache (`bitvm_cache_dev.bin`)

```
# To be updated after downloading the file
# Run: sha256sum bitvm_cache_dev.bin
SHA256: [TO BE COMPUTED]
```

## Downloading and Verifying Cache Files

### Production Mode

```bash
# Download the cache file
wget https://static.testnet.citrea.xyz/common/bitvm_cache_v3.bin -O bitvm_cache.bin

# Verify the hash
sha256sum bitvm_cache.bin

# Compare with the expected hash above
# The hash should match exactly
```

### Development Mode

```bash
# Download the dev cache file
wget https://static.testnet.citrea.xyz/common/bitvm_cache_dev.bin -O bitvm_cache_dev.bin

# Verify the hash
sha256sum bitvm_cache_dev.bin

# Compare with the expected hash above
# The hash should match exactly
```

## Automated Verification

You can use the provided script to automatically download and verify cache files:

```bash
./scripts/verify-cache-hashes.sh [production|dev]
```

This script will:
1. Download the appropriate cache file if it doesn't exist
2. Verify the SHA256 hash against the expected value
3. Exit with an error if the hash doesn't match

## Using Cache Files

### Environment Variable

Set the `BITVM_CACHE_PATH` environment variable to point to your cache file:

```bash
# For production mode (RISC0_DEV_MODE not set or set to 0)
export BITVM_CACHE_PATH=/path/to/bitvm_cache.bin

# For development mode (RISC0_DEV_MODE=1)
export BITVM_CACHE_PATH=/path/to/bitvm_cache_dev.bin
```

### Default Behavior

If `BITVM_CACHE_PATH` is not set, Clementine will look for cache files in the following locations:
- `./core/bitvm_cache.bin` or `./core/bitvm_cache_dev.bin` (depending on mode)
- `./bitvm_cache.bin` or `./bitvm_cache_dev.bin` (depending on mode)

## Cache File Sizes

Expected approximate sizes:
- Production cache: ~TBD MB
- Development cache: ~TBD MB

**Note**: Large cache file sizes are normal as they contain extensive pre-computed data.

## Updating This Documentation

When cache files are updated:

1. Download the new cache files
2. Compute their SHA256 hashes:
   ```bash
   sha256sum bitvm_cache.bin
   sha256sum bitvm_cache_dev.bin
   ```
3. Update the hashes in this document
4. Commit the changes with a descriptive message indicating the cache version

## Security Considerations

- **Always verify the hash**: Never use a cache file without verifying its SHA256 hash
- **Use HTTPS**: Always download cache files over HTTPS to prevent MITM attacks
- **Keep hashes updated**: When cache files are updated, ensure this documentation is updated accordingly
- **Store securely**: Keep cache files in a secure location with appropriate file permissions

## Troubleshooting

### Hash Mismatch

If the computed hash doesn't match the expected hash:
1. **Do not use the file** - it may be corrupted or tampered with
2. Re-download the file from the official source
3. Verify your internet connection wasn't compromised
4. If the problem persists, contact the Clementine team

### File Not Found

If the cache file URL returns 404:
1. Check if the cache file has been moved to a new location
2. Check the official Clementine documentation for updated URLs
3. Contact the Clementine team for assistance

### Wrong Cache for Mode

If you're getting errors about cache files:
1. Ensure you're using the correct cache file for your mode (production vs development)
2. Check that `RISC0_DEV_MODE` is set correctly
3. Verify `BITVM_CACHE_PATH` points to the correct file
