#!/usr/bin/env python3
"""Fail if a supported guest crypto dependency silently loses its SP1 patch."""
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'sp1-circuits'
# Versions with a published SP1 6.10.0 patch. sha3 0.11.0 has only the sp1-6.0.0 patch.
SUPPORTED = {
    'sha2': {'0.9.8', '0.9.9', '0.10.6', '0.10.8', '0.10.9', '0.11.0'},
    'sha3': {'0.10.8', '0.11.0'},
    'tiny-keccak': {'2.0.2'},
    'crypto-bigint': {'0.5.5'},
    'k256': {'0.13.4'},
    'p256': {'0.13.2'},
    'secp256k1': {'0.29.1', '0.30.0'},
    'substrate-bn': {'0.6.0'},
    'substrate-bn-succinct-rs': {'0.6.1'},
}
# secp256k1 0.31 and blst have no published SP1 patch.
errors = []
checked = 0
for lock in sorted(BASE.rglob('Cargo.lock')):
    if 'target' in lock.relative_to(BASE).parts:
        continue
    data = tomllib.loads(lock.read_text())
    for package in data['package']:
        name, version = package['name'], package['version']
        if version in SUPPORTED.get(name, set()):
            checked += 1
            if not package.get('source', '').startswith('git+https://github.com/sp1-patches/'):
                errors.append(f'{lock.relative_to(ROOT)}: {name} {version} is not SP1-patched')
    for package in data.get('patch', {}).get('unused', []):
        if package['name'] in SUPPORTED:
            errors.append(f'{lock.relative_to(ROOT)}: unused crypto patch {package["name"]}')
if not checked:
    errors.append('No guest crypto dependencies checked')
if errors:
    sys.exit('\n'.join(errors))
print(f'Checked {checked} guest crypto dependencies: all supported versions use SP1 patches')
