#!/usr/bin/env python3
"""
Check Light Client Proof Status

Finds the latest Bitcoin block that has been proven by the Citrea Light Client
by searching backwards from current block height.
"""

import sys
import requests
import subprocess
import json

CITREA_RPC_URL = "http://127.0.0.1:12345"
LIGHT_CLIENT_CONTRACT = "0x3100000000000000000000000000000000000001"
FUNCTION_SELECTOR = "0xee82ac5e"  # getBlockHash(uint256)

def get_bitcoin_height():
    """Get current Bitcoin block height"""
    result = subprocess.run(
        ['docker', 'exec', 'bitcoin_regtest',
         'bitcoin-cli', '-regtest', '-rpcport=20443',
         '-rpcuser=admin', '-rpcpassword=admin', '-rpcwallet=admin',
         'getblockcount'],
        capture_output=True,
        text=True
    )
    return int(result.stdout.strip())

def check_block_in_light_client(block_number):
    """Check if a Bitcoin block is proven in the light client"""
    data = FUNCTION_SELECTOR + hex(block_number)[2:].zfill(64)

    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": LIGHT_CLIENT_CONTRACT,
            "data": data
        }, "latest"],
        "id": 1
    }

    try:
        response = requests.post(CITREA_RPC_URL, json=payload, timeout=10)
        result = response.json()

        if "result" in result:
            block_hash = result["result"]
            # If block hash is all zeros, block is not proven
            if block_hash != "0x0000000000000000000000000000000000000000000000000000000000000000":
                return True, block_hash
        return False, None
    except Exception as e:
        print(f"Error checking block {block_number}: {e}", file=sys.stderr)
        return False, None

def find_latest_proven_block(current_height, lookback=100):
    """Find the latest block proven in light client by searching backwards"""
    print(f"Current Bitcoin height: {current_height}")
    print(f"Searching for latest proven block (looking back {lookback} blocks)...")

    for i in range(lookback):
        block_number = current_height - i
        if block_number < 0:
            break

        is_proven, block_hash = check_block_in_light_client(block_number)

        if is_proven:
            lag = i
            print(f"\n✓ Latest proven block: {block_number}")
            print(f"  Block hash: {block_hash}")
            print(f"  Lag: {lag} blocks behind current height")
            return block_number, block_hash, lag

    # No block found in lookback range
    print(f"\n✗ ERROR: No proven blocks found in last {lookback} blocks!")
    print("Light Client Prover is far too behind.")
    return None, None, None

def main():
    try:
        current_height = get_bitcoin_height()
        latest_proven, block_hash, lag = find_latest_proven_block(current_height, lookback=100)

        if latest_proven is None:
            sys.exit(1)

        # Output JSON for easy parsing
        result = {
            "current_height": current_height,
            "latest_proven_block": latest_proven,
            "block_hash": block_hash,
            "lag_blocks": lag
        }

        print(f"\nJSON output:")
        print(json.dumps(result, indent=2))

        sys.exit(0)

    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
