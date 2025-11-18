#!/usr/bin/env python3
"""
Check deposits and withdrawals saved in Citrea by calling the depositTxIds and withdrawalUTXOs arrays.
This implements the same logic as the Clementine Rust code in core/src/citrea.rs

Usage:
    # Basic usage (uses default RPC URL and starts from index 0)
    python3 check_citrea_deposits.py

    # Specify custom RPC URL
    python3 check_citrea_deposits.py --rpc-url http://localhost:12345

    # Start from a specific deposit index
    python3 check_citrea_deposits.py --start-index 10

    # Query at a specific block height
    python3 check_citrea_deposits.py --block-height 1000

    # Check withdrawals instead of deposits
    python3 check_citrea_deposits.py --withdrawals

    # Custom ABI file path (if Bridge.json is in a different location)
    python3 check_citrea_deposits.py --abi-path ../scripts/Bridge.json

Requirements:
    pip install web3
"""

import json
import sys
from web3 import Web3
from web3.exceptions import ContractLogicError
from typing import List, Tuple, Optional

# Constants
BRIDGE_CONTRACT_ADDRESS = "0x3100000000000000000000000000000000000002"
BRIDGE_ABI_PATH = "./scripts/Bridge.json"

def load_bridge_abi() -> list:
    """Load the Bridge contract ABI from the JSON file."""
    try:
        with open(BRIDGE_ABI_PATH, 'r') as f:
            bridge_json = json.load(f)
            return bridge_json['abi']
    except FileNotFoundError:
        print(f"Error: Bridge ABI file not found at {BRIDGE_ABI_PATH}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {BRIDGE_ABI_PATH}")
        sys.exit(1)
    except KeyError:
        print(f"Error: 'abi' key not found in {BRIDGE_ABI_PATH}")
        sys.exit(1)

def collect_deposit_txids(
    w3: Web3,
    contract,
    start_idx: int = 0,
    block_height: Optional[int] = None
) -> List[Tuple[int, str]]:
    """
    Collect all deposit move txids starting from the given index.

    Args:
        w3: Web3 instance
        contract: Bridge contract instance
        start_idx: Starting deposit index (default: 0)
        block_height: Optional block height to query at (default: latest)

    Returns:
        List of tuples containing (deposit_index, txid_hex)
    """
    deposit_txids = []
    current_idx = start_idx

    # Set block identifier
    block_identifier = block_height if block_height else 'latest'


    while True:
        try:
            # Call depositTxIds(index) at the specified block
            txid_bytes = contract.functions.depositTxIds(current_idx).call(
                block_identifier=block_identifier
            )

            # Convert bytes32 to hex string
            txid_hex = txid_bytes.hex()

            # Check if it's a zero txid (might indicate no deposit)
            if int(txid_hex, 16) == 0:
                print(f"Found zero txid at index {current_idx}, stopping.")
                break

            deposit_txids.append((current_idx, txid_hex))
            # print(f"  Index {current_idx}: 0x{txid_hex}")

            current_idx += 1

        except ContractLogicError as e:
            # Expected when we reach an index with no deposit (execution reverted)
            break
        except Exception as e:
            print(f"Error at index {current_idx}: {e}")
            break

    return deposit_txids

def collect_withdrawal_utxos(
    w3: Web3,
    contract,
    start_idx: int = 0,
    block_height: Optional[int] = None
) -> List[Tuple[int, str, int]]:
    """
    Collect all withdrawal UTXOs starting from the given index.

    Args:
        w3: Web3 instance
        contract: Bridge contract instance
        start_idx: Starting withdrawal index (default: 0)
        block_height: Optional block height to query at (default: latest)

    Returns:
        List of tuples containing (withdrawal_index, txid_hex, vout)
    """
    withdrawal_utxos = []
    current_idx = start_idx

    # Set block identifier
    block_identifier = block_height if block_height else 'latest'


    while True:
        try:
            # Call withdrawalUTXOs(index) at the specified block
            withdrawal_utxo = contract.functions.withdrawalUTXOs(current_idx).call(
                block_identifier=block_identifier
            )

            # withdrawal_utxo is a tuple/struct with (txId, outputId)
            txid_bytes = withdrawal_utxo[0]  # txId is bytes32
            output_id_bytes = withdrawal_utxo[1]  # outputId is bytes4

            # Convert txid bytes32 to hex string
            txid_hex = txid_bytes.hex()

            # Convert output_id bytes4 to uint32 (little-endian)
            vout = int.from_bytes(output_id_bytes, byteorder='little')

            # Check if it's a zero txid (might indicate no withdrawal)
            if int(txid_hex, 16) == 0:
                print(f"Found zero txid at index {current_idx}, stopping.")
                break

            withdrawal_utxos.append((current_idx, txid_hex, vout))
            # print(f"  Index {current_idx}: txid=0x{txid_hex}, vout={vout}")

            current_idx += 1

        except ContractLogicError as e:
            # Expected when we reach an index with no withdrawal (execution reverted)
            print(f"Reached end of withdrawals at index {current_idx} (execution reverted)")
            break
        except Exception as e:
            print(f"Error at index {current_idx}: {e}")
            break

    return withdrawal_utxos

def main():
    """Main function to check Citrea deposits and withdrawals."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Check deposits and withdrawals saved in Citrea bridge contract"
    )
    parser.add_argument(
        "--rpc-url",
        default="http://127.0.0.1:12345",
        help="Citrea RPC URL (default: http://127.0.0.1:12345)"
    )
    parser.add_argument(
        "--start-index",
        type=int,
        default=0,
        help="Starting index (default: 0)"
    )
    parser.add_argument(
        "--block-height",
        type=int,
        default=None,
        help="Block height to query at (default: latest)"
    )
    parser.add_argument(
        "--abi-path",
        default="./scripts/Bridge.json",
        help="Path to Bridge.json ABI file (default: ./Bridge.json)"
    )
    parser.add_argument(
        "--withdrawals",
        action="store_true",
        help="Check withdrawals instead of deposits"
    )

    args = parser.parse_args()

    # Update global ABI path if provided
    global BRIDGE_ABI_PATH
    BRIDGE_ABI_PATH = args.abi_path

    # Connect to Citrea RPC
    print(f"Connecting to Citrea RPC at {args.rpc_url}...")
    w3 = Web3(Web3.HTTPProvider(args.rpc_url))

    # Check connection
    if not w3.is_connected():
        print(f"Error: Failed to connect to Citrea RPC at {args.rpc_url}")
        sys.exit(1)

    print(f"Connected! Chain ID: {w3.eth.chain_id}")

    # Load Bridge ABI
    bridge_abi = load_bridge_abi()

    # Create contract instance
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(BRIDGE_CONTRACT_ADDRESS),
        abi=bridge_abi
    )
    print(f"Bridge contract loaded at {BRIDGE_CONTRACT_ADDRESS}")

    # Collect deposit txids
    deposit_txids = collect_deposit_txids(
        w3,
        contract,
        start_idx=args.start_index,
        block_height=args.block_height
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Deposits Summary:")
    print(f"{'='*60}")
    print(f"Total deposits found: {len(deposit_txids)}")

    if deposit_txids:
        if len(deposit_txids) < 5:
            # Print all deposits if less than 5
            for idx, txid in deposit_txids:
                print(f"  Index {idx} -> 0x{txid}")
        else:
            # Print first 2, ellipsis, and last 2
            print(f"  Index {deposit_txids[0][0]} -> 0x{deposit_txids[0][1]}")
            print(f"  Index {deposit_txids[1][0]} -> 0x{deposit_txids[1][1]}")
            print(f"  ...")
            print(f"  Index {deposit_txids[-2][0]} -> 0x{deposit_txids[-2][1]}")
            print(f"  Index {deposit_txids[-1][0]} -> 0x{deposit_txids[-1][1]}")
    else:
        print("No deposits found.")

    print("\n")
    # Collect withdrawal UTXOs
    withdrawal_utxos = collect_withdrawal_utxos(
        w3,
        contract,
        start_idx=args.start_index,
        block_height=args.block_height
    )

    # Print summary
    print(f"\n{'='*60}")
    print(f"Withdrawals Summary:")
    print(f"{'='*60}")
    print(f"Total withdrawals found: {len(withdrawal_utxos)}")

    if withdrawal_utxos:
        if len(withdrawal_utxos) < 5:
            # Print all withdrawals if less than 5
            for idx, txid, vout in withdrawal_utxos:
                print(f"  Index {idx} -> txid=0x{txid}, vout={vout}")
        else:
            # Print first 2, ellipsis, and last 2
            first = withdrawal_utxos[0]
            second = withdrawal_utxos[1]
            second_last = withdrawal_utxos[-2]
            last = withdrawal_utxos[-1]
            print(f"  Index {first[0]} -> txid=0x{first[1]}, vout={first[2]}")
            print(f"  Index {second[0]} -> txid=0x{second[1]}, vout={second[2]}")
            print(f"  ...")
            print(f"  Index {second_last[0]} -> txid=0x{second_last[1]}, vout={second_last[2]}")
            print(f"  Index {last[0]} -> txid=0x{last[1]}, vout={last[2]}")
    else:
        print("No withdrawals found.")



if __name__ == "__main__":
    main()
