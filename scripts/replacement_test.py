# Before running this script you need to start the actors (you can use run-test.sh)
# Bitcoin also needs to be running, example for regtest:
# bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1 -daemon -maxtxfee=1
import subprocess
import json
import time

NODE_URL = "http://127.0.0.1:17000"
RPC = "bitcoin-cli -regtest -rpcport=18443 -rpcuser=admin -rpcpassword=admin"


def run_cmd(cmd, capture=True):
    print(f"\nRunning: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    if result.returncode != 0:
        print(f"Error:\n{result.stderr}")
        return None
    return result.stdout.strip() if capture else None


def get_deposit_address():
    output = run_cmd(
        f"cargo run --bin clementine-cli -- --node-url {NODE_URL} aggregator get-deposit-address"
    )
    for word in output.split():
        if word.startswith("bcrt") or word.startswith("tb1") or word.startswith("bc1"):
            return word.strip()
    return None


def send_deposit(address, amount=10):
    txid = run_cmd(f"{RPC} sendtoaddress {address} {amount}")
    run_cmd(f"{RPC} -generate 1")
    return txid


def get_output_index(txid, address):
    raw = run_cmd(f"{RPC} getrawtransaction {txid} 2")
    tx = json.loads(raw)
    for vout in tx.get("vout", []):
        if address == vout.get("scriptPubKey", {}).get("address", []):
            return vout["n"]
    return None


def register_deposit(txid, vout):
    output = run_cmd(
        f"cargo run --bin clementine-cli -- --node-url {NODE_URL} aggregator new-deposit "
        f"--deposit-outpoint-txid {txid} --deposit-outpoint-vout {vout}"
    )

    return output.split("Move txid: ")[1].strip()


def setup():
    output = run_cmd(
        f"cargo run --bin clementine-cli -- --node-url {NODE_URL} aggregator setup"
    )

    return output


def get_replacement_address(move_txid):
    output = run_cmd(
        f"cargo run --bin clementine-cli -- --node-url {NODE_URL} aggregator get-replacement-deposit-address "
        f"--move-txid {move_txid}"
    )
    for word in output.split():
        if word.startswith("bcrt") or word.startswith("tb1") or word.startswith("bc1"):
            return word.strip()
    return None


def register_replacement_deposit(new_txid, new_vout, old_txid):
    final_output = run_cmd(
        f"cargo run --bin clementine-cli -- --node-url {NODE_URL} aggregator new-replacement-deposit "
        f"--deposit-outpoint-txid {new_txid} "
        f"--deposit-outpoint-vout {new_vout} "
        f"--old-move-txid {old_txid}"
    )

    run_cmd(f"{RPC} -generate 1")

    return final_output.split("Move txid: ")[1].strip()


def big_to_little_endian(hex_str):
    bytes_list = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]
    little_endian = "".join(reversed(bytes_list))
    return little_endian


def get_balance():
    balance = run_cmd(f"{RPC} getbalance")
    return float(balance) if balance else 0.0


if __name__ == "__main__":

    balance = get_balance()

    NUMBER_OF_REPLACEMENTS = 1

    setup_output = setup()
    print(f"Setup output: {setup_output}")

    while balance < 20 * NUMBER_OF_REPLACEMENTS:
        print(f"Balance: {balance} BTC")
        print("Generating blocks...")
        # Generate blocks to increase balance
        run_cmd(f"{RPC} -generate {NUMBER_OF_REPLACEMENTS}")
        balance = get_balance()
        print(f"Balance: {balance} BTC")

    for _ in range(NUMBER_OF_REPLACEMENTS):
        deposit_address = get_deposit_address()
        if not deposit_address:
            print("Failed to get deposit address.")
            exit(1)
        print(f"Deposit address: {deposit_address}")

        txid = send_deposit(deposit_address)
        print(f"Deposit TXID: {txid}")

        vout = get_output_index(txid, deposit_address)
        if vout is None:
            print("Failed to find vout.")
            exit(1)
        print(f"Output index: {vout}")

        move_tx = register_deposit(txid, vout)
        print("Deposit registered.")

        # Replacement flow
        OLD_TXID = move_tx  # Replace if needed
        print(f"\nStarting replacement for move-txid: {OLD_TXID}")
        replacement_address = get_replacement_address(OLD_TXID)
        if not replacement_address:
            print("Failed to get replacement address.")
            exit(1)
        print(f"Replacement address: {replacement_address}")

        replacement_txid = send_deposit(replacement_address)
        print(f"Replacement TXID: {replacement_txid}")

        replacement_vout = get_output_index(replacement_txid, replacement_address)
        if replacement_vout is None:
            print("Failed to get replacement vout.")
            exit(1)
        print(f"Replacement output index: {replacement_vout}")

        new_tx_id = register_replacement_deposit(
            replacement_txid, replacement_vout, OLD_TXID
        )

        while not (raw := run_cmd(f"{RPC} getrawtransaction {new_tx_id}")):
            run_cmd(f"{RPC} -generate 1")
            time.sleep(1)

        old_txid_le = big_to_little_endian(OLD_TXID)

        print(f"Converted OLD_TXID (le): {old_txid_le}")

        if old_txid_le not in raw:
            print("Replacement txid not found in raw transaction.")
            exit(1)

    print("All replacements completed successfully.")
    print(f"Final balance: {balance} BTC")
