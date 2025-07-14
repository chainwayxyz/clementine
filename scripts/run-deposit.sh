#!/bin/bash

# CPFP Deposit Flow Script for Clementine
set -e  # Exit on any error

# Configuration
AGGREGATOR_URL="https://127.0.0.1:17000"
DEPOSIT_AMOUNT="10"
BQR_ALIAS="bitcoin-cli -regtest -rpcport=18443 -rpcuser=admin -rpcpassword=admin"
BITCOIN_RPC_URL="http://127.0.0.1:18443"
BITCOIN_RPC_USER="admin"
BITCOIN_RPC_PASSWORD="admin"
FEE_RATE="10.0" # sat/vB

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "❌ Error: 'jq' command is required but not installed."
    echo "Please install jq to parse JSON responses:"
    echo "  - macOS: brew install jq"
    echo "  - Ubuntu/Debian: sudo apt-get install jq"
    echo "  - CentOS/RHEL: sudo yum install jq"
    echo "  - Or visit: https://stedolan.github.io/jq/download/"
    exit 1
fi

echo "🧱 Step 1: Setting up Aggregator..."
cargo run --bin cli -- --node-url $AGGREGATOR_URL aggregator setup

echo "📬 Step 2: Getting deposit address..."
DEPOSIT_ADDRESS=$(cargo run --bin cli -- --node-url $AGGREGATOR_URL aggregator get-deposit-address | grep -o 'bcrt1[a-zA-Z0-9]*')
echo "Deposit address: $DEPOSIT_ADDRESS"

echo "🪙 Step 3: Sending deposit via bitcoind..."
DEPOSIT_TXID=$($BQR_ALIAS sendtoaddress $DEPOSIT_ADDRESS $DEPOSIT_AMOUNT)
echo "Deposit TXID: $DEPOSIT_TXID"

echo "Mining a block to confirm the transaction..."
$BQR_ALIAS -generate 1

echo "🔎 Step 4: Getting deposit output index..."
RAW_TX=$($BQR_ALIAS getrawtransaction $DEPOSIT_TXID 2)
echo "Raw transaction details:"
echo $RAW_TX | jq '.'

# Extract vout index where the address matches our deposit address
VOUT_INDEX=$(echo $RAW_TX | jq -r --arg addr "$DEPOSIT_ADDRESS" '.vout[] | select(.scriptPubKey.address == $addr) | .n')
echo "Output index (vout): $VOUT_INDEX"

echo "🧾 Step 5: Creating and sending move transaction with CPFP..."
cargo run --bin cli -- --node-url $AGGREGATOR_URL aggregator send-move-transaction-cpfp \
  --deposit-outpoint-txid $DEPOSIT_TXID \
  --deposit-outpoint-vout $VOUT_INDEX \
  --fee-rate $FEE_RATE \
  --bitcoin-rpc-url $BITCOIN_RPC_URL \
  --bitcoin-rpc-user $BITCOIN_RPC_USER \
  --bitcoin-rpc-password $BITCOIN_RPC_PASSWORD

echo ""
echo "📝 Step 6: Mining a block to confirm the CPFP package..."
$BQR_ALIAS -generate 1
echo "Block mined!"

echo ""
echo "✅ CPFP Deposit flow completed successfully!"
echo "Summary:"
echo "  - Deposit Address: $DEPOSIT_ADDRESS"
echo "  - Deposit TXID: $DEPOSIT_TXID"
echo "  - Output Index: $VOUT_INDEX"
echo "  - Amount: $DEPOSIT_AMOUNT BTC"
echo "  - Fee Rate: $FEE_RATE sat/vB"
echo "  - Status: Move transaction sent via CPFP package and confirmed"
