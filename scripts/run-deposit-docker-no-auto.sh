#!/bin/bash

# CPFP Deposit Flow Script for Clementine
set -e  # Exit on any error

# Configuration
AGGREGATOR_URL="https://127.0.0.1:17000"
DEPOSIT_AMOUNT="10"
BQR_ALIAS=${BQR_ALIAS:="bitcoin-cli -regtest -rpcport=20443 -rpcuser=admin -rpcpassword=admin -rpcwallet=admin"}
BITCOIN_RPC_URL=${BITCOIN_RPC_URL:="http://127.0.0.1:20443/wallet/admin"}
BITCOIN_RPC_USER="admin"
BITCOIN_RPC_PASSWORD="admin"
FEE_RATE="10.0" # sat/vB
FEE_PAYER_AMOUNT="1"
export RUSTFLAGS="-Awarnings"

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

echo "🧱 Step 1: Setup Aggregator"
cargo run --bin clementine-cli -- --node-url $AGGREGATOR_URL aggregator setup

echo "📬 Step 2: Get Deposit Address"
DEPOSIT_ADDRESS=$(cargo run --bin clementine-cli -- --node-url $AGGREGATOR_URL aggregator get-deposit-address | grep -o 'bcrt1[a-zA-Z0-9]*')
echo "Deposit address: $DEPOSIT_ADDRESS"

echo "🪙 Step 3: Send Deposit"
DEPOSIT_TXID=$($BQR_ALIAS sendtoaddress $DEPOSIT_ADDRESS $DEPOSIT_AMOUNT)
echo "Deposit TXID: $DEPOSIT_TXID"
$BQR_ALIAS -generate 1

echo "🔎 Step 4: Get Deposit VOUT + Raw TX"
RAW_TX_JSON=$($BQR_ALIAS getrawtransaction $DEPOSIT_TXID 1)
VOUT_INDEX=$(echo "$RAW_TX_JSON" | jq -r --arg addr "$DEPOSIT_ADDRESS" '.vout[] | select(.scriptPubKey.address == $addr) | .n')
RAW_TX_HEX=$($BQR_ALIAS getrawtransaction $DEPOSIT_TXID)
echo "VOUT: $VOUT_INDEX"

STEP_START=$(date +%s)
echo "📥 Step 4.5: Registering deposit on aggregator..."
MOVE_TX_RAW=$(cargo run --bin clementine-cli -- --node-url $AGGREGATOR_URL aggregator new-deposit \
  --deposit-outpoint-txid $DEPOSIT_TXID \
  --deposit-outpoint-vout $VOUT_INDEX | awk '/Please send manually:/ { print $NF }')
STEP_END=$(date +%s)

if [ -z "$MOVE_TX_RAW" ]; then
  echo "❌ Failed to extract raw move transaction!"
  exit 1
fi
echo "Move TX raw: $MOVE_TX_RAW"
echo "⏱️  Step 4.5 took $((STEP_END - STEP_START)) seconds"

echo "🧾 Step 5: Create Move-to-Vault TX (CPFP step 1)"
FEE_PAYER_ADDRESS=$(cargo run --bin clementine-cli -- --node-url $BITCOIN_RPC_URL bitcoin send-tx-with-cpfp \
  --bitcoin-rpc-user $BITCOIN_RPC_USER \
  --bitcoin-rpc-password $BITCOIN_RPC_PASSWORD \
  --raw-tx $MOVE_TX_RAW | grep -o 'bcrt1[a-zA-Z0-9]*')
echo "Fee payer address: $FEE_PAYER_ADDRESS"

echo "💸 Step 6: Send fee to fee payer address"
$BQR_ALIAS sendtoaddress $FEE_PAYER_ADDRESS $FEE_PAYER_AMOUNT
$BQR_ALIAS -generate 1

echo "🧾 Step 7: Finalize CPFP Move TX"
MOVE_TX_DETAILS=$(cargo run --bin clementine-cli -- --node-url $BITCOIN_RPC_URL bitcoin send-tx-with-cpfp \
  --bitcoin-rpc-user $BITCOIN_RPC_USER \
  --bitcoin-rpc-password $BITCOIN_RPC_PASSWORD \
  --fee-payer-address $FEE_PAYER_ADDRESS \
  --raw-tx $MOVE_TX_RAW)


for i in {1..2}; do
  $BQR_ALIAS -generate 5
  sleep 2
done

echo "✅ CPFP move transaction sent and confirmed."
echo "Summary:"
echo "  - Deposit Address: $DEPOSIT_ADDRESS"
echo "  - Deposit TXID: $DEPOSIT_TXID"
echo "  - Output Index: $VOUT_INDEX"
echo "  - Move TX Details: $MOVE_TX_DETAILS"

PARENT_TXID=$(echo "$MOVE_TX_DETAILS" | grep -oP 'Parent transaction TXID: \K[a-f0-9]{64}')

if [ -z "$PARENT_TXID" ]; then
  echo "❌ Failed to extract parent transaction TXID!"
  exit 1
fi

echo "Step 8: Get Calldata for Deposit"
CALLDATA=$(clementine --network regtest deposit get-deposit-params $PARENT_TXID \
  $BITCOIN_RPC_URL $BITCOIN_RPC_USER $BITCOIN_RPC_PASSWORD | tail -n1 | tr -d '\n\r ' | xargs)

if [ -z "$CALLDATA" ]; then
  echo "❌ Failed to get deposit parameters!"
  exit 1
fi

$BQR_ALIAS -generate 10; sleep 5; $BQR_ALIAS -generate 10; sleep 5; 

echo "Calldata: $CALLDATA"

echo "📦 Step 9: Submit Calldata to Citrea"
CITREA_RESPONSE=$(jq -nc --arg cal "$CALLDATA" \
  '{jsonrpc:"2.0", method:"citrea_sendRawDepositTransaction", params:[$cal], id:1}' |
  curl -s -X POST http://127.0.0.1:12345 -H "Content-Type: application/json" --data @-)

echo "Citrea submission response: $CITREA_RESPONSE"

if echo "$CITREA_RESPONSE" | grep -q '"result":null'; then
  echo "✅ Calldata submission successful"
else
  echo "❌ Calldata submission failed"
  exit 1
fi


$BQR_ALIAS -generate 5; sleep 3; $BQR_ALIAS -generate 5; sleep 3; 

response=$(curl -s -X POST http://127.0.0.1:12345 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [{
      "to": "0x3100000000000000000000000000000000000002",
      "data": "0x065921670000000000000000000000000000000000000000000000000000000000000000"
    }, "latest"],
    "id": 1
  }')

echo "$response"