#!/usr/bin/env bash

# CPFP Withdrawal Flow Script for Clementine (Regtest)
set -e

AGGREGATOR_URL=${AGGREGATOR_URL:-"https://127.0.0.1:17000"}
SEQUENCER_URL=${SEQUENCER_URL:-"http://127.0.0.1:12345"}
BITCOIN_RPC_URL=${BITCOIN_RPC_URL:-"http://127.0.0.1:20443/wallet/admin"}
BITCOIN_RPC_USER=${BITCOIN_RPC_USER:-"admin"}
BITCOIN_RPC_PASSWORD=${BITCOIN_RPC_PASSWORD:-"admin"}
BQR_ALIAS=${BQR_ALIAS:-"bitcoin-cli -regtest -rpcport=20443 -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASSWORD -rpcwallet=admin"}
DEPOSIT_TXID=${DEPOSIT_TXID:-""}
DEPOSIT_VOUT=${DEPOSIT_VOUT:-""}
REIMB_FEE_PAYER_AMOUNT=${REIMB_FEE_PAYER_AMOUNT:-"1"}

# Amounts
SIGNER_FUND_BTC=${SIGNER_FUND_BTC:-"0.0000033"}   # funding for the signer UTXO (~330 sat)
WITHDRAW_AMOUNT_SATS=${WITHDRAW_AMOUNT_SATS:-"970000000"}

# Optional: fee rate hints (not all commands use this directly)
FEE_RATE=${FEE_RATE:-"10.0"} # sat/vB (informational)

SATS_PER_BTC=100000000

# Required secret key for safe-withdrawal step
: "${SECRET_KEY:?Set SECRET_KEY in your environment (private key for withdrawal signer)}"

export RUSTFLAGS="-Awarnings"

# =========================
# Helpers
# =========================
req() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "❌ Missing dependency: $1"; exit 1; fi
}

jqval() { jq -r "$1"; }

# =========================
# Preconditions
# =========================
req jq
req awk
req grep

# Quick function to mine a few blocks for regtest and give mempool a push
mine() { local n=${1:-1}; $BQR_ALIAS -generate "$n" >/dev/null; }

echo "WARNING This command will save a private key to your computer."
echo "   Anyone with access to this computer could potentially spend your funds."
echo "   Make sure you're running this in a secure environment."
echo
read -p "Are you sure you want to continue? (y/N): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
  echo "❌ Aborted by user."
  exit 1
fi

# =========================
# Step 1: Generate signer address
# =========================
echo "🔐 Step 1: Generate signer address"
SIGNER_ADDRESS=$(echo y | clementine --network regtest withdrawal generate-signer-address | grep -o 'bcrt1[0-9a-z]\+')
if [[ -z "$SIGNER_ADDRESS" ]]; then echo "❌ Could not parse signer address"; exit 1; fi
echo "Signer address: $SIGNER_ADDRESS"

# =========================
# Step 2: Fund signer UTXO
# =========================
echo "💸 Step 2: Fund signer UTXO with $SIGNER_FUND_BTC BTC"
SIGNER_FUND_TXID=$($BQR_ALIAS sendtoaddress "$SIGNER_ADDRESS" "$SIGNER_FUND_BTC")
echo "Signer fund TXID: $SIGNER_FUND_TXID"; mine 3; sleep 3; mine 3; sleep 3

RAW=$($BQR_ALIAS getrawtransaction "$SIGNER_FUND_TXID" 1)
SIGNER_VOUT=$(echo "$RAW" | jq -r --arg addr "$SIGNER_ADDRESS" '.vout[] | select(.scriptPubKey.address == $addr) | .n')

if [[ -z "$SIGNER_VOUT" ]]; then
  echo "❌ Could not find signer UTXO vout for address $SIGNER_ADDRESS"
  exit 1
fi

# =========================
# Step 3: Choose withdrawal recipient
# =========================
echo "🏦 Step 3: Create recipient address"
WITHDRAWAL_ADDRESS=$($BQR_ALIAS getnewaddress "" "bech32m")
if [[ -z "$WITHDRAWAL_ADDRESS" ]]; then echo "❌ Failed to get recipient address"; exit 1; fi

echo "Recipient address: $WITHDRAWAL_ADDRESS"

# =========================
# Step 4: Generate withdrawal signature
# =========================
echo "✍️  Step 4: Generate withdrawal signature"
# NOTE: The CLI expects <SIGNER_ADDRESS> <WITHDRAWAL_ADDRESS> <TXID>:<VOUT> <AMOUNT>
# For AMOUNT we pass satoshis (matches aggregator new-withdrawal). If your CLI expects BTC, set WITHDRAW_AMOUNT_SATS accordingly and adjust.
WITHDRAW_REF="$SIGNER_FUND_TXID:$SIGNER_VOUT"
echo "Withdrawal reference: $WITHDRAW_REF"
WITHDRAW_AMOUNT_BTC=$(echo "scale=8; $WITHDRAW_AMOUNT_SATS / $SATS_PER_BTC" | bc)
RAW_SIG_OUTPUT=$(clementine --network regtest withdrawal generate-withdrawal-signature \
  "$SIGNER_ADDRESS" "$WITHDRAWAL_ADDRESS" "$WITHDRAW_REF" "$WITHDRAW_AMOUNT_BTC")


# Try to extract signature hex (assumes it appears as a hex blob in the output)
WITHDRAW_SIGNATURE=$(echo "$RAW_SIG_OUTPUT" | grep -oE '[0-9a-fA-F]{130,}' | head -n1)
if [[ -z "$WITHDRAW_SIGNATURE" ]]; then echo "❌ Could not parse withdrawal signature from output"; echo "$RAW_SIG_OUTPUT"; exit 1; fi


echo "Signature (DER+hashType): ${WITHDRAW_SIGNATURE:0:18}... (len ${#WITHDRAW_SIGNATURE})"

# =========================
# Step 5: Submit safe withdrawal to sequencer
# =========================
echo "🧾 Step 5: Submit safe withdrawal to sequencer"
SEND_OUT=$(
  SECRET_KEY="$SECRET_KEY" clementine --network regtest withdrawal send-safe-withdrawal \
    "$SIGNER_ADDRESS" "$WITHDRAWAL_ADDRESS" "$WITHDRAW_REF" "$WITHDRAW_AMOUNT_BTC" "$WITHDRAW_SIGNATURE" \
    "$SEQUENCER_URL" \
    --bitcoin-rpc-url "$BITCOIN_RPC_URL" \
    --bitcoin-rpc-user "$BITCOIN_RPC_USER" \
    --bitcoin-rpc-password "$BITCOIN_RPC_PASSWORD"
)

echo "$SEND_OUT"

# 2) Parse the EVM block_number from the printed receipt:  block_number: Some(562)
BLOCK_NUM=$(echo "$SEND_OUT" | sed -n 's/.*block_number: Some(\([0-9]\+\)).*/\1/p' | head -n1)
if [[ -z "${BLOCK_NUM:-}" ]]; then
  echo "❌ Could not parse block_number from receipt output"; exit 1
fi
TARGET_L2=$(( BLOCK_NUM + 10 ))
echo "Baseline L2 target: lastL2Height > $TARGET_L2 (block_number=$BLOCK_NUM + 10)"

# 3) Poll LCP using current L1 (Bitcoin) height until condition is met
while true; do
  BTC_HEIGHT=$(( $($BQR_ALIAS getblockcount) - 5 ))

  RESP=$(curl -s -X POST http://localhost:12349 \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": 1,
      \"method\": \"lightClientProver_getLightClientProofByL1Height\",
      \"params\": [$BTC_HEIGHT]
    }")

  # lastL2Height is hex (e.g., "0x123"); bash $((0x..)) handles hex -> dec
  LAST_L2_HEX=$(echo "$RESP" | jq -r '.result.lightClientProofOutput.lastL2Height // empty')
  if [[ -z "${LAST_L2_HEX:-}" || "$LAST_L2_HEX" == "null" ]]; then
    echo "LCP not ready yet (height=$BTC_HEIGHT). Retrying..."
    sleep 3
    continue
  fi
  LAST_L2_DEC=$(( LAST_L2_HEX ))

  echo "BTC=$BTC_HEIGHT  lastL2Height(dec)=$LAST_L2_DEC  target=$TARGET_L2"

  if (( LAST_L2_DEC > TARGET_L2 )); then
    echo "✅ Condition met: $LAST_L2_DEC > $TARGET_L2"
    break
  fi

  sleep 3
done

# Optional: sanity check intent via eth_call (expects non-zero)
INTENT=$(curl -s -X POST "$SEQUENCER_URL" -H "Content-Type: application/json" --data '{
  "jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x3100000000000000000000000000000000000002","data":"0x781952a8"},"latest"],"id":1}')
echo "Sequencer intent check: $INTENT"

# =========================
# Step 6: Operator pays the withdrawal via aggregator
# =========================
echo "🔓 Step 6: Operator payout via aggregator"
# Get scriptPubKey for recipient
SPK=$($BQR_ALIAS getaddressinfo "$WITHDRAWAL_ADDRESS" | jq -r '.scriptPubKey')
if [[ -z "$SPK" || "$SPK" == "null" ]]; then echo "❌ Could not fetch scriptPubKey"; exit 1; fi

echo "Recipient scriptPubKey: $SPK"

# Strip the SIGHASH flag (last byte) from the signature for the aggregator input
INPUT_SIG_STRIPPED=${WITHDRAW_SIGNATURE::-2}

# Submit new-withdrawal to aggregator (withdrawal-id assumed 0; adjust if needed)
AGG_RESP=$(cargo run --bin clementine-cli -- --node-url "$AGGREGATOR_URL" aggregator new-withdrawal \
  --withdrawal-id 0 \
  --input-signature "$INPUT_SIG_STRIPPED" \
  --input-outpoint-txid "$SIGNER_FUND_TXID" \
  --input-outpoint-vout "$SIGNER_VOUT" \
  --output-script-pubkey "$SPK" \
  --output-amount "$WITHDRAW_AMOUNT_SATS")

echo "$AGG_RESP"

# Mine a few blocks and confirm
for i in {1..2}; do mine 3; sleep 2; done

# =========================
# Step 7: Verify funds received
# =========================
echo "📬 Step 7: Verify funds at recipient"
RECEIVED=$($BQR_ALIAS getreceivedbyaddress "$WITHDRAWAL_ADDRESS")
echo "Received (BTC): $RECEIVED"


# fail if received amount is less than expected
EXPECTED=$(echo "scale=8; $WITHDRAW_AMOUNT_SATS / $SATS_PER_BTC" | bc)
if (( $(echo "$RECEIVED < $EXPECTED" | bc -l) )); then
  echo "❌ Received amount ($RECEIVED BTC) is less than expected ($EXPECTED BTC)"
  exit 1
fi


send_with_cpfp() {
  local raw_tx="$1"
  echo "🧾 Reimb-CPFP: stage 1 (get fee payer)"
  local fp_addr
  fp_addr=$(cargo run --bin clementine-cli -- --node-url "$BITCOIN_RPC_URL" bitcoin send-tx-with-cpfp \
    --bitcoin-rpc-user "$BITCOIN_RPC_USER" \
    --bitcoin-rpc-password "$BITCOIN_RPC_PASSWORD" \
    --raw-tx "$raw_tx" | grep -o 'bcrt1[a-zA-Z0-9]*' | head -n1)
  if [[ -z "$fp_addr" ]]; then echo "❌ Could not get fee payer address"; return 1; fi
  echo "Fee payer: $fp_addr"

  echo "💸 Reimb-CPFP: fund fee payer with $REIMB_FEE_PAYER_AMOUNT BTC"
  $BQR_ALIAS sendtoaddress "$fp_addr" "$REIMB_FEE_PAYER_AMOUNT" >/dev/null
  mine 1

  echo "🧾 Reimb-CPFP: finalize"
  cargo run --bin clementine-cli -- --node-url "$BITCOIN_RPC_URL" bitcoin send-tx-with-cpfp \
    --bitcoin-rpc-user "$BITCOIN_RPC_USER" \
    --bitcoin-rpc-password "$BITCOIN_RPC_PASSWORD" \
    --fee-payer-address "$fp_addr" \
    --raw-tx "$raw_tx" >/dev/null
}

# =========================
# (Optional) Step 8: Operator reimbursement (if your flow requires it)
# =========================
# If you need to reimburse operators for payout fees, call get-reimbursement-txs and CPFP-broadcast them similarly to deposit flow.
# Example (requires original deposit outpoint info):

# !!! AGGREGATOR URL IS TO BE SWITCHED TO OPERATOR URL DO NOT USE THIS PART UNTIL IT's UPDATED !!!

# if [[ -n "$DEPOSIT_TXID" && -n "$DEPOSIT_VOUT" ]]; then
#   echo "🔁 Step 8.1: Fetch round tx"
#   REIMB_RAW_1=$(cargo run --bin clementine-cli -- --node-url "$AGGREGATOR_URL" operator get-reimbursement-txs \
#     --deposit-outpoint-txid "$DEPOSIT_TXID" \
#     --deposit-outpoint-vout "$DEPOSIT_VOUT" | awk '/Please send manually:/ { print $NF }' | head -n1)

#   if [[ -n "$REIMB_RAW_1" ]]; then
#     echo "Found round tx (len ${#REIMB_RAW_1}). Sending with CPFP..."
#     send_with_cpfp "$REIMB_RAW_1"
#   else
#     echo "ℹ️ No first round tx returned yet (maybe already sent)."
#   fi

#   echo "⛏️  Step 8.2: Mine and wait before kickoff"
#   mine 3; sleep 2; mine 3; sleep 2

#   echo "🔁 Step 8.3: Fetch kickoff tx"
#   REIMB_RAW_2=$(cargo run --bin clementine-cli -- --node-url "$AGGREGATOR_URL" operator get-reimbursement-txs \
#     --deposit-outpoint-txid "$DEPOSIT_TXID" \
#     --deposit-outpoint-vout "$DEPOSIT_VOUT" | awk '/Please send manually:/ { print $NF }' | tail -n1)

#   if [[ -n "$REIMB_RAW_2" && "$REIMB_RAW_2" != "$REIMB_RAW_1" ]]; then
#     echo "Found second kickoff tx (len ${#REIMB_RAW_2}). Sending with CPFP..."
#     send_with_cpfp "$REIMB_RAW_2"
#   else
#     echo "ℹ️ No distinct second kickoff tx returned (may not be ready yet)."
#   fi
# else
#   echo "ℹ️ Skipping reimbursement: DEPOSIT_TXID/DEPOSIT_VOUT not set."
# fi

# Then broadcast with your CPFP helper and mine blocks.

echo "✅ Withdrawal flow completed.
Summary:
  - Signer: $SIGNER_ADDRESS
  - Signer UTXO: $SIGNER_FUND_TXID:$SIGNER_VOUT (${SIGNER_AMOUNT_SATS} sats)
  - Recipient: $WITHDRAWAL_ADDRESS
  - Amount (sats): $WITHDRAW_AMOUNT_SATS"