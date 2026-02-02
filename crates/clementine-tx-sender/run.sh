#!/usr/bin/env bash
set -euo pipefail

# Standalone txsender runner (JSON-RPC enabled) + smoke test.
#
# Usage:
#   chmod +x crates/clementine-tx-sender/run.sh
#   crates/clementine-tx-sender/run.sh
#
# Override any env var by exporting it before running the script.

# --- Required config ---
export NETWORK="${NETWORK:-regtest}"

# 32-byte secp256k1 secret key as 64 hex chars.
# "111...1" is commonly used in Clementine configs.
export SECRET_KEY="${SECRET_KEY:-1111111111111111111111111111111111111111111111111111111111111111}"

# Optional Citrea DA blob signing key. If not set, SECRET_KEY is used.
export PRIVATE_DA_KEY="${PRIVATE_DA_KEY:-}"

# Postgres
export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-5432}"
export DB_USER="${DB_USER:-clementine}"
export DB_PASSWORD="${DB_PASSWORD:-clementine}"
export DB_NAME="${DB_NAME:-clementine_txs_standalone}"

# Bitcoin Core RPC
export BITCOIN_RPC_URL="${BITCOIN_RPC_URL:-http://127.0.0.1:18443}"
export BITCOIN_RPC_USER="${BITCOIN_RPC_USER:-admin}"
export BITCOIN_RPC_PASSWORD="${BITCOIN_RPC_PASSWORD:-admin}"

# Enable JSON-RPC server (required by standalone main).
export TX_SENDER_JSONRPC_BIND="${TX_SENDER_JSONRPC_BIND:-127.0.0.1}"
export TX_SENDER_JSONRPC_PORT="${TX_SENDER_JSONRPC_PORT:-3030}"
export TX_SENDER_POLL_DELAY_MS="${TX_SENDER_POLL_DELAY_MS:-500}"
export TX_SENDER_FINALITY_DEPTH="${TX_SENDER_FINALITY_DEPTH:-1}"

# Extra bitcoin-cli flags used for the smoke test.
export BITCOIN_CLI_RPCPORT="${BITCOIN_CLI_RPCPORT:-18443}"
export BITCOIN_CLI_RPCUSER="${BITCOIN_CLI_RPCUSER:-admin}"
export BITCOIN_CLI_RPCPASSWORD="${BITCOIN_CLI_RPCPASSWORD:-admin}"
export BITCOIN_CLI_WALLET="${BITCOIN_CLI_WALLET:-admin}"

# Amount to send (BTC) in the smoke test.
export SMOKE_TX_AMOUNT_BTC="${SMOKE_TX_AMOUNT_BTC:-0.0001}"

# --- helpers ---
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

bitcoin_cli() {
  bitcoin-cli -regtest \
    -rpcport="${BITCOIN_CLI_RPCPORT}" \
    -rpcuser="${BITCOIN_CLI_RPCUSER}" \
    -rpcpassword="${BITCOIN_CLI_RPCPASSWORD}" \
    -rpcwallet="${BITCOIN_CLI_WALLET}" \
    "$@"
}

reset_db() {
  require_cmd psql
  export PGPASSWORD="${DB_PASSWORD}"

  # Drop & recreate database (clean slate).
  psql -v ON_ERROR_STOP=1 \
    -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
    -c "DROP DATABASE IF EXISTS \"${DB_NAME}\";" \
    -c "CREATE DATABASE \"${DB_NAME}\" WITH OWNER \"${DB_USER}\";"
}

wait_for_jsonrpc() {
  local url="$1"
  local deadline="${2:-30}" # seconds

  local start_ts
  start_ts="$(date +%s)"
  while true; do
    # Send a request; if server is up we'll get *some* HTTP response body.
    # We intentionally DO NOT use --fail because jsonrpsee may return HTTP 400 for JSON-RPC errors.
    if curl -sS \
      -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"send_tx","params":[]}' \
      "${url}" >/dev/null 2>&1; then
      return 0
    fi

    if (( "$(date +%s)" - start_ts > deadline )); then
      echo "Timed out waiting for txsender JSON-RPC at ${url}" >&2
      return 1
    fi
    sleep 0.2
  done
}

create_signed_tx_hex() {
  local dest_addr
  dest_addr="$(bitcoin_cli getnewaddress)"

  # Create + fund + sign a raw tx without broadcasting.
  local raw
  raw="$(bitcoin_cli -named createrawtransaction \
    inputs='[]' \
    outputs="{\"${dest_addr}\":${SMOKE_TX_AMOUNT_BTC}}" \
    locktime=0)"

  local funded
  funded="$(bitcoin_cli fundrawtransaction "${raw}" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["hex"])')"

  local signed
  signed="$(bitcoin_cli signrawtransactionwithwallet "${funded}" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["hex"])')"

  echo "${signed}"
}

txid_from_rawtx() {
  local raw_tx_hex="$1"
  bitcoin_cli decoderawtransaction "${raw_tx_hex}" \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["txid"])'
}

ensure_mempool_accepts() {
  local raw_tx_hex="$1"

  # testmempoolaccept returns an array with a single result object.
  bitcoin_cli testmempoolaccept "[\"${raw_tx_hex}\"]" \
    | python3 -c 'import sys, json; r=json.load(sys.stdin)[0];
allowed=r.get("allowed", False);
if not allowed:
  raise SystemExit("testmempoolaccept rejected tx: %s" % r)
print("mempool accept OK (fee=%s vsize=%s)" % (r.get("fees",{}).get("base"), r.get("vsize")))'
}

send_via_jsonrpc() {
  local url="$1"
  local raw_tx_hex="$2"

  local req
  req="$(RAW_TX_HEX="${raw_tx_hex}" python3 - <<'PY'
import json, os
raw_tx_hex = os.environ["RAW_TX_HEX"]
payload = {
  "jsonrpc":"2.0",
  "id": 1,
  "method": "send_tx",
  "params": [{
    "tx_metadata": None,
    "signed_tx_hex": raw_tx_hex,
    "fee_paying_type": "NoFunding",
    "rbf_signing_info": None,
    "cancel_outpoints": [],
    "cancel_txids": [],
    "activate_txids": [],
    "activate_outpoints": [],
  }],
}
print(json.dumps(payload))
PY
)"

  curl -sS \
    -H 'content-type: application/json' \
    --data "${req}" \
    "${url}" \
    | python3 -c 'import sys, json; r=json.load(sys.stdin); 
if "error" in r: 
  raise SystemExit("JSON-RPC error: %s" % r["error"])
print(r["result"])'
}

wait_for_mempool() {
  local txid="$1"
  local deadline="${2:-120}" # seconds
  local start_ts
  start_ts="$(date +%s)"

  while true; do
    if bitcoin_cli getmempoolentry "${txid}" >/dev/null 2>&1; then
      return 0
    fi
    if (( "$(date +%s)" - start_ts > deadline )); then
      echo "Timed out waiting for tx ${txid} to appear in mempool" >&2
      return 1
    fi
    sleep 1
  done
}

mine_one_block() {
  local miner_addr
  miner_addr="$(bitcoin_cli getnewaddress)"
  bitcoin_cli generatetoaddress 1 "${miner_addr}" >/dev/null
}

ensure_wallet_funded() {
  # Only mine if wallet balance is too low; avoids bloating the regtest chain.
  #
  # We need enough to create+fund+sign a tx and pay fees.
  local min_required_btc="${1:-0.001}"

  local bal
  bal="$(bitcoin_cli getbalance \
    | python3 -c 'import sys; print(float(sys.stdin.read().strip() or "0"))')"

  python3 - <<PY
import sys
bal = float("${bal}")
need = float("${min_required_btc}")
if bal + 1e-12 < need:
  sys.exit(1)
PY
  if [[ $? -eq 0 ]]; then
    echo "Wallet already funded (balance=${bal} BTC). Skipping mining."
    return 0
  fi

  echo "Wallet balance=${bal} BTC, mining to reach >= ${min_required_btc} BTC..."
  local fund_addr
  fund_addr="$(bitcoin_cli getnewaddress)"
  # 101 blocks to mature coinbase.
  bitcoin_cli generatetoaddress 101 "${fund_addr}" >/dev/null
}

assert_confirmed() {
  local txid="$1"
  local conf
  conf="$(bitcoin_cli getrawtransaction "${txid}" true \
    | python3 -c 'import sys, json; print(json.load(sys.stdin).get("confirmations", 0))')"
  if [[ "${conf}" -lt 1 ]]; then
    echo "Expected tx ${txid} to be confirmed, confirmations=${conf}" >&2
    return 1
  fi
}

# Optional mempool.space fee endpoint (leave unset to use node fees only)
# export MEMPOOL_API_HOST="https://mempool.space/"
# export MEMPOOL_API_ENDPOINT="api/v1/fees/recommended"

# --- smoke-test flow ---
require_cmd curl
require_cmd python3
require_cmd bitcoin-cli

echo "Resetting Postgres DB ${DB_NAME}..."
reset_db

echo "Ensuring regtest wallet has funds..."
ensure_wallet_funded "0.001"

echo "Creating signed raw tx (not broadcast)..."
RAW_TX_HEX="$(create_signed_tx_hex)"
TXID="$(txid_from_rawtx "${RAW_TX_HEX}")"
echo "Prepared txid: ${TXID}"
echo "Checking tx is mempool-acceptable (sufficient fees)..."
ensure_mempool_accepts "${RAW_TX_HEX}"

echo "Starting standalone txsender (JSON-RPC on ${TX_SENDER_JSONRPC_BIND}:${TX_SENDER_JSONRPC_PORT})..."
cargo run -p clementine-tx-sender --features standalone &
TXSENDER_PID="$!"
trap 'echo "Stopping txsender (pid=${TXSENDER_PID})"; kill "${TXSENDER_PID}" >/dev/null 2>&1 || true' EXIT

JSONRPC_URL="http://${TX_SENDER_JSONRPC_BIND}:${TX_SENDER_JSONRPC_PORT}"
wait_for_jsonrpc "${JSONRPC_URL}" 30

echo "Sending tx to txsender via JSON-RPC..."
TRY_TO_SEND_ID="$(send_via_jsonrpc "${JSONRPC_URL}" "${RAW_TX_HEX}")"
echo "txsender try_to_send_id: ${TRY_TO_SEND_ID}"

echo "Waiting for tx to enter mempool..."
wait_for_mempool "${TXID}" 120

echo "Mining 1 block..."
mine_one_block

echo "Checking confirmations..."
assert_confirmed "${TXID}"

echo "OK: tx ${TXID} confirmed."

