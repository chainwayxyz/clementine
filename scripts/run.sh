#!/bin/bash

echo "Run this script in the root of the project"

# Check if BITVM_CACHE_PATH is set, if not try to find cache file automatically
if [ -z "$BITVM_CACHE_PATH" ]; then
    if [ -f "./core/bitvm_cache.bin" ]; then
        export BITVM_CACHE_PATH="./core/bitvm_cache.bin"
        echo "Using cache file: $BITVM_CACHE_PATH"
    elif [ -f "./bitvm_cache.bin" ]; then
        export BITVM_CACHE_PATH="./bitvm_cache.bin"
        echo "Using cache file: $BITVM_CACHE_PATH"
    else
        echo "BITVM_CACHE_PATH is not set and no cache file found in ./core/bitvm_cache.bin or ./bitvm_cache.bin"
        echo "Please set BITVM_CACHE_PATH or ensure a cache file exists in one of the above locations."
        exit 1
    fi
fi

export READ_CONFIG_FROM_ENV=1
export READ_PARAMSET_FROM_ENV=1

export PROTOCOL_PARAMSET=${PROTOCOL_PARAMSET:=regtest}
export HOST=${HOST:=127.0.0.1}
export WINTERNITZ_SECRET_KEY=${WINTERNITZ_SECRET_KEY:=2222222222222222222222222222222222222222222222222222222222222222}
export VERIFIERS_PUBLIC_KEYS=${VERIFIERS_PUBLIC_KEYS:="034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa,02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27,023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1,032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"}
export OPERATOR_XONLY_PKS=${OPERATOR_XONLY_PKS:="4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa,466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"}
export NUM_OPERATORS=${NUM_OPERATORS:=2}
export OPERATOR_WITHDRAWAL_FEE_SATS=${OPERATOR_WITHDRAWAL_FEE_SATS:=100000}

export CITREA_CHAIN_ID=${CITREA_CHAIN_ID:=5115}
export CITREA_RPC_URL=${CITREA_RPC_URL:="http://127.0.0.1:12345"}
export CITREA_LIGHT_CLIENT_PROVER_URL=${CITREA_LIGHT_CLIENT_PROVER_URL:="http://127.0.0.1:12346"}
export BRIDGE_CONTRACT_ADDRESS=${BRIDGE_CONTRACT_ADDRESS:="3100000000000000000000000000000000000002"}
export VERIFIER_ENDPOINTS=${VERIFIER_ENDPOINTS:="https://127.0.0.1:17001,https://127.0.0.1:17002,https://127.0.0.1:17003,https://127.0.0.1:17004"}
export OPERATOR_ENDPOINTS=${OPERATOR_ENDPOINTS:="https://127.0.0.1:17005,https://127.0.0.1:17006"}
export BITCOIN_RPC_URL=${BITCOIN_RPC_URL:="http://127.0.0.1:18443"}
export BITCOIN_RPC_USER=${BITCOIN_RPC_USER:=admin}
export BITCOIN_RPC_PASSWORD=${BITCOIN_RPC_PASSWORD:=admin}
export DB_HOST=${DB_HOST:=127.0.0.1}
export DB_PORT=${DB_PORT:=5432}
export DB_USER=${DB_USER:=clementine}
export DB_PASSWORD=${DB_PASSWORD:=clementine}
export DB_NAME=${DB_NAME:=clementine}
export PROTOCOL_CONFIG_PATH=${PROTOCOL_CONFIG_PATH:="core/src/config/protocol_paramset.toml"}
export DBG_PACKAGE_HEX=${DBG_PACKAGE_HEX:=1}
export RUST_MIN_STACK=${RUST_MIN_STACK:=33554432}
export RISC0_SKIP_BUILD=${RISC0_SKIP_BUILD:=1}
export LOG_FORMAT=json
export RUST_LOG=info
# TLS
export CA_CERT_PATH=${CA_CERT_PATH:="core/certs/ca/ca.pem"}
export SERVER_CERT_PATH=${SERVER_CERT_PATH:="core/certs/server/server.pem"}
export SERVER_KEY_PATH=${SERVER_KEY_PATH:="core/certs/server/server.key"}
export CLIENT_CERT_PATH=${CLIENT_CERT_PATH:="core/certs/server/server.pem"}
export CLIENT_KEY_PATH=${CLIENT_KEY_PATH:="core/certs/server/server.key"}
export AGGREGATOR_CERT_PATH=${AGGREGATOR_CERT_PATH:="core/certs/server/server.pem"}
export CLIENT_VERIFICATION=${CLIENT_VERIFICATION:=1}
export DISABLE_NOFN_CHECK=${DISABLE_NOFN_CHECK:=1}
export OPERATOR_WITHDRAWAL_FEE_SATS=${OPERATOR_WITHDRAWAL_FEE_SATS:=100000}

export SECURITY_COUNCIL=${SECURITY_COUNCIL:="1:50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"}
export HEADER_CHAIN_PROOF_BATCH_SIZE=100

# System parameters
export NETWORK=${NETWORK:=regtest}
export NUM_SIGNED_ROUND_TXS=${NUM_SIGNED_ROUND_TXS:=200}
export TOTAL_NUM_ROUNDS=${TOTAL_NUM_ROUNDS:=600}
export NUM_KICKOFFS_PER_ROUND=${NUM_KICKOFFS_PER_ROUND:=100}
export NUM_SIGNED_KICKOFFS=${NUM_SIGNED_KICKOFFS:=5}
export BRIDGE_AMOUNT=${BRIDGE_AMOUNT:=1000000000}
export KICKOFF_AMOUNT=${KICKOFF_AMOUNT:=0}
export OPERATOR_CHALLENGE_AMOUNT=${OPERATOR_CHALLENGE_AMOUNT:=200000000}
export COLLATERAL_FUNDING_AMOUNT=${COLLATERAL_FUNDING_AMOUNT:=200000000}
export KICKOFF_BLOCKHASH_COMMIT_LENGTH=${KICKOFF_BLOCKHASH_COMMIT_LENGTH:=40}
export WATCHTOWER_CHALLENGE_BYTES=${WATCHTOWER_CHALLENGE_BYTES:=144}
export WINTERNITZ_LOG_D=${WINTERNITZ_LOG_D:=4}
export USER_TAKES_AFTER=${USER_TAKES_AFTER:=200}
export OPERATOR_CHALLENGE_TIMEOUT_TIMELOCK=${OPERATOR_CHALLENGE_TIMEOUT_TIMELOCK:=144}
export OPERATOR_CHALLENGE_NACK_TIMELOCK=${OPERATOR_CHALLENGE_NACK_TIMELOCK:=432}
export DISPROVE_TIMEOUT_TIMELOCK=${DISPROVE_TIMEOUT_TIMELOCK:=720}
export ASSERT_TIMEOUT_TIMELOCK=${ASSERT_TIMEOUT_TIMELOCK:=576}
export OPERATOR_REIMBURSE_TIMELOCK=${OPERATOR_REIMBURSE_TIMELOCK:=12}
export WATCHTOWER_CHALLENGE_TIMEOUT_TIMELOCK=${WATCHTOWER_CHALLENGE_TIMEOUT_TIMELOCK:=288}
export TIME_TO_SEND_WATCHTOWER_CHALLENGE=${TIME_TO_SEND_WATCHTOWER_CHALLENGE:=216}
export LATEST_BLOCKHASH_TIMEOUT_TIMELOCK=${LATEST_BLOCKHASH_TIMEOUT_TIMELOCK:=360}
export FINALITY_DEPTH=${FINALITY_DEPTH:=100}
export START_HEIGHT=${START_HEIGHT:=190}
export GENESIS_HEIGHT=${GENESIS_HEIGHT:=0}
export GENESIS_CHAIN_STATE_HASH=${GENESIS_CHAIN_STATE_HASH:=5f7302ad16c8bd9ef2f3be00c8199a86f9e0ba861484abb4af5f7e457f8c2216}
export BRIDGE_NONSTANDARD=${BRIDGE_NONSTANDARD:=false}
export TELEMETRY_HOST=0.0.0.0
export TELEMETRY_PORT=8081
export RUST_MIN_STACK=33554432
export RISC0_DEV_MODE=1

# Define databases to drop and recreate
databases=("clementine0" "clementine1" "clementine2" "clementine3")

# Clear logs folder
rm -rf logs/*

export PGUSER=${PGUSER:=clementine}
export PGPASSWORD=${PGPASSWORD:=clementine}
export PGHOST=${PGHOST:=127.0.0.1}
export PGPORT=${PGPORT:=5432}

# Drop and recreate databases
for db in "${databases[@]}"; do
    echo "Dropping database: $db"
    dropdb "$db" 2>/dev/null
    echo "Creating database: $db"
    createdb -O $DB_USER "$db"
done

# Build the project once
echo "Building clementine-core..."
cargo build --package clementine-core --all-features --bin clementine-core
if [ $? -ne 0 ]; then
    echo "Build failed, exiting..."
    exit 1
fi
BIN_PATH="./target/debug/clementine-core"

# Corresponding roles
roles=(
    "verifier"
    "verifier"
    "verifier"
    "verifier"
    "operator"
    "operator"
    "aggregator"
)
role_indexes=(
    0
    1
    2
    3
    0
    1
    0
)

# Store PIDs
pids=()

# Function to kill all processes on exit
cleanup() {
    echo "Stopping all processes..."
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null
    done
    exit 1
}

# Trap Ctrl+C and call cleanup
trap cleanup SIGINT

# Run processes in the background
for i in "${!roles[@]}"; do
    role="${roles[$i]}"
    index="${role_indexes[$i]}"
    filename=$(basename -- "$role$index")
    log_file="logs/${filename%.toml}.jsonl"

    # Set dynamic config vars for each actor
    secret_key_digit=$((index + 1))
    export SECRET_KEY=$(printf "%064d" | tr '0' "$secret_key_digit")
    export PORT=$((17000 + i + 1))
    export DB_NAME="${databases[$index]}"

    # Aggregator overwrites
    if [ $role == "aggregator" ]; then
        export TELEMETRY_PORT=8082
        export PORT=$((17000))
        export SECRET_KEY=$(printf "%064d" | tr '0' "1")
    fi

    echo "Starting process with role $role, logging to $log_file"
    echo "Secret key is $SECRET_KEY"
    echo "Port is $PORT"

    "$BIN_PATH" "$role" > "$log_file" 2> "logs/${filename%.toml}_error.log" &
    pids+=("$!")

    # Small delay between starts
    sleep 1
done

# Wait for all processes
wait
