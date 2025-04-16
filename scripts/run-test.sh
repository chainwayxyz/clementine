#!/bin/bash

echo "Run this script in the root of the project"

# Check if BITVM_CACHE_PATH is set
if [ -z "$BITVM_CACHE_PATH" ]; then
    echo "BITVM_CACHE_PATH is not set. Please set it before run."
    exit 1
fi

if [ -z $PROTOCOL_PARAMSET ]; then
    export PROTOCOL_PARAMSET="regtest"
fi
if [ -z $HOST ]; then
    export HOST="127.0.0.1"
fi
if [ -z $WINTERNITZ_SECRET_KEY ]; then
    export WINTERNITZ_SECRET_KEY="2222222222222222222222222222222222222222222222222222222222222222"
fi
if [ -z "$VERIFIERS_PUBLIC_KEYS" ]; then
    export VERIFIERS_PUBLIC_KEYS="034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa,02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27,023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1,032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
fi
if [ -z "$OPERATOR_XONLY_PKS" ]; then
    export OPERATOR_XONLY_PKS="4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa,466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"
fi
if [ -z "$NUM_OPERATORS" ]; then
    export NUM_OPERATORS="2"
fi
if [ -z "$OPERATOR_WITHDRAWAL_FEE_SATS" ]; then
    export OPERATOR_WITHDRAWAL_FEE_SATS="100000"
fi
if [ -z "$CITREA_RPC_URL" ]; then
    export CITREA_RPC_URL="http://127.0.0.1:12345"
fi
if [ -z "$CITREA_LIGHT_CLIENT_PROVER_URL" ]; then
    export CITREA_LIGHT_CLIENT_PROVER_URL="http://127.0.0.1:12346"
fi
if [ -z "$BRIDGE_CONTRACT_ADDRESS" ]; then
    export BRIDGE_CONTRACT_ADDRESS="3100000000000000000000000000000000000002"
fi
if [ -z "$HEADER_CHAIN_PROOF_PATH" ]; then
    export HEADER_CHAIN_PROOF_PATH="../core/tests/data/first_1.bin"
fi
if [ -z "$VERIFIER_ENDPOINTS" ]; then
    export VERIFIER_ENDPOINTS="http://127.0.0.1:17001,http://127.0.0.1:17002,http://127.0.0.1:17003,http://127.0.0.1:17004"
fi
if [ -z "$OPERATOR_ENDPOINTS" ]; then
    export OPERATOR_ENDPOINTS="http://127.0.0.1:17005,http://127.0.0.1:17006"
fi
if [ -z "$BITCOIN_RPC_URL" ]; then
    export BITCOIN_RPC_URL="http://127.0.0.1:18443/wallet/admin"
fi
if [ -z "$BITCOIN_RPC_USER" ]; then
    export BITCOIN_RPC_USER="admin"
fi
if [ -z "$BITCOIN_RPC_PASSWORD" ]; then
    export BITCOIN_RPC_PASSWORD="admin"
fi
if [ -z "$DB_HOST" ]; then
    export DB_HOST="127.0.0.1"
fi
if [ -z "$DB_PORT" ]; then
    export DB_PORT="5432"
fi
if [ -z "$DB_USER" ]; then
    export DB_USER="clementine"
fi
if [ -z "$DB_PASSWORD" ]; then
    export DB_PASSWORD="clementine"
fi
if [ -z "$DB_NAME" ]; then
    export DB_NAME="clementine"
fi

if [ -z "$PROTOCOL_CONFIG_PATH" ]; then
    export PROTOCOL_CONFIG_PATH="core/src/config/protocol_paramset.toml"
fi
if [ -z "$DBG_PACKAGE_HEX" ]; then
    export DBG_PACKAGE_HEX="1"
fi
if [ -z "$RUST_MIN_STACK" ]; then
    export RUST_MIN_STACK="33554432"
fi
if [ -z "$RISC0_SKIP_BUILD" ]; then
    export RISC0_SKIP_BUILD="1"
fi
if [ -z "$JSON_LOGS" ]; then
    export JSON_LOGS="1"
fi
if [ -z "$RUST_LOG" ]; then
    export RUST_LOG="debug"
fi

# Define databases to drop and recreate
databases=("clementine0" "clementine1" "clementine2" "clementine3")

# Clear logs folder
rm -rf logs/*

# Drop and recreate databases
for db in "${databases[@]}"; do
    echo "Dropping database: $db"
    dropdb "$db" 2>/dev/null
    echo "Creating database: $db"
    createdb -O $DB_USER "$db"
done

# Build the project once
echo "Building clementine-core..."
cargo build --release --package clementine-core --bin clementine-core
if [ $? -ne 0 ]; then
    echo "Build failed, exiting..."
    exit 1
fi
BIN_PATH="./target/release/clementine-core"

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

    if [ "$role" == "aggregator" ]; then
        echo "Waiting 1 second before starting aggregator..."
        sleep 1
    fi

    # Set dynamic config vars for each actor
    secret_key_digit=$((index + 1))
    export SECRET_KEY=$(printf "%064d" | tr '0' "$secret_key_digit")
    export PORT=$((17000 + i + 1))
    export DB_NAME="${databases[$index]}"

    # Aggregator overwrites
    if [ $role == "aggregator" ]; then
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
