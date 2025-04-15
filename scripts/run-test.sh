#!/bin/bash

echo "Run this script in the root of the project"

# Check if BITVM_CACHE_PATH is set
if [ -z "$BITVM_CACHE_PATH" ]; then
    echo "BITVM_CACHE_PATH is not set. Please set it before run."
    exit 1
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

# Path to the compiled binary
BIN_PATH="./target/release/clementine-core"

# Corresponding roles
roles=(
    ("verifier" 0)
    ("verifier" 1)
    ("verifier" 2)
    ("verifier" 3)
    ("verifier" 4)
    ("operator" 0)
    ("operator" 1)
    ("aggregator" 0)
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

# Set static env vars
HOST=127.0.0.1

WINTERNITZ_SECRET_KEY=2222222222222222222222222222222222222222222222222222222222222222

VERIFIERS_PUBLIC_KEYS=034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa,02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27,023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1,032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
NUM_VERIFIERS=4

OPERATOR_XONLY_PKS=4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa,466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27
NUM_OPERATORS=2
OPERATOR_WITHDRAWAL_FEE_SATS=100000

CITREA_RPC_URL=http://127.0.0.1:12345
CITREA_LIGHT_CLIENT_PROVER_URL=http://127.0.0.1:12346
BRIDGE_CONTRACT_ADDRESS=3100000000000000000000000000000000000002

HEADER_CHAIN_PROOF_PATH=../core/tests/data/first_1.bin

VERIFIER_ENDPOINTS=http://127.0.0.1:17001,http://127.0.0.1:17002,http://127.0.0.1:17003,http://127.0.0.1:17004
OPERATOR_ENDPOINTS=http://127.0.0.1:17005,http://127.0.0.1:17006

PROTOCOL_PARAMSET=regtest

# Run processes in the background
for i in "${!roles[@]}"; do
    if [ -n "${roles[$i]}" ]; then
        IFS=":" read -r role index <<< "${roles[$i]}"
    else
        echo "Error: roles[$i] is empty or undefined."
        exit 1
    fi
    filename=$(basename -- "$role$index")
    log_file="logs/${filename%.toml}.jsonl"

    if [ "$role" == "aggregator" ]; then
        echo "Waiting 1 second before starting aggregator..."
        sleep 1
    fi

    # Set dynamic config vars for each actor
    SECRET_KEY=$(((index + 1) % 64))
    PORT=$((17000 + i + 1))

    # Aggregator overwrites
    if role == "aggregator" ]; then
        PORT=$((17000))
        SECRET_KEY=$((0 % 64))
    fi

    echo "Starting process with role $role, logging to $log_file"
    echo "Secret key is $SECRET_KEY"
    echo "Port is $PORT"

    PROTOCOL_CONFIG_PATH=core/src/config/protocol_paramset.toml DBG_PACKAGE_HEX=1 RUST_MIN_STACK=33554432 RISC0_SKIP_BUILD=1 JSON_LOGS=1 RUST_LOG=debug "$BIN_PATH" "$role" > "$log_file" 2> "logs/${filename%.toml}_error.log" &
    pids+=("$!")

    # Small delay between starts
    sleep 1
done

# Wait for all processes
wait
