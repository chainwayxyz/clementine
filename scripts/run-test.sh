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
    "verifier"
    "verifier"
    "verifier"
    "verifier"
    "operator"
    "operator"
    "aggregator"
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
    filename=$(basename -- "$role$i")
    log_file="logs/${filename%.toml}.jsonl"

    if [ "$role" == "aggregator" ]; then
        echo "Waiting 1 second before starting aggregator..."
        sleep 1
    fi

    echo "Starting process with role $role, logging to $log_file"

    PROTOCOL_CONFIG_PATH=core/src/config/protocol_paramset.toml DBG_PACKAGE_HEX=1 RUST_MIN_STACK=33554432 RISC0_SKIP_BUILD=1 JSON_LOGS=1 RUST_LOG=debug "$BIN_PATH" "$role" > "$log_file" 2> "logs/${filename%.toml}_error.log" &
    pids+=("$!")

    # Small delay between starts
    sleep 1
done

# Wait for all processes
wait
