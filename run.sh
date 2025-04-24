#!/bin/bash

# Define databases to drop and recreate
databases=("clementine0" "clementine1" "clementine2" "clementine3")

# Clear logs folder
rm -rf logs/*

# Drop and recreate databases
for db in "${databases[@]}"; do
    echo "Dropping database: $db"
    dropdb -h localhost -p 5432 "$db"
    echo "Creating database: $db"
    createdb -h localhost -p 5432 -O clementine "$db"
done

# Build the project once
echo "Building clementine-core..."
cargo build --package clementine-core --bin clementine-core
if [ $? -ne 0 ]; then
    echo "Build failed, exiting..."
    exit 1
fi  

# Path to the compiled binary
BIN_PATH="./target/debug/clementine-core"

# Config files
configs=(
    "core/configs/verifier0.toml"
    "core/configs/verifier1.toml"
    "core/configs/verifier2.toml"
    "core/configs/verifier3.toml"
    "core/configs/operator0.toml"
    "core/configs/operator1.toml"
    "core/configs/aggregator.toml"
)

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
for i in "${!configs[@]}"; do
    config="${configs[$i]}"
    role="${roles[$i]}"
    filename=$(basename -- "$config")
    log_file="logs/${filename%.toml}.jsonl"
    
    if [ "$role" == "aggregator" ]; then
        echo "Waiting some time before starting aggregator..."
        sleep 40
    fi
    
    echo "Starting process for $config with role $role, logging to $log_file"
    echo "Command: BITVM_CACHE_PATH=/home/atacan/chainway/clementine/core/bitvm_cache.bin PROTOCOL_CONFIG_PATH=core/src/config/protocol_paramset.toml DBG_PACKAGE_HEX=1 RUST_MIN_STACK=33554432 RISC0_SKIP_BUILD=1 JSON_LOGS=1 RUST_LOG=info,sqlx=debug \"$BIN_PATH\" \"$role\" \"$config\" > \"$log_file\" 2> \"logs/${filename%.toml}_error.log\""
    
    # if [ "$role" != "aggregator" ]; then
        BITVM_CACHE_PATH=/home/atacan/chainway/clementine/core/bitvm_cache.bin PROTOCOL_CONFIG_PATH=core/src/config/protocol_paramset.toml DBG_PACKAGE_HEX=1 RUST_MIN_STACK=33554432 RISC0_SKIP_BUILD=1 JSON_LOGS=1 RUST_LOG=info "$BIN_PATH" "$role" "$config" > "$log_file" 2> "logs/${filename%.toml}_error.log" &
        pids+=("$!")
    # else
    #     echo "Skipping aggregator role"
    # fi
    sleep 1 # Small delay between starts

done

# Wait for all processes
wait