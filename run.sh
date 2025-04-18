#!/bin/bash

# Define databases to drop and recreate
databases=("clementine0" "clementine1" "clementine2" "clementine3")

# Clear logs folder
rm -rf logs/*

Drop and recreate databases
for db in "${databases[@]}"; do
    echo "Dropping database: $db"
    dropdb "$db" 2>/dev/null
    echo "Creating database: $db"
    createdb -O clementine "$db"
done


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

ports=(
    17001
    17002
    17003
    17004
    17005
    17006
    17000
)

secret_keys=(
    1111111111111111111111111111111111111111111111111111111111111111
    2222222222222222222222222222222222222222222222222222222222222222
    3333333333333333333333333333333333333333333333333333333333333333
    4444444444444444444444444444444444444444444444444444444444444444
    1111111111111111111111111111111111111111111111111111111111111111
    2222222222222222222222222222222222222222222222222222222222222222
    1111111111111111111111111111111111111111111111111111111111111111
)

db_names=(
    "clementine0"
    "clementine1"
    "clementine2"
    "clementine3"
    "clementine0"
    "clementine1"
    "clementine0"
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



# Actor configuration
export PROTOCOL_PARAMSET=signet
export HOST=127.0.0.1
# export PORT=80

# Bitcoin RPC
export BITCOIN_RPC_URL=http://127.0.0.1:38332
export BITCOIN_RPC_USER=bitcoin
export BITCOIN_RPC_PASSWORD=bitcoin

# PostgreSQL
export DB_HOST=127.0.0.1
export DB_PORT=5432
export DB_USER=clementine
export DB_PASSWORD=clementine

# Citrea
export CITREA_RPC_URL=http://127.0.0.1:12345
export CITREA_LIGHT_CLIENT_PROVER_URL=http://127.0.0.1:12348
export BRIDGE_CONTRACT_ADDRESS=3100000000000000000000000000000000000002

# Header chain
export HEADER_CHAIN_PROOF_PATH=/Users/ekrembal/Developer/chainway/clementine/core/tests/data/first_1.bin

# Endpoints for aggregator
export VERIFIER_ENDPOINTS=http://127.0.0.1:17001,http://127.0.0.1:17002,http://127.0.0.1:17003,http://127.0.0.1:17004
export OPERATOR_ENDPOINTS=http://127.0.0.1:17005,http://127.0.0.1:17006

export OPERATOR_WITHDRAWAL_FEE_SATS=100000

# System parameters
export NETWORK=signet
export NUM_ROUND_TXS=10
export NUM_KICKOFFS_PER_ROUND=50
export NUM_SIGNED_KICKOFFS=3
export BRIDGE_AMOUNT=1000000000
export KICKOFF_AMOUNT=55000
export OPERATOR_CHALLENGE_AMOUNT=200000000
export COLLATERAL_FUNDING_AMOUNT=200000000
export KICKOFF_BLOCKHASH_COMMIT_LENGTH=40
export WATCHTOWER_CHALLENGE_BYTES=144
export WINTERNITZ_LOG_D=4
export USER_TAKES_AFTER=200
export OPERATOR_CHALLENGE_TIMEOUT_TIMELOCK=144
export OPERATOR_CHALLENGE_NACK_TIMELOCK=432
export DISPROVE_TIMEOUT_TIMELOCK=720
export ASSERT_TIMEOUT_TIMELOCK=576
export OPERATOR_REIMBURSE_TIMELOCK=12
export WATCHTOWER_CHALLENGE_TIMEOUT_TIMELOCK=288
export TIME_TO_SEND_WATCHTOWER_CHALLENGE=216
export TIME_TO_DISPROVE=648
export FINALITY_DEPTH=1
export START_HEIGHT=1

# Misc
# export ENVIRONMENT=CORE
# export IS_PRODUCTION=false
export JSON_LOGS=1
export RUST_LOG=debug
export RUST_MIN_STACK=33554432
export BITVM_CACHE_PATH=/Users/ekrembal/Developer/chainway/clementine/core/bitvm_cache.bin
export DBG_PACKAGE_HEX=1
export RISC0_SKIP_BUILD=1



# Build the project once
echo "Building clementine-core..."
cargo build --release --package clementine-core --bin clementine-core
if [ $? -ne 0 ]; then
    echo "Build failed, exiting..."
    exit 1
fi

# Path to the compiled binary
BIN_PATH="./target/release/clementine-core"



# Run processes in the background
for i in "${!configs[@]}"; do
    config="${configs[$i]}"
    role="${roles[$i]}"
    filename=$(basename -- "$config")
    log_file="logs/${filename%.toml}.jsonl"
    
    if [ "$role" = "aggregator" ]; then
        echo "Waiting 3 second before starting aggregator..."
        sleep 30
    fi
    
    echo "Starting process for $config with role $role, logging to $log_file"
    
    export SECRET_KEY=${secret_keys[$i]}
    export WINTERNITZ_SECRET_KEY=${secret_keys[$i]}
    export PORT=${ports[$i]}
    export DB_NAME=${db_names[$i]}

    "$BIN_PATH" "$role" > "$log_file" 2> "logs/${filename%.toml}_error.log" &
    # print the running command
    echo "Running command: $BIN_PATH $role > $log_file 2> logs/${filename%.toml}_error.log"
    pids+=("$!")

    sleep 1 # Small delay between starts
done

# print all pids
echo "PIDs: ${pids[@]}"

# Wait for all processes
wait
