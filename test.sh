#!/bin/bash

count=1
temp_log="running_test.tmp"

echo "🚀 Starting loop. Output is being captured to $temp_log..."

while true; do
    # 1. Run the command and redirect (>) both stdout and stderr (2>&1) to the temp file
    RUST_BACKTRACE=1 DBG_PACKAGE_HEX=1 RUST_MIN_STACK=33554432 RISC0_SKIP_BUILD=0 JSON_LOGS=1 RUST_LOG=info TXSENDER_DBG_INACTIVE_TXS=0 ENABLE_HEADER_CHAIN_PROVER=1 RISC0_DEV_MODE=1 cargo test bitvm_disprove_scripts::disprove_script_test_corrupted_assert --all-features --release -- --ignored --nocapture > "$temp_log" 2>&1
    
    # 2. Check the exit code of the command
    if [ $? -ne 0 ]; then
        fail_log="failure_run_${count}.log"
        mv "$temp_log" "$fail_log"
        echo "❌ FAILURE DETECTED on run #$count"
        echo "📄 Logs saved to: $fail_log"
        
        # Optional: Print the last 20 lines so you see the error immediately
        echo "--- Last 20 lines of failure ---"
        tail -n 20 "$fail_log"
        
        # Beep sound
        echo -e "\a"
        break
    else
        # 3. If passed, remove the temp file and continue
        echo "✅ Run #$count PASSED. Deleting log and restarting..."
        rm "$temp_log"
        ((count++))
    fi
done