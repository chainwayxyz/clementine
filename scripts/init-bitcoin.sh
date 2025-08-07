#!/bin/bash

set -e

echo "[Init] Waiting for bitcoind to start..."
until bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=20443 getblockchaininfo > /dev/null 2>&1; do
  sleep 1
done

for WALLET in admin sequencer-wallet batch-prover-wallet; do
  if bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=20443 listwalletdir \
    | grep -q "\"name\": \"$WALLET\""; then
    echo "Wallet $WALLET exists"
    bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=20443 loadwallet "$WALLET" 2>/dev/null || true
  else
    echo "Creating wallet $WALLET"
    bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=20443 createwallet "$WALLET"
  fi

  ADDR=$(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=20443 -rpcwallet="$WALLET" getnewaddress)
  bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=20443 -rpcwallet="$WALLET" generatetoaddress 202 "$ADDR"
done
