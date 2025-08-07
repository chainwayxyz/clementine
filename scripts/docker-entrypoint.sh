#!/bin/sh
set -e

bitcoind "$@" &

sleep 2
/init-bitcoin.sh

wait