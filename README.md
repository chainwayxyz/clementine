# Clementine

## To run tests

```sh
cargo test
```

## To run the flow

First you need to run the bitcoin regtest server. You can use the following commands to run the server.

### bitcoin commands

```sh
bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1
```

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin createwallet "admin"
```

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin generatetoaddress 101 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin getnewaddress)
```

### Run the flow

```sh
cargo run
```
