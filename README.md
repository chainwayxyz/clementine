# Clementine 🍊
Clementine is Citrea's BitVM based trust-minimized two-way peg program.
The repository includes:
- Smart contracts for deposit and withdrawal
- A library for bridge operator and verifiers
- Circuits that will be optimistically verified with BitVM

The flow is as follows:
- Creating the operator and verifiers
- Initial setup that includes calculating period block heights, connector tree hashes, and funding connector source UTXOs.
- User deposit flow that includes creating a deposit transaction, signing it, and submitting it to the operator.
- Operator processing the deposit, getting signatures from verifiers, and submitting the deposit to the Bitcoin network.
- Verifiers verifying the deposit and signing the deposit transaction and claim signatures.
- Operator withdrawal flow for front covering withdrawal requests.
- Verifier to start a challenge with Bitcoin Proof of Work
- Operator to respond to the challenge with a bridge proof.


> [!WARNING] 
> Clementine is still work-in-progress. It has not been audited and should not be used in production under any circumstances. It also requires a full BitVM implementation to be run fully on-chain.


## Instructions

To the the whole process of simulating deposits, withdrawals, proof generation on the Bitcoin Regtest network, you need Bitcoin Core to be installed.

To clone this repo with submodules:

```
git clone --recurse-submodules https://github.com/chainwayxyz/clementine.git
cd clementine
```

### Run Bitcoin Regtest

You can use the following commands to run the server.

Start the regtest server with the following command:
```sh
bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1
```

Create a wallet for the operator:
```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin createwallet "admin"
```

Mine some blocks to the wallet:
```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin generatetoaddress 101 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin getnewaddress)
```

Run the flow: 
```sh
cargo run
```

To run tests:
```sh
cargo test
```

# License

## Copyright

**(c) 2024 Chainway Limited** `clementine` was developed by Chainway Limited. While we plan to adopt an open source license, we have not yet selected one. As such, all rights are reserved for the time being. Please reach out to us if you have thoughts on licensing.
