# bridge-core

## contracts

- Rollup contracts

## circuits

- operator to create bitvm proof
- verifier to create challenge proof

## operator

- main bridge operator
- able to create proofs
- informs verifiers about new deposits
- verifier binary that is actively listening operator for new deposits and proofs

## user

- simple js script for making a deposit transaction in bitcoin and in the rollup

# bitcoin commands

```sh
bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin
```

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin createwallet "admin"
```

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin generatetoaddress 101 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin getnewaddress)
```

# folder structure

```text
bridge
├── Cargo.toml
├── contracts
│   ├── lib
│   ├── script
│   ├── src
│   │   ├── Bridge.sol
│   │   └── MerkleTree.sol
│   └── test
├── circuits
│   ├── core                                   common functionality
│   │   ├── Cargo.toml
│   │   └── src
│   │       ├── lib.rs
│   │       ├── merkle.rs                      hash function, zeroes, depth, etc.
│   │       └── btc.rs                         btc operations
│   ├── host
│   │   ├── Cargo.toml
│   │   ├── data                               rpc block data
│   │   └── src
│   │       ├── lib.rs
│   │       ├── main.rs                        <-- [Host code goes here]
│   │       └── merkle.rs                      MerkleTree
│   └── methods
│       ├── Cargo.toml
│       ├── build.rs
│       ├── guest
│       │   ├── Cargo.toml
│       │   └── src
│       │       ├── lib.rs
│       │       ├── main.rs                   <-- [Guest code goes here]
│       │       ├── bitcoin.rs                btc operations
│       │       └── merkle.rs                 IncrementalMerkleTree, verify_merkle_path
│       └── src
│           └── lib.rs
├── operator
│   ├── Cargo.toml
│   └── src
│       └── lib.rs
└── user
```
