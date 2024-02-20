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

There exists one operator and N-1 verifiers. A user wants to make a deposit.
They deposit to the taproot address of (N of N multisig) or (the user takes in 200).
After this, the operator collects the signatures from the verifiers, and moves the deposit to (N of N multisig).
Signatures include:
- Move signatures
- Operator claim signatures
Move signatures will move the deposit UTXO to the multisig. Operator claim signatures help the operator claim the deposit at the end of a period in case the operator pays the withdrawals up to the index of the deposit.

## User Side:
The user will mint their cBTC using the txid of the move transaction. On the rollup, they will provide:
- Txid
- Succinct inclusion proof of txid in a blockheader
- The blockheader

## Operator Side:
The operator creates a total of M connector UTXO trees, each root descending from the previous one. These trees will represent BitVM periods. 
If the operator acts maliciously, an honest verifier will burn a single root, which will lead to the loss of the future roots, making operator useless.
At the beginning, the operator creates these connector trees, and creates a Giga Merkle Tree which holds the claim data for each period.
It has M internal roots, all of each are created from the leaves that hides the preimage information regarding the claims that will be made by the operator
(internal index = the number of claims - 1). Combining all the roots of the connector trees, there will be a single hard-coded root for verification purposes.
At the end of each period i, the operator will inscribe the preimages such that revealed preimages will enable him to claim the number of withdrawals made in that period.
Revealed preimages will help verifiers burn the remaining part of the connector tree to stop the operator from stealing the funds.