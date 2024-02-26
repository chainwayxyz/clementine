# bridge-core

## bitcoin commands

```sh
bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1
```

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin createwallet "admin"
```

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin generatetoaddress 101 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin getnewaddress)
```

There exists one operator and N-1 verifiers. A user wants to make a deposit.
They deposit to the taproot address of (N+1 of N+1 multisig) or (the user takes in 200). 
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
At the beginning, the operator creates these connector trees.
It has M internal roots, all of each are created from the leaves that hides the preimage information regarding the claims that will be made by the operator
(internal index = the number of claims - 1). Combining all the roots of the connector trees, there will be M hard-coded root for verification purposes.
At the end of each period i, the operator will inscribe the preimages such that revealed preimages will enable him to claim the number of withdrawals made from genesis, since previous periods' bridge funds are already claimed, operator will not be able to claim them again.
Revealed preimages will help verifiers burn the remaining part of the connector tree to stop the operator from stealing the funds.