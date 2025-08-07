# The Design Of Clementine

Our bridge leverages BitVM for a trust minimized BTC <> Citrea bridge. The
[whitepaper](https://citrea.xyz/clementine_whitepaper.pdf) explains technicals.
Also, [https://bitvm.org/bitvm_bridge.pdf](https://bitvm.org/bitvm_bridge.pdf)
and [http://bitvm.org/bitvm2](http://bitvm.org/bitvm2) can be checked to learn
more about BitVM.

![Clementine Tx Graph](images/clementine_diagram.png)

## Depositing

Aggregator is responsible for helping verifiers to finalize deposits, using
[musig2](https://github.com/bitcoin-core/secp256k1/blob/master/doc/musig.md#signing).
It has 3 steps:

1. Nonce aggregation
2. Signature aggregation
3. Move tx creation

![Move TX creation](images/move_tx_creation.png)

1. In the first step, aggregator will collect nonces from all the verifiers,
   soon to be aggregated and send back to the verifiers. Aggregation is done by
   musig2.
2. At the second step, partial signatures will be requested from verifiers for
   the provided aggregated nonce. They will be aggregated using musig2, just
   like nonces. Final Schnorr signature will be sent to verifiers.
3. Aggregated signatures are used by verifiers to finalize deposit. Then,
   verifiers will return move tx partial signatures, which will later be
   aggregated. Finally, aggregator will create a move tx.

## FAQ

### Why the bridge funds stays in N-of-N not in M-of-N?

It is important to distinguish this N-of-N arrangement from a traditional multisignature wallet; instead, it functions as a key deletion covenant. A covenant is a mechanism that restricts how an UTXO can be spent. One potential concern is that if any of the signers refuse to sign, new deposits could be blocked, as the required N-of-N signatures could not be collected. However, this isn't a problem. Because the Bridge Contract also maintains a separate M-of-N multisig, which has the authority to update the N-of-N set. While this may appear similar to simply holding bridge funds in an M-of-N multisig, it is fundamentally different. Funds already deposited and secured by the N-of-N covenant remain safe, and updates to the N-of-N set can be subject to time restrictions (for example, allowing one month for updates). This gives participants the opportunity to exit the system if they do not trust the new set of signers. The bridge is designed to remain secure as long as at least one of the N signers deletes their keys, and to remain operational as long as at least one operator continues to participate.

### Why bridge denominator is 10 BTC not 1 BTC?

This is still open research question. But from current observations, 1 BTC doesn’t seem feasible. The reason is every round tx has a limited amount of kickoff connectors. Thus limiting the withdrawal throughput.

### Why We Use Winternitz One-Time Signatures

In Bitcoin script, with native opcodes, one can only verify Schnorr signatures that sign the transaction. In other words, one cannot verify a Schnorr signature that signs a random message. However, Winternitz and Lamport signatures can be verified just by taking hashes and checking for equality (Winternitz involves some additional mathematical operations where Bitcoin has those).
This way, we can use Winternitz to propagate state across UTXOs. For example, in BitVM, the prover signs intermediate steps; later, the same signatures can be used to disprove an incorrect proof.
