# Clementine Onboarding

Welcome! Our bridge leverages BitVM for a trust minimized BTC <> Citrea bridge. Here’s what you need to know:

Clementine Whitepaper: [https://citrea.xyz/clementine_whitepaper.pdf](https://citrea.xyz/clementine_whitepaper.pdf)

More info on BitVM2: https://bitvm.org/bitvm_bridge.pdf and http://bitvm.org/bitvm2

---

## Clementine Tx Graph

![Clementine Tx Graph](images/clementine_diagram.png)

For more up-to-date graph, see: [https://link.excalidraw.com/l/VtMON1sWKQ/61dFLxZMlGt](https://link.excalidraw.com/l/VtMON1sWKQ/61dFLxZMlGt)

---

## FAQ

1. Why the bridge denominator is constant (10 BTC)?

> Bridge funds are kind of locked in a UTXO, it can only be spent via a connector output of a BitVM instance, we need to have a lot more pre-signatures to split that UTXO into two parts, it can only be spend as a whole. We can get signatures for splitting it but it is too much overhead. And this bridge will be used rarely by normal users, rather it will be used by liquidity providers, and normal users will enter the system via Atomic Swaps. So for now i advise you to not think about how to make bridge amount variable, rather make this bridge robust for 10 BTC.

1. Why the bridge funds stays in N-of-N not in M-of-N?

> Do not think this N-of-N as a multi sig wallet, but rather as a key deletion covenant. (Covenant is a way to restrict a UTXO’s spending tx.)
The problem you would think is what if one of these signers reject to sign any message, then new deposits would not come, because N-of-N signatures would not be able to collected. But this is OK. We will have another multisig at the Bridge Contract, which is M-of-N that can update the N-of-N. This seems same as putting the bridge funds on M-of-N but IT IS NOT. Old deposits are safe if they are in N-of-N, and we can also add a time restirctions to update the N-of-N, let’s say we give 1 month to update the N. Then everyone can exit the system if they don’t trust the new N. Remember that we want our bridge to be safe as long as one of the N signers deletes their keys. We want our bridge to be live as long as one of the operators pays.

1. Why bridge denominator is 10 BTC not 1 BTC?

> This is still open research question. But from current observations, 1 BTC doesn’t seem feasible. The reason is, every opreator puts some collateral to be used in every withdrawal. An operator can make a withdrawal once at a time to use that collateral efficiently. (If operator can make two withdrawals concurrently, we would have to send 2 disprove txs thus collateral would not be enough.) Thus our number of withdrawals are rate limited. So making it 1 BTC would make the total max TVL very low. Even 10 BTC requires a lot of operators to make this efficient. See more: https://dune.com/ekrem/bitvm-bridges-research

1. Why We Use Winternitz One-Time Signatures

> In Bitcoin script, with native opcodes, one can only verify Schnorr signatures that sign the transaction. In other words, one cannot verify a Schnorr signature that signs a random message. However, Winternitz and Lamport signatures can be verified just by taking hashes and checking for equality (Winternitz involves some additional mathematical operations where Bitcoin has those).
> This way, we can use Winternitz to propagate state across UTXOs. For example, in BitVM, the prover signs intermediate steps; later, the same signatures can be used to disprove an incorrect proof.
> In watchtower challenge transactions, watchtowers provide the longest chain proof using Winternitz signatures. This way, we get the same transaction ID, allowing us to use pre-signed transactions easily.

---

## Codebase

Our repository: [https://github.com/chainwayxyz/clementine](https://github.com/chainwayxyz/clementine)

Project board: [https://github.com/orgs/chainwayxyz/projects/4/views/1](https://github.com/orgs/chainwayxyz/projects/4/views/1)

Milestones: [https://github.com/chainwayxyz/clementine/milestones](https://github.com/chainwayxyz/clementine/milestones)

Currently our codebase is a bit messy, but all you need to focus is the /core part right now.

We also have several repos to support the bridge:

- **bridge-backend** [https://github.com/chainwayxyz/bridge-backend/](https://github.com/chainwayxyz/bridge-backend/)

  > This is a nodejs repository maintaned by Berk, it does several things:

  - Sending the deposits to our Aggregator
  - Testnet Faucet
  - [CPFP](https://bitcoinops.org/en/topics/cpfp/) for Transaction fee bumping
- **risc0-to-bitvm2** [https://github.com/chainwayxyz/risc0-to-fflonk/](https://github.com/chainwayxyz/risc0-to-fflonk/)

  > This will include all required circuits for the bridge, current /circuits folder in clementine is outdated. This repo includes:

  - Header chain circuit (Proves bitcoin headers from genesis)
  - Custom stark-to-snark circuit for risc0, this will reduce our costs on verifying a groth16 proof via BitVM by reducing the public inputs to 1.

Clementine has a single binary that can act as 3 different services:

- Verifier (We sometime call this signer)
- Operator
- Aggregator

These services communicates via gRPC and uses a Postgresql database. They can be configured to share the same database.

An entity can choose to run these services on a single host to be a part of the peg-in and peg-out process. All the services that are run by a single entity should ideally share the same database. Typical entities are:

- Operator entity
  - Runs multiple operator services and one verifier service
- Verifier entity
  - Runs a verifier service
- Aggregator entity
  - Runs both an aggregator and a verifier service

## Architecture

### Aggregator

Aggregator is responsible for helping verifiers to finalize deposits, using [musig2](https://github.com/bitcoin-core/secp256k1/blob/master/doc/musig.md#signing). It has 3 steps:

1. Nonce aggregation
2. Signature aggregation
3. Move tx creation

![Move TX creation](images/move_tx_creation.png)

In the first step, aggregator will collect nonces from all the verifiers, soon to be aggregated and send back to the verifiers. Aggregation is done by musig2.

At the second step, partial signatures will be requested from verifiers for the provided aggregated nonce. They will be aggregated using musig2, just like nonces. Final Schnorr signature will be sent to verifiers.

Aggregated signatures are used by verifiers to finalize deposit. Then, verifiers will return move tx partial signatures, which will later be aggregated. Finally, aggregator will create a move tx.
