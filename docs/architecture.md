# Architecture

Clementine provides a single binary, that can act as a 3 different actor
services:

- Verifier (We sometimes call this as signer)
- Operator
- Aggregator

These services communicates via gRPC and uses a Postgresql database. They can be
configured to share the same database.

An entity can choose to run these services on a single host to be a part of the
peg-in and peg-out process. All the services that are run by a single entity
should ideally share the same database. Typical entities are:

- Operator entity
  - Runs multiple operator services and one verifier service
- Verifier entity
  - Runs a verifier service
- Aggregator entity
  - Runs both an aggregator and a verifier service

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
