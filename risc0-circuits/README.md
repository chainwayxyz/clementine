# Clementine risc0 Circuits

## Description
This package contains the risc0 guest programs and their entrypoints. You can find the libraries for them in `./circuits-lib` directory.
`work-only` is used by the watchtowers to generate a compact proof of the work that is produced by the bitcoin chain they are following.
`bridge-circuit` is used by the operators to prove that they have the right to reimburse a withdrawal from the bridge vault.
The dependency on `header-chain` comes from BitVM repository.

## Build
- To build `work-only`, from the root of the directory, use
```bash
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK_TYPE> BRIDGE_CIRCUIT_MODE=<CIRCUIT_MODE> cargo build -p work-only --release
```
where `NETWORK_TYPE` can be `mainnet`, `testnet4`, `signet`, or `regtest`.

- To build `bridge-circuit`, use
```bash
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK_TYPE> BRIDGE_CIRCUIT_MODE=<CIRCUIT_MODE> cargo build -p bridge-circuit --release
```
where `NETWORK_TYPE` can be `mainnet`, `testnet4`, `signet`, or `regtest`, and `CIRCUIT_MODE` can be either `test` or `prod`.


