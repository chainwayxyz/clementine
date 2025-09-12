# Clementine risc0 Circuits

## Description
This package contains the Risc0 guest programs and their entrypoints. You can find the libraries for them in `./circuits-lib` directory.
`header-chain` is used to prove the block headers and their chaining. It calculates the total work done up to the last input block.
`work-only` is used by the Watchtowers to generate a compact proof of the work that is produced by the Bitcoin chain they are following.
`bridge-circuit` is used by the Operators to prove that they have the right to reimburse a withdrawal from the bridge vault.

## Build
- To build `header-chain`, use
```bash
cd risc0-circuits/header-chain/
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK_TYPE> cargo build -p header-chain --release
```

- To build `work-only`, use
```bash
cd risc0-circuits/work-only/
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK_TYPE> cargo build -p work-only --release
```

- To build `bridge-circuit`, use
```bash
cd risc0-circuits/bridge-circuit/
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=<NETWORK_TYPE> BRIDGE_CIRCUIT_MODE=<CIRCUIT_MODE> cargo build -p bridge-circuit --release
```
where `NETWORK_TYPE` can be `mainnet`, `testnet4`, `signet`, or `regtest`.

- For testing purposes, also build the `bridge-circuit` with the `test-vk` (use Groth16 Verification Key for testing purposes) on `regtest`:
```bash
REPR_GUEST_BUILD=1 BITCOIN_NETWORK=regtest cargo build -p bridge-circuit --features use-test-vk --release
```


