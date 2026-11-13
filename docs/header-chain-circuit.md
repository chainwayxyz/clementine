# Header Chain Circuit Documentation

This document describes the logic and structure of the header chain circuit, which implements Bitcoin header chain verification logic. This circuit is designed to operate within a zero-knowledge virtual machine (zkVM) environment, with some components also supporting native execution. Its primary purpose is to verify sequences of Bitcoin block headers, ensuring the integrity and continuity of the chain state.

### Merkle Mountain Range (MMR) Implementations

The circuit's core logic is supported by two distinct Merkle Mountain Range (MMR) implementations. The [`mmr_guest.rs`](../circuits-lib/src/header_chain/mmr_guest.rs) module provides an MMR tailored for the constrained environment of a zkVM. The header chain circuit appends the hash of each verified block to this `MMRGuest`, which stores only the subroots, so the chain state commits to the entire chain history without storing it. The bridge circuit later uses this `MMRGuest` to verify inclusion proofs for block hashes in its SPV step.

In contrast, the [`mmr_native.rs`](../circuits-lib/src/header_chain/mmr_native.rs) module provides a native MMR implementation for use outside the zkVM. This `MMRNative` is used to build the MMR from a sequence of block headers and generate inclusion proofs. These proofs can then be passed to the `MMRGuest` within the zkVM for verification, bridging the gap between off-chain data preparation and on-chain verification.

### Core Circuit Logic

The central component of the circuit is the main logic module, found in [`mod.rs`](../circuits-lib/src/header_chain/mod.rs). This module orchestrates the entire verification process, from handling input and output to performing all necessary cryptographic and protocol-level checks.

The circuit's entry point function, `header_chain_circuit`, takes a list of block headers as input and applies them to a `ChainState` data structure. This `ChainState` keeps track of essential chain parameters such as block height, accumulated proof of work, and the current difficulty target. For each block header, the circuit performs a series of critical validations:

* **Method ID Consistency**: It first ensures that the `method_id` of the input matches that of any previous proof, preventing the use of different circuit versions.
* **Chain Continuity**: It verifies that each block's `prev_block_hash` matches the `best_block_hash` from the preceding state, guaranteeing a continuous chain.
* **Proof of Work**: It calculates the double SHA256 hash of the block header and checks that it is less than or equal to the current difficulty target.
* **Difficulty Adjustment**: It validates the `bits` field in the header and, at the end of each 2016-block epoch, calculates and validates the new difficulty target based on the time elapsed.
* **Timestamp Validation**: It ensures that the block's timestamp is greater than the median of the previous 11 block timestamps, preventing timestamp manipulation.
* **MMR Update**: It appends the block hash to the `MMRGuest` of the chain state. The circuit does not verify inclusion proofs; the bridge circuit does this in its SPV step.

Upon successful execution, the circuit outputs an updated `ChainState` and a hash of the initial state. This output can then be used as input for a subsequent circuit run, enabling the verification of a continuous, long chain of headers across multiple proofs. The entire process is designed to `panic!` on any validation failure, ensuring that only cryptographically sound and protocol-compliant proofs are generated.

### SP1 implementation

The guest entry point is `sp1-circuits/header-chain/src/main.rs`; its dependencies are pinned in that package's `Cargo.toml` and `Cargo.lock`. The shared logic lives in `circuits-lib`.

`scripts/build_sp1_guests.py` builds header-chain, work-only, and bridge guests in dependency order for each Bitcoin network. It records the ELF checksum and SP1 program commitment in `sp1-circuits/elfs/manifest.json`, and generates the commitments in `circuits-lib/src/common/sp1_programs.rs`.

See [SP1 proving and BitVM verification](sp1.md) for the proof format, development mode, and verification key specialization.
