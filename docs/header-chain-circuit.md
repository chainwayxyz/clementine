# Header Chain Circuit Documentation

This document describes the logic and structure of the header chain circuit, which implements Bitcoin header chain verification logic. This circuit is designed to operate within a zero-knowledge virtual machine (zkVM) environment, with some components also supporting native execution. Its primary purpose is to verify sequences of Bitcoin block headers, ensuring the integrity and continuity of the chain state.

## Directory Structure (Core Logic)

The relevant code is organized within the `circuits-lib/src/header_chain/` directory:

```
circuits-lib/
  src/
    header_chain/
      mmr_guest.rs
      mmr_native.rs
      mod.rs
```

## Core Components

The header chain circuit consists of several key components that work together to verify Bitcoin block headers and maintain the chain state.

### `mmr_guest.rs` - Merkle Mountain Range for zkVM (Guest)

This module defines `MMRGuest`, a Merkle Mountain Range (MMR) implementation tailored for execution inside a zkVM (guest environment). It is used to efficiently store and verify block hashes within the constrained environment of a zero-knowledge proof system.

  * **`MMRGuest` struct**:
      * `subroots`: Stores the hashes of the MMR's subroots.
      * `size`: Tracks the total number of leaves (block hashes) in the MMR.
  * **`new()`**: Creates a new, empty `MMRGuest` instance.
  * **`append(leaf: [u8; 32])`**: Adds a new leaf (block hash) to the MMR, updating its structure and subroots.
  * **`verify_proof(leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool`**: Verifies an inclusion proof for a given leaf against the current MMR subroots, ensuring the leaf is part of the MMR.

### `mmr_native.rs` - Merkle Mountain Range for Native Environment

This module defines `MMRNative`, an MMR implementation designed for usage outside the zkVM (native environment). It provides functionalities for building and querying MMRs, including generating inclusion proofs that can then be verified by `MMRGuest`.

  * **`MMRNative` struct**:
      * `nodes`: Stores the nodes of the MMR across different levels.
  * **`new()`**: Creates a new, empty `MMRNative` instance.
  * **`append(leaf: [u8; 32])`**: Appends a new leaf to the MMR and recalculates the peaks.
  * **`recalculate_peaks()` (private)**: Internally recomputes the peak nodes (subroots) of the MMR after an append operation.
  * **`get_subroots()` (private)**: Returns the current subroots of the MMR.
  * **`generate_proof(index: u32) -> Result<([u8; 32], MMRInclusionProof)>`**: Generates an inclusion proof for a leaf at a specified index. Returns the leaf and the proof. Handles errors for empty MMR or out-of-bounds indices.
  * **`get_helpers_from_index(index: u32)` (private)**: Helper function to determine the subroot and internal indices for proof generation.
  * **`verify_proof(leaf: [u8; 32], mmr_proof: &MMRInclusionProof) -> bool`**: Verifies an inclusion proof against the current MMR subroots, leveraging the `MMRInclusionProof::get_subroot` method.
  * **`MMRInclusionProof` struct**:
      * `subroot_idx`: Index of the subroot in the MMR's subroots vector.
      * `internal_idx`: Internal index of the leaf within its sub-Merkle tree.
      * `inclusion_proof`: A vector of hashes representing the Merkle path.
      * **`new()`**: Creates a new `MMRInclusionProof` instance.
      * **`get_subroot(leaf: [u8; 32]) -> [u8; 32]`**: Computes the subroot hash given a leaf and the inclusion proof, by replaying the Merkle path.

### `mod.rs` - Header Chain Circuit Logic

This module contains the main logic for the Bitcoin header chain verification circuit, including the entry point function, data structures for chain state and block headers, and utility functions for difficulty adjustment.

  * **`header_chain_circuit(guest: &impl ZkvmGuest)`**: The primary entry point for the header chain circuit. It reads input, processes block headers by applying them to the chain state, and commits the updated state as output. It also verifies `method_id` consistency for previous proofs.
  * **`NetworkConstants` struct**: Holds Bitcoin network-specific constants such as `max_bits`, `max_target`, and `max_target_bytes` for various networks (signet, regtest, testnet4, mainnet).
  * **`NETWORK_TYPE`, `IS_REGTEST`, `IS_TESTNET4`**: Constants to identify the current Bitcoin network configuration at compile time.
  * **`EXPECTED_EPOCH_TIMESPAN`**: Defines the expected time duration for an epoch, which is used in difficulty adjustment calculations.
  * **`BLOCKS_PER_EPOCH`**: The number of blocks that constitute an epoch (2016 blocks).
  * **`CircuitBlockHeader` struct**: A serializable representation of a Bitcoin block header, containing fields like version, previous block hash, Merkle root, timestamp, bits, and nonce.
      * **`compute_block_hash()`**: Calculates the double SHA256 hash of the block header.
      * **`From<Header> for CircuitBlockHeader`**: Conversion from `bitcoin::block::Header` to `CircuitBlockHeader`.
      * **`From<CircuitBlockHeader> for Header`**: Conversion from `CircuitBlockHeader` to `bitcoin::block::Header`.
  * **`ChainState` struct**: Represents the verifiable state of the Bitcoin header chain.
      * `block_height`: Current block height.
      * `total_work`: Cumulative proof of work accumulated.
      * `best_block_hash`: Hash of the most recently verified block.
      * `current_target_bits`: Current compact target (difficulty bits).
      * `epoch_start_time`: Timestamp of the first block in the current difficulty adjustment epoch.
      * `prev_11_timestamps`: Array storing timestamps of the last 11 blocks, used for median time calculation.
      * `block_hashes_mmr`: An `MMRGuest` instance to store block hashes.
      * **`new()`**: Initializes `ChainState` with default values, including the maximum target for `current_target_bits`.
      * **`genesis_state()`**: Provides a default genesis state.
      * **`to_hash()`**: Computes a hash of the current chain state.
      * **`apply_block_headers(block_headers: Vec<CircuitBlockHeader>)`**: Applies a vector of `CircuitBlockHeader`s to the `ChainState`, updating block height, total work, best block hash, and difficulty-related parameters. It performs several validations.

### Utility Functions

  * **`median(arr: [u32; 11]) -> u32`**: Calculates the median of an array of 11 `u32` timestamps.
  * **`validate_timestamp(block_time: u32, prev_11_timestamps: [u32; 11]) -> bool`**: Validates if a block's timestamp is greater than the median of the last 11 timestamps.
  * **`bits_to_target(bits: u32) -> [u8; 32]`**: Converts a compact target (bits) representation to a 32-byte target array.
  * **`target_to_bits(target: &[u8; 32]) -> u32`**: Converts a 32-byte target array back into a compact target (bits) representation.
  * **`calculate_new_difficulty(epoch_start_time: u32, last_timestamp: u32, current_target: u32) -> [u8; 32]`**: Computes the new difficulty target after an epoch, based on actual and expected timespans.
  * **`check_hash_valid(hash: &[u8; 32], target_bytes: &[u8; 32])`**: Verifies if a given hash is less than or equal to the target. Panics if the hash is not valid.
  * **`calculate_work(target: &[u8; 32]) -> U256`**: Calculates the proof of work represented by a given target.

## Circuit Input and Output

### `HeaderChainCircuitInput`

This struct defines the input structure for the `header_chain_circuit`.

  * **`method_id: [u32; 8]`**: An identifier for the circuit version.
  * **`prev_proof: HeaderChainPrevProofType`**: Specifies the preceding proof, which can be either a `GenesisBlock` (initial state) or a `PrevProof` (output from a previous circuit run).
  * **`block_headers: Vec<CircuitBlockHeader>`**: A list of Bitcoin block headers to be processed and verified in the current circuit run.

### `HeaderChainPrevProofType`

An enum representing the type of previous proof provided to the circuit.

  * **`GenesisBlock(ChainState)`**: Used when starting a new chain verification from a genesis state.
  * **`PrevProof(BlockHeaderCircuitOutput)`**: Used when continuing verification from a previously proven circuit output.

### `BlockHeaderCircuitOutput`

This struct defines the output generated by the `header_chain_circuit` upon successful execution.

  * **`method_id: [u32; 8]`**: The identifier of the circuit that produced this output.
  * **`genesis_state_hash: [u8; 32]`**: The hash of the initial chain state (genesis block).
  * **`chain_state: ChainState`**: The updated chain state after processing all block headers in the input.

## Error Handling and Validation

The circuit incorporates extensive validation checks to ensure proof integrity and consistency of the Bitcoin header chain:

  * **Method ID Mismatch**: Ensures that the `method_id` of the input matches that of any previous proof, preventing the use of different circuit versions.
  * **Previous Block Hash Validation**: Verifies that each block's `prev_block_hash` matches the `best_block_hash` from the previous state, ensuring chain continuity.
  * **Bits/Difficulty Target Validation**: Checks that the `bits` field in the block header matches the expected difficulty target for the current network and epoch.
  * **Hash Validity**: Confirms that the computed block hash is valid (i.e., less than or equal to the current target).
  * **Timestamp Validation**: Ensures that the block timestamp is greater than the median of the previous 11 block timestamps, preventing timestamp manipulation.
  * **MMR Proof Verification**: `MMRGuest` and `MMRNative` include `verify_proof` methods to ensure the integrity of Merkle Mountain Range inclusions.

The circuit is designed to `panic!` on any validation failure, indicating an invalid input or a breach of chain rules, thus ensuring that only cryptographically sound proofs are generated.

## RISC Zero Implementation (`risc0-circuits/header-chain`)

This section provides an overview of the `risc0-circuits/header-chain` module, which defines the RISC Zero specific implementation and guest environment for the Header Chain Circuit. Its primary function is to call the core `header_chain_circuit` logic (defined in `circuits-lib`) from within the RISC Zero guest environment and manage the build process for generating the necessary ELF binaries.

### Key Files (RISC Zero Implementation)

  * **`risc0-circuits/header-chain/guest/src/main.rs`**

      * This is the entry point for the **RISC Zero guest application**. It initializes the `Risc0Guest` environment and makes the crucial call to `circuits_lib::header_chain::header_chain_circuit` to execute the Bitcoin header chain verification logic inside the zkVM.

  * **`risc0-circuits/header-chain/guest/Cargo.toml`**

      * The package manifest for the guest-side code. It defines the `header-chain-guest` package and its dependencies, notably linking to the `circuits-lib` which contains the actual circuit logic.

  * **`risc0-circuits/header-chain/src/lib.rs`**

      * This file includes the `methods.rs` generated by the build script, which contains information about the guest methods (ELF image and method ID) that the host can use to prove the guest's execution. Because we use hard-coded method IDs and ELFs that are relocated by build.rs, we rely on those instead.

  * **`risc0-circuits/header-chain/build.rs`**

      * This is the **build script** for the host-side. It is responsible for:
          * Compiling the `header-chain-guest` code into a RISC Zero ELF binary.
          * Computing the unique **method ID** for the compiled guest program.
          * Handling environment variables (like `BITCOIN_NETWORK`) to configure the build.
          * Optionally using Docker for guest builds and copying the generated ELF binary to a designated `elfs` folder.

  * **`risc0-circuits/header-chain/Cargo.toml`**

      * The package manifest for the host-side crate. It defines the `header-chain` package and its build-time dependencies, including `risc0-build` for the RISC Zero toolchain integration.

---