# Work-Only Circuit Documentation

This document details the **Work-Only Circuit**, a specialized zero-knowledge virtual machine (zkVM) circuit designed to verify and commit the accumulated proof of work from a previously executed Bitcoin header chain circuit. Its primary purpose is to extract the `total_work` value and `genesis_state_hash` from a Header Chain Circuit proof and present them as a new, concise proof output.

### Core Logic

The core logic for the work-only circuit is contained within the [`mod.rs`](../circuits-lib/src/work_only/mod.rs) module. The main entry point, `work_only_circuit`, receives a `WorkOnlyCircuitInput` which includes the full output of a Header Chain Circuit execution.

The circuit begins by performing two crucial validation steps. First, it checks for method ID consistency, ensuring that the input proof's method ID matches the header chain program key of the network the circuit is compiled for, `CURRENT_HEADER_CHAIN.recursion`. This prevents the circuit from verifying proofs from an incorrect or incompatible version of the Header Chain Circuit. Second, it uses the `SP1Guest::verify()` function to cryptographically validate the entire `header_chain_circuit_output`. This step is a zero-knowledge check that proves the integrity and correctness of the preceding circuit's execution.

After successful verification, the circuit extracts the `total_work` and `genesis_state_hash` from the verified output. A private helper function, `work_conversion`, is then used to convert the 256-bit `total_work` value into a 128-bit representation, effectively truncating it to its lower 128 bits. The final output, a `WorkOnlyCircuitOutput`, contains this 128-bit work value and the genesis state hash, which are then committed to the zkVM's output.

### SP1 implementation

The guest entry point is `sp1-circuits/work-only/src/main.rs`; its dependencies are pinned in that package's `Cargo.toml` and `Cargo.lock`. The shared logic lives in `circuits-lib`.

`scripts/build_sp1_guests.py` builds header-chain, work-only, and bridge guests in dependency order for each Bitcoin network. It records the ELF checksum and SP1 program commitment in `sp1-circuits/elfs/manifest.json`, and generates the commitments in `circuits-lib/src/common/sp1_programs.rs`.

See [SP1 proving and BitVM verification](sp1.md) for the proof format, development mode, and verification key specialization.
