# Bridge Circuit Documentation

## The Role of the Bridge Circuit
The Bridge Circuit is a core component of Clementine, the trust-minimized two-way peg mechanism for the Citrea L2 rollup. The bridge circuit's primary role is to ensure the secure and verifiable transfer of assets between the Bitcoin blockchain and the Citrea L2. It acts as an automated verifier, enforcing the rules of the protocol and enabling users to confidently move their assets between the two chains. By leveraging zero-knowledge proofs, the bridge circuit allows for this cross-chain functionality without requiring users to trust a centralized intermediary, which is a significant improvement in security and decentralization compared to traditional bridge designs. This trust-minimized and automated verification is made possible through a mechanism that emulates covenants by having a committee of n signers pre-sign a specific set of transactions during the Peg-In phase. This pre-signing creates a deterministic and enforceable set of rules for how the deposited funds can be moved, effectively automating the BitVM2 challenge-response process and ensuring the Bridge Circuit receives the correct inputs for verification. Here's how these pre-signed transactions relate to the Bridge Circuit:
- Setting the Stage for Verification: During the peg-in process, the signer committee pre-signs a whole suite of potential transactions that will govern any future peg-out attempt related to that deposit. This creates a predictable and unalterable "game tree" for the BitVM2 protocol. The Operator and Challengers are not creating new rules as they go; they are simply choosing which pre-written script to execute.
- Automating the Challenge Flow: The pre-signed transactions directly map to the inputs and state transitions that the Bridge Circuit is designed to verify.
- KickOff and its Connectors: When an Operator initiates a peg-out with a KickOff transaction, they are activating a set of pre-signed "connector" outputs while also committing the payout block hash data on-chain via Winternitz One-Time Signature (WOTS). Each connector can only be spent by the specific, pre-signed transactions.
- Watchtower Challenge and OperatorChallengeACK: The circuit needs to know which Watchtowers have challenged the Operator. This is enforced through pre-signed transactions. A Watchtower spends a small amount of personal fund to send the Watchtower Challenge transaction to submit its Work Only Proof (WOP). The Operator is then forced to acknowledge this by spending the corresponding Acknowledge Connector with the pre-signed Operator ChallengeACK transaction. If the Operator fails to do so, a Challenger can use the pre-signed Operator ChallengeNACK to slash them. This mechanism guarantees that the watchtower_sent_challenge boolean array fed into the Bridge Circuit is accurate and cannot be manipulated by the Operator.
- Assert and Disprove: The Operator posts the results of their off-chain execution of the Bridge Circuit via Assert transactions. If a Challenger finds an error, they use a pre-signed Disprove transaction to execute a single step of the Bridge or Clementine Disprove Scripts on-chain. The logic for these disprove scripts, which includes verifying the Groth16 proof of the main Bridge Circuit, is encoded into the pre-signed Disprove Connector output of the KickOff transaction.

## BitVM2 Integration
The Bridge Circuit integrates with the BitVM2 design to enable the verification of complex computations on the Bitcoin blockchain without requiring any changes to Bitcoin's underlying protocol. Since the Bridge Circuit's verification logic (a zk-SNARK verifier) is too large to be executed directly within a Bitcoin transaction, it is implemented as a BitVM2 program. This integration works as follows:
- Off-Chain Execution: The Operator executes the fronting (payout) transaction for a withdrawal request. Then commits the hash of the Bitcoin block that includes this transaction in the Witness of the Kickoff transaction (via WOTS).
- On-Chain Challenge: Any Challenger who thinks the Operator is malicious can contest the Operator's claim by spending the Challenge connector, which starts the BitVM2 process. The BitVM2 protocol facilitates a "dissection game" that narrows down the disagreement to a single computational step. In this game, after a challenge, the Operator is forced to prove the correctness of their on-chain operations using Bridge Circuit, then post a series of Assert transactions, which reveal the intermediate results of the generated Groth16 proof verification computation (via WOTS). If a Verifier finds an incorrect step in this revealed trace, they can post a Disprove transaction, which pinpoints the specific faulty computation to be executed on-chain.
- On-Chain Verification: This single, incorrect step of the Bridge Circuit's execution is then verified on-chain within a Bitcoin Script. Because only one small part of the computation is verified, it fits within the size and operational limits of Bitcoin's scripting language.

By using BitVM2, Clementine can enforce the complex rules of the Bridge Circuit in a trust-minimized way, leveraging Bitcoin's security for dispute resolution while keeping the vast majority of the computational work off-chain.

### The Disprove Process
If a Challenger finds an error with the output of the Operator's off-chain execution of the bridge program, they can post a Disprove transaction. This transaction pinpoints the specific step of the program where the Operator's computation was incorrect and executes that step on-chain. If the on-chain execution confirms the Operator's error, the Challenger is able to burn the Operator's collateral. There are two types of scripts that can be executed in a Disprove transaction:
- BridgeDisproveScript: This script verifies the main Bridge Circuit. It uses a Groth16 proof to check several critical conditions related to bridge operations.
- ClementineDisproveScript: This script ensures that the inputs provided to the Bridge Circuit are consistent with the on-chain state of the relevant data, such as Watchtower challenges and block hashes (committed via WOTS). It verifies that the Operator has not censored or ignored any valid challenges from the Watchtowers, and did use the data they committed on-chain.

## TL;DR
* **Header Chain Proof (HCP) Verification:**
    * Verifies that the HCP's `method_id` is correct.
    * Verifies the HCP's Groth16 proof using the `zkvm_guest`.

* **Watchtower Challenge Processing:**
    * Verifies the Schnorr signature on each Watchtower's challenge transaction and if verification is successful, sets the corresponding bit.
    * Sorts Watchtower challenges that passed the Schnorr signature verification by their `total_work` in descending order.
    * Verifies the Groth16 proofs of the Watchtowers until the first valid proof. This will be the highest valid `total_work`, hence the name `max_total_work`.
    * Asserts that the Operator's `total_work` from their HCP is greater than the `max_total_work` from the Watchtowers.

* **Simple Payment Verification (SPV):**
    * Verifies the inclusion of the payout transaction within the claimed Bitcoin block using a Merkle tree proof based on `mid_state_txid`.
    * Verifies the inclusion of the block header in the (Merkle Mountain Range) MMR of the canonical chain.

* **Light Client Proof (LCP) Verification:**
    * Verifies the `LightClientProof` by calling `env::verify` with the correct `LC_IMAGE_ID`.
    * Performs a check to ensure the L1 block hash from the LCP output matches the payout transaction's block hash.

* **EVM Storage Proof Verification:**
    * Verifies the storage proof for the deposit UTXO using the state root from the verified LCP.
    * Verifies the storage proof for the withdrawal data.

* **Other Checks:**
    * Checks that the data on the contract matches with the payout transaction data.
    * Checks that the payout transaction is included in the HCP.

## High-Level Overview
> [!WARNING]
> Before reading this document, please read the [header chain circuit](header-chain-circuit.md) and [work only circuit](work-only-circuit.md) documentations.

The bridge circuit in Clementine serves as a critical component that enables secure and (optimistically) verifiable cross-chain interactions between Bitcoin and the Citrea L2 rollup. Its primary function is to allow Operators, when challenged, to prove the correctness of their operations and the validity of state transitions.

At a high level, the circuit performs several key verifications:

* **Header Chain Verification**: In the circuit, the Operator verifies their own Header Chain Proof (HCP).

* **Watchtower Challenge Processing**: In the circuit, the Operator processes and validates challenges from watchtowers, who monitor operator behavior and provide their own Work Only Proof (WOP) as a Groth16 proof.
    This verification is done as follows:
    For each Watchtower, the signature that is for spending the connector UTXO for the challenge-sending transaction is verified. If the signature is verified, the corresponding bit flag to that Watchtower will be set to 1.
    Then the `Work`s provided by the Watchtowers are sorted in a descending order. Then, until the first Groth16 proof is verified, they are looped. This way, the Operator obtains the maximum valid amount of Work
    provided by the Watchtowers. The Operator must provide a HCP with more work compared to the WOP with maximum Work. This is necessary, since the canonical Bitcoin blockchain is determined by the total Work done. If the Operator fails to do so, this automatically means that the Operator did not follow the canonical chain; therefore, is already malicious.

* **Simple Payment Verification (SPV)**: In the circuit, the Operator verifies the Simplified Payment Verification (SPV) proof of their payout (fronting the withdrawal) transaction.

* **Light Client Proof (LCP) Verification**: In the circuit, the Operator verifies the Light Client Proof (LCP) (which is a Groth16 proof). This proof comes from a recursive Risc0 circuit that verifies the previous LCP each time, and verifies the Batch Proofs for Citrea, and then generates the new Light Client Proof. This recursion happens per Bitcoin block. Therefore, there exists an LCP for the Bitcoin block that includes the payout transaction of the Operator. The Operator uses the state root from the LCP output to verify the storage proof of their payout transaction data for the specific deposit that corresponds to that withdrawal operation on the Bridge Contract.

After all of the verification steps above, the specific constants from the setup are calculated, and with withdrawal specific data, the output data is generated and committed.

---

### Key Files (RISC Zero Implementation)

* **`risc0-circuits/bridge-circuit/guest/src/main.rs`**
    * This is the entry point for the **RISC Zero guest application**.
    * It initializes the `Risc0Guest` environment and makes the crucial call to `circuits_lib::bridge_circuit::bridge_circuit`, passing the `zkvm_guest` and the `WORK_ONLY_IMAGE_ID` as parameters.
    * **`WORK_ONLY_IMAGE_ID: [u8; 32]`**: This is a static constant that dynamically resolves to the expected method ID (image ID) of the "Work-Only" circuit. Its value is determined at compile time based on the `BITCOIN_NETWORK` environment variable (e.g., `mainnet`, `testnet4`, `signet`, `regtest`), ensuring the Bridge Circuit verifies proofs from the correct "Work-Only" circuit version for the specified network.

* **`risc0-circuits/bridge-circuit/guest/Cargo.toml`**
    * The package manifest for the guest-side code.
    * It defines the `bridge-circuit-guest` package and its dependencies, notably linking to `circuits-lib` which contains the core circuit logic.
    * It also includes a `use-test-vk` feature, which can be enabled to use a test verification key.

* **`risc0-circuits/bridge-circuit/src/lib.rs`**
    * This file includes the `methods.rs` generated by the build script, which contains information about the guest methods (ELF image and method ID) that the host can use to prove the guest's execution. Because we use hard-coded method IDs and ELFs that are relocated by build.rs, we rely on those instead.

* **`risc0-circuits/bridge-circuit/build.rs`**
    * This is the **build script** for the host-side. It is responsible for:
        * Compiling the `bridge-circuit-guest` code into a RISC Zero ELF binary.
        * Computing the unique **method ID** for the compiled guest program.
        * Handling environment variables (like `BITCOIN_NETWORK` and `REPR_GUEST_BUILD`) to configure the build process, including optional Docker usage for guest builds.
        * Copying the generated ELF binary to a designated `elfs` folder. The destination filename incorporates a `test-` prefix if the `use-test-vk` feature is enabled.

* **`risc0-circuits/bridge-circuit/Cargo.toml`**
    * The package manifest for the host-side crate.
    * It defines the `bridge-circuit` package and its build-time dependencies, including `risc0-build` for the RISC Zero toolchain integration and `risc0-binfmt`.
    * It also defines the `use-test-vk` feature, which can influence the build process as seen in `build.rs`.

---