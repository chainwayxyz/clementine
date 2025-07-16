use crate::deposit::DepositData;
use crate::header_chain_prover::HeaderChainProver;
use bitcoin::blockdata::block::BlockHash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::secp256k1::SecretKey;
use bitvm::chunk::api::Assertions;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestParams {
    /// Controls whether the state manager component is initialized and run as part of the test setup.
    /// Allows for testing components in isolation from the state manager.
    pub should_run_state_manager: bool,

    /// Contains the secret keys for all simulated verifier nodes in the test environment.
    pub all_verifiers_secret_keys: Vec<SecretKey>,

    /// Contains the secret keys for all simulated operator nodes in the test.
    pub all_operators_secret_keys: Vec<SecretKey>,

    /// A fault injection flag. If true, an operator will intentionally commit to an incorrect latest block hash.
    /// This is used to test if verifiers can correctly detect and handle this invalid commitment.
    pub disrupt_latest_block_hash_commit: bool,

    /// A fault injection flag. If true, simulates an operator committing to an invalid block hash
    /// for the payout transaction.
    pub disrupt_payout_tx_block_hash_commit: bool,

    /// A fault injection flag for challenge sending watchtowers detection. When enabled, simulates an operator
    /// sending a corrupted or invalid commitment to watchtowers who has sent challenges.
    pub disrupt_challenge_sending_watchtowers_commit: bool,

    /// Simulates a scenario where an operator fails to include a watchtower, who has sent a challenge,
    pub operator_forgot_watchtower_challenge: bool,

    /// A flag to introduce intentionally inconsistent or invalid data into the BitVM assertions.
    pub corrupted_asserts: bool,

    /// A flag to indicate whether the public input for the BitVM challenge is corrupted.
    pub corrupted_public_input: bool,

    /// A flag to generate blocks to the address of the wallet.
    pub generate_to_address: bool,

    /// A flag to indicate whether to use small annexes in the watchtower challenge transactions.
    pub use_small_annex: bool,

    /// A flag to indicate whether to use large annexes in the watchtower challenge transactions.
    pub use_large_annex: bool,

    /// A flag to indicate whether to use large outputs in the watchtower challenge transactions.
    pub use_large_output: bool,

    /// A flag to indicate whether to use large annexes and outputs in the watchtower challenge transactions.
    pub use_large_annex_and_output: bool,

    /// A list of verifier indexes that should not attempt to send disprove transactions.
    pub verifier_do_not_send_disprove_indexes: Option<Vec<usize>>,

    /// A flag to enable data generation for bridge circuit tests (diverse total works).
    pub generate_varying_total_works_insufficient_total_work: bool,

    pub generate_varying_total_works: bool,

    pub generate_varying_total_works_first_two_valid: bool,

    #[serde(default)]
    pub timeout_params: TimeoutTestParams,
}

impl TestParams {
    /// Returns true if the verifier should attempt to send a disprove transaction, false otherwise.
    pub fn should_disprove(
        &self,
        verifier_pk: &PublicKey,
        deposit_data: &DepositData,
    ) -> eyre::Result<bool> {
        let verifier_idx = deposit_data.get_verifier_index(verifier_pk)?;
        Ok(self
            .verifier_do_not_send_disprove_indexes
            .as_ref()
            .is_none_or(|indexes| !indexes.contains(&verifier_idx)))
    }

    pub fn maybe_corrupt_asserts(&self, asserts: &mut Assertions) {
        use rand::Rng;
        if self.corrupted_asserts {
            let mut rng = rand::thread_rng();

            if rng.gen_bool(0.5) {
                let i = rng.gen_range(0..asserts.1.len());
                let j = rng.gen_range(0..asserts.1[i].len());
                tracing::info!("Disrupting asserts commit 1 with i: {}, j: {}", i, j);

                asserts.1[i][j] ^= 0x01;
            } else {
                let i = rng.gen_range(0..asserts.2.len());
                let j = rng.gen_range(0..asserts.2[i].len());
                tracing::info!("Disrupting asserts commit 2 with i: {}, j: {}", i, j);

                asserts.2[i][j] ^= 0x01;
            }
        } else if self.corrupted_public_input {
            let mut rng = rand::thread_rng();
            let j = rng.gen_range(1..asserts.0[0].len());

            tracing::info!("Disrupting public input with i: 0, j: {}", j);
            asserts.0[0][j] ^= 0x01;
        }
    }

    pub fn maybe_override_blockhashes_serialized(
        &self,
        blockhashes_serialized: &[[u8; 32]],
        payout_block_height: u32,
        genesis_height: u32,
    ) -> Vec<[u8; 32]> {
        if self.generate_varying_total_works_insufficient_total_work {
            let take_count = (payout_block_height + 1 - genesis_height) as usize;
            tracing::info!(
                "Overriding blockhashes: insufficient total work mode with {} blocks",
                take_count
            );
            return blockhashes_serialized
                .iter()
                .take(take_count)
                .cloned()
                .collect();
        }

        if self.generate_varying_total_works_first_two_valid {
            const HIGHEST_VALID_WT_INDEX: usize = 287;
            tracing::info!(
                "Overriding blockhashes: first two valid mode with {} blocks",
                HIGHEST_VALID_WT_INDEX
            );
            return blockhashes_serialized
                .iter()
                .take(HIGHEST_VALID_WT_INDEX)
                .cloned()
                .collect();
        }

        blockhashes_serialized.to_vec()
    }

    pub async fn maybe_override_current_hcp(
        &self,
        current_hcp: Receipt,
        payout_block_hash: BlockHash,
        block_hashes: &[(BlockHash, impl Sized)],
        header_chain_prover: &HeaderChainProver,
    ) -> eyre::Result<Receipt> {
        if self.generate_varying_total_works_insufficient_total_work {
            let (hcp, _) = header_chain_prover
                .prove_till_hash(payout_block_hash)
                .await?;
            return Ok(hcp);
        }

        if self.generate_varying_total_works_first_two_valid {
            let highest_valid_wt_index = 287;
            let target_blockhash = block_hashes.get(highest_valid_wt_index).ok_or_else(|| {
                eyre::eyre!("Missing blockhash at index {}", highest_valid_wt_index)
            })?;

            let (hcp, _) = header_chain_prover
                .prove_till_hash(target_blockhash.0)
                .await?;
            return Ok(hcp);
        }

        Ok(current_hcp)
    }

    pub fn maybe_disrupt_block_hash(&self, block_hash: [u8; 32]) -> [u8; 32] {
        if self.disrupt_latest_block_hash_commit {
            tracing::info!("Disrupting block hash commitment for testing purposes");
            tracing::info!("Original block hash: {:?}", block_hash);
            let mut disrupted = block_hash;
            disrupted[31] ^= 0x01;
            return disrupted;
        }

        block_hash
    }

    pub fn maybe_disrupt_commit_data_for_total_work(
        &self,
        commit_data: &mut [u8],
        total_work: &[u8],
    ) {
        if self.generate_varying_total_works_first_two_valid {
            let ref_total_work: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 64];

            tracing::debug!(
                "Ref total work: {:?}, total work: {:?}",
                ref_total_work,
                total_work
            );

            if let Ok(current_work) = total_work.try_into() {
                if ref_total_work < current_work {
                    commit_data[0] ^= 0x01;
                    tracing::info!(
                        "Flipping first byte of commit data to generate varying total work"
                    );
                }
            } else {
                tracing::warn!("Failed to convert total work to [u8; 16]");
            }
        }
    }

    pub fn maybe_disrupt_payout_tx_block_hash_commit(
        &self,
        payout_tx_blockhash: [u8; 20],
    ) -> [u8; 20] {
        if self.disrupt_payout_tx_block_hash_commit {
            tracing::info!(
                "Disrupting payout transaction block hash commitment for testing purposes"
            );
            let mut disrupted = payout_tx_blockhash;
            disrupted[19] ^= 0x01;
            return disrupted;
        }

        payout_tx_blockhash
    }

    pub fn maybe_disrupt_latest_block_hash_commit(&self, latest_block_hash: [u8; 32]) -> [u8; 32] {
        if self.disrupt_latest_block_hash_commit {
            tracing::info!("Disrupting latest block hash commitment for testing purposes");
            let mut disrupted = latest_block_hash;
            disrupted[31] ^= 0x01;
            return disrupted;
        }

        latest_block_hash
    }

    pub fn maybe_dump_bridge_circuit_params_to_file(
        &self,
        bridge_circuit_host_params: &impl borsh::BorshSerialize,
    ) -> eyre::Result<()> {
        if self.generate_varying_total_works_insufficient_total_work
            || self.generate_varying_total_works
            || self.generate_varying_total_works_first_two_valid
        {
            use std::path::PathBuf;

            let file_path = match (
             self.generate_varying_total_works,
             self.generate_varying_total_works_insufficient_total_work,
            self.generate_varying_total_works_first_two_valid,
        ) {
            (true, false, false) => PathBuf::from(
                "../bridge-circuit-host/bin-files/bch_params_varying_total_works.bin",
            ),
            (false, true, false) => PathBuf::from(
                "../bridge-circuit-host/bin-files/bch_params_varying_total_works_insufficient_total_work.bin",
            ),
            (false, false, true) => PathBuf::from(
                "../bridge-circuit-host/bin-files/bch_params_varying_total_works_first_two_valid.bin",
            ),
            _ => {
                panic!("Invalid or conflicting test params for generating varying total works");
            }
        };

            std::fs::create_dir_all(file_path.parent().unwrap())
                .map_err(|e| eyre::eyre!("Failed to create directory for output file: {}", e))?;
            let serialized_params = borsh::to_vec(&bridge_circuit_host_params).map_err(|e| {
                eyre::eyre!("Failed to serialize bridge circuit host params: {}", e)
            })?;
            std::fs::write(file_path.clone(), serialized_params).map_err(|e| {
                eyre::eyre!("Failed to write bridge circuit host params to file: {}", e)
            })?;
            tracing::info!("Bridge circuit host params written to {:?}", file_path);
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TimeoutTestParams {
    /// Verifier index that should time out during key distribution.
    pub key_distribution_verifier_idx: Option<usize>,
    /// Operator index that should time out during key distribution.
    pub key_collection_operator_idx: Option<usize>,
    /// Verifier index that should time out during nonce stream creation.
    pub nonce_stream_creation_verifier_idx: Option<usize>,
    /// Verifier index that should time out during partial signature stream creation.
    pub partial_sig_stream_creation_verifier_idx: Option<usize>,
    /// Operator index that should time out during operator signature collection.
    pub operator_sig_collection_operator_idx: Option<usize>,
    /// Verifier index that should time out during deposit finalization.
    pub deposit_finalize_verifier_idx: Option<usize>,
}

impl TimeoutTestParams {
    pub fn any_timeout(&self) -> bool {
        self.key_distribution_verifier_idx.is_some()
            || self.key_collection_operator_idx.is_some()
            || self.nonce_stream_creation_verifier_idx.is_some()
            || self.partial_sig_stream_creation_verifier_idx.is_some()
            || self.operator_sig_collection_operator_idx.is_some()
    }

    pub async fn hook_timeout_key_distribution_verifier(&self, idx: usize) {
        if self.key_distribution_verifier_idx == Some(idx) {
            use tokio::time::sleep;
            tokio::time::pause();
            sleep(crate::constants::KEY_DISTRIBUTION_TIMEOUT + std::time::Duration::from_secs(1))
                .await;
        }
    }

    pub async fn hook_timeout_key_collection_operator(&self, idx: usize) {
        if self.key_collection_operator_idx == Some(idx) {
            use tokio::time::sleep;
            tokio::time::pause();
            sleep(crate::constants::KEY_DISTRIBUTION_TIMEOUT + std::time::Duration::from_secs(1))
                .await;
        }
    }

    pub async fn hook_timeout_nonce_stream_creation_verifier(&self, idx: usize) {
        if self.nonce_stream_creation_verifier_idx == Some(idx) {
            use tokio::time::sleep;
            tokio::time::pause();
            sleep(
                crate::constants::NONCE_STREAM_CREATION_TIMEOUT + std::time::Duration::from_secs(1),
            )
            .await;
        }
    }

    pub async fn hook_timeout_partial_sig_stream_creation_verifier(&self, idx: usize) {
        if self.partial_sig_stream_creation_verifier_idx == Some(idx) {
            use tokio::time::sleep;
            tokio::time::pause();
            sleep(
                crate::constants::PARTIAL_SIG_STREAM_CREATION_TIMEOUT
                    + std::time::Duration::from_secs(1),
            )
            .await;
        }
    }

    pub async fn hook_timeout_operator_sig_collection_operator(&self, idx: usize) {
        if self.operator_sig_collection_operator_idx == Some(idx) {
            use tokio::time::sleep;
            tokio::time::pause();
            sleep(
                crate::constants::OPERATOR_SIGS_STREAM_CREATION_TIMEOUT
                    + std::time::Duration::from_secs(1),
            )
            .await;
        }
    }

    pub async fn hook_timeout_deposit_finalize_verifier(&self, idx: usize) {
        if self.deposit_finalize_verifier_idx == Some(idx) {
            use tokio::time::sleep;
            tokio::time::pause();
            sleep(
                crate::constants::DEPOSIT_FINALIZATION_TIMEOUT + std::time::Duration::from_secs(1),
            )
            .await;
        }
    }
}

impl Default for TestParams {
    fn default() -> Self {
        Self {
            should_run_state_manager: true,
            all_verifiers_secret_keys: vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                )
                .expect("known valid input"),
            ],
            all_operators_secret_keys: vec![
                SecretKey::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .expect("known valid input"),
                SecretKey::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("known valid input"),
            ],
            disrupt_latest_block_hash_commit: false,
            disrupt_payout_tx_block_hash_commit: false,
            disrupt_challenge_sending_watchtowers_commit: false,
            operator_forgot_watchtower_challenge: false,
            corrupted_asserts: false,
            corrupted_public_input: false,
            use_small_annex: false,
            use_large_annex: false,
            use_large_output: false,
            use_large_annex_and_output: false,
            timeout_params: TimeoutTestParams::default(),
            verifier_do_not_send_disprove_indexes: None,
            generate_to_address: true,
            generate_varying_total_works_insufficient_total_work: false,
            generate_varying_total_works: false,
            generate_varying_total_works_first_two_valid: false,
        }
    }
}
