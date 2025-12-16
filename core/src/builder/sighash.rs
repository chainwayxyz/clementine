//! # Sighash Builder
//!
//! This module provides functions and types for constructing signature hashes (sighashes) for the transactions in the Clementine bridge protocol.
//! Sighash is the message that is signed by the private key of the signer.
//!
//! The module supports generating sighash streams for both N-of-N (verifier) and operator signatures, as well as utilities for signature identification and protocol-specific signature requirements.
//! As the number of transactions can reach around 100_000 depending on number of entities in the protocol, we generate the sighashes in a stream to avoid memory issues.
//!
//! ## Responsibilities
//!
//! - Calculate the number of required signatures for various protocol roles and transaction types.
//! - Generate sighash streams for all protocol-required signatures for a deposit, for both verifiers and operators.
//! - Provide types for tracking signature requirements and spend paths.
//!
//! ## Key Types for Signatures
//!
//! - [`PartialSignatureInfo`] - Identifies a signature by operator, round, and kickoff index.
//! - [`SignatureInfo`] - Uniquely identifies a signature, including spend path of the signature.
//! - [`TapTweakData`] - Describes the spend path (key or script) and any required tweak data.
//!
//! For more on sighash types, see: <https://developer.bitcoin.org/devguide/transactions.html?highlight=sighash#signature-hash-types>

use crate::bitvm_client;
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::sign::get_kickoff_utxos_to_sign;
use crate::builder::transaction::{
    create_txhandlers, ContractContext, ReimburseDbCache, TxHandlerCache,
};
use clementine_errors::TransactionType;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{DepositData, KickoffData};
use clementine_primitives::RoundIndex;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::NormalSignatureKind;
use async_stream::try_stream;
use bitcoin::hashes::Hash;
use bitcoin::{TapNodeHash, TapSighash, XOnlyPublicKey};
use clementine_errors::BridgeError;
use futures_core::stream::Stream;

impl BridgeConfig {
    /// Returns the number of required signatures for N-of-N signing session.
    ///
    /// # Arguments
    /// * `deposit_data` - The deposit data for which to calculate required signatures.
    ///
    /// # Returns
    /// The number of required N-of-N signatures for the deposit.
    pub fn get_num_required_nofn_sigs(&self, deposit_data: &DepositData) -> usize {
        deposit_data.get_num_operators()
            * self.protocol_paramset().num_round_txs
            * self.protocol_paramset().num_signed_kickoffs
            * self.get_num_required_nofn_sigs_per_kickoff(deposit_data)
    }

    /// Returns the number of required operator signatures for a deposit.
    ///
    /// # Arguments
    /// * `deposit_data` - The deposit data for which to calculate required signatures.
    ///
    /// # Returns
    /// The number of required operator signatures for the deposit.
    pub fn get_num_required_operator_sigs(&self, deposit_data: &DepositData) -> usize {
        self.protocol_paramset().num_round_txs
            * self.protocol_paramset().num_signed_kickoffs
            * self.get_num_required_operator_sigs_per_kickoff(deposit_data)
    }

    /// Returns the number of required N-of-N signatures per kickoff for a deposit.
    ///
    /// # Arguments
    /// * `deposit_data` - The deposit data for which to calculate required signatures per kickoff.
    ///
    /// # Returns
    /// The number of required N-of-N signatures per kickoff.
    pub fn get_num_required_nofn_sigs_per_kickoff(&self, deposit_data: &DepositData) -> usize {
        7 + 4 * deposit_data.get_num_verifiers()
            + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs() * 2
    }

    /// Returns the number of required operator signatures per kickoff for a deposit.
    ///
    /// # Arguments
    /// * `deposit_data` - The deposit data for which to calculate required signatures per kickoff.
    ///
    /// # Returns
    /// The number of required operator signatures per kickoff.
    pub fn get_num_required_operator_sigs_per_kickoff(&self, deposit_data: &DepositData) -> usize {
        4 + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs()
            + deposit_data.get_num_verifiers()
    }

    /// Returns the total number of Winternitz public keys used in kickoff UTXOs for blockhash commits.
    ///
    /// # Returns
    /// The number of Winternitz public keys required for all rounds and kickoffs.
    pub fn get_num_kickoff_winternitz_pks(&self) -> usize {
        self.protocol_paramset().num_kickoffs_per_round
            * (self.protocol_paramset().num_round_txs + 1) // we need num_round_txs + 1 because we need one extra round tx to generate the reimburse connectors of the actual last round
    }

    /// Returns the total number of unspent kickoff signatures needed from each operator.
    ///
    /// # Returns
    /// The number of unspent kickoff signatures required for all rounds from one operator.
    pub fn get_num_unspent_kickoff_sigs(&self) -> usize {
        self.protocol_paramset().num_round_txs * self.protocol_paramset().num_kickoffs_per_round * 2
    }

    /// Returns the number of challenge ack hashes needed for a single operator for each round.
    ///
    /// # Arguments
    /// * `deposit_data` - The deposit data for which to calculate required challenge ack hashes.
    ///
    /// # Returns
    /// The number of challenge ack hashes required for the deposit.
    pub fn get_num_challenge_ack_hashes(&self, deposit_data: &DepositData) -> usize {
        deposit_data.get_num_watchtowers()
    }

    // /// Returns the number of winternitz pks needed for a single operator for each round
    // pub fn get_num_assert_winternitz_pks(&self) -> usize {
    //     crate::utils::BITVM_CACHE.num_intermediate_variables
    // }
}

/// Identifies a signature by operator, round, and kickoff index.
#[derive(Copy, Clone, Debug)]
pub struct PartialSignatureInfo {
    pub operator_idx: usize,
    pub round_idx: RoundIndex,
    pub kickoff_utxo_idx: usize,
}

/// Contains information about the spend path that is needed to sign the utxo.
/// If it is KeyPath, it also includes the merkle root hash of the scripts as
/// the root hash is needed to tweak the key before signing. For ScriptPath nothing is needed.
#[derive(Copy, Clone, Debug)]
pub enum TapTweakData {
    KeyPath(Option<TapNodeHash>),
    ScriptPath,
    Unknown,
}

/// Contains information to uniquely identify a single signature in the deposit.
/// operator_idx, round_idx, and kickoff_utxo_idx uniquely identify a kickoff.
/// signature_id uniquely identifies a signature in that specific kickoff.
/// tweak_data contains information about the spend path that is needed to sign the utxo.
/// kickoff_txid is the txid of the kickoff tx the signature belongs to. This is not actually needed for the signature, it is only used to
/// pass the kickoff txid to the caller of the sighash streams in this module.
#[derive(Copy, Clone, Debug)]
pub struct SignatureInfo {
    pub operator_idx: usize,
    pub round_idx: RoundIndex,
    pub kickoff_utxo_idx: usize,
    pub signature_id: SignatureId,
    pub tweak_data: TapTweakData,
    pub kickoff_txid: Option<bitcoin::Txid>,
}

impl PartialSignatureInfo {
    pub fn new(
        operator_idx: usize,
        round_idx: RoundIndex,
        kickoff_utxo_idx: usize,
    ) -> PartialSignatureInfo {
        PartialSignatureInfo {
            operator_idx,
            round_idx,
            kickoff_utxo_idx,
        }
    }
    /// Completes the partial info with a signature id and spend path data.
    pub fn complete(&self, signature_id: SignatureId, spend_data: TapTweakData) -> SignatureInfo {
        SignatureInfo {
            operator_idx: self.operator_idx,
            round_idx: self.round_idx,
            kickoff_utxo_idx: self.kickoff_utxo_idx,
            signature_id,
            tweak_data: spend_data,
            kickoff_txid: None,
        }
    }
    /// Completes the partial info with a kickoff txid (for yielding kickoff txid in sighash streams).
    pub fn complete_with_kickoff_txid(&self, kickoff_txid: bitcoin::Txid) -> SignatureInfo {
        SignatureInfo {
            operator_idx: self.operator_idx,
            round_idx: self.round_idx,
            kickoff_utxo_idx: self.kickoff_utxo_idx,
            signature_id: NormalSignatureKind::YieldKickoffTxid.into(),
            tweak_data: TapTweakData::ScriptPath,
            kickoff_txid: Some(kickoff_txid),
        }
    }
}

/// Generates the sighash stream for all N-of-N (verifier) signatures required for a deposit. See [clementine whitepaper](https://citrea.xyz/clementine_whitepaper.pdf) for details on the transactions.
///
/// For a given deposit, for each operator and round, generates the sighash stream for all protocol-required transactions.
/// If `yield_kickoff_txid` is true, yields the kickoff txid as a special entry.
///
/// # Arguments
/// * `db` - Database handle.
/// * `config` - Bridge configuration.
/// * `deposit_data` - Deposit data for which to generate sighashes.
/// * `deposit_blockhash` - Block hash of the deposit.
/// * `yield_kickoff_txid` - Whether to yield the kickoff txid as a special entry.
///
/// # Returns
///
/// An async stream of ([`TapSighash`], [`SignatureInfo`]) pairs, or [`BridgeError`] on failure.
pub fn create_nofn_sighash_stream(
    db: Database,
    config: BridgeConfig,
    deposit_data: DepositData,
    deposit_blockhash: bitcoin::BlockHash,
    yield_kickoff_txid: bool,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        let paramset = config.protocol_paramset();

        let operators = deposit_data.get_operators();

        for (operator_idx, op_xonly_pk) in
            operators.iter().enumerate()
        {

            let utxo_idxs = get_kickoff_utxos_to_sign(
                config.protocol_paramset(),
                *op_xonly_pk,
                deposit_blockhash,
                deposit_data.get_deposit_outpoint(),
            );
            // need to create new TxHandlerDbData for each operator
            let mut tx_db_data = ReimburseDbCache::new_for_deposit(db.clone(), *op_xonly_pk, deposit_data.get_deposit_outpoint(), config.protocol_paramset(), None);

            let mut txhandler_cache = TxHandlerCache::new();

            for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
                // For each round, we have multiple kickoff_utxos to sign for the deposit.
                for &kickoff_idx in &utxo_idxs {
                    let partial = PartialSignatureInfo::new(operator_idx, round_idx, kickoff_idx);

                    let context = ContractContext::new_context_for_kickoff(
                        KickoffData {
                            operator_xonly_pk: *op_xonly_pk,
                            round_idx,
                            kickoff_idx: kickoff_idx as u32,
                        },
                        deposit_data.clone(),
                        config.protocol_paramset(),
                    );

                    let mut txhandlers = create_txhandlers(
                        TransactionType::AllNeededForDeposit,
                        context,
                        &mut txhandler_cache,
                        &mut tx_db_data,
                    ).await?;

                    let mut sum = 0;
                    let mut kickoff_txid = None;
                    for (tx_type, txhandler) in txhandlers.iter() {
                        let sighashes = txhandler.calculate_shared_txins_sighash(EntityType::VerifierDeposit, partial)?;
                        sum += sighashes.len();
                        for sighash in sighashes {
                            yield sighash;
                        }
                        if tx_type == &TransactionType::Kickoff {
                            kickoff_txid = Some(txhandler.get_txid());
                        }
                    }

                    match (yield_kickoff_txid, kickoff_txid) {
                        (true, Some(kickoff_txid)) => {
                            yield (TapSighash::all_zeros(), partial.complete_with_kickoff_txid(*kickoff_txid));
                        }
                        (true, None) => {
                            Err(eyre::eyre!("Kickoff txid not found in sighash stream"))?;
                        }
                        _ => {}
                    }


                    if sum != config.get_num_required_nofn_sigs_per_kickoff(&deposit_data) {
                        Err(eyre::eyre!("NofN sighash count does not match: expected {0}, got {1}", config.get_num_required_nofn_sigs_per_kickoff(&deposit_data), sum))?;
                    }
                    // recollect round_tx, ready_to_reimburse_tx, and move_to_vault_tx for the next kickoff_utxo
                    txhandler_cache.store_for_next_kickoff(&mut txhandlers)?;
                }
                // collect the last ready_to_reimburse txhandler for the next round
                txhandler_cache.store_for_next_round()?;
            }
        }
    }
}

/// Generates the sighash stream for all operator signatures required for a deposit. These signatures required by the operators are
/// the signatures needed to burn the collateral of the operators, only able to be burned if the operator is malicious.
/// See [clementine whitepaper](https://citrea.xyz/clementine_whitepaper.pdf) for details on the transactions.
///
/// # Arguments
/// * `db` - Database handle.
/// * `operator_xonly_pk` - X-only public key of the operator.
/// * `config` - Bridge configuration.
/// * `deposit_data` - Deposit data for which to generate sighashes.
/// * `deposit_blockhash` - Block hash of the deposit.
///
/// # Returns
///
/// An async stream of (sighash, [`SignatureInfo`]) pairs, or [`BridgeError`] on failure.
// Possible future optimization: Each verifier already generates some of these TX's in create_nofn_sighash_stream()
// It is possible to for verifiers somehow return the required sighashes for operator signatures there too. But operators only needs to use sighashes included in this function.
pub fn create_operator_sighash_stream(
    db: Database,
    operator_xonly_pk: XOnlyPublicKey,
    config: BridgeConfig,
    deposit_data: DepositData,
    deposit_blockhash: bitcoin::BlockHash,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        let mut tx_db_data = ReimburseDbCache::new_for_deposit(db.clone(), operator_xonly_pk, deposit_data.get_deposit_outpoint(), config.protocol_paramset(), None);

        let operator = db.get_operator(None, operator_xonly_pk).await?;

        let operator = match operator {
            Some(operator) => operator,
            None => Err(BridgeError::OperatorNotFound(operator_xonly_pk))?,
        };

        let utxo_idxs = get_kickoff_utxos_to_sign(
            config.protocol_paramset(),
            operator.xonly_pk,
            deposit_blockhash,
            deposit_data.get_deposit_outpoint(),
        );

        let paramset = config.protocol_paramset();
        let mut txhandler_cache = TxHandlerCache::new();
        let operator_idx = deposit_data.get_operator_index(operator_xonly_pk)?;

        // For each round_tx, we have multiple kickoff_utxos as the connectors.
        for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
            for &kickoff_idx in &utxo_idxs {
                let partial = PartialSignatureInfo::new(operator_idx, round_idx, kickoff_idx);

                let context = ContractContext::new_context_for_kickoff(
                    KickoffData {
                        operator_xonly_pk,
                        round_idx,
                        kickoff_idx: kickoff_idx as u32,
                    },
                    deposit_data.clone(),
                    config.protocol_paramset(),
                );

                let mut txhandlers = create_txhandlers(
                    TransactionType::AllNeededForDeposit,
                    context,
                    &mut txhandler_cache,
                    &mut tx_db_data,
                ).await?;

                let mut sum = 0;
                for (_, txhandler) in txhandlers.iter() {
                    let sighashes = txhandler.calculate_shared_txins_sighash(EntityType::OperatorDeposit, partial)?;
                    sum += sighashes.len();
                    for sighash in sighashes {
                        yield sighash;
                    }
                }
                if sum != config.get_num_required_operator_sigs_per_kickoff(&deposit_data) {
                    Err(eyre::eyre!("Operator sighash count does not match: expected {0}, got {1}", config.get_num_required_operator_sigs_per_kickoff(&deposit_data), sum))?;
                }
                // recollect round_tx, ready_to_reimburse_tx, and move_to_vault_tx for the next kickoff_utxo
                txhandler_cache.store_for_next_kickoff(&mut txhandlers)?;
            }
            // collect the last ready_to_reimburse txhandler for the next round
            txhandler_cache.store_for_next_round()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitvm_client::SECP,
        builder::transaction::sign::TransactionRequestData,
        config::protocol::ProtocolParamset,
        deposit::{Actors, DepositInfo, OperatorData},
        extended_bitcoin_rpc::ExtendedBitcoinRpc,
        rpc::clementine::{
            clementine_operator_client::ClementineOperatorClient, TransactionRequest,
        },
        test::common::{
            citrea::MockCitreaClient, create_actors, create_regtest_rpc,
            create_test_config_with_thread_name, run_single_deposit,
            tx_utils::get_tx_from_signed_txs_with_type,
        },
    };
    use bincode;
    use bitcoin::hashes::sha256;
    use bitcoin::secp256k1::PublicKey;
    use bitcoin::{Block, BlockHash, OutPoint, Txid};
    use bitcoincore_rpc::RpcApi;
    use futures_util::stream::TryStreamExt;
    use std::fs::File;

    #[cfg(debug_assertions)]
    pub const DEPOSIT_STATE_FILE_PATH_DEBUG: &str = "src/test/data/deposit_state_debug.bincode";
    #[cfg(not(debug_assertions))]
    pub const DEPOSIT_STATE_FILE_PATH_RELEASE: &str = "src/test/data/deposit_state_release.bincode";

    /// State of the chain and the deposit generated in generate_deposit_state() test.
    /// Contains:
    /// - Blocks: All blocks from height 1 until the chain tip.
    /// - Deposit info: Deposit info of the deposit that were signed.
    /// - Deposit blockhash: Block hash of the deposit outpoint.
    /// - Move txid: Move to vault txid of the deposit.
    /// - Operator data: Operator data of the single operator that were used in the deposit.
    /// - Round tx txid hash: Hash of all round tx txids of the operator.
    /// - Nofn sighash hash: Hash of all nofn sighashes of the deposit.
    /// - Operator sighash hash: Hash of all operator sighashes of the deposit.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct DepositChainState {
        blocks: Vec<Block>,
        deposit_info: DepositInfo,
        deposit_blockhash: BlockHash,
        move_txid: Txid,
        operator_data: OperatorData,
        round_tx_txid_hash: sha256::Hash,
        nofn_sighash_hash: sha256::Hash,
        operator_sighash_hash: sha256::Hash,
    }

    /// To make the [`test_bridge_contract_change`] test work if breaking changes are expected, run this test again
    /// (with both debug and release), the states will get updated with the current values.
    /// Read [`test_bridge_contract_change`] test doc for more details.
    #[cfg(feature = "automation")]
    #[tokio::test]
    #[ignore = "Run this to generate fresh deposit state data, in case any breaking change occurs to deposits"]
    async fn generate_deposit_state() {
        let mut config = create_test_config_with_thread_name().await;
        // only run with one operator
        config.test_params.all_operators_secret_keys.truncate(1);

        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let actors = create_actors::<MockCitreaClient>(&config).await;
        let (deposit_info, move_txid, deposit_blockhash, verifiers_public_keys) =
            run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, &actors, None)
                .await
                .unwrap();

        // get generated blocks
        let height = rpc.get_current_chain_height().await.unwrap();
        let mut blocks = Vec::new();
        for i in 1..=height {
            let (blockhash, _) = rpc.get_block_info_by_height(i as u64).await.unwrap();
            let block = rpc.get_block(&blockhash).await.unwrap();
            blocks.push(block);
        }

        let op0_config = BridgeConfig {
            secret_key: config.test_params.all_verifiers_secret_keys[0],
            db_name: config.db_name + "0",
            ..config
        };

        let operators_xonly_pks = op0_config
            .test_params
            .all_operators_secret_keys
            .iter()
            .map(|sk| sk.x_only_public_key(&SECP).0)
            .collect::<Vec<_>>();

        let op0_xonly_pk = operators_xonly_pks[0];

        let db = Database::new(&op0_config).await.unwrap();
        let operator_data = db.get_operator(None, op0_xonly_pk).await.unwrap().unwrap();

        let (nofn_sighash_hash, operator_sighash_hash) = calculate_hash_of_sighashes(
            deposit_info.clone(),
            verifiers_public_keys,
            operators_xonly_pks.clone(),
            op0_config.clone(),
            deposit_blockhash,
        )
        .await;

        let operator = actors.get_operator_client_by_index(0);

        let round_tx_txid_hash = compute_hash_of_round_txs(
            operator,
            deposit_info.deposit_outpoint,
            operators_xonly_pks[0],
            deposit_blockhash,
            op0_config.protocol_paramset(),
        )
        .await;

        let deposit_state = DepositChainState {
            blocks,
            deposit_blockhash,
            move_txid,
            deposit_info,
            operator_data,
            round_tx_txid_hash,
            nofn_sighash_hash,
            operator_sighash_hash,
        };

        #[cfg(debug_assertions)]
        let file_path = DEPOSIT_STATE_FILE_PATH_DEBUG;
        #[cfg(not(debug_assertions))]
        let file_path = DEPOSIT_STATE_FILE_PATH_RELEASE;

        // save to file
        let file = File::create(file_path).unwrap();
        bincode::serialize_into(file, &deposit_state).unwrap();
    }

    async fn load_deposit_state(rpc: &ExtendedBitcoinRpc) -> DepositChainState {
        tracing::debug!(
            "Current chain height: {}",
            rpc.get_current_chain_height().await.unwrap()
        );
        #[cfg(debug_assertions)]
        let file_path = DEPOSIT_STATE_FILE_PATH_DEBUG;
        #[cfg(not(debug_assertions))]
        let file_path = DEPOSIT_STATE_FILE_PATH_RELEASE;

        let file = File::open(file_path).unwrap();
        let deposit_state: DepositChainState = bincode::deserialize_from(file).unwrap();

        // submit blocks to current rpc
        for block in &deposit_state.blocks {
            rpc.submit_block(block).await.unwrap();
        }
        deposit_state
    }

    /// Returns the hash of all round txs txids for a given operator.
    async fn compute_hash_of_round_txs(
        mut operator: ClementineOperatorClient<tonic::transport::Channel>,
        deposit_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_blockhash: bitcoin::BlockHash,
        paramset: &'static ProtocolParamset,
    ) -> sha256::Hash {
        let kickoff_utxo = get_kickoff_utxos_to_sign(
            paramset,
            operator_xonly_pk,
            deposit_blockhash,
            deposit_outpoint,
        )[0];

        let mut all_round_txids = Vec::new();
        for i in 0..paramset.num_round_txs {
            let tx_req = TransactionRequestData {
                deposit_outpoint,
                kickoff_data: KickoffData {
                    operator_xonly_pk,
                    round_idx: RoundIndex::Round(i),
                    kickoff_idx: kickoff_utxo as u32,
                },
            };
            let signed_txs = operator
                .internal_create_signed_txs(TransactionRequest::from(tx_req))
                .await
                .unwrap()
                .into_inner();
            let round_tx =
                get_tx_from_signed_txs_with_type(&signed_txs, TransactionType::Round).unwrap();
            all_round_txids.push(round_tx.compute_txid());
        }

        sha256::Hash::hash(&all_round_txids.concat())
    }

    /// Calculates the hash of all nofn and operator sighashes for a given deposit.
    async fn calculate_hash_of_sighashes(
        deposit_info: DepositInfo,
        verifiers_public_keys: Vec<PublicKey>,
        operators_xonly_pks: Vec<XOnlyPublicKey>,
        op0_config: BridgeConfig,
        deposit_blockhash: bitcoin::BlockHash,
    ) -> (sha256::Hash, sha256::Hash) {
        let deposit_data = DepositData {
            nofn_xonly_pk: None,
            deposit: deposit_info,
            actors: Actors {
                verifiers: verifiers_public_keys,
                watchtowers: vec![],
                operators: operators_xonly_pks.clone(),
            },
            security_council: op0_config.security_council.clone(),
        };

        let db = Database::new(&op0_config).await.unwrap();

        let sighash_stream = create_nofn_sighash_stream(
            db.clone(),
            op0_config.clone(),
            deposit_data.clone(),
            deposit_blockhash,
            true,
        );

        let nofn_sighashes: Vec<_> = sighash_stream.try_collect().await.unwrap();
        let nofn_sighashes = nofn_sighashes
            .into_iter()
            .map(|(sighash, _info)| sighash.to_byte_array())
            .collect::<Vec<_>>();

        let operator_streams = create_operator_sighash_stream(
            db.clone(),
            operators_xonly_pks[0],
            op0_config.clone(),
            deposit_data.clone(),
            deposit_blockhash,
        );

        let operator_sighashes: Vec<_> = operator_streams.try_collect().await.unwrap();
        let operator_sighashes = operator_sighashes
            .into_iter()
            .map(|(sighash, _info)| sighash.to_byte_array())
            .collect::<Vec<_>>();

        // Hash the vectors
        let nofn_hash = sha256::Hash::hash(&nofn_sighashes.concat());
        let operator_hash = sha256::Hash::hash(&operator_sighashes.concat());

        (nofn_hash, operator_hash)
    }

    /// Test for checking if the sighash stream is changed due to changes in code.
    /// If this test fails, the code contains breaking changes that needs replacement deposits on deployment.
    /// It is also possible that round tx's are changed, which is a bigger issue. In addition to replacement deposits,
    /// the collaterals of operators that created at least round 1 are unusable.
    ///
    /// Its also possible for this test to fail if default config is changed(for example num_verifiers, operators, etc).
    ///
    /// This test only uses one operator, because it is hard (too much code duplication) with
    /// current test setup fn's to generate operators with different configs (config has the
    /// reimburse address and collateral funding outpoint, which should be loaded from the saved
    /// deposit state)
    ///
    /// To make the test work if breaking changes are expected, run generate_deposit_state() test again
    /// (with both debug and release), it will get updated with the current values. Run following commands:
    /// debug: cargo test --all-features generate_deposit_state -- --ignored
    /// release: cargo test --all-features --release generate_deposit_state -- --ignored
    /// If test_bridge_contract_change failed on github CI, CI also uploads the deposit state file as an artifact, so it can be downloaded
    /// and committed to the repo.
    #[cfg(feature = "automation")]
    #[tokio::test]
    async fn test_bridge_contract_change() {
        let mut config = create_test_config_with_thread_name().await;
        // only run with one operator
        config.test_params.all_operators_secret_keys.truncate(1);

        // do not generate to address
        config.test_params.generate_to_address = false;

        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let deposit_state = load_deposit_state(&rpc).await;

        // set operator reimbursement address and collateral funding outpoint to the ones from the saved deposit state
        config.operator_reimbursement_address = Some(
            deposit_state
                .operator_data
                .reimburse_addr
                .as_unchecked()
                .to_owned(),
        );
        config.operator_collateral_funding_outpoint =
            Some(deposit_state.operator_data.collateral_funding_outpoint);

        // after loading generate some funds to rpc wallet
        // needed so that the deposit doesn't crash (I don't know why) due to insufficient funds
        let address = rpc
            .get_new_address(None, None)
            .await
            .expect("Failed to get new address");

        rpc.generate_to_address(105, address.assume_checked_ref())
            .await
            .expect("Failed to generate blocks");

        let actors = create_actors::<MockCitreaClient>(&config).await;
        let (deposit_info, move_txid, deposit_blockhash, verifiers_public_keys) =
            run_single_deposit::<MockCitreaClient>(
                &mut config,
                rpc.clone(),
                None,
                &actors,
                Some(deposit_state.deposit_info.deposit_outpoint),
            )
            .await
            .unwrap();

        // sanity checks, these should be equal if the deposit state saved is still valid
        // if not a new deposit state needs to be generated
        assert_eq!(move_txid, deposit_state.move_txid);
        assert_eq!(deposit_blockhash, deposit_state.deposit_blockhash);
        assert_eq!(deposit_info, deposit_state.deposit_info);

        let op0_config = BridgeConfig {
            secret_key: config.test_params.all_verifiers_secret_keys[0],
            db_name: config.db_name.clone() + "0",
            ..config.clone()
        };

        let operators_xonly_pks = op0_config
            .test_params
            .all_operators_secret_keys
            .iter()
            .map(|sk| sk.x_only_public_key(&SECP).0)
            .collect::<Vec<_>>();

        let operator = actors.get_operator_client_by_index(0);

        let round_tx_hash = compute_hash_of_round_txs(
            operator,
            deposit_info.deposit_outpoint,
            operators_xonly_pks[0],
            deposit_blockhash,
            op0_config.protocol_paramset(),
        )
        .await;

        // If this fails, the round txs are changed.
        assert_eq!(
            round_tx_hash, deposit_state.round_tx_txid_hash,
            "Round tx hash does not match the previous values, round txs are changed"
        );

        let (nofn_hash, operator_hash) = calculate_hash_of_sighashes(
            deposit_info,
            verifiers_public_keys,
            operators_xonly_pks,
            op0_config,
            deposit_blockhash,
        )
        .await;

        // If these fail, the bridge contract is changed.
        assert_eq!(
            nofn_hash, deposit_state.nofn_sighash_hash,
            "NofN sighashes do not match the previous values"
        );
        assert_eq!(
            operator_hash, deposit_state.operator_sighash_hash,
            "Operator sighashes do not match the previous values"
        );
    }
}
