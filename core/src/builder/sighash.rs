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
    create_txhandlers, ContractContext, ReimburseDbCache, TransactionType, TxHandlerCache,
};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{DepositData, KickoffData};
use crate::errors::BridgeError;
use crate::operator::RoundIndex;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::NormalSignatureKind;
use async_stream::try_stream;
use bitcoin::hashes::Hash;
use bitcoin::{TapNodeHash, TapSighash, XOnlyPublicKey};
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
