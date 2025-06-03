//! # Sighash Builder
//!
//! Sighash builder provides useful functions for building related SigHashes.
//! Sighash is the message that is signed by the private key of the signer. It is used to signal
//! under which conditions the input is signed. For more, see:
//! <https://developer.bitcoin.org/devguide/transactions.html?highlight=sighash#signature-hash-types>

use super::transaction::DepositData;
use crate::bitvm_client;
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::sign::get_kickoff_utxos_to_sign;
use crate::builder::transaction::{
    create_txhandlers, ContractContext, KickoffData, ReimburseDbCache, TransactionType,
    TxHandlerCache,
};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::NormalSignatureKind;
use async_stream::try_stream;
use bitcoin::hashes::Hash;
use bitcoin::{TapNodeHash, TapSighash, XOnlyPublicKey};
use futures_core::stream::Stream;

impl BridgeConfig {
    /// Returns the number of required signatures for N-of-N signing session.
    pub fn get_num_required_nofn_sigs(&self, deposit_data: &DepositData) -> usize {
        deposit_data.get_num_operators()
            * self.protocol_paramset().num_round_txs
            * self.protocol_paramset().num_signed_kickoffs
            * self.get_num_required_nofn_sigs_per_kickoff(deposit_data)
    }

    // WIP: For now, this is equal to the number of sighashes we yield in create_operator_sighash_stream.
    // This will change as we implement the system design.
    pub fn get_num_required_operator_sigs(&self, deposit_data: &DepositData) -> usize {
        self.protocol_paramset().num_round_txs
            * self.protocol_paramset().num_signed_kickoffs
            * self.get_num_required_operator_sigs_per_kickoff(deposit_data)
    }

    pub fn get_num_required_nofn_sigs_per_kickoff(&self, deposit_data: &DepositData) -> usize {
        7 + 4 * deposit_data.get_num_verifiers()
            + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs() * 2
    }

    pub fn get_num_required_operator_sigs_per_kickoff(&self, deposit_data: &DepositData) -> usize {
        4 + bitvm_client::ClementineBitVMPublicKeys::number_of_assert_txs()
            + deposit_data.get_num_verifiers()
    }

    /// Returns the total number of winternitz pks used in kickoff utxos for blockhash commits
    pub fn get_num_kickoff_winternitz_pks(&self) -> usize {
        self.protocol_paramset().num_kickoffs_per_round
            * (self.protocol_paramset().num_round_txs + 1)
    }

    /// Returns the total number of unspent kickoff signatures needed from each operator
    pub fn get_num_unspent_kickoff_sigs(&self) -> usize {
        self.protocol_paramset().num_round_txs * self.protocol_paramset().num_kickoffs_per_round * 2
    }

    /// Returns the number of challenge ack hashes needed for a single operator for each round
    pub fn get_num_challenge_ack_hashes(&self, deposit_data: &DepositData) -> usize {
        deposit_data.get_num_watchtowers()
    }

    // /// Returns the number of winternitz pks needed for a single operator for each round
    // pub fn get_num_assert_winternitz_pks(&self) -> usize {
    //     crate::utils::BITVM_CACHE.num_intermediate_variables
    // }
}

#[derive(Copy, Clone, Debug)]
pub struct PartialSignatureInfo {
    pub operator_idx: usize,
    pub round_idx: usize,
    pub kickoff_utxo_idx: usize,
}

/// Contains information about the spend path that is needed to sign the utxo.
/// If it is KeyPath, it also includes the merkle root hash of the scripts as
/// the hash is needed to tweak the key before signing. For ScriptPath nothing is needed.
#[derive(Copy, Clone, Debug)]
pub enum TapTweakData {
    KeyPath(Option<TapNodeHash>),
    ScriptPath,
    Unknown,
}

#[derive(Copy, Clone, Debug)]
pub struct SignatureInfo {
    pub operator_idx: usize,
    pub round_idx: usize,
    pub kickoff_utxo_idx: usize,
    pub signature_id: SignatureId,
    pub tweak_data: TapTweakData,
    pub kickoff_txid: Option<bitcoin::Txid>,
}

impl PartialSignatureInfo {
    pub fn new(
        operator_idx: usize,
        round_idx: usize,
        kickoff_utxo_idx: usize,
    ) -> PartialSignatureInfo {
        PartialSignatureInfo {
            operator_idx,
            round_idx,
            kickoff_utxo_idx,
        }
    }
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

/// Refer to bridge design diagram to see which NofN signatures are needed (the ones marked with blue arrows).
/// These sighashes are needed in order to create the message to be signed later for MuSig2 of NofN.
/// yield_kickoff_txid is used to yield the kickoff txid
/// Kickoff txid yield has an empty sighash and a signature info with the kickoff txid
/// For a given deposit tx, for each operator and round tx, generates the sighash stream for:
/// - challenge_tx,
/// - start_happy_reimburse_tx,
/// - happy_reimburse_tx,
/// - watchtower_challenge_kickoff_tx,
/// - kickoff_timeout_tx,
/// - for each watchtower, operator_challenge_NACK_tx (for 2 inputs),
/// - assert_end_tx,
/// - disprove_timeout_tx (for 2 inputs),
/// - already_disproved_tx,
/// - reimburse_tx.
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
            let mut tx_db_data = ReimburseDbCache::new_for_deposit(db.clone(), *op_xonly_pk, deposit_data.get_deposit_outpoint(), config.protocol_paramset());

            let mut txhandler_cache = TxHandlerCache::new();

            // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
            for round_idx in 1..=paramset.num_round_txs {
                // For each kickoff_utxo, it connnects to a kickoff_tx that results in
                // either start_happy_reimburse_tx
                // or challenge_tx, which forces the operator to initiate BitVM sequence
                // (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
                // If the operator is honest, the sequence will end with the operator being able to send the reimburse_tx.
                // Otherwise, by using the disprove_tx, the operator's sequential_collateral_tx burn connector will be burned.
                for &kickoff_idx in &utxo_idxs {
                    let partial = PartialSignatureInfo::new(operator_idx, round_idx, kickoff_idx);

                    let context = ContractContext::new_context_for_kickoffs(
                        KickoffData {
                            operator_xonly_pk: *op_xonly_pk,
                            round_idx: round_idx as u32,
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
                            Err(BridgeError::Error("Kickoff txid not found in sighash stream".to_string()))?;
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
/// These operator sighashes are needed so that each operator can share the signatures with each verifier, so that
/// verifiers have the ability to burn the burn connector of operators.
/// WIP: Update if the design changes.
/// This function generates Kickoff Timeout TX, Already Disproved TX,
/// and Disprove TX for each sequential_collateral_tx and kickoff_utxo. It yields the sighashes for these tx's for the input that has operators burn connector.
/// Possible future optimization: Each verifier already generates some of these TX's in create_operator_sighash_stream()
/// It is possible to for verifiers somehow return the required sighashes for operator signatures there too. But operators only needs to use sighashes included in this function.
pub fn create_operator_sighash_stream(
    db: Database,
    operator_xonly_pk: XOnlyPublicKey,
    config: BridgeConfig,
    deposit_data: DepositData,
    deposit_blockhash: bitcoin::BlockHash,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        let mut tx_db_data = ReimburseDbCache::new_for_deposit(db.clone(), operator_xonly_pk, deposit_data.get_deposit_outpoint(), config.protocol_paramset());

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
        for round_idx in 1..=paramset.num_round_txs {
            for &kickoff_idx in &utxo_idxs {
                let partial = PartialSignatureInfo::new(operator_idx, round_idx, kickoff_idx);

                let context = ContractContext::new_context_for_kickoffs(
                    KickoffData {
                        operator_xonly_pk,
                        round_idx: round_idx as u32,
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
