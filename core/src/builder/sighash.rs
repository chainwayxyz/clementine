//! # Sighash Builder
//!
//! Sighash builder provides useful functions for building related SigHashes.
//! Sighash is the message that is signed by the private key of the signer. It is used to signal
//! under which conditions the input is signed. For more, see:
//! https://developer.bitcoin.org/devguide/transactions.html?highlight=sighash#signature-hash-types

use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::{
    create_txhandlers, DepositData, OperatorData, ReimburseDbCache, TransactionType, TxHandler,
};
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::KickoffId;
use crate::utils;
use async_stream::try_stream;
use bitcoin::{Address, OutPoint, TapSighash, XOnlyPublicKey};
use futures_core::stream::Stream;

impl BridgeConfig {
    /// Returns the number of required signatures for N-of-N signing session.
    pub fn get_num_required_nofn_sigs(&self) -> usize {
        self.num_operators
            * self.num_round_txs
            * self.num_kickoffs_per_round
            * self.get_num_required_nofn_sigs_per_kickoff()
    }

    // WIP: For now, this is equal to the number of sighashes we yield in create_operator_sighash_stream.
    // This will change as we implement the system design.
    pub fn get_num_required_operator_sigs(&self) -> usize {
        self.num_round_txs
            * self.num_kickoffs_per_round
            * self.get_num_required_operator_sigs_per_kickoff()
    }

    pub fn get_num_required_nofn_sigs_per_kickoff(&self) -> usize {
        7 + 2 * self.num_watchtowers + utils::COMBINED_ASSERT_DATA.num_steps.len() * 2
    }

    pub fn get_num_required_operator_sigs_per_kickoff(&self) -> usize {
        2 + utils::COMBINED_ASSERT_DATA.num_steps.len() + self.num_watchtowers
    }

    /// Returns the total number of winternitz pks used in kickoff utxos for blockhash commits
    pub fn get_num_kickoff_winternitz_pks(&self) -> usize {
        self.num_kickoffs_per_round * (self.num_round_txs + 1)
    }

    /// Returns the total number of unspent kickoff signatures needed from each operator
    pub fn get_num_unspent_kickoff_sigs(&self) -> usize {
        self.num_round_txs * self.num_kickoffs_per_round * 2
    }

    /// Returns the number of challenge ack hashes needed for a single operator for each round
    pub fn get_num_challenge_ack_hashes(&self) -> usize {
        self.num_watchtowers
    }

    /// Returns the number of winternitz pks needed for a single operator for each round
    pub fn get_num_assert_winternitz_pks(&self) -> usize {
        crate::utils::BITVM_CACHE.intermediate_variables.len()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PartialSignatureInfo {
    pub operator_idx: usize,
    pub round_idx: usize,
    pub kickoff_utxo_idx: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct SignatureInfo {
    pub operator_idx: usize,
    pub round_idx: usize,
    pub kickoff_utxo_idx: usize,
    pub signature_id: SignatureId,
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
    pub fn complete(&self, signature_id: SignatureId) -> SignatureInfo {
        SignatureInfo {
            operator_idx: self.operator_idx,
            round_idx: self.round_idx,
            kickoff_utxo_idx: self.kickoff_utxo_idx,
            signature_id,
        }
    }
}

/// Refer to bridge design diagram to see which NofN signatures are needed (the ones marked with blue arrows).
/// These sighashes are needed in order to create the message to be signed later for MuSig2 of NofN.
/// WIP: Update if the design changes.
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
    nofn_xonly_pk: XOnlyPublicKey,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        // Get operator details (for each operator, (X-Only Public Key, Address, Collateral Funding Txid))
        let operators: Vec<(XOnlyPublicKey, bitcoin::Address, OutPoint)> =
            db.get_operators(None).await?;
        if operators.len() < config.num_operators {
            Err(BridgeError::NotEnoughOperators)?;
        }

        for (operator_idx, (operator_xonly_pk, operator_reimburse_address, collateral_funding_outpoint)) in
            operators.iter().enumerate()
        {
            // need to create new TxHandlerDbData for each operator
            let mut tx_db_data = ReimburseDbCache::new(db.clone(), operator_idx as u32, deposit_data.clone(), config.clone());

            let mut last_ready_to_reimburse: Option<TxHandler> = None;

            let operator_data = OperatorData {
                xonly_pk: *operator_xonly_pk,
                reimburse_addr: operator_reimburse_address.clone(),
                collateral_funding_outpoint: *collateral_funding_outpoint,
            };


            // For each sequential_collateral_tx, we have multiple kickoff_utxos as the connectors.
            for round_iidx in 0..config.num_round_txs {
                // For each kickoff_utxo, it connnects to a kickoff_tx that results in
                // either start_happy_reimburse_tx
                // or challenge_tx, which forces the operator to initiate BitVM sequence
                // (assert_begin_tx -> assert_end_tx -> either disprove_timeout_tx or already_disproven_tx).
                // If the operator is honest, the sequence will end with the operator being able to send the reimburse_tx.
                // Otherwise, by using the disprove_tx, the operator's sequential_collateral_tx burn connector will be burned.
                for kickoff_idx in 0..config.num_kickoffs_per_round {
                    let partial = PartialSignatureInfo::new(operator_idx, round_iidx, kickoff_idx);

                    let mut txhandlers = create_txhandlers(
                        nofn_xonly_pk,
                        TransactionType::AllNeededForDeposit,
                        KickoffId {
                            operator_idx: operator_idx as u32,
                            round_idx: round_iidx as u32,
                            kickoff_idx: kickoff_idx as u32,
                        },
                        operator_data.clone(),
                        last_ready_to_reimburse,
                        &mut tx_db_data,
                    ).await?;

                    let mut sum = 0;
                    for (_, txhandler) in txhandlers.iter() {
                        let sighashes = txhandler.calculate_shared_txins_sighash(EntityType::VerifierDeposit, partial)?;
                        sum += sighashes.len();
                        for sighash in sighashes {
                            yield sighash;
                        }
                    }

                    if sum != config.get_num_required_nofn_sigs_per_kickoff() {
                        Err(BridgeError::NofNSighashMismatch(config.get_num_required_nofn_sigs_per_kickoff(), sum))?;
                    }
                    last_ready_to_reimburse = txhandlers.remove(&TransactionType::ReadyToReimburse);
                }
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
    operator_idx: usize,
    collateral_funding_outpoint: OutPoint,
    operator_reimburse_addr: Address,
    operator_xonly_pk: XOnlyPublicKey,
    config: BridgeConfig,
    deposit_data: DepositData,
    nofn_xonly_pk: XOnlyPublicKey,
) -> impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>> {
    try_stream! {
        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            reimburse_addr: operator_reimburse_addr,
            collateral_funding_outpoint,
        };

        let mut tx_db_data = ReimburseDbCache::new(db.clone(), operator_idx as u32, deposit_data.clone(), config.clone());

        let mut last_reimburse_generator: Option<TxHandler> = None;

        // For each round_tx, we have multiple kickoff_utxos as the connectors.
        for round_idx in 0..config.num_round_txs {
            for kickoff_idx in 0..config.num_kickoffs_per_round {
                let partial = PartialSignatureInfo::new(operator_idx, round_idx, kickoff_idx);

                let mut txhandlers = create_txhandlers(
                    nofn_xonly_pk,
                    TransactionType::AllNeededForDeposit,
                    KickoffId {
                        operator_idx: operator_idx as u32,
                        round_idx: round_idx as u32,
                        kickoff_idx: kickoff_idx as u32,
                    },
                    operator_data.clone(),
                    last_reimburse_generator,
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
                if sum != config.get_num_required_operator_sigs_per_kickoff() {
                    Err(BridgeError::OperatorSighashMismatch(config.get_num_required_operator_sigs_per_kickoff(), sum))?;
                }
                last_reimburse_generator = txhandlers.remove(&TransactionType::Reimburse);
            }
        }
    }
}
