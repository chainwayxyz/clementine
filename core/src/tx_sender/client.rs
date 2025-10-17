//! # Transaction Sender Client
//!
//! This module is provides a client which is responsible for inserting
//! transactions into the sending queue.

use super::Result;
use super::{ActivatedWithOutpoint, ActivatedWithTxid};
use crate::builder::transaction::input::UtxoVout;
use crate::errors::ResultExt;
use crate::operator::RoundIndex;
use crate::rpc;
use crate::utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use crate::{
    builder::transaction::TransactionType,
    config::BridgeConfig,
    database::{Database, DatabaseTransaction},
};
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, Txid};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct TxSenderClient {
    pub(super) db: Database,
    pub(super) tx_sender_consumer_id: String,
}

impl TxSenderClient {
    pub fn new(db: Database, tx_sender_consumer_id: String) -> Self {
        Self {
            db,
            tx_sender_consumer_id,
        }
    }

    /// Saves a transaction to the database queue for sending/fee bumping.
    ///
    /// This function determines the initial parameters for a transaction send attempt,
    /// including its [`FeePayingType`], associated metadata, and dependencies (cancellations/activations).
    /// It then persists this information in the database via [`Database::save_tx`] and related functions.
    /// The actual sending logic (CPFP/RBF) is handled later by the transaction sender's task loop.
    ///
    /// # Default Activation and Cancellation Conditions
    ///
    /// By default, this function automatically adds cancellation conditions for all outpoints
    /// spent by the `signed_tx` itself. If `signed_tx` confirms, these input outpoints
    /// are marked as spent/cancelled in the database.
    ///
    /// There are no default activation conditions added implicitly; all activation prerequisites
    /// must be explicitly provided via the `activate_txids` and `activate_outpoints` arguments.
    ///
    /// # Arguments
    /// * `dbtx` - An active database transaction.
    /// * `tx_metadata` - Optional metadata about the transaction's purpose.
    /// * `signed_tx` - The transaction to be potentially sent.
    /// * `fee_paying_type` - Whether to use CPFP or RBF for fee management.
    /// * `cancel_outpoints` - Outpoints that should be marked invalid if this tx confirms (in addition to the tx's own inputs).
    /// * `cancel_txids` - Txids that should be marked invalid if this tx confirms.
    /// * `activate_txids` - Txids that are prerequisites for this tx, potentially with a relative timelock.
    /// * `activate_outpoints` - Outpoints that are prerequisites for this tx, potentially with a relative timelock.
    ///
    /// # Returns
    ///
    /// - [`u32`]: The database ID (`try_to_send_id`) assigned to this send attempt.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE), skip_all, fields(?tx_metadata, consumer = self.tx_sender_consumer_id))]
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_try_to_send(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        rbf_signing_info: Option<RbfSigningInfo>,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
    ) -> Result<u32> {
        let txid = signed_tx.compute_txid();

        tracing::debug!(
            "{} added tx {} with txid {} to the queue",
            self.tx_sender_consumer_id,
            tx_metadata
                .map(|data| format!("{:?}", data.tx_type))
                .unwrap_or("N/A".to_string()),
            txid
        );

        // do not add duplicate transactions to the txsender
        let tx_exists = self
            .db
            .check_if_tx_exists_on_txsender(Some(dbtx), txid)
            .await
            .map_to_eyre()?;
        if let Some(try_to_send_id) = tx_exists {
            return Ok(try_to_send_id);
        }

        let try_to_send_id = self
            .db
            .save_tx(
                Some(dbtx),
                tx_metadata,
                signed_tx,
                fee_paying_type,
                txid,
                rbf_signing_info,
            )
            .await
            .map_to_eyre()?;

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, input_outpoint)
                .await
                .map_to_eyre()?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, *outpoint)
                .await
                .map_to_eyre()?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(Some(dbtx), try_to_send_id, *txid)
                .await
                .map_to_eyre()?;
        }

        let mut max_timelock_of_activated_txids = BTreeMap::new();

        for activated_txid in activate_txids {
            let timelock = max_timelock_of_activated_txids
                .entry(activated_txid.txid)
                .or_insert(activated_txid.relative_block_height);
            if *timelock < activated_txid.relative_block_height {
                *timelock = activated_txid.relative_block_height;
            }
        }

        for input in signed_tx.input.iter() {
            let relative_block_height = if input.sequence.is_relative_lock_time() {
                let relative_locktime = input
                    .sequence
                    .to_relative_lock_time()
                    .expect("Invalid relative locktime");
                match relative_locktime {
                    bitcoin::relative::LockTime::Blocks(height) => height.value() as u32,
                    _ => {
                        return Err(eyre::eyre!("Invalid relative locktime").into());
                    }
                }
            } else {
                0
            };
            let timelock = max_timelock_of_activated_txids
                .entry(input.previous_output.txid)
                .or_insert(relative_block_height);
            if *timelock < relative_block_height {
                *timelock = relative_block_height;
            }
        }

        for (txid, timelock) in max_timelock_of_activated_txids {
            self.db
                .save_activated_txid(
                    Some(dbtx),
                    try_to_send_id,
                    &ActivatedWithTxid {
                        txid,
                        relative_block_height: timelock,
                    },
                )
                .await
                .map_to_eyre()?;
        }

        for activated_outpoint in activate_outpoints {
            self.db
                .save_activated_outpoint(Some(dbtx), try_to_send_id, activated_outpoint)
                .await
                .map_to_eyre()?;
        }

        Ok(try_to_send_id)
    }

    /// Adds a transaction to the sending queue based on its type and configuration.
    ///
    /// This is a higher-level wrapper around [`Self::insert_try_to_send`]. It determines the
    /// appropriate `FeePayingType` (CPFP or RBF) and any specific cancellation or activation
    /// dependencies based on the `tx_type` and `config`.
    ///
    /// For example:
    /// - `Challenge` transactions use `RBF`.
    /// - Most other transactions default to `CPFP`.
    /// - Specific types like `OperatorChallengeAck` might activate certain outpoints
    ///   based on related transactions (`kickoff_txid`).
    ///
    /// # Arguments
    /// * `dbtx` - An active database transaction.
    /// * `tx_type` - The semantic type of the transaction.
    /// * `signed_tx` - The transaction itself.
    /// * `related_txs` - Other transactions potentially related (e.g., the kickoff for a challenge ack).
    /// * `tx_metadata` - Optional metadata, `tx_type` will be added/overridden.
    /// * `config` - Bridge configuration providing parameters like finality depth.
    ///
    /// # Returns
    ///
    /// - [`u32`]: The database ID (`try_to_send_id`) assigned to this send attempt.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_tx_to_queue<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_metadata: Option<TxMetadata>,
        config: &BridgeConfig,
        rbf_info: Option<RbfSigningInfo>,
    ) -> Result<u32> {
        let tx_metadata = tx_metadata.map(|mut data| {
            data.tx_type = tx_type;
            data
        });
        match tx_type {
            TransactionType::Kickoff
            | TransactionType::Dummy
            | TransactionType::ChallengeTimeout
            | TransactionType::DisproveTimeout
            | TransactionType::Reimburse
            | TransactionType::Round
            | TransactionType::OperatorChallengeNack(_)
            | TransactionType::UnspentKickoff(_)
            | TransactionType::MoveToVault
            | TransactionType::BurnUnusedKickoffConnectors
            | TransactionType::KickoffNotFinalized
            | TransactionType::MiniAssert(_)
            | TransactionType::LatestBlockhashTimeout
            | TransactionType::LatestBlockhash
            | TransactionType::EmergencyStop
            | TransactionType::OptimisticPayout
            | TransactionType::ReadyToReimburse
            | TransactionType::ReplacementDeposit
            | TransactionType::AssertTimeout(_) => {
                // no_dependency and cpfp
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::Challenge
            | TransactionType::WatchtowerChallenge(_)
            | TransactionType::Payout => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::RBF,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::WatchtowerChallengeTimeout(_) => {
                // do not send watchtowet timeout if kickoff is already finalized
                // which is done by adding kickoff finalizer utxo to cancel_outpoints
                // this is not needed for any timeouts that spend the kickoff finalizer utxo like AssertTimeout
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(tx_type, tx)| {
                        if let TransactionType::Kickoff = tx_type {
                            Some(tx.compute_txid())
                        } else {
                            None
                        }
                    })
                    .ok_or(eyre::eyre!("Couldn't find kickoff tx in related_txs"))?;
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[OutPoint {
                        txid: kickoff_txid,
                        vout: UtxoVout::KickoffFinalizer.get_vout(),
                    }],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::OperatorChallengeAck(watchtower_idx) => {
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(tx_type, tx)| {
                        if let TransactionType::Kickoff = tx_type {
                            Some(tx.compute_txid())
                        } else {
                            None
                        }
                    })
                    .ok_or(eyre::eyre!("Couldn't find kickoff tx in related_txs"))?;
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[ActivatedWithOutpoint {
                        // only send OperatorChallengeAck if corresponding watchtower challenge is sent
                        outpoint: OutPoint {
                            txid: kickoff_txid,
                            vout: UtxoVout::WatchtowerChallenge(watchtower_idx).get_vout(),
                        },
                        relative_block_height: config.protocol_paramset().finality_depth - 1,
                    }],
                )
                .await
            }
            TransactionType::Disprove => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::NoFunding,
                    rbf_info,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::AllNeededForDeposit | TransactionType::YieldKickoffTxid => {
                unreachable!()
            }
        }
    }

    /// Returns debugging information for a transaction
    ///
    /// This function gathers all debugging information about a transaction from the database,
    /// including its state history, fee payer UTXOs, submission errors, and current state.
    ///
    /// # Arguments
    /// * `id` - The ID of the transaction to debug
    ///
    /// # Returns
    /// A comprehensive debug info structure with all available information about the transaction
    pub async fn debug_tx(&self, id: u32) -> Result<crate::rpc::clementine::TxDebugInfo> {
        use crate::rpc::clementine::{TxDebugFeePayerUtxo, TxDebugInfo, TxDebugSubmissionError};

        let (tx_metadata, tx, fee_paying_type, seen_block_id, _) =
            self.db.get_try_to_send_tx(None, id).await.map_to_eyre()?;

        let submission_errors = self
            .db
            .get_tx_debug_submission_errors(None, id)
            .await
            .map_to_eyre()?;

        let submission_errors = submission_errors
            .into_iter()
            .map(|(error_message, timestamp)| TxDebugSubmissionError {
                error_message,
                timestamp,
            })
            .collect();

        let current_state = self.db.get_tx_debug_info(None, id).await.map_to_eyre()?;

        let fee_payer_utxos = self
            .db
            .get_tx_debug_fee_payer_utxos(None, id)
            .await
            .map_to_eyre()?;

        let fee_payer_utxos = fee_payer_utxos
            .into_iter()
            .map(|(txid, vout, amount, confirmed)| {
                Ok(TxDebugFeePayerUtxo {
                    txid: Some(txid.into()),
                    vout,
                    amount: amount.to_sat(),
                    confirmed,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let txid = match fee_paying_type {
            FeePayingType::CPFP | FeePayingType::NoFunding => tx.compute_txid(),
            FeePayingType::RBF => self
                .db
                .get_last_rbf_txid(None, id)
                .await
                .map_to_eyre()?
                .unwrap_or(Txid::all_zeros()),
        };
        let debug_info = TxDebugInfo {
            id,
            is_active: seen_block_id.is_none(),
            current_state: current_state.unwrap_or_else(|| "unknown".to_string()),
            submission_errors,
            created_at: "".to_string(),
            txid: Some(txid.into()),
            fee_paying_type: format!("{fee_paying_type:?}"),
            fee_payer_utxos_count: fee_payer_utxos.len() as u32,
            fee_payer_utxos_confirmed_count: fee_payer_utxos
                .iter()
                .filter(|TxDebugFeePayerUtxo { confirmed, .. }| *confirmed)
                .count() as u32,
            fee_payer_utxos,
            raw_tx: bitcoin::consensus::serialize(&tx),
            metadata: tx_metadata.map(|metadata| rpc::clementine::TxMetadata {
                deposit_outpoint: metadata.deposit_outpoint.map(Into::into),
                operator_xonly_pk: metadata.operator_xonly_pk.map(Into::into),

                round_idx: metadata
                    .round_idx
                    .unwrap_or(RoundIndex::Round(0))
                    .to_index() as u32,
                kickoff_idx: metadata.kickoff_idx.unwrap_or(0),
                tx_type: Some(metadata.tx_type.into()),
            }),
        };

        Ok(debug_info)
    }
}
