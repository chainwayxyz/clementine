//! # Transaction Sender Client
//!
//! This module is provides a client which is responsible for inserting
//! transactions into the sending queue.

use crate::TxSenderDatabase;
use crate::{ActivatedWithOutpoint, ActivatedWithTxid};
use bitcoin::{OutPoint, Transaction, Txid};
use clementine_config::protocol::ProtocolParamset;
use clementine_errors::BridgeError;
use clementine_primitives::{TransactionType, UtxoVout};
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::eyre;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct TxSenderClient<D>
where
    D: TxSenderDatabase,
{
    pub db: D,
    pub tx_sender_consumer_id: String,
}

impl<D> TxSenderClient<D>
where
    D: TxSenderDatabase,
{
    pub fn new(db: D, tx_sender_consumer_id: String) -> Self {
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
        mut dbtx: Option<&mut D::Transaction>,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        rbf_signing_info: Option<RbfSigningInfo>,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
    ) -> Result<u32, BridgeError> {
        let txid = signed_tx.compute_txid();

        tracing::debug!(
            "{} added tx {} with txid {} to the queue",
            self.tx_sender_consumer_id,
            tx_metadata
                .as_ref()
                .map(|data| format!("{:?}", data.tx_type))
                .unwrap_or("N/A".to_string()),
            txid
        );

        // do not add duplicate transactions to the txsender
        let tx_exists = self
            .db
            .check_if_tx_exists_on_txsender(dbtx.as_deref_mut(), txid)
            .await?;
        if let Some(try_to_send_id) = tx_exists {
            return Ok(try_to_send_id);
        }

        let try_to_send_id = self
            .db
            .save_tx(
                dbtx.as_deref_mut(),
                tx_metadata,
                signed_tx,
                fee_paying_type,
                txid,
                rbf_signing_info,
            )
            .await?;

        // only log the raw tx in tests so that logs do not contain sensitive information
        #[cfg(test)]
        tracing::debug!(target: "ci", "Saved tx to database with try_to_send_id: {try_to_send_id}, metadata: {tx_metadata:?}, raw tx: {}", hex::encode(bitcoin::consensus::serialize(signed_tx)));

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(dbtx.as_deref_mut(), try_to_send_id, input_outpoint)
                .await?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(dbtx.as_deref_mut(), try_to_send_id, *outpoint)
                .await?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(dbtx.as_deref_mut(), try_to_send_id, *txid)
                .await?;
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
                        return Err(BridgeError::Eyre(eyre!("Invalid relative locktime")));
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
                    dbtx.as_deref_mut(),
                    try_to_send_id,
                    &ActivatedWithTxid {
                        txid,
                        relative_block_height: timelock,
                    },
                )
                .await?;
        }

        for activated_outpoint in activate_outpoints {
            self.db
                .save_activated_outpoint(dbtx.as_deref_mut(), try_to_send_id, activated_outpoint)
                .await?;
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
    pub async fn add_tx_to_queue(
        &self,
        dbtx: Option<&mut D::Transaction>,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_metadata: Option<TxMetadata>,
        protocol_paramset: &ProtocolParamset,
        rbf_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError> {
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
                    .ok_or(BridgeError::Eyre(eyre!(
                        "Couldn't find kickoff tx in related_txs"
                    )))?;
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
                    .ok_or(BridgeError::Eyre(eyre!(
                        "Couldn't find kickoff tx in related_txs"
                    )))?;
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
                        relative_block_height: protocol_paramset.finality_depth - 1,
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
                unreachable!("Higher level transaction types used for yielding kickoff txid from sighash stream should not be added to the queue");
            }
        }
    }
}
