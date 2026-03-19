use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::Txid;
use bitcoincore_rpc::RpcApi;
use clementine_errors::BridgeError;
use clementine_extended_rpc::ExtendedBitcoinRpc;
use eyre::eyre;
use tx_sender_types::{
    ActivationBlocker, ActivationBlockerReason, ActivationState, BitcoinTxStatus, TxStatus,
    TrackRequest, TrackResponse, TrackStatus,
};

#[cfg(feature = "citrea")]
use crate::citrea::TransactionKind;
use crate::db::tx_sender::TryToSendTrackingRow;
use crate::rpc_errors::{is_mempool_not_found_error, is_not_found_error};
use crate::{FeePayingType, TxSender, TxSenderDb};
#[cfg(feature = "citrea")]
use tx_sender_types::{CommitRevealKind, CommitRevealStatus, RevealStatus};

#[derive(Clone, Debug)]
pub struct TxSenderTracker {
    db: TxSenderDb,
    rpc: ExtendedBitcoinRpc,
    finality_depth: u32,
}

impl TxSenderTracker {
    pub fn new(db: TxSenderDb, rpc: ExtendedBitcoinRpc, finality_depth: u32) -> Self {
        Self {
            db,
            rpc,
            finality_depth,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TxChainSnapshot {
    mined_at_height: Option<u32>,
    in_mempool: bool,
}

struct TrackingContext<'a> {
    tracker: &'a TxSenderTracker,
    current_tip_height: u32,
    tx_cache: HashMap<Txid, TxChainSnapshot>,
}

impl<'a> TrackingContext<'a> {
    async fn new(tracker: &'a TxSenderTracker) -> Result<Self, BridgeError> {
        Ok(Self {
            tracker,
            current_tip_height: tracker
                .rpc
                .get_current_chain_height()
                .await
                .map_err(|e| BridgeError::Eyre(e.into()))?,
            tx_cache: HashMap::new(),
        })
    }

    async fn tx_chain_snapshot(&mut self, txid: Txid) -> Result<TxChainSnapshot, BridgeError> {
        if let Some(snapshot) = self.tx_cache.get(&txid).copied() {
            return Ok(snapshot);
        }

        let snapshot = match self.tracker.rpc.get_raw_transaction_info(&txid, None).await {
            Ok(info) => match info.confirmations {
                Some(confirmations) if confirmations > 0 => {
                    let blockhash = info.blockhash.ok_or_else(|| {
                        BridgeError::Eyre(eyre!(
                            "Confirmed transaction {txid} missing blockhash in RPC response"
                        ))
                    })?;
                    let block_info = self
                        .tracker
                        .rpc
                        .get_block_info(&blockhash)
                        .await
                        .map_err(|e| BridgeError::Eyre(eyre!(e)))?;

                    TxChainSnapshot {
                        mined_at_height: Some(block_info.height as u32),
                        in_mempool: false,
                    }
                }
                _ => match self.tracker.rpc.get_mempool_entry(&txid).await {
                    Ok(_) => TxChainSnapshot {
                        mined_at_height: None,
                        in_mempool: true,
                    },
                    Err(e) if is_mempool_not_found_error(&e) => TxChainSnapshot::default(),
                    Err(e) => return Err(BridgeError::Eyre(eyre!(e))),
                },
            },
            Err(e) if is_not_found_error(&e) => TxChainSnapshot::default(),
            Err(e) => return Err(BridgeError::Eyre(eyre!(e))),
        };

        self.tx_cache.insert(txid, snapshot);
        Ok(snapshot)
    }

    async fn bitcoin_tx_status(&mut self, txid: Txid) -> Result<BitcoinTxStatus, BridgeError> {
        let snapshot = self.tx_chain_snapshot(txid).await?;
        Ok(BitcoinTxStatus {
            txid: txid.to_string(),
            mined_at_height: snapshot.mined_at_height,
            in_mempool: snapshot.in_mempool,
        })
    }

    fn is_mined_height_finalized(&self, mined_at_height: Option<u32>) -> bool {
        mined_at_height.is_some_and(|height| {
            self.current_tip_height
                .saturating_add(1)
                .saturating_sub(height)
                >= self.tracker.finality_depth
        })
    }
}

impl TxSenderTracker {
    pub async fn track_request(&self, request: TrackRequest) -> Result<TrackResponse, BridgeError> {
        let mut ctx = TrackingContext::new(self).await?;
        match request {
            TrackRequest::TryToSend { try_to_send_id } => Ok(TrackResponse::Transaction(
                self.build_submission_status_by_id(&mut ctx, try_to_send_id)
                    .await?,
            )),
            TrackRequest::ByTxid { txid } => Ok(TrackResponse::Transaction(
                self.build_submission_status_by_txid(&mut ctx, &txid)
                    .await?,
            )),
            TrackRequest::CommitReveal { insertion_id } => {
                #[cfg(feature = "citrea")]
                {
                    Ok(TrackResponse::CommitReveal(
                        self.build_commit_reveal_status(&mut ctx, insertion_id).await?,
                    ))
                }
                #[cfg(not(feature = "citrea"))]
                {
                    let _ = insertion_id;
                    Err(BridgeError::Eyre(eyre!(
                        "citrea tracking is not available without the `citrea` feature"
                    )))
                }
            }
        }
    }

    async fn build_submission_status(
        &self,
        ctx: &mut TrackingContext<'_>,
        row: TryToSendTrackingRow,
    ) -> Result<TxStatus, BridgeError> {
        let try_to_send_id = row.id;

        let last_error = self
            .db
            .get_latest_tx_debug_submission_error(None, try_to_send_id)
            .await?;

        let tx_info = self
            .select_submission_tx_info(ctx, try_to_send_id, &row)
            .await?;
        let tx_chain_snapshot = ctx
            .tx_chain_snapshot(Txid::from_str(&tx_info.txid).map_err(|e| {
                BridgeError::Eyre(eyre!("Invalid tracked txid {}: {e}", tx_info.txid))
            })?)
            .await?;
        let fee_payer_rows = self
            .db
            .list_fee_payer_tracking_rows(None, try_to_send_id)
            .await?;
        let mut fee_payer_tx_infos = Vec::new();
        for fee_payer in fee_payer_rows {
            let mut fee_payer_tx_info = ctx.bitcoin_tx_status(fee_payer.txid).await?;
            fee_payer_tx_info.mined_at_height = fee_payer_tx_info
                .mined_at_height
                .or(fee_payer.mined_at_height);
            fee_payer_tx_infos.push(fee_payer_tx_info);
        }

        let activation = self.build_activation_state(ctx, try_to_send_id).await?;

        let status = if row.input_unspent_timed_out {
            TrackStatus::Cancelled
        } else if ctx.is_mined_height_finalized(tx_chain_snapshot.mined_at_height)
            || row.is_finalized
        {
            TrackStatus::Finalized
        } else if tx_info.mined_at_height.is_some() || row.mined_at_height.is_some() {
            TrackStatus::Mined
        } else if self.is_submission_in_progress(&row, &tx_info, &fee_payer_tx_infos) {
            TrackStatus::InProgress
        } else {
            TrackStatus::Pending
        };

        // Do not show last error for mined or finalized transactions.
        let last_error = if matches!(status, TrackStatus::Mined | TrackStatus::Finalized) {
            None
        } else {
            last_error
        };

        Ok(TxStatus {
            status,
            activation,
            tx_info,
            fee_sat_kvb: row.fee_sat_kvb,
            fee_payer_txs: fee_payer_tx_infos,
            last_error,
        })
    }

    async fn build_submission_status_by_id(
        &self,
        ctx: &mut TrackingContext<'_>,
        try_to_send_id: u32,
    ) -> Result<TxStatus, BridgeError> {
        let row = self
            .db
            .get_try_to_send_tracking_row(None, try_to_send_id)
            .await?
            .ok_or_else(|| BridgeError::Eyre(eyre!("Unknown try_to_send_id {try_to_send_id}")))?;
        self.build_submission_status(ctx, row).await
    }

    async fn build_submission_status_by_txid(
        &self,
        ctx: &mut TrackingContext<'_>,
        txid: &str,
    ) -> Result<TxStatus, BridgeError> {
        let txid = Txid::from_str(txid)
            .map_err(|e| BridgeError::Eyre(eyre!("Invalid try_to_send txid {txid}: {e}")))?;
        let row = if let Some(row) = self
            .db
            .get_try_to_send_tracking_row_by_txid(None, txid)
            .await?
        {
            row
        } else {
            let try_to_send_id = self
                .db
                .find_try_to_send_id_by_rbf_txid(None, txid)
                .await?
                .ok_or_else(|| BridgeError::Eyre(eyre!("Unknown try_to_send txid {txid}")))?;
            self.db
                .get_try_to_send_tracking_row(None, try_to_send_id)
                .await?
                .ok_or_else(|| {
                    BridgeError::Eyre(eyre!(
                        "Missing try_to_send row {try_to_send_id} for tracked txid {txid}"
                    ))
                })?
        };
        self.build_submission_status(ctx, row).await
    }

    async fn build_activation_state(
        &self,
        ctx: &TrackingContext<'_>,
        try_to_send_id: u32,
    ) -> Result<ActivationState, BridgeError> {
        let activations = self
            .db
            .list_activation_tracking_rows(None, try_to_send_id)
            .await?;
        if activations.is_empty() {
            return Ok(ActivationState::Active);
        }

        let mut blockers = Vec::new();

        for activation in activations {
            if activation.timelock == 0 {
                if activation.mined_at_height.is_none() && !activation.in_mempool {
                    blockers.push(ActivationBlocker {
                        txid: activation.txid.to_string(),
                        reason: ActivationBlockerReason::Missing,
                    });
                }
                continue;
            }

            match activation.mined_at_height {
                None => blockers.push(ActivationBlocker {
                    txid: activation.txid.to_string(),
                    reason: ActivationBlockerReason::Missing,
                }),
                Some(mined_at_height) => {
                    let unlock_height = mined_at_height.saturating_add(activation.timelock);
                    if unlock_height > ctx.current_tip_height {
                        blockers.push(ActivationBlocker {
                            txid: activation.txid.to_string(),
                            reason: ActivationBlockerReason::Timelocked {
                                mined_at_height,
                                required_blocks: activation.timelock,
                                remaining_blocks: unlock_height - ctx.current_tip_height,
                            },
                        });
                    }
                }
            }
        }

        if blockers.is_empty() {
            Ok(ActivationState::Active)
        } else {
            Ok(ActivationState::Waiting { blockers })
        }
    }

    fn is_submission_in_progress(
        &self,
        row: &TryToSendTrackingRow,
        tx_info: &BitcoinTxStatus,
        fee_payer_txs: &[BitcoinTxStatus],
    ) -> bool {
        if row.mined_at_height.is_some() || row.is_finalized {
            return true;
        }

        if tx_info.in_mempool {
            return true;
        }

        if !fee_payer_txs.is_empty() {
            return true;
        }

        matches!(
            row.fee_paying_type,
            FeePayingType::RBF | FeePayingType::RbfWtxidGrind
        ) && tx_info.txid != row.txid.to_string()
    }

    async fn select_submission_tx_info(
        &self,
        ctx: &mut TrackingContext<'_>,
        try_to_send_id: u32,
        row: &TryToSendTrackingRow,
    ) -> Result<BitcoinTxStatus, BridgeError> {
        if matches!(
            row.fee_paying_type,
            FeePayingType::RBF | FeePayingType::RbfWtxidGrind
        ) {
            let rbf_txids = self.db.list_rbf_txids_for_id(None, try_to_send_id).await?;
            if !rbf_txids.is_empty() {
                let mut latest_saved = None;
                let mut newest_in_mempool = None;

                for txid in rbf_txids {
                    if latest_saved.is_none() {
                        latest_saved = Some(txid);
                    }

                    let tx_info = ctx.bitcoin_tx_status(txid).await?;
                    if tx_info.mined_at_height.is_some() {
                        return Ok(tx_info);
                    }
                    if newest_in_mempool.is_none() && tx_info.in_mempool {
                        newest_in_mempool = Some(tx_info);
                    }
                }

                if let Some(tx_info) = newest_in_mempool {
                    return Ok(tx_info);
                }
                if let Some(txid) = latest_saved {
                    return ctx.bitcoin_tx_status(txid).await;
                }
            }
        }

        let mut tx_info = ctx.bitcoin_tx_status(row.txid).await?;
        tx_info.mined_at_height = tx_info.mined_at_height.or(row.mined_at_height);
        Ok(tx_info)
    }

    #[cfg(feature = "citrea")]
    async fn build_commit_reveal_status(
        &self,
        ctx: &mut TrackingContext<'_>,
        insertion_id: i64,
    ) -> Result<CommitRevealStatus, BridgeError> {
        let rows = self
            .db
            .get_citrea_rows_by_insertion_id(None, insertion_id)
            .await?;
        if rows.is_empty() {
            return Err(BridgeError::Eyre(eyre!(
                "Unknown citrea insertion_id {insertion_id}"
            )));
        }

        let commit_tx = match rows
            .iter()
            .filter(|row| !matches!(row.transaction_kind, TransactionKind::Aggregate))
            .find_map(|row| row.commit_outpoint)
        {
            Some(outpoint) => Some(ctx.bitcoin_tx_status(outpoint.txid).await?),
            None => None,
        };

        let mut reveal_statuses = Vec::new();
        let mut aggregate_commit_tx = None;
        let mut aggregate_reveal_submission = None;
        let mut aggregate_finalized = false;

        for row in rows {
            if matches!(row.transaction_kind, TransactionKind::Aggregate) {
                aggregate_finalized = row.aggregate_finalized;
                if let Some(outpoint) = row.commit_outpoint {
                    aggregate_commit_tx = Some(ctx.bitcoin_tx_status(outpoint.txid).await?);
                }
                if let Some(try_to_send_id) = row.try_to_send_id {
                    let mut aggregate_submission = self
                        .build_submission_status_by_id(ctx, try_to_send_id as u32)
                        .await?;
                    if aggregate_finalized {
                        aggregate_submission.status = TrackStatus::Finalized;
                    }
                    aggregate_reveal_submission = Some(aggregate_submission);
                }
                continue;
            }

            let submission = if let Some(try_to_send_id) = row.try_to_send_id {
                let submission = self
                    .build_submission_status_by_id(ctx, try_to_send_id as u32)
                    .await?;
                Some(submission)
            } else {
                None
            };

            reveal_statuses.push(RevealStatus {
                kind: map_commit_reveal_kind(row.transaction_kind),
                submission,
            });
        }

        let status = if aggregate_finalized {
            TrackStatus::Finalized
        } else if let Some(aggregate_reveal) = aggregate_reveal_submission.as_ref() {
            aggregate_reveal.status
        } else if reveal_statuses.len() == 1 {
            reveal_statuses
                .first()
                .and_then(|reveal| reveal.submission.as_ref().map(|track| track.status))
                .unwrap_or_else(|| {
                    if commit_tx.is_some() {
                        TrackStatus::InProgress
                    } else {
                        TrackStatus::Pending
                    }
                })
        } else if commit_tx.is_some()
            || reveal_statuses
                .iter()
                .any(|reveal| reveal.submission.is_some())
        {
            TrackStatus::InProgress
        } else {
            TrackStatus::Pending
        };

        Ok(CommitRevealStatus {
            status,
            commit_tx,
            reveals: reveal_statuses,
            aggregate_commit_tx,
            aggregate_reveal_submission,
        })
    }
}

impl TxSender {
    pub fn tracker(&self) -> TxSenderTracker {
        TxSenderTracker::new(self.db.clone(), self.rpc.clone(), self.finality_depth)
    }
}

#[cfg(feature = "citrea")]
fn map_commit_reveal_kind(kind: TransactionKind) -> CommitRevealKind {
    match kind {
        TransactionKind::Complete => CommitRevealKind::Complete,
        TransactionKind::Aggregate => CommitRevealKind::Aggregate,
        TransactionKind::Chunks => CommitRevealKind::Chunk,
        TransactionKind::BatchProofMethodId => CommitRevealKind::BatchProofMethodId,
        TransactionKind::SequencerCommitment => CommitRevealKind::SequencerCommitment,
        TransactionKind::Unknown(value) => CommitRevealKind::Unknown(value),
    }
}
