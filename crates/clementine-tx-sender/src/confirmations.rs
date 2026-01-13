use crate::{
    FeePayingType, TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder,
    FINALITY_CONFIRMATIONS,
};
use bitcoin::{OutPoint, Txid};
use bitcoincore_rpc::RpcApi;
use clementine_errors::BridgeError;
use clementine_extended_rpc::BitcoinRPCError;
use std::collections::HashMap;

#[derive(Copy, Clone, Debug)]
enum TxChainStatus {
    /// Confirmed in active chain with N confirmations.
    Confirmed(u32),
    /// Not confirmed (mempool / unknown / missing).
    NotConfirmed,
}

fn is_not_found_error(err: &bitcoincore_rpc::Error) -> bool {
    // Bitcoin Core returns this when the tx is neither in mempool nor in the active chain.
    // We treat it as "not confirmed" for our purposes.
    let s = err.to_string();
    s.contains("No such mempool or blockchain transaction")
        || s.contains("No such mempool transaction")
        || s.contains("No such transaction")
}

fn chain_status_from_confirmations(confirmations: Option<u32>) -> TxChainStatus {
    match confirmations {
        Some(c) if c > 0 => TxChainStatus::Confirmed(c),
        _ => TxChainStatus::NotConfirmed,
    }
}

fn target_seen_at_height_for_confirmations(
    observed_tip_height: u32,
    confirmations: u32,
    finality_confirmations: u32,
) -> u32 {
    if confirmations >= finality_confirmations {
        // Make it final immediately:
        // observed_tip - seen_at + 1 >= finality_confirmations
        observed_tip_height.saturating_sub(finality_confirmations.saturating_sub(1))
    } else {
        // Conservative: treat it as first observed "now".
        observed_tip_height
    }
}

impl<S, D, B> TxSender<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase,
    B: TxSenderTxBuilder + 'static,
{
    /// Synchronize tx-sender confirmation/spent tracking using Bitcoin RPC.
    ///
    /// This method updates tx-sender *tracking tables* (e.g. `seen_at_height`) based on
    /// current chain state, and clears those markers on reorgs for observations that
    /// are still below finality.
    ///
    /// Finality is based on **first-observed** height (not actual inclusion height).
    pub async fn sync_transaction_confirmations_via_rpc(
        &self,
        mut dbtx: Option<&mut D::Transaction>,
        tip_height: u32,
    ) -> Result<(), BridgeError> {
        let finality = FINALITY_CONFIRMATIONS;
        let start_tip_height = tip_height;

        // If a new block arrives while we're syncing, we must not write a "too old"
        // observation height, otherwise we could treat a <finality tx as final.
        //
        // We also cache getrawtransactioninfo results per txid per sync to avoid
        // duplicate RPC calls across tables.
        let mut tx_status_cache: HashMap<Txid, TxChainStatus> = HashMap::new();

        let mut pending_try_to_send: Vec<(u32, u32)> = vec![]; // (id, confirmations)
        let mut pending_fee_payers: Vec<(u32, u32)> = vec![]; // (fee_payer_utxo_id, confirmations)
        let mut pending_cancel_txids: Vec<(u32, Txid, u32)> = vec![]; // (cancelled_id, txid, confirmations)
        let mut pending_activate_txids: Vec<(u32, Txid, u32)> = vec![]; // (activated_id, txid, confirmations)
        let mut pending_cancel_outpoints: Vec<(u32, OutPoint)> = vec![];
        let mut pending_activate_outpoints: Vec<(u32, OutPoint)> = vec![];

        async fn get_tx_status_cached(
            rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
            cache: &mut HashMap<Txid, TxChainStatus>,
            txid: Txid,
        ) -> Result<TxChainStatus, BridgeError> {
            if let Some(status) = cache.get(&txid) {
                return Ok(*status);
            }

            let info = match rpc.get_raw_transaction_info(&txid, None).await {
                Ok(info) => info,
                Err(e) if is_not_found_error(&e) => {
                    cache.insert(txid, TxChainStatus::NotConfirmed);
                    return Ok(TxChainStatus::NotConfirmed);
                }
                Err(e) => return Err(BridgeError::Eyre(eyre::eyre!(e))),
            };

            let status = chain_status_from_confirmations(info.confirmations);
            cache.insert(txid, status);
            Ok(status)
        }

        // ---- main try_to_send_txs ----
        let unfinalized = self
            .db
            .list_unfinalized_try_to_send_txs(dbtx.as_deref_mut(), start_tip_height, finality)
            .await?;

        let rbf_ids: Vec<u32> = unfinalized
            .iter()
            .filter_map(|(id, fee_paying_type, _txid, _seen_at_height)| {
                matches!(fee_paying_type, FeePayingType::RBF).then_some(*id)
            })
            .collect();

        let mut rbf_txids_by_id: HashMap<u32, Vec<Txid>> = HashMap::new();
        if !rbf_ids.is_empty() {
            for (id, txid) in self
                .db
                .list_rbf_txids_for_ids(dbtx.as_deref_mut(), &rbf_ids)
                .await?
            {
                rbf_txids_by_id.entry(id).or_default().push(txid);
            }
        }

        for (id, fee_paying_type, txid, seen_at_height) in unfinalized {
            let status = match fee_paying_type {
                FeePayingType::CPFP | FeePayingType::NoFunding => {
                    get_tx_status_cached(&self.rpc, &mut tx_status_cache, txid).await?
                }
                FeePayingType::RBF => {
                    let Some(rbf_txids) = rbf_txids_by_id.get(&id) else {
                        // No sent RBF txids yet => nothing to confirm/unconfirm.
                        continue;
                    };
                    let mut best_confirmations: Option<u32> = None;
                    for rbf_txid in rbf_txids {
                        match get_tx_status_cached(&self.rpc, &mut tx_status_cache, *rbf_txid)
                            .await?
                        {
                            TxChainStatus::Confirmed(c) => {
                                best_confirmations =
                                    Some(best_confirmations.map_or(c, |prev| prev.max(c)));
                            }
                            TxChainStatus::NotConfirmed => {}
                        }
                    }
                    match best_confirmations {
                        Some(c) => TxChainStatus::Confirmed(c),
                        None => TxChainStatus::NotConfirmed,
                    }
                }
            };

            match (seen_at_height, status) {
                (None, TxChainStatus::Confirmed(c)) => pending_try_to_send.push((id, c)),
                // If it's unfinalized but we now observe confirmations>=finality, we can
                // mark it final immediately (handled in the final write).
                (Some(_), TxChainStatus::Confirmed(c)) => pending_try_to_send.push((id, c)),
                (Some(_), TxChainStatus::NotConfirmed) => {
                    // Reorg before finality
                    self.db
                        .set_try_to_send_seen_at_height(dbtx.as_deref_mut(), id, None)
                        .await?;
                }
                _ => {}
            }
        }

        // ---- fee payer tx confirmations ----
        for (fee_payer_utxo_id, fee_payer_txid, seen_at_height) in self
            .db
            .list_unfinalized_fee_payer_utxos(dbtx.as_deref_mut(), start_tip_height, finality)
            .await?
        {
            let status =
                get_tx_status_cached(&self.rpc, &mut tx_status_cache, fee_payer_txid).await?;

            match (seen_at_height, status) {
                (_, TxChainStatus::Confirmed(c)) => pending_fee_payers.push((fee_payer_utxo_id, c)),
                (Some(_), TxChainStatus::NotConfirmed) => {
                    self.db
                        .set_fee_payer_seen_at_height(dbtx.as_deref_mut(), fee_payer_utxo_id, None)
                        .await?;
                }
                _ => {}
            }
        }

        // ---- cancel/activate by txid ----
        for (cancelled_id, txid, seen_at_height) in self
            .db
            .list_unfinalized_cancel_txids(dbtx.as_deref_mut(), start_tip_height, finality)
            .await?
        {
            let status = get_tx_status_cached(&self.rpc, &mut tx_status_cache, txid).await?;

            match (seen_at_height, status) {
                (_, TxChainStatus::Confirmed(c)) => {
                    pending_cancel_txids.push((cancelled_id, txid, c))
                }
                (Some(_), TxChainStatus::NotConfirmed) => {
                    self.db
                        .set_cancel_txid_seen_at_height(
                            dbtx.as_deref_mut(),
                            cancelled_id,
                            txid,
                            None,
                        )
                        .await?;
                }
                _ => {}
            }
        }

        for (activated_id, txid, seen_at_height) in self
            .db
            .list_unfinalized_activate_txids(dbtx.as_deref_mut(), start_tip_height, finality)
            .await?
        {
            let status = get_tx_status_cached(&self.rpc, &mut tx_status_cache, txid).await?;

            match (seen_at_height, status) {
                (None, TxChainStatus::Confirmed(c)) => {
                    pending_activate_txids.push((activated_id, txid, c))
                }
                (Some(_), TxChainStatus::Confirmed(c)) => {
                    pending_activate_txids.push((activated_id, txid, c))
                }
                (Some(_), TxChainStatus::NotConfirmed) => {
                    self.db
                        .set_activate_txid_seen_at_height(
                            dbtx.as_deref_mut(),
                            activated_id,
                            txid,
                            None,
                        )
                        .await?;
                }
                _ => {}
            }
        }

        // ---- cancel/activate by outpoint spent ----
        async fn check_spent(
            rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
            outpoint: &OutPoint,
        ) -> Result<Option<bool>, BitcoinRPCError> {
            match rpc.is_utxo_spent(outpoint).await {
                Ok(spent) => Ok(Some(spent)),
                Err(BitcoinRPCError::TransactionNotConfirmed) => Ok(None),
                Err(e) => Err(e),
            }
        }

        for (cancelled_id, outpoint, seen_at_height) in self
            .db
            .list_unfinalized_cancel_outpoints(dbtx.as_deref_mut(), start_tip_height, finality)
            .await?
        {
            match check_spent(&self.rpc, &outpoint).await {
                Ok(Some(true)) => {
                    if seen_at_height.is_none() {
                        pending_cancel_outpoints.push((cancelled_id, outpoint));
                    }
                }
                Ok(Some(false)) | Ok(None) => {
                    // Not spent (or funding tx not confirmed anymore) => clear pre-final observations
                    if seen_at_height.is_some() {
                        self.db
                            .set_cancel_outpoint_seen_at_height(
                                dbtx.as_deref_mut(),
                                cancelled_id,
                                outpoint,
                                None,
                            )
                            .await?;
                    }
                }
                Err(e) => {
                    tracing::warn!(?outpoint, "Failed to check outpoint spent status: {}", e);
                }
            }
        }

        for (activated_id, outpoint, seen_at_height) in self
            .db
            .list_unfinalized_activate_outpoints(dbtx.as_deref_mut(), start_tip_height, finality)
            .await?
        {
            match check_spent(&self.rpc, &outpoint).await {
                Ok(Some(true)) => {
                    if seen_at_height.is_none() {
                        pending_activate_outpoints.push((activated_id, outpoint));
                    }
                }
                Ok(Some(false)) | Ok(None) => {
                    if seen_at_height.is_some() {
                        self.db
                            .set_activate_outpoint_seen_at_height(
                                dbtx.as_deref_mut(),
                                activated_id,
                                outpoint,
                                None,
                            )
                            .await?;
                    }
                }
                Err(e) => {
                    tracing::warn!(?outpoint, "Failed to check outpoint spent status: {}", e);
                }
            }
        }

        // Apply any "newly observed" confirmations/spends using a conservative observation height.
        let end_tip_height = self
            .rpc
            .get_current_chain_height()
            .await
            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;
        let observed_tip_height = std::cmp::max(start_tip_height, end_tip_height);

        for (id, confirmations) in pending_try_to_send {
            self.db
                .set_try_to_send_seen_at_height(
                    dbtx.as_deref_mut(),
                    id,
                    Some(target_seen_at_height_for_confirmations(
                        observed_tip_height,
                        confirmations,
                        finality,
                    )),
                )
                .await?;
        }

        for (fee_payer_utxo_id, confirmations) in pending_fee_payers {
            self.db
                .set_fee_payer_seen_at_height(
                    dbtx.as_deref_mut(),
                    fee_payer_utxo_id,
                    Some(target_seen_at_height_for_confirmations(
                        observed_tip_height,
                        confirmations,
                        finality,
                    )),
                )
                .await?;
        }

        for (cancelled_id, txid, confirmations) in pending_cancel_txids {
            self.db
                .set_cancel_txid_seen_at_height(
                    dbtx.as_deref_mut(),
                    cancelled_id,
                    txid,
                    Some(target_seen_at_height_for_confirmations(
                        observed_tip_height,
                        confirmations,
                        finality,
                    )),
                )
                .await?;
        }

        for (activated_id, txid, confirmations) in pending_activate_txids {
            self.db
                .set_activate_txid_seen_at_height(
                    dbtx.as_deref_mut(),
                    activated_id,
                    txid,
                    Some(target_seen_at_height_for_confirmations(
                        observed_tip_height,
                        confirmations,
                        finality,
                    )),
                )
                .await?;
        }

        for (cancelled_id, outpoint) in pending_cancel_outpoints {
            self.db
                .set_cancel_outpoint_seen_at_height(
                    dbtx.as_deref_mut(),
                    cancelled_id,
                    outpoint,
                    Some(observed_tip_height),
                )
                .await?;
        }

        for (activated_id, outpoint) in pending_activate_outpoints {
            self.db
                .set_activate_outpoint_seen_at_height(
                    dbtx.as_deref_mut(),
                    activated_id,
                    outpoint,
                    Some(observed_tip_height),
                )
                .await?;
        }

        Ok(())
    }
}
