use crate::{
    FeePayingType, TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder,
    FINALITY_CONFIRMATIONS,
};
use bitcoin::{OutPoint, Txid};
use clementine_errors::BridgeError;
use clementine_extended_rpc::BitcoinRPCError;
use std::collections::HashMap;

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

        // ---- main try_to_send_txs (including RBF handling) ----
        let unfinalized = self
            .db
            .list_unfinalized_try_to_send_txs(dbtx.as_deref_mut(), tip_height, finality)
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
            let is_on_chain = match fee_paying_type {
                FeePayingType::CPFP | FeePayingType::NoFunding => self
                    .rpc
                    .is_tx_on_chain(&txid)
                    .await
                    .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?,
                FeePayingType::RBF => {
                    let Some(rbf_txids) = rbf_txids_by_id.get(&id) else {
                        // No sent RBF txids yet => nothing to confirm/unconfirm.
                        continue;
                    };
                    let mut any_on_chain = false;
                    for rbf_txid in rbf_txids {
                        if self
                            .rpc
                            .is_tx_on_chain(rbf_txid)
                            .await
                            .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?
                        {
                            any_on_chain = true;
                            break;
                        }
                    }
                    any_on_chain
                }
            };

            match (seen_at_height, is_on_chain) {
                (None, true) => {
                    self.db
                        .set_try_to_send_seen_at_height(dbtx.as_deref_mut(), id, Some(tip_height))
                        .await?;
                }
                (Some(_), false) => {
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
            .list_unfinalized_fee_payer_utxos(dbtx.as_deref_mut(), tip_height, finality)
            .await?
        {
            let is_on_chain = self
                .rpc
                .is_tx_on_chain(&fee_payer_txid)
                .await
                .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

            match (seen_at_height, is_on_chain) {
                (None, true) => {
                    self.db
                        .set_fee_payer_seen_at_height(
                            dbtx.as_deref_mut(),
                            fee_payer_utxo_id,
                            Some(tip_height),
                        )
                        .await?;
                }
                (Some(_), false) => {
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
            .list_unfinalized_cancel_txids(dbtx.as_deref_mut(), tip_height, finality)
            .await?
        {
            let is_on_chain = self
                .rpc
                .is_tx_on_chain(&txid)
                .await
                .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

            match (seen_at_height, is_on_chain) {
                (None, true) => {
                    self.db
                        .set_cancel_txid_seen_at_height(
                            dbtx.as_deref_mut(),
                            cancelled_id,
                            txid,
                            Some(tip_height),
                        )
                        .await?;
                }
                (Some(_), false) => {
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
            .list_unfinalized_activate_txids(dbtx.as_deref_mut(), tip_height, finality)
            .await?
        {
            let is_on_chain = self
                .rpc
                .is_tx_on_chain(&txid)
                .await
                .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

            match (seen_at_height, is_on_chain) {
                (None, true) => {
                    self.db
                        .set_activate_txid_seen_at_height(
                            dbtx.as_deref_mut(),
                            activated_id,
                            txid,
                            Some(tip_height),
                        )
                        .await?;
                }
                (Some(_), false) => {
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
            .list_unfinalized_cancel_outpoints(dbtx.as_deref_mut(), tip_height, finality)
            .await?
        {
            match check_spent(&self.rpc, &outpoint).await {
                Ok(Some(true)) => {
                    if seen_at_height.is_none() {
                        self.db
                            .set_cancel_outpoint_seen_at_height(
                                dbtx.as_deref_mut(),
                                cancelled_id,
                                outpoint,
                                Some(tip_height),
                            )
                            .await?;
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
            .list_unfinalized_activate_outpoints(dbtx.as_deref_mut(), tip_height, finality)
            .await?
        {
            match check_spent(&self.rpc, &outpoint).await {
                Ok(Some(true)) => {
                    if seen_at_height.is_none() {
                        self.db
                            .set_activate_outpoint_seen_at_height(
                                dbtx.as_deref_mut(),
                                activated_id,
                                outpoint,
                                Some(tip_height),
                            )
                            .await?;
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

        Ok(())
    }
}
