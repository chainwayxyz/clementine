use crate::{
    rpc_errors::is_mempool_not_found_error, rpc_errors::is_not_found_error, FeePayingType,
    TxSender, TxSenderTransaction,
};
use bitcoin::{BlockHash, Txid};
use bitcoincore_rpc::RpcApi;
use clementine_errors::BridgeError;
use std::collections::HashMap;

#[derive(Copy, Clone, Debug)]
enum TxChainStatus {
    /// Confirmed in active chain with N confirmations at a specific block height.
    Confirmed {
        block_height: u32,
        confirmations: u32,
    },
    /// Present in the mempool (verified via `getmempoolentry`) but not yet confirmed.
    InMempool,
    /// Neither in mempool nor in the active chain.
    NotPresent,
}

impl TxSender {
    /// Synchronize tx-sender confirmation/spent tracking using Bitcoin RPC.
    ///
    /// This method updates tx-sender *tracking tables* (e.g. `seen_at_height` and `is_finalized`) based on
    /// current chain state, and clears those markers on reorgs for observations that
    /// are still below finality.
    ///
    /// Finality is explicitly tracked via `is_finalized`:
    /// - For txid-based tables: finalized when RPC reports confirmations >= finality_depth
    /// - For outpoint-based tables: finalized when seen_at_height is set and tip_height - seen_at_height + 1 >= finality_depth
    ///   Once finalized, a row is never reprocessed, avoiding incorrect finality assumptions after downtime.
    pub async fn sync_transaction_confirmations_via_rpc(
        &self,
        mut dbtx: Option<&mut TxSenderTransaction>,
    ) -> Result<(), BridgeError> {
        let finality = self.finality_depth;

        // We cache getrawtransactioninfo and block info results per sync to avoid
        // duplicate RPC calls across tables.
        let mut tx_status_cache: HashMap<Txid, TxChainStatus> = HashMap::new();
        let mut block_info_cache: HashMap<BlockHash, (u32, u32)> = HashMap::new(); // (height, confirmations)

        // ---- main try_to_send_txs ----
        let unfinalized = self
            .db
            .list_unfinalized_try_to_send_txs(dbtx.as_deref_mut())
            .await?;

        let rbf_ids: Vec<u32> = unfinalized
            .iter()
            .filter_map(|(id, fee_paying_type, _txid, _seen_at_height)| {
                matches!(
                    fee_paying_type,
                    FeePayingType::RBF | FeePayingType::RbfWtxidGrind
                )
                .then_some(*id)
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
                    get_tx_status_cached(
                        &self.rpc,
                        &mut tx_status_cache,
                        &mut block_info_cache,
                        txid,
                    )
                    .await?
                }
                FeePayingType::RBF | FeePayingType::RbfWtxidGrind => {
                    let Some(rbf_txids) = rbf_txids_by_id.get(&id) else {
                        // No sent RBF txids yet => nothing to confirm/unconfirm.
                        continue;
                    };
                    let mut first_confirmed_rbf: Option<(u32, u32)> = None; // (confirmations, block_height)
                    for rbf_txid in rbf_txids {
                        if let TxChainStatus::Confirmed {
                            block_height,
                            confirmations,
                        } = get_tx_status_cached(
                            &self.rpc,
                            &mut tx_status_cache,
                            &mut block_info_cache,
                            *rbf_txid,
                        )
                        .await?
                        {
                            first_confirmed_rbf = Some((confirmations, block_height));
                            break;
                        }
                    }
                    match first_confirmed_rbf {
                        Some((confirmations, block_height)) => TxChainStatus::Confirmed {
                            block_height,
                            confirmations,
                        },
                        None => TxChainStatus::NotPresent,
                    }
                }
            };

            match (seen_at_height, status) {
                (Some(_), TxChainStatus::InMempool | TxChainStatus::NotPresent) => {
                    // Reorg before finality
                    self.db
                        .set_try_to_send_seen_at_height(dbtx.as_deref_mut(), id, None)
                        .await?;
                }
                (
                    _,
                    TxChainStatus::Confirmed {
                        block_height,
                        confirmations,
                    },
                ) => {
                    if seen_at_height != Some(block_height) {
                        self.db
                            .set_try_to_send_seen_at_height(
                                dbtx.as_deref_mut(),
                                id,
                                Some(block_height),
                            )
                            .await?;
                    }
                    // Mark as finalized if confirmations >= finality_depth
                    if confirmations >= finality {
                        self.db
                            .set_try_to_send_finalized(dbtx.as_deref_mut(), id, true)
                            .await?;
                    }
                }
                _ => {}
            }
        }

        // ---- fee payer tx confirmations ----
        for (fee_payer_utxo_id, fee_payer_txid, seen_at_height) in self
            .db
            .list_unfinalized_fee_payer_utxos(dbtx.as_deref_mut())
            .await?
        {
            let status = get_tx_status_cached(
                &self.rpc,
                &mut tx_status_cache,
                &mut block_info_cache,
                fee_payer_txid,
            )
            .await?;

            match (seen_at_height, status) {
                (Some(_), TxChainStatus::InMempool | TxChainStatus::NotPresent) => {
                    self.db
                        .set_fee_payer_seen_at_height(dbtx.as_deref_mut(), fee_payer_utxo_id, None)
                        .await?;
                }
                (
                    _,
                    TxChainStatus::Confirmed {
                        block_height,
                        confirmations,
                    },
                ) => {
                    if seen_at_height != Some(block_height) {
                        self.db
                            .set_fee_payer_seen_at_height(
                                dbtx.as_deref_mut(),
                                fee_payer_utxo_id,
                                Some(block_height),
                            )
                            .await?;
                    }
                    // Mark as finalized if confirmations >= finality_depth
                    if confirmations >= finality {
                        self.db
                            .set_fee_payer_finalized(dbtx.as_deref_mut(), fee_payer_utxo_id, true)
                            .await?;
                    }
                }
                _ => {}
            }
        }

        for (activated_id, txid, seen_at_height, in_mempool) in self
            .db
            .list_unfinalized_activate_txids(dbtx.as_deref_mut())
            .await?
        {
            let status =
                get_tx_status_cached(&self.rpc, &mut tx_status_cache, &mut block_info_cache, txid)
                    .await?;

            match (seen_at_height, status) {
                // Reorg before finality: clear seen_at_height when previously set but no longer confirmed.
                (Some(_), TxChainStatus::InMempool | TxChainStatus::NotPresent) => {
                    self.db
                        .set_activate_txid_seen_at_height(
                            dbtx.as_deref_mut(),
                            activated_id,
                            txid,
                            None,
                        )
                        .await?;
                }
                // Not yet seen on-chain, but present in mempool: record mempool presence.
                (None, TxChainStatus::InMempool) => {
                    if !in_mempool {
                        self.db
                            .set_activate_txid_mempool_status(
                                dbtx.as_deref_mut(),
                                activated_id,
                                txid,
                                true,
                            )
                            .await?;
                    }
                }
                // Neither confirmed nor in mempool: ensure mempool flag is cleared.
                (None, TxChainStatus::NotPresent) => {
                    if in_mempool {
                        self.db
                            .set_activate_txid_mempool_status(
                                dbtx.as_deref_mut(),
                                activated_id,
                                txid,
                                false,
                            )
                            .await?;
                    }
                }
                // Confirmed: ensure mempool flag is cleared, update seen_at_height and possibly finalize.
                (
                    _,
                    TxChainStatus::Confirmed {
                        block_height,
                        confirmations,
                    },
                ) => {
                    if in_mempool {
                        self.db
                            .set_activate_txid_mempool_status(
                                dbtx.as_deref_mut(),
                                activated_id,
                                txid,
                                false,
                            )
                            .await?;
                    }

                    if seen_at_height != Some(block_height) {
                        self.db
                            .set_activate_txid_seen_at_height(
                                dbtx.as_deref_mut(),
                                activated_id,
                                txid,
                                Some(block_height),
                            )
                            .await?;
                    }

                    if confirmations >= finality {
                        self.db
                            .set_activate_txid_finalized(
                                dbtx.as_deref_mut(),
                                activated_id,
                                txid,
                                true,
                            )
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Get the status of a transaction from the cache or from the RPC.
/// The cache is used to avoid duplicate RPC calls.
async fn get_tx_status_cached(
    rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
    tx_cache: &mut HashMap<Txid, TxChainStatus>,
    block_cache: &mut HashMap<BlockHash, (u32, u32)>,
    txid: Txid,
) -> Result<TxChainStatus, BridgeError> {
    if let Some(status) = tx_cache.get(&txid) {
        return Ok(*status);
    }

    let info = match rpc.get_raw_transaction_info(&txid, None).await {
        Ok(info) => info,
        Err(e) if is_not_found_error(&e) => {
            tx_cache.insert(txid, TxChainStatus::NotPresent);
            return Ok(TxChainStatus::NotPresent);
        }
        Err(e) => return Err(BridgeError::Eyre(eyre::eyre!(e))),
    };

    let status = match info.confirmations {
        Some(c) if c > 0 => {
            let blockhash = info.blockhash.ok_or_else(|| {
                BridgeError::Eyre(eyre::eyre!(
                    "Confirmed transaction {txid} missing blockhash in RPC response"
                ))
            })?;

            let (block_height, confirmations) =
                if let Some((height, confs)) = block_cache.get(&blockhash) {
                    (*height, *confs)
                } else {
                    let block_info = rpc
                        .get_block_info(&blockhash)
                        .await
                        .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;
                    let height_u32 = block_info.height as u32;
                    let confs_u32 = block_info.confirmations as u32;
                    block_cache.insert(blockhash, (height_u32, confs_u32));
                    (height_u32, confs_u32)
                };

            TxChainStatus::Confirmed {
                block_height,
                confirmations,
            }
        }
        // Unconfirmed: require a strict mempool check.
        _ => match rpc.get_mempool_entry(&txid).await {
            Ok(_) => TxChainStatus::InMempool,
            Err(e) if is_mempool_not_found_error(&e) => TxChainStatus::NotPresent,
            Err(e) => return Err(BridgeError::Eyre(eyre::eyre!(e))),
        },
    };
    tx_cache.insert(txid, status);
    Ok(status)
}
