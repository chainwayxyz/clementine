use crate::{
    rpc_errors::is_mempool_not_found_error, rpc_errors::is_not_found_error, FeePayingType,
    TxSender, TxSenderTransaction,
};
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use clementine_errors::BridgeError;
use std::collections::HashMap;

#[derive(Debug)]
struct InputSpender {
    outpoint: OutPoint,
    spending_txid: Txid,
    blockhash: BlockHash,
    block_height: u32,
    confirmations: u32,
}

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
    /// - For all tables: finalized when RPC reports confirmations >= finality_depth
    ///   Once finalized, a row is never reprocessed.
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
            .filter_map(
                |(id, fee_paying_type, _txid, _tx, _seen_at_height, _input_spent_at_height)| {
                    matches!(
                        fee_paying_type,
                        FeePayingType::RBF | FeePayingType::RbfWtxidGrind
                    )
                    .then_some(*id)
                },
            )
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

        for (id, fee_paying_type, txid, tx, seen_at_height, input_spent_at_height) in unfinalized {
            let mut rbf_txids = rbf_txids_by_id.remove(&id).unwrap_or_default();

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
                    // Add the original txid itself, it should be in rbf_txids already, it might not be if it was already sent externally.
                    if !rbf_txids.contains(&txid) {
                        rbf_txids.push(txid);
                    }
                    let mut first_confirmed_rbf: Option<(u32, u32)> = None; // (confirmations, block_height)
                    for rbf_txid in &rbf_txids {
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

            let input_spender = if matches!(status, TxChainStatus::Confirmed { .. }) {
                None
            } else {
                if seen_at_height.is_some() {
                    self.db
                        .set_try_to_send_seen_at_height(dbtx.as_deref_mut(), id, None)
                        .await?;
                }

                confirmed_input_spender(&self.rpc, &mut block_info_cache, &tx, txid, &rbf_txids)
                    .await?
            };

            if let Some(spender) = input_spender {
                if input_spent_at_height != Some(spender.block_height) {
                    self.db
                        .set_input_spent_at_height(
                            dbtx.as_deref_mut(),
                            id,
                            Some(spender.block_height),
                        )
                        .await?;
                }

                if spender.confirmations >= finality {
                    tracing::warn!(
                        try_to_send_id = id,
                        outpoint = %spender.outpoint,
                        spending_txid = %spender.spending_txid,
                        blockhash = %spender.blockhash,
                        confirmations = spender.confirmations,
                        "Tx input was spent by a finalized tx; disabling trying to send it"
                    );
                    self.db
                        .set_try_to_send_finalized(dbtx.as_deref_mut(), id, true)
                        .await?;
                } else {
                    tracing::debug!(
                        try_to_send_id = id,
                        outpoint = %spender.outpoint,
                        spending_txid = %spender.spending_txid,
                        blockhash = %spender.blockhash,
                        confirmations = spender.confirmations,
                        "Tx input is spent by a confirmed tx; pausing send until reorg or finality"
                    );
                }
            } else if input_spent_at_height.is_some() {
                tracing::debug!(
                    try_to_send_id = id,
                    "Clearing stale confirmed input-spend marker"
                );
                self.db
                    .set_input_spent_at_height(dbtx.as_deref_mut(), id, None)
                    .await?;
            }

            if let TxChainStatus::Confirmed {
                block_height,
                confirmations,
            } = status
            {
                if seen_at_height != Some(block_height) {
                    self.db
                        .set_try_to_send_seen_at_height(dbtx.as_deref_mut(), id, Some(block_height))
                        .await?;
                }
                // Mark as finalized if confirmations >= finality_depth
                if confirmations >= finality {
                    self.db
                        .set_try_to_send_finalized(dbtx.as_deref_mut(), id, true)
                        .await?;
                }
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

            let should_be_in_mempool = matches!(status, TxChainStatus::InMempool);
            if in_mempool != should_be_in_mempool {
                self.db
                    .set_activate_txid_mempool_status(
                        dbtx.as_deref_mut(),
                        activated_id,
                        txid,
                        should_be_in_mempool,
                    )
                    .await?;
            }

            match status {
                TxChainStatus::InMempool | TxChainStatus::NotPresent => {
                    if seen_at_height.is_some() {
                        self.db
                            .set_activate_txid_seen_at_height(
                                dbtx.as_deref_mut(),
                                activated_id,
                                txid,
                                None,
                            )
                            .await?;
                    }
                }
                TxChainStatus::Confirmed {
                    block_height,
                    confirmations,
                } => {
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

            match get_active_block_info_cached(rpc, block_cache, blockhash).await? {
                Some((block_height, confirmations)) => TxChainStatus::Confirmed {
                    block_height,
                    confirmations,
                },
                None => TxChainStatus::NotPresent,
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

/// Returns the oldest external confirmed spender of any input in `tx`, ignoring
/// the original txid and known RBF txids, so `input_spent_at_height` reflects
/// when the queued tx first became unmineable.
async fn confirmed_input_spender(
    rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
    block_cache: &mut HashMap<BlockHash, (u32, u32)>,
    tx: &Transaction,
    original_txid: Txid,
    rbf_txids: &[Txid],
) -> Result<Option<InputSpender>, BridgeError> {
    let outpoints: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
    if outpoints.is_empty() {
        return Ok(None);
    }

    let spenders = rpc
        .get_tx_spending_prevouts(&outpoints)
        .await
        .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

    let mut oldest_confirmed_spender: Option<InputSpender> = None;
    for spender in spenders {
        let Some(spending_txid) = spender.spending_txid else {
            continue;
        };
        if spending_txid == original_txid || rbf_txids.contains(&spending_txid) {
            continue;
        }

        // `gettxspendingprevout` also reports mempool spenders. Only rows with
        // a blockhash came from `txospenderindex`, so only those are canonical
        // according to the connected node's active chain.
        let Some(blockhash) = spender.blockhash else {
            continue;
        };

        let Some((block_height, confirmations)) =
            get_active_block_info_cached(rpc, block_cache, blockhash).await?
        else {
            continue;
        };

        let input_spender = InputSpender {
            outpoint: spender.outpoint,
            spending_txid,
            blockhash,
            confirmations,
            block_height,
        };

        if oldest_confirmed_spender
            .as_ref()
            .is_none_or(|oldest| input_spender.block_height < oldest.block_height)
        {
            oldest_confirmed_spender = Some(input_spender);
        }
    }

    Ok(oldest_confirmed_spender)
}

/// Returns cached active-chain `(height, confirmations)` for `blockhash`.
/// Blocks with non-positive confirmations are stale/reorged and return `None`.
async fn get_active_block_info_cached(
    rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
    block_cache: &mut HashMap<BlockHash, (u32, u32)>,
    blockhash: BlockHash,
) -> Result<Option<(u32, u32)>, BridgeError> {
    if let Some((_height, confirmations)) = block_cache.get(&blockhash) {
        return Ok(Some((*_height, *confirmations)));
    }

    let block_info = rpc
        .get_block_info(&blockhash)
        .await
        .map_err(|e| BridgeError::Eyre(eyre::eyre!(e)))?;

    if block_info.confirmations <= 0 {
        return Ok(None);
    }

    let height = u32::try_from(block_info.height).map_err(|e| BridgeError::Eyre(e.into()))?;
    let confirmations =
        u32::try_from(block_info.confirmations).map_err(|e| BridgeError::Eyre(e.into()))?;
    block_cache.insert(blockhash, (height, confirmations));
    Ok(Some((height, confirmations)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_environment;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use bitcoincore_rpc::json::CreateRawTransactionInput;
    use std::collections::HashMap;

    fn unsigned_spend(prevout: OutPoint, value: Amount, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prevout,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value,
                script_pubkey,
            }],
        }
    }

    async fn signed_wallet_spend(
        tx_sender: &TxSender,
        prevout: OutPoint,
        value: Amount,
    ) -> Transaction {
        let address = tx_sender.rpc.get_new_wallet_address().await.unwrap();
        let mut outputs = HashMap::new();
        outputs.insert(address.to_string(), value);
        let inputs = [CreateRawTransactionInput {
            txid: prevout.txid,
            vout: prevout.vout,
            sequence: None,
            weight: None,
        }];
        let raw_tx = tx_sender
            .rpc
            .create_raw_transaction(&inputs, &outputs, None, Some(false))
            .await
            .unwrap();
        let signed = tx_sender
            .rpc
            .sign_raw_transaction_with_wallet(&raw_tx, None, None)
            .await
            .unwrap();
        assert!(
            signed.complete,
            "wallet must sign conflict tx: {:?}",
            signed.errors
        );
        signed.transaction().unwrap()
    }

    #[tokio::test]
    async fn input_spend_conflict_pauses_reorg_clears_and_finality_cancels() {
        let (mut config, _db, _rpc_env) = create_test_environment(true, true).await;
        config.finality_depth = 2;
        let tx_sender = TxSender::new(config).await.unwrap();

        let wallet_address = tx_sender.rpc.get_new_wallet_address().await.unwrap();
        let funding_amount = Amount::from_sat(100_000);
        let funding_outpoint = tx_sender
            .rpc
            .send_to_address(&wallet_address, funding_amount)
            .await
            .unwrap();
        tx_sender.rpc.mine_blocks(1).await.unwrap();
        let funding_txout = tx_sender
            .rpc
            .get_txout_from_outpoint(&funding_outpoint)
            .await
            .unwrap();

        let queued_tx = unsigned_spend(
            funding_outpoint,
            funding_txout
                .value
                .checked_sub(Amount::from_sat(2_000))
                .unwrap(),
            wallet_address.script_pubkey(),
        );
        let mut dbtx = tx_sender.db.begin_transaction().await.unwrap();
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(
                &mut dbtx,
                None,
                &queued_tx,
                FeePayingType::NoFunding,
                None,
                &[],
            )
            .await
            .unwrap();
        tx_sender.db.commit_transaction(dbtx).await.unwrap();

        let conflict_tx = signed_wallet_spend(
            &tx_sender,
            funding_outpoint,
            funding_txout
                .value
                .checked_sub(Amount::from_sat(1_000))
                .unwrap(),
        )
        .await;
        let conflict_txid = tx_sender
            .rpc
            .send_raw_transaction(&conflict_tx)
            .await
            .unwrap();
        tx_sender.rpc.mine_blocks(1).await.unwrap();
        let conflict_block_hash = tx_sender.rpc.get_best_block_hash().await.unwrap();
        let conflict_height = tx_sender.rpc.get_current_chain_height().await.unwrap();

        let mut block_cache = HashMap::new();
        assert!(
            confirmed_input_spender(
                &tx_sender.rpc,
                &mut block_cache,
                &conflict_tx,
                conflict_txid,
                &[],
            )
            .await
            .unwrap()
            .is_none(),
            "the original txid must not be treated as an external conflict"
        );

        tx_sender
            .sync_transaction_confirmations_via_rpc(None)
            .await
            .unwrap();
        let row = tx_sender
            .db
            .get_try_to_send_tracking_row(None, try_to_send_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.input_spent_at_height, Some(conflict_height));
        assert_eq!(row.mined_at_height, None);
        assert!(!row.is_finalized);

        tx_sender
            .rpc
            .invalidate_block(&conflict_block_hash)
            .await
            .unwrap();
        tx_sender
            .sync_transaction_confirmations_via_rpc(None)
            .await
            .unwrap();
        let row = tx_sender
            .db
            .get_try_to_send_tracking_row(None, try_to_send_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.input_spent_at_height, None);
        assert_eq!(row.mined_at_height, None);
        assert!(!row.is_finalized);

        tx_sender
            .rpc
            .reconsider_block(&conflict_block_hash)
            .await
            .unwrap();
        tx_sender.rpc.mine_blocks(1).await.unwrap();
        tx_sender
            .sync_transaction_confirmations_via_rpc(None)
            .await
            .unwrap();
        let row = tx_sender
            .db
            .get_try_to_send_tracking_row(None, try_to_send_id)
            .await
            .unwrap()
            .unwrap();
        assert!(row.input_spent_at_height.is_some());
        assert_eq!(row.mined_at_height, None);
        assert!(row.is_finalized);
    }
}
