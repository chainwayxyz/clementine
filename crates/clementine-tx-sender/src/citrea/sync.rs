use crate::citrea::data_serialization::DataOnDa;
use crate::citrea::reveal_scripts::CitreaSigningData;
use crate::citrea::TransactionKind;
use crate::db::citrea::CitreaRawTxRow;
use crate::rpc_errors::{is_mempool_not_found_error, is_not_found_error};
use crate::TxSender;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, TapSighashType};
use bitcoincore_rpc::json::FundRawTransactionOptions;
use bitcoincore_rpc::RpcApi;
use clementine_primitives::FeeRateKvb;
use clementine_utils::RbfSigningInfo;
use eyre::{Context, OptionExt};
use std::collections::{BTreeMap, BTreeSet, HashMap};

type BlockTxPositionCache = HashMap<bitcoin::BlockHash, (u32, Vec<bitcoin::Txid>)>;

/// Chain position and witness id for a confirmed transaction.
///
/// Aggregate bodies need both the legacy txid and wtxid of each confirmed
/// chunk reveal. The block position is used to reject aggregate reveals that
/// appear before a chunk reveal they reference.
#[derive(Debug, Clone, Copy)]
struct ConfirmedTxInfo {
    txid: bitcoin::Txid,
    wtxid: bitcoin::Wtxid,
    block_height: u32,
    tx_index: usize,
}

impl ConfirmedTxInfo {
    /// Returns true when `self` is strictly after `other` in chain order.
    fn is_after(&self, other: &Self) -> bool {
        self.block_height > other.block_height
            || (self.block_height == other.block_height && self.tx_index > other.tx_index)
    }
}

/// Confirmed chunk reveal ids in Citrea aggregate-body order.
struct ConfirmedChunkReveals {
    reveal_txids: Vec<[u8; 32]>,
    reveal_wtxids: Vec<[u8; 32]>,
    confirmed_txs: Vec<ConfirmedTxInfo>,
}

/// Returns a Citrea row's optional try-to-send id as a checked unsigned id.
fn optional_citrea_try_to_send_id(row: &CitreaRawTxRow) -> Result<Option<u32>, eyre::Report> {
    row.try_to_send_id
        .map(u32::try_from)
        .transpose()
        .wrap_err("Failed to convert citrea try_to_send_id to u32")
}

/// Returns a Citrea row's try-to-send id as a checked unsigned id.
fn citrea_try_to_send_id(row: &CitreaRawTxRow) -> Result<u32, eyre::Report> {
    optional_citrea_try_to_send_id(row)?.ok_or_eyre("Expected citrea try_to_send_id to be present")
}

impl TxSender {
    /// Syncs citrea transactions, creating commit transactions for txs without it.
    /// After creating commit tx, the reveal txs are added to the core txsender queue using insert_try_to_send as RBF txs.
    pub async fn sync_citrea_txs(&self, fee_rate: FeeRateKvb) -> Result<(), eyre::Report> {
        // First, check existing commit txids for eviction.
        self.check_evicted_commit_txs().await?;

        // First get all citrea rows (except aggregate tx) with commit_outpoint IS NULL.
        // For all of these we will try to fund and create a tx that creates commit utxos.
        let citrea_rows = self
            .db
            .get_citrea_txs_with_null_commit_outpoint(None)
            .await?;

        // Group rows by insertion_id since all chunk rows share the same eventual commit tx/outpoint.
        let mut by_insertion_id: BTreeMap<i64, Vec<CitreaRawTxRow>> = BTreeMap::new();

        for row in citrea_rows {
            by_insertion_id
                .entry(row.insertion_id)
                .or_default()
                .push(row);
        }

        if !by_insertion_id.is_empty() {
            tracing::info!(
                "Found {} pending non-aggregate citrea rows across {} insertion_id groups",
                by_insertion_id.values().map(|v| v.len()).sum::<usize>(),
                by_insertion_id.len()
            );
        }

        // For each insertion_id group, create a single commit tx/outpoint shared by all rows.
        for (insertion_id, rows) in by_insertion_id {
            tracing::debug!(insertion_id, group_len = rows.len(), "Pending citrea group");

            // Build reveal scripts and collect commit addresses for all rows in this group.
            let mut rows_with_scripts = Vec::with_capacity(rows.len());

            for row in rows {
                let signing_data = self.create_reveal_script(row.transaction_kind, &row.body);
                rows_with_scripts.push((row, signing_data));
            }

            let _ = self
                .create_commit_outpoints_for_rows(fee_rate, insertion_id, rows_with_scripts)
                .await?;
        }

        // Now we check for all rows (except aggregate again) that has commit_outpoint but try_to_send_id is NULL.
        // For each of these, we will use the commit outpoint to create a tx that spends the commit utxo, revealing the data.
        // All inserted txs will have RBF feepaying type.
        let reveal_rows = self
            .db
            .get_citrea_txs_with_commit_outpoint_no_try_to_send(None)
            .await?;

        if !reveal_rows.is_empty() {
            tracing::info!(
                "Found {} citrea rows with commit_outpoint but no try_to_send_id",
                reveal_rows.len()
            );
            for row in reveal_rows {
                let commit_outpoint = row
                    .commit_outpoint
                    .ok_or_eyre("Expected commit_outpoint to be present")?;
                let signing_data = self.create_reveal_script(row.transaction_kind, &row.body);

                let try_to_send_id = self
                    .insert_reveal_try_to_send(row.id, commit_outpoint, signing_data)
                    .await?;

                tracing::debug!(
				"Created reveal tx for citrea row id={}, try_to_send_id={}, commit_outpoint={}:{}",
				row.id,
				try_to_send_id,
				commit_outpoint.txid,
				commit_outpoint.vout
			);
            }
        }

        // check for aggregate tx sending eligibility (if all chunks are confirmed), then send it
        self.send_aggregate_txs(fee_rate).await?;

        Ok(())
    }

    /// Checks existing commit txids for eviction based on citrea rows whose
    /// try_to_send_id is NULL or not seen yet.
    /// If evicted (not in mempool and never seen), clear commit_outpoint and delete
    /// any reveal RBF entries tied to it.
    /// These check is only required because commit_tx creation uses include_unsafe = true, if some unsafe input is
    /// spent in another way, commit tx will become invalid.
    async fn check_evicted_commit_txs(&self) -> Result<(), eyre::Report> {
        let committed_rows = self
            .db
            .get_citrea_txs_with_commit_outpoint_unseen_try_to_send(None)
            .await?;

        let mut committed_by_commit_txid: BTreeMap<bitcoin::Txid, Vec<CitreaRawTxRow>> =
            BTreeMap::new();
        for row in committed_rows {
            let commit_txid = row
                .commit_outpoint
                .ok_or_eyre("Expected commit_outpoint to be present")?
                .txid;
            committed_by_commit_txid
                .entry(commit_txid)
                .or_default()
                .push(row);
        }

        for (commit_txid, rows) in committed_by_commit_txid {
            let insertion_ids = rows
                .iter()
                .map(|row| row.insertion_id)
                .collect::<BTreeSet<_>>();

            let Some((in_mempool, seen_at_height)) =
                self.db.get_activate_txid_status(None, commit_txid).await?
            else {
                continue;
            };

            if in_mempool || seen_at_height.is_some() {
                continue;
            }
            // We don't want to mark commit tx as evicted if it is present in rpc (mempool or confirmed).
            // To be sure if it shows as evicted in db check rpc for it too.

            let rpc_present = match self.rpc.get_raw_transaction_info(&commit_txid, None).await {
                Ok(info) => {
                    if info.confirmations.unwrap_or(0) > 0 {
                        true
                    } else {
                        match self.rpc.get_mempool_entry(&commit_txid).await {
                            Ok(_) => true,
                            Err(e) if is_mempool_not_found_error(&e) => false,
                            Err(e) => {
                                tracing::warn!(
                                    ?insertion_ids,
                                    %commit_txid,
                                    error = %e,
                                    "RPC mempool check failed; skipping eviction"
                                );
                                continue;
                            }
                        }
                    }
                }
                Err(e) if is_not_found_error(&e) => false,
                Err(e) => {
                    tracing::warn!(
                        ?insertion_ids,
                        %commit_txid,
                        error = %e,
                        "RPC tx lookup failed; skipping eviction"
                    );
                    continue;
                }
            };

            if rpc_present {
                tracing::debug!(
                    ?insertion_ids,
                    %commit_txid,
                    "Commit tx present according to RPC; skipping eviction"
                );
                continue;
            }
            tracing::warn!(
                ?insertion_ids,
                %commit_txid,
                "Commit tx evicted; clearing commit_outpoint and deleting reveal RBF entries"
            );

            let mut dbtx = self.db.begin_transaction().await?;

            let row_ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
            let try_to_send_ids = rows
                .iter()
                .filter_map(|row| row.try_to_send_id)
                .map(u32::try_from)
                .collect::<Result<BTreeSet<_>, _>>()
                .wrap_err("Failed to convert citrea try_to_send_id to u32")?;

            self.db
                .clear_citrea_commit_and_try_to_send_by_ids(Some(&mut dbtx), &row_ids)
                .await?;

            for try_to_send_id in try_to_send_ids {
                self.db
                    .delete_try_to_send_tx(Some(&mut dbtx), try_to_send_id)
                    .await?;
            }

            self.db.commit_transaction(dbtx).await?;
        }
        Ok(())
    }

    /// Build and send aggregate reveal transactions once all chunk reveals are confirmed.
    ///
    /// Computes the aggregate body from confirmed chunk reveal txids/wtxids (ordered by chunk row id),
    /// updates/reset aggregate rows on mismatch or invalid post-reorg ordering, then runs the same
    /// commit/reveal flow. Marks aggregate rows as finalized only after the aggregate reveal and all
    /// chunk reveals are finalized.
    async fn send_aggregate_txs(&self, fee_rate: FeeRateKvb) -> Result<(), eyre::Report> {
        let aggregate_rows = self.db.get_citrea_aggregate_rows_pending(None).await?;
        if aggregate_rows.is_empty() {
            return Ok(());
        }

        for aggregate_row in aggregate_rows {
            let insertion_id = aggregate_row.insertion_id;
            let chunk_rows = self
                .db
                .get_citrea_chunk_rows_by_insertion_id(None, insertion_id)
                .await?;

            if chunk_rows.is_empty() {
                continue;
            }

            if chunk_rows.iter().any(|row| row.try_to_send_id.is_none()) {
                continue;
            }
            let chunk_try_to_send_ids = chunk_rows
                .iter()
                .map(citrea_try_to_send_id)
                .collect::<Result<Vec<_>, _>>()?;

            let statuses = self
                .db
                .list_try_to_send_statuses_by_ids(None, &chunk_try_to_send_ids)
                .await?;

            let all_seen = chunk_try_to_send_ids
                .iter()
                .all(|id| statuses.get(id).and_then(|(seen, _)| *seen).is_some());

            // Aggregate can only reference chunk reveals once every chunk is seen.
            if !all_seen {
                continue;
            }

            // Finalizing the aggregate row also requires all referenced chunks to be final.
            let all_chunks_finalized = chunk_try_to_send_ids
                .iter()
                .all(|id| statuses.get(id).is_some_and(|(_, finalized)| *finalized));

            let rbf_txids = self
                .db
                .list_rbf_txids_for_ids(None, &chunk_try_to_send_ids)
                .await?;

            let mut rbf_txids_by_id: HashMap<u32, Vec<bitcoin::Txid>> = HashMap::new();
            for (id, txid) in rbf_txids {
                rbf_txids_by_id.entry(id).or_default().push(txid);
            }

            let mut block_tx_position_cache = BlockTxPositionCache::new();
            let Some(confirmed_chunk_reveals) = self
                .collect_confirmed_chunk_reveals(
                    &chunk_rows,
                    &rbf_txids_by_id,
                    &mut block_tx_position_cache,
                )
                .await?
            else {
                continue;
            };
            let ConfirmedChunkReveals {
                reveal_txids,
                reveal_wtxids,
                confirmed_txs: confirmed_chunk_txs,
            } = confirmed_chunk_reveals;

            let aggregate = DataOnDa::Aggregate(reveal_txids, reveal_wtxids);
            let aggregate_body: Vec<u8> =
                borsh::to_vec(&aggregate).wrap_err("Failed to serialize aggregate body")?;

            let body_matches = aggregate_row.body == aggregate_body;
            let aggregate_try_to_send_id = optional_citrea_try_to_send_id(&aggregate_row)?;
            let mut commit_outpoint = if body_matches {
                aggregate_row.commit_outpoint
            } else {
                None
            };
            let mut try_to_send_id = if body_matches {
                aggregate_try_to_send_id
            } else {
                None
            };

            // A changed aggregate body means chunk reveal txids/wtxids changed under us.
            if !body_matches {
                self.reset_citrea_aggregate_and_delete_try_to_send(
                    aggregate_row.id,
                    &aggregate_body,
                    aggregate_try_to_send_id,
                )
                .await?;
            } else if let Some(existing_try_to_send_id) = try_to_send_id {
                let aggregate_rbf_txids = self
                    .db
                    .list_rbf_txids_for_id(None, existing_try_to_send_id)
                    .await?;

                let aggregate_confirmed_tx = self
                    .select_confirmed_tx_info(&aggregate_rbf_txids, &mut block_tx_position_cache)
                    .await?;

                // Only validate ordering/finality once an aggregate reveal is on-chain.
                if let Some(aggregate_confirmed_tx) = aggregate_confirmed_tx {
                    let status = self
                        .db
                        .list_try_to_send_statuses_by_ids(None, &[existing_try_to_send_id])
                        .await?;

                    if let Some((aggregate_seen_at_height, is_aggregate_finalized)) =
                        status.get(&existing_try_to_send_id)
                    {
                        // No seen height yet means confirmation sync has not caught this tx.
                        if aggregate_seen_at_height.is_some() {
                            let aggregate_after_chunks = confirmed_chunk_txs
                                .iter()
                                .all(|chunk_tx| aggregate_confirmed_tx.is_after(chunk_tx));

                            // Aggregate reveal must be strictly after every chunk reveal it names.
                            if !aggregate_after_chunks {
                                tracing::warn!(
                                    insertion_id,
                                    aggregate_try_to_send_id = existing_try_to_send_id,
                                    aggregate_txid = %aggregate_confirmed_tx.txid,
                                    aggregate_height = aggregate_confirmed_tx.block_height,
                                    aggregate_index = aggregate_confirmed_tx.tx_index,
                                    "Aggregate reveal confirmed before at least one chunk reveal; resetting aggregate send state"
                                );
                                self.reset_citrea_aggregate_and_delete_try_to_send(
                                    aggregate_row.id,
                                    &aggregate_body,
                                    Some(existing_try_to_send_id),
                                )
                                .await?;
                                commit_outpoint = None;
                                try_to_send_id = None;
                            } else if all_chunks_finalized && *is_aggregate_finalized {
                                // Safe to stop processing only when chunks and aggregate are final.
                                self.db
                                    .set_citrea_aggregate_finalized(None, aggregate_row.id)
                                    .await?;
                                continue;
                            }
                        }
                    }
                }
            }

            let signing_data =
                self.create_reveal_script(TransactionKind::Aggregate, &aggregate_body);

            // Missing/stale commit state is recreated after a body/order reset.
            if commit_outpoint.is_none() {
                let rows_with_scripts = vec![(aggregate_row.clone(), signing_data.clone())];
                let Some(commit_txid) = self
                    .create_commit_outpoints_for_rows(fee_rate, insertion_id, rows_with_scripts)
                    .await?
                else {
                    continue;
                };
                commit_outpoint = Some(bitcoin::OutPoint {
                    txid: commit_txid,
                    vout: 0,
                });
            }

            // Missing/stale reveal state is recreated after commit state is available.
            if try_to_send_id.is_none() {
                let commit_outpoint = commit_outpoint.expect("commit_outpoint must be set");
                let _new_try_to_send_id = self
                    .insert_reveal_try_to_send(aggregate_row.id, commit_outpoint, signing_data)
                    .await?;
            }
        }

        Ok(())
    }

    async fn create_commit_outpoints_for_rows(
        &self,
        fee_rate: FeeRateKvb,
        insertion_id: i64,
        rows_with_scripts: Vec<(CitreaRawTxRow, CitreaSigningData)>,
    ) -> Result<Option<bitcoin::Txid>, eyre::Report> {
        if rows_with_scripts.is_empty() {
            return Ok(None);
        }

        let recipients: Vec<_> = rows_with_scripts
            .iter()
            .map(|(_row, signing_data)| signing_data.commit_address.clone())
            .collect();

        let unsigned_commit_tx = crate::citrea::build_commit_transaction(&recipients);
        let raw_bytes = crate::serialize_tx_for_fund_raw(&unsigned_commit_tx);

        let funded_hex = match self
            .rpc
            .fund_raw_transaction(
                &raw_bytes,
                Some(&FundRawTransactionOptions {
                    add_inputs: Some(true),
                    include_unsafe: Some(self.include_unsafe),
                    change_address: None,
                    change_position: Some(unsigned_commit_tx.output.len() as u32),
                    change_type: None,
                    include_watching: None,
                    lock_unspents: None,
                    fee_rate: Some(Amount::from_sat(fee_rate.to_sat_per_kvb())),
                    subtract_fee_from_outputs: None,
                    replaceable: Some(true),
                    conf_target: None,
                    estimate_mode: None,
                }),
                None,
            )
            .await
        {
            Ok(result) => result.hex,
            Err(e) => {
                tracing::error!(
                    insertion_id,
                    error = %e,
                    "Failed to fund commit transaction, skipping group"
                );
                return Ok(None);
            }
        };

        let signed_commit_tx = self
            .rpc
            .sign_raw_transaction_with_wallet(&funded_hex, None, None)
            .await
            .wrap_err("Failed to sign commit transaction")?
            .transaction()
            .wrap_err(
                "Failed to convert result of sign_raw_transaction_with_wallet to btc transaction",
            )?;

        let commit_txid = signed_commit_tx.compute_txid();

        if let Err(e) = self.rpc.send_raw_transaction(&signed_commit_tx).await {
            tracing::warn!(
                insertion_id,
                commit_txid = %commit_txid,
                error = %e,
                "Failed to broadcast commit transaction, skipping group"
            );
            return Ok(None);
        }

        for (vout, (row, _signing_data)) in rows_with_scripts.into_iter().enumerate() {
            let outpoint = bitcoin::OutPoint {
                txid: commit_txid,
                vout: vout as u32,
            };

            self.db
                .set_citrea_commit_outpoint(None, row.id, outpoint)
                .await?;
        }

        Ok(Some(commit_txid))
    }

    async fn insert_reveal_try_to_send(
        &self,
        row_id: i64,
        commit_outpoint: bitcoin::OutPoint,
        signing_data: CitreaSigningData,
    ) -> Result<u32, eyre::Report> {
        let reveal_tx =
            crate::citrea::build_reveal_transaction(commit_outpoint.txid, commit_outpoint.vout);

        let mut dbtx = self.db.begin_transaction().await?;
        let try_to_send_id = self
            .client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &reveal_tx,
                clementine_utils::FeePayingType::RbfWtxidGrind,
                Some(RbfSigningInfo::new(
                    0,
                    clementine_utils::RbfSigningSpendPath::ScriptPath {
                        control_block: signing_data.control_block.serialize(),
                        script: signing_data.reveal_script.into_bytes(),
                    },
                    TapSighashType::Default,
                )),
                &[],
                &[],
                &[],
                &[],
            )
            .await?;

        self.db
            .set_citrea_try_to_send_id(&mut dbtx, row_id, try_to_send_id as i32)
            .await?;

        self.db.commit_transaction(dbtx).await?;
        Ok(try_to_send_id)
    }

    /// Resets an aggregate row to the supplied body and removes its stale reveal
    /// tracking row in one DB transaction.
    ///
    /// `update_citrea_aggregate_body_and_reset` clears the aggregate row's
    /// foreign-key reference before `delete_try_to_send_tx` removes the linked
    /// tx-sender rows.
    async fn reset_citrea_aggregate_and_delete_try_to_send(
        &self,
        aggregate_row_id: i64,
        aggregate_body: &[u8],
        try_to_send_id: Option<u32>,
    ) -> Result<(), eyre::Report> {
        let mut dbtx = self.db.begin_transaction().await?;

        self.db
            .update_citrea_aggregate_body_and_reset(
                Some(&mut dbtx),
                aggregate_row_id,
                aggregate_body,
            )
            .await?;

        if let Some(try_to_send_id) = try_to_send_id {
            self.db
                .delete_try_to_send_tx(Some(&mut dbtx), try_to_send_id)
                .await?;
        }

        self.db.commit_transaction(dbtx).await?;
        Ok(())
    }

    /// Returns confirmed chunk reveal information in chunk row order.
    ///
    /// `None` means the database has enough seen state to consider the chunks,
    /// but the current Bitcoin RPC view does not have a confirmed RBF member for
    /// at least one chunk. That can happen transiently around reorgs or before
    /// confirmation sync catches up.
    async fn collect_confirmed_chunk_reveals(
        &self,
        chunk_rows: &[CitreaRawTxRow],
        rbf_txids_by_id: &HashMap<u32, Vec<bitcoin::Txid>>,
        block_tx_position_cache: &mut BlockTxPositionCache,
    ) -> Result<Option<ConfirmedChunkReveals>, eyre::Report> {
        let mut reveal_txids = Vec::with_capacity(chunk_rows.len());
        let mut reveal_wtxids = Vec::with_capacity(chunk_rows.len());
        let mut confirmed_txs = Vec::with_capacity(chunk_rows.len());

        for row in chunk_rows {
            let try_to_send_id = citrea_try_to_send_id(row)?;
            let txids = rbf_txids_by_id.get(&try_to_send_id).map(Vec::as_slice);
            let Some(confirmed_tx) = self
                .select_confirmed_tx_info(txids.unwrap_or_default(), block_tx_position_cache)
                .await?
            else {
                return Ok(None);
            };

            reveal_txids.push(confirmed_tx.txid.to_byte_array());
            reveal_wtxids.push(confirmed_tx.wtxid.to_byte_array());
            confirmed_txs.push(confirmed_tx);
        }

        Ok(Some(ConfirmedChunkReveals {
            reveal_txids,
            reveal_wtxids,
            confirmed_txs,
        }))
    }

    /// Selects the newest confirmed member from an RBF txid history.
    ///
    /// The input is expected in newest-first insertion order, matching the
    /// tx-sender RBF query helpers. Confirmed transactions include their wtxid
    /// and block position so aggregate bodies can reference chunk reveals and
    /// aggregate ordering can be validated after reorgs.
    async fn select_confirmed_tx_info(
        &self,
        txids: &[bitcoin::Txid],
        block_tx_position_cache: &mut BlockTxPositionCache,
    ) -> Result<Option<ConfirmedTxInfo>, eyre::Report> {
        for txid in txids {
            let tx_info = match self.rpc.get_raw_transaction_info(txid, None).await {
                Ok(info) => info,
                Err(e) if is_not_found_error(&e) => continue,
                Err(e) => return Err(eyre::eyre!(e)),
            };

            if tx_info
                .confirmations
                .is_none_or(|confirmations| confirmations == 0)
            {
                continue;
            }

            let blockhash = tx_info.blockhash.ok_or_eyre(format!(
                "Confirmed transaction {txid} missing blockhash in RPC response"
            ))?;

            match block_tx_position_cache.get(&blockhash) {
                Some(_) => {}
                None => {
                    let block_info = self
                        .rpc
                        .get_block_info(&blockhash)
                        .await
                        .wrap_err("Failed to fetch confirmed transaction block info")?;
                    let block_height = u32::try_from(block_info.height)
                        .wrap_err("Failed to convert confirmed transaction block height to u32")?;
                    block_tx_position_cache.insert(blockhash, (block_height, block_info.tx));
                }
            }

            let (block_height, block_txids) = block_tx_position_cache
                .get(&blockhash)
                .expect("block info was inserted above");
            let tx_index = block_txids
                .iter()
                .position(|block_txid| block_txid == txid)
                .ok_or_eyre(format!(
                    "Confirmed transaction {txid} missing from block {blockhash}"
                ))?;

            return Ok(Some(ConfirmedTxInfo {
                txid: *txid,
                wtxid: tx_info.hash,
                block_height: *block_height,
                tx_index,
            }));
        }

        Ok(None)
    }
}
