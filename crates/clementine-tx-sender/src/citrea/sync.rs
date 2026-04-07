use crate::citrea::data_serialization::DataOnDa;
use crate::citrea::reveal_scripts::CitreaSigningData;
use crate::citrea::TransactionKind;
use crate::db::citrea::CitreaRawTxRow;
use crate::rpc_errors::{is_mempool_not_found_error, is_not_found_error};
use crate::TxSender;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, TapSighashType, TxOut, Witness};
use bitcoincore_rpc::json::FundRawTransactionOptions;
use bitcoincore_rpc::RpcApi;
use clementine_config::NON_EPHEMERAL_ANCHOR_AMOUNT;
use clementine_primitives::{FeeRateKvb, MIN_TAPROOT_AMOUNT};
use clementine_utils::RbfSigningInfo;
use eyre::{Context, OptionExt};
use std::collections::{BTreeMap, HashMap};

const CITREA_REVEAL_FEE_BUFFER_MULTIPLIER: f64 = 1.0;

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
    /// This check protects against commit tx eviction scenarios while building reveal flows.
    async fn check_evicted_commit_txs(&self) -> Result<(), eyre::Report> {
        let committed_rows = self.db.get_citrea_txs_with_unseen_try_to_send(None).await?;

        let mut committed_by_insertion_id: BTreeMap<i64, Vec<CitreaRawTxRow>> = BTreeMap::new();
        for row in committed_rows {
            committed_by_insertion_id
                .entry(row.insertion_id)
                .or_default()
                .push(row);
        }

        for (insertion_id, rows) in committed_by_insertion_id {
            let commit_outpoint = rows
                .first()
                .and_then(|row| row.commit_outpoint)
                .ok_or_eyre("Expected commit_outpoint to be present")?;

            let Some((in_mempool, seen_at_height)) = self
                .db
                .get_activate_txid_status(None, commit_outpoint.txid)
                .await?
            else {
                continue;
            };

            if in_mempool || seen_at_height.is_some() {
                continue;
            }
            // We don't want to mark commit tx as evicted if it is present in rpc (mempool or confirmed).
            // To be sure if it shows as evicted in db check rpc for it too.

            let rpc_present = match self
                .rpc
                .get_raw_transaction_info(&commit_outpoint.txid, None)
                .await
            {
                Ok(info) => {
                    if info.confirmations.unwrap_or(0) > 0 {
                        true
                    } else {
                        match self.rpc.get_mempool_entry(&commit_outpoint.txid).await {
                            Ok(_) => true,
                            Err(e) if is_mempool_not_found_error(&e) => false,
                            Err(e) => {
                                tracing::warn!(
                                    insertion_id,
                                    commit_txid = %commit_outpoint.txid,
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
                        insertion_id,
                        commit_txid = %commit_outpoint.txid,
                        error = %e,
                        "RPC tx lookup failed; skipping eviction"
                    );
                    continue;
                }
            };

            if rpc_present {
                tracing::debug!(
                    insertion_id,
                    commit_txid = %commit_outpoint.txid,
                    "Commit tx present according to RPC; skipping eviction"
                );
                continue;
            }
            tracing::warn!(
                insertion_id,
                commit_txid = %commit_outpoint.txid,
                "Commit tx evicted; clearing commit_outpoint and deleting reveal RBF entries"
            );

            let mut dbtx = self.db.begin_transaction().await?;

            let try_to_send_ids = self
                .db
                .list_citrea_try_to_send_ids_by_insertion_id(Some(&mut dbtx), insertion_id)
                .await?;

            self.db
                .clear_citrea_commit_and_try_to_send_by_insertion_id(Some(&mut dbtx), insertion_id)
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
    /// updates/reset aggregate rows on mismatch (reorg), then runs the same commit/reveal flow. Marks
    /// aggregate rows as finalized once the aggregate reveal is seen and finalized.
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

            let mut chunk_try_to_send_ids = Vec::with_capacity(chunk_rows.len());
            if chunk_rows.iter().any(|row| row.try_to_send_id.is_none()) {
                continue;
            }
            for row in &chunk_rows {
                chunk_try_to_send_ids.push(
                    row.try_to_send_id
                        .expect("try_to_send_id should be present") as u32,
                );
            }

            let statuses = self
                .db
                .list_try_to_send_statuses_by_ids(None, &chunk_try_to_send_ids)
                .await?;

            let all_seen = chunk_try_to_send_ids
                .iter()
                .all(|id| statuses.get(id).and_then(|(seen, _)| *seen).is_some());

            if !all_seen {
                continue;
            }

            let rbf_txids = self
                .db
                .list_rbf_txids_for_ids(None, &chunk_try_to_send_ids)
                .await?;

            let mut rbf_txids_by_id: HashMap<u32, Vec<bitcoin::Txid>> = HashMap::new();
            for (id, txid) in rbf_txids {
                rbf_txids_by_id.entry(id).or_default().push(txid);
            }

            let mut reveal_txids = Vec::with_capacity(chunk_rows.len());
            let mut reveal_wtxids = Vec::with_capacity(chunk_rows.len());

            let mut missing_confirmed = false;
            for row in &chunk_rows {
                let try_to_send_id = row.try_to_send_id.expect("checked above") as u32;
                let txids = rbf_txids_by_id.get(&try_to_send_id).map(Vec::as_slice);
                let Some(confirmed_txid) = self
                    .select_confirmed_txid(txids.unwrap_or_default())
                    .await?
                else {
                    missing_confirmed = true;
                    break;
                };

                let confirmed_tx = self
                    .rpc
                    .get_tx_of_txid(&confirmed_txid)
                    .await
                    .wrap_err("Failed to fetch confirmed reveal tx")?;

                reveal_txids.push(confirmed_txid.to_byte_array());
                reveal_wtxids.push(confirmed_tx.compute_wtxid().to_byte_array());
            }

            if missing_confirmed {
                continue;
            }

            let aggregate = DataOnDa::Aggregate(reveal_txids, reveal_wtxids);
            let aggregate_body: Vec<u8> =
                borsh::to_vec(&aggregate).wrap_err("Failed to serialize aggregate body")?;

            let body_matches = aggregate_row.body == aggregate_body;
            let mut commit_outpoint = if body_matches {
                aggregate_row.commit_outpoint
            } else {
                None
            };
            let try_to_send_id = if body_matches {
                aggregate_row.try_to_send_id.map(|id| id as u32)
            } else {
                None
            };

            if !body_matches {
                self.db
                    .update_citrea_body_and_reset(None, aggregate_row.id, &aggregate_body)
                    .await?;
            } else if let Some(existing_try_to_send_id) = try_to_send_id {
                // if body matches, and the tx we try to send is already finalized, we can mark aggregate as finalized too so we don't check it anymore
                let status = self
                    .db
                    .list_try_to_send_statuses_by_ids(None, &[existing_try_to_send_id])
                    .await?;
                if let Some((seen_at_height, is_finalized)) = status.get(&existing_try_to_send_id) {
                    if seen_at_height.is_some() && *is_finalized {
                        self.db
                            .set_citrea_aggregate_finalized(None, aggregate_row.id)
                            .await?;
                        continue;
                    }
                }
            }

            let signing_data =
                self.create_reveal_script(TransactionKind::Aggregate, &aggregate_body);

            if commit_outpoint.is_none() {
                let rows_with_scripts = vec![(aggregate_row.clone(), signing_data.clone())];
                let commit_txid = self
                    .create_commit_outpoints_for_rows(fee_rate, insertion_id, rows_with_scripts)
                    .await?;
                if commit_txid.is_none() {
                    continue;
                }
                commit_outpoint = Some(bitcoin::OutPoint {
                    txid: commit_txid.expect("checked above"),
                    vout: 0,
                });
            }

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

        let recipients: Result<Vec<_>, eyre::Report> = rows_with_scripts
            .iter()
            .map(|(_row, signing_data)| {
                Ok((
                    signing_data.commit_address.clone(),
                    self.estimate_commit_output_amount_for_reveal(fee_rate, signing_data)?,
                ))
            })
            .collect();
        let recipients = recipients?;

        let unsigned_commit_tx = crate::citrea::build_commit_transaction(&recipients);
        let raw_bytes = crate::serialize_tx_for_fund_raw(&unsigned_commit_tx);

        let funded_hex = match self
            .rpc
            .fund_raw_transaction(
                &raw_bytes,
                Some(&FundRawTransactionOptions {
                    add_inputs: Some(true),
                    include_unsafe: Some(false),
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

    fn estimate_commit_output_amount_for_reveal(
        &self,
        fee_rate: FeeRateKvb,
        signing_data: &CitreaSigningData,
    ) -> Result<Amount, eyre::Report> {
        let change_value = std::cmp::max(
            MIN_TAPROOT_AMOUNT,
            self.change_script_pubkey.minimal_non_dust(),
        );
        let mut reveal_tx = crate::citrea::build_reveal_transaction(bitcoin::Txid::all_zeros(), 0);
        let mut witness = Witness::new();
        witness.push([0u8; 65]);
        witness.push(signing_data.reveal_script.clone().into_bytes());
        witness.push(signing_data.control_block.serialize());
        reveal_tx.input[0].witness = witness;
        reveal_tx.output.push(TxOut {
            value: NON_EPHEMERAL_ANCHOR_AMOUNT,
            script_pubkey: ScriptBuf::from_hex("51024e73").expect("valid anchor script"),
        });
        reveal_tx.output.push(TxOut {
            value: change_value,
            script_pubkey: self.change_script_pubkey.clone(),
        });

        let estimated_fee = fee_rate.fee_wu(reveal_tx.weight()).ok_or_eyre(format!(
            "Fee overflow while estimating reveal fee at {fee_rate} for insertion output"
        ))?;
        let buffered_fee = Amount::from_sat(
            ((estimated_fee.to_sat() as f64) * CITREA_REVEAL_FEE_BUFFER_MULTIPLIER).ceil() as u64,
        );

        NON_EPHEMERAL_ANCHOR_AMOUNT
            .checked_add(change_value)
            .and_then(|amount| amount.checked_add(buffered_fee))
            .ok_or_eyre(format!(
                "Commit output amount overflow while estimating reveal fee: dummy={NON_EPHEMERAL_ANCHOR_AMOUNT}, change={change_value}, fee={buffered_fee}",
            ))
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
                Some(RbfSigningInfo {
                    vout: 0,
                    spend_path: clementine_utils::RbfSigningSpendPath::ScriptPath {
                        control_block: signing_data.control_block.serialize(),
                        script: signing_data.reveal_script.into_bytes(),
                    },
                    tap_sighash_type: TapSighashType::Default,
                }),
                &[],
            )
            .await?;

        self.db
            .set_citrea_try_to_send_id(&mut dbtx, row_id, try_to_send_id as i32)
            .await?;

        self.db.commit_transaction(dbtx).await?;
        Ok(try_to_send_id)
    }

    async fn select_confirmed_txid(
        &self,
        txids: &[bitcoin::Txid],
    ) -> Result<Option<bitcoin::Txid>, eyre::Report> {
        for txid in txids {
            let confirmations = match self.rpc.get_raw_transaction_info(txid, None).await {
                Ok(info) => info.confirmations.filter(|c| *c > 0),
                Err(e) if is_not_found_error(&e) => None,
                Err(e) => return Err(eyre::eyre!(e)),
            };

            if confirmations.is_some() {
                return Ok(Some(*txid));
            }
        }

        Ok(None)
    }
}
