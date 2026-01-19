use crate::db::citrea::CitreaRawTxRow;
use crate::TxSender;
use bitcoin::{Amount, FeeRate};
use bitcoincore_rpc::json::FundRawTransactionOptions;
use bitcoincore_rpc::RpcApi;
use eyre::{Context, OptionExt};
use std::collections::BTreeMap;

impl TxSender {
    /// Syncs citrea transactions, creating commit transactions for txs without it.
    /// After creating commit tx, the reveal txs are added to the core txsender queue using insert_try_to_send as RBF txs.
    pub async fn sync_citrea_txs(&self, fee_rate: FeeRate) -> Result<(), eyre::Report> {
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

        tracing::info!(
            "Found {} pending non-aggregate citrea rows across {} insertion_id groups",
            by_insertion_id.values().map(|v| v.len()).sum::<usize>(),
            by_insertion_id.len()
        );

        // For each insertion_id group, create a single commit tx/outpoint shared by all rows.
        for (insertion_id, rows) in by_insertion_id {
            tracing::debug!(insertion_id, group_len = rows.len(), "Pending citrea group");

            // Build reveal scripts and collect commit addresses for all rows in this group.
            let mut recipients = Vec::with_capacity(rows.len());
            let mut rows_with_scripts = Vec::with_capacity(rows.len());

            for row in rows {
                let (reveal_script, control_block, commit_address) =
                    self.create_reveal_script(row.transaction_kind.clone(), &row.body);

                recipients.push(commit_address.clone());
                rows_with_scripts.push((row, reveal_script, control_block, commit_address));
            }

            // Build unsigned commit transaction paying to all reveal addresses.
            let unsigned_commit_tx = crate::citrea::build_commit_transaction(&recipients);

            // Serialize for fund_raw_transaction, handling 0-input segwit quirk.
            let raw_bytes = crate::serialize_tx_for_fund_raw(&unsigned_commit_tx);

            // Let the wallet fund the transaction (add inputs/change) with default options.
            let funded_hex = match self
                .rpc
                .fund_raw_transaction(
                    &raw_bytes,
                    Some(&FundRawTransactionOptions {
                        add_inputs: Some(true),
                        change_address: None,
                        change_position: None,
                        change_type: None,
                        include_watching: None,
                        lock_unspents: None,
                        fee_rate: Some(Amount::from_sat(fee_rate.to_sat_per_vb_ceil() * 1000)),
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
                    continue;
                }
            };

            // Sign the funded transaction with the wallet.
            let signed_hex = self
                .rpc
                .sign_raw_transaction_with_wallet(&funded_hex, None, None)
                .await
                .wrap_err("Failed to sign commit transaction")?
                .hex;

            let signed_commit_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
                &hex::decode(&signed_hex).wrap_err("Failed to decode signed hex transaction")?,
            )
            .wrap_err("Failed to deserialize signed commit transaction")?;

            let commit_txid = signed_commit_tx.compute_txid();

            // Broadcast the commit transaction.
            if let Err(e) = self.rpc.send_raw_transaction(&signed_commit_tx).await {
                tracing::warn!(
                    insertion_id,
                    commit_txid = %commit_txid,
                    error = %e,
                    "Failed to broadcast commit transaction, skipping group"
                );
                continue;
            }

            // Persist commit outpoints for each Citrea row in a single DB transaction.
            for (vout, (row, _reveal_script, _control_block, _commit_address)) in
                rows_with_scripts.into_iter().enumerate()
            {
                let outpoint = bitcoin::OutPoint {
                    txid: commit_txid,
                    vout: vout as u32,
                };

                self.db
                    .set_citrea_commit_outpoint(None, row.id, outpoint)
                    .await?;
            }
        }

        // Now we check for all rows (except aggregate again) that has commit_outpoint but try_to_send_id is NULL.
        // For each of these, we will use the commit outpoint to create a tx that spends the commit utxo, revealing the data.
        // All inserted txs will have RBF feepaying type.
        let reveal_rows = self
            .db
            .get_citrea_txs_with_commit_outpoint_no_try_to_send(None)
            .await?;

        tracing::info!(
            "Found {} citrea rows with commit_outpoint but no try_to_send_id",
            reveal_rows.len()
        );

        if !reveal_rows.is_empty() {
            for row in reveal_rows {
                let commit_outpoint = row
                    .commit_outpoint
                    .ok_or_eyre("Expected commit_outpoint to be present")?;

                // Build reveal transaction that spends the commit outpoint.
                let reveal_tx = crate::citrea::build_reveal_transaction(
                    commit_outpoint.txid,
                    commit_outpoint.vout,
                );

                // Insert reveal transaction into tx_sender_try_to_send_txs with RBF fee paying type.
                // Each insertion uses its own DB transaction.
                let mut dbtx = self.db.begin_transaction().await?;

                let try_to_send_id = self
                    .client
                    .insert_try_to_send(
                        &mut dbtx,
                        None, // No tx_metadata for citrea txs, it is still clementine specific
                        &reveal_tx,
                        clementine_utils::FeePayingType::RBF,
                        None,
                        &[],
                        &[],
                        &[],
                        &[],
                    )
                    .await?;

                // Link the try_to_send_id back to the citrea row.
                self.db
                    .set_citrea_try_to_send_id(&mut dbtx, row.id, try_to_send_id as i32)
                    .await?;

                self.db.commit_transaction(dbtx).await?;

                tracing::debug!(
					"Created reveal tx for citrea row id={}, try_to_send_id={}, commit_outpoint={}:{}",
					row.id,
					try_to_send_id,
					commit_outpoint.txid,
					commit_outpoint.vout
				);
            }
        }

        // TODO: aggregate txs

        Ok(())
    }
}
