use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{self};
use bitcoin::{Psbt, TapSighashType};
use bitcoincore_rpc::json::{BumpFeeOptions, BumpFeeResult, FinalizePsbtResult};
use eyre::{eyre, OptionExt};
use std::str::FromStr;

use bitcoin::{consensus, Amount, FeeRate, Transaction};
use bitcoincore_rpc::RpcApi;
use eyre::Context;

use crate::builder::{self};

use super::{log_error_for_tx, RbfSigningInfo, Result, SendTxError, TxMetadata, TxSender};

impl TxSender {
    /// Given a PSBT with inputs that've been signed by the wallet except for our new input,
    /// we have to sign the first input with our self.signer actor.
    ///
    /// Assumes that the first input is the input with our key.
    ///
    /// # Returns
    /// The signed PSBT as a base64-encoded string.
    pub async fn attempt_sign_psbt(
        &self,
        psbt: String,
        rbf_signing_info: RbfSigningInfo,
    ) -> Result<String> {
        // Parse the PSBT from string
        let mut decoded_psbt = Psbt::from_str(&psbt).map_err(|e| eyre!(e))?;

        // Ensure we have inputs to sign
        if decoded_psbt.inputs.is_empty() {
            return Err(eyre!("PSBT has no inputs to sign").into());
        }

        let input_index = rbf_signing_info.vout as usize;

        // Get the transaction to calculate the sighash
        let tx = decoded_psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&tx);

        // Determine the sighash type (default to ALL if not specified)
        let sighash_type = decoded_psbt.inputs[input_index]
            .sighash_type
            .unwrap_or((TapSighashType::All).into());

        // For Taproot key path spending
        if let Ok(tap_sighash_type) = sighash_type.taproot_hash_ty() {
            // Calculate the sighash for this input
            // Extract previous outputs from the PSBT
            let prevouts: Vec<bitcoin::TxOut> = decoded_psbt
                .inputs
                .iter()
                .map(|input| {
                    input
                        .witness_utxo
                        .clone()
                        .ok_or_eyre("expected inputs to be segwit")
                        .map_err(SendTxError::Other)
                })
                .collect::<Result<Vec<_>>>()?;

            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    tap_sighash_type,
                )
                .map_err(|e| eyre!("Failed to calculate sighash: {}", e))?;

            // Sign the sighash with our signer
            let signature = self
                .signer
                .sign_with_tweak_data(
                    sighash,
                    builder::sighash::TapTweakData::KeyPath(rbf_signing_info.tweak_merkle_root),
                    None,
                )
                .map_err(|e| eyre!("Failed to sign input: {}", e))?;

            // Add the signature to the PSBT
            decoded_psbt.inputs[input_index].tap_key_sig = Some(taproot::Signature {
                signature,
                sighash_type: tap_sighash_type,
            });

            // Serialize the signed PSBT back to base64
            Ok(decoded_psbt.to_string())
        } else {
            Err(eyre!("Only Taproot key path signing is currently supported").into())
        }
    }

    /// Sends or bumps a transaction using the Replace-By-Fee (RBF) strategy.
    ///
    /// It interacts with the database to track the latest RBF attempt (`last_rbf_txid`).
    ///
    /// # Logic:
    /// 1.  **Check for Existing RBF Tx:** Retrieves `last_rbf_txid` for the `try_to_send_id`.
    /// 2.  **Bump Existing Tx:** If `psbt_bump_fee` exists, it calls `rpc.client.psbt_bump_fee`.
    ///     - This internally uses the Bitcoin Core `psbtbumpfee` RPC.
    ///     - We then sign the inputs that we can using our Actor and have the wallet sign the rest.
    ///
    /// 3.  **Send Initial RBF Tx:** If no `last_rbf_txid` exists (first attempt):
    ///     - It uses `fund_raw_transaction` RPC to let the wallet add (potentially) inputs,
    ///       outputs, set the fee according to `fee_rate`, and mark the transaction as replaceable.
    ///     - Uses `sign_raw_transaction_with_wallet` RPC to sign the funded transaction.
    ///     - Uses `send_raw_transaction` RPC to broadcast the initial RBF transaction.
    ///     - Saves the resulting `txid` to the database as the `last_rbf_txid`.
    ///
    /// # Arguments
    /// * `try_to_send_id` - The database ID tracking this send attempt.
    /// * `tx` - The original transaction intended for RBF (used only on the first attempt).
    /// * `tx_metadata` - Optional metadata associated with the transaction.
    /// * `fee_rate` - The target fee rate for the RBF replacement.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, try_to_send_id, tx_meta=?tx_metadata))]
    pub(super) async fn send_rbf_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRate,
        rbf_signing_info: Option<RbfSigningInfo>,
    ) -> Result<()> {
        tracing::debug!(?tx_metadata, "Sending RBF tx",);

        tracing::debug!(?try_to_send_id, "Attempting to send.");

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "preparing_rbf", true)
            .await;

        let mut dbtx = self
            .db
            .begin_transaction()
            .await
            .wrap_err("Failed to begin database transaction")?;

        let last_rbf_txid = self
            .db
            .get_last_rbf_txid(Some(&mut dbtx), try_to_send_id)
            .await
            .wrap_err("Failed to get last RBF txid")?;

        if let Some(last_rbf_txid) = last_rbf_txid {
            let Some(rbf_signing_info) = rbf_signing_info else {
                return Err(eyre!("RBF signing info is required for RBF txs").into());
            };

            // --- Bump existing RBF transaction using PSBT ---
            tracing::debug!(
                ?try_to_send_id,
                "Attempting to bump fee for txid {last_rbf_txid} using psbt_bump_fee"
            );

            let psbt_bump_opts = BumpFeeOptions {
                conf_target: None, // Use fee_rate instead
                fee_rate: Some(bitcoincore_rpc::json::FeeRate::per_vbyte(Amount::from_sat(
                    fee_rate.to_sat_per_vb_ceil(),
                ))),
                replaceable: Some(true), // Ensure the bumped tx is also replaceable
                estimate_mode: None,
            };

            let bump_result = self
                .rpc
                .client
                .psbt_bump_fee(&last_rbf_txid, Some(&psbt_bump_opts))
                .await;

            let bumped_psbt = match bump_result {
                Err(e) => {
                    // Check for common errors indicating the tx is already confirmed or spent
                    let rpc_error_str = e.to_string();
                    if rpc_error_str.contains("Transaction already in block chain") {
                        tracing::debug!(
                            ?try_to_send_id,
                            "RBF bump failed for {last_rbf_txid}, likely confirmed or spent: {e}"
                        );
                        // No need to return error, just log and proceed
                        dbtx.commit().await.wrap_err(
                            "Failed to commit database transaction after failed bump check",
                        )?;
                        return Ok(());
                    } else {
                        // Other potentially transient errors
                        let error_message = format!("psbt_bump_fee error: {}", e);
                        log_error_for_tx!(self.db, try_to_send_id, error_message);
                        let _ = self
                            .db
                            .update_tx_debug_sending_state(
                                try_to_send_id,
                                "rbf_psbt_bump_failed",
                                true,
                            )
                            .await;
                        tracing::warn!(?try_to_send_id, "psbt_bump_fee failed: {e:?}");
                        return Err(SendTxError::Other(eyre!(e)));
                    }
                }
                Ok(BumpFeeResult {
                    psbt: Some(psbt), ..
                }) => psbt,
                Ok(BumpFeeResult { errors, .. }) if !errors.is_empty() => {
                    // TODO: handle errors here and update the state
                    todo!()
                }
                Ok(BumpFeeResult { psbt: None, .. }) => {
                    // TODO: print better msg and update state
                    tracing::error!(try_to_send_id, "received no psbt and no error");
                    todo!()
                }
            };

            // Wallet first pass
            // We rely on the node's wallet here because psbt_bump_fee might add inputs from it.
            let process_result = self
                .rpc
                .client
                .wallet_process_psbt(&bumped_psbt, Some(true), None, None) // sign=true
                .await;

            let processed_psbt = match process_result {
                Ok(res) if res.complete => res.psbt,
                // attempt to sign
                Ok(res) => self.attempt_sign_psbt(res.psbt, rbf_signing_info).await?,
                Err(e) => {
                    let err_msg = format!("wallet_process_psbt error: {}", e);
                    tracing::warn!(?try_to_send_id, "{}", err_msg);
                    log_error_for_tx!(self.db, try_to_send_id, err_msg);
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(try_to_send_id, "rbf_psbt_sign_failed", true)
                        .await;
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };

            // Finalize the PSBT
            let finalize_result = self
                .rpc
                .client
                .finalize_psbt(&processed_psbt, None) // extract=true by default
                .await;

            let final_tx_hex = match finalize_result {
                Ok(FinalizePsbtResult {
                    hex: Some(hex),
                    complete: true,
                    ..
                }) => hex,
                Ok(res) => {
                    let err_msg = format!("Could not finalize PSBT: {:?}", res);
                    log_error_for_tx!(self.db, try_to_send_id, err_msg);

                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_psbt_finalize_incomplete",
                            true,
                        )
                        .await;
                    return Err(SendTxError::PsbtError(err_msg));
                }
                Err(e) => {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("finalize_psbt error: {}", e)
                    );
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_psbt_finalize_failed",
                            true,
                        )
                        .await;
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };

            // Deserialize final tx to get txid
            let final_tx: Transaction = match consensus::deserialize(&final_tx_hex) {
                Ok(tx) => tx,
                Err(e) => {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("Failed to deserialize final RBF tx hex: {}", e)
                    );
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };
            let bumped_txid = final_tx.compute_txid();

            // Broadcast the finalized transaction
            let sent_txid = match self.rpc.client.send_raw_transaction(&final_tx).await {
                Ok(sent_txid) if sent_txid == bumped_txid => sent_txid,
                Ok(other_txid) => {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!(
                            "send_raw_transaction returned unexpected txid {} (expected {})",
                            other_txid, bumped_txid
                        )
                    );
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_send_txid_mismatch",
                            true,
                        )
                        .await;
                    return Err(SendTxError::Other(eyre!(
                        "send_raw_transaction returned unexpected txid"
                    )));
                }
                Err(e) => {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("send_raw_transaction error for bumped RBF tx: {}", e)
                    );
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(try_to_send_id, "rbf_bump_send_failed", true)
                        .await;
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };

            tracing::debug!(
                ?try_to_send_id,
                "RBF tx {last_rbf_txid} successfully bumped and sent as {sent_txid}"
            );

            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "rbf_bumped_sent", true)
                .await;

            self.db
                .save_rbf_txid(Some(&mut dbtx), try_to_send_id, sent_txid)
                .await
                .wrap_err("Failed to save new RBF txid after bump")?;
        } else {
            tracing::debug!(?try_to_send_id, "Funding initial RBF tx");

            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "funding_initial_rbf", true)
                .await;

            // Attempt to fund the transaction
            let fund_result = self
                .rpc
                .client
                .fund_raw_transaction(
                    &tx,
                    Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
                        add_inputs: Some(true),
                        change_address: None,
                        change_position: Some(1),
                        change_type: None,
                        include_watching: None,
                        lock_unspents: None,
                        fee_rate: Some(Amount::from_sat(5 * fee_rate.to_sat_per_kwu())),
                        subtract_fee_from_outputs: None,
                        replaceable: Some(true),
                        conf_target: None,
                        estimate_mode: None,
                    }),
                    None,
                )
                .await;

            let funded_result = match fund_result {
                Err(e) => {
                    // Record funding error in debug log
                    let error_message = format!("Failed to fund RBF tx: {:?}", e);

                    log_error_for_tx!(self.db, try_to_send_id, error_message);
                    tracing::warn!(try_to_send_id, "Failed to fund RBF tx: {:?}", e);

                    let _ = self
                        .db
                        .update_tx_debug_sending_state(try_to_send_id, "rbf_funding_failed", true)
                        .await;
                    return Err(eyre::eyre!(e).into());
                }
                Ok(funded_result) => funded_result,
            };

            let funded_tx = &funded_result.hex;
            // Record successful funding in debug log
            tracing::debug!(
                try_to_send_id,
                "Successfully funded RBF tx with fee {}",
                funded_result.fee
            );

            warn_if_tx_output_length_mismatch(try_to_send_id, &tx, &funded_result.hex);

            // Attempt to sign the transaction
            let sign_result = self
                .rpc
                .client
                .sign_raw_transaction_with_wallet(funded_tx, None, None)
                .await;

            let signed_result = sign_result
                .inspect_err(|e| {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("Failed to sign RBF tx: {}", e)
                    );
                })
                .map_err(|e| eyre::eyre!(e))?;

            // Record successful signing in debug log
            tracing::debug!(try_to_send_id, "Successfully signed RBF tx");

            // Deserialize the signed transaction
            let signed_tx: Transaction = bitcoin::consensus::deserialize(&signed_result.hex)
                .inspect_err(|e| {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("Failed to deserialize signed tx: {}", e)
                    );
                })
                .map_err(|e| eyre::eyre!(e))?;

            // Attempt to broadcast the transaction
            let txid = self
                .rpc
                .client
                .send_raw_transaction(&signed_tx)
                .await
                .inspect_err(|e| {
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("Failed to broadcast RBF tx: {}", e)
                    );
                })
                .map_err(|e| eyre::eyre!(e))?;

            // Record successful broadcast in debug log
            tracing::debug!(
                try_to_send_id,
                "Successfully sent RBF tx with txid {}",
                txid
            );

            // Update debug sending state
            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "sent", true)
                .await;

            self.db
                .save_rbf_txid(Some(&mut dbtx), try_to_send_id, txid)
                .await
                .wrap_err("Failed to save RBF txid")?;
        }

        dbtx.commit()
            .await
            .wrap_err("Failed to commit database transaction")?;

        Ok(())
    }
}

fn warn_if_tx_output_length_mismatch(try_to_send_id: u32, tx: &Transaction, rawtx: &[u8]) {
    // Deserialize the funded transaction
    let funded_tx_deser: Transaction =
        match consensus::deserialize(rawtx).wrap_err("failed to deserialize tx") {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(
                    try_to_send_id,
                    "Failed to deserialize tx after funding: {}",
                    e
                );
                return;
            }
        };

    if funded_tx_deser.output.len() != tx.output.len() {
        let mut should_warn = false;
        for inp in tx.input.iter() {
            if inp.witness.len() == 1 {
                // taproot keyspend witness
                if let Ok(sig) = taproot::Signature::from_slice(&inp.witness[0]) {
                    if sig.sighash_type != bitcoin::TapSighashType::SinglePlusAnyoneCanPay {
                        should_warn = true;
                    }
                }
            }
        }

        if should_warn {
            let warning = "Funded tx output length is not equal to the original tx output length, Tx Sender currently does not support this";
            tracing::warn!(try_to_send_id, "{}", warning);
        }
    }
}
