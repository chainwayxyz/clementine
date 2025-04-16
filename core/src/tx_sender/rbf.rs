use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{self};
use bitcoin::{Psbt, TapSighashType};
use bitcoincore_rpc::json::{
    BumpFeeOptions, BumpFeeResult, CreateRawTransactionInput, FinalizePsbtResult,
};
use eyre::{eyre, OptionExt};
use std::str::FromStr;

use bitcoin::{consensus, Address, Amount, FeeRate, Transaction};
use bitcoincore_rpc::RpcApi;
use eyre::Context;

use crate::builder::{self};

use super::{log_error_for_tx, RbfSigningInfo, Result, SendTxError, TxMetadata, TxSender};

impl TxSender {
    /// Given a PSBT with inputs, fill in the witnesses from the original tx
    /// that are definitely valid.  This allows us to create a finalized PSBT if
    /// the original tx had SinglePlusAnyoneCanPay signatures.  If the original
    /// tx did not have S+AP, these signatures will not be added.
    ///
    /// # Returns
    /// The PSBT as a base64-encoded string.
    pub async fn fill_sap_signatures(
        &self,
        psbt: String,
        initial_tx: Transaction,
    ) -> Result<String> {
        let mut decoded_psbt = Psbt::from_str(&psbt).map_err(|e| eyre!(e))?;

        for (idx, input) in initial_tx.input.iter().enumerate() {
            // check if the input has a witness with a keyspend taproot signature which is not sighashdefault
            if input.witness.len() == 1 {
                if let Ok(sig) = taproot::Signature::from_slice(&input.witness[0]) {
                    if sig.sighash_type == TapSighashType::SinglePlusAnyoneCanPay {
                        decoded_psbt.inputs[idx].final_script_witness = Some(input.witness.clone());
                    }
                }
            }
        }

        Ok(decoded_psbt.to_string())
    }

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

            let bumped_psbt = self
                .fill_sap_signatures(bumped_psbt, tx)
                .await
                .wrap_err("Failed to fill SAP signatures")?;

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
            tracing::debug!(
                ?try_to_send_id,
                "Funding initial RBF tx using PSBT workflow"
            );

            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "creating_initial_rbf_psbt", true)
                .await;

            // 1. Create a funded PSBT using the wallet
            let create_psbt_opts = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
                add_inputs: Some(true), // Let the wallet add its inputs
                change_address: None,
                change_position: Some(tx.output.len() as u16 - 1), // Add change output at last index (so that SinglePlusAnyoneCanPay signatures stay valid)
                change_type: None,
                include_watching: None,
                lock_unspent: None,
                // Bitcoincore expects sat/vbyte for fee_rate
                fee_rate: Some(Amount::from_sat(fee_rate.to_sat_per_vb_ceil())),
                subtract_fee_from_outputs: vec![],
                replaceable: Some(true), // Mark as RBF enabled
                conf_target: None,
                estimate_mode: None,
            };

            let create_psbt_result = self
                .rpc
                .client
                .wallet_create_funded_psbt(
                    &tx.input
                        .iter()
                        .map(|inp| CreateRawTransactionInput {
                            txid: inp.previous_output.txid,
                            vout: inp.previous_output.vout,
                            sequence: Some(inp.sequence.to_consensus_u32()),
                        })
                        .collect::<Vec<_>>(),
                    &tx.output
                        .iter()
                        .map(|out| -> Result<(String, Amount)> {
                            let address = Address::from_script(&out.script_pubkey, self.network)
                                .map_err(|e| eyre!(e))?;
                            Ok((address.to_string(), out.value))
                        })
                        .collect::<Result<std::collections::HashMap<_, _>>>()?, // Use original tx outputs
                    None, // locktime
                    Some(create_psbt_opts),
                    None, // Bip32 derivation options
                )
                .await;

            let initial_psbt = match create_psbt_result {
                Ok(res) => {
                    tracing::debug!(
                        try_to_send_id,
                        "Successfully created initial RBF PSBT with fee {}",
                        res.fee
                    );
                    res.psbt
                }
                Err(e) => {
                    let error_message = format!("Failed to create funded RBF PSBT: {}", e);
                    log_error_for_tx!(self.db, try_to_send_id, error_message);
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_psbt_create_failed",
                            true,
                        )
                        .await;
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };

            let initial_psbt = self
                .fill_sap_signatures(initial_psbt, tx)
                .await
                .wrap_err("Failed to fill SAP signatures")?;

            // 2. Process the PSBT (let the wallet sign its inputs)
            let process_result = self
                .rpc
                .client
                .wallet_process_psbt(&initial_psbt, Some(true), None, None) // sign=true
                .await;

            let processed_psbt = match process_result {
                Ok(res) => {
                    tracing::debug!(try_to_send_id, "Successfully processed initial RBF PSBT");
                    res
                }
                Err(e) => {
                    let error_message = format!("Failed to process initial RBF PSBT: {}", e);
                    log_error_for_tx!(self.db, try_to_send_id, error_message);
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_psbt_process_failed",
                            true,
                        )
                        .await;
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };

            let signed_psbt: String;

            // Sign the PSBT if we have RBF signing info
            if let Some(rbf_signing_info) = rbf_signing_info {
                signed_psbt = self
                    .attempt_sign_psbt(processed_psbt.psbt, rbf_signing_info)
                    .await?;
            } else if processed_psbt.complete {
                signed_psbt = processed_psbt.psbt;
            } else {
                tracing::warn!(
                    ?try_to_send_id,
                    "PSBT is not complete, and we do not have RBF signing info"
                );

                return Err(SendTxError::Other(eyre!(
                    "PSBT is not complete, and we do not have RBF signing info"
                )));
            }

            // 3. Finalize the PSBT using the wallet
            let finalize_result = self
                .rpc
                .client
                .finalize_psbt(&signed_psbt, None) // extract=true by default
                .await;

            // Deserialize complete TX
            let final_tx = match finalize_result {
                Ok(FinalizePsbtResult {
                    hex: Some(hex),
                    complete: true,
                    ..
                }) => {
                    tracing::debug!(try_to_send_id, "Successfully finalized initial RBF PSBT");
                    // Deserialize final tx to get txid and check outputs
                    match consensus::deserialize::<Transaction>(&hex) {
                        Ok(deserialized_tx) => deserialized_tx,
                        Err(e) => {
                            let err_msg = format!(
                                "Failed to deserialize finalized initial RBF tx hex: {}",
                                e
                            );
                            log_error_for_tx!(self.db, try_to_send_id, err_msg);
                            let _ = self
                                .db
                                .update_tx_debug_sending_state(
                                    try_to_send_id,
                                    "rbf_psbt_deserialize_failed",
                                    true,
                                )
                                .await;
                            return Err(SendTxError::Other(eyre!(e)));
                        }
                    }
                }
                // Could not finalize PSBT after us signing and the wallet signing, abort
                Ok(res) => {
                    let err_msg = format!("Could not finalize initial RBF PSBT: {:?}", res);
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
                // Failed to finalize for some other reason, abort
                Err(e) => {
                    let err_msg = format!("finalize_psbt error for initial RBF: {}", e);
                    log_error_for_tx!(self.db, try_to_send_id, err_msg);
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

            let initial_txid = final_tx.compute_txid();

            // 4. Broadcast the finalized transaction
            let sent_txid = match self.rpc.client.send_raw_transaction(&final_tx).await {
                Ok(sent_txid) => {
                    if sent_txid != initial_txid {
                        let err_msg = format!(
                            "send_raw_transaction returned unexpected txid {} (expected {}) for initial RBF",
                            sent_txid, initial_txid
                        );
                        log_error_for_tx!(self.db, try_to_send_id, err_msg);
                        let _ = self
                            .db
                            .update_tx_debug_sending_state(
                                try_to_send_id,
                                "rbf_initial_send_txid_mismatch",
                                true,
                            )
                            .await;
                        return Err(SendTxError::Other(eyre!(err_msg)));
                    }
                    tracing::debug!(
                        try_to_send_id,
                        "Successfully sent initial RBF tx with txid {}",
                        sent_txid
                    );
                    sent_txid
                }
                Err(e) => {
                    let err_msg = format!("send_raw_transaction error for initial RBF tx: {}", e);
                    log_error_for_tx!(self.db, try_to_send_id, err_msg);
                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_initial_send_failed",
                            true,
                        )
                        .await;
                    return Err(SendTxError::Other(eyre!(e)));
                }
            };

            // Update debug sending state
            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "rbf_initial_sent", true)
                .await;

            self.db
                .save_rbf_txid(Some(&mut dbtx), try_to_send_id, sent_txid)
                .await
                .wrap_err("Failed to save initial RBF txid")?;
        }

        dbtx.commit()
            .await
            .wrap_err("Failed to commit database transaction")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;
    use crate::actor::Actor;
    use crate::builder::script::SpendPath;
    use crate::builder::transaction::input::SpendableTxIn;
    use crate::builder::transaction::output::UnspentTxOut;
    use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
    use crate::constants::MIN_TAPROOT_AMOUNT;
    use crate::errors::BridgeError;
    use crate::extended_rpc::ExtendedRpc;
    use crate::rpc::clementine::tagged_signature::SignatureId;
    use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
    use crate::task::{IntoTask, TaskExt};
    use crate::test::common::*;
    use crate::tx_sender::FeePayingType;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::TxOut;
    use std::result::Result;
    use std::time::Duration;

    async fn create_rbf_tx(
        rpc: &ExtendedRpc,
        signer: &Actor,
        network: bitcoin::Network,
        requires_initial_funding: bool,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

        let amount = Amount::from_sat(100000);
        let outpoint = rpc.send_to_address(&address, amount).await?;
        rpc.mine_blocks(1).await?;

        let version = Version::TWO;

        let mut txhandler = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(version)
            .add_input(
                if !requires_initial_funding {
                    SignatureId::from(NormalSignatureKind::Challenge)
                } else {
                    SignatureId::from((NumberedSignatureKind::WatchtowerChallenge, 0i32))
                },
                SpendableTxIn::new(
                    outpoint,
                    TxOut {
                        value: amount,
                        script_pubkey: address.script_pubkey(),
                    },
                    vec![],
                    Some(spend_info),
                ),
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(TxOut {
                value: if requires_initial_funding {
                    amount // do not add any fee if we want to test initial funding
                } else {
                    amount - MIN_TAPROOT_AMOUNT * 3
                },
                script_pubkey: address.script_pubkey(), // In practice, should be the wallet address, not the signer address
            }))
            .finalize();

        signer
            .tx_sign_and_fill_sigs(&mut txhandler, &[], None)
            .unwrap();

        let tx = txhandler.get_cached_tx().clone();
        Ok(tx)
    }

    #[tokio::test]
    async fn test_send_rbf() -> Result<(), BridgeError> {
        // Initialize RPC, tx_sender and other components
        let mut config = create_test_config_with_thread_name().await;
        let rpc = create_regtest_rpc(&mut config).await;

        let (tx_sender, btc_sender, rpc, db, signer, network) =
            create_tx_sender(rpc.rpc().clone()).await;
        let pair = btc_sender.into_task().cancelable_loop();
        pair.0.into_bg();

        // Create a bumpable transaction
        let tx = create_rbf_tx(&rpc, &signer, network, false).await?;

        // Insert the transaction into the database
        let mut dbtx = db.begin_transaction().await?;
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(
                &mut dbtx,
                None, // No metadata
                &tx,
                FeePayingType::RBF,
                Some(RbfSigningInfo {
                    vout: 0,
                    tweak_merkle_root: None,
                }),
                &[], // No cancel outpoints
                &[], // No cancel txids
                &[], // No activate txids
                &[], // No activate outpoints
            )
            .await?;
        dbtx.commit().await?;

        // Get the current fee rate and increase it for RBF
        let current_fee_rate = tx_sender.get_fee_rate().await?;

        // Test send_rbf_tx
        tx_sender
            .send_rbf_tx(
                try_to_send_id,
                tx.clone(),
                None,
                current_fee_rate,
                Some(RbfSigningInfo {
                    vout: 0,
                    tweak_merkle_root: None,
                }),
            )
            .await
            .expect("RBF should succeed");

        // Verify that the transaction was fee-bumped
        let tx_debug_info = tx_sender
            .client()
            .debug_tx(try_to_send_id)
            .await
            .expect("Transaction should be have debug info");

        // Get the actual transaction from the mempool
        rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
            tx_debug_info.txid.try_into().unwrap(),
        ))
        .await
        .expect("Transaction should be in mempool");

        Ok(())
    }
    #[tokio::test]
    async fn test_send_without_info_rbf() -> Result<(), BridgeError> {
        // Initialize RPC, tx_sender and other components
        let mut config = create_test_config_with_thread_name().await;
        let rpc = create_regtest_rpc(&mut config).await;

        let (tx_sender, btc_sender, rpc, db, signer, network) =
            create_tx_sender(rpc.rpc().clone()).await;
        let pair = btc_sender.into_task().cancelable_loop();
        pair.0.into_bg();

        // Create a bumpable transaction
        let tx = create_rbf_tx(&rpc, &signer, network, false).await?;

        // Insert the transaction into the database
        let mut dbtx = db.begin_transaction().await?;
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(
                &mut dbtx,
                None, // No metadata
                &tx,
                FeePayingType::RBF,
                None,
                &[], // No cancel outpoints
                &[], // No cancel txids
                &[], // No activate txids
                &[], // No activate outpoints
            )
            .await?;
        dbtx.commit().await?;

        // Get the current fee rate and increase it for RBF
        let current_fee_rate = tx_sender.get_fee_rate().await?;

        // Test send_rbf_tx
        tx_sender
            .send_rbf_tx(
                try_to_send_id,
                tx.clone(),
                None,
                current_fee_rate,
                None,
            )
            .await
            .expect("RBF should succeed");

        // Verify that the transaction was fee-bumped
        let tx_debug_info = tx_sender
            .client()
            .debug_tx(try_to_send_id)
            .await
            .expect("Transaction should be have debug info");

        // Get the actual transaction from the mempool
        rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
            tx_debug_info.txid.try_into().unwrap(),
        ))
        .await
        .expect("Transaction should be in mempool");

        Ok(())
    }

    #[tokio::test]
    async fn test_bump_rbf_after_sent() -> Result<(), BridgeError> {
        // Initialize RPC, tx_sender and other components
        let mut config = create_test_config_with_thread_name().await;
        let rpc = create_regtest_rpc(&mut config).await;

        let (tx_sender, btc_sender, rpc, db, signer, network) =
            create_tx_sender(rpc.rpc().clone()).await;
        let pair = btc_sender.into_task().cancelable_loop();
        pair.0.into_bg();

        // Create a bumpable transaction
        let tx = create_rbf_tx(&rpc, &signer, network, false).await?;

        // Insert the transaction into the database
        let mut dbtx = db.begin_transaction().await?;
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(
                &mut dbtx,
                None, // No metadata
                &tx,
                FeePayingType::RBF,
                None,
                &[], // No cancel outpoints
                &[], // No cancel txids
                &[], // No activate txids
                &[], // No activate outpoints
            )
            .await?;
        dbtx.commit().await?;

        let current_fee_rate = tx_sender.get_fee_rate().await?;

        // Create initial TX
        tx_sender
            .send_rbf_tx(
                try_to_send_id,
                tx.clone(),
                None,
                current_fee_rate,
                Some(RbfSigningInfo {
                    vout: 0,
                    tweak_merkle_root: None,
                }),
            )
            .await
            .expect("RBF should succeed");

        // Verify that the transaction was saved in db
        let tx_debug_info = tx_sender
            .client()
            .debug_tx(try_to_send_id)
            .await
            .expect("Transaction should be have debug info");

        // Verify that TX is in mempool
        rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
            tx_debug_info.txid.try_into().unwrap(),
        ))
        .await
        .expect("Transaction should be in mempool");

        // Increase fee rate
        let higher_fee_rate =
            FeeRate::from_sat_per_vb(current_fee_rate.to_sat_per_vb_ceil() * 100).unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        // try to send tx with a bumped fee.
        tx_sender
            .send_rbf_tx(
                try_to_send_id,
                tx.clone(),
                None,
                higher_fee_rate,
                Some(RbfSigningInfo {
                    vout: 0,
                    tweak_merkle_root: None,
                }),
            )
            .await
            .expect("RBF should succeed");

        // Verify that the transaction was saved in db
        let tx_debug_info = tx_sender
            .client()
            .debug_tx(try_to_send_id)
            .await
            .expect("Transaction should be have debug info");

        // Verify that TX is in mempool
        rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
            tx_debug_info.txid.try_into().unwrap(),
        ))
        .await
        .expect("Transaction should be in mempool");

        Ok(())
    }

    #[tokio::test]
    async fn test_bg_send_rbf() -> Result<(), BridgeError> {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();

        let (client, _tx_sender, _cancel_txs, rpc, db, signer, network) =
            create_bg_tx_sender(rpc).await;

        let tx = create_rbf_tx(&rpc, &signer, network, false).await.unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::RBF,
                Some(RbfSigningInfo {
                    vout: 0,
                    tweak_merkle_root: None,
                }),
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        dbtx.commit().await.unwrap();

        poll_until_condition(
            async || {
                rpc.mine_blocks(1).await.unwrap();

                let tx_result = rpc
                    .client
                    .get_raw_transaction_info(&tx.compute_txid(), None)
                    .await;

                Ok(tx_result.is_ok() && tx_result.unwrap().confirmations.unwrap() > 0)
            },
            Some(Duration::from_secs(30)),
            Some(Duration::from_millis(100)),
        )
        .await
        .expect("Tx was not confirmed in time");

        Ok(())
    }
}
