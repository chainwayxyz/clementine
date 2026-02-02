use crate::{log_error_for_tx, TxSender};
use bitcoin::absolute::{LockTime, LOCK_TIME_THRESHOLD};
use bitcoin::hashes::Hash;
use bitcoin::script::Instruction;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{self, LeafVersion};
use bitcoin::{Address, Amount, ScriptBuf, TapLeafHash, Transaction};
use bitcoin::{Psbt, TxOut, Txid, Witness};
use bitcoincore_rpc::json::{
    BumpFeeOptions, BumpFeeResult, CreateRawTransactionInput, WalletCreateFundedPsbtOutput,
    WalletCreateFundedPsbtOutputs, WalletCreateFundedPsbtResult,
};
use bitcoincore_rpc::RpcApi;
use clementine_config::NON_EPHEMERAL_ANCHOR_AMOUNT;
use clementine_errors::SendTxError;
use clementine_primitives::FeeRateKvb;
use clementine_utils::sign::TapTweakData;
use clementine_utils::{RbfSigningInfo, RbfSigningSpendPath, TxMetadata};
use eyre::Context;
use eyre::{eyre, OptionExt};
use std::str::FromStr;

use super::Result;

/// Prefix for the reveal transaction ids for wtxid grinding.
#[cfg(feature = "testing")]
pub const REVEAL_TX_PREFIX: &[u8] = &[2];
#[cfg(not(feature = "testing"))]
pub const REVEAL_TX_PREFIX: &[u8] = &[2, 2];

impl TxSender {
    /// Calculates the appropriate fee rate for a Replace-By-Fee (RBF) transaction.
    ///
    /// This method determines the effective fee rate needed to successfully replace
    /// an existing transaction in the mempool. It follows Bitcoin's RBF rules by:
    ///
    /// 1. Retrieving the original transaction and calculating its current fee rate
    /// 2. Ensuring the new fee rate is higher than the original by at least the minimum
    ///    required incremental relay fee
    /// 3. Comparing the calculated minimum bump fee rate with the requested target fee rate
    ///    and selecting the higher of the two
    ///
    /// # Arguments
    /// * `txid` - The transaction ID of the original transaction to be replaced
    /// * `new_feerate` - The target fee rate requested for the replacement transaction
    ///
    /// # Returns
    /// * `Ok(Some(FeeRateKvb))` - The effective fee rate (in satoshis per kvB) to use for the replacement
    /// * `Ok(None)` - If the original transaction already has a higher fee rate than requested
    /// * `Err(...)` - If there was an error retrieving or analyzing the original transaction
    pub async fn calculate_bump_feerate_if_needed(
        &self,
        txid: &Txid,
        new_feerate: FeeRateKvb,
    ) -> Result<Option<FeeRateKvb>> {
        let original_tx = self.rpc.get_tx_of_txid(txid).await.map_err(|e| eyre!(e))?;

        // Calculate original tx fee
        let original_tx_fee = self.get_tx_fee(&original_tx).await.map_err(|e| eyre!(e))?;

        let original_tx_weight = original_tx.weight();

        // Original fee rate calculation according to Bitcoin Core
        // Use sat/kvB to retain precision when converting to sat/vB.
        let original_feerate_sat_per_kvb = FeeRateKvb::from_sat_per_kvb(
            original_tx_fee
                .to_sat()
                .saturating_mul(1000)
                .div_ceil(original_tx_weight.to_vbytes_ceil() as u64),
        );

        // If original feerate is already higher than target, avoid bumping
        if original_feerate_sat_per_kvb >= new_feerate {
            return Ok(None);
        }

        // Get minimum fee increment rate from node for BIP125 compliance. Returned value is in BTC/kvB
        let incremental_fee_rate = self
            .rpc
            .get_network_info()
            .await
            .map_err(|e| eyre!(e))?
            .incremental_fee;
        let incremental_fee_rate_sat_per_kvb = incremental_fee_rate.to_sat();
        let incremental_fee_rate = FeeRateKvb::from_sat_per_kvb(incremental_fee_rate_sat_per_kvb);

        // Use max of target fee rate and original + minimum fee increment rate.
        let min_bump_feerate =
            original_feerate_sat_per_kvb.to_sat_per_kvb() + incremental_fee_rate.to_sat_per_kvb();

        let effective_feerate_sat_per_kvb =
            std::cmp::max(new_feerate.to_sat_per_kvb(), min_bump_feerate);

        Ok(Some(FeeRateKvb::from_sat_per_kvb(
            effective_feerate_sat_per_kvb,
        )))
    }

    pub async fn fill_in_utxo_info(&self, psbt: &mut String) -> Result<()> {
        let mut decoded_psbt = Psbt::from_str(psbt).map_err(|e| eyre!(e))?;
        let tx = decoded_psbt.unsigned_tx.clone();

        for (idx, input) in tx.input.iter().enumerate() {
            let utxo = self
                .rpc
                .get_tx_out(
                    &input.previous_output.txid,
                    input.previous_output.vout,
                    Some(false),
                )
                .await
                .wrap_err("Failed to get UTXO info")?;

            if let Some(utxo) = utxo {
                decoded_psbt.inputs[idx].witness_utxo = Some(TxOut {
                    value: utxo.value,
                    script_pubkey: utxo
                        .script_pub_key
                        .script()
                        .wrap_err("Failed to get script pubkey")?,
                });
            }
        }

        *psbt = decoded_psbt.to_string();

        Ok(())
    }

    /// Given a PSBT with inputs, fill in the existing witnesses from the original tx
    /// This allows us to create a finalized PSBT if
    /// the original tx had SinglePlusAnyoneCanPay signatures.  If the original
    /// tx did not have S+AP, these signatures will be added. The expected behavior is for them to be replaced using RbfSigningInfo.
    ///
    /// # Returns
    /// The PSBT as a base64-encoded string.
    pub async fn copy_witnesses(&self, psbt: String, initial_tx: &Transaction) -> Result<String> {
        let mut decoded_psbt = Psbt::from_str(&psbt).map_err(|e| eyre!(e))?;

        for (idx, input) in initial_tx.input.iter().enumerate() {
            if let Some(sig) = input.witness.nth(0) {
                if sig.len() == 65 && sig[64] == 0x83 {
                    // This is a S+AP signature, copy it over
                    decoded_psbt.inputs[idx].final_script_witness = Some(input.witness.clone());
                }
            }
        }

        Ok(decoded_psbt.to_string())
    }

    pub async fn create_funded_psbt(
        &self,
        tx: &Transaction,
        fee_rate: FeeRateKvb,
    ) -> Result<WalletCreateFundedPsbtResult> {
        // 1. Create a funded PSBT using the wallet
        let create_psbt_opts = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            add_inputs: Some(true), // Let the wallet add its inputs
            include_unsafe: Some(true),
            change_address: None,
            change_position: Some(tx.output.len() as u16), // Add change output at last index (so that SinglePlusAnyoneCanPay signatures stay valid)
            change_type: None,
            include_watching: None,
            lock_unspent: None,
            // Bitcoincore expects BTC/kvbyte for fee_rate
            fee_rate: Some(
                fee_rate
                    .fee_vb(1000)
                    .ok_or_eyre("Failed to convert fee rate to BTC/kvbyte")?,
            ),
            subtract_fee_from_outputs: vec![],
            replaceable: Some(true), // Mark as RBF enabled
            conf_target: None,
            estimate_mode: None,
        };

        let mut omitted = 0usize;
        let filtered_outputs: Vec<WalletCreateFundedPsbtOutput> = tx
            .output
            .iter()
            .filter_map(|out| {
                if out.script_pubkey.is_op_return() {
                    if let Some(Ok(Instruction::PushBytes(data))) =
                        out.script_pubkey.instructions().last()
                    {
                        return Some(WalletCreateFundedPsbtOutput::OpReturn(
                            data.as_bytes().to_vec(),
                        ));
                    }
                }
                let address = Address::from_script(
                    &out.script_pubkey,
                    self.network,
                )
                .map_err(|e| eyre!(e));
                match address {
                    Ok(address) => Some(WalletCreateFundedPsbtOutput::Spendable(
                        address.to_string(),
                        out.value,
                    )),
                    Err(err) => {
                        tracing::error!(
                            "Failed to get address from script for output of tx with txid {} for script: {}",
                            tx.compute_txid(),
                            err
                        );
                        omitted += 1;
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

        if omitted > 0 {
            return Err(eyre::eyre!("Failed to get address for outputs of tx with txid {} for {} outputs in create_funded_psbt", tx.compute_txid(), omitted).into());
        }

        let outputs = WalletCreateFundedPsbtOutputs(filtered_outputs);

        self.rpc
            .wallet_create_funded_psbt(
                &tx.input
                    .iter()
                    .map(|inp| CreateRawTransactionInput {
                        txid: inp.previous_output.txid,
                        vout: inp.previous_output.vout,
                        sequence: Some(inp.sequence.to_consensus_u32()),
                        // give a specific weight if witness is not empty
                        weight: if inp.witness.is_empty() {
                            None
                        } else {
                            Some(inp.segwit_weight().to_wu())
                        },
                    })
                    .collect::<Vec<_>>(),
                outputs,
                None,
                Some(create_psbt_opts),
                None,
            )
            .await
            .map_err(|e| eyre!(e).into())
    }
    /// Given a PSBT with inputs that've been signed by the wallet except for our new input,
    /// we have to sign the input with our secret key.
    ///
    /// # Arguments
    /// * `psbt` - The PSBT to sign.
    /// * `rbf_signing_info` - The RBF signing info.
    /// * `cached_leaf_hash` - The cached leaf hash for script path spends.
    ///
    /// # Returns
    /// The signed PSBT as a base64-encoded string.
    pub async fn attempt_sign_psbt(
        &self,
        psbt: String,
        rbf_signing_info: &RbfSigningInfo,
        cached_leaf_hash: Option<TapLeafHash>,
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

        let tap_sighash_type = rbf_signing_info.tap_sighash_type;

        // Calculate the sighash for this input
        // Extract previous outputs from the PSBT
        let prevouts: Vec<bitcoin::TxOut> = decoded_psbt
            .inputs
            .iter()
            .zip(tx.input.iter())
            .map(|(psbt_input, tx_input)| {
                // Try witness_utxo first (for segwit inputs)
                if let Some(witness_utxo) = psbt_input.witness_utxo.clone() {
                    Ok(witness_utxo)
                } else if let Some(ref non_witness_tx) = psbt_input.non_witness_utxo {
                    // For non-segwit inputs, extract the output from the previous transaction
                    let vout = tx_input.previous_output.vout as usize;
                    non_witness_tx
                        .output
                        .get(vout)
                        .cloned()
                        .ok_or_eyre(format!(
                            "Output index {vout} out of bounds in previous transaction",
                        ))
                        .map_err(SendTxError::Other)
                } else {
                    Err(eyre!(
                        "Neither witness_utxo nor non_witness_utxo found for input"
                    ))
                    .map_err(SendTxError::Other)
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let sighash = match &rbf_signing_info.spend_path {
            RbfSigningSpendPath::KeyPath { .. } => sighash_cache
                .taproot_key_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    tap_sighash_type,
                )
                .map_err(|e| eyre!("Failed to calculate sighash: {}", e))?,
            RbfSigningSpendPath::ScriptPath { .. } => sighash_cache
                .taproot_script_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    match cached_leaf_hash {
                        Some(leaf_hash) => leaf_hash,
                        None => {
                            return Err(eyre!(
                                "Cached leaf hash expected but not found for RBF script spend"
                            )
                            .into())
                        }
                    },
                    tap_sighash_type,
                )
                .map_err(|e| eyre!("Failed to calculate sighash: {}", e))?,
        };

        #[cfg(feature = "testing")]
        let mut sighash = sighash;

        #[cfg(feature = "testing")]
        {
            // these annex code will be deleted in another PR anyway
            use bitcoin::sighash::Annex;
            // This should provide the Sighash for the key spend
            if let Some(ref annex_bytes) = rbf_signing_info.annex {
                if let RbfSigningSpendPath::ScriptPath { .. } = &rbf_signing_info.spend_path {
                    return Err(eyre!("Script path RBF signing with annex not supported").into());
                }
                let annex = Annex::new(annex_bytes).unwrap();
                sighash = sighash_cache
                    .taproot_signature_hash(
                        input_index,
                        &Prevouts::All(&prevouts),
                        Some(annex),
                        None,
                        tap_sighash_type,
                    )
                    .map_err(|e| eyre!("Failed to calculate sighash with annex: {}", e))?;
            }
        }

        // Sign the sighash with our signer
        let tweak_data = match &rbf_signing_info.spend_path {
            RbfSigningSpendPath::KeyPath { tweak_merkle_root } => {
                TapTweakData::KeyPath(*tweak_merkle_root)
            }
            RbfSigningSpendPath::ScriptPath { .. } => TapTweakData::ScriptPath,
        };

        let signature = self
            .signer
            .sign_with_tweak_data(sighash, tweak_data)
            .map_err(|e| eyre!("Failed to sign input: {}", e))?;

        let mut witness = Witness::new();

        match &rbf_signing_info.spend_path {
            RbfSigningSpendPath::KeyPath { .. } => {
                witness.push(signature.serialize());
                // Add the signature to the PSBT
                decoded_psbt.inputs[input_index].tap_key_sig = Some(taproot::Signature {
                    signature,
                    sighash_type: tap_sighash_type,
                });
            }
            RbfSigningSpendPath::ScriptPath {
                control_block,
                script,
            } => {
                witness.push(signature.serialize());
                witness.push(script.clone());
                witness.push(control_block.clone());
            }
        }

        #[cfg(feature = "testing")]
        {
            if let Some(ref annex_bytes) = rbf_signing_info.annex {
                witness.push(annex_bytes);
                tracing::info!("Decoded PSBT: {:?}", decoded_psbt);
            }
        }
        decoded_psbt.inputs[input_index].final_script_witness = Some(witness);
        // Serialize the signed PSBT back to base64
        Ok(decoded_psbt.to_string())
    }

    #[track_caller]
    pub fn handle_err(
        &self,
        err_msg: impl AsRef<str>,
        err_state: impl Into<String>,
        try_to_send_id: u32,
    ) {
        log_error_for_tx!(self.db, try_to_send_id, err_msg.as_ref());

        let err_state = err_state.into();
        let db = self.db.clone();

        tokio::spawn(async move {
            let _ = db
                .update_tx_debug_sending_state(try_to_send_id, &err_state, true)
                .await;
        });
    }

    /// This function verifies that the wallet has added a funding input to the
    /// PSBT.
    ///
    /// This is required for a transaction to be added to the wallet.
    pub fn verify_new_inputs(&self, psbt: &str, original_tx: &Transaction) -> bool {
        let Ok(psbt) = Psbt::from_str(psbt) else {
            tracing::error!("Failed to parse PSBT");
            return false;
        };

        psbt.inputs.len() > original_tx.input.len()
    }

    /// Reorders PSBT outputs so that the original transaction outputs appear first
    /// in the same order, followed by any newly added outputs (e.g., change outputs).
    ///
    /// This is important for watchtower challenge transactions where the OP_RETURN
    /// output is expected to remain at a specific index.
    pub fn reorder_psbt_outputs(&self, psbt: &mut Psbt, original_tx: &Transaction) -> Result<()> {
        if psbt.unsigned_tx.output.len() != psbt.outputs.len() {
            return Err(SendTxError::Other(eyre!(
                "PSBT outputs length mismatch: unsigned_tx outputs={} psbt outputs={}",
                psbt.unsigned_tx.output.len(),
                psbt.outputs.len()
            )));
        }

        let mut used = vec![false; psbt.unsigned_tx.output.len()];
        let mut new_outputs = Vec::with_capacity(psbt.unsigned_tx.output.len());
        let mut new_psbt_outputs = Vec::with_capacity(psbt.outputs.len());

        for original_out in &original_tx.output {
            let mut found_idx = None;
            for (idx, out) in psbt.unsigned_tx.output.iter().enumerate() {
                if !used[idx]
                    && out.value == original_out.value
                    && out.script_pubkey == original_out.script_pubkey
                {
                    found_idx = Some(idx);
                    break;
                }
            }

            let Some(idx) = found_idx else {
                return Err(SendTxError::Other(eyre!(
                    "Failed to find original output in PSBT"
                )));
            };

            used[idx] = true;
            new_outputs.push(psbt.unsigned_tx.output[idx].clone());
            new_psbt_outputs.push(psbt.outputs[idx].clone());
        }

        for (idx, out) in psbt.unsigned_tx.output.iter().enumerate() {
            if !used[idx] {
                new_outputs.push(out.clone());
                new_psbt_outputs.push(psbt.outputs[idx].clone());
            }
        }

        psbt.unsigned_tx.output = new_outputs;
        psbt.outputs = new_psbt_outputs;

        Ok(())
    }

    pub async fn get_tx_fee(&self, tx: &Transaction) -> Result<Amount> {
        let inputs = {
            let mut inputs = Amount::ZERO;
            for inp in &tx.input {
                inputs += self
                    .rpc
                    .get_txout_from_outpoint(&inp.previous_output)
                    .await
                    .map_err(|e| eyre!(e))?
                    .value;
            }
            inputs
        };
        let outputs = tx.output.iter().map(|o| o.value).sum::<Amount>();

        let tx_fee = inputs - outputs;

        Ok(tx_fee)
    }

    /// Sends or bumps a transaction using the Replace-By-Fee (RBF) strategy.
    ///
    /// It interacts with the database to track the latest RBF attempt (`last_rbf_txid`).
    ///
    /// # Logic:
    /// 1.  **Check for Existing RBF Tx:** Retrieves RBF txids for the `try_to_send_id` and
    ///     selects the most recent one still in the mempool.
    /// 2.  **Bump Existing Tx:** If a mempool tx exists, it calls `rpc.psbt_bump_fee`.
    ///     - This internally uses the Bitcoin Core `psbtbumpfee` RPC.
    ///     - We then sign the inputs that we can using our Actor and have the wallet sign the rest.
    ///
    /// 3.  **Send Initial RBF Tx:** If no RBF tx is found in the mempool:
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
    #[tracing::instrument(skip_all, fields(try_to_send_id, tx_meta=?tx_metadata))]
    #[allow(clippy::too_many_arguments)]
    pub async fn send_rbf_tx(
        &self,
        try_to_send_id: u32,
        mut tx: Transaction,
        tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRateKvb,
        rbf_signing_info: Option<RbfSigningInfo>,
        current_tip_height: u32,
        needs_wtxid_grind: bool,
    ) -> Result<()> {
        tracing::debug!(?tx_metadata, "Sending RBF tx",);

        tracing::debug!(?try_to_send_id, "Attempting to send.");

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "preparing_rbf", true)
            .await;

        let rbf_txids = self
            .db
            .list_rbf_txids_for_id(None, try_to_send_id)
            .await
            .wrap_err("Failed to list RBF txids")?;

        // We check all bumps here but technically as wallet bumpfee rpcs do not use unsafe utxos, if the last rbf txid is
        // evicted all should be evicted as well. Only while funding the first rbf tx can unsafe outputs be used.
        let mut bump_from_txid = None;
        for txid in rbf_txids {
            match self.rpc.get_mempool_entry(&txid).await {
                Ok(_) => {
                    bump_from_txid = Some(txid);
                    break;
                }
                Err(e) => {
                    // If not in mempool, either evicted or already confirmed/replaced.
                    if !e.to_string().contains("Transaction not in mempool") {
                        return Err(eyre!("Failed to get mempool entry for {txid}: {e}").into());
                    }

                    if let Ok(tx_info) = self.rpc.get_transaction(&txid, None).await {
                        if tx_info.info.blockhash.is_some() && tx_info.info.confirmations > 0 {
                            tracing::debug!(
                                ?try_to_send_id,
                                "RBF tx {txid} already confirmed, skipping bump"
                            );
                            return Ok(());
                        }
                    }
                }
            }
        }

        // cache the leaf hash for script path spends
        let cached_leaf_hash = match &rbf_signing_info {
            Some(rbf_signing_info) => match &rbf_signing_info.spend_path {
                RbfSigningSpendPath::ScriptPath { script, .. } => Some(TapLeafHash::from_script(
                    ScriptBuf::from_bytes(script.clone()).as_script(),
                    LeafVersion::TapScript,
                )),
                _ => None,
            },
            None => None,
        };

        if let Some(bump_from_txid) = bump_from_txid {
            tracing::debug!(
                ?try_to_send_id,
                "Attempting to bump fee for txid {bump_from_txid} using psbt_bump_fee"
            );

            let effective_feerate = self
                .calculate_bump_feerate_if_needed(&bump_from_txid, fee_rate)
                .await?;

            let Some(effective_feerate) = effective_feerate else {
                tracing::debug!(
                    ?try_to_send_id,
                    "Original tx feerate already higher than target ({} sat/vB), skipping bump",
                    fee_rate.to_sat_per_vb_ceil()
                );
                return Ok(());
            };

            let psbt_bump_opts = BumpFeeOptions {
                conf_target: None, // Use fee_rate instead
                fee_rate: Some(bitcoincore_rpc::json::FeeRate::per_kwu(Amount::from_sat(
                    effective_feerate.to_sat_per_kwu_ceil(),
                ))),
                replaceable: Some(true), // Ensure the bumped tx is also replaceable
                estimate_mode: None,
            };

            let bump_result = self
                .rpc
                .psbt_bump_fee(&bump_from_txid, Some(&psbt_bump_opts))
                .await;

            let mut bumped_psbt = match bump_result {
                Err(e) => {
                    // Check for common errors indicating the tx is already confirmed or spent
                    let rpc_error_str = e.to_string();
                    if rpc_error_str.contains("Transaction already in block chain") {
                        tracing::debug!(
                            ?try_to_send_id,
                            "RBF bump failed for {bump_from_txid}, likely confirmed or spent: {e}"
                        );
                        // No need to return error, just log and proceed
                        return Ok(());
                    } else {
                        // Other potentially transient errors
                        let error_message = format!("psbt_bump_fee failed: {e}");
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
                    self.handle_err(
                        format!("psbt_bump_fee failed: {errors:?}"),
                        "rbf_psbt_bump_failed",
                        try_to_send_id,
                    );
                    return Err(SendTxError::Other(eyre!(errors.join(", "))));
                }
                Ok(BumpFeeResult { psbt: None, .. }) => {
                    self.handle_err(
                        "psbt_bump_fee returned no psbt",
                        "rbf_psbt_bump_failed",
                        try_to_send_id,
                    );
                    return Err(SendTxError::Other(eyre!("psbt_bump_fee returned no psbt")));
                }
            };

            self.fill_in_utxo_info(&mut bumped_psbt)
                .await
                .map_err(|err| {
                    let err = eyre!(err).wrap_err("Failed to fill in utxo info");
                    self.handle_err(
                        format!("{err:?}"),
                        "rbf_fill_in_utxo_info_failed",
                        try_to_send_id,
                    );

                    err
                })?;

            let bumped_psbt = self
                .copy_witnesses(bumped_psbt, &tx)
                .await
                .wrap_err("Failed to fill SAP signatures")?;

            let mut unsigned_psbt = Psbt::from_str(&bumped_psbt).map_err(|e| eyre!(e))?;

            if let Err(err) = self.reorder_psbt_outputs(&mut unsigned_psbt, &tx) {
                let err_msg = format!("Failed to reorder bumped PSBT outputs: {err}");
                self.handle_err(
                    err_msg.clone(),
                    "rbf_psbt_output_reorder_failed",
                    try_to_send_id,
                );
                return Err(err);
            }
            let mut current_locktime = unsigned_psbt.unsigned_tx.lock_time;

            let final_tx = loop {
                unsigned_psbt.unsigned_tx.lock_time = current_locktime;
                let bumped_psbt = unsigned_psbt.to_string();

                // Wallet first pass
                // We rely on the node's wallet here because psbt_bump_fee might add inputs from it.
                let process_result = self
                    .rpc
                    .wallet_process_psbt(&bumped_psbt, Some(true), None, None) // sign=true
                    .await;

                let processed_psbt = match process_result {
                    Ok(res) if res.complete => res.psbt,
                    // attempt to sign
                    Ok(res) => {
                        let Some(rbf_signing_info) = &rbf_signing_info else {
                            return Err(eyre!(
                                "RBF signing info is required for non SighashSingle RBF txs"
                            )
                            .into());
                        };
                        self.attempt_sign_psbt(res.psbt, rbf_signing_info, cached_leaf_hash)
                            .await?
                    }
                    Err(e) => {
                        let err_msg = format!("wallet_process_psbt error: {e}");
                        tracing::warn!(?try_to_send_id, "{}", err_msg);
                        log_error_for_tx!(self.db, try_to_send_id, err_msg);
                        let _ = self
                            .db
                            .update_tx_debug_sending_state(
                                try_to_send_id,
                                "rbf_psbt_sign_failed",
                                true,
                            )
                            .await;
                        return Err(SendTxError::Other(eyre!(e)));
                    }
                };

                let final_tx = {
                    // Extract tx
                    let psbt = Psbt::from_str(&processed_psbt)
                        .map_err(|e| eyre!(e))
                        .map_err(|err| {
                            let err = eyre!(err).wrap_err("Failed to deserialize initial RBF PSBT");
                            self.handle_err(
                                format!("{err:?}"),
                                "rbf_psbt_deserialize_failed",
                                try_to_send_id,
                            );
                            err
                        })?;

                    let mut tx = psbt.unsigned_tx.clone();

                    for (idx, input) in tx.input.iter_mut().enumerate() {
                        if let Some(witness) = psbt.inputs[idx].final_script_witness.clone() {
                            input.witness = witness;
                        }
                        if let Some(sig) = psbt.inputs[idx].final_script_sig.clone() {
                            input.script_sig = sig;
                        }
                    }

                    tx
                };
                if !needs_wtxid_grind
                    || final_tx
                        .compute_wtxid()
                        .as_raw_hash()
                        .to_byte_array()
                        .starts_with(REVEAL_TX_PREFIX)
                {
                    break final_tx;
                } else {
                    current_locktime = LockTime::from_consensus(std::cmp::max(
                        current_locktime.to_consensus_u32() + 1,
                        LOCK_TIME_THRESHOLD,
                    ));
                }
            };

            let bumped_txid = final_tx.compute_txid();

            // Broadcast the finalized transaction
            let sent_txid = match self.rpc.send_raw_transaction(&final_tx).await {
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
                "RBF tx {bump_from_txid} successfully bumped and sent as {sent_txid}"
            );

            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "rbf_bumped_sent", true)
                .await;

            self.db
                .save_rbf_txid(None, try_to_send_id, sent_txid)
                .await
                .wrap_err("Failed to save new RBF txid after bump")?;

            // Save the effective fee rate to the db
            self.db
                .update_effective_fee_rate(
                    None,
                    try_to_send_id,
                    effective_feerate,
                    current_tip_height,
                )
                .await
                .wrap_err("Failed to update effective fee rate")?;
        } else {
            tracing::debug!(
                ?try_to_send_id,
                "Funding initial RBF tx using PSBT workflow"
            );

            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "creating_initial_rbf_psbt", true)
                .await;

            // for accurate fee calculation, fill in the witness with dummy data if its empty
            if let Some(rbf_signing_info) = &rbf_signing_info {
                let vout = rbf_signing_info.vout as usize;
                let input_count = tx.input.len();
                let input = tx.input.get_mut(vout).ok_or_else(|| {
                    SendTxError::from(eyre!(
                        "Input at vout {} given in RBF signing info does not exist in transaction (has {} inputs)",
                        vout,
                        input_count
                    ))
                })?;
                if input.witness.is_empty() {
                    match &rbf_signing_info.spend_path {
                        RbfSigningSpendPath::KeyPath { .. } => {
                            input.witness = Witness::from_slice(&[&[0u8; 65]]);
                        }
                        RbfSigningSpendPath::ScriptPath {
                            script,
                            control_block,
                        } => {
                            let mut witness = Witness::new();
                            witness.push([0u8; 65]);
                            witness.push(script.clone());
                            witness.push(control_block.clone());
                            input.witness = witness;
                        }
                    }
                }
            }

            let mut added_dummy_output = false;
            // if the tx has no outputs, btc core wallet fund transaction will fail, so we add a dummy output
            // which we will remove later to save on fees.
            if tx.output.is_empty() {
                tx.output.push(TxOut {
                    value: NON_EPHEMERAL_ANCHOR_AMOUNT,
                    script_pubkey: ScriptBuf::from_hex("51024e73").expect("valid anchor script"),
                });
                added_dummy_output = true;
            }

            let create_result = self
                .create_funded_psbt(&tx, fee_rate)
                .await
                .map_err(|err| {
                    let err = eyre!(err).wrap_err("Failed to create funded PSBT");
                    self.handle_err(format!("{err:?}"), "rbf_psbt_create_failed", try_to_send_id);

                    err
                })?;

            if !self.verify_new_inputs(&create_result.psbt, &tx) {
                tracing::warn!(
                    ?try_to_send_id,
                    "Transaction has not been funded and is being sent as is. This transaction will have to be manually bumped as the wallet will not add it to itself."
                );
            }
            let mut funded_psbt_str = create_result.psbt;

            self.fill_in_utxo_info(&mut funded_psbt_str)
                .await
                .map_err(|err| {
                    let err = eyre!(err).wrap_err("Failed to fill in utxo info");
                    self.handle_err(
                        format!("{err:?}"),
                        "rbf_fill_in_utxo_info_failed",
                        try_to_send_id,
                    );

                    err
                })?;

            funded_psbt_str = self
                .copy_witnesses(funded_psbt_str, &tx)
                .await
                .map_err(|err| {
                    let err = eyre!(err).wrap_err("Failed to copy witnesses");
                    self.handle_err(
                        format!("{err:?}"),
                        "rbf_copy_witnesses_failed",
                        try_to_send_id,
                    );

                    err
                })?;

            let mut funded_psbt = Psbt::from_str(&funded_psbt_str).map_err(|e| eyre!(e))?;
            if added_dummy_output {
                // we delete the first output which is the dummy output we added earlier
                // we also adjust the amount of the change output to compensate for removal of the dummy output.
                let dummy_output_weight = funded_psbt.unsigned_tx.output[0].weight();
                let dummy_output_value = funded_psbt.unsigned_tx.output[0].value;
                let needed_fee_for_dummy_output = fee_rate.fee_wu(dummy_output_weight).ok_or_eyre(format!("Fee overflow occurred for dummy output: current fee rate: {fee_rate}, dummy_output_weight: {dummy_output_weight}"))?;
                funded_psbt.unsigned_tx.output.remove(0);
                funded_psbt.outputs.remove(0);
                funded_psbt
                    .unsigned_tx
                    .output
                    .last_mut()
                    .expect("Change output should exist")
                    .value += needed_fee_for_dummy_output + dummy_output_value;
            } else if let Err(err) = self.reorder_psbt_outputs(&mut funded_psbt, &tx) {
                // fund transaction shouldn't reorder but keep it here in case it does
                let err_msg = format!("Failed to reorder initial PSBT outputs: {err}");
                self.handle_err(
                    err_msg.clone(),
                    "rbf_psbt_output_reorder_failed",
                    try_to_send_id,
                );
                return Err(err);
            }
            let mut current_locktime = tx.lock_time;

            let final_tx = loop {
                // replace locktime and version
                funded_psbt.unsigned_tx.lock_time = current_locktime;
                funded_psbt.unsigned_tx.version = tx.version;

                tracing::debug!(
                    try_to_send_id,
                    "Successfully created initial RBF PSBT with fee {}",
                    create_result.fee
                );

                let mut psbt = funded_psbt.to_string();

                // 2. Process the PSBT (let the wallet sign its inputs)
                let process_result = self
                    .rpc
                    .wallet_process_psbt(&psbt, Some(true), None, None)
                    .await
                    .map_err(|err| {
                        let err = eyre!(err).wrap_err("Failed to process initial RBF PSBT");
                        self.handle_err(
                            format!("{err:?}"),
                            "rbf_psbt_process_failed",
                            try_to_send_id,
                        );

                        err
                    })?;

                if let Some(rbf_signing_info) = &rbf_signing_info {
                    psbt = self
                        .attempt_sign_psbt(process_result.psbt, rbf_signing_info, cached_leaf_hash)
                        .await
                        .map_err(|err| {
                            let err = eyre!(err).wrap_err("Failed to sign initial RBF PSBT");
                            self.handle_err(
                                format!("{err:?}"),
                                "rbf_psbt_sign_failed",
                                try_to_send_id,
                            );

                            err
                        })?;
                } else {
                    psbt = process_result.psbt;
                }

                tracing::debug!(try_to_send_id, "Successfully processed initial RBF PSBT");

                let final_tx = {
                    // Extract tx
                    let psbt = Psbt::from_str(&psbt).map_err(|e| eyre!(e)).map_err(|err| {
                        let err = eyre!(err).wrap_err("Failed to deserialize initial RBF PSBT");
                        self.handle_err(
                            format!("{err:?}"),
                            "rbf_psbt_deserialize_failed",
                            try_to_send_id,
                        );
                        err
                    })?;

                    let mut tx = psbt.unsigned_tx.clone();

                    for (idx, input) in tx.input.iter_mut().enumerate() {
                        if let Some(witness) = psbt.inputs[idx].final_script_witness.clone() {
                            input.witness = witness;
                        }
                        if let Some(sig) = psbt.inputs[idx].final_script_sig.clone() {
                            input.script_sig = sig;
                        }
                    }

                    tx
                };
                // check if wtxid prefix is correct if grinding is needed
                if !needs_wtxid_grind
                    || final_tx
                        .compute_wtxid()
                        .as_raw_hash()
                        .to_byte_array()
                        .starts_with(REVEAL_TX_PREFIX)
                {
                    break final_tx;
                } else {
                    // increase locktime by 1 time unit
                    current_locktime = LockTime::from_consensus(std::cmp::max(
                        current_locktime.to_consensus_u32() + 1,
                        LOCK_TIME_THRESHOLD,
                    ));
                }
            };

            let initial_txid = final_tx.compute_txid();

            // 4. Broadcast the finalized transaction
            let sent_txid = match self.rpc.send_raw_transaction(&final_tx).await {
                Ok(sent_txid) => {
                    if sent_txid != initial_txid {
                        let err_msg = format!(
                            "send_raw_transaction returned unexpected txid {sent_txid} (expected {initial_txid}) for initial RBF",
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
                        "Successfully sent initial RBF tx with txid {sent_txid}"
                    );
                    sent_txid
                }
                Err(e) => {
                    tracing::error!("RBF failed for: {:?}", final_tx);
                    let err_msg = format!("send_raw_transaction error for initial RBF tx: {e}");
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
                .save_rbf_txid(None, try_to_send_id, sent_txid)
                .await
                .wrap_err("Failed to save initial RBF txid")?;

            // Save the effective fee rate to the db
            self.db
                .update_effective_fee_rate(None, try_to_send_id, fee_rate, current_tip_height)
                .await
                .wrap_err("Failed to update effective fee rate")?;
        }

        Ok(())
    }
}
