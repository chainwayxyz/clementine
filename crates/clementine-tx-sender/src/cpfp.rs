//! # Child Pays For Parent (CPFP) Support For Transaction Sender
//!
//! This module implements the Child Pays For Parent (CPFP) strategy for sending
//! Bitcoin transactions with transaction sender.
//!
//! ## Child Transaction Details
//!
//! A child transaction is created to pay for the fees of a parent transaction.
//! They must be submitted together as a package for Bitcoin nodes to accept
//! them.
//!
//! ### Fee Payer Transactions/UTXOs
//!
//! Child transaction needs to spend an UTXO for the fees. But because of the
//! TRUC rules (https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki#specification),
//! a third transaction can't be put into the package. So, a so called "fee
//! payer" transaction must be send and confirmed before the CPFP package is
//! send.

use super::Result;
use crate::{SpendableInputInfo, TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, FeeRate, OutPoint, Transaction, TxOut, Weight};
use bitcoincore_rpc::json::FundRawTransactionOptions;
use bitcoincore_rpc::{PackageTransactionResult, RpcApi};
use clementine_errors::{BridgeError, ResultExt as _, SendTxError};
use clementine_primitives::MIN_TAPROOT_AMOUNT;
use clementine_utils::{FeePayingType, TxMetadata};
use eyre::{eyre, Context};
use std::collections::HashSet;
use std::env;

impl<S, D, B> TxSender<S, D, B>
where
    S: TxSenderSigner,
    D: TxSenderDatabase,
    B: TxSenderTxBuilder,
{
    /// Creates and broadcasts a new "fee payer" UTXO to be used for CPFP
    /// transactions.
    ///
    /// This function is called when a CPFP attempt fails due to insufficient funds
    /// in the existing confirmed fee payer UTXOs associated with a transaction (`bumped_id`).
    /// It calculates the required fee based on the parent transaction (`tx`) and the current
    /// `fee_rate`, adding a buffer (2x required fee + dust limit) to handle potential fee spikes.
    /// It then sends funds to the `TxSender`'s own signer address using the RPC's
    /// `send_to_address` and saves the resulting UTXO information (`outpoint`, `amount`)
    /// to the database, linking it to the `bumped_id`.
    ///
    /// # Arguments
    /// * `bumped_id` - The database ID of the parent transaction requiring the fee bump.
    /// * `tx` - The parent transaction itself.
    /// * `fee_rate` - The target fee rate for the CPFP package.
    /// * `total_fee_payer_amount` - The sum of amounts in currently available confirmed fee payer UTXOs.
    /// * `fee_payer_utxos_len` - The number of currently available confirmed fee payer UTXOs.
    async fn create_fee_payer_utxo(
        &self,
        bumped_id: u32,
        dbtx: Option<&mut D::Transaction>,
        tx: &Transaction,
        fee_rate: FeeRate,
        total_fee_payer_amount: Amount,
        fee_payer_utxos_len: usize,
    ) -> Result<()> {
        tracing::debug!(
            "Creating fee payer UTXO for txid {} with bump id {}",
            &tx.compute_txid().to_string(),
            bumped_id
        );
        let required_fee = Self::calculate_required_fee(
            tx.weight(),
            fee_payer_utxos_len + 1,
            fee_rate,
            FeePayingType::CPFP,
        )?;

        // Aggressively add 2x required fee to the total amount to account for sudden spikes
        // We won't actually use 2x fees, but the fee payer utxo will hold that much amount so that while fee payer utxo gets mined
        // if fees increase the utxo should still be sufficient to fund the tx with high probability
        // leftover fees will get sent back to wallet with a change output in fn create_child_tx
        let new_total_fee_needed = required_fee
            .checked_mul(2)
            .and_then(|fee| fee.checked_add(MIN_TAPROOT_AMOUNT));
        if new_total_fee_needed.is_none() {
            return Err(eyre!("Total fee needed is too large, required fee: {}, total fee payer amount: {}, fee rate: {}", required_fee, total_fee_payer_amount, fee_rate).into());
        }
        let new_fee_payer_amount =
            new_total_fee_needed.and_then(|fee| fee.checked_sub(total_fee_payer_amount));

        let new_fee_payer_amount = match new_fee_payer_amount {
            Some(fee) => fee,
            // if underflow, no new fee payer utxo is needed, log it anyway in case its a bug
            None => {
                tracing::debug!("create_fee_payer_utxo was called but no new fee payer utxo is needed for tx: {:?}, required fee: {}, total fee payer amount: {}, current fee rate: {}", tx, required_fee, total_fee_payer_amount, fee_rate);
                return Ok(());
            }
        };

        tracing::debug!(
            "Creating fee payer UTXO with amount {} ({} sat/vb)",
            new_fee_payer_amount,
            fee_rate
        );

        let fee_payer_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: new_fee_payer_amount,
                script_pubkey: self.signer.address().script_pubkey(),
            }],
        };

        // Manually serialize in legacy format for 0-input transactions
        // Because fund_raw_transaction RPC gives deserialization error for 0-input transactions with segwit flag
        // but in the end fund_raw_transaction returns a segwit transaction after adding inputs
        let fee_payer_bytes = if fee_payer_tx.input.is_empty() {
            use bitcoin::consensus::Encodable;
            let mut buf = Vec::new();
            // Serialize version
            fee_payer_tx
                .version
                .consensus_encode(&mut buf)
                .expect("Failed to serialize version");
            fee_payer_tx
                .input
                .consensus_encode(&mut buf)
                .expect("Failed to serialize inputs");
            fee_payer_tx
                .output
                .consensus_encode(&mut buf)
                .expect("Failed to serialize outputs");
            // Serialize locktime
            fee_payer_tx
                .lock_time
                .consensus_encode(&mut buf)
                .expect("Failed to serialize locktime");

            buf
        } else {
            bitcoin::consensus::encode::serialize(&fee_payer_tx)
        };

        let funded_fee_payer_tx = self
            .rpc
            .fund_raw_transaction(
                &fee_payer_bytes,
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
            .wrap_err("Failed to fund cpfp fee payer tx")?
            .hex;

        let signed_fee_payer_tx: Transaction = bitcoin::consensus::deserialize(
            &self
                .rpc
                .sign_raw_transaction_with_wallet(&funded_fee_payer_tx, None, None)
                .await
                .wrap_err("Failed to sign funded tx through bitcoin RPC")?
                .hex,
        )
        .wrap_err("Failed to deserialize signed tx")?;

        let outpoint_vout = signed_fee_payer_tx
            .output
            .iter()
            .position(|o| {
                o.value == new_fee_payer_amount
                    && o.script_pubkey == self.signer.address().script_pubkey()
            })
            .ok_or(eyre!("Failed to find outpoint vout"))?;

        self.rpc
            .send_raw_transaction(&signed_fee_payer_tx)
            .await
            .wrap_err("Failed to send signed fee payer tx")?;

        self.db
            .save_fee_payer_tx(
                dbtx,
                None,
                bumped_id,
                signed_fee_payer_tx.compute_txid(),
                outpoint_vout as u32,
                new_fee_payer_amount,
                None,
            )
            .await
            .map_to_eyre()?;

        Ok(())
    }

    /// Creates a Child-Pays-For-Parent (CPFP) child transaction.
    ///
    /// This transaction spends:
    /// 1.  The designated "P2A anchor" output of the parent transaction (`p2a_anchor`).
    /// 2.  One or more confirmed "fee payer" UTXOs (`fee_payer_utxos`) controlled by the `signer`.
    ///
    /// It calculates the total fee required (`required_fee`) to make the combined parent + child
    /// package attractive to miners at the target `fee_rate`. The `required_fee` is paid entirely
    /// by this child transaction.
    ///
    /// The remaining value (total input value - `required_fee`) is sent to the `change_address`.
    ///
    /// # Signing
    /// We sign the input spending the P2A anchor and all fee payer UTXOs.
    ///
    /// # Returns
    /// The constructed and partially signed child transaction.
    async fn create_child_tx(
        &self,
        p2a_anchor: OutPoint,
        anchor_sat: Amount,
        fee_payer_utxos: Vec<B::SpendableInput>,
        parent_tx_size: Weight,
        fee_rate: FeeRate,
    ) -> Result<Transaction> {
        let required_fee = Self::calculate_required_fee(
            parent_tx_size,
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::CPFP,
        )?;

        let change_address = self
            .rpc
            .get_new_address(None, None)
            .await
            .wrap_err("Failed to get new wallet address")?
            .assume_checked();

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + anchor_sat;

        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        // Delegate to the TxBuilder's static method
        B::build_child_tx(
            p2a_anchor,
            anchor_sat,
            fee_payer_utxos,
            change_address,
            required_fee,
            &self.signer,
        )
        .map_err(|e| SendTxError::Other(e.into()))
    }

    /// Creates a transaction package for CPFP submission.
    ///
    /// Finds the P2A anchor output in the parent transaction (`tx`), then constructs
    /// the child transaction using `create_child_tx`.
    ///
    /// # Returns
    ///
    /// - [`Vec<Transaction>`]: Parent transaction followed by the child
    ///   transaction ready for submission via the `submitpackage` RPC.
    async fn create_package(
        &self,
        tx: Transaction,
        fee_rate: FeeRate,
        fee_payer_utxos: Vec<B::SpendableInput>,
    ) -> Result<Vec<Transaction>> {
        let txid = tx.compute_txid();
        let p2a_vout = self
            .find_p2a_vout(&tx)
            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
        let anchor_sat = tx.output[p2a_vout].value;

        let child_tx = self
            .create_child_tx(
                OutPoint {
                    txid,
                    vout: p2a_vout as u32,
                },
                anchor_sat,
                fee_payer_utxos,
                tx.weight(),
                fee_rate,
            )
            .await?;

        Ok(vec![tx, child_tx])
    }

    async fn get_confirmed_fee_payer_utxos(
        &self,
        try_to_send_id: u32,
    ) -> Result<Vec<B::SpendableInput>> {
        let utxos = self
            .db
            .get_confirmed_fee_payer_utxos(None, try_to_send_id)
            .await
            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
        Ok(B::utxos_to_spendable_inputs(utxos, self.signer.address()))
    }

    pub async fn bump_fees_of_unconfirmed_fee_payer_txs(&self, fee_rate: FeeRate) -> Result<()> {
        let bumpable_txs = self
            .db
            .get_all_unconfirmed_fee_payer_txs(None)
            .await
            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
        let mut not_evicted_ids = HashSet::new();
        let mut all_parent_ids = HashSet::new();

        for (id, try_to_send_id, txid, vout, amount, replacement_of_id) in bumpable_txs {
            let parent_id = replacement_of_id.unwrap_or(id);
            all_parent_ids.insert(parent_id);

            match self.rpc.get_mempool_entry(&txid).await {
                Ok(info) => {
                    not_evicted_ids.insert(parent_id);
                    if info.descendant_count > 1
                        || std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            .saturating_sub(info.time)
                            < self.tx_sender_limits.cpfp_fee_payer_bump_wait_time_seconds
                    {
                        continue;
                    }
                }
                Err(e) => {
                    if !e.to_string().contains("Transaction not in mempool") {
                        return Err(eyre!("Failed to get mempool entry for {txid}: {e}").into());
                    }
                    if let Ok(tx_info) = self.rpc.get_transaction(&txid, None).await {
                        if tx_info.info.blockhash.is_some() && tx_info.info.confirmations > 0 {
                            not_evicted_ids.insert(parent_id);
                        }
                    }
                    continue;
                }
            }

            if let Ok(new_txid) = self.rpc.bump_fee_with_fee_rate(txid, fee_rate).await {
                if new_txid != txid {
                    self.db
                        .save_fee_payer_tx(
                            None,
                            Some(try_to_send_id),
                            0, /* bumped_id not used here? */
                            new_txid,
                            vout,
                            amount,
                            Some(parent_id),
                        )
                        .await
                        .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
                }
            }
        }

        for parent_id in all_parent_ids {
            if !not_evicted_ids.contains(&parent_id) {
                self.db
                    .mark_fee_payer_utxo_as_evicted(None, parent_id)
                    .await
                    .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
            }
        }
        Ok(())
    }

    pub async fn send_cpfp_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        _tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<()> {
        let unconfirmed = self
            .db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await
            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
        if !unconfirmed.is_empty() {
            // Log that we're waiting for unconfirmed UTXOs
            tracing::debug!(
                try_to_send_id,
                "Waiting for {} UTXOs to confirm",
                unconfirmed.len()
            );

            let _ = self
                .db
                .update_tx_debug_sending_state(
                    try_to_send_id,
                    "waiting_for_utxo_confirmation",
                    true,
                )
                .await;
            return Ok(());
        }

        let confirmed = self.get_confirmed_fee_payer_utxos(try_to_send_id).await?;
        let total_amount: Amount = confirmed.iter().map(|u| u.get_prevout().value).sum();

        let package = match self
            .create_package(tx.clone(), fee_rate, confirmed.clone())
            .await
        {
            Ok(p) => p,
            Err(SendTxError::InsufficientFeePayerAmount) => {
                self.create_fee_payer_utxo(
                    try_to_send_id,
                    None,
                    &tx,
                    fee_rate,
                    total_amount,
                    confirmed.len(),
                )
                .await?;
                let _ = self
                    .db
                    .update_tx_debug_sending_state(
                        try_to_send_id,
                        "waiting_for_fee_payer_utxos",
                        true,
                    )
                    .await;
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let package_refs: Vec<&Transaction> = package.iter().collect();

        // Save the effective fee rate before attempting to send
        // This ensures that even if the send fails, we track the attempt
        // so the 10-block stuck logic can trigger a bump
        self.db
            .update_effective_fee_rate(None, try_to_send_id, fee_rate, current_tip_height)
            .await
            .wrap_err("Failed to update effective fee rate")?;

        tracing::debug!(
            try_to_send_id,
            "Submitting package\n Pkg tx hexs: {:?}",
            if env::var("DBG_PACKAGE_HEX").is_ok() {
                package
                    .iter()
                    .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                    .collect::<Vec<_>>()
            } else {
                vec!["use DBG_PACKAGE_HEX=1 to print the package as hex".into()]
            }
        );

        // Update sending state to submitting_package
        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "submitting_package", true)
            .await;

        let submit_result = self
            .rpc
            .submit_package(&package_refs, Some(Amount::ZERO), None)
            .await
            .wrap_err("Failed to submit package")?;

        // If tx_results is empty, it means the txs were already accepted by the network.
        if submit_result.tx_results.is_empty() {
            return Ok(());
        }

        for (_txid, result) in submit_result.tx_results {
            if let PackageTransactionResult::Failure { error, .. } = result {
                tracing::error!(try_to_send_id, "Error submitting package: {:?}", error);
                return Ok(());
            }
        }

        Ok(())
    }
}
