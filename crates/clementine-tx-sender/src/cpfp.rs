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
use crate::{log_error_for_tx, TxSender, TxSenderTransaction};
use bitcoin::absolute::LockTime;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Weight};
use bitcoin::{TapSighashType, Witness};
use bitcoincore_rpc::json::FundRawTransactionOptions;
use bitcoincore_rpc::{PackageTransactionResult, RpcApi};
use clementine_errors::{BitcoinRPCError, BridgeError, ResultExt as _, SendTxError};
use clementine_primitives::FeeRateKvb;
use clementine_primitives::{MIN_TAPROOT_AMOUNT, NON_STANDARD_V3};
use clementine_utils::{FeePayingType, TxMetadata};
use eyre::{eyre, Context};
use std::collections::HashSet;
use std::env;

impl TxSender {
    fn anchor_prevout(anchor_sat: Amount) -> TxOut {
        // P2A anchor script: OP_1 OP_PUSHBYTES_2 0x4e73
        TxOut {
            value: anchor_sat,
            script_pubkey: ScriptBuf::from_hex("51024e73").expect("statically valid anchor script"),
        }
    }

    fn build_and_sign_child_tx(
        &self,
        p2a_anchor: OutPoint,
        anchor_sat: Amount,
        fee_payer_utxos: Vec<crate::SpendableUtxo>,
        change_address: bitcoin::Address,
        required_fee: Amount,
    ) -> Result<Transaction> {
        let total_in: Amount = fee_payer_utxos
            .iter()
            .map(|u| u.txout.value)
            .sum::<Amount>()
            + anchor_sat;

        let change_amount = total_in
            .checked_sub(required_fee)
            .ok_or_else(|| SendTxError::Other(eyre!("required_fee > total_in")))?;

        let mut inputs: Vec<TxIn> = Vec::with_capacity(1 + fee_payer_utxos.len());
        inputs.push(TxIn {
            previous_output: p2a_anchor,
            script_sig: ScriptBuf::new(),
            sequence: crate::DEFAULT_SEQUENCE,
            witness: Witness::new(),
        });

        for utxo in &fee_payer_utxos {
            inputs.push(TxIn {
                previous_output: utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: crate::DEFAULT_SEQUENCE,
                witness: Witness::new(),
            });
        }

        let mut child_tx = Transaction {
            version: NON_STANDARD_V3,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: vec![TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            }],
        };

        // Prevouts must match the tx input order (anchor first).
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(child_tx.input.len());
        prevouts.push(Self::anchor_prevout(anchor_sat));
        prevouts.extend(fee_payer_utxos.into_iter().map(|u| u.txout));

        // Compute witnesses without mutating tx while the sighash cache borrows it.
        let mut cache = SighashCache::new(&child_tx);
        let mut signed_witnesses: Vec<(usize, Witness)> = Vec::new();

        for input_index in 1..child_tx.input.len() {
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .map_err(|e| SendTxError::Other(eyre!("failed to compute sighash: {e}")))?;

            let signature = self
                .signer
                .sign_with_tweak_data(sighash, clementine_utils::sign::TapTweakData::KeyPath(None))
                .map_err(|e| SendTxError::Other(e.into()))?;

            let tr_sig = taproot::Signature {
                signature,
                sighash_type: TapSighashType::Default,
            };
            signed_witnesses.push((input_index, Witness::p2tr_key_spend(&tr_sig)));
        }

        for (idx, witness) in signed_witnesses {
            child_tx.input[idx].witness = witness;
        }

        Ok(child_tx)
    }

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
        dbtx: Option<&mut TxSenderTransaction>,
        tx: &Transaction,
        fee_rate: FeeRateKvb,
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
            "Creating fee payer UTXO with amount {} ({} sat/kvB)",
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

        let fee_payer_bytes = crate::serialize_tx_for_fund_raw(&fee_payer_tx);

        let funded_fee_payer_tx = self
            .rpc
            .fund_raw_transaction(
                &fee_payer_bytes,
                Some(&FundRawTransactionOptions {
                    add_inputs: Some(true),
                    // for cpfp txs, the speed of tx inclusion is not that important, so we can not use unsafe utxos and wait for them to become safe. Also all cpfp fee payer tx's are safe (all wallet owned inputs), so wallet can already chain them
                    include_unsafe: Some(self.include_unsafe),
                    change_address: None,
                    change_position: None,
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
        fee_payer_utxos: Vec<crate::SpendableUtxo>,
        parent_tx_size: Weight,
        fee_rate: FeeRateKvb,
    ) -> Result<Transaction> {
        let required_fee = Self::calculate_required_fee(
            parent_tx_size,
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::CPFP,
        )?;

        let change_address = self
            .rpc
            .get_new_wallet_address()
            .await
            .wrap_err("Failed to get new wallet address")?;

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.txout.value)
            .sum::<Amount>()
            + anchor_sat;

        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        self.build_and_sign_child_tx(
            p2a_anchor,
            anchor_sat,
            fee_payer_utxos,
            change_address,
            required_fee,
        )
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
        fee_rate: FeeRateKvb,
        fee_payer_utxos: Vec<crate::SpendableUtxo>,
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

    /// Retrieves confirmed fee payer UTXOs associated with a specific send attempt.
    ///
    /// Queries the database for UTXOs linked to `try_to_send_id` that are marked as confirmed.
    /// These UTXOs are controlled by the `TxSender`'s `signer` and are intended to be
    /// spent by a CPFP child transaction.
    ///
    /// # Returns
    ///
    /// - [`Vec<B::SpendableInput>`]: [`B::SpendableInput`]s of the confirmed fee payer
    ///   UTXOs that are ready to be included as inputs in the CPFP child tx.
    async fn get_confirmed_fee_payer_utxos(
        &self,
        try_to_send_id: u32,
    ) -> Result<Vec<crate::SpendableUtxo>> {
        let utxos = self
            .db
            .get_confirmed_fee_payer_utxos(None, try_to_send_id)
            .await
            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;

        let mut spendables = Vec::with_capacity(utxos.len());

        for (txid, vout, _db_amount) in utxos {
            let utxo = self
                .rpc
                .get_tx_out(&txid, vout, Some(false))
                .await
                .wrap_err("Failed to gettxout for fee payer utxo")?;

            let Some(utxo) = utxo else {
                // We expected this to be a confirmed, spendable fee payer UTXO, but it is no
                // longer unspent (spent/reorg/evicted). Do not mutate DB here; bubble up.
                return Err(SendTxError::Other(eyre!(
                    "Confirmed fee payer UTXO missing from gettxout: {txid}:{vout}"
                )));
            };

            let script_pubkey = utxo
                .script_pub_key
                .script()
                .wrap_err("Failed to parse script pubkey from gettxout")?;

            spendables.push(crate::SpendableUtxo {
                outpoint: OutPoint { txid, vout },
                txout: TxOut {
                    value: utxo.value,
                    script_pubkey,
                },
                spend_info: None,
            });
        }

        Ok(spendables)
    }

    /// Attempts to bump the fees of unconfirmed "fee payer" UTXOs using RBF.
    ///
    /// Fee payer UTXOs are created to fund CPFP child transactions. However, these
    /// fee payer creation transactions might themselves get stuck due to low fees.
    /// This function identifies such unconfirmed fee payer transactions associated with
    /// a parent transaction (`bumped_id`) and attempts to RBF them using the provided `fee_rate`.
    ///
    /// This ensures the fee payer UTXOs confirm quickly, making them available to be spent
    /// by the actual CPFP child transaction.
    ///
    /// # Arguments
    /// * `fee_rate` - The target fee rate for bumping the fee payer transactions.
    #[tracing::instrument(skip_all, fields(fee_rate))]
    pub async fn bump_fees_of_unconfirmed_fee_payer_txs(&self, fee_rate: FeeRateKvb) -> Result<()> {
        let bumpable_txs = self
            .db
            .get_all_unconfirmed_fee_payer_txs(None)
            .await
            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
        let mut not_evicted_ids = HashSet::new();
        let mut all_parent_ids = HashSet::new();

        for (id, try_to_send_id, fee_payer_txid, vout, amount, replacement_of_id) in bumpable_txs {
            tracing::debug!(
                "Bumping fee for fee payer tx {} for try to send id {} for fee rate {}",
                fee_payer_txid,
                try_to_send_id,
                fee_rate
            );
            let parent_id = replacement_of_id.unwrap_or(id);
            all_parent_ids.insert(parent_id);

            match self.rpc.get_mempool_entry(&fee_payer_txid).await {
                Ok(info) => {
                    not_evicted_ids.insert(parent_id);
                    // if it has descendants, it cannot be bumped, or if it was bumped recently, we should not bump it again
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
                    // If not in mempool we should ignore, it was either evicted or replaced by a bumped feepayer tx
                    // give an error if the error is not "Transaction not in mempool"
                    if !e.to_string().contains("Transaction not in mempool") {
                        return Err(
                            eyre!("Failed to get mempool entry for {fee_payer_txid}: {e}").into(),
                        );
                    }
                    // get_transaction only returns if tx is wallet owned, it should not be an issue here as if it is not wallet owned,
                    // for example if wallet was changed and txsender restarted, it cannot be bumped anyway
                    if let Ok(tx_info) = self.rpc.get_transaction(&fee_payer_txid, None).await {
                        if tx_info.info.blockhash.is_some() && tx_info.info.confirmations > 0 {
                            not_evicted_ids.insert(parent_id);
                        }
                    }
                    continue;
                }
            }

            match self
                .rpc
                .bump_fee_with_fee_rate(fee_payer_txid, fee_rate)
                .await
            {
                Ok(new_txid) => {
                    if new_txid != fee_payer_txid {
                        self.db
                            .save_fee_payer_tx(
                                None,
                                try_to_send_id,
                                new_txid,
                                vout,
                                amount,
                                Some(parent_id),
                            )
                            .await
                            .map_err(|e: BridgeError| SendTxError::Other(e.into()))?;
                    } else {
                        tracing::trace!(
                            "Fee payer tx {} has enough fee, no need to bump",
                            fee_payer_txid
                        );
                    }
                }
                Err(e) => match e {
                    BitcoinRPCError::TransactionAlreadyInBlock(block_hash) => {
                        tracing::debug!(
                            "Fee payer tx {} is already in block {}, skipping",
                            fee_payer_txid,
                            block_hash
                        );
                        continue;
                    }
                    BitcoinRPCError::BumpFeeUTXOSpent(outpoint) => {
                        tracing::debug!(
                            "Fee payer tx {} is already onchain, skipping: {:?}",
                            fee_payer_txid,
                            outpoint
                        );
                        continue;
                    }
                    _ => {
                        tracing::warn!(
                            "Failed to bump fee the fee payer tx {} with error {e}, skipping",
                            fee_payer_txid
                        );
                        continue;
                    }
                },
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

    /// Sends a transaction using the Child-Pays-For-Parent (CPFP) strategy.
    ///
    /// # Logic:
    /// 1.  **Check Unconfirmed Fee Payers:** Ensures no unconfirmed fee payer UTXOs exist
    ///     for this `try_to_send_id`. If they do, skips this transaction for now
    ///     as they need to confirm before being spendable by the child.
    /// 2.  **Get Confirmed Fee Payers:** Retrieves the available confirmed fee payer UTXOs.
    /// 3.  **Create Package:** Calls `create_package` to build the `vec![parent_tx, child_tx]`.
    ///     The `child_tx` spends the parent's anchor output and the fee payer UTXOs, paying
    ///     a fee calculated for the whole package.
    /// 4.  **Test Mempool Accept (Not implemented right now as testmempoolaccept didn't support TRUC package submission #1011):**
    ///     Uses `testmempoolaccept` RPC to check if the package is likely to be accepted by the network before submitting.
    /// 5.  **Submit Package:** Uses the `submitpackage` RPC to atomically submit the parent
    ///     and child transactions. Bitcoin Core evaluates the fee rate of the package together.
    /// 6.  **Handle Results:** Checks the `submitpackage` result. If successful or already in
    ///     mempool, updates the effective fee rate in the database. If failed, logs an error.
    ///
    /// # Arguments
    /// * `try_to_send_id` - The database ID tracking this send attempt.
    /// * `tx` - The parent transaction requiring the fee bump.
    /// * `tx_metadata` - Optional metadata associated with the transaction.
    /// * `fee_rate` - The target fee rate for the CPFP package.
    /// * `current_tip_height` - The current height of the tip of the chain.
    #[tracing::instrument(skip_all, fields(try_to_send_id, tx_meta=?tx_metadata))]
    pub async fn send_cpfp_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRateKvb,
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
        let total_amount: Amount = confirmed.iter().map(|u| u.txout.value).sum();

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "creating_package", true)
            .await;

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
            Err(e) => {
                tracing::error!(try_to_send_id, "Failed to create CPFP package: {:?}", e);
                return Err(e);
            }
        };

        let package_refs: Vec<&Transaction> = package.iter().collect();

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

        // Save the effective fee rate before attempting to send
        // This ensures that even if the send fails, we track the attempt
        // so the 10-block stuck logic can trigger a bump
        self.db
            .update_effective_fee_rate(None, try_to_send_id, fee_rate, current_tip_height)
            .await
            .wrap_err("Failed to update effective fee rate")?;

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
                if crate::rpc_errors::is_rejecting_replacement_error(&error) {
                    tracing::debug!(
                        try_to_send_id,
                        "Package tx rejected (tx already in mempool): {error}"
                    );
                } else {
                    tracing::error!(
                        try_to_send_id,
                        "Error submitting package: {:?}, package: {:?}",
                        error,
                        package_refs
                            .iter()
                            .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                            .collect::<Vec<_>>()
                    );
                    log_error_for_tx!(
                        self.db,
                        try_to_send_id,
                        format!("Failed to submit package: {error}")
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "testing", feature = "standalone"))]
mod tests {
    use super::*;
    use crate::task::TxSenderTaskInternal;
    use crate::test_utils::create_test_environment;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::deserialize;
    use bitcoin::{OutPoint, ScriptBuf, TxOut};
    use bitcoincore_rpc::json::FundRawTransactionOptions;
    use clementine_config::NON_EPHEMERAL_ANCHOR_AMOUNT;
    use clementine_primitives::NON_STANDARD_V3;

    async fn create_default_cpfp_parent_tx(tx_sender: &TxSender) -> Transaction {
        let parent_tx = Transaction {
            version: NON_STANDARD_V3,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: tx_sender.address().script_pubkey(),
                },
                TxOut {
                    value: NON_EPHEMERAL_ANCHOR_AMOUNT,
                    script_pubkey: ScriptBuf::from_hex("51024e73").expect("valid anchor script"),
                },
            ],
        };

        let funded = tx_sender
            .rpc
            .fund_raw_transaction(
                &crate::serialize_tx_for_fund_raw(&parent_tx),
                Some(&FundRawTransactionOptions {
                    add_inputs: Some(true),
                    include_unsafe: Some(true),
                    ..Default::default()
                }),
                None,
            )
            .await
            .expect("fund_raw_transaction should succeed")
            .hex;

        let signed = tx_sender
            .rpc
            .sign_raw_transaction_with_wallet(&funded, None, None)
            .await
            .expect("sign_raw_transaction_with_wallet should succeed")
            .hex;

        deserialize::<Transaction>(&signed).expect("signed tx should deserialize")
    }

    async fn calculate_package_feerate_sat_per_kvb(
        tx_sender: &TxSender,
        parent: &Transaction,
        child: &Transaction,
    ) -> u64 {
        let parent_fee = tx_sender.get_tx_fee(parent).await.unwrap();
        let child_fee = tx_sender.get_tx_fee(child).await.unwrap();
        let total_fee_sat = parent_fee.to_sat().saturating_add(child_fee.to_sat());
        let total_vbytes = (parent.weight() + child.weight()).to_vbytes_ceil();
        total_fee_sat.saturating_mul(1000).div_ceil(total_vbytes)
    }

    async fn find_cpfp_child_txid_for_parent(
        tx_sender: &TxSender,
        parent_tx: &Transaction,
    ) -> bitcoin::Txid {
        let parent_txid = parent_tx.compute_txid();
        let anchor_vout = tx_sender
            .find_p2a_vout(parent_tx)
            .expect("parent should contain p2a anchor") as u32;

        let mempool_txids = tx_sender
            .rpc
            .get_raw_mempool()
            .await
            .expect("get_raw_mempool should succeed");

        for txid in mempool_txids {
            if txid == parent_txid {
                continue;
            }
            let tx = tx_sender
                .rpc
                .get_tx_of_txid(&txid)
                .await
                .expect("mempool tx should be retrievable");

            if tx.input.iter().any(|input| {
                input.previous_output
                    == OutPoint {
                        txid: parent_txid,
                        vout: anchor_vout,
                    }
            }) {
                return txid;
            }
        }

        panic!("could not find cpfp child tx for parent txid {parent_txid}");
    }

    #[tokio::test]
    async fn cpfp_dynamic_mock_feerate_increases_effective_package_feerate() {
        let (config, _db, rpc_env) = create_test_environment(true, true).await;
        let rpc_env = rpc_env.expect("RPC environment must be created");
        let tx_sender = TxSender::new(config).await.unwrap();
        let mut task = TxSenderTaskInternal::new(tx_sender.clone());

        let low_target_feerate = 8_000_u64;
        let high_target_feerate = 10_000_u64;

        tx_sender
            .rpc
            .set_mock_fee_rate_sat_per_kvb(Some(low_target_feerate))
            .await;

        let parent_tx = create_default_cpfp_parent_tx(&tx_sender).await;

        let mut dbtx = tx_sender.db.begin_transaction().await.unwrap();
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(&mut dbtx, None, &parent_tx, FeePayingType::CPFP, None, &[])
            .await
            .expect("insert_try_to_send should succeed");
        tx_sender.db.commit_transaction(dbtx).await.unwrap();

        // First run creates fee payer UTXO(s) at the low target.
        task.run_once().await.unwrap();

        let initial_unconfirmed = tx_sender
            .db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await
            .expect("query should succeed");
        assert!(
            !initial_unconfirmed.is_empty(),
            "expected at least one unconfirmed fee payer after first run"
        );

        // Confirm fee-payer tx(s) so CPFP package can be submitted.
        rpc_env.rpc().mine_blocks(1).await.unwrap();

        // First CPFP package submit at low target.
        task.run_once().await.unwrap();

        let parent_txid = parent_tx.compute_txid();
        let initial_child_txid = find_cpfp_child_txid_for_parent(&tx_sender, &parent_tx).await;
        let initial_parent_mempool_tx = tx_sender.rpc.get_tx_of_txid(&parent_txid).await.unwrap();
        let initial_child_mempool_tx = tx_sender
            .rpc
            .get_tx_of_txid(&initial_child_txid)
            .await
            .unwrap();
        let initial_package_feerate = calculate_package_feerate_sat_per_kvb(
            &tx_sender,
            &initial_parent_mempool_tx,
            &initial_child_mempool_tx,
        )
        .await;

        assert!(
            initial_package_feerate >= low_target_feerate,
            "expected initial package feerate >= {low_target_feerate}, got {initial_package_feerate}"
        );

        tx_sender
            .rpc
            .set_mock_fee_rate_sat_per_kvb(Some(high_target_feerate))
            .await;

        // No mining between runs: re-run with higher target and verify effective package feerate increases.
        task.run_once().await.unwrap();

        let bumped_child_txid = find_cpfp_child_txid_for_parent(&tx_sender, &parent_tx).await;
        let bumped_parent_mempool_tx = tx_sender.rpc.get_tx_of_txid(&parent_txid).await.unwrap();
        let bumped_child_mempool_tx = tx_sender
            .rpc
            .get_tx_of_txid(&bumped_child_txid)
            .await
            .unwrap();
        let bumped_package_feerate = calculate_package_feerate_sat_per_kvb(
            &tx_sender,
            &bumped_parent_mempool_tx,
            &bumped_child_mempool_tx,
        )
        .await;

        assert!(
            bumped_package_feerate >= high_target_feerate,
            "expected bumped package feerate >= {high_target_feerate}, got {bumped_package_feerate}"
        );
        assert!(
            bumped_package_feerate > initial_package_feerate,
            "expected bumped package feerate > initial ({initial_package_feerate}), got {bumped_package_feerate}"
        );
    }
}
