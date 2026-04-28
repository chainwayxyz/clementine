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

const CPFP_FEE_PAYER_FEE_BUFFER_MULTIPLIER: f64 = 2.0;

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
        change_script_pubkey: ScriptBuf,
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
                script_pubkey: change_script_pubkey,
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

    fn calculate_fee_payer_total_amount(required_fee: Amount) -> Option<Amount> {
        let buffered_fee_sat =
            (required_fee.to_sat() as f64 * CPFP_FEE_PAYER_FEE_BUFFER_MULTIPLIER).ceil();
        if !buffered_fee_sat.is_finite()
            || buffered_fee_sat < 0.0
            || buffered_fee_sat > u64::MAX as f64
        {
            return None;
        }

        Amount::from_sat(buffered_fee_sat as u64).checked_add(MIN_TAPROOT_AMOUNT)
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

        // Aggressively buffer the required fee to account for sudden spikes.
        // We won't actually use the buffered fees, but the fee payer utxo will hold that much amount so that while fee payer utxo gets mined
        // if fees increase the utxo should still be sufficient to fund the tx with high probability
        // leftover fees will get sent back to wallet with a change output in fn create_child_tx
        let new_total_fee_needed = Self::calculate_fee_payer_total_amount(required_fee);
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
                    // Always avoid unsafe wallet UTXOs while funding.
                    include_unsafe: Some(false),
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

        let change_script_pubkey = self.change_script_pubkey.clone();

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.txout.value)
            .sum::<Amount>()
            + anchor_sat;

        if change_script_pubkey.minimal_non_dust() + required_fee > total_fee_payer_amount {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        self.build_and_sign_child_tx(
            p2a_anchor,
            anchor_sat,
            fee_payer_utxos,
            change_script_pubkey,
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

        for (id, try_to_send_id, fee_payer_txid, _vout, amount, replacement_of_id) in bumpable_txs {
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
                        let bumped_tx = self
                            .rpc
                            .get_tx_of_txid(&new_txid)
                            .await
                            .map_err(|e| SendTxError::Other(eyre!(e)))?;
                        let Some(new_vout) = bumped_tx.output.iter().position(|output| {
                            output.value == amount
                                && output.script_pubkey == self.signer.address().script_pubkey()
                        }) else {
                            tracing::warn!(
                                "Bumped fee payer tx {} did not preserve expected output of {} sats for try_to_send_id {}, skipping DB save",
                                new_txid,
                                amount,
                                try_to_send_id
                            );
                            continue;
                        };

                        self.db
                            .save_fee_payer_tx(
                                None,
                                try_to_send_id,
                                new_txid,
                                new_vout as u32,
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

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::absolute::LockTime;
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::taproot;
    use bitcoin::{OutPoint, TapSighashType, Txid};
    use bitcoincore_rpc::RpcApi;
    use clementine_utils::sign::TapTweakData;

    use crate::test_utils::create_test_environment;
    use crate::DEFAULT_SEQUENCE;

    const CPFP_TEST_FEE_RATE_SAT_KVB: u64 = 2_500;
    const CPFP_BUMP_FEE_RATE_SAT_KVB: u64 = 4_000;
    const FEE_RATE_TOLERANCE_PERCENT: u64 = 1;

    struct QueuedCpfpParent {
        try_to_send_id: u32,
        tx: Transaction,
        txid: Txid,
        anchor_vout: u32,
    }

    #[derive(Debug, Clone)]
    struct FeePayerRow {
        id: u32,
        txid: Txid,
        vout: u32,
        amount: Amount,
    }

    fn build_zero_fee_parent_tx(
        tx_sender: &TxSender,
        funding_outpoint: OutPoint,
        funding_txout: TxOut,
    ) -> Transaction {
        let anchor = TxSender::anchor_prevout(Amount::ZERO);
        let change_value = funding_txout
            .value
            .checked_sub(anchor.value)
            .expect("funding amount must cover anchor");

        let mut parent_tx = Transaction {
            version: NON_STANDARD_V3,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: DEFAULT_SEQUENCE,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: change_value,
                    script_pubkey: tx_sender.address().script_pubkey(),
                },
                anchor,
            ],
        };

        let prevouts = vec![funding_txout];
        let sighash = SighashCache::new(&parent_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .expect("parent sighash must be computed");
        let signature = tx_sender
            .signer
            .sign_with_tweak_data(sighash, TapTweakData::KeyPath(None))
            .expect("parent input must be signable");
        let tr_sig = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };
        parent_tx.input[0].witness = Witness::p2tr_key_spend(&tr_sig);

        parent_tx
    }

    async fn queue_cpfp_parent(tx_sender: &TxSender) -> QueuedCpfpParent {
        let funding_outpoint = tx_sender
            .rpc
            .send_to_address(tx_sender.address(), Amount::from_sat(400_000))
            .await
            .expect("parent funding tx should be sent");
        tx_sender
            .rpc
            .mine_blocks(1)
            .await
            .expect("parent funding tx should confirm");

        let funding_txout = tx_sender
            .rpc
            .get_txout_from_outpoint(&funding_outpoint)
            .await
            .expect("parent funding txout should be available");
        let parent_tx = build_zero_fee_parent_tx(tx_sender, funding_outpoint, funding_txout);
        let parent_txid = parent_tx.compute_txid();
        let anchor_vout = tx_sender.find_p2a_vout(&parent_tx).unwrap() as u32;

        let mut dbtx = tx_sender.db.begin_transaction().await.unwrap();
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(&mut dbtx, None, &parent_tx, FeePayingType::CPFP, None, &[])
            .await
            .unwrap();
        tx_sender.db.commit_transaction(dbtx).await.unwrap();
        tx_sender
            .sync_transaction_confirmations_via_rpc(None)
            .await
            .unwrap();

        QueuedCpfpParent {
            try_to_send_id,
            tx: parent_tx,
            txid: parent_txid,
            anchor_vout,
        }
    }

    async fn run_txsender_with_fee_rate(tx_sender: &TxSender, fee_rate: FeeRateKvb) {
        let current_tip_height = tx_sender.rpc.get_current_chain_height().await.unwrap();
        tx_sender
            .sync_transaction_confirmations_via_rpc(None)
            .await
            .unwrap();
        tx_sender
            .try_to_send_unconfirmed_txs(fee_rate, current_tip_height, false)
            .await
            .unwrap();
    }

    async fn latest_unconfirmed_fee_payer(
        tx_sender: &TxSender,
        try_to_send_id: u32,
    ) -> FeePayerRow {
        let rows = tx_sender
            .db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await
            .unwrap();

        let (id, txid, vout, amount) = rows
            .into_iter()
            .max_by_key(|(id, _, _, _)| *id)
            .expect("expected an unconfirmed fee payer tx");

        FeePayerRow {
            id,
            txid,
            vout,
            amount,
        }
    }

    async fn tx_is_in_mempool(tx_sender: &TxSender, txid: Txid) -> bool {
        tx_sender
            .rpc
            .get_raw_mempool()
            .await
            .expect("getrawmempool must work")
            .contains(&txid)
    }

    async fn get_child_spending_anchor(
        tx_sender: &TxSender,
        parent_txid: Txid,
        anchor_vout: u32,
    ) -> Transaction {
        let txids = tx_sender
            .rpc
            .get_raw_mempool()
            .await
            .expect("getrawmempool must work");

        for txid in txids {
            if txid == parent_txid {
                continue;
            }

            let tx = tx_sender
                .rpc
                .get_tx_of_txid(&txid)
                .await
                .expect("getrawtransaction must work");
            if tx.input.iter().any(|input| {
                input.previous_output.txid == parent_txid
                    && input.previous_output.vout == anchor_vout
            }) {
                return tx;
            }
        }

        panic!("expected a child tx spending {parent_txid}:{anchor_vout}");
    }

    async fn calculate_feerate_sat_per_kvb(tx_sender: &TxSender, tx: &Transaction) -> u64 {
        let fee = tx_sender.get_tx_fee(tx).await.unwrap();
        fee.to_sat()
            .saturating_mul(1000)
            .div_ceil(tx.weight().to_vbytes_ceil())
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

    fn assert_feerate_near_target(context: &str, actual: u64, target: FeeRateKvb) {
        let target = target.to_sat_per_kvb();
        let max = target
            .saturating_mul(100 + FEE_RATE_TOLERANCE_PERCENT)
            .saturating_div(100);
        assert!(
            actual >= target && actual <= max,
            "expected {context} feerate between {target} and {max} sat/kvB, got {actual}"
        );
    }

    fn expected_child_fee(parent: &Transaction, fee_rate: FeeRateKvb) -> Amount {
        TxSender::calculate_required_fee(parent.weight(), 1, fee_rate, FeePayingType::CPFP).unwrap()
    }

    fn expected_fee_payer_amount(parent: &Transaction, fee_rate: FeeRateKvb) -> Amount {
        TxSender::calculate_fee_payer_total_amount(expected_child_fee(parent, fee_rate)).unwrap()
    }

    async fn assert_fee_payer_creation_tx(
        tx_sender: &TxSender,
        parent: &Transaction,
        row: &FeePayerRow,
        fee_rate: FeeRateKvb,
        context: &str,
    ) {
        let fee_payer_tx = tx_sender.rpc.get_tx_of_txid(&row.txid).await.unwrap();
        assert_eq!(
            fee_payer_tx.output[row.vout as usize].value, row.amount,
            "fee payer DB amount should match the created output"
        );
        assert_eq!(
            row.amount,
            expected_fee_payer_amount(parent, fee_rate),
            "unexpected fee payer output amount for {context}"
        );

        let fee_payer_feerate = calculate_feerate_sat_per_kvb(tx_sender, &fee_payer_tx).await;
        assert_feerate_near_target(context, fee_payer_feerate, fee_rate);
    }

    async fn assert_cpfp_package_fees(
        tx_sender: &TxSender,
        parent: &Transaction,
        child: &Transaction,
        fee_rate: FeeRateKvb,
        context: &str,
    ) {
        let parent_fee = tx_sender.get_tx_fee(parent).await.unwrap();
        let child_fee = tx_sender.get_tx_fee(child).await.unwrap();
        assert_eq!(
            parent_fee,
            Amount::ZERO,
            "expected zero-fee CPFP parent tx for {context}"
        );
        assert_eq!(
            child_fee,
            expected_child_fee(parent, fee_rate),
            "unexpected CPFP child fee for {context}"
        );

        let package_feerate = calculate_package_feerate_sat_per_kvb(tx_sender, parent, child).await;
        assert_feerate_near_target(context, package_feerate, fee_rate);
    }

    /// This test verifies that the 1p1c TRUC CPFP package is rejected if the fee payer input is unconfirmed.
    /// If this test faild, depending on the reason it could mean we do not have to wait for fee-payer confirmation anymore.
    #[tokio::test]
    async fn cpfp_package_rejects_unconfirmed_fee_payer_input() {
        let (config, _db, _rpc_env) = create_test_environment(true, true).await;
        let tx_sender = TxSender::new(config).await.unwrap();
        let fee_rate = FeeRateKvb::from_sat_per_kvb(CPFP_TEST_FEE_RATE_SAT_KVB);
        let parent = queue_cpfp_parent(&tx_sender).await;
        assert_eq!(
            parent.tx.output[parent.anchor_vout as usize].value,
            Amount::ZERO
        );

        run_txsender_with_fee_rate(&tx_sender, fee_rate).await;
        let fee_payer = latest_unconfirmed_fee_payer(&tx_sender, parent.try_to_send_id).await;
        assert!(tx_is_in_mempool(&tx_sender, fee_payer.txid).await);

        let fee_payer_tx = tx_sender.rpc.get_tx_of_txid(&fee_payer.txid).await.unwrap();
        let package = tx_sender
            .create_package(
                parent.tx,
                fee_rate,
                vec![crate::SpendableUtxo {
                    outpoint: OutPoint {
                        txid: fee_payer.txid,
                        vout: fee_payer.vout,
                    },
                    txout: fee_payer_tx.output[fee_payer.vout as usize].clone(),
                    spend_info: None,
                }],
            )
            .await
            .unwrap();
        assert_eq!(package.len(), 2, "expected 1-parent/1-child package");
        let child_txid = package[1].compute_txid();
        let package_refs: Vec<&Transaction> = package.iter().collect();

        let submit_result = tx_sender
            .rpc
            .submit_package(&package_refs, Some(Amount::ZERO), None)
            .await
            .unwrap();
        assert!(
            submit_result
                .tx_results
                .values()
                .any(|result| matches!(result, PackageTransactionResult::Failure { .. })),
            "expected package to be rejected with unconfirmed fee payer input, got {submit_result:?}"
        );
        assert!(!tx_is_in_mempool(&tx_sender, child_txid).await);

        tx_sender.rpc.mine_blocks(1).await.unwrap();
        let submit_result = tx_sender
            .rpc
            .submit_package(&package_refs, Some(Amount::ZERO), None)
            .await
            .unwrap();
        assert!(
            submit_result
                .tx_results
                .values()
                .all(|result| !matches!(result, PackageTransactionResult::Failure { .. })),
            "expected package to be accepted after fee payer confirms, got {submit_result:?}"
        );
        assert!(tx_is_in_mempool(&tx_sender, child_txid).await);
    }

    #[tokio::test]
    async fn cpfp_package_and_fee_payer_creation_use_fixed_fee_rate() {
        let (config, _db, _rpc_env) = create_test_environment(true, true).await;
        let tx_sender = TxSender::new(config).await.unwrap();
        let fee_rate = FeeRateKvb::from_sat_per_kvb(CPFP_TEST_FEE_RATE_SAT_KVB);

        let parent = queue_cpfp_parent(&tx_sender).await;

        run_txsender_with_fee_rate(&tx_sender, fee_rate).await;
        let fee_payer = latest_unconfirmed_fee_payer(&tx_sender, parent.try_to_send_id).await;
        assert_fee_payer_creation_tx(
            &tx_sender,
            &parent.tx,
            &fee_payer,
            fee_rate,
            "initial fee payer creation tx",
        )
        .await;

        tx_sender.rpc.mine_blocks(1).await.unwrap();
        run_txsender_with_fee_rate(&tx_sender, fee_rate).await;

        let child = get_child_spending_anchor(&tx_sender, parent.txid, parent.anchor_vout).await;
        assert_cpfp_package_fees(
            &tx_sender,
            &parent.tx,
            &child,
            fee_rate,
            "initial CPFP package",
        )
        .await;

        tx_sender.rpc.mine_blocks(1).await.unwrap();
        let parent_confirmations = tx_sender
            .rpc
            .confirmation_blocks(&parent.txid)
            .await
            .unwrap();
        let child_confirmations = tx_sender
            .rpc
            .confirmation_blocks(&child.compute_txid())
            .await
            .unwrap();
        assert!(parent_confirmations >= 1, "expected CPFP parent to confirm");
        assert!(child_confirmations >= 1, "expected CPFP child to confirm");
    }

    #[tokio::test]
    async fn cpfp_fee_bump_updates_fee_payer_and_package_fees() {
        let (mut config, _db, _rpc_env) = create_test_environment(true, true).await;
        config.limits.cpfp_fee_payer_bump_wait_time_seconds = 0;
        config.limits.min_bump_kvb = 300;

        let tx_sender = TxSender::new(config).await.unwrap();
        let initial_fee_rate = FeeRateKvb::from_sat_per_kvb(CPFP_TEST_FEE_RATE_SAT_KVB);
        let bumped_fee_rate = FeeRateKvb::from_sat_per_kvb(CPFP_BUMP_FEE_RATE_SAT_KVB);

        let parent = queue_cpfp_parent(&tx_sender).await;

        run_txsender_with_fee_rate(&tx_sender, initial_fee_rate).await;
        let initial_fee_payer =
            latest_unconfirmed_fee_payer(&tx_sender, parent.try_to_send_id).await;
        assert_fee_payer_creation_tx(
            &tx_sender,
            &parent.tx,
            &initial_fee_payer,
            initial_fee_rate,
            "initial fee payer creation tx before bump",
        )
        .await;

        tx_sender
            .bump_fees_of_unconfirmed_fee_payer_txs(bumped_fee_rate)
            .await
            .unwrap();
        let bumped_fee_payer =
            latest_unconfirmed_fee_payer(&tx_sender, parent.try_to_send_id).await;
        assert_ne!(
            bumped_fee_payer.txid, initial_fee_payer.txid,
            "expected fee payer creation tx to be RBF-bumped"
        );
        assert!(
            bumped_fee_payer.id > initial_fee_payer.id,
            "expected bumped fee payer row to be newer"
        );
        let bumped_fee_payer_tx = tx_sender
            .rpc
            .get_tx_of_txid(&bumped_fee_payer.txid)
            .await
            .unwrap();
        assert_eq!(
            bumped_fee_payer.amount,
            expected_fee_payer_amount(&parent.tx, initial_fee_rate),
            "fee payer bump should preserve the CPFP funding output amount"
        );
        assert_eq!(
            bumped_fee_payer_tx.output[bumped_fee_payer.vout as usize].value,
            bumped_fee_payer.amount,
            "bumped fee payer DB vout should point to the preserved funding output"
        );
        assert_eq!(
            bumped_fee_payer_tx.output[bumped_fee_payer.vout as usize].script_pubkey,
            tx_sender.address().script_pubkey(),
            "bumped fee payer DB vout should remain spendable by txsender"
        );
        let bumped_fee_payer_feerate =
            calculate_feerate_sat_per_kvb(&tx_sender, &bumped_fee_payer_tx).await;
        assert_feerate_near_target(
            "bumped fee payer creation tx",
            bumped_fee_payer_feerate,
            bumped_fee_rate,
        );

        tx_sender.rpc.mine_blocks(1).await.unwrap();
        run_txsender_with_fee_rate(&tx_sender, initial_fee_rate).await;
        let initial_child =
            get_child_spending_anchor(&tx_sender, parent.txid, parent.anchor_vout).await;
        let initial_child_txid = initial_child.compute_txid();
        assert_cpfp_package_fees(
            &tx_sender,
            &parent.tx,
            &initial_child,
            initial_fee_rate,
            "initial CPFP package before bump",
        )
        .await;

        let below_min_bump = FeeRateKvb::from_sat_per_kvb(
            initial_fee_rate
                .to_sat_per_kvb()
                .saturating_add(tx_sender.tx_sender_limits.min_bump_kvb)
                .saturating_sub(1),
        );
        run_txsender_with_fee_rate(&tx_sender, below_min_bump).await;
        let not_bumped_child =
            get_child_spending_anchor(&tx_sender, parent.txid, parent.anchor_vout).await;
        assert_eq!(
            not_bumped_child.compute_txid(),
            initial_child_txid,
            "expected CPFP package to keep the same child below min_bump_kvb"
        );

        run_txsender_with_fee_rate(&tx_sender, bumped_fee_rate).await;
        let bumped_child =
            get_child_spending_anchor(&tx_sender, parent.txid, parent.anchor_vout).await;
        assert_ne!(
            bumped_child.compute_txid(),
            initial_child_txid,
            "expected CPFP package bump to create a replacement child"
        );
        assert!(
            !tx_is_in_mempool(&tx_sender, initial_child_txid).await,
            "expected initial CPFP child to be replaced"
        );
        assert_cpfp_package_fees(
            &tx_sender,
            &parent.tx,
            &bumped_child,
            bumped_fee_rate,
            "bumped CPFP package",
        )
        .await;

        tx_sender.rpc.mine_blocks(1).await.unwrap();
        let parent_confirmations = tx_sender
            .rpc
            .confirmation_blocks(&parent.txid)
            .await
            .unwrap();
        let child_confirmations = tx_sender
            .rpc
            .confirmation_blocks(&bumped_child.compute_txid())
            .await
            .unwrap();
        assert!(
            parent_confirmations >= 1,
            "expected bumped CPFP parent to confirm"
        );
        assert!(
            child_confirmations >= 1,
            "expected bumped CPFP child to confirm"
        );
    }
}
