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

use super::{Result, SendTxError, TxMetadata, TxSender};
use crate::constants::NON_STANDARD_V3;
use crate::errors::{ErrorExt, ResultExt};
use crate::extended_bitcoin_rpc::BitcoinRPCError;
use crate::utils::FeePayingType;
use crate::{
    builder::{
        self,
        script::SpendPath,
        transaction::{
            input::SpendableTxIn, output::UnspentTxOut, TransactionType, TxHandlerBuilder,
            DEFAULT_SEQUENCE,
        },
    },
    constants::MIN_TAPROOT_AMOUNT,
    rpc::clementine::NormalSignatureKind,
};
use bitcoin::{Amount, FeeRate, OutPoint, Transaction, TxOut, Weight};
use bitcoincore_rpc::PackageSubmissionResult;
use bitcoincore_rpc::{PackageTransactionResult, RpcApi};
use eyre::eyre;
use eyre::Context;
use std::collections::HashSet;
use std::env;

impl TxSender {
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
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: new_fee_payer_amount,
                script_pubkey: self.signer.address.script_pubkey(),
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
                Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
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
                    && o.script_pubkey == self.signer.address.script_pubkey()
            })
            .ok_or(eyre!("Failed to find outpoint vout"))?;

        self.rpc
            .send_raw_transaction(&signed_fee_payer_tx)
            .await
            .wrap_err("Failed to send signed fee payer tx")?;

        self.db
            .save_fee_payer_tx(
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
        fee_payer_utxos: Vec<SpendableTxIn>,
        parent_tx_size: Weight,
        fee_rate: FeeRate,
    ) -> Result<Transaction> {
        tracing::debug!(
            "Creating child tx with {} fee payer utxos",
            fee_payer_utxos.len()
        );
        let required_fee = Self::calculate_required_fee(
            parent_tx_size,
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::CPFP,
        )
        .map_err(|e| eyre!(e))?;

        let change_address = self
            .rpc
            .get_new_wallet_address()
            .await
            .wrap_err("Failed to get new wallet address")?;

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + anchor_sat; // We add the anchor output value to the total amount.
        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(NON_STANDARD_V3)
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new_partial(
                    p2a_anchor,
                    builder::transaction::anchor_output(anchor_sat),
                ),
                SpendPath::Unknown,
                DEFAULT_SEQUENCE,
            );

        for fee_payer_utxo in fee_payer_utxos {
            builder = builder.add_input(
                NormalSignatureKind::OperatorSighashDefault,
                fee_payer_utxo,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            );
        }

        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: total_fee_payer_amount - required_fee,
            script_pubkey: change_address.script_pubkey(),
        }));

        let mut tx_handler = builder.finalize();

        for fee_payer_input in 1..tx_handler.get_cached_tx().input.len() {
            let sighash = tx_handler
                .calculate_pubkey_spend_sighash(fee_payer_input, bitcoin::TapSighashType::Default)
                .map_err(|e| eyre!(e))?;
            let signature = self
                .signer
                .sign_with_tweak_data(sighash, builder::sighash::TapTweakData::KeyPath(None), None)
                .map_err(|e| eyre!(e))?;
            tx_handler
                .set_p2tr_key_spend_witness(
                    &bitcoin::taproot::Signature {
                        signature,
                        sighash_type: bitcoin::TapSighashType::Default,
                    },
                    fee_payer_input,
                )
                .map_err(|e| eyre!(e))?;
        }
        let child_tx = tx_handler.get_cached_tx().clone();

        Ok(child_tx)
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
        fee_payer_utxos: Vec<SpendableTxIn>,
    ) -> Result<Vec<Transaction>> {
        tracing::debug!(
            "Creating package with {} fee payer utxos",
            fee_payer_utxos.len()
        );
        let txid = tx.compute_txid();

        let p2a_vout = self
            .find_p2a_vout(&tx)
            .wrap_err("Failed to find p2a vout")?;

        // get sat amount of anchor output in the tx
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
            .await
            .wrap_err("Failed to create child tx")?;

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
    /// - [`Vec<SpendableTxIn>`]: [`SpendableTxIn`]s of the confirmed fee payer
    ///   UTXOs that are ready to be included as inputs in the CPFP child tx.
    async fn get_confirmed_fee_payer_utxos(
        &self,
        try_to_send_id: u32,
    ) -> Result<Vec<SpendableTxIn>> {
        Ok(self
            .db
            .get_confirmed_fee_payer_utxos(None, try_to_send_id)
            .await
            .map_to_eyre()?
            .iter()
            .map(|(txid, vout, amount)| {
                SpendableTxIn::new(
                    OutPoint {
                        txid: *txid,
                        vout: *vout,
                    },
                    TxOut {
                        value: *amount,
                        script_pubkey: self.signer.address.script_pubkey(),
                    },
                    vec![],
                    Some(self.cached_spendinfo.clone()),
                )
            })
            .collect())
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
    /// * `bumped_id` - The database ID of the parent transaction whose fee payer UTXOs need bumping.
    /// * `fee_rate` - The target fee rate for bumping the fee payer transactions.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, fee_rate))]
    pub(crate) async fn bump_fees_of_unconfirmed_fee_payer_txs(
        &self,
        fee_rate: FeeRate,
    ) -> Result<()> {
        let bumpable_fee_payer_txs = self
            .db
            .get_all_unconfirmed_fee_payer_txs(None)
            .await
            .map_to_eyre()?;

        let mut not_evicted_ids = HashSet::new();
        let mut all_parent_ids = HashSet::new();

        for (id, try_to_send_id, fee_payer_txid, vout, amount, replacement_of_id) in
            bumpable_fee_payer_txs
        {
            tracing::debug!(
                "Bumping fee for fee payer tx {} for try to send id {} for fee rate {}",
                fee_payer_txid,
                try_to_send_id,
                fee_rate
            );
            // parent id is the id of the first created tx for all replacements
            let parent_id = match replacement_of_id {
                Some(replacement_of_id) => replacement_of_id,
                None => id,
            };
            all_parent_ids.insert(parent_id);
            let mempool_info = self.rpc.get_mempool_entry(&fee_payer_txid).await;
            let mempool_info = match mempool_info {
                Ok(mempool_info) => {
                    not_evicted_ids.insert(parent_id);
                    mempool_info
                }
                Err(e) => {
                    // If not in mempool we should ignore
                    // give an error if the error is not "Transaction not in mempool"
                    if !e.to_string().contains("Transaction not in mempool") {
                        return Err(eyre::eyre!(
                            "Failed to get mempool entry for fee payer tx {}: {}",
                            fee_payer_txid,
                            e
                        )
                        .into());
                    }
                    // check here if the tx is already in block, if so do not mark it as evicted
                    let tx_info = self.rpc.get_transaction(&fee_payer_txid, None).await;
                    if let Ok(tx_info) = tx_info {
                        if tx_info.info.blockhash.is_some() && tx_info.info.confirmations > 0 {
                            not_evicted_ids.insert(parent_id);
                        }
                    }
                    continue;
                }
            };
            // only try to bump if tx has no descendants and some time has passed since tx was created
            if mempool_info.descendant_count > 1
                || std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .wrap_err("Failed to get unix timestamp")?
                    .as_secs()
                    .saturating_sub(mempool_info.time)
                    < self
                        .config
                        .tx_sender_limits
                        .cpfp_fee_payer_bump_wait_time_seconds
            {
                continue;
            }
            let new_txid_result = self
                .rpc
                .bump_fee_with_fee_rate(fee_payer_txid, fee_rate)
                .await;

            match new_txid_result {
                Ok(new_txid) => {
                    if new_txid != fee_payer_txid {
                        self.db
                            .save_fee_payer_tx(
                                None,
                                try_to_send_id,
                                new_txid,
                                vout,
                                amount,
                                match replacement_of_id {
                                    Some(replacement_of_id) => Some(replacement_of_id),
                                    None => Some(id),
                                },
                            )
                            .await
                            .map_to_eyre()?;
                    } else {
                        tracing::trace!(
                            "Fee payer tx {} has enough fee, no need to bump",
                            fee_payer_txid
                        );
                    }
                }
                Err(e) => {
                    let e = e.into_eyre();
                    match e.root_cause().downcast_ref::<BitcoinRPCError>() {
                        Some(BitcoinRPCError::TransactionAlreadyInBlock(block_hash)) => {
                            tracing::debug!(
                                "Fee payer tx {} is already in block {}, skipping",
                                fee_payer_txid,
                                block_hash
                            );
                            continue;
                        }
                        Some(BitcoinRPCError::BumpFeeUTXOSpent(outpoint)) => {
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
                    }
                }
            }
        }

        // if all fee payer utxos are not in mempool
        // in very rare cases, (if tx was mined, but before we called gettransaction it was reorged)
        // it can be marked as evicted accidentally, but this is very rare and if it was mined once but reorged,
        // it will likely enter the chain without any bumping anyway, but an extra fee payer utxo can be created by txsender
        // because it is considered to be evicted
        for parent_id in all_parent_ids {
            if !not_evicted_ids.contains(&parent_id) {
                self.db
                    .mark_fee_payer_utxo_as_evicted(None, parent_id)
                    .await
                    .map_to_eyre()?;
            }
        }

        Ok(())
    }

    /// Sends a transaction using the Child-Pays-For-Parent (CPFP) strategy.
    ///
    /// # Logic:
    /// 1.  **Check Unconfirmed Fee Payers:** Ensures no unconfirmed fee payer UTXOs exist
    ///     for this `try_to_send_id`. If they do, returns [`SendTxError::UnconfirmedFeePayerUTXOsLeft`]
    ///     as they need to confirm before being spendable by the child.
    /// 2.  **Get Confirmed Fee Payers:** Retrieves the available confirmed fee payer UTXOs.
    /// 3.  **Create Package:** Calls `create_package` to build the `vec![parent_tx, child_tx]`.
    ///     The `child_tx` spends the parent's anchor output and the fee payer UTXOs, paying
    ///     a fee calculated for the whole package.
    /// 4.  **Test Mempool Accept (Debug step):** Uses `testmempoolaccept` RPC
    ///     to check if the package is likely to be accepted by the network before submitting.
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
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, try_to_send_id, tx_meta=?tx_metadata))]
    pub(super) async fn send_cpfp_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<()> {
        let unconfirmed_fee_payer_utxos = self
            .db
            .get_unconfirmed_fee_payer_txs(None, try_to_send_id)
            .await
            .map_to_eyre()?;

        if !unconfirmed_fee_payer_utxos.is_empty() {
            // Log that we're waiting for unconfirmed UTXOs
            tracing::debug!(
                try_to_send_id,
                "Waiting for {} UTXOs to confirm",
                unconfirmed_fee_payer_utxos.len()
            );

            // Update the sending state
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

        tracing::debug!(try_to_send_id, "Attempting to send CPFP tx");

        let confirmed_fee_payers = self.get_confirmed_fee_payer_utxos(try_to_send_id).await?;
        let confirmed_fee_payer_len = confirmed_fee_payers.len();

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "creating_package", true)
            .await;

        // to be used below
        let total_fee_payer_amount = confirmed_fee_payers
            .iter()
            .map(|txi| txi.get_prevout().value)
            .sum::<Amount>();

        let package = self
            .create_package(tx.clone(), fee_rate, confirmed_fee_payers)
            .await
            .wrap_err("Failed to create CPFP package");

        let package = match package {
            Ok(package) => package,
            Err(e) => match e.root_cause().downcast_ref::<SendTxError>() {
                Some(SendTxError::InsufficientFeePayerAmount) => {
                    tracing::debug!(
                        try_to_send_id,
                        "Insufficient fee payer amount, creating new fee payer utxo."
                    );

                    self.create_fee_payer_utxo(
                        try_to_send_id,
                        &tx,
                        fee_rate,
                        total_fee_payer_amount,
                        confirmed_fee_payer_len,
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
                _ => {
                    tracing::error!(try_to_send_id, "Failed to create CPFP package: {:?}", e);
                    return Err(e.into());
                }
            },
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

        // Update sending state to submitting_package
        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "submitting_package", true)
            .await;

        tracing::debug!(try_to_send_id, "Submitting package, size {}", package.len());

        // let test_mempool_result = self
        //     .rpc
        //     .test_mempool_accept(&package_refs)
        //     .await
        //     .wrap_err("Failed to test mempool accept")?;

        let submit_package_result: PackageSubmissionResult = self
            .rpc
            .submit_package(&package_refs, Some(Amount::from_sat(0)), None)
            .await
            .wrap_err("Failed to submit package")?;

        tracing::debug!(
            try_to_send_id,
            "Submit package result: {submit_package_result:?}"
        );

        // Save the effective fee rate before attempting to send
        // This ensures that even if the send fails, we track the attempt
        // so the 10-block stuck logic can trigger a bump
        self.db
            .update_effective_fee_rate(None, try_to_send_id, fee_rate, current_tip_height)
            .await
            .wrap_err("Failed to update effective fee rate")?;

        // If tx_results is empty, it means the txs were already accepted by the network.
        if submit_package_result.tx_results.is_empty() {
            return Ok(());
        }

        let mut early_exit = false;
        for (_txid, result) in submit_package_result.tx_results {
            if let PackageTransactionResult::Failure { error, .. } = result {
                tracing::error!(
                    try_to_send_id,
                    "Error submitting package: {:?}, package: {:?}",
                    error,
                    package_refs
                        .iter()
                        .map(|tx| hex::encode(bitcoin::consensus::serialize(tx)))
                        .collect::<Vec<_>>()
                );

                early_exit = true;
            }
        }
        if early_exit {
            return Ok(());
        }

        tracing::info!("Package submitted successfully.");

        // // Get the effective fee rate from the first transaction result
        // let effective_fee_rate_btc_per_kvb = submit_package_result
        //     .tx_results
        //     .iter()
        //     .next()
        //     .and_then(|(_, result)| match result {
        //         PackageTransactionResult::Success { fees, .. } => Some(fees.effective_feerate),
        //         PackageTransactionResult::SuccessAlreadyInMempool { txid, .. } => {
        //             tracing::warn!(
        //                 "{}: transaction {txid} is already in mempool, skipping",
        //                 self.consumer_handle
        //             );
        //             None
        //         }
        //         PackageTransactionResult::Failure { txid, error } => {
        //             tracing::warn!(
        //                 "{}: failed to send the transaction {txid} with error {error}, skipping",
        //                 self.consumer_handle
        //             );
        //             None
        //         }
        //     })
        //     .expect("Effective fee rate should be present")
        //     .expect("Effective fee rate should be present");

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test::common::{create_regtest_rpc, create_test_config_with_thread_name};

    use super::super::tests::*;
    use bitcoin::FeeRate;
    use bitcoincore_rpc::RpcApi;

    /// Test that calculate_target_fee_rate correctly handles fee bumping scenarios
    #[tokio::test]
    async fn test_calculate_target_fee_rate_incremental_bump() {
        let mut config = create_test_config_with_thread_name().await;
        let rpc = create_regtest_rpc(&mut config).await;

        let (tx_sender, _btc_sender, rpc, _db, _signer, _network) =
            create_tx_sender(rpc.rpc().clone()).await;

        // Get incremental fee rate from node (typically 1000 sat/kvB = 250 sat/kwu on regtest)
        let incremental_fee_btc_per_kvb = rpc.get_network_info().await.unwrap().incremental_fee;
        let incremental_fee_sat_per_kwu = incremental_fee_btc_per_kvb.to_sat() / 4;

        // Test 1: No previous fee rate - should return new_fee_rate
        let new_fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let result = tx_sender
            .calculate_target_fee_rate(None, new_fee_rate, None, 100)
            .await
            .unwrap();
        assert_eq!(
            result, new_fee_rate,
            "Should return new_fee_rate when no previous rate"
        );

        // Test 2: New fee rate higher than previous but LOWER than previous + incremental
        // This tests BIP125 compliance: the result should be previous + incremental, NOT new_fee_rate
        let previous_rate = FeeRate::from_sat_per_vb(10).unwrap(); // 2500 sat/kwu
                                                                   // Add only 0.5 sat/kwu (less than incremental fee which is typically 250 sat/kwu)
        let new_fee_rate_slightly_higher =
            FeeRate::from_sat_per_kwu(previous_rate.to_sat_per_kwu() + 1);
        let expected_min_bump =
            FeeRate::from_sat_per_kwu(previous_rate.to_sat_per_kwu() + incremental_fee_sat_per_kwu);

        let result = tx_sender
            .calculate_target_fee_rate(
                Some(previous_rate),
                new_fee_rate_slightly_higher,
                Some(100),
                100,
            )
            .await
            .unwrap();

        // Result should be previous + incremental, NOT the new_fee_rate
        assert_eq!(
            result, expected_min_bump,
            "When new_fee_rate ({} sat/kwu) is higher than previous ({} sat/kwu) but lower than \
             previous + incremental ({} sat/kwu), result should be previous + incremental, not new_fee_rate",
            new_fee_rate_slightly_higher.to_sat_per_kwu(),
            previous_rate.to_sat_per_kwu(),
            expected_min_bump.to_sat_per_kwu()
        );
        assert!(
            result.to_sat_per_kwu() > new_fee_rate_slightly_higher.to_sat_per_kwu(),
            "Result ({} sat/kwu) should be greater than new_fee_rate ({} sat/kwu) due to BIP125 min increment",
            result.to_sat_per_kwu(),
            new_fee_rate_slightly_higher.to_sat_per_kwu()
        );

        // Test 3: New fee rate higher than previous + incremental - should use new_fee_rate
        let previous_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let new_fee_rate_much_higher = FeeRate::from_sat_per_vb(20).unwrap(); // Much higher than previous + incremental
        let result = tx_sender
            .calculate_target_fee_rate(
                Some(previous_rate),
                new_fee_rate_much_higher,
                Some(100),
                100,
            )
            .await
            .unwrap();
        assert_eq!(
            result, new_fee_rate_much_higher,
            "When new_fee_rate is much higher than previous + incremental, should use new_fee_rate"
        );

        // Test 4: Same fee rate, not stuck - should return previous rate
        let previous_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let new_fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let result = tx_sender
            .calculate_target_fee_rate(Some(previous_rate), new_fee_rate, Some(95), 100) // Only 5 blocks
            .await
            .unwrap();
        assert_eq!(
            result, previous_rate,
            "Should return previous rate when not stuck and same fee rate"
        );

        // Test 5: Same fee rate but stuck for 10+ blocks - should bump
        let previous_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let new_fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
        let result = tx_sender
            .calculate_target_fee_rate(Some(previous_rate), new_fee_rate, Some(90), 100) // 10 blocks stuck
            .await
            .unwrap();
        let expected_stuck_bump =
            FeeRate::from_sat_per_kwu(previous_rate.to_sat_per_kwu() + incremental_fee_sat_per_kwu);
        assert_eq!(
            result, expected_stuck_bump,
            "When stuck for 10+ blocks, should bump to previous + incremental"
        );

        // Test 6: Hard cap is respected
        let previous_rate = FeeRate::from_sat_per_vb(90).unwrap();
        let new_fee_rate = FeeRate::from_sat_per_vb(200).unwrap(); // Way above hard cap (default 100)
        let result = tx_sender
            .calculate_target_fee_rate(Some(previous_rate), new_fee_rate, Some(90), 100)
            .await
            .unwrap();
        let hard_cap = FeeRate::from_sat_per_vb(config.tx_sender_limits.fee_rate_hard_cap).unwrap();
        assert!(
            result <= hard_cap,
            "Result {} should be <= hard cap {}",
            result.to_sat_per_vb_ceil(),
            hard_cap.to_sat_per_vb_ceil()
        );
    }
}
