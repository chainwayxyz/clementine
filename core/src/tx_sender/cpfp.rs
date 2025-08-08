use eyre::eyre;
use std::env;

use bitcoin::{Amount, FeeRate, OutPoint, Transaction, TxOut, Weight};
use bitcoincore_rpc::PackageSubmissionResult;
use bitcoincore_rpc::{PackageTransactionResult, RpcApi};
use eyre::Context;

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

use super::{Result, SendTxError, TxMetadata, TxSender};

impl TxSender {
    /// Creates and broadcasts a new "fee payer" UTXO to be used for CPFP.
    ///
    /// This function is called when a CPFP attempt fails due to insufficient funds
    /// in the existing confirmed fee payer UTXOs associated with a transaction (`bumped_id`).
    /// It calculates the required fee based on the parent transaction (`tx`) and the current
    /// `fee_rate`, adding a buffer (3x required fee + dust limit) to handle potential fee spikes.
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

        // Aggressively add 3x required fee to the total amount to account for sudden spikes
        let new_fee_payer_amount = (required_fee - total_fee_payer_amount)
            + required_fee
            + required_fee
            + required_fee
            + MIN_TAPROOT_AMOUNT;

        tracing::debug!(
            "Creating fee payer UTXO with amount {} ({} sat/vb)",
            new_fee_payer_amount,
            fee_rate
        );

        let outpoint = self
            .rpc
            .send_to_address(&self.signer.address, new_fee_payer_amount)
            .await
            .map_to_eyre()?;

        self.db
            .save_fee_payer_tx(
                None,
                bumped_id,
                outpoint.txid,
                outpoint.vout,
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
    /// A `Vec` containing the parent transaction followed by the child transaction,
    /// ready for submission via the `submitpackage` RPC.
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
    /// A `Vec` of `SpendableTxIn`, ready to be included as inputs in the CPFP child tx.
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
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, bumped_id, fee_rate))]
    async fn _bump_fees_of_fee_payer_txs(&self, bumped_id: u32, fee_rate: FeeRate) -> Result<()> {
        let bumpable_fee_payer_txs = self
            .db
            .get_bumpable_fee_payer_txs(None, bumped_id)
            .await
            .map_to_eyre()?;

        for (id, fee_payer_txid, vout, amount) in bumpable_fee_payer_txs {
            tracing::debug!(
                "Bumping fee for fee payer tx {} with bumped tx {} for fee rate {}",
                fee_payer_txid,
                bumped_id,
                fee_rate
            );
            let new_txi_result = self
                .rpc
                .bump_fee_with_fee_rate(fee_payer_txid, fee_rate)
                .await;

            match new_txi_result {
                Ok(new_txid) => {
                    if new_txid != fee_payer_txid {
                        self.db
                            .save_fee_payer_tx(None, bumped_id, new_txid, vout, amount, Some(id))
                            .await
                            .map_to_eyre()?;
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
                            tracing::warn!("Failed to bump fee the fee payer tx {} of bumped tx {} with error {e}, skipping", fee_payer_txid, bumped_id);
                            continue;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Sends a transaction using the Child-Pays-For-Parent (CPFP) strategy.
    ///
    /// # Logic:
    /// 1.  **Check Unconfirmed Fee Payers:** Ensures no unconfirmed fee payer UTXOs exist
    ///     for this `try_to_send_id`. If they do, returns `UnconfirmedFeePayerUTXOsLeft`
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
    ) -> Result<()> {
        let unconfirmed_fee_payer_utxos = self
            .db
            .get_bumpable_fee_payer_txs(None, try_to_send_id)
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

        // let effective_fee_rate = Self::btc_per_kvb_to_fee_rate(effective_fee_rate_btc_per_kvb);
        // Save the effective fee rate to the db
        self.db
            .update_effective_fee_rate(None, try_to_send_id, fee_rate)
            .await
            .wrap_err("Failed to update effective fee rate")?;

        // Sanity check to make sure the fee rate is equal to the required fee rate
        // assert_eq!(
        //     effective_fee_rate, fee_rate,
        //     "Effective fee rate is not equal to the required fee rate: {:?} to {:?} != {:?}",
        //     effective_fee_rate_btc_per_kvb, effective_fee_rate, fee_rate
        // );

        Ok(())
    }
}
