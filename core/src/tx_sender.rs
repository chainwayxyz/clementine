use bitcoin::hashes::Hash;
use bitcoin::taproot::{self, TaprootSpendInfo};
use eyre::{eyre, OptionExt};
use std::{collections::BTreeMap, env, time::Duration};

use bitcoin::{
    consensus, transaction::Version, Address, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid,
    Weight,
};
use bitcoincore_rpc::PackageSubmissionResult;
use bitcoincore_rpc::{json::EstimateMode, PackageTransactionResult, RpcApi};
use eyre::Context;
use serde::{Deserialize, Serialize};
use tonic::async_trait;

use crate::errors::{ErrorExt, ResultExt};
use crate::extended_rpc::BitcoinRPCError;
use crate::rpc;
use crate::task::{IgnoreError, WithDelay};
use crate::{
    actor::Actor,
    bitcoin_syncer::BitcoinSyncerEvent,
    builder::{
        self,
        script::SpendPath,
        transaction::{
            input::{get_watchtower_challenge_utxo_vout, SpendableTxIn},
            output::UnspentTxOut,
            TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE,
        },
    },
    config::BridgeConfig,
    constants::MIN_TAPROOT_AMOUNT,
    database::{Database, DatabaseTransaction},
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    rpc::clementine::NormalSignatureKind,
    task::{IntoTask, Task, TaskExt},
};

const POLL_DELAY: Duration = if cfg!(test) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(1)
};

/// Manages the process of sending Bitcoin transactions, including handling fee bumping
/// strategies like Replace-By-Fee (RBF) and Child-Pays-For-Parent (CPFP).
///
/// It interacts with a Bitcoin Core RPC endpoint (`ExtendedRpc`) to query network state
/// (like fee rates) and submit transactions. It uses a `Database` to persist transaction
/// state, track confirmation status, and manage associated data like fee payer UTXOs.
/// The `Actor` provides signing capabilities for transactions controlled by this service.
#[derive(Clone, Debug)]
pub struct TxSender {
    pub signer: Actor,
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub network: bitcoin::Network,
    pub btc_syncer_consumer_id: String,
    cached_spendinfo: TaprootSpendInfo,
}

/// Specifies the fee bumping strategy used for a transaction.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, sqlx::Type)]
#[sqlx(type_name = "fee_paying_type", rename_all = "lowercase")]
pub enum FeePayingType {
    /// Child-Pays-For-Parent: A new "child" transaction is created, spending an output
    /// from the original "parent" transaction. The child pays a high fee, sufficient
    /// to cover both its own cost and the parent's fee deficit, incentivizing miners
    /// to confirm both together. Specifically, we utilize "fee payer" UTXOs.
    CPFP,
    /// Replace-By-Fee: The original unconfirmed transaction is replaced with a new
    /// version that includes a higher fee. The original transaction must signal
    /// RBF enablement (e.g., via nSequence). Bitcoin Core's `bumpfee` RPC is often used.
    RBF,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ActivatedWithTxid {
    pub txid: Txid,
    pub relative_block_height: u32,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct ActivatedWithOutpoint {
    pub outpoint: OutPoint,
    pub relative_block_height: u32,
}

#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxMetadata {
    pub deposit_outpoint: Option<OutPoint>,
    pub operator_idx: Option<u32>,
    pub verifier_idx: Option<u32>,
    pub round_idx: Option<u32>,
    pub kickoff_idx: Option<u32>,
    pub tx_type: TransactionType,
}
impl std::fmt::Debug for TxMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg_struct = f.debug_struct("TxMetadata");
        if let Some(deposit_outpoint) = self.deposit_outpoint {
            dbg_struct.field("deposit_outpoint", &deposit_outpoint);
        }
        if let Some(operator_idx) = self.operator_idx {
            dbg_struct.field("operator_idx", &operator_idx);
        }
        if let Some(verifier_idx) = self.verifier_idx {
            dbg_struct.field("verifier_idx", &verifier_idx);
        }
        if let Some(round_idx) = self.round_idx {
            dbg_struct.field("round_idx", &round_idx);
        }
        if let Some(kickoff_idx) = self.kickoff_idx {
            dbg_struct.field("kickoff_idx", &kickoff_idx);
        }
        dbg_struct.field("tx_type", &self.tx_type);
        dbg_struct.finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendTxError {
    #[error("Unconfirmed fee payer UTXOs left")]
    UnconfirmedFeePayerUTXOsLeft,
    #[error("Insufficient fee payer amount")]
    InsufficientFeePayerAmount,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

type Result<T> = std::result::Result<T, SendTxError>;

#[derive(Debug)]
pub struct TxSenderTask {
    db: Database,
    current_tip_height: u32,
    inner: TxSender,
}

#[async_trait]
impl Task for TxSenderTask {
    type Output = bool;

    async fn run_once(&mut self) -> std::result::Result<Self::Output, BridgeError> {
        let mut dbtx = self.db.begin_transaction().await.map_to_eyre()?;

        let is_block_update = async {
            let Some(event) = self
                .db
                .fetch_next_bitcoin_syncer_evt(&mut dbtx, &self.inner.btc_syncer_consumer_id)
                .await?
            else {
                return Ok(false);
            };

            match event {
                BitcoinSyncerEvent::NewBlock(block_id) => {
                    self.db.confirm_transactions(&mut dbtx, block_id).await?;
                    self.current_tip_height = self
                        .db
                        .get_block_info_from_id(Some(&mut dbtx), block_id)
                        .await?
                        .ok_or(BridgeError::Error("Block not found".to_string()))?
                        .1;

                    tracing::trace!("TXSENDER: Confirmed transactions for block {}", block_id);
                }
                BitcoinSyncerEvent::ReorgedBlock(block_id) => {
                    tracing::trace!("TXSENDER: Unconfirming transactions for block {}", block_id);
                    self.db.unconfirm_transactions(&mut dbtx, block_id).await?;
                }
            }

            dbtx.commit().await?;
            Ok::<_, BridgeError>(true)
        }
        .await?;

        if is_block_update {
            // Pull in all block updates before trying to send.
            return Ok(true);
        }

        tracing::trace!("TXSENDER: Getting fee rate");
        let fee_rate = self.inner.get_fee_rate().await?;
        tracing::trace!("TXSENDER: Trying to send unconfirmed txs");

        // Main loop which handles sending unconfirmed txs
        self.inner
            .try_to_send_unconfirmed_txs(fee_rate, self.current_tip_height)
            .await?;

        Ok(false)
    }
}

impl IntoTask for TxSender {
    type Task = WithDelay<IgnoreError<TxSenderTask>>;

    fn into_task(self) -> Self::Task {
        TxSenderTask {
            db: self.db.clone(),
            current_tip_height: 0,
            inner: self,
        }
        .ignore_error()
        .with_delay(POLL_DELAY)
    }
}

impl TxSender {
    pub fn new(
        signer: Actor,
        rpc: ExtendedRpc,
        db: Database,
        btc_syncer_consumer_id: String,
        network: bitcoin::Network,
    ) -> Self {
        Self {
            cached_spendinfo: builder::address::create_taproot_address(
                &[],
                Some(signer.xonly_public_key),
                network,
            )
            .1,
            signer,
            rpc,
            db,
            btc_syncer_consumer_id,
            network,
        }
    }

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

    /// Gets the current recommended fee rate from the Bitcoin Core node.
    ///
    /// Uses the `estimatesmartfee` RPC call with a confirmation target of 1 block
    /// and conservative estimation mode.
    ///
    /// If fee estimation is unavailable (e.g., node is warming up), it returns
    /// an error, except in Regtest mode where it defaults to 1 sat/vB for testing convenience.
    ///
    /// TODO: Implement more sophisticated fee estimation (e.g., mempool.space API).
    async fn get_fee_rate(&self) -> Result<FeeRate> {
        let fee_rate = self
            .rpc
            .client
            .estimate_smart_fee(1, Some(EstimateMode::Conservative))
            .await
            .wrap_err("Failed to estimate smart fee")?;

        match fee_rate.fee_rate {
            Some(fee_rate) => Ok(FeeRate::from_sat_per_kwu(fee_rate.to_sat())),
            None => {
                if self.network == bitcoin::Network::Regtest {
                    tracing::trace!("Using fee rate of 1 sat/vb (Regtest mode)");
                    return Ok(FeeRate::from_sat_per_vb_unchecked(1));
                }

                Err(eyre::eyre!("Fee estimation error: {:?}", fee_rate.errors).into())
            }
        }
    }

    /// Calculates the total fee required for a transaction package based on the fee bumping strategy.
    ///
    /// # Arguments
    /// * `parent_tx_weight` - The weight of the main transaction being bumped.
    /// * `num_fee_payer_utxos` - The number of fee payer UTXOs used (relevant for child tx size in CPFP).
    /// * `fee_rate` - The target fee rate (sat/kwu or similar).
    /// * `fee_paying_type` - The strategy being used (CPFP or RBF).
    ///
    /// # Calculation Logic
    /// *   **CPFP:** Calculates the weight of the hypothetical child transaction based on the
    ///     number of fee payer inputs and standard P2TR output sizes. It then calculates the
    ///     fee based on the *combined virtual size* (vbytes) of the parent and child transactions,
    ///     as miners evaluate the package deal.
    /// *   **RBF:** Calculates the weight of the replacement transaction itself (assuming inputs
    ///     and potentially outputs change slightly). The fee is calculated based on the weight
    ///     of this single replacement transaction.
    ///
    /// Reference for weight estimates: <https://bitcoin.stackexchange.com/a/116959>
    fn calculate_required_fee(
        parent_tx_weight: Weight,
        num_fee_payer_utxos: usize,
        fee_rate: FeeRate,
        fee_paying_type: FeePayingType,
    ) -> Result<Amount> {
        // Estimate the weight of the child transaction (for CPFP) or the RBF replacement.
        // P2TR input witness adds ~57.5vbytes (230 WU). P2TR output adds 43 vbytes (172 WU).
        // Base transaction overhead (version, locktime, input/output counts) ~ 10.5 vBytes (42 WU)
        // Anchor input marker (OP_FALSE OP_RETURN ..) adds overhead. Exact WU TBD.
        // For CPFP child: (N fee payer inputs) + (1 anchor input) + (1 change output)
        // For RBF replacement: (N fee payer inputs) + (1 change output) - assuming it replaces a tx with an anchor.
        // TODO: Refine these weight estimations.
        let child_tx_weight = match fee_paying_type {
            // CPFP Child: N fee payer inputs + 1 anchor input + 1 change output + base overhead.
            // Approx WU: (230 * num_fee_payer_utxos) + 230 + 172 + base_overhead_wu
            // Simplified calculation used here needs verification.
            FeePayingType::CPFP => Weight::from_wu_usize(230 * num_fee_payer_utxos + 207 + 172), // TODO: Verify 207 WU for anchor input + overhead
            // RBF Replacement: N fee payer inputs + 1 change output + base overhead.
            // Assumes it replaces a tx of similar structure but potentially different inputs/fees.
            // Simplified calculation used here needs verification.
            FeePayingType::RBF => Weight::from_wu_usize(230 * num_fee_payer_utxos + 172), // TODO: Verify WU for RBF structure
        };

        // Calculate total weight for fee calculation.
        // For CPFP, miners consider the effective fee rate over the combined *vbytes* of parent + child.
        // For RBF, miners consider the fee rate of the single replacement transaction's weight.
        let total_weight = match fee_paying_type {
            FeePayingType::CPFP => Weight::from_vb_unchecked(
                child_tx_weight.to_vbytes_ceil() + parent_tx_weight.to_vbytes_ceil(),
            ),
            FeePayingType::RBF => child_tx_weight + parent_tx_weight, // Should likely just be the RBF tx weight? Check RBF rules.
        };

        fee_rate
            .checked_mul_by_weight(total_weight)
            .ok_or_eyre("Fee calculation overflow")
            .map_err(Into::into)
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
    /// Currently, it signs the input spending the P2A anchor and potentially the first fee payer UTXO.
    /// TODO: Ensure *all* fee payer UTXO inputs are correctly signed if more than one is used.
    ///
    /// # Returns
    /// The constructed and partially signed child transaction.
    fn create_child_tx(
        &self,
        p2a_anchor: OutPoint,
        fee_payer_utxos: Vec<SpendableTxIn>,
        parent_tx_size: Weight,
        fee_rate: FeeRate,
        change_address: Address,
    ) -> Result<Transaction> {
        let required_fee = Self::calculate_required_fee(
            parent_tx_size,
            fee_payer_utxos.len(),
            fee_rate,
            FeePayingType::CPFP,
        )
        .map_err(|e| eyre!(e))?;

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + builder::transaction::anchor_output().value; // We add the anchor output value to the total amount.

        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(SendTxError::InsufficientFeePayerAmount);
        }

        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new_partial(p2a_anchor, builder::transaction::anchor_output()),
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

        let sighash = tx_handler
            .calculate_pubkey_spend_sighash(1, bitcoin::TapSighashType::Default)
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
                1,
            )
            .map_err(|e| eyre!(e))?;
        let child_tx = tx_handler.get_cached_tx().clone();
        Ok(child_tx)
    }

    fn is_p2a_anchor(&self, output: &TxOut) -> bool {
        output.value == builder::transaction::anchor_output().value
            && output.script_pubkey == builder::transaction::anchor_output().script_pubkey
    }

    fn find_p2a_vout(&self, tx: &Transaction) -> Result<usize> {
        let p2a_anchor = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| self.is_p2a_anchor(output));
        if let Some((vout, _)) = p2a_anchor {
            Ok(vout)
        } else {
            Err(eyre::eyre!("P2A anchor output not found in transaction").into())
        }
    }

    /// Submit package returns the effective fee rate in btc/kvb.
    /// This function converts the btc/kvb to a fee rate in sat/vb.
    #[allow(dead_code)]
    fn btc_per_kvb_to_fee_rate(btc_per_kvb: f64) -> FeeRate {
        FeeRate::from_sat_per_vb_unchecked((btc_per_kvb * 100000.0) as u64)
    }

    /// Creates a transaction package for CPFP submission.
    ///
    /// Finds the P2A anchor output in the parent transaction (`tx`), then constructs
    /// the child transaction using `create_child_tx`.
    ///
    /// # Returns
    /// A `Vec` containing the parent transaction followed by the child transaction,
    /// ready for submission via the `submitpackage` RPC.
    fn create_package(
        &self,
        tx: Transaction,
        fee_rate: FeeRate,
        fee_payer_utxos: Vec<SpendableTxIn>,
    ) -> Result<Vec<Transaction>> {
        let txid = tx.compute_txid();

        let p2a_vout = self
            .find_p2a_vout(&tx)
            .wrap_err("Failed to find p2a vout")?;

        let child_tx = self
            .create_child_tx(
                OutPoint {
                    txid,
                    vout: p2a_vout as u32,
                },
                fee_payer_utxos,
                tx.weight(),
                fee_rate,
                self.signer.address.clone(),
            )
            .wrap_err("Failed to create child tx")?;

        Ok(vec![tx, child_tx])
    }

    /// Sends or bumps a transaction using the Replace-By-Fee (RBF) strategy.
    ///
    /// It interacts with the database to track the latest RBF attempt (`last_rbf_txid`).
    ///
    /// # Logic:
    /// 1.  **Check for Existing RBF Tx:** Retrieves `last_rbf_txid` for the `try_to_send_id`.
    /// 2.  **Bump Existing Tx:** If `last_rbf_txid` exists, it calls `rpc.bump_fee_with_fee_rate`.
    ///     - This internally uses the Bitcoin Core `bumpfee` RPC.
    ///     - It handles cases where the tx is already confirmed or its inputs are spent.
    ///     - If `bumpfee` succeeds and returns a *new* txid, the database is updated.
    /// 3.  **Send Initial RBF Tx:** If no `last_rbf_txid` exists (first attempt):
    ///     - It uses `fund_raw_transaction` RPC to let the wallet add inputs, potentially
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
    async fn send_rbf_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        tx_metadata: Option<TxMetadata>,
        fee_rate: FeeRate,
    ) -> Result<()> {
        tracing::debug!(?tx_metadata, "Sending RBF tx",);

        tracing::debug!(?try_to_send_id, "Attempting to send.");

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "preparing_rbf", 0, 0, true)
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
            tracing::debug!(
                ?try_to_send_id,
                "Attempting to bump fee for txid {last_rbf_txid}"
            );

            let bumped_txid = self
                .rpc
                // TODO: convert to psbt_bump_fee
                .bump_fee_with_fee_rate(last_rbf_txid, fee_rate)
                .await;

            // signer.sign_tx

            match bumped_txid {
                Err(e) => {
                    let e = e.into_eyre();

                    match e.root_cause().downcast_ref::<BitcoinRPCError>() {
                        Some(
                            err @ (BitcoinRPCError::TransactionAlreadyInBlock(_)
                            | BitcoinRPCError::BumpFeeUTXOSpent(_)),
                        ) => {
                            tracing::debug!(
                                "RBF tx {} either already in block or UTXO spent, skipping: {:?}",
                                last_rbf_txid,
                                err
                            );

                            tracing::debug!(?try_to_send_id, "RBF tx {last_rbf_txid}: {err}");

                            dbtx.commit()
                                .await
                                .wrap_err("Failed to commit database transaction")?;
                            return Ok(());
                        }
                        _ => {
                            // Record error in debug log
                            let error_message = format!("RBF bump error: {}", e);
                            let _ = self
                                .db
                                .save_tx_debug_submission_error(try_to_send_id, &error_message)
                                .await;

                            let _ = self
                                .db
                                .update_tx_debug_sending_state(
                                    try_to_send_id,
                                    "rbf_bump_failed",
                                    0,
                                    0,
                                    true,
                                )
                                .await;

                            tracing::debug!(?try_to_send_id, "RBF bump failed: {e:?}");

                            return Err(e.into_eyre().into());
                        }
                    }
                }
                Ok(bumped_txid) if bumped_txid != last_rbf_txid => {
                    tracing::debug!(
                        ?try_to_send_id,
                        "RBF tx {last_rbf_txid} bumped to {bumped_txid}"
                    );

                    let _ = self
                        .db
                        .update_tx_debug_sending_state(try_to_send_id, "rbf_bumped", 0, 0, true)
                        .await;

                    self.db
                        .save_rbf_txid(Some(&mut dbtx), try_to_send_id, bumped_txid)
                        .await
                        .wrap_err("Failed to save RBF txid")?;
                }
                Ok(_) => {
                    tracing::debug!(?try_to_send_id, "RBF tx was not bumped: {last_rbf_txid}");
                }
            }
        } else {
            tracing::debug!(?try_to_send_id, "Funding initial RBF tx");

            let _ = self
                .db
                .update_tx_debug_sending_state(try_to_send_id, "funding_initial_rbf", 0, 0, true)
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

            match fund_result {
                Err(e) => {
                    // Record funding error in debug log
                    let error_message = format!("Failed to fund RBF tx: {:?}", e);

                    let _ = self
                        .db
                        .save_tx_debug_submission_error(try_to_send_id, &error_message)
                        .await;
                    tracing::warn!(try_to_send_id, "Failed to fund RBF tx: {:?}", e);

                    let _ = self
                        .db
                        .update_tx_debug_sending_state(
                            try_to_send_id,
                            "rbf_funding_failed",
                            0,
                            0,
                            true,
                        )
                        .await;

                    dbtx.commit()
                        .await
                        .wrap_err("Failed to commit database transaction")?;
                    return Err(eyre::eyre!(e).into());
                }
                Ok(funded_result) => {
                    let funded_tx = &funded_result.hex;

                    // Record successful funding in debug log
                    tracing::debug!(
                        try_to_send_id,
                        "Successfully funded RBF tx with fee {}",
                        funded_result.fee
                    );

                    // Deserialize the funded transaction
                    let funded_tx_deser: Transaction = consensus::deserialize(&funded_result.hex)
                        .wrap_err("failed to deserialize tx")?;

                    if funded_tx_deser.output.len() != tx.output.len() {
                        let mut should_warn = false;
                        for inp in tx.input.iter() {
                            if inp.witness.len() == 1 {
                                // taproot keyspend witness
                                if let Ok(sig) = taproot::Signature::from_slice(&inp.witness[0]) {
                                    if sig.sighash_type
                                        != bitcoin::TapSighashType::SinglePlusAnyoneCanPay
                                    {
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

                    // Attempt to sign the transaction
                    let sign_result = self
                        .rpc
                        .client
                        .sign_raw_transaction_with_wallet(funded_tx, None, None)
                        .await;

                    match sign_result {
                        Err(e) => {
                            let error_message = format!("Failed to sign RBF tx: {:?}", e);

                            let _ = self
                                .db
                                .save_tx_debug_submission_error(try_to_send_id, &error_message)
                                .await;

                            tracing::warn!(try_to_send_id, "{}", error_message);

                            return Err(eyre::eyre!(e).into());
                        }
                        Ok(signed_result) => {
                            // Record successful signing in debug log
                            tracing::debug!(try_to_send_id, "Successfully signed RBF tx");

                            // Deserialize the signed transaction
                            let signed_tx: Transaction =
                                match bitcoin::consensus::deserialize(&signed_result.hex) {
                                    Ok(tx) => tx,
                                    Err(e) => {
                                        let _ = self
                                            .db
                                            .save_tx_debug_submission_error(
                                                try_to_send_id,
                                                &format!(
                                                    "Failed to deserialize signed tx: {:?}",
                                                    e
                                                ),
                                            )
                                            .await;

                                        tracing::warn!(
                                            try_to_send_id,
                                            "Failed to deserialize signed tx: {e:?}"
                                        );

                                        return Err(eyre::eyre!(
                                            "Failed to deserialize signed tx: {}",
                                            e
                                        )
                                        .into());
                                    }
                                };

                            // Attempt to broadcast the transaction
                            let send_result =
                                self.rpc.client.send_raw_transaction(&signed_tx).await;

                            match send_result {
                                Err(e) => {
                                    let _ = self
                                        .db
                                        .save_tx_debug_submission_error(
                                            try_to_send_id,
                                            &format!("Failed to broadcast RBF tx: {}", e),
                                        )
                                        .await;
                                    tracing::warn!(try_to_send_id, "RBF broadcast failed: {e:?}");

                                    return Err(eyre::eyre!(e).into());
                                }
                                Ok(txid) => {
                                    // Record successful broadcast in debug log
                                    tracing::debug!(
                                        try_to_send_id,
                                        "Successfully sent RBF tx with txid {}",
                                        txid
                                    );

                                    // Update debug sending state
                                    let _ = self
                                        .db
                                        .update_tx_debug_sending_state(
                                            try_to_send_id,
                                            "sent",
                                            0,
                                            0,
                                            true,
                                        )
                                        .await;

                                    self.db
                                        .save_rbf_txid(Some(&mut dbtx), try_to_send_id, txid)
                                        .await
                                        .wrap_err("Failed to save RBF txid")?;
                                }
                            }
                        }
                    }
                }
            }
        }

        dbtx.commit()
            .await
            .wrap_err("Failed to commit database transaction")?;

        Ok(())
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
    async fn send_cpfp_tx(
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
            let confirmed_utxos = self
                .db
                .get_confirmed_fee_payer_utxos(None, try_to_send_id)
                .await
                .map_to_eyre()?;

            // Update the sending state
            let _ = self
                .db
                .update_tx_debug_sending_state(
                    try_to_send_id,
                    "waiting_for_utxo_confirmation",
                    (unconfirmed_fee_payer_utxos.len() + confirmed_utxos.len()) as u32,
                    confirmed_utxos.len() as u32,
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
            .update_tx_debug_sending_state(
                try_to_send_id,
                "creating_package",
                confirmed_fee_payer_len as u32,
                confirmed_fee_payer_len as u32,
                true,
            )
            .await;

        // to be used below
        let total_fee_payer_amount = confirmed_fee_payers
            .iter()
            .map(|txi| txi.get_prevout().value)
            .sum::<Amount>();

        let package = self
            .create_package(tx.clone(), fee_rate, confirmed_fee_payers)
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
                            confirmed_fee_payer_len as u32 + 1,
                            confirmed_fee_payer_len as u32,
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
            .update_tx_debug_sending_state(
                try_to_send_id,
                "submitting_package",
                confirmed_fee_payer_len as u32,
                confirmed_fee_payer_len as u32,
                true,
            )
            .await;

        tracing::debug!(try_to_send_id, "Submitting package, size {}", package.len());

        // TODO: this currently doesn't return valid results as TRUC is not fully supported.
        // let test_mempool_result = self
        //     .rpc
        //     .client
        //     .test_mempool_accept(&package_refs)
        //     .await
        //     .wrap_err("Failed to test mempool accept")?;

        let submit_package_result: PackageSubmissionResult = self
            .rpc
            .client
            .submit_package(&package_refs)
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
                tracing::error!(try_to_send_id, "Error submitting package: {:?}", error);

                // TODO: implement txid checking so we can save the correct error.

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

    /// Dispatches the transaction sending logic based on its `FeePayingType`.
    ///
    /// Retrieves the transaction details and its associated `FeePayingType` from the database.
    /// Calls either `send_rbf_tx` or `send_cpfp_tx` accordingly.
    ///
    /// # Arguments
    /// * `try_to_send_id` - The database ID tracking this send attempt.
    /// * `fee_rate` - The target fee rate for the bump attempt.
    async fn send_tx(&self, try_to_send_id: u32, fee_rate: FeeRate) -> Result<()> {
        let (tx_metadata, tx, fee_paying_type, _) = self
            .db
            .get_tx(None, try_to_send_id)
            .await
            .wrap_err("Failed to get tx")?;

        match fee_paying_type {
            FeePayingType::RBF => {
                self.send_rbf_tx(try_to_send_id, tx, tx_metadata, fee_rate)
                    .await
            }
            FeePayingType::CPFP => {
                self.send_cpfp_tx(try_to_send_id, tx, tx_metadata, fee_rate)
                    .await
            }
        }
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
    async fn bump_fees_of_fee_payer_txs(&self, bumped_id: u32, fee_rate: FeeRate) -> Result<()> {
        let bumpable_fee_payer_txs = self
            .db
            .get_bumpable_fee_payer_txs(None, bumped_id)
            .await
            .map_to_eyre()?;

        for (id, fee_payer_txid, vout, amount) in bumpable_fee_payer_txs {
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

    /// The main loop for processing transactions requiring fee bumps or initial sending.
    ///
    /// Fetches transactions from the database that are eligible to be sent or bumped
    /// based on the `new_fee_rate` and `current_tip_height`.
    ///
    /// For each eligible transaction (`id`):
    /// 1.  **Bump Fee Payers:** Calls `bump_fees_of_fee_payer_txs` to ensure any associated,
    ///     unconfirmed fee payer UTXOs (used for CPFP) are themselves confirmed.
    /// 2.  **Send/Bump Main Tx:** Calls `send_tx` to either perform RBF or CPFP on the main
    ///     transaction (`id`) using the `new_fee_rate`.
    /// 3.  **Handle Errors:**
    ///     - `UnconfirmedFeePayerUTXOsLeft`: Skips the current tx, waiting for fee payers to confirm.
    ///     - `InsufficientFeePayerAmount`: Calls `create_fee_payer_utxo` to provision more funds
    ///       for a future CPFP attempt.
    ///     - Other errors are logged.
    ///
    /// # Arguments
    /// * `new_fee_rate` - The current target fee rate based on network conditions.
    /// * `current_tip_height` - The current blockchain height, used for time-lock checks.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, new_fee_rate, current_tip_height))]
    async fn try_to_send_unconfirmed_txs(
        &self,
        new_fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<()> {
        let txs = self
            .db
            .get_sendable_txs(None, new_fee_rate, current_tip_height)
            .await
            .map_to_eyre()?;

        if !txs.is_empty() {
            tracing::debug!("Trying to send {} sendable txs ", txs.len());
        }

        for id in txs {
            // Update debug state
            tracing::debug!(
                try_to_send_id = id,
                "Processing TX in try_to_send_unconfirmed_txs with fee rate {new_fee_rate}",
            );

            let (tx_metadata, tx, fee_paying_type, seen_block_id) =
                match self.db.get_tx(None, id).await {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::error!("Sending Tx {}: Failed to get tx details: {:?}", id, e);

                        // Update debug error
                        let _ = self
                            .db
                            .save_tx_debug_submission_error(
                                id,
                                &format!("Failed to get tx details: {}", e),
                            )
                            .await;

                        continue;
                    }
                };

            // Check if the transaction is already confirmed
            if let Some(block_id) = seen_block_id {
                // Update debug state to confirm
                tracing::debug!(
                    try_to_send_id = id,
                    "Transaction confirmed in block {}",
                    block_id
                );

                // Update sending state
                let _ = self
                    .db
                    .update_tx_debug_sending_state(
                        id,
                        "confirmed",
                        0, // Not relevant for confirmed tx
                        0,
                        true,
                    )
                    .await;

                // We could purge debug info here if needed
                // self.db.purge_tx_debug_info(None, id).await.ok();

                continue;
            }

            let result = match fee_paying_type {
                FeePayingType::CPFP => self.send_cpfp_tx(id, tx, tx_metadata, new_fee_rate).await,
                FeePayingType::RBF => self.send_rbf_tx(id, tx, tx_metadata, new_fee_rate).await,
            };

            if let Err(e) = result {
                tracing::error!(try_to_send_id = id, "Failed to send tx: {:?}", e);
            }
        }

        Ok(())
    }

    pub fn client(&self) -> TxSenderClient {
        TxSenderClient::new(self.db.clone(), self.btc_syncer_consumer_id.clone())
    }
}

#[derive(Debug, Clone)]
pub struct TxSenderClient {
    db: Database,
    tx_sender_consumer_id: String,
}

impl TxSenderClient {
    pub fn new(db: Database, tx_sender_consumer_id: String) -> Self {
        Self {
            db,
            tx_sender_consumer_id,
        }
    }

    /// Saves a transaction to the database queue for sending/fee bumping.
    ///
    /// This function determines the initial parameters for a transaction send attempt,
    /// including its `FeePayingType`, associated metadata, and dependencies (cancellations/activations).
    /// It then persists this information in the database via `db.save_tx` and related functions.
    /// The actual sending logic (CPFP/RBF) is handled later by the `TxSender` task loop.
    ///
    /// # Default activation and cancellation conditions
    ///
    /// By default, this function automatically adds cancellation conditions for all outpoints
    /// spent by the `signed_tx` itself. If `signed_tx` confirms, these input outpoints
    /// are marked as spent/cancelled in the database.
    ///
    /// There are no default activation conditions added implicitly; all activation prerequisites
    /// must be explicitly provided via the `activate_txids` and `activate_outpoints` arguments.
    ///
    /// # Arguments
    /// * `dbtx` - An active database transaction.
    /// * `tx_metadata` - Optional metadata about the transaction's purpose.
    /// * `signed_tx` - The transaction to be potentially sent.
    /// * `fee_paying_type` - Whether to use CPFP or RBF for fee management.
    /// * `cancel_outpoints` - Outpoints that should be marked invalid if this tx confirms (in addition to the tx's own inputs).
    /// * `cancel_txids` - Txids that should be marked invalid if this tx confirms.
    /// * `activate_txids` - Txids that are prerequisites for this tx, potentially with a relative timelock.
    /// * `activate_outpoints` - Outpoints that are prerequisites for this tx, potentially with a relative timelock.
    ///
    /// # Returns
    /// The database ID (`try_to_send_id`) assigned to this send attempt.
    #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE), skip_all, fields(?tx_metadata, consumer = self.tx_sender_consumer_id))]
    pub async fn insert_try_to_send(
        &self,
        dbtx: DatabaseTransaction<'_, '_>,
        tx_metadata: Option<TxMetadata>,
        signed_tx: &Transaction,
        fee_paying_type: FeePayingType,
        cancel_outpoints: &[OutPoint],
        cancel_txids: &[Txid],
        activate_txids: &[ActivatedWithTxid],
        activate_outpoints: &[ActivatedWithOutpoint],
    ) -> Result<u32> {
        tracing::debug!(
            "{} added tx {:?}",
            self.tx_sender_consumer_id,
            tx_metadata
                .map(|data| format!("{:?}", data.tx_type))
                .unwrap_or("N/A".to_string()),
        );

        let txid = signed_tx.compute_txid();

        let try_to_send_id = self
            .db
            .save_tx(Some(dbtx), tx_metadata, signed_tx, fee_paying_type, txid)
            .await
            .map_to_eyre()?;

        for input_outpoint in signed_tx.input.iter().map(|input| input.previous_output) {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, input_outpoint)
                .await
                .map_to_eyre()?;
        }

        for outpoint in cancel_outpoints {
            self.db
                .save_cancelled_outpoint(Some(dbtx), try_to_send_id, *outpoint)
                .await
                .map_to_eyre()?;
        }

        for txid in cancel_txids {
            self.db
                .save_cancelled_txid(Some(dbtx), try_to_send_id, *txid)
                .await
                .map_to_eyre()?;
        }

        let mut max_timelock_of_activated_txids = BTreeMap::new();

        for activated_txid in activate_txids {
            let timelock = max_timelock_of_activated_txids
                .entry(activated_txid.txid)
                .or_insert(activated_txid.relative_block_height);
            if *timelock < activated_txid.relative_block_height {
                *timelock = activated_txid.relative_block_height;
            }
        }

        for input in signed_tx.input.iter() {
            let relative_block_height = if input.sequence.is_relative_lock_time() {
                let relative_locktime = input
                    .sequence
                    .to_relative_lock_time()
                    .expect("Invalid relative locktime");
                match relative_locktime {
                    bitcoin::relative::LockTime::Blocks(height) => height.value() as u32,
                    _ => {
                        return Err(eyre::eyre!("Invalid relative locktime").into());
                    }
                }
            } else {
                0
            };
            let timelock = max_timelock_of_activated_txids
                .entry(input.previous_output.txid)
                .or_insert(relative_block_height);
            if *timelock < relative_block_height {
                *timelock = relative_block_height;
            }
        }

        for (txid, timelock) in max_timelock_of_activated_txids {
            self.db
                .save_activated_txid(
                    Some(dbtx),
                    try_to_send_id,
                    &ActivatedWithTxid {
                        txid,
                        relative_block_height: timelock,
                    },
                )
                .await
                .map_to_eyre()?;
        }

        for activated_outpoint in activate_outpoints {
            self.db
                .save_activated_outpoint(Some(dbtx), try_to_send_id, activated_outpoint)
                .await
                .map_to_eyre()?;
        }

        let _ = self
            .db
            .update_tx_debug_sending_state(try_to_send_id, "inserted", 0, 0, false)
            .await;

        Ok(try_to_send_id)
    }

    /// Adds a transaction to the sending queue based on its type and configuration.
    ///
    /// This is a higher-level wrapper around `insert_try_to_send`. It determines the
    /// appropriate `FeePayingType` (CPFP or RBF) and any specific cancellation or activation
    /// dependencies based on the `tx_type` and `config`.
    ///
    /// For example:
    /// - `Challenge` transactions use `RBF`.
    /// - Most other transactions default to `CPFP`.
    /// - Specific types like `OperatorChallengeAck` might activate certain outpoints
    ///   based on related transactions (`kickoff_txid`).
    ///
    /// # Arguments
    /// * `dbtx` - An active database transaction.
    /// * `tx_type` - The semantic type of the transaction.
    /// * `signed_tx` - The transaction itself.
    /// * `related_txs` - Other transactions potentially related (e.g., the kickoff for a challenge ack).
    /// * `tx_metadata` - Optional metadata, `tx_type` will be added/overridden.
    /// * `config` - Bridge configuration providing parameters like finality depth.
    ///
    /// # Returns
    /// The database ID (`try_to_send_id`) assigned to this send attempt.
    pub async fn add_tx_to_queue<'a>(
        &'a self,
        dbtx: DatabaseTransaction<'a, '_>,
        tx_type: TransactionType,
        signed_tx: &Transaction,
        related_txs: &[(TransactionType, Transaction)],
        tx_metadata: Option<TxMetadata>,
        config: &BridgeConfig,
    ) -> Result<u32> {
        let tx_metadata = tx_metadata.map(|mut data| {
            data.tx_type = tx_type;
            data
        });
        match tx_type {
            TransactionType::Kickoff
            | TransactionType::Dummy
            | TransactionType::ChallengeTimeout
            | TransactionType::DisproveTimeout
            | TransactionType::Reimburse
            | TransactionType::Round
            | TransactionType::OperatorChallengeNack(_)
            | TransactionType::UnspentKickoff(_)
            | TransactionType::Payout
            | TransactionType::MoveToVault
            | TransactionType::AssertTimeout(_)
            | TransactionType::Disprove
            | TransactionType::BurnUnusedKickoffConnectors
            | TransactionType::KickoffNotFinalized
            | TransactionType::MiniAssert(_)
            | TransactionType::WatchtowerChallenge(_) => {
                // no_dependency and cpfp
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::Challenge => {
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::RBF,
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::WatchtowerChallengeTimeout(_watchtower_idx) => {
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(tx_type, tx)| {
                        if let TransactionType::Kickoff = tx_type {
                            Some(tx.compute_txid())
                        } else {
                            None
                        }
                    })
                    .ok_or(eyre::eyre!("Couldn't find kickoff tx in related_txs"))?;
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    &[OutPoint {
                        txid: kickoff_txid,
                        vout: 1, // TODO: Make this a function of smth
                    }],
                    &[],
                    &[],
                    &[],
                )
                .await
            }
            TransactionType::OperatorChallengeAck(watchtower_idx) => {
                let kickoff_txid = related_txs
                    .iter()
                    .find_map(|(tx_type, tx)| {
                        if let TransactionType::Kickoff = tx_type {
                            Some(tx.compute_txid())
                        } else {
                            None
                        }
                    })
                    .ok_or(eyre::eyre!("Couldn't find kickoff tx in related_txs"))?;
                self.insert_try_to_send(
                    dbtx,
                    tx_metadata,
                    signed_tx,
                    FeePayingType::CPFP,
                    &[],
                    &[],
                    &[],
                    &[ActivatedWithOutpoint {
                        outpoint: OutPoint {
                            txid: kickoff_txid,
                            vout: get_watchtower_challenge_utxo_vout(watchtower_idx) as u32,
                        },
                        relative_block_height: config.protocol_paramset().finality_depth,
                    }],
                )
                .await
            }
            TransactionType::AllNeededForDeposit | TransactionType::YieldKickoffTxid => {
                unreachable!()
            }
            TransactionType::ReadyToReimburse
            | TransactionType::BaseDeposit
            | TransactionType::ReplacementDeposit => unimplemented!(),
        }
    }

    /// Returns debugging information for a transaction
    ///
    /// This function gathers all debugging information about a transaction from the database,
    /// including its state history, fee payer UTXOs, submission errors, and current state.
    ///
    /// # Arguments
    /// * `tx_id` - The ID of the transaction to debug
    ///
    /// # Returns
    /// A comprehensive debug info structure with all available information about the transaction
    pub async fn debug_tx(&self, tx_id: u32) -> Result<crate::rpc::clementine::TxDebugInfo> {
        use crate::rpc::clementine::{TxDebugFeePayerUtxo, TxDebugInfo, TxDebugSubmissionError};

        let (tx_metadata, tx, fee_paying_type, seen_block_id) =
            self.db.get_tx(None, tx_id).await.map_to_eyre()?;

        let submission_errors = self
            .db
            .get_tx_debug_submission_errors(None, tx_id)
            .await
            .map_to_eyre()?;

        let submission_errors = submission_errors
            .into_iter()
            .map(|(error_message, timestamp)| TxDebugSubmissionError {
                error_message,
                timestamp,
            })
            .collect();

        let (current_state, fee_payer_utxos_count, fee_payer_utxos_confirmed_count) =
            self.db.get_tx_debug_info(None, tx_id).await.map_to_eyre()?;

        let fee_payer_utxos = self
            .db
            .get_tx_debug_fee_payer_utxos(None, tx_id)
            .await
            .map_to_eyre()?;
        let fee_payer_utxos = fee_payer_utxos
            .into_iter()
            .map(|(txid, vout, amount, confirmed)| TxDebugFeePayerUtxo {
                txid: txid.as_raw_hash().to_byte_array().to_vec(),
                vout,
                amount: amount.to_sat(),
                confirmed,
            })
            .collect();

        let txid = tx.compute_txid();
        let debug_info = TxDebugInfo {
            tx_id,
            is_active: seen_block_id.is_none(),
            current_state: current_state.unwrap_or_else(|| "unknown".to_string()),
            submission_errors,
            fee_payer_utxos,
            created_at: "".to_string(),
            txid: txid.as_raw_hash().to_byte_array().to_vec(),
            fee_paying_type: format!("{:?}", fee_paying_type),
            fee_payer_utxos_count: fee_payer_utxos_count.unwrap_or(0),
            fee_payer_utxos_confirmed_count: fee_payer_utxos_confirmed_count.unwrap_or(0),
            raw_tx: bitcoin::consensus::serialize(&tx),
            metadata: tx_metadata.map(|metadata| rpc::clementine::TxMetadata {
                deposit_outpoint: metadata.deposit_outpoint.map(Into::into),
                operator_idx: metadata.operator_idx.unwrap_or(0),
                verifier_idx: metadata.verifier_idx.unwrap_or(0),
                round_idx: metadata.round_idx.unwrap_or(0),
                kickoff_idx: metadata.kickoff_idx.unwrap_or(0),
                tx_type: Some(metadata.tx_type.into()),
            }),
        };

        Ok(debug_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::TweakCache;
    use crate::bitcoin_syncer::BitcoinSyncer;
    use crate::bitvm_client::SECP;
    use crate::builder::script::{CheckSig, SpendableScript};
    use crate::builder::transaction::TransactionType;
    use crate::{database::Database, test::common::*};
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use secp256k1::rand;
    use std::result::Result;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    impl TxSenderClient {
        pub async fn test_dbtx(
            &self,
        ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
            self.db.begin_transaction().await
        }
    }

    async fn create_tx_sender(
        rpc: ExtendedRpc,
    ) -> (
        TxSender,
        BitcoinSyncer,
        ExtendedRpc,
        Database,
        Actor,
        bitcoin::Network,
    ) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = bitcoin::Network::Regtest;
        let actor = Actor::new(sk, None, network);

        let config = create_test_config_with_thread_name().await;

        let db = Database::new(&config).await.unwrap();

        let tx_sender = TxSender::new(
            actor.clone(),
            rpc.clone(),
            db.clone(),
            "tx_sender".into(),
            network,
        );

        (
            tx_sender,
            BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset())
                .await
                .unwrap(),
            rpc,
            db,
            actor,
            network,
        )
    }

    async fn create_bg_tx_sender(
        rpc: ExtendedRpc,
    ) -> (
        TxSenderClient,
        TxSender,
        Vec<oneshot::Sender<()>>,
        ExtendedRpc,
        Database,
        Actor,
        bitcoin::Network,
    ) {
        let (tx_sender, syncer, rpc, db, actor, network) = create_tx_sender(rpc).await;

        let sender_task = tx_sender.clone().into_task().cancelable_loop();
        sender_task.0.into_bg();

        let syncer_task = syncer.into_task().cancelable_loop();
        syncer_task.0.into_bg();

        (
            tx_sender.client(),
            tx_sender,
            vec![sender_task.1, syncer_task.1],
            rpc,
            db,
            actor,
            network,
        )
    }

    async fn create_bumpable_tx(
        rpc: &ExtendedRpc,
        signer: &Actor,
        network: bitcoin::Network,
        fee_paying_type: FeePayingType,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

        let amount = Amount::from_sat(100000);
        let outpoint = rpc.send_to_address(&address, amount).await?;
        rpc.mine_blocks(1).await?;

        let version = match fee_paying_type {
            FeePayingType::CPFP => Version::non_standard(3),
            FeePayingType::RBF => Version::TWO,
        };

        let mut txhandler = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(version)
            .add_input(
                match fee_paying_type {
                    FeePayingType::CPFP => NormalSignatureKind::OperatorSighashDefault,
                    FeePayingType::RBF => NormalSignatureKind::Challenge,
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
                value: amount
                    - builder::transaction::anchor_output().value
                    - MIN_TAPROOT_AMOUNT * 3, // buffer so that rbf works without adding inputs
                script_pubkey: address.script_pubkey(), // TODO: This should be the wallet address, not the signer address
            }))
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .finalize();

        signer
            .tx_sign_and_fill_sigs(&mut txhandler, &[], None)
            .unwrap();

        let tx = txhandler.get_cached_tx().clone();
        Ok(tx)
    }

    #[tokio::test]
    async fn test_try_to_send_duplicate() -> Result<(), BridgeError> {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();

        let (client, _tx_sender, _cancel_txs, rpc, db, signer, network) =
            create_bg_tx_sender(rpc).await;

        let tx = create_bumpable_tx(&rpc, &signer, network, FeePayingType::CPFP)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        let tx_id1 = client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::CPFP,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap();
        let tx_id2 = client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::CPFP,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .unwrap(); // It is ok to call this twice
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

        poll_until_condition(
            async || {
                let (_, _, _, tx_id1_seen_block_id) = db.get_tx(None, tx_id1).await.unwrap();
                let (_, _, _, tx_id2_seen_block_id) = db.get_tx(None, tx_id2).await.unwrap();

                // Wait for tx sender to catch up to bitcoin syncer
                Ok(tx_id2_seen_block_id.is_some() && tx_id1_seen_block_id.is_some())
            },
            Some(Duration::from_secs(5)),
            Some(Duration::from_millis(100)),
        )
        .await
        .expect("Tx was not confirmed in time");

        Ok(())
    }

    #[tokio::test]
    async fn test_try_to_send_rbf() -> Result<(), BridgeError> {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();

        let (client, _tx_sender, _cancel_txs, rpc, db, signer, network) =
            create_bg_tx_sender(rpc).await;

        let tx = create_bumpable_tx(&rpc, &signer, network, FeePayingType::RBF)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        client
            .insert_try_to_send(&mut dbtx, None, &tx, FeePayingType::RBF, &[], &[], &[], &[])
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

    #[tokio::test]
    async fn get_fee_rate() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc: ExtendedRpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let amount = Amount::from_sat(100_000);
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );
        let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

        let tx_sender = TxSender::new(
            signer.clone(),
            rpc.clone(),
            db,
            "tx_sender".into(),
            config.protocol_paramset().network,
        );

        let scripts: Vec<Arc<dyn SpendableScript>> =
            vec![Arc::new(CheckSig::new(xonly_pk)).clone()];
        let (taproot_address, taproot_spend_info) = builder::address::create_taproot_address(
            &scripts
                .iter()
                .map(|s| s.to_script_buf())
                .collect::<Vec<_>>(),
            None,
            config.protocol_paramset().network,
        );

        let input_utxo = rpc.send_to_address(&taproot_address, amount).await.unwrap();

        let builder = TxHandlerBuilder::new(TransactionType::Dummy).add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new(
                input_utxo,
                TxOut {
                    value: amount,
                    script_pubkey: taproot_address.script_pubkey(),
                },
                scripts.clone(),
                Some(taproot_spend_info.clone()),
            ),
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        );

        let mut will_fail_handler = builder
            .clone()
            .add_output(UnspentTxOut::new(
                TxOut {
                    value: amount,
                    script_pubkey: taproot_address.script_pubkey(),
                },
                scripts.clone(),
                Some(taproot_spend_info.clone()),
            ))
            .finalize();

        let mut tweak_cache = TweakCache::default();
        signer
            .tx_sign_and_fill_sigs(&mut will_fail_handler, &[], Some(&mut tweak_cache))
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        let will_fail_tx = will_fail_handler.get_cached_tx();
        assert!(rpc.client.send_raw_transaction(will_fail_tx).await.is_err());

        // Calculate and send with fee.
        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        let fee = TxSender::calculate_required_fee(
            will_fail_tx.weight(),
            1,
            fee_rate,
            FeePayingType::CPFP,
        )
        .unwrap();
        println!("Fee rate: {:?}, fee: {}", fee_rate, fee);

        let mut will_successful_handler = builder
            .add_output(UnspentTxOut::new(
                TxOut {
                    value: amount - fee,
                    script_pubkey: taproot_address.script_pubkey(),
                },
                scripts,
                Some(taproot_spend_info),
            ))
            .finalize();
        signer
            .tx_sign_and_fill_sigs(&mut will_successful_handler, &[], Some(&mut tweak_cache))
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();

        rpc.client
            .send_raw_transaction(will_successful_handler.get_cached_tx())
            .await
            .unwrap();
    }
}
