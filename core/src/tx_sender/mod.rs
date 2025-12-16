//! # Transaction Sender
//!
//! Transaction sender is responsible for sending Bitcoin transactions, bumping
//! fees and making sure that transactions are finalized until the deadline. It
//! can utilize [Child-Pays-For-Parent (CPFP)](crate::tx_sender::cpfp) and
//! [Replace-By-Fee (RBF)](crate::tx_sender::rbf) strategies for sending
//! transactions.
//!
//! Sending transactions is done by the [`TxSenderClient`], which is a client
//! that puts transactions into the sending queue and the [`TxSenderTask`] is
//! responsible for processing this queue and sending them.
//!
//! ## Debugging Transaction Sender
//!
//! There are several database tables that saves the transaction states. Please
//! look for [`core/src/database/tx_sender.rs`] for more information.

use crate::config::BridgeConfig;
use crate::errors::ResultExt;
use crate::utils::FeePayingType;
use crate::{
    actor::Actor,
    builder::{self},
    database::Database,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    utils::TxMetadata,
};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight};
use bitcoincore_rpc::RpcApi;
use eyre::OptionExt;

#[cfg(test)]
use std::env;

mod client;
mod cpfp;
mod nonstandard;
mod rbf;
mod task;

pub use client::TxSenderClient;
pub use task::TxSenderTask;

/// Number of blocks after which a stuck transaction should be fee-bumped
const FEE_BUMP_AFTER_BLOCKS: u32 = 10;

// Define a macro for logging errors and saving them to the database
macro_rules! log_error_for_tx {
    ($db:expr, $try_to_send_id:expr, $err:expr) => {{
        let db = $db.clone();
        let try_to_send_id = $try_to_send_id;
        let err = $err.to_string();
        tracing::warn!(try_to_send_id, "{}", err);
        tokio::spawn(async move {
            let _ = db
                .save_tx_debug_submission_error(try_to_send_id, &err)
                .await;
        });
    }};
}

// Exports to this module.
use log_error_for_tx;

/// Manages the process of sending Bitcoin transactions, including handling fee bumping
/// strategies like Replace-By-Fee (RBF) and Child-Pays-For-Parent (CPFP).
///
/// It interacts with a Bitcoin Core RPC endpoint (`ExtendedBitcoinRpc`) to query network state
/// (like fee rates) and submit transactions. It uses a `Database` to persist transaction
/// state, track confirmation status, and manage associated data like fee payer UTXOs.
/// The `Actor` provides signing capabilities for transactions controlled by this service.
#[derive(Clone, Debug)]
pub struct TxSender {
    pub signer: Actor,
    pub rpc: ExtendedBitcoinRpc,
    pub db: Database,
    pub btc_syncer_consumer_id: String,
    pub config: BridgeConfig,
    cached_spendinfo: TaprootSpendInfo,
    http_client: reqwest::Client,
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

#[derive(Debug, thiserror::Error)]
pub enum SendTxError {
    #[error("Unconfirmed fee payer UTXOs left")]
    UnconfirmedFeePayerUTXOsLeft,
    #[error("Insufficient fee payer amount")]
    InsufficientFeePayerAmount,

    #[error("Failed to create a PSBT for fee bump")]
    PsbtError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

type Result<T> = std::result::Result<T, SendTxError>;

impl TxSender {
    pub fn new(
        signer: Actor,
        rpc: ExtendedBitcoinRpc,
        db: Database,
        btc_syncer_consumer_id: String,
        config: BridgeConfig,
    ) -> Self {
        Self {
            cached_spendinfo: builder::address::create_taproot_address(
                &[],
                Some(signer.xonly_public_key),
                config.protocol_paramset.network,
            )
            .1,
            signer,
            rpc,
            db,
            btc_syncer_consumer_id,
            config: config.clone(),
            http_client: reqwest::Client::new(),
        }
    }

    /// Gets the current recommended fee rate in sat/vb from Mempool Space and Bitcoin Core and selects the minimum.
    /// For Regtest and Signet, it uses a fixed fee rate of 1 sat/vB.
    /// # Logic
    /// *   **Regtest:** Uses a fixed fee rate of 1 sat/vB for simplicity.
    /// *   **Mainnet, Testnet4 and Signet:** Fetches fee rates from both Mempool Space API and Bitcoin Core RPC and takes the minimum.
    /// *   **Hard Cap:** Applies a hard cap from configuration to prevent excessive fees.
    /// # Fallbacks
    /// *   If one source fails, it uses the other.
    /// *   If both fail, it falls back to a default of 1 sat/vB.
    async fn get_fee_rate(&self) -> Result<FeeRate> {
        self.rpc
            .get_fee_rate(
                self.config.protocol_paramset.network,
                &self.config.mempool_api_host,
                &self.config.mempool_api_endpoint,
                self.config.tx_sender_limits.mempool_fee_rate_multiplier,
                self.config.tx_sender_limits.mempool_fee_rate_offset_sat_kvb,
                self.config.tx_sender_limits.fee_rate_hard_cap,
            )
            .await
            .map_err(|e| SendTxError::Other(e.into()))
    }

    /// Calculates the effective fee rate for a transaction, considering previous effective fee rate
    /// and minimum incremental fee requirements.
    ///
    /// This function implements the logic for fee bumping that ensures:
    /// 1. If no previous effective fee rate exists, use the new fee rate
    /// 2. If previous effective fee rate exists, use the maximum of:
    ///    - The new fee rate
    ///    - Previous effective fee rate + minimum incremental fee rate
    ///
    /// # Arguments
    /// * `previous_effective_fee_rate` - The previous effective fee rate (if any)
    /// * `new_fee_rate` - The target fee rate for the new attempt
    /// * `last_bump_block_height` - The block height when the last fee bump was done (if any)
    /// * `current_tip_height` - The current blockchain tip height
    ///
    /// # Returns
    /// The effective fee rate to use (in sat/kwu), capped by the hard cap from config
    pub async fn calculate_target_fee_rate(
        &self,
        previous_effective_fee_rate: Option<FeeRate>,
        new_fee_rate: FeeRate,
        last_bump_block_height: Option<u32>,
        current_tip_height: u32,
    ) -> Result<FeeRate> {
        // Hard cap from config (in sat/vB), convert to sat/kwu
        let hard_cap = FeeRate::from_sat_per_vb(self.config.tx_sender_limits.fee_rate_hard_cap)
            .expect("fee_rate_hard_cap should be valid");

        let Some(previous_rate) = previous_effective_fee_rate else {
            // No previous effective fee rate, use the new fee rate (capped)
            return Ok(std::cmp::min(new_fee_rate, hard_cap));
        };

        // Check if the tx has been stuck for 10+ blocks
        let is_stuck = match last_bump_block_height {
            Some(block_height) => {
                current_tip_height.saturating_sub(block_height) >= FEE_BUMP_AFTER_BLOCKS
            }
            None => false,
        };

        // Get minimum fee increment rate from node for BIP125 compliance. Returned value is in BTC/kvB
        let incremental_fee_rate = self
            .rpc
            .get_network_info()
            .await
            .map_err(|e| eyre::eyre!(e))?
            .incremental_fee;
        let incremental_fee_rate_sat_per_kvb = incremental_fee_rate.to_sat();
        let incremental_fee_rate = FeeRate::from_sat_per_kwu(incremental_fee_rate_sat_per_kvb / 4);

        // Minimum bump fee rate required by BIP125
        let min_bump_feerate =
            previous_rate.to_sat_per_kwu() + incremental_fee_rate.to_sat_per_kwu();

        // If new fee rate is higher than previous, use max of new_fee_rate and min_bump_feerate
        if new_fee_rate.to_sat_per_kwu() > previous_rate.to_sat_per_kwu() {
            let effective_feerate = std::cmp::max(new_fee_rate.to_sat_per_kwu(), min_bump_feerate);
            let result = FeeRate::from_sat_per_kwu(effective_feerate);
            return Ok(std::cmp::min(result, hard_cap));
        }

        // If the tx is stuck for 10+ blocks, force a fee bump (previous + incremental)
        if is_stuck {
            let result = FeeRate::from_sat_per_kwu(min_bump_feerate);
            let capped_result = std::cmp::min(result, hard_cap);

            tracing::debug!(
                "TX stuck for {} blocks, forcing fee bump from {} to {} sat/kwu (hard cap: {} sat/kwu)",
                FEE_BUMP_AFTER_BLOCKS,
                previous_rate.to_sat_per_kwu(),
                capped_result.to_sat_per_kwu(),
                hard_cap.to_sat_per_kwu()
            );

            return Ok(capped_result);
        }

        // Neither higher fee rate nor stuck, use previous rate (no change needed)
        Ok(previous_rate)
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
        tracing::info!(
            "Calculating required fee for {} fee payer utxos",
            num_fee_payer_utxos
        );
        // Estimate the weight of the child transaction (for CPFP) or the RBF replacement.
        // P2TR input witness adds ~57.5vbytes (230 WU). P2TR output adds 43 vbytes (172 WU).
        // Base transaction overhead (version, locktime, input/output counts) ~ 10.5 vBytes (42 WU)
        // Anchor input marker (OP_FALSE OP_RETURN ..) adds overhead. Exact WU TBD.
        // For CPFP child: (N fee payer inputs) + (1 anchor input) + (1 change output)
        // For RBF replacement: (N fee payer inputs) + (1 change output) - assuming it replaces a tx with an anchor.
        let child_tx_weight = match fee_paying_type {
            // CPFP Child: N fee payer inputs + 1 anchor input + 1 change output + base overhead.
            // Approx WU: (230 * num_fee_payer_utxos) + 230 + 172 + base_overhead_wu
            // Simplified calculation used here needs verification.
            FeePayingType::CPFP => Weight::from_wu_usize(230 * num_fee_payer_utxos + 207 + 172),
            // RBF Replacement: N fee payer inputs + 1 change output + base overhead.
            // Assumes it replaces a tx of similar structure but potentially different inputs/fees.
            // Simplified calculation used here needs verification.
            FeePayingType::RBF => Weight::from_wu_usize(230 * num_fee_payer_utxos + 172),
            FeePayingType::NoFunding => Weight::from_wu_usize(0),
        };

        // Calculate total weight for fee calculation.
        // For CPFP, miners consider the effective fee rate over the combined *vbytes* of parent + child.
        // For RBF, miners consider the fee rate of the single replacement transaction's weight.
        let total_weight = match fee_paying_type {
            FeePayingType::CPFP => Weight::from_vb_unchecked(
                child_tx_weight.to_vbytes_ceil() + parent_tx_weight.to_vbytes_ceil(),
            ),
            FeePayingType::RBF => child_tx_weight + parent_tx_weight, // Should likely just be the RBF tx weight? Check RBF rules.
            FeePayingType::NoFunding => parent_tx_weight,
        };

        fee_rate
            .checked_mul_by_weight(total_weight)
            .ok_or_eyre("Fee calculation overflow")
            .map_err(Into::into)
    }

    fn is_p2a_anchor(&self, output: &TxOut) -> bool {
        output.script_pubkey
            == builder::transaction::anchor_output(self.config.protocol_paramset.anchor_amount())
                .script_pubkey
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

    /// Fetches transactions that are eligible to be sent or bumped from
    /// database based on the given fee rate and tip height. Then, places a send
    /// transaction request to the Bitcoin based on the fee strategy.
    ///
    /// For each eligible transaction (`id`):
    ///
    /// 1.  **Send/Bump Main Tx:** Calls `send_tx` to either perform RBF or CPFP on the main
    ///     transaction (`id`) using the `new_fee_rate`.
    /// 2.  **Handle Errors:**
    ///     - [`SendTxError::UnconfirmedFeePayerUTXOsLeft`]: Skips the current tx, waiting for fee
    ///       payers to confirm.
    ///     - [`SendTxError::InsufficientFeePayerAmount`]: Calls `create_fee_payer_utxo` to
    ///       provision more funds for a future CPFP attempt.
    ///     - Other errors are logged.
    ///
    /// # Arguments
    /// * `new_fee_rate` - The current target fee rate based on network conditions.
    /// * `current_tip_height` - The current blockchain height, used for time-lock checks.
    /// * `is_tip_height_increased` - True if the tip height has increased since the last time we sent unconfirmed transactions.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, new_fee_rate, current_tip_height))]
    async fn try_to_send_unconfirmed_txs(
        &self,
        new_fee_rate: FeeRate,
        current_tip_height: u32,
        is_tip_height_increased: bool,
    ) -> Result<()> {
        // get_sendable_txs doesn't return txs that we already sent in the past with >= fee rate to the current fee rate
        // but if we have a new block height, but the tx is still not confirmed, we want to send it again anyway in case
        // some error occurred on our bitcoin rpc/our tx got evicted from mempool somehow (for ex: if a fee payer of cpfp tx was reorged,
        // cpfp tx will get evicted as v3 cpfp cannot have unconfirmed ancestors)
        // if block height is increased, we use a dummy high fee rate to get all sendable txs
        let get_sendable_txs_fee_rate = if is_tip_height_increased {
            FeeRate::from_sat_per_kwu(u32::MAX as u64)
        } else {
            new_fee_rate
        };
        let txs = self
            .db
            .get_sendable_txs(None, get_sendable_txs_fee_rate, current_tip_height)
            .await
            .map_to_eyre()?;

        // bump fees of fee payer transactions that are unconfirmed
        self.bump_fees_of_unconfirmed_fee_payer_txs(new_fee_rate)
            .await?;

        if !txs.is_empty() {
            tracing::debug!("Trying to send {} sendable txs ", txs.len());
        }

        #[cfg(test)]
        {
            if env::var("TXSENDER_DBG_INACTIVE_TXS").is_ok() {
                self.db
                    .debug_inactive_txs(get_sendable_txs_fee_rate, current_tip_height)
                    .await;
            }
        }

        for id in txs {
            // Update debug state
            tracing::debug!(
                try_to_send_id = id,
                "Processing TX in try_to_send_unconfirmed_txs with fee rate {new_fee_rate}",
            );

            let (tx_metadata, tx, fee_paying_type, seen_block_id, rbf_signing_info) =
                match self.db.get_try_to_send_tx(None, id).await {
                    Ok(res) => res,
                    Err(e) => {
                        log_error_for_tx!(self.db, id, format!("Failed to get tx details: {}", e));
                        continue;
                    }
                };

            // Check if the transaction is already confirmed (only happens if it was confirmed after this loop started)
            if let Some(block_id) = seen_block_id {
                tracing::debug!(
                    try_to_send_id = id,
                    "Transaction already confirmed in block with block id of {}",
                    block_id
                );

                // Update sending state
                let _ = self
                    .db
                    .update_tx_debug_sending_state(id, "confirmed", true)
                    .await;

                continue;
            }

            // Get effective fee rate and block height to calculate adjusted fee rate
            let (previous_effective_fee_rate, last_bump_block_height) =
                match self.db.get_effective_fee_rate(None, id).await {
                    Ok(res) => res,
                    Err(e) => {
                        log_error_for_tx!(
                            self.db,
                            id,
                            format!("Failed to get effective fee rate: {}", e)
                        );
                        continue;
                    }
                };

            // Calculate adjusted fee rate considering:
            // 1. If new_fee_rate > previous_effective_fee_rate, use new_fee_rate
            // 2. If tx has been stuck for 10+ blocks, bump with incremental fee
            let adjusted_fee_rate = match self
                .calculate_target_fee_rate(
                    previous_effective_fee_rate,
                    new_fee_rate,
                    last_bump_block_height,
                    current_tip_height,
                )
                .await
            {
                Ok(rate) => rate,
                Err(e) => {
                    log_error_for_tx!(
                        self.db,
                        id,
                        format!("Failed to calculate adjusted fee rate: {}", e)
                    );
                    continue;
                }
            };

            let result = match fee_paying_type {
                // Send nonstandard transactions to testnet4 using the mempool.space accelerator.
                // As mempool uses out of band payment, we don't need to do cpfp or rbf.
                _ if self.config.protocol_paramset.network == bitcoin::Network::Testnet4
                    && self.is_bridge_tx_nonstandard(&tx) =>
                {
                    self.send_testnet4_nonstandard_tx(&tx, id).await
                }
                FeePayingType::CPFP => {
                    self.send_cpfp_tx(id, tx, tx_metadata, adjusted_fee_rate, current_tip_height)
                        .await
                }
                FeePayingType::RBF => {
                    self.send_rbf_tx(
                        id,
                        tx,
                        tx_metadata,
                        adjusted_fee_rate,
                        rbf_signing_info,
                        current_tip_height,
                    )
                    .await
                }
                FeePayingType::NoFunding => self.send_no_funding_tx(id, tx, tx_metadata).await,
            };

            if let Err(e) = result {
                log_error_for_tx!(self.db, id, format!("Failed to send tx: {:?}", e));
            }
        }

        Ok(())
    }

    pub fn client(&self) -> TxSenderClient {
        TxSenderClient::new(self.db.clone(), self.btc_syncer_consumer_id.clone())
    }

    /// Sends a transaction that is already fully funded and signed.
    ///
    /// This function is used for transactions that do not require fee bumping strategies
    /// like RBF or CPFP. The transaction is submitted directly to the Bitcoin network
    /// without any modifications.
    ///
    /// # Arguments
    /// * `try_to_send_id` - The database ID tracking this send attempt.
    /// * `tx` - The fully funded and signed transaction ready for broadcast.
    /// * `tx_metadata` - Optional metadata associated with the transaction for debugging.
    ///
    /// # Behavior
    /// 1. Attempts to broadcast the transaction using `send_raw_transaction` RPC.
    /// 2. Updates the database with success/failure state for debugging purposes.
    /// 3. Logs appropriate messages for monitoring and troubleshooting.
    ///
    /// # Returns
    /// * `Ok(())` - If the transaction was successfully broadcast.
    /// * `Err(SendTxError)` - If the broadcast failed.
    #[tracing::instrument(skip_all, fields(sender = self.btc_syncer_consumer_id, try_to_send_id, tx_meta=?tx_metadata))]
    pub(super) async fn send_no_funding_tx(
        &self,
        try_to_send_id: u32,
        tx: Transaction,
        tx_metadata: Option<TxMetadata>,
    ) -> Result<()> {
        match self.rpc.send_raw_transaction(&tx).await {
            Ok(sent_txid) => {
                tracing::debug!(
                    try_to_send_id,
                    "Successfully sent no funding tx with txid {}",
                    sent_txid
                );
                let _ = self
                    .db
                    .update_tx_debug_sending_state(try_to_send_id, "no_funding_send_success", true)
                    .await;
            }
            Err(e) => {
                tracing::error!(
                    "Failed to send no funding tx with try_to_send_id: {try_to_send_id:?} and metadata: {tx_metadata:?}"
                );
                let err_msg = format!("send_raw_transaction error for no funding tx: {e}");
                log_error_for_tx!(self.db, try_to_send_id, err_msg);
                let _ = self
                    .db
                    .update_tx_debug_sending_state(try_to_send_id, "no_funding_send_failed", true)
                    .await;
                return Err(SendTxError::Other(eyre::eyre!(e)));
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::TweakCache;
    use crate::bitcoin_syncer::BitcoinSyncer;
    use crate::bitvm_client::SECP;
    use crate::builder::script::{CheckSig, SpendPath, SpendableScript};
    use crate::builder::transaction::input::SpendableTxIn;
    use crate::builder::transaction::output::UnspentTxOut;
    use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
    use crate::config::protocol::ProtocolParamset;
    use crate::errors::BridgeError;
    use crate::rpc::clementine::NormalSignatureKind;
    use crate::task::{IntoTask, TaskExt};
    use crate::test::common::tx_utils::{create_bg_tx_sender, create_bumpable_tx};
    use crate::{database::Database, test::common::*};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::SecretKey;
    use serde_json::json;
    use std::ops::Mul;
    use std::result::Result;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    pub(super) async fn create_tx_sender(
        rpc: ExtendedBitcoinRpc,
    ) -> (
        TxSender,
        BitcoinSyncer,
        ExtendedBitcoinRpc,
        Database,
        Actor,
        bitcoin::Network,
    ) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = bitcoin::Network::Regtest;
        let actor = Actor::new(sk, network);

        let config = create_test_config_with_thread_name().await;

        let db = Database::new(&config).await.unwrap();

        let tx_sender = TxSender::new(
            actor.clone(),
            rpc.clone(),
            db.clone(),
            "tx_sender".into(),
            config.clone(),
        );

        (
            tx_sender,
            BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset)
                .await
                .unwrap(),
            rpc,
            db,
            actor,
            network,
        )
    }

    impl TxSenderClient {
        pub async fn test_dbtx(
            &self,
        ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
            self.db.begin_transaction().await
        }
    }

    #[tokio::test]
    async fn test_try_to_send_duplicate() -> Result<(), BridgeError> {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        rpc.mine_blocks(1).await.unwrap();

        let (client, _tx_sender, _cancel_txs, rpc, db, signer, network) =
            create_bg_tx_sender(config).await;

        let tx = create_bumpable_tx(&rpc, &signer, network, FeePayingType::CPFP, false)
            .await
            .unwrap();

        let mut dbtx = db.begin_transaction().await.unwrap();
        let tx_id1 = client
            .insert_try_to_send(
                &mut dbtx,
                None,
                &tx,
                FeePayingType::CPFP,
                None,
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
                None,
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

                match rpc.get_raw_transaction_info(&tx.compute_txid(), None).await {
                    Ok(tx_result) => {
                        if let Some(conf) = tx_result.confirmations {
                            return Ok(conf > 0);
                        }
                        Ok(false)
                    }
                    Err(_) => Ok(false),
                }
            },
            Some(Duration::from_secs(30)),
            Some(Duration::from_millis(100)),
        )
        .await
        .expect("Tx was not confirmed in time");

        poll_until_condition(
            async || {
                let (_, _, _, tx_id1_seen_block_id, _) =
                    db.get_try_to_send_tx(None, tx_id1).await.unwrap();
                let (_, _, _, tx_id2_seen_block_id, _) =
                    db.get_try_to_send_tx(None, tx_id2).await.unwrap();

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
    async fn get_fee_rate() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let db = Database::new(&config).await.unwrap();

        let amount = Amount::from_sat(100_000);
        let signer = Actor::new(config.secret_key, config.protocol_paramset().network);
        let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

        let tx_sender = TxSender::new(
            signer.clone(),
            rpc.clone(),
            db,
            "tx_sender".into(),
            config.clone(),
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
        let mempool_info = rpc.get_mempool_info().await.unwrap();
        tracing::info!("Mempool info: {:?}", mempool_info);

        let will_fail_tx = will_fail_handler.get_cached_tx();

        if mempool_info.mempool_min_fee.to_sat() > 0 {
            assert!(rpc.send_raw_transaction(will_fail_tx).await.is_err());
        }

        // Calculate and send with fee.
        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        let fee = TxSender::calculate_required_fee(
            will_fail_tx.weight(),
            1,
            fee_rate,
            FeePayingType::CPFP,
        )
        .unwrap();
        tracing::info!("Fee rate: {:?}, fee: {}", fee_rate, fee);

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

        rpc.send_raw_transaction(will_successful_handler.get_cached_tx())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_send_no_funding_tx() -> Result<(), BridgeError> {
        // Initialize RPC, tx_sender and other components
        let mut config = create_test_config_with_thread_name().await;
        let rpc = create_regtest_rpc(&mut config).await;

        let (tx_sender, btc_sender, rpc, db, signer, network) =
            create_tx_sender(rpc.rpc().clone()).await;
        let pair = btc_sender.into_task().cancelable_loop();
        pair.0.into_bg();

        // Create a transaction that doesn't need funding
        let tx = rbf::tests::create_rbf_tx(&rpc, &signer, network, false).await?;

        // Insert the transaction into the database
        let mut dbtx = db.begin_transaction().await?;
        let try_to_send_id = tx_sender
            .client()
            .insert_try_to_send(
                &mut dbtx,
                None, // No metadata
                &tx,
                FeePayingType::NoFunding,
                None,
                &[], // No cancel outpoints
                &[], // No cancel txids
                &[], // No activate txids
                &[], // No activate outpoints
            )
            .await?;
        dbtx.commit().await?;

        // Test send_rbf_tx
        tx_sender
            .send_no_funding_tx(try_to_send_id, tx.clone(), None)
            .await
            .expect("Already funded should succeed");

        tx_sender
            .send_no_funding_tx(try_to_send_id, tx.clone(), None)
            .await
            .expect("Should not return error if sent again");

        // Verify that the transaction was fee-bumped
        let tx_debug_info = tx_sender
            .client()
            .debug_tx(try_to_send_id)
            .await
            .expect("Transaction should be have debug info");

        // Get the actual transaction from the mempool
        rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
            tx_debug_info.txid.unwrap().txid.try_into().unwrap(),
        ))
        .await
        .expect("Transaction should be in mempool");

        tx_sender
            .send_no_funding_tx(try_to_send_id, tx.clone(), None)
            .await
            .expect("Should not return error if sent again but still in mempool");

        Ok(())
    }

    #[tokio::test]
    async fn test_get_fee_rate_mempool_higher_than_rpc_uses_rpc() {
        let mock_rpc_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "feerate": 0.00002,
                    "blocks": 1
                }
            })))
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "ping"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fastestFee": 3,
                "halfHourFee": 2,
                "hourFee": 1
            })))
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";

        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(500));
    }

    #[tokio::test]
    async fn test_get_fee_rate_rpc_higher_than_mempool() {
        let mock_rpc_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "feerate": 0.00005,
                    "blocks": 1
                }
            })))
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "ping"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fastestFee": 4,
                "halfHourFee": 3,
                "hourFee": 2
            })))
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";

        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1000));
    }

    #[tokio::test]
    async fn test_get_fee_rate_rpc_failure_mempool_fallback() {
        let mock_rpc_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32603,
                    "message": "Internal error"
                }
            })))
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "ping"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fastestFee": 10,
                "halfHourFee": 9,
                "hourFee": 8
            })))
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";

        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500));
    }

    #[tokio::test]
    async fn test_get_fee_rate_mempool_space_timeout() {
        let mock_rpc_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "feerate": 0.00008,
                    "blocks": 1
                }
            })))
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "ping"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(10))
                    .set_body_json(json!({
                        "fastestFee": 2,
                        "halfHourFee": 1,
                        "hourFee": 1
                    })),
            )
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";

        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2000));
    }

    #[tokio::test]
    async fn test_get_fee_rate_rpc_timeout() {
        let mock_rpc_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(31))
                    .set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "feerate": 0.00002,
                            "blocks": 1
                        }
                    })),
            )
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "ping"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fastestFee": 8,
                "halfHourFee": 1,
                "hourFee": 1
            })))
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";

        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2000));
    }

    #[tokio::test]
    async fn test_rpc_retry_after_failures() {
        struct RpcSeqResponder {
            n: Arc<AtomicUsize>,
        }
        impl Respond for RpcSeqResponder {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                let i = self.n.fetch_add(1, Ordering::SeqCst);
                match i {
                    0 => ResponseTemplate::new(500).set_body_json(json!({
                        "jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Connection error 1"}
                    })),
                    1 => ResponseTemplate::new(500).set_body_json(json!({
                        "jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Connection error 2"}
                    })),
                    _ => ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc":"2.0","id":1,"result":{"feerate":0.00003,"blocks":1}
                    })),
                }
            }
        }

        let mock_rpc_server = MockServer::start().await;
        let counter = Arc::new(AtomicUsize::new(0));

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(RpcSeqResponder { n: counter.clone() })
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({"method": "ping"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";
        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(750));
    }

    #[tokio::test]
    async fn test_mempool_retry_after_failures() {
        let mock_rpc_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({"method": "estimatesmartfee"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "feerate": 0.00009,
                    "blocks": 1
                }
            })))
            .expect(1)
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({"method": "ping"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        struct SeqResponder {
            n: Arc<AtomicUsize>,
        }

        impl Respond for SeqResponder {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                let i = self.n.fetch_add(1, Ordering::SeqCst);
                match i {
                    0 => ResponseTemplate::new(500),
                    1 => ResponseTemplate::new(503),
                    2 => ResponseTemplate::new(500),
                    _ => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "fastestFee": 6,
                        "halfHourFee": 4,
                        "hourFee": 3
                    })),
                }
            }
        }

        let mock_mempool_server = MockServer::start().await;

        let counter = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(SeqResponder { n: counter.clone() })
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";
        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(signer, mock_rpc, db, "test_tx_sender".into(), config);

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1500));
    }

    #[tokio::test]
    async fn test_hard_cap() {
        let mock_rpc_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "estimatesmartfee"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "feerate": 0.00500,
                    "blocks": 1
                }
            })))
            .mount(&mock_rpc_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({
                "method": "ping"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": null
            })))
            .mount(&mock_rpc_server)
            .await;

        let mock_mempool_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "fastestFee": 500,
                "halfHourFee": 499,
                "hourFee": 498
            })))
            .mount(&mock_mempool_server)
            .await;

        let mock_rpc = ExtendedBitcoinRpc::connect(
            mock_rpc_server.uri(),
            secrecy::SecretString::new("test_user".into()),
            secrecy::SecretString::new("test_password".into()),
            None,
        )
        .await
        .unwrap();

        let mut config = create_test_config_with_thread_name().await;
        let network = bitcoin::Network::Bitcoin;
        let paramset = ProtocolParamset {
            network,
            ..ProtocolParamset::default()
        };

        let mempool_space_uri = mock_mempool_server.uri() + "/";

        config.protocol_paramset = Box::leak(Box::new(paramset));
        config.mempool_api_host = Some(mempool_space_uri);
        config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

        let db = Database::new(&config).await.unwrap();
        let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

        let tx_sender = TxSender::new(
            signer,
            mock_rpc,
            db,
            "test_tx_sender".into(),
            config.clone(),
        );

        let fee_rate = tx_sender.get_fee_rate().await.unwrap();
        assert_eq!(
            fee_rate,
            FeeRate::from_sat_per_kwu(
                config
                    .tx_sender_limits
                    .fee_rate_hard_cap
                    .mul(1000)
                    .div_ceil(4)
            )
        );
    }
}
