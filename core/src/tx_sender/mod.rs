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
use crate::errors::{FeeErr, ResultExt};
use crate::extended_bitcoin_rpc::RetryConfig;
use crate::utils::FeePayingType;
use crate::{
    actor::Actor,
    builder::{self},
    database::Database,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    utils::TxMetadata,
};
use alloy::transports::http::reqwest;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, FeeRate, Network, OutPoint, Transaction, TxOut, Txid, Weight};
use bitcoincore_rpc::RpcApi;
use eyre::eyre;
use eyre::OptionExt;
use eyre::WrapErr;
use http::StatusCode;
use tokio::time::timeout;
use tokio_retry::RetryIf;

#[cfg(test)]
use std::env;
use std::time::Duration;

mod client;
mod cpfp;
mod nonstandard;
mod rbf;
mod task;

pub use client::TxSenderClient;
pub use task::TxSenderTask;

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
        match self.config.protocol_paramset.network {
            // Regtest use a fixed, low fee rate.
            Network::Regtest => {
                tracing::debug!(
                    "Using fixed fee rate of 1 sat/vB for {} network",
                    self.config.protocol_paramset.network
                );
                Ok(FeeRate::from_sat_per_vb_unchecked(1))
            }

            // Mainnet and Testnet4 fetch fees from Mempool Space and Bitcoin Core RPC.
            Network::Bitcoin | Network::Testnet4 | Network::Signet => {
                tracing::debug!(
                    "Fetching fee rate for {} network...",
                    self.config.protocol_paramset.network
                );

                // Fetch fees from both mempool.space and Bitcoin Core RPC
                let mempool_fee = get_fee_rate_from_mempool_space(
                    &self.config.mempool_api_host,
                    &self.config.mempool_api_endpoint,
                    self.config.protocol_paramset.network,
                )
                .await;

                let rpc_fee = timeout(
                    Duration::from_secs(30),
                    self.rpc.estimate_smart_fee(1, None),
                )
                .await
                .map_err(|_| eyre!("RPC estimate_smart_fee timed out after 30 seconds"))
                .and_then(|result| {
                    result.wrap_err("Failed to estimate smart fee using Bitcoin Core RPC")
                })
                .and_then(|estimate| {
                    estimate.fee_rate.ok_or_else(|| {
                        eyre!("Failed to extract fee rate from Bitcoin Core RPC response")
                    })
                });

                // Use the minimum of both fee sources, with fallback logic, carefully avoiding overflow
                let selected_fee_amount = match (mempool_fee, rpc_fee) {
                    (Ok(mempool_amt), Ok(rpc_amt)) => {
                        // Use checked arithmetic to avoid overflow
                        let multiplier = self.config.tx_sender_limits.mempool_fee_rate_multiplier;
                        let offset = self.config.tx_sender_limits.mempool_fee_rate_offset_sat_kvb;
                        let rpc_amt_sat = rpc_amt.to_sat();

                        let threshold_sat = multiplier
                            .checked_mul(rpc_amt_sat)
                            .and_then(|v| v.checked_add(offset))
                            .unwrap_or(u64::MAX);

                        let threshold = Amount::from_sat(threshold_sat);

                        if mempool_amt <= threshold {
                            tracing::info!(
                                "Selected mempool.space fee rate: {} sat/kvB (mempool: {}, rpc: {}, threshold: {})",
                                mempool_amt.to_sat(),
                                mempool_amt.to_sat(),
                                rpc_amt.to_sat(),
                                threshold
                            );
                            mempool_amt
                        } else {
                            tracing::info!(
                                "Selected Bitcoin Core RPC fee rate: {} sat/kvB (mempool: {}, rpc: {}, threshold: {})",
                                rpc_amt.to_sat(),
                                mempool_amt.to_sat(),
                                rpc_amt.to_sat(),
                                threshold
                            );
                            rpc_amt
                        }
                    }
                    (Ok(mempool_amt), Err(rpc_err)) => {
                        tracing::warn!(
                            "RPC fee estimation failed, using mempool.space: {:#}",
                            rpc_err
                        );
                        mempool_amt
                    }
                    (Err(mempool_err), Ok(rpc_amt)) => {
                        tracing::warn!(
                            "Mempool.space fee fetch failed, using Bitcoin Core RPC: {:#}",
                            mempool_err
                        );
                        rpc_amt
                    }
                    (Err(mempool_err), Err(rpc_err)) => {
                        tracing::warn!(
                            "Both fee sources failed (mempool: {:#}, rpc: {:#}), using default of 1 sat/vB",
                            mempool_err, rpc_err
                        );
                        Amount::from_sat(1000) // 1 sat/vB * 1000 = 1000 sat/kvB
                    }
                };

                // Convert sat/kvB to sat/vB and apply hard cap
                let mut fee_sat_kvb = selected_fee_amount.to_sat();

                // Apply hard cap from config
                if fee_sat_kvb > self.config.tx_sender_limits.fee_rate_hard_cap * 1000 {
                    tracing::warn!(
                        "Fee rate {} sat/kvb exceeds hard cap {} sat/kvb, using hard cap",
                        fee_sat_kvb,
                        self.config.tx_sender_limits.fee_rate_hard_cap * 1000
                    );
                    fee_sat_kvb = self.config.tx_sender_limits.fee_rate_hard_cap * 1000;
                }

                tracing::info!("Final fee rate: {} sat/kvb", fee_sat_kvb);
                Ok(FeeRate::from_sat_per_kwu(fee_sat_kvb.div_ceil(4)))
            }

            // All other network types are unsupported.
            _ => Err(eyre!(
                "Fee rate estimation is not supported for network: {:?}",
                self.config.protocol_paramset.network
            )
            .into()),
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

        #[cfg(test)]
        {
            if env::var("TXSENDER_DBG_INACTIVE_TXS").is_ok() {
                self.db
                    .debug_inactive_txs(new_fee_rate, current_tip_height)
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

            let result = match fee_paying_type {
                // Send nonstandard transactions to testnet4 using the mempool.space accelerator.
                // As mempool uses out of band payment, we don't need to do cpfp or rbf.
                _ if self.config.protocol_paramset.network == bitcoin::Network::Testnet4
                    && self.is_bridge_tx_nonstandard(&tx) =>
                {
                    self.send_testnet4_nonstandard_tx(&tx, id).await
                }
                FeePayingType::CPFP => self.send_cpfp_tx(id, tx, tx_metadata, new_fee_rate).await,
                FeePayingType::RBF => {
                    self.send_rbf_tx(id, tx, tx_metadata, new_fee_rate, rbf_signing_info)
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
        tracing::debug!(target: "ci", "Sending no funding tx, raw tx: {:?}", hex::encode(bitcoin::consensus::serialize(&tx)));
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
                    "Failed to send no funding tx with try_to_send_id: {:?} and metadata: {:?}",
                    try_to_send_id,
                    tx_metadata
                );
                let err_msg = format!("send_raw_transaction error for no funding tx: {}", e);
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

/// Fetches the current recommended fee rate from the provider. Currently only supports
/// Mempool Space API.
/// This function is used to get the fee rate in sat/vkb (satoshis per kilovbyte).
/// See [Mempool Space API](https://mempool.space/docs/api/rest#get-recommended-fees) for more details.
async fn get_fee_rate_from_mempool_space(
    url: &Option<String>,
    endpoint: &Option<String>,
    network: Network,
) -> Result<Amount> {
    let url = url
        .as_ref()
        .ok_or_else(|| eyre!("Fee rate API host is not configured"))?;

    let endpoint = endpoint
        .as_ref()
        .ok_or_else(|| eyre!("Fee rate API endpoint is not configured"))?;

    let url = match network {
        Network::Bitcoin => format!(
            // If the variables are not, return Error to fallback to Bitcoin Core RPC.
            "{}{}",
            url, endpoint
        ),
        Network::Testnet4 => format!("{}testnet4/{}", url, endpoint),
        // Return early with error for unsupported networks
        Network::Signet => {
            tracing::warn!("You should use Citrea signet url for mempool.space");
            format!("{}{}", url, endpoint)
        }
        _ => return Err(eyre!("Unsupported network for mempool.space: {:?}", network).into()),
    };

    let retry_config = RetryConfig::new(
        Duration::from_millis(250),
        Duration::from_secs(5),
        4,
        2,
        true,
    );

    let retry_strategy = retry_config.get_strategy();

    // Retry predicate: only retry on timeouts, connect errors, and 5xx/429 statuses.
    let should_retry = |e: &FeeErr| match e {
        FeeErr::Timeout => true,
        FeeErr::Transport(req_err) => req_err.is_timeout() || req_err.is_connect(),
        FeeErr::Status(code) => code.is_server_error() || *code == StatusCode::TOO_MANY_REQUESTS,
        FeeErr::JsonDecode(_) | FeeErr::MissingField => false,
    };

    let fee_sat_per_vb: u64 = RetryIf::spawn(
        retry_strategy,
        || {
            let url = url.clone();
            async move {
                let resp = timeout(Duration::from_secs(5), reqwest::get(&url))
                    .await
                    .map_err(|_| FeeErr::Timeout)?
                    .map_err(FeeErr::Transport)?;

                let status = resp.status();
                if !status.is_success() {
                    return Err(FeeErr::Status(status));
                }

                let json: serde_json::Value = timeout(Duration::from_secs(5), resp.json())
                    .await
                    .map_err(|_| FeeErr::Timeout)?
                    .map_err(FeeErr::JsonDecode)?;

                json.get("fastestFee")
                    .and_then(|fee| fee.as_u64())
                    .ok_or(FeeErr::MissingField)
            }
        },
        should_retry,
    )
    .await
    .map_err(|e| eyre::eyre!(e))
    .wrap_err_with(|| format!("Failed to fetch/parse fees from {}", url))?;

    // The API returns the fee rate in sat/vB. We multiply by 1000 to get sat/kvB.
    let fee_rate = Amount::from_sat(fee_sat_per_vb * 1000);

    Ok(fee_rate)
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
    use crate::constants::{MIN_TAPROOT_AMOUNT, NON_EPHEMERAL_ANCHOR_AMOUNT, NON_STANDARD_V3};
    use crate::errors::BridgeError;
    use crate::rpc::clementine::tagged_signature::SignatureId;
    use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
    use crate::task::{IntoTask, TaskExt};
    use crate::{database::Database, test::common::*};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::rand;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use serde_json::json;
    use std::ops::Mul;
    use std::result::Result;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    impl TxSenderClient {
        pub async fn test_dbtx(
            &self,
        ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, BridgeError> {
            self.db.begin_transaction().await
        }
    }

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
        let actor = Actor::new(sk, None, network);

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

    pub(super) async fn create_bg_tx_sender(
        rpc: ExtendedBitcoinRpc,
    ) -> (
        TxSenderClient,
        TxSender,
        Vec<oneshot::Sender<()>>,
        ExtendedBitcoinRpc,
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
        rpc: &ExtendedBitcoinRpc,
        signer: &Actor,
        network: bitcoin::Network,
        fee_paying_type: FeePayingType,
        requires_rbf_signing_info: bool,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

        let amount = Amount::from_sat(100000);
        let outpoint = rpc.send_to_address(&address, amount).await?;
        rpc.mine_blocks(1).await?;

        let version = match fee_paying_type {
            FeePayingType::CPFP => NON_STANDARD_V3,
            FeePayingType::RBF | FeePayingType::NoFunding => Version::TWO,
        };

        let mut txhandler = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(version)
            .add_input(
                match fee_paying_type {
                    FeePayingType::CPFP => {
                        SignatureId::from(NormalSignatureKind::OperatorSighashDefault)
                    }
                    FeePayingType::RBF if !requires_rbf_signing_info => {
                        NormalSignatureKind::Challenge.into()
                    }
                    FeePayingType::RBF => (NumberedSignatureKind::WatchtowerChallenge, 0i32).into(),
                    FeePayingType::NoFunding => {
                        unreachable!("AlreadyFunded should not be used for bumpable txs")
                    }
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
                value: amount - NON_EPHEMERAL_ANCHOR_AMOUNT - MIN_TAPROOT_AMOUNT * 3, // buffer so that rbf works without adding inputs
                script_pubkey: address.script_pubkey(), // In practice, should be the wallet address, not the signer address
            }))
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::non_ephemeral_anchor_output(),
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
    async fn test_mempool_space_fee_rate_mainnet() {
        get_fee_rate_from_mempool_space(
            &Some("https://mempool.space/".to_string()),
            &Some("api/v1/fees/recommended".to_string()),
            bitcoin::Network::Bitcoin,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_mempool_space_fee_rate_testnet4() {
        get_fee_rate_from_mempool_space(
            &Some("https://mempool.space/".to_string()),
            &Some("api/v1/fees/recommended".to_string()),
            bitcoin::Network::Testnet4,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Unsupported network for mempool.space: Regtest")]
    async fn test_mempool_space_fee_rate_regtest() {
        get_fee_rate_from_mempool_space(
            &Some("https://mempool.space/".to_string()),
            &Some("api/v1/fees/recommended".to_string()),
            bitcoin::Network::Regtest,
        )
        .await
        .unwrap();
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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
        let signer = Actor::new(config.secret_key, None, config.protocol_paramset.network);

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
