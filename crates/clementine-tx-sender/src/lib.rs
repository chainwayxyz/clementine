//! # Clementine Transaction Sender
//!
//! This crate handles the creation, signing, and broadcasting of Bitcoin transactions,
//! supporting various fee-bumping strategies like CPFP and RBF.

#[cfg(feature = "citrea")]
pub mod citrea;
pub mod client;
pub mod config;
mod confirmations;
pub mod cpfp;
pub mod db;
#[cfg(feature = "json-rpc")]
pub mod jsonrpc;
pub mod nonstandard;
pub mod rbf;
mod signer;
pub mod task;
#[cfg(feature = "testing")]
pub mod test_utils;

// Define a macro for logging errors and saving them to the database
#[macro_export]
macro_rules! log_error_for_tx {
    ($db:expr, $try_to_send_id:expr, $err:expr) => {{
        let db = $db.clone();
        let try_to_send_id = $try_to_send_id;
        let err = $err.to_string();
        tracing::warn!(try_to_send_id, "{}", err);
        tokio::spawn(async move {
            let _ = db
                .save_tx_debug_submission_error(None, try_to_send_id, &err)
                .await;
        });
    }};
}

pub use clementine_errors::SendTxError;
pub use client::TxSenderClient;

use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, FeeRate, OutPoint, Sequence, Transaction, Txid, Weight};
use bitcoincore_rpc::RpcApi;
use clementine_config::tx_sender::TxSenderLimits;
use clementine_errors::{BridgeError, ResultExt};

pub type Result<T, E = SendTxError> = std::result::Result<T, E>;

use clementine_utils::{FeePayingType, TxMetadata};
use eyre::OptionExt;
use serde::{Deserialize, Serialize};
use signer::TxSenderSigningKey;

/// Activation condition based on a transaction ID.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActivatedWithTxid {
    /// The transaction ID that must be seen.
    pub txid: Txid,
    /// Number of blocks that must pass after seeing the transaction.
    pub relative_block_height: u32,
}

/// Activation condition based on an outpoint.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActivatedWithOutpoint {
    /// The outpoint that must be spent.
    pub outpoint: OutPoint,
    /// Number of blocks that must pass after seeing the outpoint spent.
    pub relative_block_height: u32,
}

/// Default sequence for transactions.
pub const DEFAULT_SEQUENCE: Sequence = Sequence(0xFFFFFFFD);

/// Once a tx/outpoint has been observed confirmed/spent for at least this many
/// blocks, we treat it as final and skip further RPC re-checks.
///
/// IMPORTANT: for observations with confirmations < FINALITY_DEPTH we
/// must assume they can be reorged and therefore keep re-checking.
pub const DEFAULT_FINALITY_DEPTH: u32 = 5;

/// Represents a spendable UTXO.
#[derive(Debug, Clone)]
pub struct SpendableUtxo {
    pub outpoint: OutPoint,
    pub txout: bitcoin::TxOut,
    pub spend_info: Option<TaprootSpendInfo>,
}

/// Serialize a transaction for `fund_raw_transaction`, working around Bitcoin Core's
/// deserialization bug for 0-input segwit transactions. fund_raw_transaction RPC
/// gives deserialization error for 0-input transactions with segwit flag.
///
/// For transactions with no inputs, this uses legacy-style serialization
/// (version, inputs, outputs, locktime) without segwit markers. Core will
/// then add inputs and return a proper segwit transaction.
pub(crate) fn serialize_tx_for_fund_raw(tx: &Transaction) -> Vec<u8> {
    if tx.input.is_empty() {
        use bitcoin::consensus::Encodable;

        let mut buf = Vec::new();
        // Serialize version
        tx.version
            .consensus_encode(&mut buf)
            .expect("Failed to serialize version");
        // Serialize inputs
        tx.input
            .consensus_encode(&mut buf)
            .expect("Failed to serialize inputs");
        // Serialize outputs
        tx.output
            .consensus_encode(&mut buf)
            .expect("Failed to serialize outputs");
        // Serialize locktime
        tx.lock_time
            .consensus_encode(&mut buf)
            .expect("Failed to serialize locktime");

        buf
    } else {
        bitcoin::consensus::encode::serialize(tx)
    }
}

pub use db::{TxSenderDb, TxSenderDbTx, TxSenderTransaction};

#[derive(Clone, Debug, Default)]
pub struct MempoolConfig {
    pub host: Option<String>,
    pub endpoint: Option<String>,
}

/// Manages the process of sending Bitcoin transactions, including handling fee bumping
/// strategies like Replace-By-Fee (RBF) and Child-Pays-For-Parent (CPFP).
///
/// It interacts with a Bitcoin Core RPC endpoint (`ExtendedBitcoinRpc`) to query network state
/// (like fee rates) and submit transactions. It uses a `Database` to persist transaction
/// state, track confirmation status, and manage associated data like fee payer UTXOs.
/// The `Actor` provides signing capabilities for transactions controlled by this service.
///
#[derive(Clone)]
pub struct TxSender {
    signer: TxSenderSigningKey,
    pub rpc: clementine_extended_rpc::ExtendedBitcoinRpc,
    pub db: TxSenderDb,
    client: TxSenderClient,
    pub network: bitcoin::Network,
    pub tx_sender_limits: TxSenderLimits,
    pub finality_depth: u32,
    pub http_client: reqwest::Client,
    mempool_config: MempoolConfig,
}

impl std::fmt::Debug for TxSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxSender")
            .field("signer", &self.signer)
            .field("db", &self.db)
            .field("network", &self.network)
            .field("tx_sender_limits", &self.tx_sender_limits)
            .finish()
    }
}

impl TxSender {
    pub fn address(&self) -> &bitcoin::Address {
        self.signer.address()
    }

    pub fn xonly_public_key(&self) -> bitcoin::XOnlyPublicKey {
        self.signer.xonly_public_key()
    }

    /// Creates a new TxSender.
    pub async fn new(
        tx_sender_config: crate::config::TxSenderConfig,
    ) -> std::result::Result<Self, BridgeError> {
        let signer = TxSenderSigningKey::new(tx_sender_config.secret_key, tx_sender_config.network);
        let rpc = clementine_extended_rpc::ExtendedBitcoinRpc::connect(
            tx_sender_config.bitcoin_rpc.url.clone(),
            tx_sender_config.bitcoin_rpc.user.clone(),
            tx_sender_config.bitcoin_rpc.password.clone(),
            None,
        )
        .await
        .map_err(|e| BridgeError::Eyre(e.into()))?;

        let db = TxSenderDb::connect(&tx_sender_config.postgres).await?;
        let client = TxSenderClient::new(db.clone());

        Ok(Self {
            signer,
            rpc,
            db,
            client,
            network: tx_sender_config.network,
            tx_sender_limits: tx_sender_config.limits,
            finality_depth: tx_sender_config.finality_depth,
            http_client: reqwest::Client::new(),
            mempool_config: tx_sender_config.mempool,
        })
    }

    pub async fn get_fee_rate(&self) -> Result<FeeRate, BridgeError> {
        self.rpc
            .get_fee_rate(
                self.network,
                &self.mempool_config.host,
                &self.mempool_config.endpoint,
                self.tx_sender_limits.mempool_fee_rate_multiplier,
                self.tx_sender_limits.mempool_fee_rate_offset_sat_kvb,
                self.tx_sender_limits.fee_rate_hard_cap,
            )
            .await
            .map_err(|e| BridgeError::Eyre(e.into()))
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
            FeePayingType::RBF | FeePayingType::RbfWtxidGrind => {
                Weight::from_wu_usize(230 * num_fee_payer_utxos + 172)
            }
            FeePayingType::NoFunding => Weight::from_wu_usize(0),
        };

        // Calculate total weight for fee calculation.
        // For CPFP, miners consider the effective fee rate over the combined *vbytes* of parent + child.
        // For RBF, miners consider the fee rate of the single replacement transaction's weight.
        let total_weight = match fee_paying_type {
            FeePayingType::CPFP => Weight::from_vb_unchecked(
                child_tx_weight.to_vbytes_ceil() + parent_tx_weight.to_vbytes_ceil(),
            ),
            FeePayingType::RBF | FeePayingType::RbfWtxidGrind => {
                child_tx_weight + parent_tx_weight // Should likely just be the RBF tx weight? Check RBF rules.
            }
            FeePayingType::NoFunding => parent_tx_weight,
        };

        fee_rate
            .checked_mul_by_weight(total_weight)
            .ok_or_eyre("Fee calculation overflow")
            .map_err(Into::into)
    }

    pub fn is_p2a_anchor(&self, output: &bitcoin::TxOut) -> bool {
        clementine_utils::address::is_p2a_anchor(output)
    }

    pub fn find_p2a_vout(&self, tx: &Transaction) -> Result<usize, BridgeError> {
        tx.output
            .iter()
            .position(|output| self.is_p2a_anchor(output))
            .ok_or_eyre("P2A anchor output not found in transaction")
            .map_err(BridgeError::Eyre)
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
    #[tracing::instrument(skip_all, fields(new_fee_rate, current_tip_height))]
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

        if std::env::var("TXSENDER_DBG_INACTIVE_TXS").is_ok() {
            self.db
                .debug_inactive_txs(get_sendable_txs_fee_rate, current_tip_height)
                .await;
        }

        for id in txs {
            // Update debug state
            tracing::debug!(
                try_to_send_id = id,
                "Processing TX in try_to_send_unconfirmed_txs with fee rate {new_fee_rate}",
            );

            let (tx_metadata, tx, fee_paying_type, seen_at_height, rbf_signing_info) =
                match self.db.get_try_to_send_tx(None, id).await {
                    Ok(res) => res,
                    Err(e) => {
                        log_error_for_tx!(self.db, id, format!("Failed to get tx details: {}", e));
                        continue;
                    }
                };

            // Check if the transaction is already confirmed (only happens if it was confirmed after this loop started)
            if let Some(seen_at_height) = seen_at_height {
                tracing::debug!(
                    try_to_send_id = id,
                    "Transaction already confirmed (first seen at height {})",
                    seen_at_height
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
            // 1. If new_fee_rate > previous_effective_fee_rate, use max(new_fee_rate, previous_effective_fee_rate + incremental_fee_rate)
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
                _ if self.network == bitcoin::Network::Testnet4
                    && self.is_bridge_tx_nonstandard(&tx) =>
                {
                    self.send_testnet4_nonstandard_tx(&tx, id).await
                }
                FeePayingType::CPFP => {
                    self.send_cpfp_tx(id, tx, tx_metadata, adjusted_fee_rate, current_tip_height)
                        .await
                }
                FeePayingType::RBF | FeePayingType::RbfWtxidGrind => {
                    self.send_rbf_tx(
                        id,
                        tx,
                        tx_metadata,
                        adjusted_fee_rate,
                        rbf_signing_info,
                        current_tip_height,
                        fee_paying_type == FeePayingType::RbfWtxidGrind,
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
        self.client.clone()
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
        let hard_cap = FeeRate::from_sat_per_vb(self.tx_sender_limits.fee_rate_hard_cap)
            .expect("fee_rate_hard_cap should be valid");

        let Some(previous_rate) = previous_effective_fee_rate else {
            // No previous effective fee rate, use the new fee rate (capped)
            return Ok(std::cmp::min(new_fee_rate, hard_cap));
        };

        // Check if the tx has been stuck for 10+ blocks
        let is_stuck = match last_bump_block_height {
            Some(block_height) => {
                current_tip_height.saturating_sub(block_height)
                    >= self.tx_sender_limits.fee_bump_after_blocks
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
                "TX stuck for at least {} blocks, forcing fee bump from {} to {} sat/kwu (hard cap: {} sat/kwu)",
                self.tx_sender_limits.fee_bump_after_blocks,
                previous_rate.to_sat_per_kwu(),
                capped_result.to_sat_per_kwu(),
                hard_cap.to_sat_per_kwu()
            );

            return Ok(capped_result);
        }

        // Neither higher fee rate nor stuck, use previous rate (no change needed)
        Ok(previous_rate)
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
    #[tracing::instrument(skip_all, fields(try_to_send_id, tx_meta=?tx_metadata))]
    pub async fn send_no_funding_tx(
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
