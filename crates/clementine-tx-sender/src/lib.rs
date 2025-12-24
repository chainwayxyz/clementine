//! # Clementine Transaction Sender
//!
//! This crate handles the creation, signing, and broadcasting of Bitcoin transactions,
//! supporting various fee-bumping strategies like CPFP and RBF.

pub mod client;
pub mod cpfp;
pub mod nonstandard;
pub mod rbf;
pub mod task;

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

use async_trait::async_trait;
use bitcoin::secp256k1::schnorr;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{
    Address, Amount, FeeRate, OutPoint, Sequence, Transaction, Txid, Weight, XOnlyPublicKey,
};
use bitcoincore_rpc::RpcApi;
use clementine_config::protocol::ProtocolParamset;
use clementine_config::tx_sender::TxSenderLimits;
use clementine_errors::{BridgeError, ResultExt};
use clementine_primitives::BitcoinSyncerEvent;

pub type Result<T, E = SendTxError> = std::result::Result<T, E>;

use clementine_utils::rbf::TapTweakData;
use clementine_utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use eyre::OptionExt;
use serde::{Deserialize, Serialize};

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

/// Represents a spendable UTXO.
#[derive(Debug, Clone)]
pub struct SpendableUtxo {
    pub outpoint: OutPoint,
    pub txout: bitcoin::TxOut,
    pub spend_info: Option<TaprootSpendInfo>,
}

impl SpendableInputInfo for SpendableUtxo {
    fn get_prevout(&self) -> &bitcoin::TxOut {
        &self.txout
    }

    fn get_outpoint(&self) -> OutPoint {
        self.outpoint
    }
}

/// Trait for extracting information from a spendable input.
/// This allows different input types (SpendableUtxo, SpendableTxIn) to be used interchangeably.
pub trait SpendableInputInfo: Send + Sync + Clone {
    /// Returns a reference to the previous output (TxOut) for this input.
    fn get_prevout(&self) -> &bitcoin::TxOut;

    /// Returns the outpoint for this input.
    fn get_outpoint(&self) -> OutPoint;
}

/// Trait for building child transactions in the transaction sender.
///
/// This abstraction allows the core crate to provide `SpendableTxIn`-based transaction building
/// using `TxHandler`, while keeping the tx-sender crate independent of the builder module.
///
/// All methods are static - no instance of this trait is stored.
pub trait TxSenderTxBuilder: Send + Sync + 'static {
    /// The type representing a spendable transaction input.
    /// In core, this would be `SpendableTxIn`.
    type SpendableInput: SpendableInputInfo;

    /// Builds a child transaction for CPFP.
    ///
    /// This method constructs a child transaction that spends the P2A anchor output
    /// and fee payer UTXOs, paying the required fees for the CPFP package.
    ///
    /// # Arguments
    /// * `p2a_anchor` - The P2A anchor output to spend
    /// * `anchor_sat` - Amount in the anchor output
    /// * `fee_payer_utxos` - UTXOs to fund the child transaction
    /// * `change_address` - Address for the change output
    /// * `required_fee` - The calculated required fee for the package
    /// * `signer_address` - The signer's address (for script pubkey)
    /// * `signer` - The signer to sign the transaction inputs
    ///
    /// # Returns
    /// A signed child transaction ready for package submission.
    fn build_child_tx<S: TxSenderSigner>(
        p2a_anchor: OutPoint,
        anchor_sat: Amount,
        fee_payer_utxos: Vec<Self::SpendableInput>,
        change_address: Address,
        required_fee: Amount,
        signer: &S,
    ) -> Result<Transaction, BridgeError>;

    /// Converts database UTXOs into the builder's SpendableInput type.
    ///
    /// # Arguments
    /// * `utxos` - Vector of (txid, vout, amount) tuples from the database
    /// * `signer_address` - The signer's address (for script pubkey generation)
    ///
    /// # Returns
    /// Vector of SpendableInput instances ready for use in transaction building.
    fn utxos_to_spendable_inputs(
        utxos: Vec<(Txid, u32, Amount)>,
        signer_address: &Address,
    ) -> Vec<Self::SpendableInput>;
}

/// Trait for signing transactions in the transaction sender.
#[async_trait]
pub trait TxSenderSigner: Send + Sync {
    /// Returns the signer's Bitcoin address.
    fn address(&self) -> &Address;

    /// Returns the signer's X-only public key.
    fn xonly_public_key(&self) -> XOnlyPublicKey;

    /// Signs a message with a tweak.
    fn sign_with_tweak_data(
        &self,
        sighash: bitcoin::TapSighash,
        tweak_data: TapTweakData,
        tweak_cache: Option<&mut ()>, // Placeholder for cache
    ) -> Result<schnorr::Signature, BridgeError>;
}

/// Trait for database operations required by the transaction sender.
#[async_trait]
pub trait TxSenderDatabase: Send + Sync + Clone {
    /// Type for database transactions.
    type Transaction: Send;

    /// Begin a new database transaction.
    async fn begin_transaction(&self) -> Result<Self::Transaction, BridgeError>;

    /// Commit a database transaction.
    async fn commit_transaction(&self, dbtx: Self::Transaction) -> Result<(), BridgeError>;

    /// Save a debug message for a transaction submission error.
    async fn save_tx_debug_submission_error(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
        error: &str,
    ) -> Result<(), BridgeError>;

    /// Get transactions that are ready to be sent.
    async fn get_sendable_txs(
        &self,
        fee_rate: FeeRate,
        current_tip_height: u32,
    ) -> Result<Vec<u32>, BridgeError>;

    /// Get details of a transaction to be sent.
    async fn get_try_to_send_tx(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<
        (
            Option<TxMetadata>,
            Transaction,
            FeePayingType,
            Option<u32>,
            Option<RbfSigningInfo>,
        ),
        BridgeError,
    >;

    /// Update the debug sending state of a transaction.
    async fn update_tx_debug_sending_state(
        &self,
        id: u32,
        state: &str,
        is_error: bool,
    ) -> Result<(), BridgeError>;

    /// Get all unconfirmed fee payer transactions.
    async fn get_all_unconfirmed_fee_payer_txs(
        &self,
        dbtx: Option<&mut Self::Transaction>,
    ) -> Result<Vec<(u32, u32, Txid, u32, Amount, Option<u32>)>, BridgeError>;

    /// Get unconfirmed fee payer transactions for a specific parent transaction.
    async fn get_unconfirmed_fee_payer_txs(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        bumped_id: u32,
    ) -> Result<Vec<(u32, Txid, u32, Amount)>, BridgeError>;

    /// Mark a fee payer UTXO as evicted.
    async fn mark_fee_payer_utxo_as_evicted(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<(), BridgeError>;

    /// Get confirmed fee payer UTXOs for a specific parent transaction.
    async fn get_confirmed_fee_payer_utxos(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Vec<(Txid, u32, Amount)>, BridgeError>;

    /// Save a fee payer transaction.
    #[allow(clippy::too_many_arguments)]
    async fn save_fee_payer_tx(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        try_to_send_id: Option<u32>,
        bumped_id: u32,
        fee_payer_txid: Txid,
        vout: u32,
        amount: Amount,
        replacement_of_id: Option<u32>,
    ) -> Result<(), BridgeError>;

    /// Get the last RBF transaction ID for a specific send attempt.
    async fn get_last_rbf_txid(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Option<Txid>, BridgeError>;

    /// Save a new RBF transaction ID.
    async fn save_rbf_txid(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
        txid: Txid,
    ) -> Result<(), BridgeError>;

    /// Save a cancelled outpoint activation condition.
    async fn save_cancelled_outpoint(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        cancelled_id: u32,
        outpoint: OutPoint,
    ) -> Result<(), BridgeError>;

    /// Save a cancelled transaction ID activation condition.
    async fn save_cancelled_txid(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        cancelled_id: u32,
        txid: Txid,
    ) -> Result<(), BridgeError>;

    /// Save an activated transaction ID condition.
    async fn save_activated_txid(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        activated_id: u32,
        prerequisite_tx: &ActivatedWithTxid,
    ) -> Result<(), BridgeError>;

    /// Save an activated outpoint condition.
    async fn save_activated_outpoint(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        activated_id: u32,
        activated_outpoint: &ActivatedWithOutpoint,
    ) -> Result<(), BridgeError>;

    /// Update the effective fee rate of a transaction.
    async fn update_effective_fee_rate(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
        effective_fee_rate: FeeRate,
    ) -> Result<(), BridgeError>;

    /// Check if a transaction already exists in the transaction sender queue.
    async fn check_if_tx_exists_on_txsender(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        txid: Txid,
    ) -> Result<Option<u32>, BridgeError>;

    /// Save a transaction to the sending queue.
    async fn save_tx(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        tx_metadata: Option<TxMetadata>,
        tx: &Transaction,
        fee_paying_type: FeePayingType,
        txid: Txid,
        rbf_signing_info: Option<RbfSigningInfo>,
    ) -> Result<u32, BridgeError>;

    /// Returns debug information for a transaction.
    async fn get_tx_debug_info(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Option<String>, BridgeError>;

    /// Returns submission errors for a transaction.
    async fn get_tx_debug_submission_errors(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Vec<(String, String)>, BridgeError>;

    /// Returns fee payer UTXOs for an attempt.
    async fn get_tx_debug_fee_payer_utxos(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        id: u32,
    ) -> Result<Vec<(Txid, u32, Amount, bool)>, BridgeError>;

    /// Fetch the next event from the Bitcoin syncer.
    async fn fetch_next_bitcoin_syncer_evt(
        &self,
        dbtx: &mut Self::Transaction,
        consumer_id: &str,
    ) -> Result<Option<BitcoinSyncerEvent>, BridgeError>;

    /// Get block hash and height from its ID.
    async fn get_block_info_from_id(
        &self,
        dbtx: Option<&mut Self::Transaction>,
        block_id: u32,
    ) -> Result<Option<(bitcoin::BlockHash, u32)>, BridgeError>;

    /// Confirm transactions in a block.
    async fn confirm_transactions(
        &self,
        dbtx: &mut Self::Transaction,
        block_id: u32,
    ) -> Result<(), BridgeError>;

    /// Unconfirm transactions in a block (due to reorg).
    async fn unconfirm_transactions(
        &self,
        dbtx: &mut Self::Transaction,
        block_id: u32,
    ) -> Result<(), BridgeError>;
}

#[derive(Clone, Debug)]
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
/// The `TxSenderTxBuilder` type parameter provides static methods for transaction building
/// capabilities for CPFP child transactions, using `SpendableTxIn` and `TxHandler`.
#[derive(Clone)]
pub struct TxSender<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + 'static,
    B: TxSenderTxBuilder + 'static,
{
    pub signer: S,
    pub rpc: clementine_extended_rpc::ExtendedBitcoinRpc,
    pub db: D,
    pub btc_syncer_consumer_id: String,
    pub protocol_paramset: &'static ProtocolParamset,
    pub tx_sender_limits: TxSenderLimits,
    pub http_client: reqwest::Client,
    mempool_config: MempoolConfig,
    /// Phantom data to track the TxBuilder type.
    /// B provides static methods for transaction building.
    _tx_builder: std::marker::PhantomData<B>,
}

impl<S, D, B> std::fmt::Debug for TxSender<S, D, B>
where
    S: TxSenderSigner + std::fmt::Debug + 'static,
    D: TxSenderDatabase + std::fmt::Debug + 'static,
    B: TxSenderTxBuilder + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxSender")
            .field("signer", &self.signer)
            .field("db", &self.db)
            .field("btc_syncer_consumer_id", &self.btc_syncer_consumer_id)
            .field("protocol_paramset", &self.protocol_paramset)
            .field("tx_sender_limits", &self.tx_sender_limits)
            .finish()
    }
}

impl<S, D, B> TxSender<S, D, B>
where
    S: TxSenderSigner + 'static,
    D: TxSenderDatabase + 'static,
    B: TxSenderTxBuilder + 'static,
{
    /// Creates a new TxSender.
    ///
    /// The type parameter `B` provides static methods for CPFP child transaction creation
    /// using SpendableTxIn and TxHandler from the core builder module.
    pub fn new(
        signer: S,
        rpc: clementine_extended_rpc::ExtendedBitcoinRpc,
        db: D,
        btc_syncer_consumer_id: String,
        protocol_paramset: &'static ProtocolParamset,
        tx_sender_limits: TxSenderLimits,
        mempool_config: MempoolConfig,
    ) -> Self {
        Self {
            signer,
            rpc,
            db,
            btc_syncer_consumer_id,
            protocol_paramset,
            tx_sender_limits,
            http_client: reqwest::Client::new(),
            mempool_config,
            _tx_builder: std::marker::PhantomData,
        }
    }

    pub async fn get_fee_rate(&self) -> Result<FeeRate, BridgeError> {
        self.rpc
            .get_fee_rate(
                self.protocol_paramset.network,
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
            .get_sendable_txs(get_sendable_txs_fee_rate, current_tip_height)
            .await
            .map_to_eyre()?;

        // bump fees of fee payer transactions that are unconfirmed
        self.bump_fees_of_unconfirmed_fee_payer_txs(new_fee_rate)
            .await?;

        if !txs.is_empty() {
            tracing::debug!("Trying to send {} sendable txs ", txs.len());
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
                _ if self.protocol_paramset.network == bitcoin::Network::Testnet4
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
    pub fn client(&self) -> TxSenderClient<D> {
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
